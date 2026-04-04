/**
 * Quantum Seal Relay — Opaque Envelope Mailbox
 *
 * Stores and forwards PQC-sealed envelopes between agents.
 * The relay never performs cryptographic operations or accesses
 * private keys. It is a dumb pipe that stores JSON blobs.
 *
 * Storage: Cloudflare KV with built-in TTL for automatic expiry.
 * Key format: mailbox:{fp}:msg:{uuid}
 */

interface Env {
  MAILBOX: KVNamespace;
  MAX_ENVELOPE_SIZE: string;
  MAX_MESSAGES_PER_MAILBOX: string;
  MESSAGE_TTL_SECONDS: string;
  RATE_LIMIT_POST_PER_MIN: string;
  RATE_LIMIT_GET_PER_MIN: string;
}

interface StoredMessage {
  id: string;
  received_at: string;
  sender_fp: string;
  size: number;
  envelope: unknown;
}

interface MailboxMeta {
  message_count: number;
  allowed_senders?: string[];
}

// ─── Helpers ─────────────────────────────────────────────

function jsonResponse(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function errorResponse(error: string, message: string, status: number): Response {
  return jsonResponse({ error, message }, status);
}

function generateId(): string {
  return crypto.randomUUID();
}

function isValidFingerprint(fp: string): boolean {
  return /^[0-9a-f]{64}$/.test(fp);
}

async function getMailboxMeta(kv: KVNamespace, fp: string): Promise<MailboxMeta> {
  const raw = await kv.get(`mailbox:${fp}:meta`);
  if (!raw) return { message_count: 0 };
  try {
    return JSON.parse(raw) as MailboxMeta;
  } catch {
    return { message_count: 0 };
  }
}

async function setMailboxMeta(kv: KVNamespace, fp: string, meta: MailboxMeta): Promise<void> {
  await kv.put(`mailbox:${fp}:meta`, JSON.stringify(meta));
}

// ─── Route Handler ───────────────────────────────────────

async function handleRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  // CORS preflight
  if (method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
    });
  }

  // Route: POST /mailboxes/:fp
  const postMatch = path.match(/^\/mailboxes\/([0-9a-f]{64})$/);
  if (postMatch && method === "POST") {
    return handlePost(request, env, postMatch[1]);
  }

  // Route: GET /mailboxes/:fp
  const getMatch = path.match(/^\/mailboxes\/([0-9a-f]{64})$/);
  if (getMatch && method === "GET") {
    return handleGet(request, env, getMatch[1]);
  }

  // Route: DELETE /mailboxes/:fp/:id
  const deleteMatch = path.match(/^\/mailboxes\/([0-9a-f]{64})\/([a-f0-9-]{36})$/);
  if (deleteMatch && method === "DELETE") {
    return handleDelete(env, deleteMatch[1], deleteMatch[2]);
  }

  // Route: PUT /mailboxes/:fp/allowlist
  const allowlistMatch = path.match(/^\/mailboxes\/([0-9a-f]{64})\/allowlist$/);
  if (allowlistMatch && method === "PUT") {
    return handleAllowlist(request, env, allowlistMatch[1]);
  }

  // Health check
  if (path === "/" || path === "/health") {
    return jsonResponse({
      service: "quantum-seal-relay",
      status: "ok",
      protocol: "pqc-mcp-v3",
    });
  }

  return errorResponse("not_found", "Unknown endpoint", 404);
}

// ─── POST: Deposit Envelope ──────────────────────────────

async function handlePost(request: Request, env: Env, recipientFp: string): Promise<Response> {
  const maxSize = parseInt(env.MAX_ENVELOPE_SIZE);
  const maxMessages = parseInt(env.MAX_MESSAGES_PER_MAILBOX);
  const ttl = parseInt(env.MESSAGE_TTL_SECONDS);

  // Size check
  const contentLength = parseInt(request.headers.get("content-length") || "0");
  if (contentLength > maxSize) {
    return errorResponse("payload_too_large", `Envelope exceeds ${maxSize} byte limit`, 413);
  }

  // Parse body
  let envelope: Record<string, unknown>;
  try {
    const body = await request.text();
    if (body.length > maxSize) {
      return errorResponse("payload_too_large", `Envelope exceeds ${maxSize} byte limit`, 413);
    }
    envelope = JSON.parse(body);
  } catch {
    return errorResponse("bad_request", "Invalid JSON body", 400);
  }

  // Basic envelope validation (opaque — we just check structure, not crypto)
  if (!envelope.version || !envelope.suite || !envelope.ciphertext) {
    return errorResponse("bad_request", "Missing required envelope fields (version, suite, ciphertext)", 400);
  }

  // Extract sender fingerprint for metadata/filtering
  const senderFp = (envelope.sender_key_fingerprint as string) || "";

  // Check allowlist
  const meta = await getMailboxMeta(env.MAILBOX, recipientFp);
  if (meta.allowed_senders && meta.allowed_senders.length > 0) {
    if (!senderFp || !meta.allowed_senders.includes(senderFp)) {
      return errorResponse("forbidden", "Sender not in allowlist", 403);
    }
  }

  // Check mailbox capacity
  if (meta.message_count >= maxMessages) {
    return errorResponse("mailbox_full", `Mailbox has ${maxMessages} messages (limit reached)`, 429);
  }

  // Store
  const messageId = generateId();
  const receivedAt = new Date().toISOString();
  const stored: StoredMessage = {
    id: messageId,
    received_at: receivedAt,
    sender_fp: senderFp,
    size: JSON.stringify(envelope).length,
    envelope,
  };

  await env.MAILBOX.put(
    `mailbox:${recipientFp}:msg:${messageId}`,
    JSON.stringify(stored),
    { expirationTtl: ttl }
  );

  // Update count
  meta.message_count += 1;
  await setMailboxMeta(env.MAILBOX, recipientFp, meta);

  return jsonResponse(
    {
      id: messageId,
      recipient_fp: recipientFp,
      received_at: receivedAt,
      size: stored.size,
    },
    201
  );
}

// ─── GET: Fetch Messages ─────────────────────────────────

async function handleGet(request: Request, env: Env, recipientFp: string): Promise<Response> {
  const url = new URL(request.url);
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "10"), 100);

  // List all messages in this mailbox
  const prefix = `mailbox:${recipientFp}:msg:`;
  const listed = await env.MAILBOX.list({ prefix, limit });

  const messages: StoredMessage[] = [];
  for (const key of listed.keys) {
    const raw = await env.MAILBOX.get(key.name);
    if (raw) {
      try {
        messages.push(JSON.parse(raw) as StoredMessage);
      } catch {
        // Skip corrupted entries
      }
    }
  }

  return jsonResponse({
    mailbox: recipientFp,
    count: messages.length,
    messages,
    next_cursor: listed.list_complete ? null : listed.cursor,
  });
}

// ─── DELETE: Acknowledge Receipt ─────────────────────────

async function handleDelete(env: Env, recipientFp: string, messageId: string): Promise<Response> {
  const key = `mailbox:${recipientFp}:msg:${messageId}`;
  const exists = await env.MAILBOX.get(key);

  if (!exists) {
    return errorResponse("not_found", "Message not found", 404);
  }

  await env.MAILBOX.delete(key);

  // Decrement count
  const meta = await getMailboxMeta(env.MAILBOX, recipientFp);
  meta.message_count = Math.max(0, meta.message_count - 1);
  await setMailboxMeta(env.MAILBOX, recipientFp, meta);

  return jsonResponse({ deleted: messageId });
}

// ─── PUT: Configure Allowlist ────────────────────────────

async function handleAllowlist(request: Request, env: Env, recipientFp: string): Promise<Response> {
  let body: { allowed_senders?: string[] };
  try {
    body = await request.json();
  } catch {
    return errorResponse("bad_request", "Invalid JSON body", 400);
  }

  const senders = body.allowed_senders || [];

  // Validate fingerprints
  for (const fp of senders) {
    if (!isValidFingerprint(fp)) {
      return errorResponse("bad_request", `Invalid fingerprint format: ${fp}`, 400);
    }
  }

  const meta = await getMailboxMeta(env.MAILBOX, recipientFp);
  meta.allowed_senders = senders.length > 0 ? senders : undefined;
  await setMailboxMeta(env.MAILBOX, recipientFp, meta);

  return jsonResponse({
    mailbox: recipientFp,
    allowed_senders: senders,
    mode: senders.length > 0 ? "allowlist" : "open",
  });
}

// ─── Export ──────────────────────────────────────────────

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const response = await handleRequest(request, env);
    // Add CORS headers to all responses
    response.headers.set("Access-Control-Allow-Origin", "*");
    return response;
  },
};
