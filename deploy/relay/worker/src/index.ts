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

import { checkRateLimit, isTrustedIp, logRateLimitEvent } from "./rate-limiter";

export interface Env {
  MAILBOX: KVNamespace;
  MAX_ENVELOPE_SIZE: string;
  MAX_MESSAGES_PER_MAILBOX: string;
  MESSAGE_TTL_SECONDS: string;
  RATE_LIMIT_POST_PER_MIN: string;
  RATE_LIMIT_GET_PER_MIN: string;
  TRUSTED_IPS: string; // comma-separated IPs that bypass rate limiting
  RELAY_ADMIN_TOKEN: string; // Bearer token for admin operations (allowlist)
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

// ─── Constant-time comparison ────────────────────────────

function timingSafeEqual(a: string, b: string): boolean {
  const lengthMatch = a.length === b.length;
  if (!lengthMatch) {
    // Compare against dummy to avoid leaking length difference via timing.
    // We still return false because lengthMatch is captured before reassignment.
    b = a;
  }
  const encoder = new TextEncoder();
  const aBuf = encoder.encode(a);
  const bBuf = encoder.encode(b);
  let diff = lengthMatch ? 0 : 1;
  for (let i = 0; i < aBuf.length; i++) {
    diff |= aBuf[i] ^ bBuf[i];
  }
  return diff === 0;
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

async function setMailboxMeta(
  kv: KVNamespace, fp: string, meta: MailboxMeta, ttlSeconds: number = 172800
): Promise<void> {
  // TTL on meta prevents permanent orphan block (Sonnet finding #10).
  // Default 48h — longer than message TTL so active mailboxes stay valid.
  await kv.put(`mailbox:${fp}:meta`, JSON.stringify(meta), {
    expirationTtl: ttlSeconds,
  });
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

  // Rate limiting by IP (trusted IPs bypass)
  const clientIp = request.headers.get("cf-connecting-ip") || "unknown";
  const trusted = isTrustedIp(clientIp, env.TRUSTED_IPS || "");

  // Route: POST /mailboxes/:fp
  const postMatch = path.match(/^\/mailboxes\/([0-9a-f]{64})$/);
  if (postMatch && method === "POST") {
    if (!trusted) {
      try {
        const postLimit = parseInt(env.RATE_LIMIT_POST_PER_MIN || "60");
        const result = await checkRateLimit(env.MAILBOX, `post:${clientIp}`, postLimit);
        if (!result.allowed) {
          logRateLimitEvent("blocked", clientIp, method, path, result);
          return errorResponse("rate_limited", "Too many requests. Try again later.", 429);
        }
      } catch {
        // KV error — fail open (allow request, log warning)
        console.log(JSON.stringify({ event: "rate_limit_error", ip: clientIp, method, path }));
      }
    }
    return handlePost(request, env, postMatch[1]);
  }

  // Route: GET /mailboxes/:fp
  const getMatch = path.match(/^\/mailboxes\/([0-9a-f]{64})$/);
  if (getMatch && method === "GET") {
    if (!trusted) {
      try {
        const getLimit = parseInt(env.RATE_LIMIT_GET_PER_MIN || "120");
        const result = await checkRateLimit(env.MAILBOX, `get:${clientIp}`, getLimit);
        if (!result.allowed) {
          logRateLimitEvent("blocked", clientIp, method, path, result);
          return errorResponse("rate_limited", "Too many requests. Try again later.", 429);
        }
      } catch {
        console.log(JSON.stringify({ event: "rate_limit_error", ip: clientIp, method, path }));
      }
    }
    return handleGet(request, env, getMatch[1]);
  }

  // Route: DELETE /mailboxes/:fp/:id
  const deleteMatch = path.match(/^\/mailboxes\/([0-9a-f]{64})\/([a-f0-9-]{36})$/);
  if (deleteMatch && method === "DELETE") {
    return handleDelete(env, deleteMatch[1], deleteMatch[2]);
  }

  // Route: PUT /mailboxes/:fp/allowlist (requires admin auth + rate limited)
  const allowlistMatch = path.match(/^\/mailboxes\/([0-9a-f]{64})\/allowlist$/);
  if (allowlistMatch && method === "PUT") {
    // Rate limit ALL admin attempts (before auth check — prevents brute force)
    if (!trusted) {
      try {
        const result = await checkRateLimit(env.MAILBOX, `admin:${clientIp}`, 10);
        if (!result.allowed) {
          logRateLimitEvent("blocked", clientIp, method, path, result);
          return errorResponse("rate_limited", "Too many admin requests.", 429);
        }
      } catch {
        console.log(JSON.stringify({ event: "rate_limit_error", ip: clientIp, method, path }));
      }
    }
    // Constant-time admin token comparison (prevents timing oracle)
    const adminToken = env.RELAY_ADMIN_TOKEN || "";
    const authHeader = request.headers.get("authorization") || "";
    const expected = `Bearer ${adminToken}`;
    if (!adminToken || !timingSafeEqual(expected, authHeader)) {
      return errorResponse("unauthorized", "Admin authentication required for allowlist mutations", 401);
    }
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
  let meta: MailboxMeta;
  try {
    meta = await getMailboxMeta(env.MAILBOX, recipientFp);
  } catch {
    meta = { message_count: 0 }; // KV error — fail open
  }

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

  try {
    await env.MAILBOX.put(
      `mailbox:${recipientFp}:msg:${messageId}`,
      JSON.stringify(stored),
      { expirationTtl: ttl }
    );

    // Update count (best-effort — race under concurrency is OK)
    meta.message_count += 1;
    await setMailboxMeta(env.MAILBOX, recipientFp, meta);
  } catch (err) {
    console.log(JSON.stringify({ event: "kv_error", op: "put", error: String(err) }));
    return errorResponse("internal_error", "Failed to store envelope", 500);
  }

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
  const afterCursor = url.searchParams.get("after") || undefined;

  // List messages in this mailbox, with optional KV cursor for pagination
  const prefix = `mailbox:${recipientFp}:msg:`;
  const listOpts: KVNamespaceListOptions = { prefix, limit };
  if (afterCursor) {
    listOpts.cursor = afterCursor;
  }

  const listed = await env.MAILBOX.list(listOpts);

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
    next_cursor: listed.list_complete ? null : (listed.cursor || null),
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
    const start = Date.now();
    const response = await handleRequest(request, env);
    const latency = Date.now() - start;

    // Add CORS headers to all responses
    response.headers.set("Access-Control-Allow-Origin", "*");

    // Success-path observability
    const method = request.method;
    const path = new URL(request.url).pathname;
    if (method !== "OPTIONS" && path !== "/" && path !== "/health") {
      console.log(
        JSON.stringify({
          event: "request",
          method,
          path: path.substring(0, 80),
          status: response.status,
          latency_ms: latency,
          timestamp: new Date().toISOString(),
        })
      );
    }

    return response;
  },
};
