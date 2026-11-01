/** Shared bounded parsing and structured errors at the relay boundary. */
export class RequestError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}
export function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
      "Cache-Control": "no-store",
    },
  });
}
export function failure(
  status: number,
  code: string,
  message: string,
): Response {
  return json({ error: code, message }, status);
}
export function positiveInt(
  value: string | undefined,
  name: string,
  fallback?: number,
): number {
  const number =
    value === undefined && fallback !== undefined ? fallback : Number(value);
  if (
    !Number.isSafeInteger(number) ||
    number < 1 ||
    !/^\d+$/.test(String(value ?? number))
  )
    throw new RequestError(400, "bad_request", `Invalid ${name}`);
  return number;
}
export async function readJson(
  request: Request,
  maxBytes: number,
): Promise<Record<string, unknown>> {
  const length = request.headers.get("Content-Length");
  if (length !== null && Number(length) > maxBytes)
    throw new RequestError(
      413,
      "payload_too_large",
      "Request body exceeds byte limit",
    );
  const reader = request.body?.getReader();
  if (!reader)
    throw new RequestError(400, "bad_request", "JSON object required");
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      bytes += value.byteLength;
      if (bytes > maxBytes) {
        await reader.cancel();
        throw new RequestError(
          413,
          "payload_too_large",
          "Request body exceeds byte limit",
        );
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const buffer = new Uint8Array(bytes);
  let offset = 0;
  for (const chunk of chunks) {
    buffer.set(chunk, offset);
    offset += chunk.length;
  }
  try {
    const value: unknown = JSON.parse(
      new TextDecoder("utf-8", { fatal: true, ignoreBOM: false }).decode(
        buffer,
      ),
    );
    if (value === null || typeof value !== "object" || Array.isArray(value))
      throw Error();
    return value as Record<string, unknown>;
  } catch {
    throw new RequestError(400, "bad_request", "JSON object required");
  }
}
export async function hash(value: string): Promise<string> {
  return Array.from(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)),
    ),
  )
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}
export function bearer(request: Request): string {
  const auth = request.headers.get("Authorization") ?? "";
  return auth.startsWith("Bearer ") && auth.length <= 520 ? auth.slice(7) : "";
}
export function equalHashes(a: string, b: string): boolean {
  if (a.length !== 64 || b.length !== 64) return false;
  let difference = 0;
  for (let i = 0; i < 64; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}
export interface Env {
  MAILBOXES: DurableObjectNamespace;
  RATE_LIMITERS: DurableObjectNamespace;
  MAX_ENVELOPE_SIZE: string;
  MAX_MESSAGES_PER_MAILBOX: string;
  MESSAGE_TTL_SECONDS: string;
  RATE_LIMIT_POST_PER_MIN: string;
  RATE_LIMIT_GET_PER_MIN: string;
  TRUSTED_IPS?: string;
  RELAY_ADMIN_TOKEN?: string;
}
export async function requireAdmin(request: Request, env: Env): Promise<void> {
  const configured = env.RELAY_ADMIN_TOKEN ?? "";
  if (
    configured.length < 16 ||
    configured === "test-admin-token-do-not-use-in-production"
  )
    throw new RequestError(
      503,
      "unavailable",
      "Admin credential is not configured",
    );
  if (!equalHashes(await hash(bearer(request)), await hash(configured)))
    throw new RequestError(
      401,
      "unauthorized",
      "Admin authentication required",
    );
}
