/** Opaque relay: transactional mailboxes, durable authorization, bounded requests. */
import { failure, json, positiveInt, RequestError, type Env } from "./http";
export { Mailbox } from "./mailbox";
export { RateLimiter } from "./rate-limiter";

async function route(request: Request, env: Env): Promise<Response> {
  const path = new URL(request.url).pathname,
    method = request.method;
  if (method === "OPTIONS")
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers":
          "Content-Type, Authorization, Idempotency-Key",
      },
    });
  if ((path === "/" || path === "/health") && method === "GET")
    return json({
      service: "quantum-seal-relay",
      status: "ok",
      protocol: "pqc-mcp-v3",
      storage: "durable-objects-sqlite",
    });
  const match = path.match(
    /^\/mailboxes\/([a-f0-9]{64})(?:\/(register|allowlist|[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}))?$/,
  );
  if (!match) return failure(404, "not_found", "Unknown endpoint");
  const suffix = match[2];
  if (!(
    (!suffix && ["POST", "GET"].includes(method)) ||
    (suffix === "register" && method === "POST") ||
    (suffix === "allowlist" && method === "PUT") ||
    (suffix &&
      suffix !== "register" &&
      suffix !== "allowlist" &&
      method === "DELETE")
  ))
    return failure(405, "method_not_allowed", "Unsupported method");
  const ip = request.headers.get("CF-Connecting-IP") ?? "unknown";
  const trusted = (env.TRUSTED_IPS ?? "")
    .split(",")
    .map((x) => x.trim())
    .filter(Boolean)
    .includes(ip);
  if (!trusted) {
    const category =
      suffix === "register" || suffix === "allowlist"
        ? "admin"
        : method.toLowerCase();
    const limit =
      category === "admin"
        ? 10
        : positiveInt(
            category === "post"
              ? env.RATE_LIMIT_POST_PER_MIN
              : env.RATE_LIMIT_GET_PER_MIN,
            "rate limit",
          );
    const limiter = env.RATE_LIMITERS.get(env.RATE_LIMITERS.idFromName(ip));
    const limited = await limiter.fetch("https://limiter.invalid/", {
      method: "POST",
      body: JSON.stringify({ category, limit }),
    });
    if (!limited.ok)
      return failure(503, "unavailable", "Rate limiter unavailable");
    const result = (await limited.json()) as { allowed?: boolean };
    if (result.allowed !== true)
      return failure(429, "rate_limited", "Too many requests");
  }
  return env.MAILBOXES.get(env.MAILBOXES.idFromName(match[1])).fetch(request);
}
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const start = Date.now();
    let response: Response;
    try {
      response = await route(request, env);
    } catch (error) {
      response =
        error instanceof RequestError
          ? failure(error.status, error.code, error.message)
          : failure(503, "unavailable", "Relay temporarily unavailable");
    }
    // Durable Object fetch responses have immutable headers in workerd.
    response = new Response(response.body, response);
    response.headers.set("Access-Control-Allow-Origin", "*");
    // Never log tokens, bodies, mailbox fingerprints, or complete URLs.
    console.log(
      JSON.stringify({
        event: "request",
        method: request.method,
        status: response.status,
        latency_ms: Date.now() - start,
      }),
    );
    return response;
  },
};
