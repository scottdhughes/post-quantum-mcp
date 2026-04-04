/**
 * KV-backed sliding-window rate limiter.
 *
 * Uses time-bucketed counters in Cloudflare KV with auto-expiring TTL.
 * Not fully atomic (KV get+put race under extreme concurrency), but
 * correct for single-region Workers at current scale.
 */

interface RateLimitResult {
  allowed: boolean;
  count: number;
  limit: number;
  remaining: number;
  windowKey: string;
}

/**
 * Check and increment the rate limit counter for a given key.
 * Returns whether the request is allowed and current counter state.
 */
export async function checkRateLimit(
  kv: KVNamespace,
  key: string,
  maxRequests: number,
  windowSeconds: number = 60
): Promise<RateLimitResult> {
  const now = Math.floor(Date.now() / 1000);
  const windowKey = `ratelimit:${key}:${Math.floor(now / windowSeconds)}`;

  const raw = await kv.get(windowKey);
  const count = raw ? parseInt(raw, 10) : 0;

  if (count >= maxRequests) {
    return {
      allowed: false,
      count,
      limit: maxRequests,
      remaining: 0,
      windowKey,
    };
  }

  await kv.put(windowKey, String(count + 1), {
    expirationTtl: windowSeconds * 2,
  });

  return {
    allowed: true,
    count: count + 1,
    limit: maxRequests,
    remaining: maxRequests - count - 1,
    windowKey,
  };
}

/**
 * Check if an IP is in the trusted allowlist (skips rate limiting).
 */
export function isTrustedIp(
  ip: string,
  trustedIps: string
): boolean {
  if (!trustedIps) return false;
  const list = trustedIps.split(",").map((s) => s.trim()).filter(Boolean);
  return list.includes(ip);
}

/**
 * Log a rate limit event for observability.
 */
export function logRateLimitEvent(
  action: "blocked" | "allowed",
  ip: string,
  method: string,
  path: string,
  result: RateLimitResult
): void {
  console.log(
    JSON.stringify({
      event: "rate_limit",
      action,
      ip,
      method,
      path,
      count: result.count,
      limit: result.limit,
      remaining: result.remaining,
      window: result.windowKey,
      timestamp: new Date().toISOString(),
    })
  );
}
