import { failure, json, positiveInt, readJson } from "./http";

/** A per-IP, SQLite-backed fixed-window limiter. Errors fail closed at the edge. */
export class RateLimiter {
  private state: DurableObjectState;
  private sql: SqlStorage;
  constructor(state: DurableObjectState) {
    this.state = state;
    this.sql = state.storage.sql;
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS buckets (key TEXT PRIMARY KEY, window INTEGER NOT NULL, count INTEGER NOT NULL)",
    );
  }
  async fetch(request: Request): Promise<Response> {
    try {
      const input = await readJson(request, 1024);
      const limit = positiveInt(String(input.limit), "limit");
      const category = input.category;
      if (!["post", "get", "delete", "admin"].includes(String(category)))
        return failure(400, "bad_request", "Invalid limiter category");
      const window = Math.floor(Date.now() / 60000);
      const allowed = this.state.storage.transactionSync(() => {
        this.sql.exec("DELETE FROM buckets WHERE window < ?", window);
        const row = this.sql
          .exec<{ count: number }>(
            "SELECT count FROM buckets WHERE key=? AND window=?",
            String(category),
            window,
          )
          .toArray()[0];
        if (row && row.count >= limit) return false;
        this.sql.exec(
          "INSERT INTO buckets VALUES (?,?,1) ON CONFLICT(key) DO UPDATE SET window=excluded.window,count=buckets.count+1",
          String(category),
          window,
        );
        return true;
      });
      // Remove idle IP state without depending on KV expiry/write rate limits.
      try {
        await this.state.storage.setAlarm((window + 2) * 60000);
      } catch {
        /* state remains bounded */
      }
      return json({ allowed });
    } catch {
      return failure(503, "unavailable", "Rate limiter unavailable");
    }
  }
  async alarm(): Promise<void> {
    this.sql.exec(
      "DELETE FROM buckets WHERE window < ?",
      Math.floor(Date.now() / 60000),
    );
  }
}
