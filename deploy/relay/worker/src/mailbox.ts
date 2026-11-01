import {
  bearer,
  equalHashes,
  failure,
  hash,
  json,
  positiveInt,
  readJson,
  RequestError,
  requireAdmin,
  type Env,
} from "./http";

type Meta = { token_hash: string; allowed_senders: string };
type Message = {
  id: string;
  envelope: string;
  received_at: string;
  expires_at: number;
  sender_fp: string;
  size: number;
};
type Receipt = {
  key: string;
  digest: string;
  message_id: string;
  received_at: string;
  size: number;
  expires_at: number;
};

/** One SQLite-backed actor owns authorization, expiry, quota, and retry receipts. */
export class Mailbox {
  state: DurableObjectState;
  env: Env;
  private sql: SqlStorage;
  constructor(state: DurableObjectState, env: Env) {
    this.state = state;
    this.env = env;
    this.sql = state.storage.sql;
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS auth (id INTEGER PRIMARY KEY CHECK(id=1), token_hash TEXT NOT NULL, allowed_senders TEXT NOT NULL)",
    );
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, envelope TEXT NOT NULL, received_at TEXT NOT NULL, expires_at INTEGER NOT NULL, sender_fp TEXT NOT NULL, size INTEGER NOT NULL)",
    );
    this.sql.exec(
      "CREATE INDEX IF NOT EXISTS message_expiry ON messages(expires_at)",
    );
    this.sql.exec(
      "CREATE TABLE IF NOT EXISTS receipts (key TEXT PRIMARY KEY, digest TEXT NOT NULL, message_id TEXT NOT NULL, received_at TEXT NOT NULL, size INTEGER NOT NULL, expires_at INTEGER NOT NULL)",
    );
    this.sql.exec(
      "CREATE INDEX IF NOT EXISTS receipt_expiry ON receipts(expires_at)",
    );
  }
  private prune(now: number): void {
    this.sql.exec("DELETE FROM messages WHERE expires_at <= ?", now);
    this.sql.exec("DELETE FROM receipts WHERE expires_at <= ?", now);
  }
  private async scheduleCleanup(): Promise<void> {
    const row = this.sql
      .exec<{ expiry: number | null }>(
        "SELECT MIN(expires_at) AS expiry FROM (SELECT expires_at FROM messages UNION ALL SELECT expires_at FROM receipts)",
      )
      .toArray()[0];
    if (row?.expiry !== null && row?.expiry !== undefined)
      await this.state.storage.setAlarm(
        Math.max(Date.now() + 1000, row.expiry),
      );
  }
  async alarm(): Promise<void> {
    this.state.storage.transactionSync(() => this.prune(Date.now()));
    await this.scheduleCleanup();
  }
  async fetch(request: Request): Promise<Response> {
    try {
      return await this.handle(request);
    } catch (error) {
      if (error instanceof RequestError)
        return failure(error.status, error.code, error.message);
      console.log(JSON.stringify({ event: "mailbox_storage_error" }));
      return failure(503, "unavailable", "Mailbox storage unavailable");
    }
  }
  private async handle(request: Request): Promise<Response> {
    const url = new URL(request.url),
      method = request.method;
    const fp = url.pathname.split("/")[2];
    if (!/^[a-f0-9]{64}$/.test(fp ?? ""))
      throw new RequestError(400, "bad_request", "Invalid mailbox");
    const register = url.pathname.endsWith("/register"),
      allowlist = url.pathname.endsWith("/allowlist");
    const admin =
      (method === "POST" && register) || (method === "PUT" && allowlist);
    if (admin) await requireAdmin(request, this.env);
    let body: Record<string, unknown> | undefined;
    if ((method === "POST" && !register) || method === "PUT")
      body = await readJson(
        request,
        positiveInt(this.env.MAX_ENVELOPE_SIZE, "MAX_ENVELOPE_SIZE"),
      );
    const tokenHash = await hash(bearer(request));
    const newToken = register ? crypto.randomUUID() + crypto.randomUUID() : "";
    const newHash = register ? await hash(newToken) : "";
    const payload = body ? JSON.stringify(body) : "";
    const digest = body ? await hash(payload) : "";
    const retryKey = request.headers.get("Idempotency-Key");
    if (retryKey !== null && !/^[A-Za-z0-9._:-]{1,128}$/.test(retryKey))
      throw new RequestError(400, "bad_request", "Invalid Idempotency-Key");
    const now = Date.now(),
      receivedAt = new Date(now).toISOString(),
      messageId = crypto.randomUUID();
    const response = this.state.storage.transactionSync(() => {
      this.prune(now);
      const meta = this.sql
        .exec<Meta>("SELECT token_hash, allowed_senders FROM auth WHERE id=1")
        .toArray()[0];
      if (register && method === "POST") {
        this.sql.exec(
          "INSERT INTO auth (id,token_hash,allowed_senders) VALUES (1,?,'[]') ON CONFLICT(id) DO UPDATE SET token_hash=excluded.token_hash",
          newHash,
        );
        return json(
          {
            mailbox: fp,
            token: newToken,
            message:
              "Store this credential securely; it cannot be retrieved again.",
          },
          201,
        );
      }
      if (!meta)
        throw new RequestError(
          method === "GET" || method === "DELETE" ? 401 : 404,
          "unregistered",
          "Mailbox registration required",
        );
      if (method === "GET" || method === "DELETE") {
        if (!bearer(request) || !equalHashes(tokenHash, meta.token_hash))
          throw new RequestError(401, "unauthorized", "Mailbox token required");
      }
      if (method === "PUT" && allowlist) {
        const senders = body?.allowed_senders;
        if (
          !Array.isArray(senders) ||
          senders.length > 1000 ||
          senders.some(
            (fp) => typeof fp !== "string" || !/^[a-f0-9]{64}$/.test(fp),
          )
        )
          throw new RequestError(
            400,
            "bad_request",
            "allowed_senders must be an array of fingerprints (maximum 1000)",
          );
        this.sql.exec(
          "UPDATE auth SET allowed_senders=? WHERE id=1",
          JSON.stringify(senders),
        );
        return json({
          mailbox: fp,
          allowed_senders: senders,
          mode: senders.length ? "allowlist" : "open",
        });
      }
      if (method === "POST" && !register) {
        if (
          !body ||
          ["version", "suite", "ciphertext"].some(
            (key) => typeof body![key] !== "string" || !body![key],
          )
        )
          throw new RequestError(
            400,
            "bad_request",
            "Required envelope fields must be non-empty strings",
          );
        const senders: unknown = JSON.parse(meta.allowed_senders);
        if (!Array.isArray(senders)) throw Error("Corrupt advisory policy");
        const sender = body.sender_key_fingerprint ?? "";
        if (typeof sender !== "string")
          throw new RequestError(
            400,
            "bad_request",
            "Invalid sender fingerprint",
          );
        if (senders.length && !senders.includes(sender))
          throw new RequestError(
            403,
            "forbidden",
            "Sender not in advisory allowlist",
          );
        if (retryKey) {
          const receipt = this.sql
            .exec<Receipt>("SELECT * FROM receipts WHERE key=?", retryKey)
            .toArray()[0];
          if (receipt) {
            if (receipt.digest !== digest)
              throw new RequestError(
                409,
                "conflict",
                "Idempotency key already used with a different envelope",
              );
            return json(
              {
                id: receipt.message_id,
                recipient_fp: fp,
                received_at: receipt.received_at,
                size: receipt.size,
              },
              201,
            );
          }
        }
        const max = positiveInt(
          this.env.MAX_MESSAGES_PER_MAILBOX,
          "MAX_MESSAGES_PER_MAILBOX",
        );
        const count = this.sql
          .exec<{ n: number }>("SELECT COUNT(*) AS n FROM messages")
          .toArray()[0].n;
        if (count >= max)
          throw new RequestError(
            429,
            "mailbox_full",
            "Mailbox capacity reached",
          );
        if (
          retryKey &&
          this.sql
            .exec<{ n: number }>("SELECT COUNT(*) AS n FROM receipts")
            .toArray()[0].n >= 50000
        )
          throw new RequestError(
            429,
            "retry_cache_full",
            "Retry receipt capacity reached",
          );
        const ttl = positiveInt(
          this.env.MESSAGE_TTL_SECONDS,
          "MESSAGE_TTL_SECONDS",
        );
        const expiry = now + ttl * 1000;
        if (!Number.isSafeInteger(expiry))
          throw new RequestError(400, "bad_request", "Invalid message TTL");
        const size = new TextEncoder().encode(payload).byteLength;
        this.sql.exec(
          "INSERT INTO messages VALUES (?,?,?,?,?,?)",
          messageId,
          payload,
          receivedAt,
          expiry,
          sender,
          size,
        );
        if (retryKey)
          this.sql.exec(
            "INSERT INTO receipts VALUES (?,?,?,?,?,?)",
            retryKey,
            digest,
            messageId,
            receivedAt,
            size,
            expiry,
          );
        return json(
          { id: messageId, recipient_fp: fp, received_at: receivedAt, size },
          201,
        );
      }
      if (method === "GET") {
        const limit = Math.min(
          positiveInt(url.searchParams.get("limit") ?? "10", "limit"),
          100,
        );
        const after = url.searchParams.get("after") ?? "";
        if (after && !/^[a-f0-9-]{36}$/.test(after))
          throw new RequestError(400, "bad_request", "Invalid cursor");
        const rows = this.sql
          .exec<Message>(
            "SELECT * FROM messages WHERE id>? ORDER BY id LIMIT ?",
            after,
            limit + 1,
          )
          .toArray();
        const messages = rows
          .slice(0, limit)
          .map((row) => ({
            id: row.id,
            received_at: row.received_at,
            sender_fp: row.sender_fp,
            size: row.size,
            envelope: JSON.parse(row.envelope),
          }));
        return json({
          mailbox: fp,
          count: messages.length,
          messages,
          next_cursor:
            rows.length > limit ? messages[messages.length - 1].id : null,
        });
      }
      if (method === "DELETE") {
        const id = url.pathname.split("/")[3];
        const existing = this.sql
          .exec<{ id: string }>("SELECT id FROM messages WHERE id=?", id)
          .toArray()[0];
        if (!existing)
          throw new RequestError(404, "not_found", "Message not found");
        this.sql.exec("DELETE FROM messages WHERE id=?", id);
        return json({ deleted: id });
      }
      throw new RequestError(404, "not_found", "Unknown endpoint");
    });
    // A failed housekeeping alarm must not turn a committed deposit into a 500.
    try {
      await this.scheduleCleanup();
    } catch {
      console.log(JSON.stringify({ event: "mailbox_alarm_error" }));
    }
    return response;
  }
}
