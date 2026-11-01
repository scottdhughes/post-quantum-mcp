import { test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import worker, * as classes from "../dist/local-worker.mjs";
const { Mailbox, RateLimiter } = classes;

// Real SQLite; adapter exposes the Cloudflare SQL storage cursor/transaction API.
function state() {
  const db = new DatabaseSync(":memory:");
  return {
    storage: {
      sql: {
        exec(query, ...params) {
          const rows = db.prepare(query).all(...params);
          return {
            toArray: () => rows,
            [Symbol.iterator]: () => rows[Symbol.iterator](),
          };
        },
      },
      transactionSync(fn) {
        db.exec("BEGIN");
        try {
          const value = fn();
          db.exec("COMMIT");
          return value;
        } catch (error) {
          db.exec("ROLLBACK");
          throw error;
        }
      },
      setAlarm: async () => {},
    },
  };
}
function setup(overrides = {}) {
  const objects = new Map();
  const legacy = new Map();
  const env = {
    MAILBOX: {
      get: async (k) => legacy.get(k) ?? null,
      put: async (k, v) => legacy.set(k, v),
      delete: async (k) => legacy.delete(k),
      list: async () => ({ keys: [], list_complete: true }),
    },
    MAX_ENVELOPE_SIZE: "51200",
    MAX_MESSAGES_PER_MAILBOX: "2",
    MESSAGE_TTL_SECONDS: "86400",
    RATE_LIMIT_POST_PER_MIN: "60",
    RATE_LIMIT_GET_PER_MIN: "120",
    RELAY_ADMIN_TOKEN: "local-admin-secret",
    ...overrides,
  };
  for (const [binding, Class] of [
    ["MAILBOXES", Mailbox],
    ["RATE_LIMITERS", RateLimiter],
  ]) {
    env[binding] = {
      idFromName: (name) => `${binding}:${name}`,
      get(id) {
        if (!objects.has(id)) objects.set(id, new Class(state(), env));
        return {
          fetch: (input, init) =>
            objects
              .get(id)
              .fetch(
                input instanceof Request ? input : new Request(input, init),
              ),
        };
      },
    };
  }
  const fp = "a".repeat(64),
    base = `https://relay.invalid/mailboxes/${fp}`;
  const request = (method = "GET", suffix = "", body, token, extra = {}) =>
    worker.fetch(
      new Request(base + suffix, {
        method,
        headers: {
          "CF-Connecting-IP": "192.0.2.5",
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
          ...extra,
        },
        ...(body === undefined ? {} : { body: JSON.stringify(body) }),
      }),
      env,
    );
  return { env, request, objects, base };
}
const envelope = {
  version: "pqc-mcp-v3",
  suite: "test-suite",
  ciphertext: "test",
};
async function register(ctx) {
  const response = await ctx.request(
    "POST",
    "/register",
    undefined,
    "local-admin-secret",
  );
  assert.equal(response.status, 201);
  return (await response.json()).token;
}

test("unregistered mailboxes fail closed; placeholder admin token is rejected", async () => {
  const ctx = setup();
  assert.equal((await ctx.request()).status, 401);
  assert.equal((await ctx.request("POST", "", envelope)).status, 404);
  const unsafe = setup({
    RELAY_ADMIN_TOKEN: "test-admin-token-do-not-use-in-production",
  });
  assert.equal(
    (
      await unsafe.request(
        "POST",
        "/register",
        undefined,
        "test-admin-token-do-not-use-in-production",
      )
    ).status,
    503,
  );
});

test("registration persists across message expiry and object restart; token rotation is authoritative", async () => {
  const ctx = setup(),
    token = await register(ctx);
  assert.equal((await ctx.request("POST", "", envelope)).status, 201);
  assert.equal((await ctx.request()).status, 401);
  const id = ctx.env.MAILBOXES.idFromName("a".repeat(64));
  const original = ctx.objects.get(id);
  original.state.storage.sql.exec("UPDATE messages SET expires_at=0");
  ctx.objects.set(id, new Mailbox(original.state, ctx.env));
  const response = await ctx.request("GET", "", undefined, token);
  assert.equal(response.status, 200);
  assert.equal((await response.json()).count, 0);
  const next = await register(ctx);
  assert.equal((await ctx.request("GET", "", undefined, token)).status, 401);
  assert.equal((await ctx.request("GET", "", undefined, next)).status, 200);
});

test("concurrent deposits enforce capacity and release it on ack", async () => {
  const ctx = setup(),
    token = await register(ctx);
  const replies = await Promise.all(
    Array.from({ length: 8 }, (_, i) =>
      ctx.request("POST", "", { ...envelope, ciphertext: String(i) }),
    ),
  );
  assert.equal(replies.filter((r) => r.status === 201).length, 2);
  assert.equal(replies.filter((r) => r.status === 429).length, 6);
  const messages = (
    await (await ctx.request("GET", "", undefined, token)).json()
  ).messages;
  assert.equal(messages.length, 2);
  assert.equal(
    (await ctx.request("DELETE", `/${messages[0].id}`, undefined)).status,
    401,
  );
  assert.equal(
    (await ctx.request("DELETE", `/${messages[0].id}`, undefined, token))
      .status,
    200,
  );
  assert.equal((await ctx.request("POST", "", envelope)).status, 201);
});

test("idempotency keys deduplicate retries, reject conflicting payloads, and survive ack", async () => {
  const ctx = setup(),
    token = await register(ctx),
    headers = { "Idempotency-Key": "retry-1" };
  const a = await (
    await ctx.request("POST", "", envelope, undefined, headers)
  ).json();
  const b = await (
    await ctx.request("POST", "", envelope, undefined, headers)
  ).json();
  assert.equal(a.id, b.id);
  assert.equal(
    (
      await ctx.request(
        "POST",
        "",
        { ...envelope, ciphertext: "different" },
        undefined,
        headers,
      )
    ).status,
    409,
  );
  await ctx.request("DELETE", `/${a.id}`, undefined, token);
  const c = await (
    await ctx.request("POST", "", envelope, undefined, headers)
  ).json();
  assert.equal(a.id, c.id);
  assert.equal(
    (await (await ctx.request("GET", "", undefined, token)).json()).count,
    0,
  );
});

test("advisory filter changes preserve authorization", async () => {
  const ctx = setup(),
    token = await register(ctx);
  assert.equal(
    (
      await ctx.request(
        "PUT",
        "/allowlist",
        { allowed_senders: ["b".repeat(64)] },
        "local-admin-secret",
      )
    ).status,
    200,
  );
  assert.equal((await ctx.request("POST", "", envelope)).status, 403);
  assert.equal(
    (
      await ctx.request("POST", "", {
        ...envelope,
        sender_key_fingerprint: "b".repeat(64),
      })
    ).status,
    201,
  );
  assert.equal((await ctx.request()).status, 401);
  assert.equal((await ctx.request("GET", "", undefined, token)).status, 200);
});

test("malformed, oversized UTF-8 bodies and invalid pagination are structured errors", async () => {
  const ctx = setup(),
    token = await register(ctx);
  for (const body of [null, [], { version: 1, suite: "s", ciphertext: "c" }])
    assert.equal((await ctx.request("POST", "", body)).status, 400);
  assert.equal(
    (
      await ctx.request("POST", "", {
        ...envelope,
        ciphertext: "é".repeat(26000),
      })
    ).status,
    413,
  );
  assert.equal(
    (await ctx.request("PUT", "/allowlist", null, "local-admin-secret")).status,
    400,
  );
  for (const query of ["?limit=0", "?limit=NaN", "?limit=-1", "?after=invalid"])
    assert.equal(
      (await ctx.request("GET", query, undefined, token)).status,
      400,
    );
});

test("rate limiter enforces a burst and storage failures fail closed", async () => {
  const ctx = setup({ RATE_LIMIT_POST_PER_MIN: "2" });
  await register(ctx);
  const replies = await Promise.all(
    Array.from({ length: 6 }, () => ctx.request("POST", "", envelope)),
  );
  assert.equal(replies.filter((r) => r.status === 429).length, 4);
  ctx.env.RATE_LIMITERS = {
    idFromName: (x) => x,
    get: () => ({
      fetch: async () => {
        throw Error("storage unavailable");
      },
    }),
  };
  assert.equal((await ctx.request()).status, 503);
});

test("failed housekeeping cannot turn a committed deposit into an error", async () => {
  const ctx = setup(),
    token = await register(ctx);
  const object = ctx.objects.get(ctx.env.MAILBOXES.idFromName("a".repeat(64)));
  object.state.storage.setAlarm = async () => {
    throw Error("alarm unavailable");
  };
  assert.equal((await ctx.request("POST", "", envelope)).status, 201);
  assert.equal(
    (await (await ctx.request("GET", "", undefined, token)).json()).count,
    1,
  );
});

test("pagination has stable cursors and quotas work above the old KV page limit", async () => {
  const ctx = setup({ MAX_MESSAGES_PER_MAILBOX: "1001" }),
    token = await register(ctx);
  const object = ctx.objects.get(ctx.env.MAILBOXES.idFromName("a".repeat(64)));
  for (let i = 0; i < 1000; i++)
    object.state.storage.sql.exec(
      "INSERT INTO messages VALUES (?,?,?,?,?,?)",
      `${String(i).padStart(8, "0")}-0000-0000-0000-000000000000`,
      JSON.stringify(envelope),
      "today",
      Date.now() + 60000,
      "",
      1,
    );
  assert.equal((await ctx.request("POST", "", envelope)).status, 201);
  assert.equal((await ctx.request("POST", "", envelope)).status, 429);
  const first = await (
    await ctx.request("GET", "?limit=100", undefined, token)
  ).json();
  assert.equal(first.count, 100);
  assert.ok(first.next_cursor);
  const second = await (
    await ctx.request(
      "GET",
      "?limit=100&after=" + first.next_cursor,
      undefined,
      token,
    )
  ).json();
  assert.equal(second.count, 100);
  assert.notEqual(first.messages[0].id, second.messages[0].id);
});
