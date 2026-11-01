import { describe, it, expect } from "vitest";
import { runInDurableObject, evictDurableObject } from "cloudflare:test";
import { env, exports } from "cloudflare:workers";

const ADMIN = "local-admin-secret";
const ENVELOPE = {
  version: "pqc-mcp-v3",
  mode: "anon-seal",
  suite: "mlkem768-x25519-sha3-256",
  ciphertext: "dGVzdA==",
};
const freshFp = () => crypto.randomUUID().replaceAll("-", "").repeat(2);
function request(
  fp: string,
  method = "GET",
  suffix = "",
  body?: unknown,
  token?: string,
  extra: Record<string, string> = {},
) {
  return exports.default.fetch(
    new Request(`https://relay/mailboxes/${fp}${suffix}`, {
      method,
      headers: {
        "Content-Type": "application/json",
        "CF-Connecting-IP": fp,
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...extra,
      },
      ...(body === undefined ? {} : { body: JSON.stringify(body) }),
    }),
  );
}
async function registered() {
  const fp = freshFp();
  const response = await request(fp, "POST", "/register", undefined, ADMIN);
  expect(response.status).toBe(201);
  const data = (await response.json()) as { token: string };
  return { fp, token: data.token };
}

describe("transactional relay in workerd", () => {
  it("reports service health", async () => {
    const response = await exports.default.fetch("https://relay/health");
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      protocol: "pqc-mcp-v3",
      storage: "durable-objects-sqlite",
    });
  });
  it("fails closed for unknown mailboxes and unauthorized registration", async () => {
    const fp = freshFp();
    expect((await request(fp)).status).toBe(401);
    expect((await request(fp, "POST", "", ENVELOPE)).status).toBe(404);
    expect((await request(fp, "POST", "/register")).status).toBe(401);
  });
  it("stores, authenticates, fetches, and acknowledges", async () => {
    const { fp, token } = await registered();
    const post = await request(fp, "POST", "", ENVELOPE);
    expect(post.status).toBe(201);
    const { id } = (await post.json()) as { id: string };
    expect((await request(fp)).status).toBe(401);
    expect(
      (await request(fp, "GET", "", undefined, "wrong-token")).status,
    ).toBe(401);
    const data = (await (
      await request(fp, "GET", "", undefined, token)
    ).json()) as { count: number; messages: { envelope: unknown }[] };
    expect(data.count).toBe(1);
    expect(data.messages[0].envelope).toEqual(ENVELOPE);
    expect((await request(fp, "DELETE", `/${id}`)).status).toBe(401);
    expect(
      (await request(fp, "DELETE", `/${id}`, undefined, token)).status,
    ).toBe(200);
    expect(
      (await request(fp, "DELETE", `/${id}`, undefined, token)).status,
    ).toBe(404);
  });
  it("rotates credentials without reopening mailbox reads", async () => {
    const { fp, token } = await registered();
    const rotated = (await (
      await request(fp, "POST", "/register", undefined, ADMIN)
    ).json()) as { token: string };
    expect((await request(fp, "GET", "", undefined, token)).status).toBe(401);
    expect((await request(fp)).status).toBe(401);
    expect(
      (await request(fp, "GET", "", undefined, rotated.token)).status,
    ).toBe(200);
  });
  it("deduplicates concurrent retries transactionally", async () => {
    const { fp, token } = await registered();
    const responses = await Promise.all(
      Array.from({ length: 5 }, () =>
        request(fp, "POST", "", ENVELOPE, undefined, {
          "Idempotency-Key": "same-retry",
        }),
      ),
    );
    expect(responses.every((r) => r.status === 201)).toBe(true);
    const ids = await Promise.all(
      responses.map(async (r) => ((await r.json()) as { id: string }).id),
    );
    expect(new Set(ids).size).toBe(1);
    expect(
      await (await request(fp, "GET", "", undefined, token)).json(),
    ).toMatchObject({ count: 1 });
    expect(
      (
        await request(
          fp,
          "POST",
          "",
          { ...ENVELOPE, ciphertext: "different" },
          undefined,
          { "Idempotency-Key": "same-retry" },
        )
      ).status,
    ).toBe(409);
  });
  it("rejects malformed bodies, byte oversize, and invalid pagination", async () => {
    const { fp, token } = await registered();
    for (const body of [null, [], { foo: "bar" }])
      expect((await request(fp, "POST", "", body)).status).toBe(400);
    expect(
      (
        await request(fp, "POST", "", {
          ...ENVELOPE,
          ciphertext: "é".repeat(26000),
        })
      ).status,
    ).toBe(413);
    expect(
      (await request(fp, "GET", "?limit=0", undefined, token)).status,
    ).toBe(400);
  });
  it("advisory sender filters never remove authentication", async () => {
    const { fp, token } = await registered();
    const sender = freshFp();
    expect(
      (await request(fp, "PUT", "/allowlist", { allowed_senders: [sender] }))
        .status,
    ).toBe(401);
    expect(
      (
        await request(
          fp,
          "PUT",
          "/allowlist",
          { allowed_senders: [sender] },
          ADMIN,
        )
      ).status,
    ).toBe(200);
    expect((await request(fp, "POST", "", ENVELOPE)).status).toBe(403);
    expect(
      (
        await request(fp, "POST", "", {
          ...ENVELOPE,
          sender_key_fingerprint: sender,
        })
      ).status,
    ).toBe(201);
    expect((await request(fp)).status).toBe(401);
    expect((await request(fp, "GET", "", undefined, token)).status).toBe(200);
  });
  it("expiry and actor eviction preserve mailbox credentials", async () => {
    const { fp, token } = await registered();
    const deposited = await request(fp, "POST", "", ENVELOPE);
    expect(deposited.status).toBe(201);
    await deposited.arrayBuffer();
    const stub = env.MAILBOXES.get(env.MAILBOXES.idFromName(fp));
    await runInDurableObject(stub, async (_instance, state) => {
      state.storage.sql.exec("UPDATE messages SET expires_at=0");
    });
    await evictDurableObject(stub);
    expect((await request(fp)).status).toBe(401);
    expect(
      await (await request(fp, "GET", "", undefined, token)).json(),
    ).toMatchObject({ count: 0 });
  });
  it("concurrent deposits enforce a full mailbox quota", async () => {
    const { fp } = await registered();
    const stub = env.MAILBOXES.get(env.MAILBOXES.idFromName(fp));
    await runInDurableObject(stub, async (_instance, state) => {
      for (let i = 0; i < 999; i++)
        state.storage.sql.exec(
          "INSERT INTO messages VALUES (?,?,?,?,?,?)",
          `seed-${i}`,
          JSON.stringify(ENVELOPE),
          new Date().toISOString(),
          Date.now() + 86400000,
          "",
          100,
        );
    });
    const replies = await Promise.all(
      Array.from({ length: 6 }, () => request(fp, "POST", "", ENVELOPE)),
    );
    expect(replies.filter((r) => r.status === 201).length).toBe(1);
    expect(replies.filter((r) => r.status === 429).length).toBe(5);
  });
});
