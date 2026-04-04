import { describe, it, expect } from "vitest";
import { SELF } from "cloudflare:test";

const VALID_FP = "a".repeat(64);
const VALID_FP_2 = "b".repeat(64);

const MINIMAL_ENVELOPE = JSON.stringify({
  version: "pqc-mcp-v3",
  mode: "auth-seal",
  suite: "mlkem768-x25519-sha3-256",
  sender_signature_algorithm: "ML-DSA-65",
  sender_public_key: "dGVzdA==",
  sender_key_fingerprint: VALID_FP_2,
  recipient_classical_key_fingerprint: VALID_FP,
  recipient_pqc_key_fingerprint: "c".repeat(64),
  x25519_ephemeral_public_key: "dGVzdA==",
  pqc_ciphertext: "dGVzdA==",
  ciphertext: "dGVzdA==",
  timestamp: "1711929600",
  signature: "dGVzdA==",
});

describe("Health Check", () => {
  it("returns service info", async () => {
    const resp = await SELF.fetch("https://relay/");
    expect(resp.status).toBe(200);
    const data = await resp.json() as Record<string, string>;
    expect(data.service).toBe("quantum-seal-relay");
    expect(data.protocol).toBe("pqc-mcp-v3");
  });
});

describe("POST /mailboxes/:fp", () => {
  it("accepts a valid envelope", async () => {
    const resp = await SELF.fetch(`https://relay/mailboxes/${VALID_FP}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: MINIMAL_ENVELOPE,
    });
    expect(resp.status).toBe(201);
    const data = await resp.json() as Record<string, unknown>;
    expect(data.id).toBeTruthy();
    expect(data.recipient_fp).toBe(VALID_FP);
  });

  it("rejects invalid JSON", async () => {
    const resp = await SELF.fetch(`https://relay/mailboxes/${VALID_FP}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "not json!!!",
    });
    expect(resp.status).toBe(400);
  });

  it("rejects envelope missing required fields", async () => {
    const resp = await SELF.fetch(`https://relay/mailboxes/${VALID_FP}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ foo: "bar" }),
    });
    expect(resp.status).toBe(400);
  });

  it("rejects invalid fingerprint in path", async () => {
    const resp = await SELF.fetch("https://relay/mailboxes/not-a-fingerprint", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: MINIMAL_ENVELOPE,
    });
    expect(resp.status).toBe(404);
  });

  it("rejects oversized envelope", async () => {
    const huge = JSON.stringify({
      version: "pqc-mcp-v3",
      suite: "mlkem768-x25519-sha3-256",
      ciphertext: "x".repeat(60000),
    });
    const resp = await SELF.fetch(`https://relay/mailboxes/${VALID_FP}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: huge,
    });
    expect(resp.status).toBe(413);
  });
});

describe("GET /mailboxes/:fp", () => {
  it("returns empty mailbox", async () => {
    const fp = "d".repeat(64);
    const resp = await SELF.fetch(`https://relay/mailboxes/${fp}`);
    expect(resp.status).toBe(200);
    const data = await resp.json() as Record<string, unknown>;
    expect(data.count).toBe(0);
  });

  it("returns deposited envelope", async () => {
    const fp = "e".repeat(64);
    // Deposit
    await SELF.fetch(`https://relay/mailboxes/${fp}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: MINIMAL_ENVELOPE,
    });
    // Fetch
    const resp = await SELF.fetch(`https://relay/mailboxes/${fp}`);
    expect(resp.status).toBe(200);
    const data = await resp.json() as { count: number; messages: Array<{ envelope: Record<string, string> }> };
    expect(data.count).toBe(1);
    expect(data.messages[0].envelope.version).toBe("pqc-mcp-v3");
  });
});

describe("DELETE /mailboxes/:fp/:id", () => {
  it("deletes a deposited message", async () => {
    const fp = "f".repeat(64);
    // Deposit
    const postResp = await SELF.fetch(`https://relay/mailboxes/${fp}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: MINIMAL_ENVELOPE,
    });
    const postData = await postResp.json() as { id: string };

    // Delete
    const delResp = await SELF.fetch(`https://relay/mailboxes/${fp}/${postData.id}`, {
      method: "DELETE",
    });
    expect(delResp.status).toBe(200);

    // Verify gone
    const getResp = await SELF.fetch(`https://relay/mailboxes/${fp}`);
    const getData = await getResp.json() as { count: number };
    expect(getData.count).toBe(0);
  });

  it("returns 404 for nonexistent message", async () => {
    const fp = "f".repeat(64);
    const resp = await SELF.fetch(
      `https://relay/mailboxes/${fp}/00000000-0000-0000-0000-000000000000`,
      { method: "DELETE" }
    );
    expect(resp.status).toBe(404);
  });
});

describe("PUT /mailboxes/:fp/allowlist", () => {
  const ADMIN_TOKEN = "test-admin-token";
  const adminHeaders = {
    "Content-Type": "application/json",
    "Authorization": `Bearer ${ADMIN_TOKEN}`,
  };

  it("rejects unauthenticated allowlist mutation", async () => {
    const fp = "1".repeat(64);
    const resp = await SELF.fetch(`https://relay/mailboxes/${fp}/allowlist`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ allowed_senders: [VALID_FP_2] }),
    });
    expect(resp.status).toBe(401);
  });

  it("configures sender allowlist with admin auth", async () => {
    const fp = "1".repeat(64);
    const resp = await SELF.fetch(`https://relay/mailboxes/${fp}/allowlist`, {
      method: "PUT",
      headers: adminHeaders,
      body: JSON.stringify({ allowed_senders: [VALID_FP_2] }),
    });
    expect(resp.status).toBe(200);
    const data = await resp.json() as { mode: string };
    expect(data.mode).toBe("allowlist");
  });

  it("blocks non-allowlisted sender", async () => {
    const fp = "2".repeat(64);
    // Set allowlist with admin auth
    await SELF.fetch(`https://relay/mailboxes/${fp}/allowlist`, {
      method: "PUT",
      headers: adminHeaders,
      body: JSON.stringify({ allowed_senders: ["c".repeat(64)] }),
    });
    // Try to send from non-allowlisted sender
    const resp = await SELF.fetch(`https://relay/mailboxes/${fp}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: MINIMAL_ENVELOPE,  // sender_fp is VALID_FP_2, not "c"*64
    });
    expect(resp.status).toBe(403);
  });
});
