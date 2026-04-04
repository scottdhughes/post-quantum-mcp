# Quantum Seal Relay — Transport Spec

## Overview

Opaque envelope mailbox relay. Stores and forwards PQC-sealed envelopes
between agents without accessing private keys or decrypted content.
The relay is a dumb pipe — it never performs cryptographic operations.

## Endpoints

### POST /mailboxes/:recipient_fp

Deposit an envelope into a recipient's mailbox.

**Path params:**
- `recipient_fp` — SHA3-256 hex fingerprint of recipient's classical public key (64 chars)

**Request body:** Raw JSON envelope (as produced by `pqc_hybrid_auth_seal`)

**Response:**
```json
{
  "id": "<server-generated UUID>",
  "recipient_fp": "<fingerprint>",
  "received_at": "<ISO-8601>",
  "size": 9087
}
```

**Status codes:**
- `201 Created` — envelope stored
- `400 Bad Request` — missing/invalid body, exceeds size limit
- `403 Forbidden` — sender not in allowlist (if configured)
- `413 Payload Too Large` — body exceeds 50KB
- `429 Too Many Requests` — rate limited

### GET /mailboxes/:recipient_fp

Fetch pending envelopes for a recipient.

**Query params:**
- `limit` — max envelopes to return (default 10, max 100)
- `after` — cursor for pagination (message ID)

**Response:**
```json
{
  "mailbox": "<fingerprint>",
  "count": 3,
  "messages": [
    {
      "id": "<UUID>",
      "received_at": "<ISO-8601>",
      "sender_fp": "<fingerprint from envelope metadata>",
      "size": 9087,
      "envelope": { ... }
    }
  ],
  "next_cursor": "<UUID or null>"
}
```

**Status codes:**
- `200 OK` — messages returned (may be empty)
- `404 Not Found` — mailbox does not exist (optional — or return empty)

### DELETE /mailboxes/:recipient_fp/:message_id

Acknowledge receipt and remove a message.

**Response:**
```json
{
  "deleted": "<message_id>"
}
```

**Status codes:**
- `200 OK` — deleted
- `404 Not Found` — message not found

## Limits

| Limit | Value | Rationale |
|-------|-------|-----------|
| Max envelope size | 50 KB | Largest auth-seal envelope is ~22KB |
| Max messages per mailbox | 1000 | Prevents unbounded storage |
| Max mailboxes | 10,000 | Prevents abuse |
| Message TTL | 24 hours | Aligns with replay cache TTL |
| Rate limit (POST) | 60/min per IP | Prevents flooding |
| Rate limit (GET) | 120/min per IP | Allows reasonable polling |

## Retention

- Messages expire after 24 hours (server-side TTL)
- Expired messages are purged on next access or periodic cleanup
- Deletion via DELETE is immediate

## Sender Filtering

Optional allowlist per mailbox:

### PUT /mailboxes/:recipient_fp/allowlist

```json
{
  "allowed_senders": ["<sender_fp_1>", "<sender_fp_2>"]
}
```

When configured, POST checks `envelope.sender_key_fingerprint` against
the allowlist before storing. Unknown senders get `403 Forbidden`.

When not configured, all senders are accepted (open mailbox).

## Security Properties

- **Relay sees:** envelope metadata (version, mode, fingerprints, sizes)
- **Relay never sees:** plaintext, secret keys, shared secrets
- **Relay does not verify:** signatures, timestamps, or crypto
- **Integrity:** envelope is stored and returned byte-identical
- **Confidentiality:** ciphertext is opaque to the relay
- **No protocol changes:** v3 envelope format is unchanged

## Storage Backend

Cloudflare R2 (object storage) or KV (key-value):

- **R2:** better for large envelopes, cheaper storage, no TTL built-in
- **KV:** built-in TTL (expirationTtl), 25MB value limit, simpler API

**Recommendation:** KV for MVP (simpler, has built-in TTL).

Key format: `mailbox:{recipient_fp}:msg:{uuid}`
Metadata: `mailbox:{recipient_fp}:meta` (allowlist, config)

## Error Format

All errors return:
```json
{
  "error": "<short code>",
  "message": "<human-readable description>"
}
```
