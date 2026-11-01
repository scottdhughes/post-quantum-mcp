# Quantum Seal relay v0.2 — transactional transport contract

Updated November 1, 2026. Envelope cryptography remains `pqc-mcp-v3`.
This describes the repaired source; it does not assert that an existing public
Worker has been upgraded.

## Storage and authorization

`MAILBOXES` is a SQLite-backed Durable Object namespace. One actor per recipient
fingerprint owns authorization, advisory sender filters, message rows, and retry
receipts. All reads and mutations of that state are transactional. Registration
is required; unknown mailboxes have no anonymous read/delete fallback.

`RATE_LIMITERS` is a separate SQLite-backed Durable Object namespace, one actor
per client IP. The legacy `MAILBOX` KV binding is retained for an operator-controlled
migration; new routes never read or write it.

Mailbox tokens are 72-character random UUID pairs. Only SHA-256 token hashes are
stored. Authorization rows have no TTL. Message cleanup never changes credentials.
Admin registration rotates the mailbox token while preserving messages and filters.
All tokens grant access only to the corresponding mailbox or operator endpoints;
this is transport access control, not end-to-end sender authentication.

Provision an admin secret with `wrangler secret put RELAY_ADMIN_TOKEN` before
using admin endpoints. It must have at least 16 characters. Missing credentials
and the historical development placeholder fail closed with 503. Tests inject
an isolated synthetic credential; no usable admin value is in deployable vars.

## Endpoints

Fingerprints must be 64 lowercase hex characters. Message IDs are UUIDs.
All response bodies are JSON, with `Cache-Control: no-store`. Responses include
permissive CORS; credentials must be explicitly supplied as bearer headers.
The service never sends tokens in URLs.

| Endpoint | Method | Authorization | Success |
|---|---|---|---|
| `/health` or `/` | GET | None | Service/protocol/storage information |
| `/mailboxes/:fp/register` | POST | Admin bearer | 201 `{mailbox, token, message}`; raw token returned once |
| `/mailboxes/:fp` | POST | Existing registered mailbox; no bearer needed | 201 `{id, recipient_fp, received_at, size}` |
| `/mailboxes/:fp` | GET | Mailbox bearer | 200 `{mailbox,count,messages,next_cursor}` |
| `/mailboxes/:fp/:id` | DELETE | Mailbox bearer | 200 `{deleted}`; 404 if already absent |
| `/mailboxes/:fp/allowlist` | PUT | Admin bearer | 200 `{mailbox,allowed_senders,mode}` |

GET/DELETE on an unregistered mailbox return 401. Deposits to one return 404.
Invalid credentials return 401. Invalid bodies/parameters return 400; oversized
bodies return 413; quota/rate exhaustion returns 429; storage unavailability
returns 503. Unsupported methods return 405. Expected validation errors never
fall through to an uncaught JavaScript exception.

### Deposit and retry behavior

The envelope must be a JSON object with nonempty string `version`, `suite`, and
`ciphertext` fields. The relay does not verify cryptography. It measures UTF-8
request bytes while streaming and cancels reads at the configured limit; it does
not rely on Content-Length. Stored size describes canonicalized JSON bytes.

An optional `Idempotency-Key` header must match `[A-Za-z0-9._:-]{1,128}`. Within
the original message TTL, the same key and identical serialized envelope return
the original receipt without inserting another message. Reusing a key for a
different payload returns 409. Acknowledgment leaves the retry receipt until
expiry, preventing a delayed retry from resurrecting an acknowledged message.
There are at most 50,000 unexpired receipts per mailbox; at capacity new keyed
deposits return 429 rather than evict live receipts.

The Python client sorts JSON keys, emits compact UTF-8 JSON, and uses its SHA-256
as the idempotency key. Repeating the same sealed envelope is a retry; resealing
creates a fresh envelope/message. Other clients should preserve exact serialized
payloads for retries. Without a key, repeated deposits are independent messages.
After receipt expiry a key may be reused. Permanent exactly-once delivery is not
promised.

Message insertion and receipt insertion share one transaction. Failed transactions
roll back. Expiration-alarm failures cannot change a committed deposit to an error.

### Fetch, acknowledgment, and expiration

GET accepts `limit` (positive integer, default 10, capped at 100) and `after`
(the message-ID cursor returned by a preceding page). Messages are ordered by ID.
A new polling pass should start without a cursor: a newly inserted random UUID
may sort before an existing cursor. Pagination is not a frozen snapshot.

Each message includes `{id,received_at,sender_fp,size,envelope}`. Empty registered
mailboxes return `messages:[]` and `next_cursor:null`. The Python client treats
DELETE 404 as successful acknowledgment; an unauthorized delete still fails.
Expiry is enforced on every actor request and by cleanup alarms. Failed alarms
may delay physical removal, but expired records are never returned or counted
against live capacity on a subsequent successful request.

The transport does not tie acknowledgment to successful decryption or application
processing. Recipients must verify, decrypt, process durably, then acknowledge,
and define their own crash-recovery policy.

### Advisory sender filter

PUT takes `{"allowed_senders":["<fp>"]}`; an empty array clears the filter.
At most 1000 valid fingerprints are allowed. Values are matched against the
**self-reported** `sender_key_fingerprint`, which is spoofable. This reduces junk
from cooperating clients; it is not sender authentication. Recipients must use
ML-DSA verification with an independently trusted sender identity.

## Limits and observability

| Setting | Default |
|---|---|
| `MAX_ENVELOPE_SIZE` | 51200 request bytes |
| `MAX_MESSAGES_PER_MAILBOX` | 1000 live messages; enforced transactionally |
| `MESSAGE_TTL_SECONDS` | 86400 seconds |
| `RATE_LIMIT_POST_PER_MIN` | 60/IP/minute |
| `RATE_LIMIT_GET_PER_MIN` | 120/IP/minute each for GET and DELETE |
| Admin operations | 10/IP/minute, shared across register/filter operations |

Rate windows are fixed one-minute buckets, not sliding windows. GET, POST,
DELETE, and admin use distinct counters. Trusted operator-configured IPs may
bypass rate limits. The deployed edge supplies `CF-Connecting-IP`; do not expose
this Worker behind an ingress that trusts caller-spoofed copies of that header.
Limiter failures fail closed. There is no per-request hot KV counter.

Logs contain event, method, status, and latency. They do not contain request
bodies, credentials, complete URLs, or mailbox fingerprints. A 503 can still
represent an ambiguous network failure if the caller loses a committed response;
idempotency is the recovery mechanism.

## Python server configuration

Enable with `PQC_RELAY_ENABLED=1`, set exact origins in `PQC_RELAY_ALLOWED_URLS`,
and select an owner-only JSON credential file with `PQC_RELAY_TOKEN_FILE`:

```json
[
  {"relay_url":"https://relay.example","fingerprint":"<64 lowercase hex>","token":"<mailbox token>"}
]
```

POSIX file permissions must exclude group/other access; ownership must match the
server user. Symlinks are refused where O_NOFOLLOW is available. Malformed,
unrecognized-origin, duplicate, or invalid records prevent startup. Credentials
are not tool parameters and are scoped to origin plus mailbox. Editing the file
requires a server restart to load rotated credentials.

HTTPS is required unless explicit local development enables `PQC_RELAY_ALLOW_HTTP=1`.
Query/fragment/userinfo/path components are refused in base URLs; requests use the
validated canonical origin. Redirects are never followed. Timeouts must be finite
positive values. Responses are streamed with a 6,000,000-byte decoded cap, and
untrusted error bodies are not reflected to the model. Relay network calls do
not block the MCP event loop.

## Migration from the KV relay — operator action, not automatic

1. Stage the repaired Worker under a separate name/environment. Deploy its
   SQLite-class migration and provision an independent admin secret. Test against
   that disposable endpoint before changing existing client origins.
2. Inventory existing mailbox owners through trusted operator records. The new
   relay deliberately does not infer ownership from public fingerprints or
   missing/expired legacy metadata.
3. Coordinate a maintenance window: stop new deposits to the old deployment,
   let authenticated recipients drain/ack pending messages, or export encrypted
   KV records with authorized operator tooling. Retain the old namespace as a
   backup. Do not clear KV as part of this source upgrade.
4. Register each mailbox in the new deployment and deliver its new token to the
   authorized recipient outside model transcripts. Legacy tokens/filters are not
   silently copied. Reapply filters explicitly if needed.
5. Update clients' allowed origins and owner-only token files; restart them.
   Replay locally preserved encrypted envelopes through the new endpoint only
   when their recipient and sender verification requirements are known. Expired
   envelopes may correctly fail freshness checks.
6. Cut over ingress after authenticated send/fetch/verify/open/ack tests pass.
   Keep the legacy deployment/data available for an agreed recovery period;
   archive/remove them only in a separate reviewed operation.

Deploying the source over a live KV Worker without this migration will make old
mailboxes unavailable through new routes. This fail-closed behavior is intentional;
no legacy messages or authorization records are deleted by the new code.

## Validation

`npm ci && npm run typecheck && npm test && npm run build` runs local contract
checks against real SQLite and integration tests in workerd. Python tests default
to offline operation. Explicit cross-process transport/crypto integration:

```sh
PQC_RELAY_E2E_URL=https://disposable-relay.example \
PQC_RELAY_E2E_ADMIN_TOKEN='<operator-supplied disposable credential>' \
uv run --frozen pytest -m e2e
```

Use secret injection suitable for your environment rather than putting real
credentials in command history. No public endpoint is selected by default.
