# Repository review — November 1, 2026

Reviewed baseline: `06a08e39f25dbece90890e93b0d9770beecb4139` (v0.9.2 metadata).

The next release should repair policy enforcement, relay authorization/state,
and the verification pipeline before adding cryptographic features. The v3
mode separation, explicit sender binding, verify-before-decrypt path, strict
base64 decoding, and negative-path tests are useful foundations. They do not
establish the stronger operational claims currently made in the README.

This is a local engineering review, with targeted security probes and upstream
documentation checks. It is not an independent cryptographic certification or
a live deployment audit. No production deployment or dependency upgrade was
performed. Synthetic keys were generated only for local probes; secret values
were not printed. Runtime source and existing documentation were left unchanged.

## Verification results

Environment: Python 3.12.12; installed MCP 1.26.0, cryptography 46.0.6,
liboqs-python 0.14.1 against vendored C liboqs 0.15.0.

| Check | Result |
|---|---|
| Full Python suite, excluding live e2e | **373 passed, 15 failed, 6 skipped, 3 deselected** |
| Same suite excluding `test_relay_tools.py` | **349 passed, 6 skipped, 3 deselected** |
| Affected server/signature/state/utility files in isolation | **64 passed** |
| Black check | **Fails: 5 files need formatting** |
| mypy | **Fails: 3 `no-any-return` errors in relay_tools.py** |
| Relay TypeScript typecheck | **Passes** |
| Wrangler dry-run build | **Passes** with logs redirected into `/tmp` |
| Relay Vitest suite | **Unverified**: exits 1 while starting isolated runtimes, no completed test results |
| npm advisory audit | **Blocked**: registry DNS lookup fails in this environment |
| Hypothesis properties | **6 skipped**; Hypothesis is not installed or declared in dev dependencies |

Python commands used the existing virtual environment, with `OQS_INSTALL_PATH`
set to `$PWD/.vendor/liboqs-0.15` and `DYLD_LIBRARY_PATH` to its `lib` directory.
No dependency installation was needed. These are local results, not assertions
about the current GitHub Actions run.

## Findings and repairs

### R01 — High: handle-only key generation can return private keys

Locations: `pqc_mcp_server/handlers_hybrid.py:128`,
`pqc_mcp_server/handlers_pqc.py:80`, and the keygen tool schemas.

With `PQC_REQUIRE_KEY_HANDLES=1`:

* `pqc_hybrid_keygen({})` returns both private keys. The hybrid handler has no
  policy check before falling back to its raw result.
* `pqc_generate_keypair({"algorithm":"ML-DSA-65","store_as":""})` returns its
  private key. The generic guard checks field presence; storage checks truthiness.

Both were reproduced through the server's `call_tool` dispatch, not just direct
handler calls. Only booleans indicating secret-field presence were printed.
This exposes newly generated keys to the tool transcript despite the explicit
policy. It does not demonstrate extraction of an existing stored key.

Repair: share one handle-name validator; reject absent, null, empty, or blank
handles when policy is active, before key generation. Apply it to both handlers
and add transport-level policy tests for these cases. Bound handle-name length.
The existing policy tests cover generic missing `store_as`, but miss these paths.

### R02 — High: mailbox authorization expires or can be overwritten with metadata

Locations: `deploy/relay/worker/src/index.ts:96`, `:106`, `:172`, `:199`, `:407`.

`token_hash`, advisory sender rules, and the message count share one KV record.
Every metadata write gives the record a 172800-second TTL. GET and DELETE require
a token only if the record currently contains `token_hash`. Missing or invalid
JSON metadata becomes `{message_count:0}`.

Local bundled-Worker probe with an in-memory KV substitute:

1. Register mailbox: 201; stored metadata TTL is 172800 seconds.
2. GET without token: 401.
3. Remove metadata to model expiry, then deposit a new message: 201.
4. GET without token: **200**.

The same authorization downgrade applies to DELETE. After a long idle period,
future deposits reopen the mailbox; message expiry does not eliminate this risk.
Read-modify-write metadata updates also allow stale deposit/delete state to
overwrite a concurrent registration or token rotation. That race is established
from source and KV consistency semantics, not reproduced against production.

Repair: store durable authorization separately from expiring message state;
fail closed for protected mailboxes when authorization cannot be read. Serialize
registration, rotation, and mailbox mutations in a per-mailbox Durable Object or
another transactional owner. Explicitly define whether unregistered mailboxes
are intentionally public.

### R03 — High operational priority: Python cannot access protected mailboxes

Locations: `pqc_mcp_server/relay_client.py:358`, `:425`,
`pqc_mcp_server/relay_tools.py`, and `pqc_mcp_server/__init__.py:220`.

The Worker accepts bearer tokens for GET/DELETE, but the Python client has no
token configuration or Authorization header path. The relay MCP tools cannot
fetch or acknowledge registered mailboxes. Current lifecycle tests use public
mailboxes, so they do not cover the supported authorization flow.

Repair: load mailbox credentials from server-side configuration/credential
storage, keyed by normalized relay origin and mailbox fingerprint. Avoid passing
tokens through ordinary model tool arguments. Add register/fetch/open/ack tests
covering missing, wrong, valid, and rotated tokens.

### R04 — High deployment risk: a public development admin token is deployable

Location: `deploy/relay/worker/wrangler.toml:14`.

The default production-target config includes a known development admin token.
The Worker rejects only an empty token; it accepts the placeholder. A clean
deployment without a separately provisioned secret therefore enables public
admin access, including mailbox token replacement. The dry-run build includes
the placeholder binding.

This is a confirmed unsafe deployment default. Whether the live Worker overrides
it with a secret was not inspected and is unknown.

Repair: remove the admin token from deployable vars; inject a test-only binding
in Vitest configuration or local ignored dev vars. Reject the known placeholder
in deployable runtime configuration. Document secret provisioning and rotation.

### R05 — Medium: KV cannot enforce the advertised rate and capacity guarantees

Locations: `deploy/relay/worker/src/rate-limiter.ts:21` and
`deploy/relay/worker/src/index.ts:324`.

Each allowed request rewrites the same IP/minute counter. Cloudflare limits
writes to a single KV key to one per second and documents eventual consistency.
The Worker catches limiter errors and allows the request. Consequently bursts
can bypass the limiter even without extreme concurrency. This is a fixed-window
counter, despite the “sliding-window” description.

Mailbox capacity is checked using one eventually consistent list, followed by a
separate put. Concurrent deposits can exceed capacity. Configurations over 1000
messages are additionally broken: the capacity query is capped at 1000 keys and
is not paginated, so its length can never reach a larger configured maximum.

Repair: use Cloudflare's rate-limiting facility for coarse abuse control and a
transactional per-mailbox owner for strict quotas. Keep KV for workloads that
tolerate stale reads. Validate all numeric configuration. Do not describe a KV
counter as an enforcement guarantee.

### R06 — Medium: a POST can fail after the envelope has been stored

Location: `deploy/relay/worker/src/index.ts:342`.

The message put and informational metadata put share a try/catch. A metadata
failure after a successful message put returns 500. A retry creates another UUID
and duplicates the message. Reproduced locally with a KV substitute that succeeds
on message writes and fails on metadata writes: response 500, message retained.

Repair: define the message write as the commit point, or atomically commit both
records. A nonessential counter failure should not change a committed deposit to
an ambiguous failure. Add sender idempotency keys and deterministic retry behavior.
Eventually consistent delete/fetch behavior also needs an explicit delivery contract.

### R07 — Medium: accepted plaintext can produce an unopenable envelope

Locations: `pqc_mcp_server/__init__.py:136`,
`pqc_mcp_server/hybrid.py:1158`, and `:1190`.

Pre-dispatch validation accepts 1048576 plaintext characters. Open rejects
ciphertext base64 above 1000000 characters. Reproduction: 800000 ASCII bytes
seal successfully into 1066688 ciphertext characters; open rejects that exact
envelope for exceeding the field limit. UTF-8 multibyte plaintext widens the gap.
The relay separately limits the entire serialized envelope to 51200 bytes.

Repair: define distinct decoded-plaintext, serialized-envelope, and relay-byte
budgets; derive base64 allowances from those budgets. Reject over-budget seals
before encryption. Test exact boundaries and multibyte plaintext. A local seal
limit may exceed the relay limit, but that distinction must be explicit.

### R08 — Medium: the test suite contaminates global imports

Location: `tests/test_relay_tools.py:438`, especially `_ensure_stub` and cleanup.

The helper replaces existing entries in `sys.modules` but records only entries
that were previously absent. Existing `hybrid`, handler, and key-store modules
are left replaced by stubs after the helper returns. Later tests encounter
missing constants/helpers and MagicMock results.

Evidence: full non-live suite has 15 failures; excluding this test file gives
349 passes; all 64 tests in the affected files pass alone.

Repair: use scoped patching that restores every previous module object, or
move relay configuration parsing into a lightweight independently importable
module. Avoid loading multiple identities of the same module at collection time
in the other relay tests. Add an import-identity regression check.

### R09 — Medium: CI checks already fail, and fuzz coverage silently disappears

Black identifies `__init__.py`, `relay_client.py`, and the three relay test files
as requiring formatting. mypy finds three Any-return errors at
`relay_tools.py:162`, `:193`, and `:224`; its client argument is typed `Any`.

Hypothesis is absent from `pyproject.toml` dev extras and `uv.lock`. The six
property tests quietly skip. CI also runs the live relay tests by default on
every matrix leg, coupling ordinary validation to a public service and its KV
propagation delays. The relay workflow's paths filter excludes changes to its
own workflow file.

Repair: type handlers against `RelayClient` or a small protocol; format touched
files; declare Hypothesis and require those properties in CI; make live tests a
separate opt-in/scheduled job with an explicit endpoint. Use `uv sync --frozen`
and an explicit selected Python interpreter. Add dependency advisory checks and
a package build/install smoke test. Include the workflow itself in path filters.

### R10 — Medium: native oqs objects are never explicitly released

Locations: `pqc_mcp_server/hybrid.py` and `pqc_mcp_server/handlers_pqc.py`.

The installed 0.14.1 wrapper allocates native KEM/signature objects and supplies
context managers whose exit invokes `free()`. That method also cleanses its
secret buffer. The application repeatedly constructs these objects without a
context manager or `free()`; the installed wrapper has no `__del__` fallback.

This establishes missing native cleanup and missed explicit cleansing; sustained
resident-memory growth was not benchmarked. It does not mean Python secret byte
copies can be reliably zeroized by adding a context manager.

Repair: use `with oqs.KeyEncapsulation(...)` and `with oqs.Signature(...)`
throughout, including benchmark iterations. Verify exception-path cleanup, and
separately document the limitations of keeping immutable Python secret bytes.

### R11 — Medium: relay request parsing and URL canonicalization are incomplete

Worker `handlePost` reads the entire body before checking its size and measures
JavaScript string length instead of UTF-8 bytes. A JSON `null` body then throws
an uncaught TypeError while checking envelope fields; this was reproduced locally.
Allowlist request shapes and GET pagination limits also lack complete type/range
validation. Failed requests can bypass structured response logging.

Client `check_allowlist` validates an origin reconstructed from the URL but
request construction reuses the original URL. Query/fragment inputs are not
rejected. A mocked request for allowed `https://relay.example?x=1` became
`https://relay.example?x=1/mailboxes/<fp>`: the mailbox path is query text, not
the intended endpoint. This reproduces routing/validation inconsistency, not an
off-origin SSRF bypass.

Repair: bounded byte-stream reads, object/type checks, finite positive integer
limits, a structured outer error boundary, and one canonical URL parser shared
by startup validation and request construction. Reject query, fragment, userinfo,
missing host, and invalid ports. Validate relay response shapes and bound response
size before exposing data to the model.

### R12 — Medium architectural limit: replay dedup is best effort

The JSON replay cache has no cross-process coordination, resets on corruption,
silently ignores persistence errors, and evicts still-live entries at capacity.
`max_age_seconds=0` disables freshness, allowing previously seen envelopes after
cache expiry. Most of this is already acknowledged in source/audit notes.

Repair: choose and document the promised semantics. If one-time acceptance is
required, use a transactional SQLite uniqueness constraint across local MCP
processes, retain entries for the full acceptance window, and surface persistence
failure rather than silently accepting. Define behavior when freshness is disabled.
Separate envelope acceptance from application processing/acknowledgment; a crash
between successful open and processing is otherwise a recovery problem.

The async dispatcher also directly calls blocking httpx and crypto handlers.
Relay timeouts stall unrelated requests in that server process. Prefer an async
client with reusable connections. If offloading crypto, preserve replay atomicity
and add explicit key-store concurrency protection rather than blindly threading it.

### R13 — Medium trust/documentation issue: security descriptions overstate behavior

* `handle_security_analysis` infers “NIST approved” and generic quantum security
  claims from a liboqs claimed security category. Categories 2/4 are not AES
  categories, and a claimed category is not evidence of standardization. Return
  separately sourced standardization status, claimed category, and assumptions.
* `handle_hash` silently computes SHA3-256 for an unsupported algorithm but echoes
  the requested name. Reject unsupported names instead of mislabeling the digest.
* README replay ordering says check-before-decrypt, but the active handler checks
  and marks after successful verification/decryption. Replay requests still incur
  full crypto work before rejection.
* README promises v2 deprecation warnings. Verification only creates a v1 warning,
  and authenticated open does not propagate that warning from verification.
* Sender TTL is an API-enforced refusal rule. The holder of the recipient keys
  can ignore it and perform decryption; “self-destruct” and “cannot decrypt” should
  not imply a cryptographic expiry guarantee.
* ROADMAP still calls network transport missing. SECURITY_AUDIT's accepted risks
  and historical pass counts cannot serve as a current release assessment.
* `filesystem.py` says the server never writes files, despite replay persistence.

Repair: preserve the historical audit as historical; maintain a current release
status and evidence table. Replace numerical self-grades with acceptance criteria.
Keep protocol notes, tool schemas, examples, and current behavior synchronized.

## Upstream updates verified on the review date

| Component | Repository state | Verified update / action |
|---|---|---|
| C liboqs | 0.15.0 in CI/install/bootstrap | 0.16.0 released July 9; adopt a tested aligned pair |
| liboqs-python | 0.14.1 locked | 0.16.0.2 released October 28; remove the old mismatch workaround after validation |
| MCP | 1.26.0 locked; allowed range starts at 1.6.0 | 1.30.0 is a verified 1.x maintenance target containing later fixes; evaluate 2.x as a separate migration |
| Relay CI Node | 20 | EOL; use a supported LTS such as 24, then validate Wrangler/Vitest together |
| Python dev tooling | Hypothesis absent | Declare and run property tests; optionally declare Ruff if it is to be enforced |

liboqs 0.16 removes SPHINCS+ and changes FrodoKEM naming/behavior. An upgrade
requires rechecking algorithm inventory, legacy aliases, generic tool examples,
and compatibility tests. Do not merely bump the C build while retaining an old
wrapper. Its release notes list security fixes, but this review does not assert
that every fixed algorithm/path is exercised by this project's hybrid suite.

MCP advisories require path-specific assessment: GHSA-jpw9-pfvf-9f58 affects
authenticated HTTP sessions, whereas this server uses stdio. GHSA-rwrf-2pqf-9j8j
affects MCP client output-schema validation; production code here builds a
server, while its integration tests do instantiate a client. An old installed
version is an upgrade reason, not proof of a reachable production exploit.

Current npm advisory status remains unknown because the registry audit was
blocked. No blanket claim that the locked Node packages are vulnerable is made.

## Recommended work order

1. **Policy and verification repair:** R01, R08, R09. Acceptance: handle-only
   keygen cannot emit secret fields under missing/empty/null names; the complete
   offline suite passes in one process; formatting/types pass; no skipped
   Hypothesis properties.
2. **Relay authorization repair:** R02–R04. Acceptance: credentials persist
   independently of message TTL; expiry/corruption/rotation never makes a
   protected mailbox public; the Python client handles valid credentials;
   deployable config contains no usable development admin credential.
3. **Relay consistency and boundaries:** R05–R07, R10–R11. Acceptance: bounded
   byte reads, consistent seal/open budgets, deterministic deposit retry
   behavior, cleanup on every crypto path, and documented quota semantics.
4. **Dependency maintenance:** aligned liboqs/Python wrapper, supported Node,
   maintained MCP 1.x; frozen locks and a reproducible build/install check.
5. **Operational contract:** R12–R13. Decide replay/delivery guarantees and
   supported protocol versions; update docs against measured behavior.

Forward secrecy is a separate protocol project and should follow these repairs.
It requires explicit identity/prekey/session state and a reviewed protocol choice;
fresh ephemeral sender keys alone do not solve later recipient-key compromise.

## Primary sources

* Cloudflare KV write limits, overwrite races, propagation and expiry:
  https://developers.cloudflare.com/kv/api/write-key-value-pairs/
* Cloudflare KV consistency/design fit:
  https://developers.cloudflare.com/kv/concepts/how-kv-works/
* liboqs release notes:
  https://github.com/open-quantum-safe/liboqs/releases
* OQS release announcements:
  https://openquantumsafe.org/
* liboqs-python 0.16.0.2 package release:
  https://pypi.org/project/liboqs-python/0.16.0.2/
* MCP maintenance releases:
  https://github.com/modelcontextprotocol/python-sdk/releases
* MCP HTTP-session advisory and explicit stdio exclusion:
  https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-jpw9-pfvf-9f58
* MCP client schema-reference advisory:
  https://github.com/modelcontextprotocol/python-sdk/security/advisories/GHSA-rwrf-2pqf-9j8j
* Node supported/EOL release lines:
  https://nodejs.org/en/about/previous-releases
* NIST security-category definitions and quantum-cost caveats:
  https://csrc.nist.gov/Projects/Post-Quantum-Cryptography/faqs

## Reproduction commands

Run from the repository root using the existing environment:

```sh
export OQS_INSTALL_PATH="$PWD/.vendor/liboqs-0.15"
export DYLD_LIBRARY_PATH="$OQS_INSTALL_PATH/lib"
.venv/bin/python -m pytest tests -q -m 'not e2e'
.venv/bin/python -m pytest tests -q -m 'not e2e' --ignore=tests/test_relay_tools.py
.venv/bin/python -m pytest tests/test_server.py tests/test_signatures.py tests/test_state_corruption_and_recovery.py tests/test_utilities.py -q
.venv/bin/python -m black --check pqc_mcp_server tests
.venv/bin/python -m mypy pqc_mcp_server
npm --prefix deploy/relay/worker run typecheck
WRANGLER_LOG_PATH=/tmp/pqc-wrangler-logs WRANGLER_SEND_METRICS=false npm --prefix deploy/relay/worker run build
WRANGLER_LOG_PATH=/tmp/pqc-wrangler-logs WRANGLER_SEND_METRICS=false npm --prefix deploy/relay/worker test
```

Policy reproduction, printing only secret-presence booleans:

```sh
PQC_REQUIRE_KEY_HANDLES=1 .venv/bin/python - <<'PY'
import asyncio, json
from pqc_mcp_server import call_tool

async def main():
    cases = [
        ('pqc_hybrid_keygen', {}),
        ('pqc_generate_keypair', {'algorithm': 'ML-DSA-65', 'store_as': ''}),
    ]
    for name, args in cases:
        result = json.loads((await call_tool(name, args))[0].text)
        exposed = 'secret_key' in result or any(
            isinstance(v, dict) and 'secret_key' in v for v in result.values()
        )
        print(name, 'secret_returned=', exposed)

asyncio.run(main())
PY
```

Both cases print `secret_returned= True` on the reviewed baseline.
