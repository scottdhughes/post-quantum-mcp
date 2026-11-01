# Hardening repair status — November 1, 2026

Prepared source: Python package **0.10.0 (unreleased)** and relay **0.2.0**.
Baseline review: [repository review](2026-11-01-repository-review.md).

## Outcome

The authorized repair sequence is implemented locally. Private-key generation
honors handle-only policy, tests no longer replace global crypto modules, mailbox
authorization is durable and fail closed, and mailbox/rate/retry state is
transactional. Dependency locks and documentation are updated. The v3 wire
cryptography is unchanged. No public deployment, external mailbox operation,
or legacy KV migration was performed. GitHub integration and cross-platform CI
are tracked by the publishing pull request and repository history.

## Verification

| Check | Measured result |
|---|---|
| Complete default Python suite | **421 passed, 2 external e2e tests deselected; no skipped property tests** |
| Explicit Python transport/crypto e2e | **2 passed** against a disposable local workerd relay |
| Node contract suite with real SQLite | **9 passed** |
| Actual workerd integration suite | **9 passed** |
| Black / mypy | **Pass** |
| TypeScript typecheck | **Pass** |
| Frozen Python lock check | **Pass** |
| Wrangler dry-run deployment build | **Pass; no deployment** |
| Python sdist / wheel build/install | **Pass**; isolated installed wheel imports and completes a crypto roundtrip outside the checkout; archives exclude local state/dependencies |
| npm registry advisory audit | **0 known advisories** |
| pip-audit 2.10.1, installed Python 3.12 dependencies | **0 known advisories across 46 distributions**; editable application itself excluded |

Audit evidence: [npm JSON](2026-11-01-npm-audit.json) and
[Python JSON](2026-11-01-python-audit.json). Advisory results describe available
registry records at the time of this check; they are not proof of vulnerability
absence or a review of the native C implementation.

Local environment: macOS ARM64, Python 3.12.12, Node 26.12.1. The configured
Ubuntu/macOS × Python 3.10–3.13 CI matrix and Node 24 CI have not been executed
on GitHub by this session. Python 3.10 frozen dependency selection was checked
with a resolver dry-run, not a full interpreter test run.

CI actions were updated to verified current release commits and pinned by SHA;
all use Node 24. [Action pin evidence](2026-11-01-action-pins.json). Workflow YAML
parses successfully and job token permissions are limited to contents read.

## Changes mapped to findings

| Review finding | Repair |
|---|---|
| R01 — key policy | Shared bounded handle validation before generation; dispatch tests for missing/null/empty/blank/oversized names |
| R02 — authorization expiry/races | SQLite-backed per-mailbox actor; authorization never expires with message records; rotation and mutations serialize transactionally |
| R03 — Python credential gap | Owner-only server token file; exact origin/mailbox scoping; tokens never enter tool arguments |
| R04 — public admin default | Removed deployable placeholder; reject absent/placeholder admin credentials; test-only injected credentials |
| R05 — KV limits/quotas | Transactional SQL quotas and per-IP fixed-window limiter; fail closed; quotas above 1000 covered |
| R06 — ambiguous post/duplicates | Atomic message/receipt insertion; stable retry keys; acknowledgment preserves receipt; failed housekeeping does not turn a commit into a failure |
| R07 — size mismatch | One MiB decoded-byte seal limit with matching GCM/base64 allowance; separate full-JSON relay byte limit |
| R08 — import contamination | Canonical imports; deleted stub-replacement machinery; module-identity regression |
| R09 — verification drift | Required Hypothesis, passing format/types, frozen dependencies, opt-in external tests, package and advisory CI jobs |
| R10 — native resources | Context managers throughout oqs handlers/crypto; per-iteration benchmark allocation cleanup; private-key copies in Python remain subject to Python memory limits |
| R11 — parsing/URL issues | Bounded byte-stream parsing, shape/range validation, canonical URLs, no redirects, bounded responses, structured failures |
| R12 — replay/process limits | Default transactional local SQLite; fail closed at capacity/corruption; one-time legacy JSON import; cross-process acceptance test; clock-skew retention margin; relay calls off the event loop |
| R13 — claims/docs | Correct category/standardization distinctions, unsupported hash rejection, legacy warnings, TTL wording, current compatibility/roadmap/migration evidence |

The legacy JSON `ReplayCache` class remains for compatibility and historical
probes; production defaults to `SqliteReplayCache`. Freshness must remain
positive in MCP authenticated open/verify calls. Retention includes 300 seconds
of allowed future skew plus a one-second inclusive-boundary margin. Legacy v1
compatibility still lacks mandatory freshness; finite replay state does not
make those envelopes equivalent to v3.

The dependency upgrade exposed a real stdio regression: liboqs-python 0.16
installs an INFO logger against stdout. Backend import is now bound to stderr;
a subprocess test asserts the protocol stdout remains empty before JSON-RPC.
Tests and spawned servers use isolated replay directories rather than operator
state. Operators can select a dedicated state directory with `PQC_STATE_DIR`.

## Dependency state

| Component | Previous | Current locally validated |
|---|---|---|
| liboqs C / Python | 0.15.0 / 0.14.1 | **0.16.0 / 0.16.0.2** |
| cryptography | 46.0.6 | **50.0.2** |
| MCP | 1.26.0 | **1.30.0**; 2.x deliberately remains a separate migration |
| Hypothesis | Undeclared / absent | **6.170.14**, with a Python-3.10-compatible lock branch |
| Wrangler | 4.80.0 | **4.156.0** |
| Vitest / Cloudflare testing | 3.2.4 / deprecated pool package | **5.0.5 / maintained plugin 1.4.11** |
| Cloudflare types / esbuild | 4.x / 0.27.3 | **5.20261101.1 / 0.28.2** |

No major TypeScript migration was needed; the locked TypeScript version remains
5.9.3. New liboqs inventory uses current exact names; SPHINCS+ removal and
FrodoKEM changes are documented rather than assumed to be aliases.

## Operational handoff

1. Review the GitHub integration and its CI results. Publishing source does not
   deploy or migrate the live relay.
2. Follow [the relay migration contract](../../deploy/relay/RELAY-SPEC.md) using
   staging and an explicit legacy mailbox drain/export window. New source does
   not import or delete legacy KV records automatically.
3. Register mailboxes, provision/rotate credentials outside model transcripts,
   update owner-only token files and allowed origins, then restart clients.
4. Review any legacy replay-cache corruption manually; the repaired server
   intentionally refuses to reset it silently.
5. Begin [forward-secrecy protocol selection](../forward-secrecy-next.md).
   No session ratchet or forward-secrecy guarantee is implemented here.
