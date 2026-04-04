# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.8.0] - 2026-04-04

### Added
- **Cloudflare Worker relay** — opaque envelope mailbox for cross-machine A2A
  messaging. Live at `https://quantum-seal-relay.novoamorx1.workers.dev`.
  POST/GET/DELETE by recipient fingerprint. KV-backed with 24h TTL.
- **Rate limiting** — KV-backed sliding-window counter per IP. POST: 60/min,
  GET: 120/min. Configurable via `wrangler.toml`. Fails open on KV errors.
- **Trusted IP allowlist** — `TRUSTED_IPS` env var bypasses rate limiting for
  configured IPs.
- **Structured observability** — JSON logs on blocked requests (rate limit events)
  and all requests (method, path, status, latency_ms).
- **Relay Worker CI** — TypeScript type-check, build validation, 12 Vitest tests
  covering POST/GET/DELETE, allowlist, size limits, and error paths.
- `deploy/relay/RELAY-SPEC.md` — transport contract specification with endpoints,
  limits, rate limiting docs, log schema, and security properties.

### Fixed
- KV error handling under concurrent load — rate limiter and message storage
  fail open with structured error logging instead of 500s.
- `node_modules` accidentally committed — `.gitignore` updated.

### Security
- Relay never accesses private keys or decrypted content (opaque transport).
- First successful remote PQC message delivery verified end-to-end.
- Operational hardening: replay-cache process boundary documented, 15 state
  corruption tests, 13 handle-policy negative tests, liboqs 0.14.0 vendored.

## [0.7.0] - 2026-04-03

### Changed
- **BREAKING:** Envelope version bumped from pqc-mcp-v2 to pqc-mcp-v3
- Mode field required in all v3 envelopes (anon-seal or auth-seal)
- Mode bound into HKDF info, AAD, and auth transcript (true cross-mode separation)
- AAD switched to length-prefixed framing for v3 (self-delimiting)
- Auth transcript prefix updated to pqc-mcp-auth-v3
- PQC_REQUIRE_KEY_HANDLES now enforces across ALL handlers (keygen, sign, decapsulate), not just hybrid envelope operations

### Added
- _core_encrypt() with mode parameter — both hybrid_seal and hybrid_auth_seal derive AEAD keys with their respective mode, preventing auth-stripping downgrade
- ML-KEM-768 ciphertext size validation (1088 bytes) before decapsulation
- ML-KEM-768 secret key size validation (2400 bytes) before decapsulation
- GCM ciphertext minimum length check (16 bytes for tag)
- Strict v3 schema validation: anon-seal rejects auth fields, auth-seal requires all
- Replay cache TTL alignment: max_age_seconds cannot exceed cache TTL
- v3 envelope spec document (docs/v3-envelope-spec.md)
- 13 cross-mode confusion tests (test_v3_mode_separation.py)

### Fixed
- Auth-stripping downgrade: auth-seal ciphertext now uses different AEAD derivation than anon-seal (ChatGPT finding — most architecturally significant fix)
- Stale is_v2 variable in timestamp enforcement: replaced with requires_timestamp checking v1 exclusion
- Missing max_size in replay cache fallback path (AttributeError on eviction)
- signature_digest now rejects missing/empty signatures
- Concurrency window in replay check/mark explicitly documented as single-process tradeoff

### Security
- Five-model adversarial review: Claude, Codex, Qwen, ChatGPT (two passes)
- Auth-stripping downgrade blocked at AEAD layer (InvalidTag), not parser
- Mode separation enforced at 5 layers: HKDF, AAD, transcript, schema, handler

## [0.6.0] - 2026-04-02

### Changed
- **BREAKING:** Envelope version bumped from `pqc-mcp-v1` to `pqc-mcp-v2`
- HKDF info prefix updated to `pqc-mcp-v2|...` with ephemeral public key hash
  bound into the derivation for domain separation (NIST SP 800-56C defense-in-depth)
- Auth transcript prefix updated to `pqc-mcp-auth-v2`
- AAD construction now uses envelope version dynamically
- Module docstring corrected: authenticated envelopes encrypt first (anonymous
  seal), then sign the finished envelope — not "sign before encryption"

### Added
- **`pqc_hybrid_auth_verify`**: Verify sender signature without decrypting.
  Checks sender binding, fingerprint consistency, ML-DSA-65 signature, and
  timestamp freshness. No secret keys needed. Returns `replay_seen` advisory.
- **Replay protection:** Signed timestamps in v2 envelopes + JSON-backed
  signature-digest cache (`replay_cache.py`). Freshness configurable via
  `max_age_seconds` (now exposed on MCP tool schemas). Check-before-decrypt,
  mark-after-success pattern prevents pre-image blocking.
- **Security policy:** `security_policy.py` with `PQC_REQUIRE_KEY_HANDLES`
  env var to reject raw secret keys in tool calls.
- **Envelope size validation:** `_validate_envelope_size()` — max 1MB per
  base64 field, max 50 fields. Checked before any crypto or replay processing.
- **ML-KEM-768 public key validation:** Rejects empty/truncated/wrong-size keys.
- **ML-DSA-65 key size validation:** Rejects wrong-type keys (prevents liboqs
  silently accepting undersized signing keys).
- **v1 legacy warning:** v1 authenticated envelopes return a loud warning about
  missing freshness protection. v2 envelopes require timestamps.
- **Ghost Timestamp protection:** v2 envelopes must include a timestamp; missing
  timestamps are rejected before signature verification.
- `pqc_mcp_server.filesystem` module: `ensure_secure_directory` (0o700) and
  `ensure_secure_file` (0o600) helpers for `~/.pqc/` paths.
- `scripts/install-liboqs.sh`: Reusable installer with `--prefix` and `--version`.
- `include_secret_key` parameter on `pqc_generate_keypair` to redact secrets.
- Negative `max_age_seconds` rejection (only 0 or positive accepted).
- Backwards-compatible v1 acceptance with documented deprecation path.
- `_verify_authenticated_envelope()` shared function eliminates ~80 lines of
  duplication between `hybrid_auth_open` and `hybrid_auth_verify`.
- Wycheproof test vectors (AES-256-GCM, X25519, HKDF-SHA256: 834+ vectors).
- Hypothesis property-based fuzzing (530+ random inputs).
- Protocol mutation fuzzer (500+ mutated envelopes).
- High-iteration native fuzzing (13,300 iterations: KEM, DSA, combiner, HKDF).
- `SECURITY_AUDIT.md`: Formal audit report from multi-model adversarial review.
- `ROADMAP.md`: Phased improvement plan with projected scores.

### Fixed
- `ValueError` from `int()` parsing now caught in timestamp validation.
- Pre-verification cache marking (Codex finding): replay cache check moved
  before verification, marking moved after success.
- Cache-flood DoS: max 50K entries with oldest-first eviction.
- Stale `test_utilities.py` v1 assertion.
- Stale `EXPECTED_TOOLS` in `test_server.py`.
- `tools.py` missing `include_secret_key` in schema.
- `hybrid_auth_verify` uncaught KeyError on malformed envelopes.
- Dead code: v1_warning was unreachable (return before attachment).
- Signature digest computed before envelope size validation in handlers.

### Security
- 25 findings from multi-model adversarial review (Claude Opus 4.6, Codex
  GPT-5.4, Qwen 3.5 35B). 19 fixed, 6 accepted by design.
- ~15,750 test inputs: zero crashes, zero key leaks.
- Prompt injection testing: 27 payloads, all contained.
- Content leakage audit: 29 checks, zero leaks.

## [0.4.0] - 2026-04-01

### Added
- Secret-handle keyring: `store_as` parameter on `pqc_hybrid_keygen` and `pqc_generate_keypair`
- `key_store_name` / `recipient_key_store_name` / `sender_key_store_name` on all downstream tools
- Keys generated with `store_as` redact secrets from output (public material + fingerprints only). Note: `pqc_key_store_save`/`pqc_key_store_load` still handle raw key data for manual workflows.
- Collision protection: `store_as` fails on name collision unless `overwrite: true`
- Conflict detection: store name + raw keys in same call = error
- Type validation: hybrid vs flat, signature vs KEM, algorithm mismatch via liboqs canonical names
- Fingerprint included in flat keypair handle output

## [0.3.0] - 2026-03-30

### Added
- Sender-authenticated hybrid envelopes: `pqc_hybrid_auth_seal`, `pqc_hybrid_auth_open`
- ML-DSA-65 (FIPS 204) signature over canonical binary transcript
- Sender identity binding via `expected_sender_public_key` or `expected_sender_fingerprint`
- SHA3-256 public key fingerprinting helper
- Canonical length-prefixed binary transcript for signature input
- `SenderVerificationError` distinct from `InvalidTag` for clear error separation
- Signature verified before decryption (verify-then-decrypt ordering)
- 110 tests across the full suite

### Fixed
- Fingerprint-binding bug: `hybrid_auth_open` now recomputes `SHA3-256(sender_public_key)` and verifies it matches the envelope's embedded fingerprint before checking expected sender identity. Previously, a malicious sender could sign with their own key while placing a different fingerprint in the envelope.

### Tested Dependency Pairing
- liboqs C library: 0.15.0
- liboqs-python: 0.14.1 (PyPI)
- cryptography: 46.0.6 (PyPI)
- mcp: 1.26.0 (PyPI)
- Python: 3.10, 3.11, 3.12, 3.13
- Platforms: Ubuntu (latest), macOS (latest)

## [0.2.0] - 2026-03-30

### Added
- Hybrid X25519 + ML-KEM-768 key exchange (suite: `mlkem768-x25519-sha3-256`)
- 5 new tools: `pqc_hybrid_keygen`, `pqc_hybrid_encap`, `pqc_hybrid_decap`, `pqc_hybrid_seal`, `pqc_hybrid_open`
- SHA3-256 KEM combiner borrowing from LAMPS composite ML-KEM draft (`id-MLKEM768-X25519-SHA3-256`)
- AES-256-GCM sealed envelope with full-header AAD binding and deterministic nonce
- `cryptography>=42.0.0` dependency for X25519, HKDFExpand, AESGCM
- Test suite: 73 tests covering KEM, signatures, hashing, algorithm info, and hybrid tools
- GitHub Actions CI pipeline (Python 3.10-3.13, Ubuntu + macOS, liboqs 0.15.0)
- CHANGELOG.md

### Fixed
- `run.sh` now uses portable paths instead of hardcoded user-specific paths
- Bare `except:` clauses replaced with specific `MechanismNotSupportedError` handling

### Changed
- Renamed `pqc_hash_to_curve` to `pqc_hash` (`pqc_hash_to_curve` remains as a deprecated alias)
- `pqc_security_analysis` description clarified as educational static lookup
- README centered on ML-KEM / ML-DSA / SLH-DSA; legacy names noted as compatibility aliases
- Added `pytest-asyncio` to dev dependencies

## [0.1.0] - 2026-01-07

### Added
- Initial release
- MCP server with 9 tools: list algorithms, algorithm info, keygen, encapsulate, decapsulate, sign, verify, hash, security analysis
- Support for ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205)
- liboqs backend for KEMs and signature algorithms
- Base64-encoded key/signature transport
- SHA3 and SHAKE hash functions

[0.7.0]: https://github.com/scottdhughes/post-quantum-mcp/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/scottdhughes/post-quantum-mcp/compare/v0.4.0...v0.6.0
[0.4.0]: https://github.com/scottdhughes/post-quantum-mcp/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/scottdhughes/post-quantum-mcp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/scottdhughes/post-quantum-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/scottdhughes/post-quantum-mcp/releases/tag/v0.1.0
