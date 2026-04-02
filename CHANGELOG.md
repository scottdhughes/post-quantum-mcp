# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.5.0] - 2026-04-02

### Changed
- **BREAKING:** Envelope version bumped from `pqc-mcp-v1` to `pqc-mcp-v2`
- HKDF info prefix updated to `pqc-mcp-v2|...` with ephemeral public key hash
  bound into the derivation for domain separation (NIST SP 800-56C defense-in-depth)
- Auth transcript prefix updated to `pqc-mcp-auth-v2`
- AAD construction now uses envelope version dynamically

### Added
- **Replay protection:** Authenticated envelopes include a signed timestamp.
  `hybrid_auth_open` checks freshness after signature verification (24h default,
  configurable via `max_age_seconds`). Timestamp is covered by the ML-DSA
  signature — stripping or modifying it invalidates the envelope.
- Backwards-compatible version acceptance: `hybrid_open` and `hybrid_auth_open`
  accept both `pqc-mcp-v1` and `pqc-mcp-v2` envelopes. V1 envelopes use the
  original HKDF prefix and skip timestamp checks.
- `pqc_mcp_server.filesystem` module: `ensure_secure_directory` (0o700) and
  `ensure_secure_file` (0o600) helpers for securing `~/.pqc/` paths.
- Clock skew tolerance: future timestamps rejected if >5 minutes ahead.
- New test class `TestReplayProtection` covering timestamp signing, staleness
  rejection, timestamp stripping detection, and freshness acceptance.

### Fixed
- `ValueError` from `int()` parsing now caught in timestamp validation
  (previously only `TypeError` and `OverflowError` were handled).

### Security
- Adversarial review conducted via multi-model analysis (Qwen 3.5 + Codex + Claude).
  Findings: nonce derivation confirmed safe for single-shot protocol; replay
  protection gap identified and fixed; file permissions helper added.

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

[0.4.0]: https://github.com/scottdhughes/post-quantum-mcp/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/scottdhughes/post-quantum-mcp/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/scottdhughes/post-quantum-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/scottdhughes/post-quantum-mcp/releases/tag/v0.1.0
