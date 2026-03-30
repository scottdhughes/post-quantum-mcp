# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

### Tested Dependency Pairing
- liboqs C library: 0.15.0
- liboqs-python: 0.14.1 (PyPI)
- cryptography: 46.0.6 (PyPI)
- mcp: 1.26.0 (PyPI)
- Python: 3.10, 3.11, 3.12, 3.13
- Platforms: Ubuntu (latest), macOS (latest)

The liboqs 0.15.0 C library paired with liboqs-python 0.14.1 produces a version-skew warning but passes all tests across the full matrix. If you encounter issues, align the versions or pin to this tested pairing.

## [0.1.0] - 2026-01-07

### Added
- Initial release
- MCP server with 9 tools: list algorithms, algorithm info, keygen, encapsulate, decapsulate, sign, verify, hash, security analysis
- Support for ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205)
- liboqs backend for KEMs and signature algorithms
- Base64-encoded key/signature transport
- SHA3 and SHAKE hash functions

[0.2.0]: https://github.com/scottdhughes/post-quantum-mcp/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/scottdhughes/post-quantum-mcp/releases/tag/v0.1.0
