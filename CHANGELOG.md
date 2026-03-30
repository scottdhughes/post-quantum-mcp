# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Test suite with pytest covering KEM, signatures, hashing, and algorithm info tools
- GitHub Actions CI pipeline (Python 3.10-3.13, Ubuntu + macOS)
- CHANGELOG.md

### Fixed
- `run.sh` now uses portable paths instead of hardcoded `/Users/scott/` paths
- Bare `except:` clauses replaced with specific `MechanismNotSupportedError` handling

### Changed
- Added `pytest-asyncio` to dev dependencies

## [0.1.0] - 2026-01-07

### Added
- Initial release
- MCP server with 9 tools: list algorithms, algorithm info, keygen, encapsulate, decapsulate, sign, verify, hash, security analysis
- Support for ML-KEM (FIPS 203), ML-DSA (FIPS 204), SLH-DSA (FIPS 205)
- liboqs backend with 32 KEMs and 221+ signature algorithms
- Base64-encoded key/signature transport
- SHA3 and SHAKE hash functions via `pqc_hash_to_curve`

[Unreleased]: https://github.com/scottdhughes/post-quantum-mcp/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/scottdhughes/post-quantum-mcp/releases/tag/v0.1.0
