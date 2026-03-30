# Post-Quantum Cryptography MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![liboqs](https://img.shields.io/badge/liboqs-0.15.0-green.svg)](https://openquantumsafe.org/)
[![MCP](https://img.shields.io/badge/MCP-1.0+-purple.svg)](https://modelcontextprotocol.io/)

> **Research and Prototyping Only.** This server uses [liboqs](https://github.com/open-quantum-safe/liboqs), which is explicitly not recommended for production use or for protecting sensitive data. Secret keys and shared secrets appear in tool output, which may enter model context, client logs, or transcripts. Suitable for experimentation, education, and interoperability testing.

A **Model Context Protocol (MCP) server** that provides post-quantum cryptographic operations using [Open Quantum Safe's liboqs](https://openquantumsafe.org/). Enables AI assistants like Claude to perform quantum-resistant cryptographic operations including key generation, encryption, signing, and verification.

## Why Post-Quantum Cryptography?

Current cryptographic systems (RSA, ECC, ECDSA) will be broken by quantum computers running Shor's algorithm. NIST has standardized new quantum-resistant algorithms:

| Standard | Algorithm | Type | Status |
|----------|-----------|------|--------|
| **FIPS 203** | ML-KEM (formerly CRYSTALS-Kyber) | Key Encapsulation | Finalized 2024 |
| **FIPS 204** | ML-DSA (formerly CRYSTALS-Dilithium) | Digital Signature | Finalized 2024 |
| **FIPS 205** | SLH-DSA (formerly SPHINCS+) | Hash-based Signature | Finalized 2024 |

This MCP server makes these algorithms accessible to AI agents for research, development, and integration.

## Features

- **Key Encapsulation Mechanisms (KEMs) available via liboqs**: ML-KEM, FrodoKEM, HQC, BIKE, Classic McEliece
- **Signature algorithms available via liboqs**: ML-DSA, Falcon, SLH-DSA, MAYO, CROSS, UOV
- **Full MCP Integration**: Works with Claude Desktop, Claude Code, Cursor, and any MCP client
- **Supports NIST-standardized algorithms**: Implements FIPS 203, 204, and 205 algorithms
- **Security Analysis**: Compare classical vs quantum security levels

## Quick Start

### Prerequisites

- Python 3.10+
- [liboqs](https://github.com/open-quantum-safe/liboqs) shared library
- [uv](https://github.com/astral-sh/uv) (recommended) or pip

### Installation

#### 1. Install liboqs

**macOS (Homebrew with shared library):**
```bash
# Homebrew only provides static library, build from source for shared:
git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs.git
cd liboqs && mkdir build && cd build
cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=$HOME/.local ..
make -j4 && make install
```

**Ubuntu/Debian:**
```bash
sudo apt-get install liboqs-dev
```

#### 2. Clone and Install

```bash
git clone https://github.com/scottdhughes/post-quantum-mcp.git
cd post-quantum-mcp

# Install all dependencies (creates .venv automatically)
uv sync --all-extras
```

#### 3. Configure Claude Code / Claude Desktop

Add to your MCP configuration:

**Claude Code (`~/.claude.json`):**
```json
{
  "mcpServers": {
    "pqc": {
      "type": "stdio",
      "command": "/path/to/post-quantum-mcp/run.sh",
      "args": [],
      "env": {}
    }
  }
}
```

**Claude Desktop (`claude_desktop_config.json`):**
```json
{
  "mcpServers": {
    "pqc": {
      "command": "/path/to/post-quantum-mcp/run.sh"
    }
  }
}
```

## Available Tools

### `pqc_list_algorithms`
List all available post-quantum algorithms.

```
Input: { "type": "kem" | "sig" | "all" }
Output: List of available algorithms with NIST standard mappings
```

### `pqc_algorithm_info`
Get detailed information about a specific algorithm.

```
Input: { "algorithm": "ML-KEM-768" }
Output: Key sizes, security level, performance characteristics
```

### `pqc_generate_keypair`
Generate a quantum-resistant key pair.

```
Input: { "algorithm": "ML-DSA-65" }
Output: Base64-encoded public and secret keys
```

### `pqc_encapsulate`
Perform key encapsulation (create shared secret).

```
Input: { "algorithm": "ML-KEM-768", "public_key": "<base64>" }
Output: Ciphertext and shared secret
```

### `pqc_decapsulate`
Recover shared secret from ciphertext.

```
Input: { "algorithm": "ML-KEM-768", "secret_key": "<base64>", "ciphertext": "<base64>" }
Output: Shared secret
```

### `pqc_sign`
Sign a message with a post-quantum signature.

```
Input: { "algorithm": "ML-DSA-65", "secret_key": "<base64>", "message": "Hello, quantum world!" }
Output: Base64-encoded signature
```

### `pqc_verify`
Verify a post-quantum signature.

```
Input: { "algorithm": "ML-DSA-65", "public_key": "<base64>", "message": "...", "signature": "<base64>" }
Output: { "valid": true/false }
```

### `pqc_hash`
Hash a message using quantum-safe hash functions.

```
Input: { "message": "data", "algorithm": "SHA3-256" | "SHA3-512" | "SHAKE128" | "SHAKE256" }
Output: Digest in hex and base64
```

### `pqc_security_analysis`
Analyze security properties of an algorithm.

```
Input: { "algorithm": "ML-KEM-768" }
Output: NIST level, classical/quantum security equivalents, Grover/Shor resistance
```

## Hybrid Key Exchange (X25519 + ML-KEM-768)

Suite: `mlkem768-x25519-sha3-256` — borrows the KEM combiner from the LAMPS composite ML-KEM draft (`id-MLKEM768-X25519-SHA3-256`). The sealed-envelope layer is this project's own protocol built on top of that combiner.

This is an **anonymous sealed-box** construction providing hybrid confidentiality with ciphertext integrity. It is not forward-secret against recipient key compromise, and it is not sender-authenticated.

### `pqc_hybrid_keygen`
Generate a hybrid keypair bundle. No parameters needed.

### `pqc_hybrid_encap` / `pqc_hybrid_decap`
Building-block key encapsulation. Returns a combined shared secret derived via the suite's SHA3-256 combiner.

### `pqc_hybrid_seal` / `pqc_hybrid_open`
Encrypt/decrypt plaintext using hybrid encapsulation + AES-256-GCM. Full-header AAD binding. Deterministic nonce (not transmitted in envelope).

### Example Hybrid Usage

> "Generate a hybrid keypair and seal a message for me"

> "Perform a hybrid key exchange and show me the shared secret"

> "Encrypt 'classified data' using hybrid PQC and then decrypt it"

## Supported Algorithms

> **Note:** Legacy algorithm names (Kyber, Dilithium, SPHINCS+) are accepted as aliases for compatibility with older liboqs versions.

### Key Encapsulation Mechanisms (KEMs)

| Algorithm | NIST Level | Public Key | Ciphertext | Shared Secret |
|-----------|------------|------------|------------|---------------|
| ML-KEM-512 | 1 | 800 B | 768 B | 32 B |
| ML-KEM-768 | 3 | 1,184 B | 1,088 B | 32 B |
| ML-KEM-1024 | 5 | 1,568 B | 1,568 B | 32 B |
| FrodoKEM-640 | 1 | 9,616 B | 9,720 B | 16 B |
| HQC-128 | 1 | 2,249 B | 4,481 B | 64 B |

### Digital Signatures

| Algorithm | NIST Level | Public Key | Signature | Notes |
|-----------|------------|------------|-----------|-------|
| ML-DSA-44 | 2 | 1,312 B | 2,420 B | Balanced |
| ML-DSA-65 | 3 | 1,952 B | 3,309 B | Recommended |
| ML-DSA-87 | 5 | 2,592 B | 4,627 B | High security |
| Falcon-512 | 1 | 897 B | 653 B | Smallest sigs |
| Falcon-1024 | 5 | 1,793 B | 1,280 B | Compact |
| SLH-DSA-SHA2-128f (formerly SPHINCS+-SHA2-128f) | 1 | 32 B | 17,088 B | Stateless, hash-based |
| SLH-DSA-SHA2-256f (formerly SPHINCS+-SHA2-256f) | 5 | 64 B | 49,856 B | Maximum security |

## Example Usage with Claude

Once configured, you can ask Claude:

> "Generate an ML-KEM-768 keypair and show me the security analysis"

> "Sign the message 'Hello quantum world' using ML-DSA-65 and verify it"

> "Compare the signature sizes of Falcon-512 vs SLH-DSA-SHA2-128f"

> "What's the quantum security level of ML-KEM-1024?"

## Architecture

```
post-quantum-mcp/
├── pqc_mcp_server/
│   ├── __init__.py      # MCP server + tool handlers
│   ├── __main__.py      # Entry point
│   └── hybrid.py        # Hybrid X25519 + ML-KEM-768 crypto (suite: mlkem768-x25519-sha3-256)
├── tests/               # 73 tests (KEM, signatures, hashing, hybrid, MCP handlers)
├── .github/workflows/   # CI pipeline (Python 3.10-3.13 × Ubuntu/macOS)
├── run.sh               # Wrapper script (sets library paths, finds venv)
├── pyproject.toml       # Package configuration
├── uv.lock              # Cross-platform lockfile
├── CHANGELOG.md
└── README.md
```

## Security Considerations

- **Not for production.** liboqs is research/prototyping software. Secret material appears in tool output.
- **Key Storage**: Keys are generated in memory and returned in tool output. No persistent key storage.
- **Side Channels**: liboqs implementations aim to be constant-time but may not be suitable for all threat models.
- **Algorithm Selection**: ML-KEM and ML-DSA are NIST-standardized. Other algorithms are experimental.
- **Hybrid Scheme**: The sealed-envelope layer is anonymous (not sender-authenticated) and not forward-secret against recipient key compromise.
- **Version Compatibility**: Tested with liboqs 0.15.0 + liboqs-python 0.14.1. Version skew may produce warnings.

## Development

```bash
# Run tests
uv run pytest tests/ -v

# Format code
uv run black pqc_mcp_server/ tests/

# Type checking
uv run mypy pqc_mcp_server/
```

## Related Projects

- [Open Quantum Safe](https://openquantumsafe.org/) - The liboqs library
- [Model Context Protocol](https://modelcontextprotocol.io/) - MCP specification
- [quantum-proof-bitcoin](https://github.com/scottdhughes/quantum-proof-bitcoin) - Bitcoin with PQC signatures

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.

## Acknowledgments

- [Open Quantum Safe Project](https://openquantumsafe.org/) for liboqs
- [Anthropic](https://anthropic.com/) for the Model Context Protocol
- NIST for PQC standardization efforts
