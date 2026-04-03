# Post-Quantum Cryptography MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![liboqs](https://img.shields.io/badge/liboqs-0.15.0-green.svg)](https://openquantumsafe.org/)
[![MCP](https://img.shields.io/badge/MCP-1.6+-purple.svg)](https://modelcontextprotocol.io/)

> **Research and Prototyping Only.** This server uses [liboqs](https://github.com/open-quantum-safe/liboqs), which is explicitly not recommended for production use or for protecting sensitive data. When using `store_as` mode (recommended), secret keys are redacted from tool output and held in a session-scoped keyring. Without `store_as`, secret keys and shared secrets appear in tool output, which may enter model context, client logs, or transcripts. Set `PQC_REQUIRE_KEY_HANDLES=1` to enforce handle-only mode for hybrid envelope operations (note: raw PQC tools like `pqc_sign`/`pqc_decapsulate` are not yet covered). Suitable for experimentation, education, and interoperability testing.

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

**Alternative:** Use the bundled install script which automates the above:
```bash
bash scripts/install-liboqs.sh
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

The server can also be run directly via `python -m pqc_mcp_server`.

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
Generate a hybrid keypair bundle.

**Recommended: with `store_as` (secret keys redacted)**
```json
// Input
{"store_as": "alice"}

// Output — no secret keys
{
  "suite": "mlkem768-x25519-sha3-256",
  "handle": "alice",
  "classical": {"algorithm": "X25519", "public_key": "DeRN3xLbEglMdXKO7P98cAvc...", "fingerprint": "a1b2c3d4..."},
  "pqc": {"algorithm": "ML-KEM-768", "public_key": "gDsL8UgEVcMeJgUOQgSlAotx...", "fingerprint": "e5f6a7b8..."}
}
```

**Without `store_as` (raw keys returned — not recommended):**
```json
// Input
{}

// Output — secret keys exposed in tool output
{
  "suite": "mlkem768-x25519-sha3-256",
  "classical": {
    "algorithm": "X25519",
    "public_key": "DeRN3xLbEglMdXKO7P98cAvc...",
    "secret_key": "YEYD9j5c2hpTei0ferXWbAFb..."
  },
  "pqc": {
    "algorithm": "ML-KEM-768",
    "public_key": "gDsL8UgEVcMeJgUOQgSlAotx...",
    "secret_key": "MQB2U0EzNGmloLuiTYG3BTcr..."
  }
}
```

### `pqc_hybrid_encap` / `pqc_hybrid_decap`
Building-block key encapsulation. Returns a combined shared secret derived via the suite's SHA3-256 combiner.

### `pqc_hybrid_seal` / `pqc_hybrid_open`
Encrypt/decrypt plaintext using hybrid encapsulation + AES-256-GCM. Full-header AAD binding. Deterministic nonce (not transmitted in envelope).

```json
// Seal input
{
  "plaintext": "Hello, quantum world!",
  "recipient_classical_public_key": "<base64 X25519 public key>",
  "recipient_pqc_public_key": "<base64 ML-KEM-768 public key>"
}

// Seal output
{
  "envelope": {
    "version": "pqc-mcp-v2",
    "suite": "mlkem768-x25519-sha3-256",
    "x25519_ephemeral_public_key": "6+b1Y8AkgEycKL5wL2cIeSMv...",
    "pqc_ciphertext": "DF+PYy4zx+OmnW8wLD3EL+4M...",
    "ciphertext": "NnEap2fDq5+xTCwvHdKfy5Xj..."
  }
}

// Open input
{
  "envelope": { "...envelope from seal..." },
  "classical_secret_key": "<base64 X25519 secret key>",
  "pqc_secret_key": "<base64 ML-KEM-768 secret key>"
}

// Open output
{
  "suite": "mlkem768-x25519-sha3-256",
  "plaintext": "Hello, quantum world!",
  "plaintext_base64": "SGVsbG8sIHF1YW50dW0gd29ybGQh"
}
```

### Example Hybrid Prompts

> "Generate a hybrid keypair and seal a message for me"

> "Perform a hybrid key exchange and show me the shared secret"

> "Encrypt 'classified data' using hybrid PQC and then decrypt it"

## Authenticated Hybrid Envelopes

Adds sender authentication to the hybrid confidentiality layer using ML-DSA-65 (FIPS 204) signatures. The sender signs a canonical binary transcript covering the entire envelope. The recipient verifies sender identity before decryption.

This is a **sender-authenticated sealed-envelope** construction. It is still not forward-secret against later recipient long-term key compromise. The sealed-envelope layer is this project's own protocol.

### `pqc_hybrid_auth_seal`
Encrypt + sign. Requires sender ML-DSA-65 signing keys + recipient hybrid keys.

**Recommended: with key handles**
```json
// Input
{
  "plaintext": "Authenticated message",
  "recipient_key_store_name": "bob",
  "sender_key_store_name": "alice-signing"
}

// Output
{
  "envelope": {
    "version": "pqc-mcp-v2",
    "suite": "mlkem768-x25519-sha3-256",
    
    "sender_signature_algorithm": "ML-DSA-65",
    "sender_public_key": "0ji6POTItnZUX8rELwVwWSOV...",
    "sender_key_fingerprint": "0f617ece2f1d04c0...",
    "recipient_classical_key_fingerprint": "c1deade4a5300a9a...",
    "recipient_pqc_key_fingerprint": "bb0e084213d6ac74...",
    "x25519_ephemeral_public_key": "5LEikNANeJNhZSiq...",
    "pqc_ciphertext": "ybgWc3ruG3JwXmr4...",
    "ciphertext": "6OYdADdh0eH/LviD...",
    "signature": "BOniPALs1kfhWcRh..."
  }
}
```

**Alternative: with raw keys (not recommended)**
```json
// Input
{
  "plaintext": "Authenticated message",
  "recipient_classical_public_key": "<base64 X25519 public key>",
  "recipient_pqc_public_key": "<base64 ML-KEM-768 public key>",
  "sender_secret_key": "<base64 ML-DSA-65 secret key>",
  "sender_public_key": "<base64 ML-DSA-65 public key>"
}
```

### `pqc_hybrid_auth_open`
Verify sender + decrypt. Requires either `expected_sender_public_key` or `expected_sender_fingerprint`. Signature is verified before decryption — auth failures are distinct from decrypt failures.

```json
// Open with expected sender public key
{
  "envelope": { "...envelope from auth_seal..." },
  "classical_secret_key": "<base64 X25519 secret key>",
  "pqc_secret_key": "<base64 ML-KEM-768 secret key>",
  "expected_sender_public_key": "<base64 ML-DSA-65 public key>"
}

// Or open with expected sender fingerprint
{
  "envelope": { "...envelope from auth_seal..." },
  "classical_secret_key": "...",
  "pqc_secret_key": "...",
  "expected_sender_fingerprint": "0f617ece2f1d04c0481aa0fe..."
}

// Output
{
  "suite": "mlkem768-x25519-sha3-256",
  "plaintext": "Authenticated message",
  "plaintext_base64": "QXV0aGVudGljYXRlZCBtZXNzYWdl",
  "sender_key_fingerprint": "0f617ece2f1d04c0481aa0fe...",
  "sender_signature_algorithm": "ML-DSA-65",
  "authenticated": true
}
```

### `pqc_hybrid_auth_verify`
Verify sender signature on an authenticated envelope WITHOUT decrypting. No secret keys needed. Checks sender binding, fingerprint consistency, ML-DSA-65 signature, and timestamp freshness.

```json
// Input
{
  "envelope": { "...envelope from auth_seal..." },
  "expected_sender_fingerprint": "0f617ece2f1d04c0..."
}

// Output
{
  "verified": true,
  "sender_key_fingerprint": "0f617ece2f1d04c0...",
  "sender_signature_algorithm": "ML-DSA-65",
  "version": "pqc-mcp-v2",
  "replay_seen": false,
  "timestamp": "1711929600"
}
```

### `pqc_envelope_inspect`
Inspect envelope metadata without decrypting. No secret keys needed. Returns version, suite, fingerprints, and field sizes.

```json
// Input
{"envelope": { "...any sealed or authenticated envelope..." }}

// Output
{
  "version": "pqc-mcp-v2",
  "suite": "mlkem768-x25519-sha3-256",
  "authenticated": true,
  "sender_key_fingerprint": "0f617ece2f1d04c0...",
  
  
  "ciphertext_size": 1234,
  "plaintext_size_approx": 1218,
  "pqc_ciphertext_size": 1088,
  "signature_size": 3309
}
```

### `pqc_fingerprint`
Compute SHA3-256 fingerprint of a public key. Returns lowercase hex.

```json
// Input
{"public_key": "<base64-encoded public key>"}

// Output
{"fingerprint": "a1b2c3d4e5f6...", "algorithm": "SHA3-256"}
```

### `pqc_benchmark`
Benchmark a PQC algorithm: timed keygen, encap/sign, decap/verify, and key/ciphertext/signature sizes.

```json
// Input
{"algorithm": "ML-KEM-768", "iterations": 10}

// Output — timing and size measurements
```

### Key Generation Flow
```
1. Sender: generate ML-DSA-65 signing keys via pqc_generate_keypair
2. Recipient: generate hybrid keys via pqc_hybrid_keygen
3. Exchange public keys out-of-band
4. Sender: pqc_hybrid_auth_seal with both key sets
5. Recipient: pqc_hybrid_auth_open with expected sender identity
```

### Example Authenticated Prompts

> "Generate an ML-DSA-65 signing keypair and a hybrid recipient keypair, then send an authenticated encrypted message"

> "Open this authenticated envelope and verify it came from the expected sender"

> "Seal a message to Bob and sign it with my ML-DSA key, then have Bob open it using my fingerprint"

## Key Handles (Secret Redaction)

Opt-in mode where secret keys are stored process-locally and never appear in tool output. Handles are process-global and lost on server restart.

### Generating with handles
```json
// pqc_hybrid_keygen with store_as
{"store_as": "alice"}

// Output — no secret keys
{
  "suite": "mlkem768-x25519-sha3-256",
  "handle": "alice",
  "classical": {"algorithm": "X25519", "public_key": "...", "fingerprint": "..."},
  "pqc": {"algorithm": "ML-KEM-768", "public_key": "...", "fingerprint": "..."}
}
```

### Using handles in downstream tools
```json
// pqc_hybrid_seal with store name instead of raw keys
{
  "plaintext": "Hello via handle!",
  "recipient_key_store_name": "alice"
}

// pqc_hybrid_auth_seal with two store names
{
  "plaintext": "Authenticated via handles",
  "recipient_key_store_name": "alice",
  "sender_key_store_name": "bob-signing"
}
```

Generic PQC tools (`pqc_sign`, `pqc_verify`, `pqc_encapsulate`, `pqc_decapsulate`) also accept `key_store_name`.

Providing both a store name and raw keys for the same role is an error.

### Key Store Management

- **`pqc_key_store_save`**: Save a keygen output by name for convenient reference. Session-scoped, no persistence.
- **`pqc_key_store_load`**: Load a stored key by name. Returns public material only for handle entries.
- **`pqc_key_store_list`**: List all stored keys with metadata (names, types, fingerprints). No secret material shown.
- **`pqc_key_store_delete`**: Delete a stored key by name.

## Security Features

### v2 Envelope Protocol
Authenticated envelopes now include a signed `timestamp` field in the canonical transcript. On verification/open, the server checks freshness (default: 24 hours, configurable via `max_age_seconds`). Clock skew tolerance is 5 minutes. Anonymous (non-authenticated) envelopes are unaffected.

### Replay Protection
The server maintains a signature-digest cache (SHA3-256 of envelope signature bytes) with TTL. `pqc_hybrid_auth_verify` performs a read-only replay check. `pqc_hybrid_auth_open` performs check-before-decrypt and mark-after-success. The cache persists to `~/.pqc/state/replay-cache.json` and survives server restarts. Max 50,000 entries with oldest-first eviction.

### Envelope Size Validation
All envelopes are validated before any cryptographic processing: max 1MB per base64 field (`ciphertext`, `pqc_ciphertext`, `signature`, `sender_public_key`, `x25519_ephemeral_public_key`), max 50 fields total. Prevents memory bombs and resource exhaustion.

### Server Security Policy
Set `PQC_REQUIRE_KEY_HANDLES=1` to enforce handle-only mode: the server rejects any tool call that passes raw secret keys, forcing use of `store_as`/`key_store_name` for all secret-key operations. This is a server-side check that cannot be bypassed by a misbehaving agent.

### v1 Backwards Compatibility
v1 envelopes (`pqc-mcp-v1`) are accepted on open/verify for backwards compatibility but produce a loud warning. v1 envelopes lack signed timestamps and therefore skip freshness checks and provide no replay protection.

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
│   ├── __init__.py          # MCP server setup + tool dispatch
│   ├── __main__.py          # Entry point
│   ├── tools.py             # Tool definitions (24 tools)
│   ├── handlers_pqc.py      # Core PQC handlers (KEM, signatures, hashing)
│   ├── handlers_hybrid.py   # Hybrid, authenticated, and utility handlers
│   ├── hybrid.py            # Crypto implementation (X25519, ML-KEM, ML-DSA, envelopes)
│   ├── key_store.py         # Session-scoped secret-handle keyring
│   ├── security_policy.py   # Server-enforced security checks (PQC_REQUIRE_KEY_HANDLES)
│   ├── replay_cache.py      # Signature-digest replay dedup with TTL
│   └── filesystem.py        # Secure directory/file permission helpers
├── examples/                # Runnable Python examples
│   ├── anonymous_envelope.py
│   ├── authenticated_envelope.py
│   └── failure_modes.py
├── tests/                   # Unit, handler, and stdio integration tests
├── scripts/
│   └── install-liboqs.sh   # Automated liboqs build script
├── .github/workflows/       # CI pipeline (Python 3.10-3.13 × Ubuntu/macOS)
├── run.sh                   # Wrapper script (sets library paths, finds venv)
├── pyproject.toml           # Package configuration
├── uv.lock                  # Cross-platform lockfile
├── CHANGELOG.md
└── README.md
```

## Threat Model / Guarantees / Non-Goals

### What this provides
- **Hybrid confidentiality**: shared secret is protected unless both X25519 and ML-KEM-768 are broken simultaneously.
- **Ciphertext integrity**: AES-256-GCM with full-header AAD binding detects tampering.
- **Sender authentication** (authenticated mode only): ML-DSA-65 signature over a canonical transcript proves sender identity. Signature is verified before decryption.
- **Quantum resistance**: ML-KEM-768 (FIPS 203, NIST Level 3) resists Shor's algorithm. ML-DSA-65 (FIPS 204) provides post-quantum signature security.

### What this does NOT provide
- **Forward secrecy.** Neither envelope mode is forward-secret against later recipient long-term key compromise. FIPS 203 decapsulation is deterministic from (decapsulation key, ciphertext), and X25519 ECDH is deterministic from (private key, peer public key).
- **Mutual authentication.** The authenticated mode proves sender identity to the recipient. It does not prove recipient identity to the sender.
- **Session protocols.** This is single-shot sealed-envelope encryption, not a session protocol, ratchet, or PQXDH.
- **Production readiness.** liboqs is research/prototyping software and is not recommended for production use or protecting sensitive data.

### Operational considerations
- **Secret material in tool output.** When using `store_as`, secret keys are redacted from tool output and held in a session-scoped handle keyring. Without `store_as`, keys, shared secrets, and signatures appear in MCP tool responses, which may enter model context, client logs, or transcripts. Set `PQC_REQUIRE_KEY_HANDLES=1` to reject raw secret keys server-wide.
- **Key storage.** Keys generated with `store_as` are held in a session-scoped in-memory keyring (process-global, lost on server restart). Without `store_as`, keys are generated in memory and returned in tool output with no persistent storage.
- **Side channels.** liboqs implementations aim to be constant-time but may not be suitable for all threat models.
- **Anonymous vs authenticated.** `hybrid_seal`/`hybrid_open` is anonymous — anyone with recipient public keys can seal. `hybrid_auth_seal`/`hybrid_auth_open` adds sender authentication via ML-DSA-65 signature.
- **Version compatibility.** See Tested Compatibility below.

## Tested Compatibility

This table shows the exact versions CI-tested on every push. Other combinations may work but are not verified.

| Component | CI-Tested Version | Floor (pyproject.toml) | Notes |
|-----------|------------------|----------------------|-------|
| **liboqs** (C library) | 0.15.0 | — (built from source) | CI builds from source on Ubuntu and macOS |
| **liboqs-python** | 0.14.1 | `>=0.10.0` | Version skew with liboqs 0.15.0 produces a warning; all 110 tests pass |
| **cryptography** | 46.0.6 | `>=42.0.0` | X25519, HKDFExpand, AESGCM |
| **mcp** | 1.26.0 | `>=1.6.0,<2.0.0` | MCP Server + stdio transport |
| **Python** | 3.10, 3.11, 3.12, 3.13 | `>=3.10` | Full matrix on Ubuntu + macOS |

**liboqs / liboqs-python version skew:** The C library at 0.15.0 paired with the Python wrapper at 0.14.1 triggers `UserWarning: liboqs version (major, minor) 0.15.0 differs from liboqs-python version 0.14.1`. This is cosmetic — all algorithms used by this project (ML-KEM-768, ML-DSA-65, ML-DSA-44/87, Falcon, SLH-DSA) work correctly. When liboqs-python 0.15.x reaches PyPI, update and the warning will resolve.

**What "may work" means:** Versions above the pyproject.toml floor but not in the CI-tested column are untested. They will likely work if no breaking API changes occurred, but we make no guarantee. If you encounter issues, pin to the CI-tested versions.

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
