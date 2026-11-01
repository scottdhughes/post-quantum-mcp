# Post-Quantum Cryptography MCP Server

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![liboqs](https://img.shields.io/badge/liboqs-0.16.0-green.svg)](https://openquantumsafe.org/)
[![MCP](https://img.shields.io/badge/MCP-1.30+-purple.svg)](https://modelcontextprotocol.io/)

> **Research and Prototyping Only.** This server uses [liboqs](https://github.com/open-quantum-safe/liboqs), which is explicitly not recommended for production use or for protecting sensitive data. When using `store_as` mode (recommended), secret keys are redacted from tool output and held in a session-scoped keyring. Without `store_as`, secret keys and shared secrets appear in tool output, which may enter model context, client logs, or transcripts. Set `PQC_REQUIRE_KEY_HANDLES=1` to enforce handle-only mode for all secret-key operations. Suitable for experimentation, education, and interoperability testing.

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

#### 1. Clone and build the aligned backend

```bash
git clone https://github.com/scottdhughes/post-quantum-mcp.git
cd post-quantum-mcp
mkdir -p .vendor/liboqs-0.16
bash scripts/install-liboqs.sh --prefix "$PWD/.vendor/liboqs-0.16"
```

The script builds liboqs 0.16.0 as a shared library and installs build tools through
Homebrew or apt if needed. The project-local prefix avoids a system-wide liboqs
installation. Distribution packages may lag the tested version.

#### 2. Install locked Python dependencies

```bash
uv sync --frozen --all-extras
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
      "env": {"PQC_REQUIRE_KEY_HANDLES": "1"}
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
Input: { "algorithm": "ML-DSA-65", "store_as": "sender-signing" }
Output: Public key and opaque handle (private key stays in the server)
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

Suite: `mlkem768-x25519-sha3-256` — borrows the KEM combiner from the LAMPS composite ML-KEM draft (`id-MLKEM768-X25519-SHA3-256`). The `sha3-256` in the suite name refers to the KEM combiner hash; HKDF key derivation uses SHA-256 (via `cryptography` HKDF). The sealed-envelope layer is this project's own protocol built on top of that combiner.

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
    "version": "pqc-mcp-v3",
    "mode": "anon-seal",
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
    "version": "pqc-mcp-v3",
    "mode": "auth-seal",
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
  "version": "pqc-mcp-v3",
  "mode": "auth-seal",
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
  "version": "pqc-mcp-v3",
  "mode": "auth-seal",
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

### v3 Envelope Protocol
v3 envelopes are mode-bound: every envelope carries an explicit `mode` field (`anon-seal` or `auth-seal`) that is bound into HKDF info, AAD, and the auth transcript. This provides true cross-mode separation — ciphertext produced by one mode cannot be decrypted by the other, blocking auth-stripping downgrade attacks at the AEAD layer. AAD uses length-prefixed framing (self-delimiting) in v3. Authenticated envelopes include a signed `timestamp` field in the canonical transcript; on verification/open, the server checks freshness (default: 24 hours, configurable via `max_age_seconds`). Clock skew tolerance is 5 minutes.

### Replay Protection
Authenticated MCP open calls use `~/.pqc/state/replay-cache.sqlite3`. SQLite transactions coordinate processes sharing that file. The signature digest is checked/inserted atomically after successful verification and decryption; verify-only calls do not mark it. Persistence failure, corruption, and a full 50,000-entry store fail closed. Live entries are retained for 24 hours plus 301 seconds (the permitted 300-second future clock skew and a one-second boundary margin) rather than evicted. A valid existing JSON cache is imported once; malformed legacy state blocks initialization instead of silently resetting it. The legacy JSON `ReplayCache` class remains available for diagnostic compatibility and is not the server default.

MCP `max_age_seconds` must be positive and cannot exceed the configured replay acceptance window. The low-level library API still permits research opt-outs. Deduplication is not application-level exactly-once processing: a crash after open but before processing or acknowledgment requires an application recovery strategy.

### Envelope Size Validation
Local seals accept at most 1,048,576 **decoded bytes**, including UTF-8 encoding costs. The ciphertext base64 allowance includes the 16-byte GCM tag and base64 expansion, so a successful local seal can be opened. Other envelope field/field-count bounds still apply. The relay separately limits the entire serialized JSON request to 51,200 bytes; a locally valid envelope can be too large for relay delivery.

### Server Security Policy
Set `PQC_REQUIRE_KEY_HANDLES=1` to reject raw private-key arguments and require `store_as` during both generic and hybrid key generation. Names must be non-blank strings of at most 128 characters; missing, null, and empty handles cannot fall back to raw key output. Handles last only for the server process. This policy prevents private-key bytes from being returned by key generation; it does not hide plaintext from an authorized open operation or shared secrets returned by low-level KEM tools.

### v1/v2 Backwards Compatibility
New envelopes are v3. Low-level and MCP open/verify paths retain legacy v1/v2 compatibility, with warnings on authenticated verify/open. v1 lacks mandatory signed timestamps and can become replayable after finite deduplication retention; v2 lacks mode binding. Legacy support is a research compatibility concession, not equivalent security to v3. Prefer v3-only inputs in new applications.

## Relay Transport

The v0.2 relay uses SQLite-backed Durable Objects for persistent mailbox authorization, transactional quotas, message expiry, and idempotent deposits. An operator must register a mailbox before deposits or reads; GET/DELETE always require that mailbox's bearer token. Unknown mailboxes fail closed. The public endpoint listed in older releases has **not** been upgraded by these source changes.

| Endpoint | Method | Authorization |
|---|---|---|
| `/mailboxes/:fp/register` | POST | Operator admin token; issues/rotates mailbox token |
| `/mailboxes/:fp` | POST | Public deposit to an existing mailbox; advisory sender filter may apply |
| `/mailboxes/:fp` | GET | Mailbox token |
| `/mailboxes/:fp/:id` | DELETE | Mailbox token |
| `/mailboxes/:fp/allowlist` | PUT | Operator admin token; advisory sender filter |

The default admin credential is absent; missing/known development credentials are rejected. Register/rotate through operator tooling, outside model tool arguments. Configure the Python MCP server with:

```text
PQC_RELAY_ENABLED=1
PQC_RELAY_ALLOWED_URLS=https://your-relay.example
PQC_RELAY_TOKEN_FILE=/absolute/path/to/owner-only-relay-tokens.json
```

The token file must be an owner-only regular file (mode 0600 on POSIX) owned by the server user:

```json
[
  {"relay_url":"https://your-relay.example","fingerprint":"<64 lowercase hex characters>","token":"<mailbox token>"}
]
```

Credentials are scoped to origin and mailbox and are never accepted as tool arguments. Redirects are refused. GET responses are bounded to 6,000,000 decoded bytes. Relay calls run outside the MCP event loop.

Defaults: 51,200 request bytes, 1,000 live messages/mailbox, 24-hour message expiry. Credential records never expire with messages. Per-IP fixed-window rate limits use a separate Durable Object and fail closed on storage errors. Sender allowlists are advisory metadata filters; recipients must verify ML-DSA signatures.

The Python client sends a stable SHA-256 idempotency key for the canonical serialized envelope. Retries retain one message within its original TTL, even after acknowledgment. Receipt expiry permits a later new deposit; this does not promise permanent exactly-once delivery.

See [the relay contract and migration guide](deploy/relay/RELAY-SPEC.md) before deployment. Legacy KV data is retained and is not automatically imported or deleted.

## Supported Algorithms

> Algorithm names are the exact names reported by the installed liboqs build. liboqs 0.16 removed SPHINCS+ and changed FrodoKEM naming/behavior; do not assume old names are aliases. Prefer ML-KEM, ML-DSA, and SLH-DSA names.

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

The November 1, 2026 local validation used the following versions on macOS ARM64/Python 3.12.12. The configured CI matrix covers Python 3.10–3.13 on Ubuntu/macOS; use the associated GitHub Actions runs for cross-platform CI evidence.

| Component | Locally validated version | Declared dependency |
|---|---|---|
| liboqs C | 0.16.0 | Built from the release tag |
| liboqs-python | 0.16.0.2 | `>=0.16.0.2,<0.17` |
| cryptography | 50.0.2 | `>=50.0.2` |
| MCP | 1.30.0 | `>=1.30.0,<2.0.0` |
| Hypothesis | 6.170.14 | `>=6.100,<7` (dev; lock selects a compatible version on Python 3.10) |
| Wrangler / Vitest / Cloudflare test plugin | 4.156.0 / 5.0.5 / 1.4.11 | See relay package-lock.json |
| Node | 26.12.1 locally; 24 in CI | `>=24` for the relay toolchain |

Use `uv sync --frozen --all-extras` and `npm ci` to reproduce locked environments. The previous 0.15.0/0.14.1 mismatch workaround has been removed; use an aligned C library and wrapper. MCP 2.x is a separate migration.

## Development

```bash
# Run tests
uv run --frozen pytest tests/ -v

# Format code
uv run --frozen black pqc_mcp_server/ tests/

# Type checking
uv run --frozen mypy pqc_mcp_server/
```

Ordinary pytest excludes external e2e tests. To run against an explicitly selected disposable relay, set `PQC_RELAY_E2E_URL`, `PQC_RELAY_E2E_ADMIN_TOKEN`, and (for local HTTP only) `PQC_RELAY_E2E_ALLOW_HTTP=1`, then run `uv run --frozen pytest -m e2e`.

Relay checks: `npm ci && npm run typecheck && npm test && npm run build` from `deploy/relay/worker`. Tests include a SQLite-backed Node contract suite and the actual Workers runtime. See [repair status](docs/reviews/2026-11-01-repair-status.md) for measured results and limits.

Forward secrecy remains a separate next milestone. v3 envelopes are not forward-secret against later recipient-key compromise; see [the next-stage requirements](docs/forward-secrecy-next.md).

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
