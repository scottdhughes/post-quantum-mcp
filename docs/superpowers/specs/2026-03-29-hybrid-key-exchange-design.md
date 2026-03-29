# Hybrid X25519 + ML-KEM Key Exchange — Design Spec

**Date:** 2026-03-29
**Status:** Approved
**Author:** Scott Hughes + Claude

## Goal

Add hybrid classical + post-quantum key exchange to the post-quantum-mcp server. Two layers: building-block tools (keygen, encap, decap) and a complete sealed envelope (seal, open). This makes the MCP server the first to offer production-grade hybrid PQC key exchange for AI assistants.

## Why Hybrid

No single algorithm is trusted alone during the quantum transition:

- **If ML-KEM breaks** (cryptanalytic advance against lattices): X25519 still protects the shared secret.
- **If X25519 breaks** (quantum computer running Shor's): ML-KEM still protects the shared secret.
- Both must fail simultaneously for the exchange to be compromised.

This is what TLS 1.3, Signal, iMessage, and Chrome deploy today. NIST SP 800-227 explicitly endorses this pattern.

## New Dependency

**`cryptography>=42.0.0`** added to `pyproject.toml` dependencies. Provides:

- `cryptography.hazmat.primitives.asymmetric.x25519` — X25519 keygen + ECDH
- `cryptography.hazmat.primitives.kdf.hkdf` — HKDF-SHA256 (Extract + Expand)
- `cryptography.hazmat.primitives.ciphers.aead.AESGCM` — AES-256-GCM

## New Tools

### Layer 1 — Building Blocks

#### `pqc_hybrid_keygen`

Generate a hybrid keypair bundle (X25519 + ML-KEM).

**Input:**
```json
{
  "kem_algorithm": "ML-KEM-768"  // optional, defaults to ML-KEM-768
}
```

**Output:**
```json
{
  "kem_algorithm": "ML-KEM-768",
  "classical": {
    "algorithm": "X25519",
    "public_key": "<base64>",
    "secret_key": "<base64>"
  },
  "pqc": {
    "algorithm": "ML-KEM-768",
    "public_key": "<base64>",
    "secret_key": "<base64>"
  }
}
```

#### `pqc_hybrid_encap`

Perform hybrid key encapsulation against a recipient's public keys. Generates an ephemeral X25519 keypair, performs ECDH + ML-KEM encap, combines via HKDF.

**Input:**
```json
{
  "classical_public_key": "<base64 X25519 public key>",
  "pqc_public_key": "<base64 ML-KEM public key>",
  "kem_algorithm": "ML-KEM-768"  // optional
}
```

**Output:**
```json
{
  "shared_secret": "<base64, 32 bytes>",
  "shared_secret_hex": "<hex>",
  "classical_ciphertext": "<base64 ephemeral X25519 public key>",
  "pqc_ciphertext": "<base64 ML-KEM ciphertext>",
  "kem_algorithm": "ML-KEM-768"
}
```

#### `pqc_hybrid_decap`

Recover the shared secret using both secret keys.

**Input:**
```json
{
  "classical_secret_key": "<base64 X25519 secret key>",
  "pqc_secret_key": "<base64 ML-KEM secret key>",
  "classical_ciphertext": "<base64 ephemeral X25519 public key>",
  "pqc_ciphertext": "<base64 ML-KEM ciphertext>",
  "kem_algorithm": "ML-KEM-768"  // optional
}
```

**Output:**
```json
{
  "shared_secret": "<base64, 32 bytes>",
  "shared_secret_hex": "<hex>",
  "kem_algorithm": "ML-KEM-768"
}
```

### Layer 2 — Sealed Envelope

#### `pqc_hybrid_seal`

Encrypt plaintext using hybrid key exchange + AES-256-GCM. One-shot operation: encap + derive AES key + encrypt.

**Input:**
```json
{
  "plaintext": "Hello, quantum world!",
  "recipient_classical_public_key": "<base64 X25519 public key>",
  "recipient_pqc_public_key": "<base64 ML-KEM public key>",
  "kem_algorithm": "ML-KEM-768"  // optional
}
```

**Output:**
```json
{
  "envelope": {
    "version": "pqc-mcp-v1",
    "kem_algorithm": "ML-KEM-768",
    "classical_ciphertext": "<base64>",
    "pqc_ciphertext": "<base64>",
    "nonce": "<base64, 12 bytes>",
    "encrypted_data": "<base64>",
    "tag": "<base64, 16 bytes>"
  }
}
```

#### `pqc_hybrid_open`

Decrypt a sealed envelope using both secret keys.

**Input:**
```json
{
  "envelope": { "...same structure as seal output..." },
  "classical_secret_key": "<base64 X25519 secret key>",
  "pqc_secret_key": "<base64 ML-KEM secret key>"
}
```

The `kem_algorithm` is read from `envelope.kem_algorithm` — no separate parameter needed.

**Output:**
```json
{
  "plaintext": "Hello, quantum world!",
  "kem_algorithm": "ML-KEM-768"
}
```

## Cryptographic Construction

### Combiner (HKDF-SHA256)

Follows NIST SP 800-227, TLS 1.3 (`X25519MLKEM768`), and RFC 5869.

```
# Step 1: Concatenate shared secrets (FIPS-approved scheme first)
ikm = ss_mlkem (32 bytes) || ss_x25519 (32 bytes)

# Step 2: Extract — concentrate entropy into a PRK
prk = HKDF-Extract(salt=None, ikm=ikm)
    # salt=None means zero-filled HashLen bytes, per RFC 5869
    # Matches TLS 1.3 and Signal PQXDH

# Step 3: Expand — derive keys with domain-separated info strings
```

### Info String Format

Domain separation per RFC 5869 Section 3.2, matching Signal PQXDH and HPKE patterns:

```
"pqc-mcp-v1 X25519-{kem_algorithm} {purpose}"
```

Where `{purpose}` is one of:
- `shared-secret` — for building-block layer output
- `aes-256-gcm-key` — for seal/open AES key
- `aes-256-gcm-nonce` — for seal/open deterministic nonce

Example: `b"pqc-mcp-v1 X25519-ML-KEM-768 aes-256-gcm-key"`

### Key Derivation (Building Block Layer)

```python
shared_secret = HKDF-Expand(
    prk,
    info=f"pqc-mcp-v1 X25519-{kem_alg} shared-secret".encode(),
    length=32
)
```

### Key Derivation (Envelope Layer)

```python
aes_key = HKDF-Expand(
    prk,
    info=f"pqc-mcp-v1 X25519-{kem_alg} aes-256-gcm-key".encode(),
    length=32
)

nonce = HKDF-Expand(
    prk,
    info=f"pqc-mcp-v1 X25519-{kem_alg} aes-256-gcm-nonce".encode(),
    length=12
)
```

The nonce is deterministic, not random. This is safe because each seal generates a fresh ephemeral X25519 keypair, producing a unique PRK per operation. A deterministic nonce from a unique PRK cannot collide. This eliminates RNG dependency for the nonce and follows the HPKE pattern.

### Encryption

```python
aesgcm = AESGCM(aes_key)
encrypted_data_with_tag = aesgcm.encrypt(nonce, plaintext_bytes, associated_data=None)
# GCM appends 16-byte auth tag; split for the envelope
encrypted_data = encrypted_data_with_tag[:-16]
tag = encrypted_data_with_tag[-16:]
```

### Security Properties

| Property | Guarantee |
|----------|-----------|
| **Quantum resistance** | ML-KEM (FIPS 203, lattice-based) resists Shor's algorithm |
| **Classical fallback** | X25519 (Curve25519 ECDH) protects if ML-KEM is broken |
| **Forward secrecy** | Ephemeral X25519 keypair per encapsulation |
| **Ciphertext integrity** | AES-256-GCM authenticated encryption (16-byte tag) |
| **Domain separation** | HKDF info strings prevent cross-protocol key reuse |
| **Nonce safety** | Deterministic nonce from unique-per-operation PRK |

### Standards Alignment

| Decision | Aligned With |
|----------|-------------|
| ML-KEM secret first in IKM | NIST SP 800-56Cr2, TLS 1.3 `X25519MLKEM768` |
| `salt=None` | TLS 1.3, Signal PQXDH |
| Single Extract + multiple Expand | RFC 5869, HPKE (RFC 9180) |
| Algorithm IDs in info | Signal PQXDH, HPKE suite_id |
| Concatenation combiner | NIST SP 800-227, dual-PRF security proof (Bindel et al.) |

## Code Organization

### New file: `pqc_mcp_server/hybrid.py`

Pure crypto logic, no MCP dependencies. Contains:

- `hybrid_keygen(kem_algorithm) -> dict` — generate X25519 + ML-KEM keypair bundle
- `hybrid_encap(classical_pk, pqc_pk, kem_algorithm) -> dict` — encapsulate, return shared secret + ciphertexts
- `hybrid_decap(classical_sk, pqc_sk, classical_ct, pqc_ct, kem_algorithm) -> dict` — decapsulate, return shared secret
- `hybrid_seal(plaintext, recipient_classical_pk, recipient_pqc_pk, kem_algorithm) -> dict` — full encrypt
- `hybrid_open(envelope, classical_sk, pqc_sk) -> dict` — full decrypt
- `_derive_prk(ss_mlkem, ss_x25519) -> bytes` — internal HKDF-Extract
- `_expand_key(prk, kem_algorithm, purpose, length) -> bytes` — internal HKDF-Expand

### Modified file: `pqc_mcp_server/__init__.py`

- Import from `hybrid.py`
- Add 5 new Tool definitions to `list_tools()`
- Add 5 new tool handlers to `call_tool()`
- Handle `HAS_CRYPTOGRAPHY` flag similar to `HAS_LIBOQS`

### New file: `tests/test_hybrid.py`

Test cases:

1. **Keygen** — produces valid key bundles with correct sizes
2. **Encap/decap roundtrip** — shared secrets match
3. **Seal/open roundtrip** — plaintext recovers
4. **Wrong key decap** — produces different shared secret (ML-KEM implicit rejection)
5. **Wrong key open** — AES-GCM tag verification fails (raises error)
6. **Tampered ciphertext** — open fails
7. **Tampered encrypted data** — open fails (GCM integrity)
8. **Non-default KEM** — ML-KEM-512 and ML-KEM-1024 work
9. **Deterministic nonce** — same PRK produces same nonce (verified by re-deriving)
10. **Domain separation** — building-block shared secret differs from seal's AES key

### Modified file: `pyproject.toml`

- Add `cryptography>=42.0.0` to dependencies

### Modified file: `README.md`

- Add "Hybrid Key Exchange" section after existing tools
- Add hybrid tools to the Available Tools list
- Add example Claude prompts for hybrid operations
- Update Features bullet list

### Modified file: `CHANGELOG.md`

- Add hybrid key exchange entries to Unreleased section
