# Hybrid X25519 + ML-KEM Key Exchange — Design Spec

**Date:** 2026-03-29
**Status:** Revised (v2)
**Author:** Scott Hughes + Claude

## Goal

Add hybrid classical + post-quantum key exchange to the post-quantum-mcp server. Two layers: building-block tools (keygen, encap, decap) and an anonymous sealed-box envelope (seal, open).

**Scope disclaimer:** This is research and prototyping tooling. liboqs upstream explicitly states it is not recommended for production use or to protect sensitive data. This server returns secret material into tool output, which may enter model context, client logs, or transcripts. That is acceptable for the intended use cases (hybrid PQC demos, agent-to-agent experiments, test-vector generation, algorithm education) but must be stated conspicuously.

## Why Hybrid

No single algorithm is trusted alone during the quantum transition:

- **If ML-KEM breaks** (cryptanalytic advance against lattices): X25519 still protects the shared secret.
- **If X25519 breaks** (quantum computer running Shor's): ML-KEM still protects the shared secret.
- Both must fail simultaneously for the exchange to be compromised.

This is the pattern deployed in TLS 1.3 (`X25519MLKEM768`), Signal PQXDH, and iMessage PQ3. NIST SP 800-227 explicitly endorses hybrid combiners.

## Scheme Classification

This is an **anonymous sealed-box** construction. Anyone with the recipient's public keys can produce a valid envelope. There is no sender authentication — the recipient cannot verify who sealed the envelope. This is analogous to NaCl's `crypto_box_seal`.

This is **not** an authenticated key exchange. It is **not** forward-secret against recipient key compromise. The sender uses an ephemeral X25519 key, but the recipient uses long-term ML-KEM and X25519 secret keys. If an attacker records the ciphertexts today and later compromises the recipient's long-term private keys, they can recover the shared secret: FIPS 203 decapsulation is deterministic from (decapsulation key, ciphertext), and X25519 ECDH is deterministic from (private key, peer public key).

The correct characterization is: **hybrid confidentiality with ciphertext integrity**.

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
    "public_key": "<base64, raw 32 bytes>",
    "secret_key": "<base64, raw 32 bytes>"
  },
  "pqc": {
    "algorithm": "ML-KEM-768",
    "public_key": "<base64>",
    "secret_key": "<base64>"
  }
}
```

X25519 keys are raw 32-byte values per RFC 7748. Public key is the result of `X25519PublicKey.public_bytes(Raw, Raw)`. Secret key is the result of `X25519PrivateKey.private_bytes(Raw, Raw, NoEncryption)`.

#### `pqc_hybrid_encap`

Perform hybrid key encapsulation against a recipient's public keys. Generates an ephemeral X25519 keypair, performs ECDH + ML-KEM encap, combines via HKDF.

**Input:**
```json
{
  "classical_public_key": "<base64, raw 32-byte X25519 public key>",
  "pqc_public_key": "<base64 ML-KEM public key>",
  "kem_algorithm": "ML-KEM-768"  // optional
}
```

**Output:**
```json
{
  "shared_secret": "<base64, 32 bytes>",
  "shared_secret_hex": "<hex>",
  "x25519_ephemeral_public_key": "<base64, raw 32 bytes>",
  "pqc_ciphertext": "<base64 ML-KEM ciphertext>",
  "kem_algorithm": "ML-KEM-768"
}
```

#### `pqc_hybrid_decap`

Recover the shared secret using both secret keys.

**Input:**
```json
{
  "classical_secret_key": "<base64, raw 32-byte X25519 secret key>",
  "pqc_secret_key": "<base64 ML-KEM secret key>",
  "x25519_ephemeral_public_key": "<base64, raw 32-byte ephemeral public key>",
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

### Layer 2 — Sealed Envelope (Anonymous Sealed-Box)

#### `pqc_hybrid_seal`

Encrypt plaintext using hybrid key encapsulation + AES-256-GCM. One-shot anonymous sealed-box operation.

**Input:**
```json
{
  "plaintext": "Hello, quantum world!",
  "recipient_classical_public_key": "<base64, raw 32-byte X25519 public key>",
  "recipient_pqc_public_key": "<base64 ML-KEM public key>",
  "kem_algorithm": "ML-KEM-768"  // optional
}
```

Or with binary plaintext:
```json
{
  "plaintext_base64": "<base64-encoded binary data>",
  "recipient_classical_public_key": "...",
  "recipient_pqc_public_key": "...",
  "kem_algorithm": "ML-KEM-768"
}
```

Exactly one of `plaintext` (UTF-8 string) or `plaintext_base64` (base64-encoded bytes) must be provided.

**Output:**
```json
{
  "envelope": {
    "version": "pqc-mcp-v1",
    "kem_algorithm": "ml-kem-768",
    "classical_algorithm": "x25519",
    "aead_algorithm": "aes-256-gcm",
    "x25519_ephemeral_public_key": "<base64, 32 bytes>",
    "pqc_ciphertext": "<base64>",
    "ciphertext": "<base64, encrypted data + 16-byte GCM tag>",
    "nonce": "<base64, 12 bytes>"
  }
}
```

The `ciphertext` field contains the encrypted data with the 16-byte GCM authentication tag appended, exactly as returned by `AESGCM.encrypt()`. This is a single opaque blob, not a split of encrypted_data + tag.

#### `pqc_hybrid_open`

Decrypt a sealed envelope using both secret keys.

**Input:**
```json
{
  "envelope": { "...same structure as seal output..." },
  "classical_secret_key": "<base64, raw 32-byte X25519 secret key>",
  "pqc_secret_key": "<base64 ML-KEM secret key>"
}
```

The `kem_algorithm` is read from `envelope.kem_algorithm` — no separate parameter needed.

**Output:**
```json
{
  "plaintext": "Hello, quantum world!",
  "plaintext_base64": "<base64 of raw bytes>",
  "kem_algorithm": "ml-kem-768"
}
```

Both `plaintext` (UTF-8 decode attempt) and `plaintext_base64` are always returned. If the decrypted bytes are not valid UTF-8, `plaintext` is `null`.

## Cryptographic Construction

### Suite Identifier

All info strings and AAD use a single canonical suite-ID format. Lowercase, pipe-delimited, no variation:

```
pqc-mcp-v1|x25519|ml-kem-768
```

For other KEM algorithms:
```
pqc-mcp-v1|x25519|ml-kem-512
pqc-mcp-v1|x25519|ml-kem-1024
```

This is wire format. It must be byte-for-byte identical everywhere it appears. Tests must verify exact bytes.

### Combiner (HKDF-SHA256)

Follows NIST SP 800-227, TLS 1.3 (`X25519MLKEM768`), and RFC 5869.

```
# Step 1: Concatenate shared secrets (FIPS-approved scheme first per SP 800-56Cr2)
ikm = ss_mlkem (32 bytes) || ss_x25519 (32 bytes)

# Step 2: Extract — concentrate entropy into a PRK
prk = HKDF-Extract(salt=None, ikm=ikm)

# Step 3: Expand — derive keys with domain-separated info strings
```

**Salt:** `None` (interpreted as zero-filled `HashLen` bytes per RFC 5869). This is acceptable because the IKM is already the concatenation of two independent shared secrets with sufficient entropy. RFC 5869 notes that salt materially strengthens HKDF and should be used when available; in this construction, no independent salt material is available, so zero-salt is the standard choice, consistent with TLS 1.3 and Signal PQXDH. This is an acceptable design choice, not the only defensible one.

### X25519 Validation

Before any ECDH computation, validate inputs:

1. X25519 public keys and secret keys must be exactly 32 bytes after base64 decode. Reject with an error if length differs.
2. After X25519 ECDH, check that the shared secret is not all-zero bytes. RFC 7748 recommends this check to reject small-order public key inputs. If all-zero, return an error.

### Info String Format

Domain separation per RFC 5869 Section 3.2:

```
{suite_id}|{purpose}
```

Where `{suite_id}` is the canonical suite identifier above, and `{purpose}` is one of:

| Purpose | Used By |
|---------|---------|
| `shared-secret` | Building-block layer (`pqc_hybrid_encap` / `pqc_hybrid_decap`) |
| `aes-256-gcm-key` | Envelope layer (`pqc_hybrid_seal` / `pqc_hybrid_open`) |
| `aes-256-gcm-nonce` | Envelope layer (deterministic nonce derivation) |

Full examples (these are the exact bytes used):
```
b"pqc-mcp-v1|x25519|ml-kem-768|shared-secret"
b"pqc-mcp-v1|x25519|ml-kem-768|aes-256-gcm-key"
b"pqc-mcp-v1|x25519|ml-kem-768|aes-256-gcm-nonce"
```

### Key Derivation (Building Block Layer)

```python
shared_secret = HKDF-Expand(
    prk,
    info=f"pqc-mcp-v1|x25519|{kem_alg_canonical}|shared-secret".encode(),
    length=32
)
```

Where `kem_alg_canonical` is the lowercase hyphenated form (e.g., `ml-kem-768`).

### Key Derivation (Envelope Layer)

```python
aes_key = HKDF-Expand(
    prk,
    info=f"pqc-mcp-v1|x25519|{kem_alg_canonical}|aes-256-gcm-key".encode(),
    length=32
)

nonce = HKDF-Expand(
    prk,
    info=f"pqc-mcp-v1|x25519|{kem_alg_canonical}|aes-256-gcm-nonce".encode(),
    length=12
)
```

The nonce is deterministic, not random. This is safe because each seal generates a fresh ephemeral X25519 keypair, producing a unique PRK per operation. A deterministic nonce from a unique PRK cannot collide.

### Authenticated Associated Data (AAD)

AES-256-GCM encryption uses AAD to bind the ciphertext to the envelope metadata. The AAD is the canonical suite-ID:

```python
aad = f"pqc-mcp-v1|x25519|{kem_alg_canonical}".encode()
```

This authenticates the version, classical algorithm, and PQC algorithm. If any of these are tampered with in the envelope JSON, GCM tag verification will fail on open. Per SP 800-227, combiners and KDF inputs should include domain separators; using the suite-ID as AAD provides this binding at the AEAD layer as well.

### Encryption

```python
aesgcm = AESGCM(aes_key)
ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, aad)
# ciphertext includes the 16-byte GCM authentication tag appended
# Stored as a single opaque field in the envelope
```

### Algorithm Name Canonicalization

The MCP tool inputs accept liboqs-style names (e.g., `ML-KEM-768`). Internally, map to a canonical lowercase form for suite-ID construction:

| Input (accepted) | Canonical (internal) |
|-------------------|---------------------|
| `ML-KEM-512` | `ml-kem-512` |
| `ML-KEM-768` | `ml-kem-768` |
| `ML-KEM-1024` | `ml-kem-1024` |

The liboqs API still receives the original casing. Only the suite-ID and info strings use the canonical form.

### Security Properties

| Property | Guarantee |
|----------|-----------|
| **Hybrid confidentiality** | Shared secret is protected unless both X25519 and ML-KEM are broken |
| **Quantum resistance** | ML-KEM (FIPS 203, lattice-based) resists Shor's algorithm |
| **Classical fallback** | X25519 (Curve25519 ECDH) protects if ML-KEM is broken |
| **Ciphertext integrity** | AES-256-GCM authenticated encryption with AAD binding |
| **Domain separation** | HKDF info strings and AAD prevent cross-protocol key reuse |
| **Nonce safety** | Deterministic nonce from unique-per-operation PRK |
| **Small-order rejection** | All-zero X25519 shared secret check per RFC 7748 |

**Not provided:**
- Forward secrecy against recipient key compromise (one-pass, long-term recipient keys)
- Sender authentication (anonymous sealed-box — anyone with the public keys can seal)

### Standards Alignment

| Decision | Aligned With |
|----------|-------------|
| ML-KEM secret first in IKM | NIST SP 800-56Cr2, TLS 1.3 `X25519MLKEM768` |
| `salt=None` | TLS 1.3, Signal PQXDH (acceptable, not uniquely correct) |
| Single Extract + multiple Expand | RFC 5869, HPKE (RFC 9180) |
| Algorithm IDs in info + AAD | Signal PQXDH, HPKE suite_id, SP 800-227 |
| Concatenation combiner | NIST SP 800-227, dual-PRF security proof (Bindel et al.) |
| Raw 32-byte X25519 encoding | RFC 7748 |
| All-zero shared secret check | RFC 7748 Section 6.1 |

## Code Organization

### New file: `pqc_mcp_server/hybrid.py`

Pure crypto logic, no MCP dependencies. Contains:

- `hybrid_keygen(kem_algorithm) -> dict` — generate X25519 + ML-KEM keypair bundle
- `hybrid_encap(classical_pk, pqc_pk, kem_algorithm) -> dict` — encapsulate, return shared secret + ciphertexts
- `hybrid_decap(classical_sk, pqc_sk, x25519_epk, pqc_ct, kem_algorithm) -> dict` — decapsulate, return shared secret
- `hybrid_seal(plaintext_bytes, recipient_classical_pk, recipient_pqc_pk, kem_algorithm) -> dict` — full encrypt
- `hybrid_open(envelope, classical_sk, pqc_sk) -> dict` — full decrypt
- `_derive_prk(ss_mlkem, ss_x25519) -> bytes` — internal HKDF-Extract
- `_expand_key(prk, kem_algorithm, purpose, length) -> bytes` — internal HKDF-Expand with canonical suite-ID
- `_canonicalize_kem(algorithm) -> str` — map liboqs name to canonical lowercase
- `_validate_x25519_key(key_bytes, label) -> None` — length check, raises ValueError
- `_check_x25519_shared_secret(ss) -> None` — all-zero check, raises ValueError

### Modified file: `pqc_mcp_server/__init__.py`

- Import from `hybrid.py`
- Add 5 new Tool definitions to `list_tools()`
- Add 5 new tool handlers to `call_tool()`
- Handle `HAS_CRYPTOGRAPHY` flag similar to `HAS_LIBOQS`
- Handle `plaintext` vs `plaintext_base64` input routing in seal
- Return both `plaintext` and `plaintext_base64` from open

### New file: `tests/test_hybrid.py`

Test cases:

1. **Keygen** — produces valid key bundles, X25519 keys are exactly 32 bytes
2. **Encap/decap roundtrip** — shared secrets match
3. **Seal/open roundtrip (string)** — plaintext recovers via `plaintext` field
4. **Seal/open roundtrip (binary)** — binary data recovers via `plaintext_base64` field
5. **Wrong key decap** — produces different shared secret (ML-KEM implicit rejection)
6. **Wrong key open** — AES-GCM tag verification fails (raises error)
7. **Tampered ciphertext** — open fails
8. **Tampered envelope metadata** — AAD mismatch, GCM tag fails
9. **Non-default KEM** — ML-KEM-512 and ML-KEM-1024 work
10. **Suite-ID byte-for-byte** — verify exact info string bytes for each KEM variant
11. **Domain separation** — building-block shared secret differs from seal's AES key (same PRK, different Expand info)
12. **X25519 key length validation** — wrong-length keys rejected with clear error
13. **Non-UTF-8 binary** — seal with `plaintext_base64`, open returns `plaintext: null` + valid `plaintext_base64`

### Modified files: `pyproject.toml`, `README.md`, `CHANGELOG.md`

- `pyproject.toml`: Add `cryptography>=42.0.0` to dependencies
- `README.md`: Add hybrid section, update features, add security warning at top
- `CHANGELOG.md`: Add hybrid entries to Unreleased

## PR Roadmap

This work lands in three PRs, in order:

### PR 1: Infrastructure Credibility
- Fix `run.sh` portability (done)
- Add test suite + pytest-asyncio (done)
- Add GitHub Actions CI (done)
- Replace bare `except:` with specific exceptions (done)
- Add `CHANGELOG.md` (done)
- Tighten dependency version floors in `pyproject.toml`
- Add liboqs research-use warning to top of README

### PR 2: Naming, Docs, Security Cleanup
- Rename `pqc_hash_to_curve` → `pqc_hash` (it computes digests, not hash-to-curve)
- Label `pqc_security_analysis` as educational estimate in tool description
- Update algorithm naming: ML-KEM / ML-DSA / SLH-DSA as first-class, legacy aliases as compatibility notes
- Remove hardcoded algorithm counts from README (or pin to specific liboqs version)
- Add conspicuous security disclaimer: liboqs is research tooling, secret material appears in tool output
- Refresh algorithm tables for current liboqs state

### PR 3: Hybrid X25519 + ML-KEM
- New file `pqc_mcp_server/hybrid.py` with all crypto logic
- 5 new tools in `__init__.py`
- `tests/test_hybrid.py` with 13+ test cases
- `cryptography>=42.0.0` dependency
- README hybrid section + example prompts
- CHANGELOG update
