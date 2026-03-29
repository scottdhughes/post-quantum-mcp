# Hybrid X25519 + ML-KEM Key Exchange — Design Spec

**Date:** 2026-03-29
**Status:** Revised (v3)
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
- `cryptography.hazmat.primitives.kdf.hkdf.HKDFExpand` — HKDF-Expand step
- `cryptography.hazmat.primitives.ciphers.aead.AESGCM` — AES-256-GCM

**HKDF implementation note:** Stable `cryptography` (through at least 46.0.x) does not expose a public `HKDF.extract()` method. The Extract step is implemented using stdlib `hmac.new(key=salt, msg=ikm, digestmod=hashlib.sha256).digest()`, which is the exact computation defined by RFC 5869 Section 2.1. The Expand step uses `cryptography`'s `HKDFExpand`. This is the standard pattern for one-Extract-multiple-Expand on stable releases.

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
    "ciphertext": "<base64, encrypted data + 16-byte GCM tag>"
  }
}
```

The `ciphertext` field contains the encrypted data with the 16-byte GCM authentication tag appended, exactly as returned by `AESGCM.encrypt()`. This is a single opaque blob, not a split of encrypted_data + tag.

**No nonce field in the envelope.** The nonce is derived deterministically from the PRK (see Cryptographic Construction below). The recipient rederives the PRK from the ciphertexts + their secret keys, then derives the same nonce. Transmitting it would be redundant.

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

Inspired by the TLS 1.3 `X25519MLKEM768` construction and X-Wing KEM, adapted for this protocol. Uses RFC 5869 HKDF with context binding per NIST SP 800-227.

SP 800-227 warns that the naive combiner `K <- KDF(K1, K2)` does not generically preserve IND-CCA security, and recommends that combiners include ciphertexts and/or encapsulation keys alongside shared secrets. Following X-Wing's pattern (which includes the X25519 ephemeral public key in its combiner input but omits the ML-KEM ciphertext because ML-KEM's Fujisaki-Okamoto transform already provides internal ciphertext binding):

```
# Step 1: Concatenate shared secrets + X25519 ephemeral public key for context binding
# FIPS-approved scheme first per SP 800-56Cr2
ikm = ss_mlkem (32 bytes) || ss_x25519 (32 bytes) || epk_x25519 (32 bytes)

# ML-KEM ciphertext is NOT included in IKM. ML-KEM's FO transform already binds
# the ciphertext to the shared secret internally. This follows X-Wing's design
# rationale: including ct_mlkem would be redundant.

# Step 2: Extract — concentrate entropy into a PRK
prk = HKDF-Extract(salt=None, ikm=ikm)

# Step 3: Expand — derive keys with domain-separated info strings
```

Including `epk_x25519` in the IKM binds the derived keys to the specific key exchange instance. An attacker who substitutes a different ephemeral key will produce a different PRK, even if the shared secrets happen to match (e.g., under a hypothetical partial break).

**Salt:** `None` (interpreted as zero-filled `HashLen` bytes per RFC 5869). This is an acceptable design choice for this protocol: the IKM already contains 96 bytes from two independent shared secrets plus a public key. RFC 5869 notes that salt materially strengthens HKDF and should be used when available; here, no independent salt material is available. Zero-salt is consistent with how TLS 1.3 and Signal PQXDH handle their respective key schedules, but this protocol's construction is simpler than either of those and should not be described as equivalent to them.

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
# Extract: HMAC-SHA256 per RFC 5869 Section 2.1
salt = b"\x00" * 32  # HashLen zero bytes
prk = hmac.new(key=salt, msg=ss_mlkem + ss_x25519 + epk_x25519, digestmod=hashlib.sha256).digest()

# Expand: derive shared secret
shared_secret = HKDFExpand(
    algorithm=hashes.SHA256(),
    length=32,
    info=f"pqc-mcp-v1|x25519|{kem_alg_canonical}|shared-secret".encode()
).derive(prk)
```

Where `kem_alg_canonical` is the lowercase hyphenated form (e.g., `ml-kem-768`).

### Key Derivation (Envelope Layer)

Uses the same PRK as the building-block layer (same IKM), but derives different outputs via distinct info strings:

```python
aes_key = HKDFExpand(
    algorithm=hashes.SHA256(),
    length=32,
    info=f"pqc-mcp-v1|x25519|{kem_alg_canonical}|aes-256-gcm-key".encode()
).derive(prk)

nonce = HKDFExpand(
    algorithm=hashes.SHA256(),
    length=12,
    info=f"pqc-mcp-v1|x25519|{kem_alg_canonical}|aes-256-gcm-nonce".encode()
).derive(prk)
```

The nonce is deterministic, not random. This is safe because each seal generates a fresh ephemeral X25519 keypair, producing a unique IKM (and therefore unique PRK) per operation. A deterministic nonce from a unique PRK cannot collide. The nonce is not transmitted in the envelope — the recipient rederives it identically from their own decapsulation.

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

### Standards References

This construction is simpler than TLS 1.3 or Signal PQXDH and should not be described as equivalent to either. It is inspired by their design choices and follows the same primary sources:

| Decision | Informed By |
|----------|-------------|
| ML-KEM secret first in IKM | NIST SP 800-56Cr2 (FIPS-approved scheme first) |
| Context binding via `epk_x25519` in IKM | X-Wing KEM (draft-connolly-cfrg-xwing-kem), SP 800-227 combiner guidance |
| `salt=None` | RFC 5869 (acceptable when IKM has sufficient entropy) |
| Single Extract + multiple Expand | RFC 5869, HPKE (RFC 9180) |
| Algorithm IDs in info + AAD | HPKE suite_id pattern, SP 800-227 domain separation |
| Concatenation combiner with public values | SP 800-227, dual-PRF security proof (Bindel et al.) |
| Raw 32-byte X25519 encoding | RFC 7748 |
| All-zero shared secret check | RFC 7748 Section 6.1, TLS 1.3 hybrid draft |
| HMAC-SHA256 for HKDF-Extract | RFC 5869 Section 2.1 (HKDF-Extract = HMAC-Hash) |

## Code Organization

### New file: `pqc_mcp_server/hybrid.py`

Pure crypto logic, no MCP dependencies. Contains:

- `hybrid_keygen(kem_algorithm) -> dict` — generate X25519 + ML-KEM keypair bundle
- `hybrid_encap(classical_pk, pqc_pk, kem_algorithm) -> dict` — encapsulate, return shared secret + ciphertexts
- `hybrid_decap(classical_sk, pqc_sk, x25519_epk, pqc_ct, kem_algorithm) -> dict` — decapsulate, return shared secret
- `hybrid_seal(plaintext_bytes, recipient_classical_pk, recipient_pqc_pk, kem_algorithm) -> dict` — full encrypt
- `hybrid_open(envelope, classical_sk, pqc_sk) -> dict` — full decrypt
- `_derive_prk(ss_mlkem, ss_x25519, epk_x25519) -> bytes` — internal HKDF-Extract via HMAC-SHA256
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
5. **Wrong key decap** — ML-KEM performs implicit rejection: returns a deterministic but incorrect shared secret rather than an explicit error. Test verifies returned secret does not match the sender's (except with negligible collision probability)
6. **Wrong key open** — AES-GCM tag verification fails (raises error)
7. **Tampered ciphertext** — open fails
8. **Tampered envelope metadata** — AAD mismatch, GCM tag fails
9. **Non-default KEM** — ML-KEM-512 and ML-KEM-1024 work
10. **Suite-ID byte-for-byte** — verify exact info string bytes for each KEM variant
11. **Domain separation** — building-block shared secret differs from seal's AES key (same PRK, different Expand info)
12. **X25519 key length validation** — wrong-length keys rejected with clear error
13. **Non-UTF-8 binary** — seal with `plaintext_base64`, open returns `plaintext: null` + valid `plaintext_base64`
14. **Nonce rederivation** — verify that open succeeds without any nonce in the envelope (nonce is derived from PRK)
15. **All-zero X25519 shared secret** — rejected with clear error when small-order public key is provided

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
