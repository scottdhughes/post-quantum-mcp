# Hybrid X25519 + ML-KEM Key Exchange — Design Spec

**Date:** 2026-03-29
**Status:** Revised (v4)
**Author:** Scott Hughes + Claude

## Goal

Add hybrid classical + post-quantum key establishment and anonymous sealed-box encryption to the post-quantum-mcp server. Two layers: building-block tools (keygen, encap, decap) and a sealed-envelope API (seal, open).

**Scope disclaimer:** This is research and prototyping tooling. liboqs upstream explicitly states it is not recommended for production use or to protect sensitive data. This server returns secret material into tool output, which may enter model context, client logs, or transcripts. That is acceptable for the intended use cases (hybrid PQC demos, agent-to-agent experiments, test-vector generation, algorithm education) but must be stated conspicuously in the README.

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

## Suite Design

### Single Named Suite for v1

Rather than exposing a free-form `kem_algorithm` parameter, v1 pins to one concrete named suite:

```
mlkem768-x25519-sha3-256
```

This is aligned with the LAMPS composite ML-KEM draft's `id-MLKEM768-X25519-SHA3-256` and is described as "largely interchangeable" with X-Wing. The main difference is that X-Wing combines KeyGen from one seed; our construction generates ML-KEM and X25519 keypairs independently.

Rationale: TLS hybrid drafts treat each hybrid combination as a distinct named ordered pair, not as "X25519 plus whatever KEM string someone passes in." NIST SP 800-227 warns that the naive combiner `K <- KDF(K1, K2)` does not generically preserve IND-CCA security. Pinning to a published suite with an analyzed combiner avoids inventing a custom construction.

If additional suites are needed later (e.g., `mlkem1024-x25519-sha3-256`), they would be added as new suite values, each with their own tested combiner and wire format.

### KEM Combiner

Following the LAMPS composite ML-KEM draft (`id-MLKEM768-X25519-SHA3-256`):

```
combined_ss = SHA3-256(ss_mlkem || ss_x25519 || epk_x25519 || pk_x25519 || label)
```

Where:
- `ss_mlkem` — ML-KEM-768 shared secret (32 bytes, from encapsulation)
- `ss_x25519` — X25519 shared secret (32 bytes, from ECDH)
- `epk_x25519` — sender's ephemeral X25519 public key (32 bytes)
- `pk_x25519` — recipient's static X25519 public key (32 bytes)
- `label` — domain separator: `b"pqc-mcp-v1-mlkem768-x25519-sha3-256"` (36 bytes)

Total combiner input: 164 bytes → 32-byte output.

This construction includes public values (ephemeral key and recipient key) in the combiner hash, providing context binding. ML-KEM's Fujisaki-Okamoto transform already binds the ML-KEM ciphertext to its shared secret internally, so `ct_mlkem` is not included in the combiner (following X-Wing's design rationale).

The `combined_ss` is the output of the KEM layer. It is what the building-block tools return.

### AEAD Key Derivation (Envelope Layer Only)

The seal/open tools derive AES-256-GCM key material from `combined_ss` via HKDF. This is the pedestrian task of deriving multiple fixed-length keys from one shared secret — HKDF is standard and uncontroversial for this purpose.

```python
# Extract: HMAC-SHA256 per RFC 5869 Section 2.1
salt = b"\x00" * 32  # HashLen zero bytes
prk = hmac.new(key=salt, msg=combined_ss, digestmod=hashlib.sha256).digest()

# Expand: derive AES key
aes_key = HKDFExpand(
    algorithm=hashes.SHA256(),
    length=32,
    info=b"pqc-mcp-v1|mlkem768-x25519-sha3-256|aes-256-gcm-key"
).derive(prk)

# Expand: derive nonce
nonce = HKDFExpand(
    algorithm=hashes.SHA256(),
    length=12,
    info=b"pqc-mcp-v1|mlkem768-x25519-sha3-256|aes-256-gcm-nonce"
).derive(prk)
```

**HKDF implementation note:** Stable `cryptography` (through at least 46.0.x) does not expose a public `HKDF.extract()` method. The Extract step is implemented using stdlib `hmac.new(key=salt, msg=ikm, digestmod=hashlib.sha256).digest()`, which is the exact computation defined by RFC 5869 Section 2.1. The Expand step uses `cryptography`'s `HKDFExpand`.

**Salt:** `None` (zero-filled `HashLen` bytes per RFC 5869). Acceptable because the IKM (`combined_ss`) is a 32-byte output of SHA3-256 with sufficient entropy. RFC 5869 notes that salt strengthens HKDF when available; here, no independent salt material exists. This is an acceptable design choice.

**Nonce:** Deterministic, derived from the PRK. Safe because each seal generates a fresh ephemeral X25519 keypair → unique `combined_ss` → unique PRK → unique nonce. Not transmitted in the envelope — the recipient rederives it.

**Info strings** are the exact bytes shown above. Pipe-delimited, lowercase. This is wire format — byte-for-byte identical everywhere. Tests must verify exact bytes.

**This construction is explicitly single-shot:** one encapsulation, one AEAD encryption. If reusable session contexts are ever needed, a base-nonce-plus-sequence-number schedule (as in HPKE) would be required instead.

## New Dependency

**`cryptography>=42.0.0`** added to `pyproject.toml` dependencies. Provides:

- `cryptography.hazmat.primitives.asymmetric.x25519` — X25519 keygen + ECDH
- `cryptography.hazmat.primitives.kdf.hkdf.HKDFExpand` — HKDF-Expand step
- `cryptography.hazmat.primitives.ciphers.aead.AESGCM` — AES-256-GCM

SHA3-256 (for the KEM combiner) and HMAC-SHA256 (for HKDF-Extract) come from Python's stdlib `hashlib` and `hmac`.

## New Tools

### Layer 1 — Building Blocks

#### `pqc_hybrid_keygen`

Generate a hybrid keypair bundle (X25519 + ML-KEM-768). No parameters — the suite is fixed.

**Input:**
```json
{}
```

**Output:**
```json
{
  "suite": "mlkem768-x25519-sha3-256",
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

X25519 keys are raw 32-byte values per RFC 7748. Public key: `X25519PublicKey.public_bytes(Raw, Raw)`. Secret key: `X25519PrivateKey.private_bytes(Raw, Raw, NoEncryption)`.

#### `pqc_hybrid_encap`

Perform hybrid key encapsulation against a recipient's public keys. Generates an ephemeral X25519 keypair, performs ECDH + ML-KEM-768 encap, combines via the suite's SHA3-256 combiner.

**Input:**
```json
{
  "classical_public_key": "<base64, raw 32-byte X25519 public key>",
  "pqc_public_key": "<base64 ML-KEM-768 public key>"
}
```

**Output:**
```json
{
  "suite": "mlkem768-x25519-sha3-256",
  "shared_secret": "<base64, 32 bytes>",
  "shared_secret_hex": "<hex>",
  "x25519_ephemeral_public_key": "<base64, raw 32 bytes>",
  "pqc_ciphertext": "<base64 ML-KEM-768 ciphertext>"
}
```

#### `pqc_hybrid_decap`

Recover the shared secret using both secret keys.

**Input:**
```json
{
  "classical_secret_key": "<base64, raw 32-byte X25519 secret key>",
  "pqc_secret_key": "<base64 ML-KEM-768 secret key>",
  "x25519_ephemeral_public_key": "<base64, raw 32-byte ephemeral public key>",
  "pqc_ciphertext": "<base64 ML-KEM-768 ciphertext>"
}
```

The recipient's static X25519 public key (needed for the combiner) is derived internally from `classical_secret_key`.

**Output:**
```json
{
  "suite": "mlkem768-x25519-sha3-256",
  "shared_secret": "<base64, 32 bytes>",
  "shared_secret_hex": "<hex>"
}
```

### Layer 2 — Sealed Envelope (Anonymous Sealed-Box)

#### `pqc_hybrid_seal`

Encrypt plaintext using hybrid key encapsulation + AES-256-GCM. One-shot anonymous sealed-box.

**Input (string):**
```json
{
  "plaintext": "Hello, quantum world!",
  "recipient_classical_public_key": "<base64, raw 32-byte X25519 public key>",
  "recipient_pqc_public_key": "<base64 ML-KEM-768 public key>"
}
```

**Input (binary):**
```json
{
  "plaintext_base64": "<base64-encoded binary data>",
  "recipient_classical_public_key": "...",
  "recipient_pqc_public_key": "..."
}
```

Exactly one of `plaintext` (UTF-8 string) or `plaintext_base64` (base64-encoded bytes) must be provided.

**Output:**
```json
{
  "envelope": {
    "version": "pqc-mcp-v1",
    "suite": "mlkem768-x25519-sha3-256",
    "x25519_ephemeral_public_key": "<base64, 32 bytes>",
    "pqc_ciphertext": "<base64>",
    "ciphertext": "<base64, encrypted data + 16-byte GCM tag>"
  }
}
```

The `ciphertext` field contains encrypted data with the 16-byte GCM authentication tag appended, exactly as returned by `AESGCM.encrypt()`. Single opaque blob.

No nonce field — the recipient rederives it deterministically from the PRK.

#### `pqc_hybrid_open`

Decrypt a sealed envelope using both secret keys.

**Input:**
```json
{
  "envelope": { "...same structure as seal output..." },
  "classical_secret_key": "<base64, raw 32-byte X25519 secret key>",
  "pqc_secret_key": "<base64 ML-KEM-768 secret key>"
}
```

**Output:**
```json
{
  "suite": "mlkem768-x25519-sha3-256",
  "plaintext": "Hello, quantum world!",
  "plaintext_base64": "<base64 of raw bytes>"
}
```

Both `plaintext` (UTF-8 decode attempt) and `plaintext_base64` are always returned. If the decrypted bytes are not valid UTF-8, `plaintext` is `null`.

## X25519 Validation

Before any ECDH computation:

1. X25519 public keys and secret keys must be exactly 32 bytes after base64 decode. Reject with an error if length differs.
2. After X25519 ECDH, check that the shared secret is not all-zero bytes. RFC 7748 recommends this check to reject small-order public key inputs. The TLS `X25519MLKEM768` draft requires it. If all-zero, return an error.

## Authenticated Associated Data (AAD)

AES-256-GCM encryption uses AAD to bind the ciphertext to the full envelope header. The AAD is the canonical concatenation of all non-ciphertext envelope fields:

```python
aad = (
    b"pqc-mcp-v1"                    # version (10 bytes)
    + b"|mlkem768-x25519-sha3-256|"   # suite with delimiters (28 bytes)
    + epk_x25519_bytes                # ephemeral public key (32 bytes)
    + pqc_ciphertext_bytes            # ML-KEM ciphertext (raw bytes)
)
```

This authenticates the version, suite, ephemeral key, and ML-KEM ciphertext. If any of these are tampered with in the envelope, GCM tag verification fails on open. The recipient reconstructs this AAD from the envelope fields before decryption.

## Security Properties

| Property | Guarantee |
|----------|-----------|
| **Hybrid confidentiality** | Shared secret is protected unless both X25519 and ML-KEM-768 are broken simultaneously |
| **Quantum resistance** | ML-KEM-768 (FIPS 203, NIST Level 3, lattice-based) resists Shor's algorithm |
| **Classical fallback** | X25519 (Curve25519 ECDH) protects if ML-KEM is broken by cryptanalysis |
| **Ciphertext integrity** | AES-256-GCM authenticated encryption with full-header AAD binding |
| **Context binding** | KEM combiner includes ephemeral key and recipient public key per LAMPS/X-Wing |
| **Domain separation** | Suite label in combiner hash, suite-ID in HKDF info strings |
| **Nonce safety** | Deterministic nonce from unique-per-operation PRK; single-shot only |
| **Small-order rejection** | All-zero X25519 shared secret check per RFC 7748 |

**Not provided:**
- Forward secrecy against recipient key compromise (one-pass, long-term recipient keys)
- Sender authentication (anonymous sealed-box — anyone with the public keys can seal)
- Multi-message sessions (single-shot only; would need HPKE-style nonce schedule)

## Standards References

This construction is simpler than TLS 1.3 or Signal PQXDH and should not be described as equivalent to either. It uses a published suite combiner and standard HKDF for AEAD key derivation:

| Decision | Informed By |
|----------|-------------|
| Single named suite, not free-form algorithm parameter | TLS hybrid drafts (named ordered pairs), LAMPS composite ML-KEM |
| SHA3-256 KEM combiner with public values | LAMPS `id-MLKEM768-X25519-SHA3-256`, X-Wing KEM |
| Ephemeral key + recipient key in combiner | SP 800-227 (combiners should include ciphertexts, encapsulation keys, domain separator) |
| ML-KEM ciphertext NOT in combiner | X-Wing design rationale (FO transform provides internal binding) |
| ML-KEM shared secret first in combiner input | NIST SP 800-56Cr2 (FIPS-approved scheme first) |
| HMAC-SHA256 for HKDF-Extract | RFC 5869 Section 2.1 |
| HKDFExpand for AEAD key derivation | RFC 5869, HPKE (RFC 9180) |
| `salt=None` for HKDF | RFC 5869 (acceptable when IKM has sufficient entropy) |
| Full-header AAD for AES-GCM | SP 800-227 domain separation, `cryptography` AESGCM docs |
| Raw 32-byte X25519 encoding | RFC 7748, `cryptography` API requirements |
| All-zero shared secret check | RFC 7748 Section 6.1, TLS hybrid draft |
| Single-shot nonce derivation | Safe for one-encap-one-encrypt; not for multi-message |

## Code Organization

### New file: `pqc_mcp_server/hybrid.py`

Pure crypto logic, no MCP dependencies:

- `SUITE = "mlkem768-x25519-sha3-256"` — constant
- `COMBINER_LABEL = b"pqc-mcp-v1-mlkem768-x25519-sha3-256"` — constant
- `hybrid_keygen() -> dict` — generate X25519 + ML-KEM-768 keypair bundle
- `hybrid_encap(classical_pk, pqc_pk) -> dict` — encapsulate, return combined shared secret + ciphertexts
- `hybrid_decap(classical_sk, pqc_sk, x25519_epk, pqc_ct) -> dict` — decapsulate, return combined shared secret
- `hybrid_seal(plaintext_bytes, recipient_classical_pk, recipient_pqc_pk) -> dict` — full encrypt
- `hybrid_open(envelope, classical_sk, pqc_sk) -> dict` — full decrypt
- `_kem_combine(ss_mlkem, ss_x25519, epk_x25519, pk_x25519) -> bytes` — SHA3-256 combiner
- `_derive_aead_key_and_nonce(combined_ss) -> tuple[bytes, bytes]` — HKDF Extract+Expand for AES key + nonce
- `_build_aad(epk_x25519, pqc_ciphertext) -> bytes` — canonical AAD construction
- `_validate_x25519_key(key_bytes, label) -> None` — 32-byte length check
- `_check_x25519_shared_secret(ss) -> None` — all-zero check per RFC 7748

### Modified file: `pqc_mcp_server/__init__.py`

- Import from `hybrid.py`
- Add 5 new Tool definitions to `list_tools()`
- Add 5 new tool handlers to `call_tool()`
- Handle `HAS_CRYPTOGRAPHY` flag similar to `HAS_LIBOQS`
- Handle `plaintext` vs `plaintext_base64` input routing in seal
- Return both `plaintext` and `plaintext_base64` from open

### New file: `tests/test_hybrid.py`

Test cases:

1. **Keygen** — produces valid key bundles, X25519 keys are exactly 32 bytes, suite field is correct
2. **Encap/decap roundtrip** — combined shared secrets match
3. **Seal/open roundtrip (string)** — plaintext recovers via `plaintext` field
4. **Seal/open roundtrip (binary)** — binary data recovers via `plaintext_base64` field
5. **Wrong key decap** — ML-KEM performs implicit rejection: returns a deterministic but incorrect shared secret rather than an explicit error. Test verifies returned secret does not match the sender's (except with negligible collision probability)
6. **Wrong key open** — AES-GCM tag verification fails (raises error)
7. **Tampered pqc_ciphertext in envelope** — AAD mismatch, GCM tag fails
8. **Tampered x25519_ephemeral_public_key in envelope** — AAD mismatch, GCM tag fails
9. **Tampered ciphertext** — GCM tag verification fails
10. **Combiner byte-for-byte** — verify exact SHA3-256 combiner output for known test inputs
11. **Info string byte-for-byte** — verify exact HKDF info bytes
12. **Domain separation** — combined shared secret (from encap) differs from AES key (derived via HKDF Expand with different info)
13. **X25519 key length validation** — wrong-length keys rejected with clear error
14. **All-zero X25519 shared secret** — rejected with clear error
15. **Non-UTF-8 binary** — seal with `plaintext_base64`, open returns `plaintext: null` + valid `plaintext_base64`
16. **Nonce rederivation** — open succeeds without nonce in envelope (derived from PRK)
17. **AAD reconstruction** — verify `_build_aad()` produces identical bytes on sender and recipient sides

### Modified files: `pyproject.toml`, `README.md`, `CHANGELOG.md`

- `pyproject.toml`: Add `cryptography>=42.0.0` to dependencies
- `README.md`: Add hybrid section, update features, security warning at top
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
- Rename `pqc_hash_to_curve` → `pqc_hash` (computes digests, not hash-to-curve)
- Label `pqc_security_analysis` as educational NIST-level mapping in tool description
- Update algorithm naming: ML-KEM / ML-DSA / SLH-DSA as first-class, legacy aliases as compatibility notes
- Remove hardcoded algorithm counts from README (or pin to specific liboqs version)
- Add conspicuous security disclaimer: liboqs is research tooling, secret material appears in tool output
- Refresh algorithm tables for current liboqs state
- Add MCP Inspector instructions to dev docs

### PR 3: Hybrid X25519 + ML-KEM-768
- New file `pqc_mcp_server/hybrid.py` with all crypto logic
- 5 new tools in `__init__.py`
- `tests/test_hybrid.py` with 17 test cases
- `cryptography>=42.0.0` dependency
- README hybrid section + example prompts
- CHANGELOG update
