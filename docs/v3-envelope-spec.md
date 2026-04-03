# pqc-mcp-v3 Envelope Specification

## Motivation

v2 envelopes do not cryptographically distinguish between anonymous seals
(`hybrid_seal`) and authenticated envelopes (`hybrid_auth_seal`). Both use
the same HKDF info prefix and AAD construction. This creates a theoretical
cross-mode confusion risk if both envelope types coexist in the same system.

Additionally, the v2 AAD uses raw concatenation (`version|suite|epk||pqc_ct`)
which is fragile — it relies on fixed field sizes and becomes ambiguous if
suites with variable-length components are added.

v3 fixes both issues in a single version bump.

## Changes from v2

### 1. Mode field (required in v3)

Every v3 envelope includes a `"mode"` field:
- `"anon-seal"` — anonymous sealed-box (no sender authentication)
- `"auth-seal"` — sender-authenticated envelope (ML-DSA-65 signature)

Mode is bound into cryptographic context (HKDF info + AAD).

### 2. HKDF info includes mode

```
v2: b"pqc-mcp-v2|mlkem768-x25519-sha3-256|aes-256-gcm-key" + sha256(epk)
v3: b"pqc-mcp-v3|mlkem768-x25519-sha3-256|anon-seal|aes-256-gcm-key" + sha256(epk)
```

### 3. Length-prefixed AAD (v3 only)

```
v2 AAD: ver_bytes + b"|" + suite_bytes + b"|" + epk + pqc_ct
v3 AAD: lp(ver) + lp(suite) + lp(mode) + lp(epk) + lp(pqc_ct)

where lp(x) = len(x).to_bytes(4, "big") + x
```

This makes the AAD self-delimiting and safe for variable-length fields.

### 4. Parser enforcement

- `hybrid_open` requires `mode == "anon-seal"` for v3 envelopes
- `hybrid_auth_open` requires `mode == "auth-seal"` for v3 envelopes
- v1/v2 envelopes: mode is inferred from field presence (backwards compat)

## Envelope Formats

### v3 Anonymous Seal
```json
{
  "version": "pqc-mcp-v3",
  "mode": "anon-seal",
  "suite": "mlkem768-x25519-sha3-256",
  "x25519_ephemeral_public_key": "<base64>",
  "pqc_ciphertext": "<base64>",
  "ciphertext": "<base64>"
}
```

### v3 Authenticated Seal
```json
{
  "version": "pqc-mcp-v3",
  "mode": "auth-seal",
  "suite": "mlkem768-x25519-sha3-256",
  "sender_signature_algorithm": "ML-DSA-65",
  "sender_public_key": "<base64>",
  "sender_key_fingerprint": "<hex>",
  "recipient_classical_key_fingerprint": "<hex>",
  "recipient_pqc_key_fingerprint": "<hex>",
  "x25519_ephemeral_public_key": "<base64>",
  "pqc_ciphertext": "<base64>",
  "ciphertext": "<base64>",
  "timestamp": "<unix epoch string>",
  "signature": "<base64>"
}
```

## Migration Policy

- **Emit:** v3 only for all new envelopes
- **Accept:** v1, v2, v3 for decryption
- **v1:** no timestamps, no mode, old HKDF prefix, old AAD — legacy warning
- **v2:** timestamps, no mode, v2 HKDF prefix with epk domain sep, concat AAD
- **v3:** timestamps (auth only), mode, mode-bound HKDF, length-prefixed AAD

## Constants

```python
ENVELOPE_VERSION = "pqc-mcp-v3"
_MODE_ANON_SEAL = "anon-seal"
_MODE_AUTH_SEAL = "auth-seal"
_ACCEPTED_VERSIONS = {"pqc-mcp-v3", "pqc-mcp-v2", "pqc-mcp-v1"}
_HKDF_INFO_PREFIX_V3 = b"pqc-mcp-v3|mlkem768-x25519-sha3-256|"
_AUTH_TRANSCRIPT_PREFIX_V3 = b"pqc-mcp-auth-v3\x00"
```

## Transcript (auth-seal v3)

Same structure as v2 but uses `_AUTH_TRANSCRIPT_PREFIX_V3` and includes
mode in the prefix. Timestamp remains optional-but-required for v3.
