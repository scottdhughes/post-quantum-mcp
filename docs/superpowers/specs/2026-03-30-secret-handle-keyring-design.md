# Secret-Handle Keyring — Design Spec

**Date:** 2026-03-30
**Status:** Revised (v2)
**Author:** Scott Hughes + Claude

## Goal

Add opt-in opaque secret-handle mode to the PQC MCP server. When a caller generates keys with `store_as`, secret keys are stored process-locally and never appear in tool output. Downstream tools — both hybrid and generic PQC — accept `key_store_name` to reference stored keys by name. This materially reduces secret-material leakage into model context, client logs, and transcripts.

**Scope disclaimer:** This remains research/prototyping tooling. The handle system protects against output leakage, not against a compromised server process. liboqs is not recommended for production use.

**Handle lifetime:** Handles are process-local and lost on server restart. There is no persistent storage.

## Design Decisions (Resolved)

1. **Opt-in via `store_as` parameter** on existing keygen tools. No new keygen tools. Behavior unchanged when parameter is omitted.
2. **Single `key_store_name` parameter** on downstream tools resolves a full key bundle from the store. For `hybrid_auth_seal`, two parameters: `recipient_key_store_name` + `sender_key_store_name`.
3. **Output-only protection.** Secrets are plain bytes in the server process. The threat model is "secrets in LLM context and logs," not "secrets in the server process."
4. **Storage method distinguishes redaction.** Keys stored via `store_as` (handle mode) → `pqc_key_store_load` returns public material + metadata only. Keys stored via `pqc_key_store_save` (explicit save) → returns full key_data as before.
5. **Conflict is an error.** If both a store-name parameter and raw base64 key parameters are provided for the same key role, the tool returns a structured error. No silent precedence. This prevents caller mistakes in crypto tooling.
6. **`store_as` fails on collision** unless `overwrite: true` is passed. Accidentally replacing an identity key is worse than failing loudly. Returns `{"error": "Key 'name' already exists in store. Pass overwrite: true to replace."}`.
7. **Generic PQC tools also support `key_store_name`.** `pqc_sign`, `pqc_verify`, `pqc_encapsulate`, `pqc_decapsulate` all accept `key_store_name` to resolve flat keypairs. This closes the hole where `store_as` on `pqc_generate_keypair` would produce a handle that no downstream tool could consume.
8. **Strict type validation.** Resolution checks `type` and `algorithm` fields, not just shape. `sender_key_store_name` on `hybrid_auth_seal` rejects flat KEM keypairs (must be signature type). Hybrid tool `key_store_name` rejects flat keypairs (must be hybrid bundle).
9. **Crypto layer untouched.** `hybrid.py` still only sees raw bytes. Resolution happens in the handler layer.

## Modified Tools

### Keygen tools (new `store_as` parameter)

#### `pqc_hybrid_keygen`

New optional parameters: `store_as` (string), `overwrite` (boolean, default false).

When `store_as` is provided:
- Fails if name already exists and `overwrite` is not true
- Generates keys normally
- Stores full key_data internally with `stored_as_handle: true`
- Returns public material only:

```json
{
  "suite": "mlkem768-x25519-sha3-256",
  "handle": "alice",
  "classical": {
    "algorithm": "X25519",
    "public_key": "<base64>",
    "fingerprint": "<hex>"
  },
  "pqc": {
    "algorithm": "ML-KEM-768",
    "public_key": "<base64>",
    "fingerprint": "<hex>"
  }
}
```

No `secret_key` fields in output. Handle lifetime: process-local, lost on server restart.

When `store_as` is omitted: behavior unchanged (returns full key_data including secrets).

#### `pqc_generate_keypair`

New optional parameters: `store_as` (string), `overwrite` (boolean, default false).

When `store_as` is provided:
- Fails if name already exists and `overwrite` is not true
- Generates keypair normally
- Stores full result internally with `stored_as_handle: true`
- Returns public material + fingerprint:

```json
{
  "algorithm": "ML-DSA-65",
  "type": "Signature",
  "handle": "alice-signing",
  "public_key": "<base64>",
  "public_key_size": 1952,
  "fingerprint": "<hex>",
  "fingerprint_algorithm": "SHA3-256"
}
```

No `secret_key` or `secret_key_size` in output. Fingerprint included so authenticated-envelope flows can immediately pin sender identity.

### Hybrid downstream tools (new store-name parameters)

| Tool | New Parameter | Resolves From Store | Store Entry Type Required |
|------|--------------|-------------------|--------------------------|
| `pqc_hybrid_encap` | `key_store_name` | `classical.public_key`, `pqc.public_key` | hybrid |
| `pqc_hybrid_decap` | `key_store_name` | `classical.secret_key`, `pqc.secret_key` (epk + pqc_ct still from arguments) | hybrid |
| `pqc_hybrid_seal` | `recipient_key_store_name` | `classical.public_key`, `pqc.public_key` | hybrid |
| `pqc_hybrid_open` | `key_store_name` | `classical.secret_key`, `pqc.secret_key` | hybrid |
| `pqc_hybrid_auth_seal` | `recipient_key_store_name` + `sender_key_store_name` | recipient: `classical.public_key`, `pqc.public_key`; sender: `secret_key`, `public_key` | recipient: hybrid; sender: flat signature (type=Signature) |
| `pqc_hybrid_auth_open` | `key_store_name` | `classical.secret_key`, `pqc.secret_key` (sender binding still explicit) | hybrid |

### Generic PQC downstream tools (new `key_store_name` parameter)

| Tool | Resolves From Store | Store Entry Type Required |
|------|-------------------|--------------------------|
| `pqc_sign` | `secret_key` | flat signature (type=Signature) |
| `pqc_verify` | `public_key` | flat signature (type=Signature) |
| `pqc_encapsulate` | `public_key` | flat KEM (type=KEM) |
| `pqc_decapsulate` | `secret_key` | flat KEM (type=KEM) |

For generic PQC tools, `key_store_name` resolves the key but `algorithm` must still be provided in arguments (since the store may hold keys for different algorithms). If `algorithm` in arguments differs from the stored entry's algorithm, return an error.

### Conflict rule

If both `key_store_name` (or `recipient_key_store_name` / `sender_key_store_name`) and the corresponding raw base64 key parameters are present, return:
```json
{"error": "Provide either key_store_name or raw key parameters, not both"}
```

### `pqc_key_store_load` behavior change

Entry with `stored_as_handle: true` returns public material + metadata:
```json
{
  "name": "alice",
  "stored_as_handle": true,
  "type": "hybrid",
  "suite": "mlkem768-x25519-sha3-256",
  "classical": {
    "algorithm": "X25519",
    "public_key": "<base64>",
    "fingerprint": "<hex>"
  },
  "pqc": {
    "algorithm": "ML-KEM-768",
    "public_key": "<base64>",
    "fingerprint": "<hex>"
  }
}
```

No secret keys. Includes name, type, fingerprints — everything needed to use the handle downstream.

Entry with `stored_as_handle: false` (or absent) returns full key_data as before.

### `pqc_key_store_list` metadata

Each entry in the list includes `stored_as_handle` flag:
```json
{
  "name": "alice",
  "type": "hybrid",
  "stored_as_handle": true,
  "suite": "mlkem768-x25519-sha3-256",
  "classical_fingerprint": "<hex>",
  "pqc_fingerprint": "<hex>"
}
```

## Key Data Shapes

### Hybrid bundle (from `pqc_hybrid_keygen`)
```
{
  "suite": "...",
  "classical": {"algorithm", "public_key", "secret_key", "fingerprint"},
  "pqc": {"algorithm", "public_key", "secret_key", "fingerprint"}
}
```

### Flat keypair (from `pqc_generate_keypair`)
```
{
  "algorithm": "...",
  "type": "Signature" | "KEM",
  "public_key": "...",
  "secret_key": "...",
  "public_key_size": N,
  "secret_key_size": N
}
```

### Type detection and validation
- `"suite" in key_data` → hybrid bundle
- `"algorithm" in key_data` and no `"suite"` → flat keypair
- Flat keypair `key_data["type"]` must match expected role:
  - `sender_key_store_name` requires `type == "Signature"`
  - `key_store_name` on `pqc_sign`/`pqc_verify` requires `type == "Signature"`
  - `key_store_name` on `pqc_encapsulate`/`pqc_decapsulate` requires `type == "KEM"`
  - `sender_key_store_name` with `type == "KEM"` → error: `"Key 'name' is a KEM keypair, not a signing keypair"`
- Algorithm mismatch (generic PQC tools): if `arguments["algorithm"]` differs from `key_data["algorithm"]` → error: `"Algorithm mismatch: requested 'X' but key 'name' is 'Y'"`

## Resolution Logic

### `_resolve_from_store(name: str) -> dict[str, Any]`

Internal function in `key_store.py`. Returns the full key_data dict (including secrets) regardless of handle mode. Only called by handler functions, never exposed via MCP.

Raises `ValueError` if name not found in store.

### Handler resolution pattern

Each handler checks for conflicts first, then resolves:

```python
def handle_hybrid_seal(arguments):
    has_store = "recipient_key_store_name" in arguments
    has_raw = "recipient_classical_public_key" in arguments or "recipient_pqc_public_key" in arguments
    if has_store and has_raw:
        raise ValueError("Provide either recipient_key_store_name or raw key parameters, not both")
    if has_store:
        keys = _resolve_from_store(arguments["recipient_key_store_name"])
        _require_hybrid_bundle(keys, arguments["recipient_key_store_name"])
        classical_pk = _b64(keys["classical"]["public_key"])
        pqc_pk = _b64(keys["pqc"]["public_key"])
    else:
        classical_pk = _b64(arguments["recipient_classical_public_key"])
        pqc_pk = _b64(arguments["recipient_pqc_public_key"])
    ...
```

### Type validation helpers

```python
def _require_hybrid_bundle(keys: dict, name: str) -> None:
    if "suite" not in keys:
        raise ValueError(f"Key '{name}' is not a hybrid bundle")

def _require_flat_signature(keys: dict, name: str) -> None:
    if "suite" in keys:
        raise ValueError(f"Key '{name}' is a hybrid bundle, not a signing keypair")
    if keys.get("type", "").lower() != "signature":
        raise ValueError(f"Key '{name}' is a {keys.get('type', 'unknown')} keypair, not a signing keypair")

def _require_flat_kem(keys: dict, name: str) -> None:
    if "suite" in keys:
        raise ValueError(f"Key '{name}' is a hybrid bundle, not a KEM keypair")
    if keys.get("type", "").lower() != "kem":
        raise ValueError(f"Key '{name}' is a {keys.get('type', 'unknown')} keypair, not a KEM keypair")
```

## Error Handling

| Condition | Error Message |
|-----------|---------------|
| Store name not found | `"Key 'name' not found in store"` |
| Both store name and raw keys provided | `"Provide either key_store_name or raw key parameters, not both"` |
| `store_as` collision without `overwrite: true` | `"Key 'name' already exists in store. Pass overwrite: true to replace."` |
| Hybrid bundle where flat keypair expected | `"Key 'name' is a hybrid bundle, not a signing keypair"` |
| Flat keypair where hybrid bundle expected | `"Key 'name' is not a hybrid bundle"` |
| KEM keypair where signature expected | `"Key 'name' is a KEM keypair, not a signing keypair"` |
| Algorithm mismatch (generic PQC) | `"Algorithm mismatch: requested 'X' but key 'name' is 'Y'"` |
| All existing errors | Unchanged: `binascii.Error`, `SenderVerificationError`, `InvalidTag`, `ValueError` |

## Security Properties

| Property | Status |
|----------|--------|
| Secret keys never in tool output (handle mode) | **New** |
| Secret keys never leave server process (handle mode) | **New** |
| Output-only protection (server process is trusted) | By design |
| Handles are process-local, lost on restart | By design |
| Backward compatible (omit new params = old behavior) | By design |
| Conflict between store name and raw keys is an error | **New** |
| Collision on store_as requires explicit overwrite | **New** |
| Sender trust still explicit (never auto-resolved from store) | Preserved |
| Type + algorithm validation on resolution | **New** |
| Research/prototyping only | Unchanged |

## Code Changes

### `key_store.py`
- Add `stored_as_handle` flag to store entries
- Add `_resolve_from_store(name)` internal function
- Add `store_from_keygen(name, key_data, overwrite=False)` for handle-mode storage (fails on collision unless overwrite)
- Modify `handle_key_store_load` to return public material + metadata for handle entries
- Modify `handle_key_store_list` to show `stored_as_handle` in summary
- Add type validation helpers: `_require_hybrid_bundle`, `_require_flat_signature`, `_require_flat_kem`

### `handlers_hybrid.py`
- Add `_resolve_hybrid_recipient(arguments)` helper (conflict check + type validation + resolution)
- Add `_resolve_hybrid_own_keys(arguments)` helper (for open/decap — resolves secret keys)
- Add `_resolve_sender_keys(arguments)` helper (conflict check + type validation)
- Modify all 7 hybrid handlers to use resolution helpers

### `handlers_pqc.py`
- Modify `handle_generate_keypair` to support `store_as` + `overwrite` + fingerprint in output
- Modify `handle_sign` to support `key_store_name` (resolves `secret_key`, validates type=Signature)
- Modify `handle_verify` to support `key_store_name` (resolves `public_key`, validates type=Signature)
- Modify `handle_encapsulate` to support `key_store_name` (resolves `public_key`, validates type=KEM)
- Modify `handle_decapsulate` to support `key_store_name` (resolves `secret_key`, validates type=KEM)
- Add `_resolve_flat_key(arguments, field, expected_type, name)` helper

### `tools.py`
- Add `store_as` + `overwrite` to keygen tool schemas
- Add `key_store_name` / `recipient_key_store_name` / `sender_key_store_name` to all downstream tool schemas

### `hybrid.py`
- **No changes.** Crypto core untouched.

### `__init__.py`
- **No changes.** Handler registry and dispatch unchanged.

## Testing

### Pure key-store tests
1. `store_as` on `hybrid_keygen` returns no secret keys
2. `store_as` on `generate_keypair` returns no secret key
3. `store_as` on `generate_keypair` returns fingerprint + fingerprint_algorithm
4. `pqc_key_store_load` on handle entry returns public material + metadata (name, type, fingerprints)
5. `pqc_key_store_load` on explicit-save entry returns full data
6. `pqc_key_store_list` shows `stored_as_handle` flag
7. `store_as` collision without `overwrite` fails with clear error
8. `store_as` collision with `overwrite: true` succeeds

### Hybrid resolution tests
9. `hybrid_seal` with `recipient_key_store_name` works
10. `hybrid_open` with `key_store_name` works
11. `hybrid_auth_seal` with both store names works
12. `hybrid_auth_open` with `key_store_name` + explicit sender binding works
13. `hybrid_encap` with `key_store_name` works
14. `hybrid_decap` with `key_store_name` works

### Generic PQC resolution tests
15. `pqc_sign` with `key_store_name` (signature keypair) works
16. `pqc_verify` with `key_store_name` (signature keypair) works
17. `pqc_encapsulate` with `key_store_name` (KEM keypair) works
18. `pqc_decapsulate` with `key_store_name` (KEM keypair) works

### Conflict tests
19. Both `key_store_name` and raw keys on same call → error
20. Both `recipient_key_store_name` and raw recipient keys → error
21. Both `sender_key_store_name` and raw sender keys → error

### Type mismatch tests
22. Hybrid bundle as sender (`sender_key_store_name`) → error
23. Flat keypair as hybrid recipient (`key_store_name` on seal) → error
24. Flat KEM keypair as sender (`sender_key_store_name`) → error "KEM keypair, not signing"
25. Flat signature keypair on `pqc_encapsulate` → error
26. Flat KEM keypair on `pqc_sign` → error
27. Algorithm mismatch on generic PQC tool → error

### Security tests
28. Handle-stored secret key never appears in any tool response (scan all output fields)
29. Full seal→open roundtrip entirely via store names (no raw keys in any call)
30. Authenticated seal→open roundtrip via store names
31. Generic sign→verify roundtrip via store names

### MCP handler tests
32. `store_as` via MCP handler returns handle output
33. `key_store_name` via MCP handler resolves correctly
34. Store-name error returns structured JSON error
35. Conflict error returns structured JSON error

### Backward compatibility
36. All existing 129 tests pass unchanged (no store params = old behavior)
