# Secret-Handle Keyring — Design Spec

**Date:** 2026-03-30
**Status:** Draft
**Author:** Scott Hughes + Claude

## Goal

Add opt-in opaque secret-handle mode to the PQC MCP server. When a caller generates keys with `store_as`, secret keys are stored process-locally and never appear in tool output. Downstream tools accept `key_store_name` to reference stored keys by name. This materially reduces secret-material leakage into model context, client logs, and transcripts.

**Scope disclaimer:** This remains research/prototyping tooling. The handle system protects against output leakage, not against a compromised server process. liboqs is not recommended for production use.

## Design Decisions (Resolved)

1. **Opt-in via `store_as` parameter** on existing keygen tools. No new keygen tools. Behavior unchanged when parameter is omitted.
2. **Single `key_store_name` parameter** on downstream tools resolves a full key bundle from the store. For `hybrid_auth_seal`, two parameters: `recipient_key_store_name` + `sender_key_store_name`.
3. **Output-only protection.** Secrets are plain bytes in the server process. The threat model is "secrets in LLM context and logs," not "secrets in the server process."
4. **Storage method distinguishes redaction.** Keys stored via `store_as` (handle mode) → `pqc_key_store_load` returns public material only. Keys stored via `pqc_key_store_save` (explicit save) → returns full key_data as before.
5. **Store name takes precedence** over raw base64 parameters when both are provided. No conflict error.
6. **`store_as` overwrites** existing entries with the same name, consistent with `pqc_key_store_save` behavior.
7. **Crypto layer untouched.** `hybrid.py` still only sees raw bytes. Resolution happens in the handler layer.

## Modified Tools

### Keygen tools (new `store_as` parameter)

#### `pqc_hybrid_keygen`

New optional parameter: `store_as` (string).

When `store_as` is provided:
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

No `secret_key` fields in output.

When `store_as` is omitted: behavior unchanged (returns full key_data including secrets).

#### `pqc_generate_keypair`

New optional parameter: `store_as` (string).

When `store_as` is provided:
- Generates keypair normally
- Stores full result internally with `stored_as_handle: true`
- Returns public material only:

```json
{
  "algorithm": "ML-DSA-65",
  "type": "Signature",
  "handle": "alice-signing",
  "public_key": "<base64>",
  "public_key_size": 1952
}
```

No `secret_key` or `secret_key_size` in output.

### Downstream tools (new store-name parameters)

| Tool | New Parameter | Resolves From Store |
|------|--------------|-------------------|
| `pqc_hybrid_encap` | `key_store_name` | `classical.public_key`, `pqc.public_key` |
| `pqc_hybrid_decap` | `key_store_name` | `classical.secret_key`, `pqc.secret_key` (epk + pqc_ct still from arguments) |
| `pqc_hybrid_seal` | `recipient_key_store_name` | `classical.public_key`, `pqc.public_key` |
| `pqc_hybrid_open` | `key_store_name` | `classical.secret_key`, `pqc.secret_key` |
| `pqc_hybrid_auth_seal` | `recipient_key_store_name` + `sender_key_store_name` | recipient: `classical.public_key`, `pqc.public_key`; sender: `secret_key`, `public_key` |
| `pqc_hybrid_auth_open` | `key_store_name` | `classical.secret_key`, `pqc.secret_key` (sender binding still explicit via `expected_sender_public_key` or `expected_sender_fingerprint`) |

All store-name parameters are optional. When omitted, raw base64 parameters work as before.

### `pqc_key_store_load` behavior change

- Entry with `stored_as_handle: true` → returns public material only (secret keys redacted)
- Entry with `stored_as_handle: false` (or absent) → returns full key_data as before

## Key Data Shapes

### Hybrid bundle (from `pqc_hybrid_keygen`)
```
{
  "suite": "...",
  "classical": {"algorithm", "public_key", "secret_key", "fingerprint"},
  "pqc": {"algorithm", "public_key", "secret_key", "fingerprint"}
}
```

Store resolution for recipient tools: `key_data["classical"]["public_key"]`, `key_data["pqc"]["public_key"]` (or `secret_key` for decryption).

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

Store resolution for sender tools: `key_data["secret_key"]`, `key_data["public_key"]`.

### Type detection
- `"suite" in key_data` → hybrid bundle
- `"algorithm" in key_data` and no `"suite"` → flat keypair

## Resolution Logic

### `_resolve_from_store(name: str) -> dict[str, Any]`

Internal function in `key_store.py`. Returns the full key_data dict (including secrets) regardless of handle mode. Only called by handler functions, never exposed via MCP.

Raises `ValueError` if name not found in store.

### Handler resolution pattern

Each handler checks for its store-name parameter first:

```python
def handle_hybrid_seal(arguments):
    if "recipient_key_store_name" in arguments:
        keys = _resolve_from_store(arguments["recipient_key_store_name"])
        # keys is a hybrid bundle
        classical_pk = _b64(keys["classical"]["public_key"])
        pqc_pk = _b64(keys["pqc"]["public_key"])
    else:
        classical_pk = _b64(arguments["recipient_classical_public_key"])
        pqc_pk = _b64(arguments["recipient_pqc_public_key"])
    ...
```

### Type mismatch errors

If `sender_key_store_name` points to a hybrid bundle instead of a signing keypair:
```json
{"error": "Key 'alice-hybrid' is a hybrid bundle, not a signing keypair"}
```

If `key_store_name` on a hybrid tool points to a flat keypair:
```json
{"error": "Key 'alice-signing' is not a hybrid bundle"}
```

## Error Handling

- Store name not found: `{"error": "Key 'name' not found in store"}`
- Type mismatch: `{"error": "Key 'name' is a hybrid bundle, not a signing keypair"}` (or vice versa)
- All existing error handling unchanged: `binascii.Error`, `SenderVerificationError`, `InvalidTag`, `ValueError`

## Security Properties

| Property | Status |
|----------|--------|
| Secret keys never in tool output (handle mode) | **New** |
| Secret keys never leave server process (handle mode) | **New** |
| Output-only protection (server process is trusted) | By design |
| Backward compatible (omit new params = old behavior) | By design |
| Sender trust still explicit (never auto-resolved from store) | Preserved |
| Research/prototyping only | Unchanged |

## Code Changes

### `key_store.py`
- Add `stored_as_handle` flag to store entries
- Add `_resolve_from_store(name)` internal function
- Add `store_from_keygen(name, key_data)` for handle-mode storage
- Modify `handle_key_store_load` to redact secrets for handle entries
- Modify `handle_key_store_list` to show `stored_as_handle` in summary

### `handlers_hybrid.py`
- Add `_resolve_hybrid_bundle(arguments, pk_or_sk)` helper
- Add `_resolve_sender_keys(arguments)` helper
- Modify 7 handlers to check store-name params before raw params

### `handlers_pqc.py`
- Modify `handle_generate_keypair` to support `store_as`

### `tools.py`
- Add `store_as` to keygen tool schemas
- Add `key_store_name` / `recipient_key_store_name` / `sender_key_store_name` to downstream tool schemas

### `hybrid.py`
- **No changes.** Crypto core untouched.

### `__init__.py`
- **No changes.** Handler registry and dispatch unchanged.

## Testing

### Pure key-store tests
1. `store_as` on `hybrid_keygen` returns no secret keys
2. `store_as` on `generate_keypair` returns no secret key
3. `pqc_key_store_load` on handle entry returns public only
4. `pqc_key_store_load` on explicit-save entry returns full data
5. `pqc_key_store_list` shows `stored_as_handle` flag
6. Overwrite handle entry preserves handle flag

### Resolution tests
7. `hybrid_seal` with `recipient_key_store_name` works
8. `hybrid_open` with `key_store_name` works
9. `hybrid_auth_seal` with both store names works
10. `hybrid_auth_open` with `key_store_name` + explicit sender binding works
11. `hybrid_encap` with `key_store_name` works
12. `hybrid_decap` with `key_store_name` works

### Error tests
13. Nonexistent store name returns error
14. Type mismatch (hybrid bundle as sender) returns error
15. Type mismatch (flat keypair as recipient) returns error

### Security tests
16. Handle-stored secret key never appears in any tool response
17. Full seal→open roundtrip works entirely via store names (no raw keys in any call)
18. Authenticated seal→open roundtrip via store names

### MCP handler tests
19. `store_as` via MCP handler returns handle output
20. `key_store_name` via MCP handler resolves correctly
21. Store-name error returns structured JSON error

### Backward compatibility tests
22. All existing tests pass unchanged (no store params = old behavior)
