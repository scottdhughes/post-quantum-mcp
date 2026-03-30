# Secret-Handle Keyring Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add opt-in opaque secret-handle mode so secret keys never appear in MCP tool output when `store_as` is used, and downstream tools can resolve keys by name via `key_store_name`.

**Architecture:** `key_store.py` gains handle storage + resolution + type validation. Handler files gain resolution helpers that check for conflicts, validate types, and resolve from store before falling through to raw base64. Tool schemas gain optional store-name parameters. Crypto core (`hybrid.py`) and dispatch (`__init__.py`) are untouched.

**Tech Stack:** Python 3.10+, existing pqc_mcp_server modules, liboqs for algorithm canonicalization

**Spec:** `docs/superpowers/specs/2026-03-30-secret-handle-keyring-design.md` (v3)

---

## File Map

| File | Changes |
|------|---------|
| `pqc_mcp_server/key_store.py` | `store_from_keygen()`, `_resolve_from_store()`, type validators, redacted load, `stored_as_handle` flag |
| `pqc_mcp_server/handlers_hybrid.py` | Resolution helpers for hybrid recipient/own-keys/sender, modify 7 handlers |
| `pqc_mcp_server/handlers_pqc.py` | `store_as` on `generate_keypair`, `key_store_name` on sign/verify/encap/decap, fingerprint in output |
| `pqc_mcp_server/tools.py` | Add optional params to 13 tool schemas |
| `tests/test_handle_keyring.py` | New: 40 test cases |
| `pqc_mcp_server/hybrid.py` | **No changes** |
| `pqc_mcp_server/__init__.py` | **No changes** |

---

## Task 1: Key store internals — handle storage + resolution + type validators

**Files:**
- Modify: `pqc_mcp_server/key_store.py`
- Create: `tests/test_handle_keyring.py`

This task adds the core store functions that all subsequent tasks depend on.

- [ ] **Step 1: Write tests for store internals**

Create `tests/test_handle_keyring.py` with tests for `store_from_keygen`, `_resolve_from_store`, type validators, redacted load, collision behavior, and `stored_as_handle` in list. Use `pytest.importorskip` for oqs/cryptography. Use `clear_store()` fixture. Import `hybrid_keygen` and `handle_generate_keypair` to generate real key data.

Test cases to cover (spec items 1-8, 36-37):
- `store_from_keygen` stores and `_resolve_from_store` returns full data including secrets
- `handle_key_store_load` on handle entry returns public material + metadata, no secrets
- `handle_key_store_load` on explicit-save entry returns full data (backward compat)
- `handle_key_store_list` shows `stored_as_handle: true`
- Collision without `overwrite` raises ValueError
- Collision with `overwrite=True` succeeds
- `_resolve_from_store` on nonexistent name raises ValueError
- `_require_hybrid_bundle` rejects flat keypair
- `_require_flat_signature` rejects hybrid bundle
- `_require_flat_signature` rejects KEM keypair
- `_require_flat_kem` rejects signature keypair
- Delete handle entry, then resolve raises error
- `store_from_keygen` for flat keypair stores with fingerprint

- [ ] **Step 2: Run tests to verify they fail**

Run: `uv run pytest tests/test_handle_keyring.py -v --tb=short`

- [ ] **Step 3: Implement store internals**

Add to `key_store.py`:

```python
import hashlib

def _fingerprint(public_key_b64: str) -> str:
    """SHA3-256 fingerprint of a base64-encoded public key."""
    import base64
    return hashlib.sha3_256(base64.b64decode(public_key_b64)).hexdigest()

def store_from_keygen(name: str, key_data: dict[str, Any], overwrite: bool = False) -> None:
    """Store keygen output as a handle. Fails on collision unless overwrite=True."""
    if name in _STORE and not overwrite:
        raise ValueError(f"Key '{name}' already exists in store. Pass overwrite: true to replace.")

    entry: dict[str, Any] = {
        "name": name,
        "key_data": key_data,
        "stored_as_handle": True,
    }

    if "suite" in key_data:
        entry["type"] = "hybrid"
        entry["suite"] = key_data["suite"]
        if "classical" in key_data and "fingerprint" in key_data["classical"]:
            entry["classical_fingerprint"] = key_data["classical"]["fingerprint"]
        if "pqc" in key_data and "fingerprint" in key_data["pqc"]:
            entry["pqc_fingerprint"] = key_data["pqc"]["fingerprint"]
    elif "algorithm" in key_data:
        entry["type"] = key_data.get("type", "unknown").lower()
        entry["algorithm"] = key_data["algorithm"]
        if "public_key" in key_data:
            entry["fingerprint"] = _fingerprint(key_data["public_key"])

    _STORE[name] = entry


def _resolve_from_store(name: str) -> dict[str, Any]:
    """Internal: resolve full key_data (including secrets) by name.
    Never exposed via MCP. Only called by handler resolution helpers."""
    entry = _STORE.get(name)
    if entry is None:
        raise ValueError(f"Key '{name}' not found in store")
    result: dict[str, Any] = entry["key_data"]
    return result


def _require_hybrid_bundle(keys: dict[str, Any], name: str) -> None:
    if "suite" not in keys:
        raise ValueError(f"Key '{name}' is not a hybrid bundle")


def _require_flat_signature(keys: dict[str, Any], name: str) -> None:
    if "suite" in keys:
        raise ValueError(f"Key '{name}' is a hybrid bundle, not a signing keypair")
    if keys.get("type", "").lower() != "signature":
        raise ValueError(
            f"Key '{name}' is a {keys.get('type', 'unknown')} keypair, not a signing keypair"
        )


def _require_flat_kem(keys: dict[str, Any], name: str) -> None:
    if "suite" in keys:
        raise ValueError(f"Key '{name}' is a hybrid bundle, not a KEM keypair")
    if keys.get("type", "").lower() != "kem":
        raise ValueError(
            f"Key '{name}' is a {keys.get('type', 'unknown')} keypair, not a KEM keypair"
        )
```

Modify `handle_key_store_load` to redact handle entries:

```python
def handle_key_store_load(arguments: dict[str, Any]) -> dict[str, Any]:
    name = arguments["name"]
    entry = _STORE.get(name)
    if entry is None:
        return {"error": f"Key '{name}' not found in store"}

    if entry.get("stored_as_handle"):
        # Return public material + metadata only
        key_data = entry["key_data"]
        result: dict[str, Any] = {"name": name, "stored_as_handle": True}
        if "suite" in key_data:
            result["type"] = "hybrid"
            result["suite"] = key_data["suite"]
            result["classical"] = {
                "algorithm": key_data["classical"]["algorithm"],
                "public_key": key_data["classical"]["public_key"],
                "fingerprint": key_data["classical"].get("fingerprint", ""),
            }
            result["pqc"] = {
                "algorithm": key_data["pqc"]["algorithm"],
                "public_key": key_data["pqc"]["public_key"],
                "fingerprint": key_data["pqc"].get("fingerprint", ""),
            }
        else:
            result["type"] = key_data.get("type", "unknown")
            result["algorithm"] = key_data.get("algorithm", "")
            result["public_key"] = key_data.get("public_key", "")
            result["public_key_size"] = key_data.get("public_key_size", 0)
            if "public_key" in key_data:
                result["fingerprint"] = _fingerprint(key_data["public_key"])
                result["fingerprint_algorithm"] = "SHA3-256"
        return result

    result2: dict[str, Any] = entry["key_data"]
    return result2
```

Modify `handle_key_store_list` to include `stored_as_handle`:

```python
# In the summary dict construction, add:
summary["stored_as_handle"] = entry.get("stored_as_handle", False)
```

- [ ] **Step 4: Run tests**

Run: `uv run pytest tests/test_handle_keyring.py -v --tb=short`

- [ ] **Step 5: Commit**

```bash
git add pqc_mcp_server/key_store.py tests/test_handle_keyring.py
git commit -m "feat(keyring): add handle storage, resolution, type validators"
```

---

## Task 2: Hybrid handler resolution helpers

**Files:**
- Modify: `pqc_mcp_server/handlers_hybrid.py`
- Modify: `tests/test_handle_keyring.py`

Add resolution helpers and modify all 7 hybrid handlers + keygen.

- [ ] **Step 1: Add resolution tests**

Append to `tests/test_handle_keyring.py` test classes for:
- `hybrid_keygen` with `store_as` returns no secrets, returns `handle` field
- `hybrid_seal` with `recipient_key_store_name` works
- `hybrid_open` with `key_store_name` works
- `hybrid_auth_seal` with both store names works
- `hybrid_auth_open` with `key_store_name` + explicit sender works
- `hybrid_encap` with `key_store_name` works
- `hybrid_decap` with `key_store_name` works
- Conflict: both store name and raw keys → error
- Full seal→open roundtrip entirely via store names
- Auth seal→open roundtrip via store names
- Handle-stored secret never in any hybrid tool output

- [ ] **Step 2: Implement resolution helpers in handlers_hybrid.py**

Add these helpers at the top of `handlers_hybrid.py` (after imports):

```python
from pqc_mcp_server.key_store import (
    store_from_keygen,
    _resolve_from_store,
    _require_hybrid_bundle,
    _require_flat_signature,
)


def _resolve_hybrid_public(arguments: dict[str, Any], prefix: str = "") -> tuple[bytes, bytes]:
    """Resolve hybrid recipient public keys from store or raw args.
    prefix is '' for encap/decap/open, 'recipient_' for seal/auth_seal."""
    store_param = f"{prefix}key_store_name" if not prefix else f"{prefix}key_store_name"
    # Fix: for seal/auth_seal it's 'recipient_key_store_name', for others 'key_store_name'
    raw_cpk = f"{prefix}classical_public_key" if prefix else "classical_public_key"
    raw_ppk = f"{prefix}pqc_public_key" if prefix else "pqc_public_key"

    has_store = store_param in arguments
    has_raw = raw_cpk in arguments or raw_ppk in arguments
    if has_store and has_raw:
        raise ValueError(f"Provide either {store_param} or raw key parameters, not both")
    if has_store:
        keys = _resolve_from_store(arguments[store_param])
        _require_hybrid_bundle(keys, arguments[store_param])
        return _b64(keys["classical"]["public_key"]), _b64(keys["pqc"]["public_key"])
    return _b64(arguments[raw_cpk]), _b64(arguments[raw_ppk])


def _resolve_hybrid_secret(arguments: dict[str, Any]) -> tuple[bytes, bytes]:
    """Resolve hybrid recipient secret keys from store or raw args."""
    has_store = "key_store_name" in arguments
    has_raw = "classical_secret_key" in arguments or "pqc_secret_key" in arguments
    if has_store and has_raw:
        raise ValueError("Provide either key_store_name or raw key parameters, not both")
    if has_store:
        keys = _resolve_from_store(arguments["key_store_name"])
        _require_hybrid_bundle(keys, arguments["key_store_name"])
        return _b64(keys["classical"]["secret_key"]), _b64(keys["pqc"]["secret_key"])
    return _b64(arguments["classical_secret_key"]), _b64(arguments["pqc_secret_key"])


def _resolve_sender(arguments: dict[str, Any]) -> tuple[bytes, bytes]:
    """Resolve sender signing keys from store or raw args. Returns (sk, pk)."""
    has_store = "sender_key_store_name" in arguments
    has_raw = "sender_secret_key" in arguments or "sender_public_key" in arguments
    if has_store and has_raw:
        raise ValueError("Provide either sender_key_store_name or raw key parameters, not both")
    if has_store:
        keys = _resolve_from_store(arguments["sender_key_store_name"])
        _require_flat_signature(keys, arguments["sender_key_store_name"])
        return _b64(keys["secret_key"]), _b64(keys["public_key"])
    return _b64(arguments["sender_secret_key"]), _b64(arguments["sender_public_key"])
```

Modify `handle_hybrid_keygen`:
```python
def handle_hybrid_keygen(arguments: dict[str, Any]) -> dict[str, Any]:
    result = hybrid_keygen()
    store_name = arguments.get("store_as")
    if store_name:
        overwrite = arguments.get("overwrite", False)
        store_from_keygen(store_name, result, overwrite=overwrite)
        # Return public material only
        return {
            "suite": result["suite"],
            "handle": store_name,
            "classical": {
                "algorithm": result["classical"]["algorithm"],
                "public_key": result["classical"]["public_key"],
                "fingerprint": result["classical"]["fingerprint"],
            },
            "pqc": {
                "algorithm": result["pqc"]["algorithm"],
                "public_key": result["pqc"]["public_key"],
                "fingerprint": result["pqc"]["fingerprint"],
            },
        }
    return result
```

Modify each downstream hybrid handler to use the resolution helpers. For example `handle_hybrid_seal`:
```python
def handle_hybrid_seal(arguments: dict[str, Any]) -> dict[str, Any]:
    pt_bytes = _resolve_plaintext(arguments)
    classical_pk, pqc_pk = _resolve_hybrid_public(arguments, prefix="recipient_")
    envelope = hybrid_seal(pt_bytes, classical_pk, pqc_pk)
    return {"envelope": envelope}
```

Apply same pattern for `handle_hybrid_open` (uses `_resolve_hybrid_secret`), `handle_hybrid_encap` (uses `_resolve_hybrid_public` with no prefix), `handle_hybrid_decap` (uses `_resolve_hybrid_secret` + raw epk/pqc_ct), `handle_hybrid_auth_seal` (uses `_resolve_hybrid_public` for recipient + `_resolve_sender` for sender), `handle_hybrid_auth_open` (uses `_resolve_hybrid_secret`, sender binding still explicit).

- [ ] **Step 3: Run tests**

Run: `uv run pytest tests/test_handle_keyring.py tests/test_hybrid.py tests/test_hybrid_auth.py -v --tb=short`

- [ ] **Step 4: Commit**

```bash
git add pqc_mcp_server/handlers_hybrid.py tests/test_handle_keyring.py
git commit -m "feat(keyring): hybrid handler resolution + store_as on keygen"
```

---

## Task 3: Generic PQC handler resolution

**Files:**
- Modify: `pqc_mcp_server/handlers_pqc.py`
- Modify: `tests/test_handle_keyring.py`

Add `store_as` to `generate_keypair` and `key_store_name` to sign/verify/encap/decap.

- [ ] **Step 1: Add tests**

Append to `tests/test_handle_keyring.py`:
- `generate_keypair` with `store_as` returns no secret key, returns fingerprint
- `pqc_sign` with `key_store_name` works
- `pqc_verify` with `key_store_name` works
- `pqc_encapsulate` with `key_store_name` works
- `pqc_decapsulate` with `key_store_name` works
- Sign→verify roundtrip via store names
- Conflict: both store name and raw keys on sign → error
- Type mismatch: KEM key on sign → error
- Type mismatch: signature key on encapsulate → error
- Algorithm mismatch → error (if liboqs supports aliases, also test alias acceptance)

- [ ] **Step 2: Implement**

Modify `handle_generate_keypair` to support `store_as` + `overwrite` + fingerprint:
```python
def handle_generate_keypair(arguments: dict[str, Any]) -> dict[str, Any]:
    alg = arguments["algorithm"]
    # ... existing keygen logic ...
    result = { ... }  # existing result dict

    store_name = arguments.get("store_as")
    if store_name:
        from pqc_mcp_server.key_store import store_from_keygen
        overwrite = arguments.get("overwrite", False)
        store_from_keygen(store_name, result, overwrite=overwrite)
        # Return public material + fingerprint only
        import hashlib
        fp = hashlib.sha3_256(base64.b64decode(result["public_key"])).hexdigest()
        return {
            "algorithm": result["algorithm"],
            "type": result["type"],
            "handle": store_name,
            "public_key": result["public_key"],
            "public_key_size": result["public_key_size"],
            "fingerprint": fp,
            "fingerprint_algorithm": "SHA3-256",
        }
    return result
```

Add resolution helper and modify sign/verify/encap/decap:
```python
def _resolve_flat_key(
    arguments: dict[str, Any],
    key_field: str,
    expected_type: str,
) -> bytes | None:
    """Resolve a flat key from store or return None (use raw args).
    Checks conflict, type, and algorithm match."""
    from pqc_mcp_server.key_store import _resolve_from_store, _require_flat_signature, _require_flat_kem

    has_store = "key_store_name" in arguments
    has_raw = key_field in arguments
    if has_store and has_raw:
        raise ValueError("Provide either key_store_name or raw key parameters, not both")
    if not has_store:
        return None  # caller uses raw args

    keys = _resolve_from_store(arguments["key_store_name"])
    name = arguments["key_store_name"]

    if expected_type == "signature":
        _require_flat_signature(keys, name)
    elif expected_type == "kem":
        _require_flat_kem(keys, name)

    # Algorithm mismatch check (canonical comparison via liboqs)
    if "algorithm" in arguments:
        stored_alg = keys.get("algorithm", "")
        requested_alg = arguments["algorithm"]
        # Both must be valid liboqs names — liboqs will reject invalid ones downstream
        # For alias tolerance: try instantiating both to see if they resolve to the same mechanism
        if stored_alg.lower() != requested_alg.lower():
            # Try liboqs canonical check
            try:
                import oqs
                if expected_type == "kem":
                    k1 = oqs.KeyEncapsulation(stored_alg)
                    k2 = oqs.KeyEncapsulation(requested_alg)
                    if k1.details["name"] != k2.details["name"]:
                        raise ValueError(
                            f"Algorithm mismatch: requested '{requested_alg}' but key '{name}' is '{stored_alg}'"
                        )
                else:
                    s1 = oqs.Signature(stored_alg)
                    s2 = oqs.Signature(requested_alg)
                    if s1.details["name"] != s2.details["name"]:
                        raise ValueError(
                            f"Algorithm mismatch: requested '{requested_alg}' but key '{name}' is '{stored_alg}'"
                        )
            except Exception:
                raise ValueError(
                    f"Algorithm mismatch: requested '{requested_alg}' but key '{name}' is '{stored_alg}'"
                )

    return base64.b64decode(keys[key_field])
```

Then modify each handler:
```python
def handle_sign(arguments: dict[str, Any]) -> dict[str, Any]:
    resolved_sk = _resolve_flat_key(arguments, "secret_key", "signature")
    alg = arguments["algorithm"]
    secret_key = resolved_sk if resolved_sk is not None else base64.b64decode(arguments["secret_key"])
    message = arguments["message"].encode("utf-8")
    sig = oqs.Signature(alg, secret_key)
    signature = sig.sign(message)
    return { ... }  # same result dict as before
```

Same pattern for verify (resolves `public_key`), encapsulate (resolves `public_key`, type=kem), decapsulate (resolves `secret_key`, type=kem).

- [ ] **Step 3: Run tests**

Run: `uv run pytest tests/ -v --tb=short`
Expected: all existing + new tests pass

- [ ] **Step 4: Commit**

```bash
git add pqc_mcp_server/handlers_pqc.py tests/test_handle_keyring.py
git commit -m "feat(keyring): generic PQC handler resolution + store_as on generate_keypair"
```

---

## Task 4: Tool schema updates

**Files:**
- Modify: `pqc_mcp_server/tools.py`

Add optional parameters to all affected tool schemas. No logic changes — just schema declarations.

- [ ] **Step 1: Update schemas**

Add to `pqc_hybrid_keygen` schema: `store_as` (string, optional), `overwrite` (boolean, optional).
Add to `pqc_generate_keypair` schema: `store_as` (string, optional), `overwrite` (boolean, optional).
Add to all hybrid downstream tools: `key_store_name` or `recipient_key_store_name` / `sender_key_store_name` as applicable.
Add to `pqc_sign`, `pqc_verify`, `pqc_encapsulate`, `pqc_decapsulate`: `key_store_name` (string, optional).

- [ ] **Step 2: Run tests to verify schemas don't break tool registration**

Run: `uv run pytest tests/test_server.py::test_list_tools_returns_all_expected -v`

- [ ] **Step 3: Commit**

```bash
git add pqc_mcp_server/tools.py
git commit -m "feat(keyring): add store_as and key_store_name to tool schemas"
```

---

## Task 5: MCP handler integration tests

**Files:**
- Modify: `tests/test_handle_keyring.py` or `tests/test_server.py`

Add MCP-layer tests that go through the actual `call_tool` dispatch:
- `store_as` via MCP returns handle output (no secrets)
- `key_store_name` via MCP resolves correctly
- Store-name error returns structured JSON
- Conflict error returns structured JSON

- [ ] **Step 1: Write MCP handler tests**

Use the `call_tool` fixture from conftest.py.

- [ ] **Step 2: Run full suite**

Run: `uv run pytest tests/ -v --tb=short`

- [ ] **Step 3: Commit**

```bash
git add tests/
git commit -m "test(keyring): MCP handler integration tests for handle mode"
```

---

## Task 6: Final verification + docs

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Run all gates**

```bash
uv run pytest tests/ -v --tb=short
uv run black --check pqc_mcp_server/ tests/
uv run mypy pqc_mcp_server/
```

- [ ] **Step 2: Update README**

Add a "Key Handles" section explaining `store_as` and `key_store_name` with a usage example.

- [ ] **Step 3: Update CHANGELOG**

Add handle-mode entries to Unreleased section.

- [ ] **Step 4: Commit and push**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: add key handle documentation to README and CHANGELOG"
git push origin main
```

- [ ] **Step 5: Verify CI green**

Run: `gh run watch <run-id> --exit-status`
