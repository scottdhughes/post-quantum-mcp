"""Session-scoped in-memory key store.

Stores keygen outputs by name for convenient reference.
No persistence — cleared on server restart.
Research/prototyping only.
"""

import base64
import hashlib
import json as _json
from typing import Any

_MAX_KEY_DATA_SIZE = 102_400  # 100 KB

# Module-level store (lives for the server's lifetime)
_STORE: dict[str, dict[str, Any]] = {}


def _fingerprint(public_key_b64: str) -> str:
    """SHA3-256 fingerprint of a base64-encoded public key."""
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
    """Internal: resolve full key_data (including secrets) by name."""
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


def _require_mldsa65(keys: dict[str, Any], name: str) -> None:
    """Require key is a flat ML-DSA-65 signing keypair (for authenticated envelopes)."""
    _require_flat_signature(keys, name)
    algorithm = keys.get("algorithm", "")
    if algorithm != "ML-DSA-65":
        raise ValueError(
            f"Key '{name}' uses {algorithm}, but authenticated envelopes require ML-DSA-65"
        )


def _require_flat_kem(keys: dict[str, Any], name: str) -> None:
    if "suite" in keys:
        raise ValueError(f"Key '{name}' is a hybrid bundle, not a KEM keypair")
    if keys.get("type", "").lower() != "kem":
        raise ValueError(
            f"Key '{name}' is a {keys.get('type', 'unknown')} keypair, not a KEM keypair"
        )


def _reject_secret_fields(key_data: dict[str, Any]) -> None:
    """Reject key_data containing secret_key fields when handle-only policy is active.

    Checks flat key structures and hybrid bundle sub-dicts.
    """
    if "secret_key" in key_data:
        raise ValueError(
            "key_store_save rejected: key_data contains 'secret_key'. "
            "PQC_REQUIRE_KEY_HANDLES policy prohibits importing raw secrets. "
            "Use pqc_generate_keypair with store_as or pqc_hybrid_keygen with store_as."
        )
    for component in ("classical", "pqc"):
        sub = key_data.get(component)
        if isinstance(sub, dict) and "secret_key" in sub:
            raise ValueError(
                f"key_store_save rejected: key_data['{component}'] contains 'secret_key'. "
                "PQC_REQUIRE_KEY_HANDLES policy prohibits importing raw secrets. "
                "Use pqc_hybrid_keygen with store_as to generate keys as opaque handles."
            )


def handle_key_store_save(arguments: dict[str, Any]) -> dict[str, Any]:
    """Save a keygen output by name."""
    name = arguments["name"]
    key_data = arguments["key_data"]

    if not isinstance(key_data, dict):
        raise ValueError("key_data must be a JSON object (e.g., output of pqc_hybrid_keygen)")

    # Policy enforcement: reject raw secrets when handle-only mode is active
    from pqc_mcp_server.security_policy import get_policy

    if get_policy().require_key_handles:
        _reject_secret_fields(key_data)

    # Size limit on key_data (prevents memory exhaustion via oversized dicts)
    key_data_size = len(_json.dumps(key_data))
    if key_data_size > _MAX_KEY_DATA_SIZE:
        raise ValueError(f"key_data is {key_data_size} bytes (max {_MAX_KEY_DATA_SIZE})")

    entry = {
        "name": name,
        "key_data": key_data,
        "stored_as_handle": True,
    }

    # Extract type info for listing
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

    _STORE[name] = entry
    return {"saved": name, "type": entry.get("type", "unknown")}


def handle_key_store_load(arguments: dict[str, Any]) -> dict[str, Any]:
    """Load a stored key by name. Handle entries return public material only."""
    name = arguments["name"]
    entry = _STORE.get(name)
    if entry is None:
        return {"error": f"Key '{name}' not found in store"}

    if entry.get("stored_as_handle"):
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

    # All entries now have stored_as_handle=True (set by both
    # store_from_keygen and handle_key_store_save), so this path
    # is unreachable. Return error rather than leaking secrets.
    return {"error": f"Key '{name}' has unexpected storage format"}


def handle_key_store_list(arguments: dict[str, Any]) -> dict[str, Any]:
    """List all stored keys with metadata (no secret material)."""
    keys = []
    for name, entry in _STORE.items():
        summary: dict[str, Any] = {"name": name, "type": entry.get("type", "unknown")}
        summary["stored_as_handle"] = entry.get("stored_as_handle", False)
        if "algorithm" in entry:
            summary["algorithm"] = entry["algorithm"]
        if "suite" in entry:
            summary["suite"] = entry["suite"]
        if "classical_fingerprint" in entry:
            summary["classical_fingerprint"] = entry["classical_fingerprint"]
        if "pqc_fingerprint" in entry:
            summary["pqc_fingerprint"] = entry["pqc_fingerprint"]
        keys.append(summary)
    return {"count": len(keys), "keys": keys}


def handle_key_store_delete(arguments: dict[str, Any]) -> dict[str, Any]:
    """Delete a stored key by name."""
    name = arguments["name"]
    if name not in _STORE:
        return {"error": f"Key '{name}' not found in store"}
    del _STORE[name]
    return {"deleted": name}


def clear_store() -> None:
    """Clear the entire store. Used for testing."""
    _STORE.clear()
