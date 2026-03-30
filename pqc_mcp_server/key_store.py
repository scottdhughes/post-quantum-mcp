"""Session-scoped in-memory key store.

Stores keygen outputs by name for convenient reference.
No persistence — cleared on server restart.
Research/prototyping only.
"""

from typing import Any

# Module-level store (lives for the server's lifetime)
_STORE: dict[str, dict[str, Any]] = {}


def handle_key_store_save(arguments: dict[str, Any]) -> dict[str, Any]:
    """Save a keygen output by name."""
    name = arguments["name"]
    key_data = arguments["key_data"]

    if not isinstance(key_data, dict):
        raise ValueError("key_data must be a JSON object (e.g., output of pqc_hybrid_keygen)")

    entry = {
        "name": name,
        "key_data": key_data,
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
    """Load a stored key by name."""
    name = arguments["name"]
    entry = _STORE.get(name)
    if entry is None:
        return {"error": f"Key '{name}' not found in store"}
    result: dict[str, Any] = entry["key_data"]
    return result


def handle_key_store_list(arguments: dict[str, Any]) -> dict[str, Any]:
    """List all stored keys with metadata (no secret material)."""
    keys = []
    for name, entry in _STORE.items():
        summary: dict[str, Any] = {"name": name, "type": entry.get("type", "unknown")}
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
