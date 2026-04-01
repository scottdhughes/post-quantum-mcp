"""Handlers for hybrid and authenticated envelope tools.

Each handler takes arguments dict, returns a result dict.
Raises specific exceptions for the dispatch layer to catch:
- binascii.Error for invalid base64
- ValueError for bad headers/keys
- SenderVerificationError for auth failures
- InvalidTag for AEAD decryption failures
"""

# mypy: disable-error-code="no-any-return"
import base64
import binascii
from typing import Any

from pqc_mcp_server.hybrid import (
    hybrid_keygen,
    hybrid_encap,
    hybrid_decap,
    hybrid_seal,
    hybrid_open,
    hybrid_auth_seal,
    hybrid_auth_open,
    _fingerprint_public_key,
)
from pqc_mcp_server.key_store import (
    store_from_keygen,
    _resolve_from_store,
    _require_hybrid_bundle,
    _require_flat_signature,
    _require_mldsa65,
)


def _b64(value: str | bytes) -> bytes:
    """Strict base64 decode. Raises binascii.Error on invalid input."""
    return base64.b64decode(value, validate=True)


def _resolve_plaintext(arguments: dict[str, Any]) -> bytes:
    """Extract plaintext bytes from arguments. Enforces exactly-one-of."""
    if "plaintext" in arguments and "plaintext_base64" in arguments:
        raise ValueError("Provide exactly one of plaintext or plaintext_base64, not both")
    if "plaintext" in arguments:
        return arguments["plaintext"].encode("utf-8")
    if "plaintext_base64" in arguments:
        return _b64(arguments["plaintext_base64"])
    raise ValueError("Provide plaintext or plaintext_base64")


def _resolve_hybrid_public(arguments: dict[str, Any], prefix: str = "") -> tuple[bytes, bytes]:
    """Resolve hybrid recipient public keys from store or raw args."""
    store_param = f"{prefix}key_store_name"
    raw_cpk = f"{prefix}classical_public_key"
    raw_ppk = f"{prefix}pqc_public_key"
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
        _require_mldsa65(keys, arguments["sender_key_store_name"])
        return _b64(keys["secret_key"]), _b64(keys["public_key"])
    return _b64(arguments["sender_secret_key"]), _b64(arguments["sender_public_key"])


def handle_fingerprint(arguments: dict[str, Any]) -> dict[str, Any]:
    pk_bytes = _b64(arguments["public_key"])
    return {
        "fingerprint": _fingerprint_public_key(pk_bytes),
        "algorithm": "SHA3-256",
        "public_key_size": len(pk_bytes),
    }


def handle_hybrid_keygen(arguments: dict[str, Any]) -> dict[str, Any]:
    result = hybrid_keygen()
    store_name = arguments.get("store_as")
    if store_name:
        overwrite = arguments.get("overwrite", False)
        store_from_keygen(store_name, result, overwrite=overwrite)
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


def handle_hybrid_encap(arguments: dict[str, Any]) -> dict[str, Any]:
    classical_pk, pqc_pk = _resolve_hybrid_public(arguments)
    return hybrid_encap(classical_pk, pqc_pk)


def handle_hybrid_decap(arguments: dict[str, Any]) -> dict[str, Any]:
    classical_sk, pqc_sk = _resolve_hybrid_secret(arguments)
    return hybrid_decap(
        classical_sk,
        pqc_sk,
        _b64(arguments["x25519_ephemeral_public_key"]),
        _b64(arguments["pqc_ciphertext"]),
    )


def handle_hybrid_seal(arguments: dict[str, Any]) -> dict[str, Any]:
    pt_bytes = _resolve_plaintext(arguments)
    classical_pk, pqc_pk = _resolve_hybrid_public(arguments, prefix="recipient_")
    envelope = hybrid_seal(pt_bytes, classical_pk, pqc_pk)
    return {"envelope": envelope}


def handle_hybrid_open(arguments: dict[str, Any]) -> dict[str, Any]:
    classical_sk, pqc_sk = _resolve_hybrid_secret(arguments)
    return hybrid_open(arguments["envelope"], classical_sk, pqc_sk)


def handle_hybrid_auth_seal(arguments: dict[str, Any]) -> dict[str, Any]:
    pt_bytes = _resolve_plaintext(arguments)
    classical_pk, pqc_pk = _resolve_hybrid_public(arguments, prefix="recipient_")
    sender_sk, sender_pk = _resolve_sender(arguments)
    envelope = hybrid_auth_seal(pt_bytes, classical_pk, pqc_pk, sender_sk, sender_pk)
    return {"envelope": envelope}


def handle_hybrid_auth_open(arguments: dict[str, Any]) -> dict[str, Any]:
    classical_sk, pqc_sk = _resolve_hybrid_secret(arguments)
    expected_pk = (
        _b64(arguments["expected_sender_public_key"])
        if "expected_sender_public_key" in arguments
        else None
    )
    expected_fp = arguments.get("expected_sender_fingerprint")
    return hybrid_auth_open(
        arguments["envelope"],
        classical_sk,
        pqc_sk,
        expected_sender_public_key=expected_pk,
        expected_sender_fingerprint=expected_fp,
    )


def handle_envelope_inspect(arguments: dict[str, Any]) -> dict[str, Any]:
    """Inspect an envelope's metadata without decrypting. No secret keys needed."""
    envelope = arguments["envelope"]
    result: dict[str, Any] = {
        "version": envelope.get("version"),
        "suite": envelope.get("suite"),
    }

    # Measure ciphertext sizes
    if "ciphertext" in envelope:
        ct_bytes = _b64(envelope["ciphertext"])
        result["ciphertext_size"] = len(ct_bytes)
        # GCM tag is last 16 bytes
        result["plaintext_size_approx"] = max(0, len(ct_bytes) - 16)

    if "pqc_ciphertext" in envelope:
        result["pqc_ciphertext_size"] = len(_b64(envelope["pqc_ciphertext"]))

    if "x25519_ephemeral_public_key" in envelope:
        result["x25519_ephemeral_public_key_size"] = len(
            _b64(envelope["x25519_ephemeral_public_key"])
        )

    # Authenticated envelope fields
    is_authenticated = "sender_signature_algorithm" in envelope
    result["authenticated"] = is_authenticated

    if is_authenticated:
        result["sender_signature_algorithm"] = envelope.get("sender_signature_algorithm")
        result["sender_key_fingerprint"] = envelope.get("sender_key_fingerprint")
        result["recipient_classical_key_fingerprint"] = envelope.get(
            "recipient_classical_key_fingerprint"
        )
        result["recipient_pqc_key_fingerprint"] = envelope.get("recipient_pqc_key_fingerprint")
        if "signature" in envelope:
            result["signature_size"] = len(_b64(envelope["signature"]))

    return result
