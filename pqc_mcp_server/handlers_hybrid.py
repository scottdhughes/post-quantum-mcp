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


def handle_fingerprint(arguments: dict[str, Any]) -> dict[str, Any]:
    pk_bytes = _b64(arguments["public_key"])
    return {
        "fingerprint": _fingerprint_public_key(pk_bytes),
        "algorithm": "SHA3-256",
        "public_key_size": len(pk_bytes),
    }


def handle_hybrid_keygen(arguments: dict[str, Any]) -> dict[str, Any]:
    return hybrid_keygen()


def handle_hybrid_encap(arguments: dict[str, Any]) -> dict[str, Any]:
    return hybrid_encap(
        _b64(arguments["classical_public_key"]),
        _b64(arguments["pqc_public_key"]),
    )


def handle_hybrid_decap(arguments: dict[str, Any]) -> dict[str, Any]:
    return hybrid_decap(
        _b64(arguments["classical_secret_key"]),
        _b64(arguments["pqc_secret_key"]),
        _b64(arguments["x25519_ephemeral_public_key"]),
        _b64(arguments["pqc_ciphertext"]),
    )


def handle_hybrid_seal(arguments: dict[str, Any]) -> dict[str, Any]:
    pt_bytes = _resolve_plaintext(arguments)
    envelope = hybrid_seal(
        pt_bytes,
        _b64(arguments["recipient_classical_public_key"]),
        _b64(arguments["recipient_pqc_public_key"]),
    )
    return {"envelope": envelope}


def handle_hybrid_open(arguments: dict[str, Any]) -> dict[str, Any]:
    return hybrid_open(
        arguments["envelope"],
        _b64(arguments["classical_secret_key"]),
        _b64(arguments["pqc_secret_key"]),
    )


def handle_hybrid_auth_seal(arguments: dict[str, Any]) -> dict[str, Any]:
    pt_bytes = _resolve_plaintext(arguments)
    envelope = hybrid_auth_seal(
        pt_bytes,
        _b64(arguments["recipient_classical_public_key"]),
        _b64(arguments["recipient_pqc_public_key"]),
        _b64(arguments["sender_secret_key"]),
        _b64(arguments["sender_public_key"]),
    )
    return {"envelope": envelope}


def handle_hybrid_auth_open(arguments: dict[str, Any]) -> dict[str, Any]:
    expected_pk = (
        _b64(arguments["expected_sender_public_key"])
        if "expected_sender_public_key" in arguments
        else None
    )
    expected_fp = arguments.get("expected_sender_fingerprint")
    return hybrid_auth_open(
        arguments["envelope"],
        _b64(arguments["classical_secret_key"]),
        _b64(arguments["pqc_secret_key"]),
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
