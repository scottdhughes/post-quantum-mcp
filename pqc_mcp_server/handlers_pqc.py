"""Handlers for generic PQC tools (liboqs wrappers).

Each handler takes arguments dict, returns a result dict.
Error handling is done by the dispatch layer in __init__.py.
"""

import base64
import hashlib
import time
from typing import Any

import binascii

import oqs
from oqs import MechanismNotSupportedError


def _b64(value: str | bytes) -> bytes:
    """Strict base64 decode. Raises binascii.Error on invalid input."""
    return base64.b64decode(value, validate=True)


def handle_list_algorithms(arguments: dict[str, Any]) -> dict[str, Any]:
    filter_type = arguments.get("type", "all")
    result: dict[str, Any] = {
        "kem_algorithms": oqs.get_enabled_kem_mechanisms(),
        "sig_algorithms": oqs.get_enabled_sig_mechanisms(),
    }

    if filter_type == "kem":
        result = {"kem_algorithms": result["kem_algorithms"]}
    elif filter_type == "sig":
        result = {"sig_algorithms": result["sig_algorithms"]}

    result["nist_standards"] = {
        "ML-KEM": "FIPS 203 (formerly CRYSTALS-Kyber)",
        "ML-DSA": "FIPS 204 (formerly CRYSTALS-Dilithium)",
        "SLH-DSA": "FIPS 205 (formerly SPHINCS+)",
        "HQC": "Round 4 finalist, standardization in progress",
    }
    return result


def handle_algorithm_info(arguments: dict[str, Any]) -> dict[str, Any]:
    alg = arguments["algorithm"]

    try:
        kem = oqs.KeyEncapsulation(alg)
        return {
            "name": alg,
            "type": "KEM (Key Encapsulation Mechanism)",
            "public_key_size": kem.details["length_public_key"],
            "secret_key_size": kem.details["length_secret_key"],
            "ciphertext_size": kem.details["length_ciphertext"],
            "shared_secret_size": kem.details["length_shared_secret"],
            "nist_level": kem.details.get("claimed_nist_level", "Unknown"),
            "is_ind_cca": kem.details.get("is_ind_cca", True),
        }
    except MechanismNotSupportedError:
        pass

    try:
        sig = oqs.Signature(alg)
        return {
            "name": alg,
            "type": "Digital Signature",
            "public_key_size": sig.details["length_public_key"],
            "secret_key_size": sig.details["length_secret_key"],
            "signature_size": sig.details["length_signature"],
            "nist_level": sig.details.get("claimed_nist_level", "Unknown"),
            "is_euf_cma": sig.details.get("is_euf_cma", True),
        }
    except MechanismNotSupportedError:
        pass

    return {"error": f"Unknown algorithm: {alg}"}


def handle_generate_keypair(arguments: dict[str, Any]) -> dict[str, Any]:
    alg = arguments["algorithm"]

    try:
        kem = oqs.KeyEncapsulation(alg)
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
        result: dict[str, Any] = {
            "algorithm": alg,
            "type": "KEM",
            "public_key": base64.b64encode(public_key).decode(),
            "secret_key": base64.b64encode(secret_key).decode(),
            "public_key_size": len(public_key),
            "secret_key_size": len(secret_key),
        }
    except MechanismNotSupportedError:
        sig = oqs.Signature(alg)
        public_key = sig.generate_keypair()
        secret_key = sig.export_secret_key()
        result = {
            "algorithm": alg,
            "type": "Signature",
            "public_key": base64.b64encode(public_key).decode(),
            "secret_key": base64.b64encode(secret_key).decode(),
            "public_key_size": len(public_key),
            "secret_key_size": len(secret_key),
        }

    store_name = arguments.get("store_as")
    if store_name:
        from pqc_mcp_server.key_store import store_from_keygen

        overwrite = arguments.get("overwrite", False)
        store_from_keygen(store_name, result, overwrite=overwrite)
        fp = hashlib.sha3_256(_b64(result["public_key"])).hexdigest()
        return {
            "algorithm": result["algorithm"],
            "type": result["type"],
            "handle": store_name,
            "public_key": result["public_key"],
            "public_key_size": result["public_key_size"],
            "fingerprint": fp,
            "fingerprint_algorithm": "SHA3-256",
        }

    # Without store_as: warn about secret exposure, allow opt-out
    if not arguments.get("include_secret_key", True):
        result.pop("secret_key", None)
        result.pop("secret_key_size", None)
        result["secret_key_redacted"] = True
        result["hint"] = "Use store_as to store keys as opaque handles (recommended)"
    else:
        result["warning"] = (
            "Secret key is included in this response. Use store_as parameter "
            "to store keys as opaque handles and prevent secret exposure."
        )
    return result


def _resolve_flat_key(
    arguments: dict[str, Any],
    key_field: str,
    expected_type: str,
) -> bytes | None:
    """Resolve a flat key from store or return None (use raw args).
    Checks conflict, type, and algorithm match."""
    from pqc_mcp_server.key_store import (
        _resolve_from_store,
        _require_flat_signature,
        _require_flat_kem,
    )

    has_store = "key_store_name" in arguments
    has_raw = key_field in arguments
    if has_store and has_raw:
        raise ValueError("Provide either key_store_name or raw key parameters, not both")
    if not has_store and not has_raw:
        raise ValueError(f"Provide key_store_name or {key_field}")
    if not has_store:
        return None

    keys = _resolve_from_store(arguments["key_store_name"])
    name = arguments["key_store_name"]

    if expected_type == "signature":
        _require_flat_signature(keys, name)
    elif expected_type == "kem":
        _require_flat_kem(keys, name)

    # Algorithm mismatch check
    if "algorithm" in arguments:
        stored_alg = keys.get("algorithm", "")
        requested_alg = arguments["algorithm"]
        if stored_alg != requested_alg:
            # Try liboqs canonical comparison
            try:
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
            except ValueError:
                raise
            except Exception:
                raise ValueError(
                    f"Algorithm mismatch: requested '{requested_alg}' but key '{name}' is '{stored_alg}'"
                )

    return _b64(keys[key_field])


def handle_encapsulate(arguments: dict[str, Any]) -> dict[str, Any]:
    alg = arguments["algorithm"]
    resolved_pk = _resolve_flat_key(arguments, "public_key", "kem")
    public_key = resolved_pk if resolved_pk is not None else _b64(arguments["public_key"])
    kem = oqs.KeyEncapsulation(alg)
    ciphertext, shared_secret = kem.encap_secret(public_key)
    return {
        "algorithm": alg,
        "ciphertext": base64.b64encode(ciphertext).decode(),
        "shared_secret": base64.b64encode(shared_secret).decode(),
        "shared_secret_hex": shared_secret.hex(),
        "ciphertext_size": len(ciphertext),
    }


def handle_decapsulate(arguments: dict[str, Any]) -> dict[str, Any]:
    alg = arguments["algorithm"]
    resolved_sk = _resolve_flat_key(arguments, "secret_key", "kem")
    secret_key = resolved_sk if resolved_sk is not None else _b64(arguments["secret_key"])
    ciphertext = _b64(arguments["ciphertext"])
    kem = oqs.KeyEncapsulation(alg, secret_key)
    shared_secret = kem.decap_secret(ciphertext)
    return {
        "algorithm": alg,
        "shared_secret": base64.b64encode(shared_secret).decode(),
        "shared_secret_hex": shared_secret.hex(),
    }


def handle_sign(arguments: dict[str, Any]) -> dict[str, Any]:
    alg = arguments["algorithm"]
    resolved_sk = _resolve_flat_key(arguments, "secret_key", "signature")
    secret_key = resolved_sk if resolved_sk is not None else _b64(arguments["secret_key"])
    message = arguments["message"].encode("utf-8")
    sig = oqs.Signature(alg, secret_key)
    signature = sig.sign(message)
    return {
        "algorithm": alg,
        "message_hash": hashlib.sha3_256(message).hexdigest(),
        "signature": base64.b64encode(signature).decode(),
        "signature_size": len(signature),
    }


def handle_verify(arguments: dict[str, Any]) -> dict[str, Any]:
    alg = arguments["algorithm"]
    resolved_pk = _resolve_flat_key(arguments, "public_key", "signature")
    public_key = resolved_pk if resolved_pk is not None else _b64(arguments["public_key"])
    message = arguments["message"].encode("utf-8")
    signature = _b64(arguments["signature"])
    sig = oqs.Signature(alg)
    is_valid = sig.verify(message, signature, public_key)
    return {
        "algorithm": alg,
        "valid": is_valid,
        "message_hash": hashlib.sha3_256(message).hexdigest(),
    }


def handle_hash(arguments: dict[str, Any]) -> dict[str, Any]:
    message = arguments["message"].encode("utf-8")
    alg = arguments.get("algorithm", "SHA3-256")

    if alg == "SHA3-256":
        digest = hashlib.sha3_256(message).digest()
    elif alg == "SHA3-512":
        digest = hashlib.sha3_512(message).digest()
    elif alg == "SHAKE128":
        digest = hashlib.shake_128(message).digest(32)
    elif alg == "SHAKE256":
        digest = hashlib.shake_256(message).digest(64)
    else:
        digest = hashlib.sha3_256(message).digest()

    return {
        "algorithm": alg,
        "input": arguments["message"],
        "digest_hex": digest.hex(),
        "digest_base64": base64.b64encode(digest).decode(),
        "digest_size": len(digest),
    }


def handle_security_analysis(arguments: dict[str, Any]) -> dict[str, Any]:
    alg = arguments["algorithm"]

    security_levels = {
        1: {"classical": "AES-128", "quantum": "AES-64 equivalent", "bits": 128},
        2: {"classical": "SHA-256", "quantum": "AES-80 equivalent", "bits": 192},
        3: {"classical": "AES-192", "quantum": "AES-96 equivalent", "bits": 192},
        4: {"classical": "SHA-384", "quantum": "AES-112 equivalent", "bits": 256},
        5: {"classical": "AES-256", "quantum": "AES-128 equivalent", "bits": 256},
    }

    nist_level = None
    alg_type = None

    try:
        kem = oqs.KeyEncapsulation(alg)
        nist_level = kem.details.get("claimed_nist_level", 3)
        alg_type = "KEM"
    except MechanismNotSupportedError:
        try:
            sig = oqs.Signature(alg)
            nist_level = sig.details.get("claimed_nist_level", 3)
            alg_type = "Signature"
        except MechanismNotSupportedError:
            return {"error": f"Unknown algorithm: {alg}"}

    level_info = security_levels.get(nist_level, security_levels[3])
    bits: int = level_info["bits"]  # type: ignore[assignment]

    return {
        "algorithm": alg,
        "type": alg_type,
        "nist_security_level": nist_level,
        "classical_security": level_info["classical"],
        "quantum_security": level_info["quantum"],
        "security_bits": bits,
        "quantum_resistant": True,
        "grover_resistance": f"Grover's algorithm reduces security by ~50% to {bits // 2} bits",
        "shor_resistance": "Resistant to Shor's algorithm (not based on factoring/DLP)",
        "recommendation": (
            "NIST approved for post-quantum security" if nist_level else "Experimental"
        ),
    }


def handle_benchmark(arguments: dict[str, Any]) -> dict[str, Any]:
    """Benchmark a PQC algorithm: timed keygen, operations, and sizes."""
    alg = arguments["algorithm"]
    iterations = min(arguments.get("iterations", 10), 100)  # cap at 100
    test_message = b"Benchmark test message for PQC operations"

    # Try as KEM
    try:
        kem = oqs.KeyEncapsulation(alg)
        details = kem.details

        # Keygen timing
        t0 = time.perf_counter()
        for _ in range(iterations):
            pk = kem.generate_keypair()
            kem.export_secret_key()
        keygen_ms = (time.perf_counter() - t0) / iterations * 1000

        # Encap timing
        sk = kem.export_secret_key()
        t0 = time.perf_counter()
        for _ in range(iterations):
            ct, ss = kem.encap_secret(pk)
        encap_ms = (time.perf_counter() - t0) / iterations * 1000

        # Decap timing
        kem2 = oqs.KeyEncapsulation(alg, sk)
        t0 = time.perf_counter()
        for _ in range(iterations):
            kem2.decap_secret(ct)
        decap_ms = (time.perf_counter() - t0) / iterations * 1000

        return {
            "algorithm": alg,
            "type": "KEM",
            "iterations": iterations,
            "timing_ms": {
                "keygen": round(keygen_ms, 3),
                "encap": round(encap_ms, 3),
                "decap": round(decap_ms, 3),
            },
            "sizes_bytes": {
                "public_key": details["length_public_key"],
                "secret_key": details["length_secret_key"],
                "ciphertext": details["length_ciphertext"],
                "shared_secret": details["length_shared_secret"],
            },
            "nist_level": details.get("claimed_nist_level", "Unknown"),
        }
    except MechanismNotSupportedError:
        pass

    # Try as signature
    sig = oqs.Signature(alg)
    details = sig.details

    # Keygen timing
    t0 = time.perf_counter()
    for _ in range(iterations):
        pk = sig.generate_keypair()
        sig.export_secret_key()
    keygen_ms = (time.perf_counter() - t0) / iterations * 1000

    # Sign timing
    sk = sig.export_secret_key()
    sig2 = oqs.Signature(alg, sk)
    t0 = time.perf_counter()
    for _ in range(iterations):
        signature = sig2.sign(test_message)
    sign_ms = (time.perf_counter() - t0) / iterations * 1000

    # Verify timing
    sig3 = oqs.Signature(alg)
    t0 = time.perf_counter()
    for _ in range(iterations):
        sig3.verify(test_message, signature, pk)
    verify_ms = (time.perf_counter() - t0) / iterations * 1000

    return {
        "algorithm": alg,
        "type": "Signature",
        "iterations": iterations,
        "timing_ms": {
            "keygen": round(keygen_ms, 3),
            "sign": round(sign_ms, 3),
            "verify": round(verify_ms, 3),
        },
        "sizes_bytes": {
            "public_key": details["length_public_key"],
            "secret_key": details["length_secret_key"],
            "signature": details["length_signature"],
        },
        "nist_level": details.get("claimed_nist_level", "Unknown"),
    }
