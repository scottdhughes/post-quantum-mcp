"""Handlers for generic PQC tools (liboqs wrappers).

Each handler takes arguments dict, returns a result dict.
Error handling is done by the dispatch layer in __init__.py.
"""

import base64
import hashlib
import time
from typing import Any


import oqs
from oqs import MechanismNotSupportedError

from pqc_mcp_server.security_policy import get_policy


def _b64(value: str | bytes) -> bytes:
    """Strict base64 decode. Raises binascii.Error on invalid input."""
    return base64.b64decode(value, validate=True)


def _require_length(value: bytes, expected: int, label: str) -> None:
    if len(value) != expected:
        raise ValueError(f"{label} must be exactly {expected} bytes")


def _iterations(arguments: dict[str, Any]) -> int:
    value = arguments.get("iterations", 10)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("iterations must be a positive integer")
    return min(value, 100)


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
        "HQC": "Selected for standardization; not a final FIPS claim",
    }
    return result


def handle_algorithm_info(arguments: dict[str, Any]) -> dict[str, Any]:
    alg = arguments["algorithm"]

    try:
        with oqs.KeyEncapsulation(alg) as kem:
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
        with oqs.Signature(alg) as sig:
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

    store_name = get_policy().keygen_handle(arguments)

    try:
        with oqs.KeyEncapsulation(alg) as kem:
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
        with oqs.Signature(alg) as sig:
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
                    with oqs.KeyEncapsulation(stored_alg) as k1:
                        with oqs.KeyEncapsulation(requested_alg) as k2:
                            if k1.details["name"] != k2.details["name"]:
                                msg = (
                                    f"Algorithm mismatch: requested"
                                    f" '{requested_alg}' but key"
                                    f" '{name}' is '{stored_alg}'"
                                )
                                raise ValueError(msg)
                else:
                    with oqs.Signature(stored_alg) as s1:
                        with oqs.Signature(requested_alg) as s2:
                            if s1.details["name"] != s2.details["name"]:
                                msg = (
                                    f"Algorithm mismatch: requested"
                                    f" '{requested_alg}' but key"
                                    f" '{name}' is '{stored_alg}'"
                                )
                                raise ValueError(msg)
            except ValueError:
                raise
            except Exception:
                msg = (
                    f"Algorithm mismatch: requested"
                    f" '{requested_alg}' but key"
                    f" '{name}' is '{stored_alg}'"
                )
                raise ValueError(msg)

    return _b64(keys[key_field])


def handle_encapsulate(arguments: dict[str, Any]) -> dict[str, Any]:
    alg = arguments["algorithm"]
    resolved_pk = _resolve_flat_key(arguments, "public_key", "kem")
    public_key = resolved_pk if resolved_pk is not None else _b64(arguments["public_key"])
    with oqs.KeyEncapsulation(alg) as kem:
        _require_length(public_key, kem.details["length_public_key"], "public_key")
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
    get_policy().check_no_raw_secrets(arguments, ["secret_key"])
    resolved_sk = _resolve_flat_key(arguments, "secret_key", "kem")
    secret_key = resolved_sk if resolved_sk is not None else _b64(arguments["secret_key"])
    ciphertext = _b64(arguments["ciphertext"])
    with oqs.KeyEncapsulation(alg, secret_key) as kem:
        _require_length(secret_key, kem.details["length_secret_key"], "secret_key")
        _require_length(ciphertext, kem.details["length_ciphertext"], "ciphertext")
        shared_secret = kem.decap_secret(ciphertext)
        return {
            "algorithm": alg,
            "shared_secret": base64.b64encode(shared_secret).decode(),
            "shared_secret_hex": shared_secret.hex(),
        }


def handle_sign(arguments: dict[str, Any]) -> dict[str, Any]:
    alg = arguments["algorithm"]
    get_policy().check_no_raw_secrets(arguments, ["secret_key"])
    resolved_sk = _resolve_flat_key(arguments, "secret_key", "signature")
    secret_key = resolved_sk if resolved_sk is not None else _b64(arguments["secret_key"])
    message = arguments["message"].encode("utf-8")
    with oqs.Signature(alg, secret_key) as sig:
        _require_length(secret_key, sig.details["length_secret_key"], "secret_key")
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
    with oqs.Signature(alg) as sig:
        _require_length(public_key, sig.details["length_public_key"], "public_key")
        if len(signature) > sig.details["length_signature"]:
            raise ValueError("signature exceeds algorithm byte length")
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
        raise ValueError(f"Unsupported hash algorithm: {alg}")

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
        1: {"classical": "AES-128 key search", "bits": 128},
        2: {"classical": "SHA-256 collision search", "bits": 128},
        3: {"classical": "AES-192 key search", "bits": 192},
        4: {"classical": "SHA-384 collision search", "bits": 192},
        5: {"classical": "AES-256 key search", "bits": 256},
    }

    nist_level = None
    alg_type = None

    try:
        with oqs.KeyEncapsulation(alg) as kem:
            nist_level = kem.details.get("claimed_nist_level", 3)
            alg_type = "KEM"
    except MechanismNotSupportedError:
        try:
            with oqs.Signature(alg) as sig:
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
        "quantum_security": "Claimed NIST category; not a per-algorithm quantum cost estimate",
        "standardization_status": (
            "FIPS 203"
            if alg.startswith("ML-KEM-")
            else (
                "FIPS 204"
                if alg.startswith("ML-DSA-")
                else "FIPS 205" if alg.startswith("SLH-DSA-") else "Not established by this tool"
            )
        ),
        "security_bits": bits,
        "quantum_resistant": True,
        "grover_resistance": "Generic search speedups do not determine this algorithm's quantum security",
        "shor_resistance": "Resistant to Shor's algorithm (not based on factoring/DLP)",
        "recommendation": (
            "Use standardized parameter sets; claimed categories are not implementation certification"
        ),
    }


def handle_benchmark(arguments: dict[str, Any]) -> dict[str, Any]:
    """Benchmark a PQC algorithm: timed keygen, operations, and sizes."""
    alg = arguments["algorithm"]
    iterations = _iterations(arguments)
    test_message = b"Benchmark test message for PQC operations"

    # Try as KEM
    try:
        with oqs.KeyEncapsulation(alg) as kem:
            details = kem.details

            # Keygen timing
            t0 = time.perf_counter()
            for _ in range(iterations):
                with oqs.KeyEncapsulation(alg) as generated:
                    pk = generated.generate_keypair()
                    sk = generated.export_secret_key()
            keygen_ms = (time.perf_counter() - t0) / iterations * 1000

            # Encap timing
            t0 = time.perf_counter()
            for _ in range(iterations):
                ct, ss = kem.encap_secret(pk)
            encap_ms = (time.perf_counter() - t0) / iterations * 1000

            # Decap timing
            with oqs.KeyEncapsulation(alg, sk) as kem2:
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
    with oqs.Signature(alg) as sig:
        details = sig.details

        # Keygen timing
        t0 = time.perf_counter()
        for _ in range(iterations):
            with oqs.Signature(alg) as generated:
                pk = generated.generate_keypair()
                sk = generated.export_secret_key()
        keygen_ms = (time.perf_counter() - t0) / iterations * 1000

        # Sign timing
        with oqs.Signature(alg, sk) as sig2:
            t0 = time.perf_counter()
            for _ in range(iterations):
                signature = sig2.sign(test_message)
            sign_ms = (time.perf_counter() - t0) / iterations * 1000

            # Verify timing
            with oqs.Signature(alg) as sig3:
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


# Classical counterpart mapping for comparison tool
_CLASSICAL_COUNTERPARTS: dict[str, str] = {
    "ML-KEM-768": "X25519",
    "ML-KEM-512": "X25519",
    "ML-KEM-1024": "X25519",
    "ML-DSA-44": "Ed25519",
    "ML-DSA-65": "Ed25519",
    "ML-DSA-87": "Ed25519",
}


def _benchmark_classical(algorithm: str, iterations: int) -> dict[str, Any]:
    """Benchmark a classical algorithm (X25519 or Ed25519)."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    test_message = b"Benchmark test message for classical operations"

    if algorithm == "X25519":
        # Keygen
        t0 = time.perf_counter()
        for _ in range(iterations):
            x_sk = X25519PrivateKey.generate()
            x_sk.public_key()
        keygen_ms = (time.perf_counter() - t0) / iterations * 1000

        # Key exchange
        x_sk1 = X25519PrivateKey.generate()
        x_pk2 = X25519PrivateKey.generate().public_key()
        t0 = time.perf_counter()
        for _ in range(iterations):
            x_sk1.exchange(x_pk2)
        exchange_ms = (time.perf_counter() - t0) / iterations * 1000

        return {
            "algorithm": "X25519",
            "type": "Key Exchange",
            "iterations": iterations,
            "timing_ms": {"keygen": round(keygen_ms, 3), "exchange": round(exchange_ms, 3)},
            "sizes_bytes": {"public_key": 32, "secret_key": 32, "shared_secret": 32},
        }

    elif algorithm == "Ed25519":
        # Keygen
        t0 = time.perf_counter()
        for _ in range(iterations):
            ed_sk = Ed25519PrivateKey.generate()
            ed_sk.public_key()
        keygen_ms = (time.perf_counter() - t0) / iterations * 1000

        # Sign
        ed_sk = Ed25519PrivateKey.generate()
        t0 = time.perf_counter()
        for _ in range(iterations):
            ed_sig = ed_sk.sign(test_message)
        sign_ms = (time.perf_counter() - t0) / iterations * 1000

        # Verify
        ed_pk = ed_sk.public_key()
        t0 = time.perf_counter()
        for _ in range(iterations):
            ed_pk.verify(ed_sig, test_message)
        verify_ms = (time.perf_counter() - t0) / iterations * 1000

        return {
            "algorithm": "Ed25519",
            "type": "Signature",
            "iterations": iterations,
            "timing_ms": {
                "keygen": round(keygen_ms, 3),
                "sign": round(sign_ms, 3),
                "verify": round(verify_ms, 3),
            },
            "sizes_bytes": {"public_key": 32, "secret_key": 32, "signature": 64},
        }

    raise ValueError(f"Unknown classical algorithm: {algorithm}")


def handle_compare(arguments: dict[str, Any]) -> dict[str, Any]:
    """Compare a PQC algorithm against its classical counterpart."""
    alg = arguments["algorithm"]
    iterations = _iterations(arguments)

    classical_name = _CLASSICAL_COUNTERPARTS.get(alg)
    if not classical_name:
        supported = ", ".join(sorted(_CLASSICAL_COUNTERPARTS.keys()))
        raise ValueError(f"No classical counterpart for '{alg}'. Supported: {supported}")

    pqc_result = handle_benchmark({"algorithm": alg, "iterations": iterations})
    classical_result = _benchmark_classical(classical_name, iterations)

    # Compute ratios
    ratios: dict[str, str] = {}
    ratios["keygen"] = (
        f"{pqc_result['timing_ms']['keygen'] / max(classical_result['timing_ms']['keygen'], 0.001):.1f}x"
    )

    if pqc_result["type"] == "KEM":
        classical_op = classical_result["timing_ms"]["exchange"]
        pqc_op = pqc_result["timing_ms"]["encap"]
        ratios["encap_vs_exchange"] = f"{pqc_op / max(classical_op, 0.001):.1f}x"
        pk_ratio = (
            pqc_result["sizes_bytes"]["public_key"] / classical_result["sizes_bytes"]["public_key"]
        )
        ratios["public_key_size"] = f"{pk_ratio:.0f}x"
    else:
        classical_sign = classical_result["timing_ms"]["sign"]
        pqc_sign = pqc_result["timing_ms"]["sign"]
        ratios["sign"] = f"{pqc_sign / max(classical_sign, 0.001):.1f}x"
        classical_verify = classical_result["timing_ms"]["verify"]
        pqc_verify = pqc_result["timing_ms"]["verify"]
        ratios["verify"] = f"{pqc_verify / max(classical_verify, 0.001):.1f}x"
        sig_ratio = (
            pqc_result["sizes_bytes"]["signature"] / classical_result["sizes_bytes"]["signature"]
        )
        ratios["signature_size"] = f"{sig_ratio:.0f}x"

    return {
        "pqc": pqc_result,
        "classical": classical_result,
        "ratios": ratios,
        "summary": (
            f"{alg} vs {classical_name}: PQC keygen is {ratios['keygen']} slower. "
            f"PQC provides NIST Level {pqc_result.get('nist_level', '?')} quantum resistance."
        ),
    }
