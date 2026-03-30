"""Hybrid X25519 + ML-KEM-768 key exchange.

Suite: mlkem768-x25519-sha3-256
Combiner: SHA3-256(ss_mlkem || ss_x25519 || epk_x25519 || pk_x25519 || label)
Borrows the KEM combiner from the LAMPS composite ML-KEM draft
(id-MLKEM768-X25519-SHA3-256). The sealed-envelope layer is this
project's own protocol built on top of that combiner.

This is an anonymous sealed-box construction providing hybrid confidentiality
with ciphertext integrity. It is NOT forward-secret against recipient key
compromise, and it is NOT authenticated (anyone with recipient public keys
can seal an envelope).

liboqs is research/prototyping software and is not recommended for production.
"""

import base64
import hashlib
import hmac
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import oqs

SUITE = "mlkem768-x25519-sha3-256"
COMBINER_LABEL = b"\x5c\x2e\x2f\x2f\x5e\x5c"  # \.//^\ — LAMPS id-MLKEM768-X25519-SHA3-256
_HKDF_INFO_PREFIX = b"pqc-mcp-v1|mlkem768-x25519-sha3-256|"


def _validate_x25519_key(key_bytes: bytes, label: str) -> None:
    if len(key_bytes) != 32:
        raise ValueError(f"{label} must be exactly 32 bytes, got {len(key_bytes)}")


def _check_x25519_shared_secret(ss: bytes) -> None:
    if ss == b"\x00" * 32:
        raise ValueError(
            "X25519 shared secret is all-zero (small-order public key input per RFC 7748)"
        )


def _kem_combine(
    ss_mlkem: bytes,
    ss_x25519: bytes,
    epk_x25519: bytes,
    pk_x25519: bytes,
) -> bytes:
    """SHA3-256 KEM combiner per LAMPS id-MLKEM768-X25519-SHA3-256.

    combined_ss = SHA3-256(ss_mlkem || ss_x25519 || epk_x25519 || pk_x25519 || label)
    """
    return hashlib.sha3_256(ss_mlkem + ss_x25519 + epk_x25519 + pk_x25519 + COMBINER_LABEL).digest()


def _derive_aead_key_and_nonce(combined_ss: bytes) -> tuple[bytes, bytes]:
    """HKDF Extract+Expand to derive AES-256-GCM key and deterministic nonce."""
    salt = b"\x00" * 32
    prk = hmac.new(key=salt, msg=combined_ss, digestmod=hashlib.sha256).digest()

    aes_key = HKDFExpand(
        algorithm=SHA256(), length=32, info=_HKDF_INFO_PREFIX + b"aes-256-gcm-key"
    ).derive(prk)

    nonce = HKDFExpand(
        algorithm=SHA256(), length=12, info=_HKDF_INFO_PREFIX + b"aes-256-gcm-nonce"
    ).derive(prk)

    return aes_key, nonce


def _build_aad(epk_x25519: bytes, pqc_ciphertext: bytes) -> bytes:
    """Canonical AAD: version|suite|epk|pqc_ct.

    Layout: b"pqc-mcp-v1" (10) + b"|mlkem768-x25519-sha3-256|" (26) + epk (32) + ct (variable)
    Total prefix before epk: 36 bytes.
    """
    return b"pqc-mcp-v1" + b"|mlkem768-x25519-sha3-256|" + epk_x25519 + pqc_ciphertext
