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


def hybrid_keygen() -> dict[str, Any]:
    """Generate a hybrid X25519 + ML-KEM-768 keypair bundle."""
    x_sk = X25519PrivateKey.generate()
    x_pk = x_sk.public_key()

    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pqc_pk = kem.generate_keypair()
    pqc_sk = kem.export_secret_key()

    return {
        "suite": SUITE,
        "classical": {
            "algorithm": "X25519",
            "public_key": base64.b64encode(
                x_pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).decode(),
            "secret_key": base64.b64encode(
                x_sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            ).decode(),
        },
        "pqc": {
            "algorithm": "ML-KEM-768",
            "public_key": base64.b64encode(pqc_pk).decode(),
            "secret_key": base64.b64encode(pqc_sk).decode(),
        },
    }


def hybrid_encap(classical_pk: bytes, pqc_pk: bytes) -> dict[str, Any]:
    """Perform hybrid encapsulation. Returns combined shared secret + ciphertexts."""
    _validate_x25519_key(classical_pk, "classical_public_key")

    # X25519: generate ephemeral keypair and perform ECDH
    eph_sk = X25519PrivateKey.generate()
    eph_pk = eph_sk.public_key()
    eph_pk_bytes = eph_pk.public_bytes(Encoding.Raw, PublicFormat.Raw)

    recipient_x_pk = X25519PublicKey.from_public_bytes(classical_pk)
    ss_x25519 = eph_sk.exchange(recipient_x_pk)
    _check_x25519_shared_secret(ss_x25519)

    # ML-KEM-768: encapsulate
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pqc_ct, ss_mlkem = kem.encap_secret(pqc_pk)

    # Combine via SHA3-256
    combined_ss = _kem_combine(ss_mlkem, ss_x25519, eph_pk_bytes, classical_pk)

    return {
        "suite": SUITE,
        "shared_secret": base64.b64encode(combined_ss).decode(),
        "shared_secret_hex": combined_ss.hex(),
        "x25519_ephemeral_public_key": base64.b64encode(eph_pk_bytes).decode(),
        "pqc_ciphertext": base64.b64encode(pqc_ct).decode(),
    }


def hybrid_decap(
    classical_sk: bytes,
    pqc_sk: bytes,
    x25519_epk: bytes,
    pqc_ct: bytes,
) -> dict[str, Any]:
    """Recover the combined shared secret."""
    _validate_x25519_key(classical_sk, "classical_secret_key")
    _validate_x25519_key(x25519_epk, "x25519_ephemeral_public_key")

    # X25519: ECDH with ephemeral public key
    sk = X25519PrivateKey.from_private_bytes(classical_sk)
    peer_pk = X25519PublicKey.from_public_bytes(x25519_epk)
    ss_x25519 = sk.exchange(peer_pk)
    _check_x25519_shared_secret(ss_x25519)

    # Derive recipient's own public key for the combiner
    pk_x25519 = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # ML-KEM-768: decapsulate
    kem = oqs.KeyEncapsulation("ML-KEM-768", pqc_sk)
    ss_mlkem = kem.decap_secret(pqc_ct)

    # Combine via SHA3-256
    combined_ss = _kem_combine(ss_mlkem, ss_x25519, x25519_epk, pk_x25519)

    return {
        "suite": SUITE,
        "shared_secret": base64.b64encode(combined_ss).decode(),
        "shared_secret_hex": combined_ss.hex(),
    }


def hybrid_seal(
    plaintext_bytes: bytes,
    recipient_classical_pk: bytes,
    recipient_pqc_pk: bytes,
) -> dict[str, Any]:
    """Encrypt plaintext using hybrid encapsulation + AES-256-GCM.

    Anonymous sealed-box: anyone with recipient public keys can seal.
    Single-shot: one encapsulation, one AEAD encryption.
    """
    _validate_x25519_key(recipient_classical_pk, "recipient_classical_public_key")

    # Encapsulate (raw bytes, not base64)
    eph_sk = X25519PrivateKey.generate()
    eph_pk = eph_sk.public_key()
    eph_pk_bytes = eph_pk.public_bytes(Encoding.Raw, PublicFormat.Raw)

    recipient_x_pk = X25519PublicKey.from_public_bytes(recipient_classical_pk)
    ss_x25519 = eph_sk.exchange(recipient_x_pk)
    _check_x25519_shared_secret(ss_x25519)

    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pqc_ct, ss_mlkem = kem.encap_secret(recipient_pqc_pk)

    combined_ss = _kem_combine(ss_mlkem, ss_x25519, eph_pk_bytes, recipient_classical_pk)

    # Derive AEAD key + nonce
    aes_key, nonce = _derive_aead_key_and_nonce(combined_ss)

    # Encrypt with AAD
    aad = _build_aad(eph_pk_bytes, pqc_ct)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, aad)

    return {
        "version": "pqc-mcp-v1",
        "suite": SUITE,
        "x25519_ephemeral_public_key": base64.b64encode(eph_pk_bytes).decode(),
        "pqc_ciphertext": base64.b64encode(pqc_ct).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def hybrid_open(
    envelope: dict[str, Any],
    classical_sk: bytes,
    pqc_sk: bytes,
) -> dict[str, Any]:
    """Decrypt a sealed envelope."""
    # Validate transmitted header fields before any crypto
    if envelope.get("version") != "pqc-mcp-v1":
        raise ValueError(f"Unsupported envelope version: {envelope.get('version')}")
    if envelope.get("suite") != SUITE:
        raise ValueError(f"Unsupported envelope suite: {envelope.get('suite')}")

    _validate_x25519_key(classical_sk, "classical_secret_key")

    epk_bytes = base64.b64decode(envelope["x25519_ephemeral_public_key"], validate=True)
    pqc_ct = base64.b64decode(envelope["pqc_ciphertext"], validate=True)
    ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)

    _validate_x25519_key(epk_bytes, "x25519_ephemeral_public_key")

    # X25519 ECDH
    sk = X25519PrivateKey.from_private_bytes(classical_sk)
    peer_pk = X25519PublicKey.from_public_bytes(epk_bytes)
    ss_x25519 = sk.exchange(peer_pk)
    _check_x25519_shared_secret(ss_x25519)

    # Derive recipient's own public key for combiner
    pk_x25519 = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # ML-KEM-768 decapsulate
    kem = oqs.KeyEncapsulation("ML-KEM-768", pqc_sk)
    ss_mlkem = kem.decap_secret(pqc_ct)

    # Combine + derive AEAD key + nonce
    combined_ss = _kem_combine(ss_mlkem, ss_x25519, epk_bytes, pk_x25519)
    aes_key, nonce = _derive_aead_key_and_nonce(combined_ss)

    # Decrypt with AAD verification
    aad = _build_aad(epk_bytes, pqc_ct)
    aesgcm = AESGCM(aes_key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, aad)

    # Try UTF-8 decode
    try:
        plaintext_str = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        plaintext_str = None

    return {
        "suite": SUITE,
        "plaintext": plaintext_str,
        "plaintext_base64": base64.b64encode(plaintext_bytes).decode(),
    }
