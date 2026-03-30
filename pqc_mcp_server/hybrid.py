"""Hybrid X25519 + ML-KEM-768 key exchange.

Suite: mlkem768-x25519-sha3-256
Combiner: SHA3-256(ss_mlkem || ss_x25519 || epk_x25519 || pk_x25519 || label)
Borrows the KEM combiner from the LAMPS composite ML-KEM draft
(id-MLKEM768-X25519-SHA3-256). The sealed-envelope layer is this
project's own protocol built on top of that combiner.

Two envelope modes:
- Anonymous sealed-box (hybrid_seal/hybrid_open): anyone with recipient public
  keys can seal. No sender authentication.
- Sender-authenticated sealed-envelope (hybrid_auth_seal/hybrid_auth_open):
  sender signs a canonical transcript with ML-DSA-65 before encryption.
  Recipient must supply expected sender identity to verify.

Neither mode is forward-secret against later recipient key compromise.

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
DEFAULT_SIG_ALGORITHM = "ML-DSA-65"
_AUTH_TRANSCRIPT_PREFIX = b"pqc-mcp-auth-v1\x00"  # 16 bytes, null-terminated


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


class SenderVerificationError(Exception):
    """Raised when sender identity or signature verification fails."""


def _fingerprint_public_key(public_key_bytes: bytes) -> str:
    """SHA3-256 fingerprint of a public key, returned as lowercase hex."""
    return hashlib.sha3_256(public_key_bytes).hexdigest()


def _len_prefix(data: bytes) -> bytes:
    """4-byte big-endian length prefix + raw bytes."""
    return len(data).to_bytes(4, "big") + data


def _build_auth_transcript(
    version: bytes,
    suite: bytes,
    sig_algorithm: bytes,
    sender_pk: bytes,
    sender_fp: bytes,
    recipient_classical_fp: bytes,
    recipient_pqc_fp: bytes,
    epk_x25519: bytes,
    pqc_ciphertext: bytes,
    aead_ciphertext: bytes,
) -> bytes:
    """Build canonical binary transcript for authenticated envelope signature.

    Fixed domain prefix + length-prefixed fields. Deterministic and unambiguous.
    """
    return (
        _AUTH_TRANSCRIPT_PREFIX
        + _len_prefix(version)
        + _len_prefix(suite)
        + _len_prefix(sig_algorithm)
        + _len_prefix(sender_pk)
        + _len_prefix(sender_fp)
        + _len_prefix(recipient_classical_fp)
        + _len_prefix(recipient_pqc_fp)
        + _len_prefix(epk_x25519)
        + _len_prefix(pqc_ciphertext)
        + _len_prefix(aead_ciphertext)
    )


def hybrid_keygen() -> dict[str, Any]:
    """Generate a hybrid X25519 + ML-KEM-768 keypair bundle."""
    x_sk = X25519PrivateKey.generate()
    x_pk = x_sk.public_key()
    x_pk_bytes = x_pk.public_bytes(Encoding.Raw, PublicFormat.Raw)

    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pqc_pk = kem.generate_keypair()
    pqc_sk = kem.export_secret_key()

    return {
        "suite": SUITE,
        "classical": {
            "algorithm": "X25519",
            "public_key": base64.b64encode(x_pk_bytes).decode(),
            "secret_key": base64.b64encode(
                x_sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            ).decode(),
            "fingerprint": _fingerprint_public_key(x_pk_bytes),
        },
        "pqc": {
            "algorithm": "ML-KEM-768",
            "public_key": base64.b64encode(pqc_pk).decode(),
            "secret_key": base64.b64encode(pqc_sk).decode(),
            "fingerprint": _fingerprint_public_key(pqc_pk),
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


def hybrid_auth_seal(
    plaintext_bytes: bytes,
    recipient_classical_pk: bytes,
    recipient_pqc_pk: bytes,
    sender_sig_sk: bytes,
    sender_sig_pk: bytes,
    sender_sig_algorithm: str = DEFAULT_SIG_ALGORITHM,
) -> dict[str, Any]:
    """Encrypt + sign: sender-authenticated hybrid sealed envelope.

    Composes the existing anonymous seal, then signs a canonical transcript
    covering the entire envelope. The signature proves sender identity.
    Still not forward-secret against later recipient key compromise.
    """
    # Seal (anonymous confidentiality layer — reuse existing core)
    envelope = hybrid_seal(plaintext_bytes, recipient_classical_pk, recipient_pqc_pk)

    # Compute fingerprints
    sender_fp = _fingerprint_public_key(sender_sig_pk)
    recipient_classical_fp = _fingerprint_public_key(recipient_classical_pk)
    recipient_pqc_fp = _fingerprint_public_key(recipient_pqc_pk)

    epk_bytes = base64.b64decode(envelope["x25519_ephemeral_public_key"])
    pqc_ct_bytes = base64.b64decode(envelope["pqc_ciphertext"])
    aead_ct_bytes = base64.b64decode(envelope["ciphertext"])

    # Build canonical transcript
    transcript = _build_auth_transcript(
        version=envelope["version"].encode(),
        suite=envelope["suite"].encode(),
        sig_algorithm=sender_sig_algorithm.encode(),
        sender_pk=sender_sig_pk,
        sender_fp=sender_fp.encode(),
        recipient_classical_fp=recipient_classical_fp.encode(),
        recipient_pqc_fp=recipient_pqc_fp.encode(),
        epk_x25519=epk_bytes,
        pqc_ciphertext=pqc_ct_bytes,
        aead_ciphertext=aead_ct_bytes,
    )

    # Sign transcript with ML-DSA
    sig = oqs.Signature(sender_sig_algorithm, sender_sig_sk)
    signature = sig.sign(transcript)

    return {
        "version": envelope["version"],
        "suite": envelope["suite"],
        "sender_signature_algorithm": sender_sig_algorithm,
        "sender_public_key": base64.b64encode(sender_sig_pk).decode(),
        "sender_key_fingerprint": sender_fp,
        "recipient_classical_key_fingerprint": recipient_classical_fp,
        "recipient_pqc_key_fingerprint": recipient_pqc_fp,
        "x25519_ephemeral_public_key": envelope["x25519_ephemeral_public_key"],
        "pqc_ciphertext": envelope["pqc_ciphertext"],
        "ciphertext": envelope["ciphertext"],
        "signature": base64.b64encode(signature).decode(),
    }


def hybrid_auth_open(
    envelope: dict[str, Any],
    classical_sk: bytes,
    pqc_sk: bytes,
    expected_sender_public_key: bytes | None = None,
    expected_sender_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Verify sender + decrypt: authenticated hybrid envelope.

    Sender verification happens BEFORE decryption. If the signature is
    invalid, the AEAD layer is never reached.

    Exactly one of expected_sender_public_key or expected_sender_fingerprint
    must be provided. The recipient must NOT trust the envelope's embedded
    sender key by itself.
    """
    # Require exactly one sender binding
    if expected_sender_public_key is None and expected_sender_fingerprint is None:
        raise SenderVerificationError(
            "Must provide expected_sender_public_key or expected_sender_fingerprint"
        )
    if expected_sender_public_key is not None and expected_sender_fingerprint is not None:
        raise SenderVerificationError(
            "Provide exactly one of expected_sender_public_key or expected_sender_fingerprint, not both"
        )

    # Validate header fields
    if envelope.get("version") != "pqc-mcp-v1":
        raise ValueError(f"Unsupported envelope version: {envelope.get('version')}")
    if envelope.get("suite") != SUITE:
        raise ValueError(f"Unsupported envelope suite: {envelope.get('suite')}")
    sig_alg = envelope.get("sender_signature_algorithm", "")
    if sig_alg != DEFAULT_SIG_ALGORITHM:
        raise ValueError(f"Unsupported sender signature algorithm: {sig_alg}")

    # Decode sender public key from envelope
    sender_pk = base64.b64decode(envelope["sender_public_key"], validate=True)
    envelope_fp = envelope["sender_key_fingerprint"]

    # Verify embedded fingerprint is consistent with embedded public key
    recomputed_fp = _fingerprint_public_key(sender_pk)
    if recomputed_fp != envelope_fp:
        raise SenderVerificationError(
            "Envelope sender_key_fingerprint is inconsistent with sender_public_key"
        )

    # Verify sender binding BEFORE signature verification
    if expected_sender_public_key is not None:
        if sender_pk != expected_sender_public_key:
            raise SenderVerificationError("Sender public key does not match expected key")
    else:
        # expected_sender_fingerprint must be non-None here (enforced above)
        if envelope_fp != expected_sender_fingerprint:
            raise SenderVerificationError(
                "Sender key fingerprint does not match expected fingerprint"
            )

    # Decode envelope fields for transcript reconstruction
    epk_bytes = base64.b64decode(envelope["x25519_ephemeral_public_key"], validate=True)
    pqc_ct_bytes = base64.b64decode(envelope["pqc_ciphertext"], validate=True)
    aead_ct_bytes = base64.b64decode(envelope["ciphertext"], validate=True)
    signature = base64.b64decode(envelope["signature"], validate=True)

    # Reconstruct canonical transcript
    transcript = _build_auth_transcript(
        version=envelope["version"].encode(),
        suite=envelope["suite"].encode(),
        sig_algorithm=sig_alg.encode(),
        sender_pk=sender_pk,
        sender_fp=envelope_fp.encode(),
        recipient_classical_fp=envelope["recipient_classical_key_fingerprint"].encode(),
        recipient_pqc_fp=envelope["recipient_pqc_key_fingerprint"].encode(),
        epk_x25519=epk_bytes,
        pqc_ciphertext=pqc_ct_bytes,
        aead_ciphertext=aead_ct_bytes,
    )

    # Verify signature BEFORE decryption
    sig_verifier = oqs.Signature(sig_alg)
    is_valid = sig_verifier.verify(transcript, signature, sender_pk)
    if not is_valid:
        raise SenderVerificationError("Signature verification failed")

    # Signature valid — now decrypt via the existing anonymous open path
    # Build the inner anonymous envelope for hybrid_open
    inner_envelope = {
        "version": envelope["version"],
        "suite": envelope["suite"],
        "x25519_ephemeral_public_key": envelope["x25519_ephemeral_public_key"],
        "pqc_ciphertext": envelope["pqc_ciphertext"],
        "ciphertext": envelope["ciphertext"],
    }
    result = hybrid_open(inner_envelope, classical_sk, pqc_sk)

    result["sender_key_fingerprint"] = envelope_fp
    result["sender_signature_algorithm"] = sig_alg
    result["authenticated"] = True
    return result
