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
  sender encrypts first (anonymous seal), then signs a canonical transcript
  over the finished envelope with ML-DSA-65. Recipient verifies the signature
  before decrypting. Expected sender identity must be supplied.

Neither mode is forward-secret against later recipient key compromise.

liboqs is research/prototyping software and is not recommended for production.
"""

import base64
import hashlib
import hmac
import time
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
ENVELOPE_VERSION = "pqc-mcp-v3"
_ENVELOPE_VERSION_V2 = "pqc-mcp-v2"
_ENVELOPE_VERSION_V1 = "pqc-mcp-v1"
_MODE_ANON_SEAL = "anon-seal"
_MODE_AUTH_SEAL = "auth-seal"
_HKDF_INFO_PREFIX_V3 = b"pqc-mcp-v3|mlkem768-x25519-sha3-256|"
_HKDF_INFO_PREFIX_V2 = b"pqc-mcp-v2|mlkem768-x25519-sha3-256|"
_HKDF_INFO_PREFIX_V1 = b"pqc-mcp-v1|mlkem768-x25519-sha3-256|"
DEFAULT_SIG_ALGORITHM = "ML-DSA-65"
_AUTH_TRANSCRIPT_PREFIX_V3 = b"pqc-mcp-auth-v3\x00"
_AUTH_TRANSCRIPT_PREFIX_V2 = b"pqc-mcp-auth-v2\x00"
_ACCEPTED_VERSIONS = {ENVELOPE_VERSION, _ENVELOPE_VERSION_V2, _ENVELOPE_VERSION_V1}
_LEGACY_VERSIONS = {_ENVELOPE_VERSION_V2, _ENVELOPE_VERSION_V1}


_MLKEM768_PK_SIZE = 1184
_MLKEM768_SK_SIZE = 2400
_MLKEM768_CT_SIZE = 1088
_MLDSA65_PK_SIZE = 1952
_MLDSA65_SK_SIZE = 4032
_GCM_TAG_SIZE = 16


def _validate_x25519_key(key_bytes: bytes, label: str) -> None:
    if len(key_bytes) != 32:
        raise ValueError(f"{label} must be exactly 32 bytes, got {len(key_bytes)}")


def _validate_mlkem768_ct(ct_bytes: bytes, label: str = "pqc_ciphertext") -> None:
    """Validate ML-KEM-768 ciphertext size before decapsulation."""
    if len(ct_bytes) != _MLKEM768_CT_SIZE:
        raise ValueError(
            f"{label} must be exactly {_MLKEM768_CT_SIZE} bytes for ML-KEM-768, "
            f"got {len(ct_bytes)}"
        )


def _validate_mlkem768_sk(sk_bytes: bytes, label: str = "pqc_secret_key") -> None:
    """Validate ML-KEM-768 secret key size before decapsulation."""
    if len(sk_bytes) != _MLKEM768_SK_SIZE:
        raise ValueError(
            f"{label} must be exactly {_MLKEM768_SK_SIZE} bytes for ML-KEM-768, "
            f"got {len(sk_bytes)}"
        )


def _validate_gcm_ciphertext(ct_bytes: bytes, label: str = "ciphertext") -> None:
    """Validate GCM ciphertext has at least a tag (16 bytes)."""
    if len(ct_bytes) < _GCM_TAG_SIZE:
        raise ValueError(
            f"{label} must be at least {_GCM_TAG_SIZE} bytes (GCM tag), "
            f"got {len(ct_bytes)}"
        )


def _validate_mldsa65_key(sk: bytes, pk: bytes) -> None:
    """Validate ML-DSA-65 key sizes. Prevents key type confusion with liboqs."""
    if len(sk) != _MLDSA65_SK_SIZE:
        raise ValueError(
            f"ML-DSA-65 secret key must be {_MLDSA65_SK_SIZE} bytes, got {len(sk)}. "
            "Wrong key type? Ensure you are using a signing key, not an encryption key."
        )
    if len(pk) != _MLDSA65_PK_SIZE:
        raise ValueError(
            f"ML-DSA-65 public key must be {_MLDSA65_PK_SIZE} bytes, got {len(pk)}. "
            "Wrong key type? Ensure you are using a signing key, not an encryption key."
        )


def _validate_mlkem768_pk(key_bytes: bytes, label: str) -> None:
    if len(key_bytes) != _MLKEM768_PK_SIZE:
        raise ValueError(
            f"{label} must be exactly {_MLKEM768_PK_SIZE} bytes for ML-KEM-768, "
            f"got {len(key_bytes)}"
        )


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

    SECURITY NOTE (Combiner Input Boundary): Inputs are concatenated without
    length prefixes per the LAMPS spec. This is safe because all inputs are
    fixed-size (ML-KEM-768 ss=32B, X25519 ss=32B, epk=32B, pk=32B, label=6B).
    If a future algorithm produced variable-length shared secrets, this combiner
    would need length-prefixed inputs to prevent boundary ambiguity collisions.
    """
    return hashlib.sha3_256(ss_mlkem + ss_x25519 + epk_x25519 + pk_x25519 + COMBINER_LABEL).digest()


def _derive_aead_key_and_nonce(
    combined_ss: bytes,
    epk_bytes: bytes = b"",
    version: str = "",
    mode: str = "",
) -> tuple[bytes, bytes]:
    """HKDF Extract+Expand to derive AES-256-GCM key and deterministic nonce.

    v3: mode is bound into HKDF info for cross-mode separation. epk_bytes
    is included for domain separation (defense-in-depth, NIST SP 800-56C).
    v2: epk domain separation only (no mode binding).
    v1: original derivation (no epk, no mode).
    """
    salt = b"\x00" * 32
    prk = hmac.new(key=salt, msg=combined_ss, digestmod=hashlib.sha256).digest()

    ver = version or ENVELOPE_VERSION
    if ver == _ENVELOPE_VERSION_V1:
        prefix = _HKDF_INFO_PREFIX_V1
        epk_domain = b""
    elif ver == _ENVELOPE_VERSION_V2:
        prefix = _HKDF_INFO_PREFIX_V2
        epk_domain = hashlib.sha256(epk_bytes).digest() if epk_bytes else b""
    else:
        # v3+: mode-bound derivation
        mode_label = (mode or _MODE_ANON_SEAL).encode()
        prefix = _HKDF_INFO_PREFIX_V3 + mode_label + b"|"
        epk_domain = hashlib.sha256(epk_bytes).digest() if epk_bytes else b""

    aes_key = HKDFExpand(
        algorithm=SHA256(),
        length=32,
        info=prefix + b"aes-256-gcm-key" + epk_domain,
    ).derive(prk)

    nonce = HKDFExpand(
        algorithm=SHA256(),
        length=12,
        info=prefix + b"aes-256-gcm-nonce" + epk_domain,
    ).derive(prk)

    return aes_key, nonce


def _lp(data: bytes) -> bytes:
    """4-byte big-endian length prefix + raw bytes."""
    return len(data).to_bytes(4, "big") + data


def _build_aad(
    epk_x25519: bytes,
    pqc_ciphertext: bytes,
    version: str = "",
    mode: str = "",
) -> bytes:
    """Canonical AAD binding version, suite, and ciphertext components.

    v3: length-prefixed framing with mode binding (self-delimiting).
    v1/v2: legacy concatenation (fragile but backwards-compatible).
    """
    ver = version or ENVELOPE_VERSION
    if ver in _LEGACY_VERSIONS:
        return ver.encode() + b"|" + SUITE.encode() + b"|" + epk_x25519 + pqc_ciphertext
    # v3+: length-prefixed, mode-bound AAD
    mode_label = mode or _MODE_ANON_SEAL
    return (
        _lp(ver.encode())
        + _lp(SUITE.encode())
        + _lp(mode_label.encode())
        + _lp(epk_x25519)
        + _lp(pqc_ciphertext)
    )


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
    timestamp: bytes = b"",
    mode: bytes = b"",
) -> bytes:
    """Build canonical binary transcript for authenticated envelope signature.

    Fixed domain prefix + length-prefixed fields. Deterministic and unambiguous.
    v3: mode is explicitly bound into the signed transcript, ensuring the
    signature covers the mode label (defense-in-depth alongside AEAD separation).
    v3 uses _AUTH_TRANSCRIPT_PREFIX_V3; v1/v2 use _AUTH_TRANSCRIPT_PREFIX_V2.
    """
    ver_str = version.decode() if isinstance(version, bytes) else version
    is_v3 = ver_str == ENVELOPE_VERSION
    prefix = _AUTH_TRANSCRIPT_PREFIX_V3 if is_v3 else _AUTH_TRANSCRIPT_PREFIX_V2
    transcript = (
        prefix
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
    if timestamp:
        transcript += _len_prefix(timestamp)
    if mode:
        transcript += _len_prefix(mode)
    return transcript


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
    _validate_mlkem768_pk(pqc_pk, "pqc_public_key")

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
    if len(pqc_ct) != _MLKEM768_CT_SIZE:
        raise RuntimeError(f"Unexpected ML-KEM-768 ciphertext length: {len(pqc_ct)}")

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
    _validate_mlkem768_ct(pqc_ct, "pqc_ciphertext")
    _validate_mlkem768_sk(pqc_sk, "pqc_secret_key")

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


def _core_encrypt(
    plaintext_bytes: bytes,
    recipient_classical_pk: bytes,
    recipient_pqc_pk: bytes,
    mode: str,
) -> dict[str, Any]:
    """Core hybrid encryption. Mode is bound into HKDF and AAD.

    Both hybrid_seal (anon-seal) and hybrid_auth_seal (auth-seal) use this
    core, ensuring the AEAD ciphertext is cryptographically bound to the mode.
    An auth-seal ciphertext cannot be opened as anon-seal and vice versa.
    """
    _validate_x25519_key(recipient_classical_pk, "recipient_classical_public_key")
    _validate_mlkem768_pk(recipient_pqc_pk, "recipient_pqc_public_key")

    # Encapsulate (raw bytes, not base64)
    eph_sk = X25519PrivateKey.generate()
    eph_pk = eph_sk.public_key()
    eph_pk_bytes = eph_pk.public_bytes(Encoding.Raw, PublicFormat.Raw)

    recipient_x_pk = X25519PublicKey.from_public_bytes(recipient_classical_pk)
    ss_x25519 = eph_sk.exchange(recipient_x_pk)
    _check_x25519_shared_secret(ss_x25519)

    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pqc_ct, ss_mlkem = kem.encap_secret(recipient_pqc_pk)
    if len(pqc_ct) != _MLKEM768_CT_SIZE:
        raise RuntimeError(f"Unexpected ML-KEM-768 ciphertext length: {len(pqc_ct)}")

    combined_ss = _kem_combine(ss_mlkem, ss_x25519, eph_pk_bytes, recipient_classical_pk)

    # Derive AEAD key + nonce (v3: mode-bound, epk domain separation)
    aes_key, nonce = _derive_aead_key_and_nonce(
        combined_ss, eph_pk_bytes, mode=mode
    )

    # Encrypt with AAD (v3: length-prefixed, mode-bound)
    aad = _build_aad(eph_pk_bytes, pqc_ct, mode=mode)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, aad)

    return {
        "version": ENVELOPE_VERSION,
        "mode": mode,
        "suite": SUITE,
        "x25519_ephemeral_public_key": base64.b64encode(eph_pk_bytes).decode(),
        "pqc_ciphertext": base64.b64encode(pqc_ct).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def hybrid_seal(
    plaintext_bytes: bytes,
    recipient_classical_pk: bytes,
    recipient_pqc_pk: bytes,
) -> dict[str, Any]:
    """Encrypt plaintext as anonymous sealed-box (mode=anon-seal)."""
    return _core_encrypt(plaintext_bytes, recipient_classical_pk, recipient_pqc_pk, _MODE_ANON_SEAL)


def hybrid_open(
    envelope: dict[str, Any],
    classical_sk: bytes,
    pqc_sk: bytes,
    _internal: bool = False,
) -> dict[str, Any]:
    """Decrypt a sealed envelope."""
    # Validate envelope size before any processing
    _validate_envelope_size(envelope)
    if not _internal:
        _validate_v3_schema(envelope)
        # Public API: reject auth-seal envelopes (must use hybrid_auth_open)
        env_mode = envelope.get("mode", "")
        if (
            envelope.get("version") == ENVELOPE_VERSION
            and env_mode == _MODE_AUTH_SEAL
        ):
            raise ValueError(
                "auth-seal envelopes must be opened with hybrid_auth_open, "
                "not hybrid_open"
            )

    # Validate transmitted header fields before any crypto
    if envelope.get("version") not in _ACCEPTED_VERSIONS:
        raise ValueError(f"Unsupported envelope version: {envelope.get('version')}")
    if envelope.get("suite") != SUITE:
        raise ValueError(f"Unsupported envelope suite: {envelope.get('suite')}")

    _validate_x25519_key(classical_sk, "classical_secret_key")

    epk_bytes = base64.b64decode(envelope["x25519_ephemeral_public_key"], validate=True)
    pqc_ct = base64.b64decode(envelope["pqc_ciphertext"], validate=True)
    ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)

    _validate_x25519_key(epk_bytes, "x25519_ephemeral_public_key")
    _validate_mlkem768_ct(pqc_ct, "pqc_ciphertext")
    _validate_mlkem768_sk(pqc_sk, "pqc_secret_key")
    _validate_gcm_ciphertext(ciphertext)

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

    # Combine + derive AEAD key + nonce (version-aware for backwards compat)
    env_version = envelope["version"]
    env_mode = envelope.get("mode", "")

    # v3 public API: enforce mode = anon-seal. Auth envelopes must go
    # through hybrid_auth_open which calls _core_decrypt with auth-seal.
    if env_version == ENVELOPE_VERSION and env_mode not in (_MODE_ANON_SEAL, _MODE_AUTH_SEAL):
        raise ValueError(
            f"Unknown mode '{env_mode}' for v3 envelope. "
            f"Expected '{_MODE_ANON_SEAL}' or '{_MODE_AUTH_SEAL}'."
        )

    combined_ss = _kem_combine(ss_mlkem, ss_x25519, epk_bytes, pk_x25519)
    aes_key, nonce = _derive_aead_key_and_nonce(
        combined_ss, epk_bytes, version=env_version, mode=env_mode
    )

    # Decrypt with AAD verification
    aad = _build_aad(epk_bytes, pqc_ct, version=env_version, mode=env_mode)
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
    # Validate signing key sizes (prevents key type confusion — liboqs
    # silently accepts wrong-size keys, producing garbage signatures)
    _validate_mldsa65_key(sender_sig_sk, sender_sig_pk)

    # Seal with auth-seal mode — ciphertext is cryptographically bound to auth mode.
    # This prevents auth-stripping: an attacker cannot strip the signature and
    # open the ciphertext as anon-seal because the HKDF/AAD use different mode labels.
    envelope = _core_encrypt(
        plaintext_bytes, recipient_classical_pk, recipient_pqc_pk, _MODE_AUTH_SEAL
    )

    # Timestamp for replay protection (signed as part of transcript)
    timestamp = str(int(time.time()))

    # Compute fingerprints
    sender_fp = _fingerprint_public_key(sender_sig_pk)
    recipient_classical_fp = _fingerprint_public_key(recipient_classical_pk)
    recipient_pqc_fp = _fingerprint_public_key(recipient_pqc_pk)

    epk_bytes = base64.b64decode(envelope["x25519_ephemeral_public_key"])
    pqc_ct_bytes = base64.b64decode(envelope["pqc_ciphertext"])
    aead_ct_bytes = base64.b64decode(envelope["ciphertext"])

    # Build canonical transcript (timestamp included — bound to signature)
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
        timestamp=timestamp.encode(),
        mode=_MODE_AUTH_SEAL.encode(),
    )

    # Sign transcript with ML-DSA
    sig = oqs.Signature(sender_sig_algorithm, sender_sig_sk)
    signature = sig.sign(transcript)

    return {
        "version": envelope["version"],
        "mode": _MODE_AUTH_SEAL,
        "suite": envelope["suite"],
        "sender_signature_algorithm": sender_sig_algorithm,
        "sender_public_key": base64.b64encode(sender_sig_pk).decode(),
        "sender_key_fingerprint": sender_fp,
        "recipient_classical_key_fingerprint": recipient_classical_fp,
        "recipient_pqc_key_fingerprint": recipient_pqc_fp,
        "x25519_ephemeral_public_key": envelope["x25519_ephemeral_public_key"],
        "pqc_ciphertext": envelope["pqc_ciphertext"],
        "ciphertext": envelope["ciphertext"],
        "timestamp": timestamp,
        "signature": base64.b64encode(signature).decode(),
    }


# Default max envelope age for replay protection (24 hours)
_MAX_ENVELOPE_AGE_SECONDS = 24 * 60 * 60

# Envelope field size limits (prevent resource exhaustion / memory bombs)
_MAX_B64_FIELD_SIZE = 1_000_000  # 1MB base64 = ~750KB decoded
_MAX_ENVELOPE_FIELDS = 50  # prevent field-count DoS

_SIZE_LIMITED_FIELDS = (
    "ciphertext", "pqc_ciphertext", "signature",
    "sender_public_key", "x25519_ephemeral_public_key",
)


_V3_ANON_REQUIRED = {
    "version", "mode", "suite",
    "x25519_ephemeral_public_key", "pqc_ciphertext", "ciphertext",
}
_V3_AUTH_REQUIRED = _V3_ANON_REQUIRED | {
    "sender_signature_algorithm", "sender_public_key",
    "sender_key_fingerprint", "recipient_classical_key_fingerprint",
    "recipient_pqc_key_fingerprint", "timestamp", "signature",
}
_V3_AUTH_ONLY_FIELDS = _V3_AUTH_REQUIRED - _V3_ANON_REQUIRED


def _validate_envelope_size(envelope: dict[str, Any]) -> None:
    """Reject oversized or pathological envelopes before any crypto processing.

    Prevents: memory bombs via huge base64 fields, field-count DoS,
    and resource exhaustion during base64 decoding.
    """
    if len(envelope) > _MAX_ENVELOPE_FIELDS:
        raise ValueError(
            f"Envelope has {len(envelope)} fields (max {_MAX_ENVELOPE_FIELDS})"
        )
    for field in _SIZE_LIMITED_FIELDS:
        val = envelope.get(field, "")
        if isinstance(val, str) and len(val) > _MAX_B64_FIELD_SIZE:
            raise ValueError(
                f"Envelope field '{field}' is {len(val)} chars (max {_MAX_B64_FIELD_SIZE})"
            )


def _validate_v3_schema(envelope: dict[str, Any]) -> None:
    """Strict schema validation for v3 envelopes by mode.

    anon-seal: must not contain auth-only fields (signature, sender, timestamp)
    auth-seal: must contain all auth fields
    """
    if envelope.get("version") not in (ENVELOPE_VERSION,):
        return  # only enforce strict schema for v3

    mode = envelope.get("mode", "")
    if mode == _MODE_ANON_SEAL:
        # Reject auth-only fields in anon envelopes
        unexpected = _V3_AUTH_ONLY_FIELDS & envelope.keys()
        if unexpected:
            raise ValueError(
                f"anon-seal envelope contains auth-only fields: "
                f"{', '.join(sorted(unexpected))}"
            )
    elif mode == _MODE_AUTH_SEAL:
        # Require all auth fields
        missing = _V3_AUTH_REQUIRED - envelope.keys()
        if missing:
            raise ValueError(
                f"auth-seal envelope missing required fields: "
                f"{', '.join(sorted(missing))}"
            )
    else:
        raise ValueError(f"Unknown v3 mode: '{mode}'")


def _verify_authenticated_envelope(
    envelope: dict[str, Any],
    expected_sender_public_key: bytes | None = None,
    expected_sender_fingerprint: str | None = None,
    max_age_seconds: int = _MAX_ENVELOPE_AGE_SECONDS,
) -> dict[str, Any]:
    """Shared verification logic for authenticated envelopes.

    Performs: sender binding, header validation, field-presence checks,
    fingerprint consistency, ML-DSA-65 signature verification, and
    timestamp freshness. Returns verification metadata dict.

    Used by both hybrid_auth_open (verify then decrypt) and
    hybrid_auth_verify (verify only, no secret keys needed).
    """
    # Validate envelope size before any processing (prevents resource exhaustion)
    _validate_envelope_size(envelope)
    # Note: v3 schema validation is NOT applied here — we want signature
    # verification to catch mode tampering, not a pre-check. Schema
    # validation runs at the handler/public API level instead.

    # Require exactly one sender binding
    if expected_sender_public_key is None and expected_sender_fingerprint is None:
        raise SenderVerificationError(
            "Must provide expected_sender_public_key or expected_sender_fingerprint"
        )
    if expected_sender_public_key is not None and expected_sender_fingerprint is not None:
        raise SenderVerificationError(
            "Provide exactly one of expected_sender_public_key"
            " or expected_sender_fingerprint, not both"
        )

    # Validate header fields
    if envelope.get("version") not in _ACCEPTED_VERSIONS:
        raise ValueError(f"Unsupported envelope version: {envelope.get('version')}")
    if envelope.get("suite") != SUITE:
        raise ValueError(f"Unsupported envelope suite: {envelope.get('suite')}")

    # LEGACY WARNING: v1 authenticated envelopes skip timestamp freshness,
    # making them replayable indefinitely. This is accepted for backwards
    # compatibility but should trigger a visible warning to the caller.
    is_v1 = envelope.get("version") == _ENVELOPE_VERSION_V1
    v1_warning = None
    if is_v1:
        v1_warning = (
            "WARNING: This is a v1 envelope without signed timestamps. "
            "It has no freshness protection and can be replayed indefinitely. "
            "Upgrade to pqc-mcp-v2 envelopes for replay protection."
        )
    sig_alg = envelope.get("sender_signature_algorithm", "")
    if not sig_alg:
        raise ValueError("Envelope is not authenticated (no sender_signature_algorithm)")
    if sig_alg != DEFAULT_SIG_ALGORITHM:
        raise ValueError(f"Unsupported sender signature algorithm: {sig_alg}")

    # Verify required auth fields exist before accessing them
    for field in (
        "sender_public_key",
        "sender_key_fingerprint",
        "signature",
        "recipient_classical_key_fingerprint",
        "recipient_pqc_key_fingerprint",
    ):
        if field not in envelope:
            raise ValueError(f"Missing required authenticated envelope field: {field}")

    # Decode sender public key from envelope
    sender_pk = base64.b64decode(envelope["sender_public_key"], validate=True)
    envelope_fp = envelope["sender_key_fingerprint"]

    # Verify embedded fingerprint is consistent with embedded public key
    recomputed_fp = _fingerprint_public_key(sender_pk)
    if recomputed_fp != envelope_fp:
        raise SenderVerificationError(
            "Envelope sender_key_fingerprint is inconsistent with sender_public_key"
        )

    # Verify sender binding BEFORE signature verification.
    # SECURITY NOTE (Timing Oracle): This check is faster than signature
    # verification, creating a distinguishable timing difference. An attacker
    # can determine if a fingerprint is correct by measuring response time.
    # This reveals contact membership (metadata) but not key material.
    # Acceptable for research; production should use uniform error timing.
    if expected_sender_public_key is not None:
        if sender_pk != expected_sender_public_key:
            raise SenderVerificationError("Sender public key does not match expected key")
    else:
        if envelope_fp != expected_sender_fingerprint:
            raise SenderVerificationError(
                "Sender key fingerprint does not match expected fingerprint"
            )

    # Decode envelope fields for transcript reconstruction
    epk_bytes = base64.b64decode(envelope["x25519_ephemeral_public_key"], validate=True)
    pqc_ct_bytes = base64.b64decode(envelope["pqc_ciphertext"], validate=True)
    aead_ct_bytes = base64.b64decode(envelope["ciphertext"], validate=True)
    signature = base64.b64decode(envelope["signature"], validate=True)

    # Extract timestamp for replay protection
    # SECURITY: v2 envelopes MUST have a timestamp. A malicious sender could
    # otherwise omit it to create eternally-replayable envelopes (Ghost
    # Timestamp Replay — Codex adversarial finding). v1 envelopes are exempt.
    envelope_timestamp = envelope.get("timestamp", "")
    is_v2 = envelope.get("version") == ENVELOPE_VERSION
    if is_v2 and not envelope_timestamp:
        raise ValueError(
            "v2 envelopes must include a timestamp for replay protection. "
            "Missing timestamp may indicate a forged or downgraded envelope."
        )
    # NOTE: v1 envelopes skip timestamp requirement (backwards compat).
    # A sender could deliberately use v1 to avoid freshness checks.
    # Mitigation: deprecate v1 acceptance in a future version.
    timestamp_bytes = str(envelope_timestamp).encode() if envelope_timestamp else b""

    # Reconstruct canonical transcript (mode + timestamp for v3)
    env_mode = envelope.get("mode", "")
    mode_bytes = env_mode.encode() if env_mode else b""
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
        timestamp=timestamp_bytes,
        mode=mode_bytes,
    )

    # Verify signature
    sig_verifier = oqs.Signature(sig_alg)
    is_valid = sig_verifier.verify(transcript, signature, sender_pk)
    if not is_valid:
        raise SenderVerificationError("Signature verification failed")

    # Replay protection: check timestamp freshness AFTER signature verification
    # (timestamp is now trustworthy because it's covered by the signature)
    if envelope_timestamp and max_age_seconds > 0:
        try:
            age = time.time() - int(envelope_timestamp)
            if age > max_age_seconds:
                raise ValueError(
                    f"Envelope is stale ({int(age)}s old, max {max_age_seconds}s). "
                    "Possible replay attack."
                )
            if age < -300:  # 5 min clock skew tolerance
                raise ValueError("Envelope timestamp is in the future. Clock skew or tampering.")
        except (TypeError, ValueError, OverflowError) as exc:
            raise ValueError(f"Invalid envelope timestamp: {exc}") from exc

    result = {
        "sender_key_fingerprint": envelope_fp,
        "sender_signature_algorithm": sig_alg,
        "recipient_classical_key_fingerprint": envelope["recipient_classical_key_fingerprint"],
        "recipient_pqc_key_fingerprint": envelope["recipient_pqc_key_fingerprint"],
        "version": envelope["version"],
        "suite": envelope["suite"],
        "timestamp": envelope_timestamp or None,
    }
    if v1_warning:
        result["warning"] = v1_warning
    return result


def hybrid_auth_open(
    envelope: dict[str, Any],
    classical_sk: bytes,
    pqc_sk: bytes,
    expected_sender_public_key: bytes | None = None,
    expected_sender_fingerprint: str | None = None,
    max_age_seconds: int = _MAX_ENVELOPE_AGE_SECONDS,
) -> dict[str, Any]:
    """Verify sender + decrypt: authenticated hybrid envelope.

    Sender verification happens BEFORE decryption. If the signature is
    invalid, the AEAD layer is never reached.
    """
    verified = _verify_authenticated_envelope(
        envelope,
        expected_sender_public_key,
        expected_sender_fingerprint,
        max_age_seconds,
    )

    # v3: enforce mode = auth-seal
    env_version = envelope.get("version", "")
    if env_version == ENVELOPE_VERSION:
        env_mode = envelope.get("mode", "")
        if env_mode != _MODE_AUTH_SEAL:
            raise ValueError(
                f"hybrid_auth_open requires mode='{_MODE_AUTH_SEAL}' for v3 envelopes, "
                f"got '{env_mode}'"
            )

    # Signature valid — now decrypt. Auth envelopes use auth-seal mode for
    # AEAD derivation, preventing auth-stripping downgrade attacks.
    inner_envelope = {
        "version": envelope["version"],
        "mode": envelope.get("mode", ""),  # preserve original mode for AEAD
        "suite": envelope["suite"],
        "x25519_ephemeral_public_key": envelope["x25519_ephemeral_public_key"],
        "pqc_ciphertext": envelope["pqc_ciphertext"],
        "ciphertext": envelope["ciphertext"],
    }
    result = hybrid_open(inner_envelope, classical_sk, pqc_sk, _internal=True)

    result["sender_key_fingerprint"] = verified["sender_key_fingerprint"]
    result["sender_signature_algorithm"] = verified["sender_signature_algorithm"]
    result["authenticated"] = True
    return result


def hybrid_auth_verify(
    envelope: dict[str, Any],
    expected_sender_public_key: bytes | None = None,
    expected_sender_fingerprint: str | None = None,
    max_age_seconds: int = _MAX_ENVELOPE_AGE_SECONDS,
) -> dict[str, Any]:
    """Verify sender signature without decrypting. No secret keys needed."""
    verified = _verify_authenticated_envelope(
        envelope,
        expected_sender_public_key,
        expected_sender_fingerprint,
        max_age_seconds,
    )
    verified["verified"] = True
    return verified
