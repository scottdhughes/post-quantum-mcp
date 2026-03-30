"""Tests for hybrid X25519 + ML-KEM-768 key exchange.

Requires both liboqs and cryptography to be installed.
Module import errors fail loudly — no silent skips.
"""

import base64
import binascii
import hashlib
import pytest

oqs = pytest.importorskip("oqs", reason="liboqs-python not installed")
pytest.importorskip("cryptography", reason="cryptography not installed")

from pqc_mcp_server.hybrid import (
    SUITE,
    COMBINER_LABEL,
    _HKDF_INFO_PREFIX,
    _validate_x25519_key,
    _check_x25519_shared_secret,
    _kem_combine,
    _build_aad,
    _derive_aead_key_and_nonce,
    hybrid_keygen,
    hybrid_encap,
    hybrid_decap,
    hybrid_seal,
    hybrid_open,
)


class TestValidation:
    def test_valid_x25519_key(self):
        _validate_x25519_key(b"\x01" * 32, "test key")

    def test_x25519_key_too_short(self):
        with pytest.raises(ValueError, match="test key must be exactly 32 bytes"):
            _validate_x25519_key(b"\x01" * 31, "test key")

    def test_x25519_key_too_long(self):
        with pytest.raises(ValueError, match="test key must be exactly 32 bytes"):
            _validate_x25519_key(b"\x01" * 33, "test key")

    def test_all_zero_shared_secret_rejected(self):
        with pytest.raises(ValueError, match="all-zero"):
            _check_x25519_shared_secret(b"\x00" * 32)

    def test_nonzero_shared_secret_accepted(self):
        _check_x25519_shared_secret(b"\x01" + b"\x00" * 31)


class TestCombiner:
    def test_combiner_output_is_32_bytes(self):
        result = _kem_combine(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, b"\x04" * 32)
        assert len(result) == 32

    def test_combiner_is_deterministic(self):
        args = (b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, b"\x04" * 32)
        assert _kem_combine(*args) == _kem_combine(*args)

    def test_combiner_lamps_kat(self):
        """Published LAMPS KAT for id-MLKEM768-X25519-SHA3-256.

        Source: lamps-wg/draft-composite-kem, kemCombiner_MLKEM768_X25519_SHA3_256.md
        """
        ss_mlkem = bytes.fromhex("461b74b074818906edcd2fd976008caca5247f496670ae86e34abe35e62a7ae1")
        ss_x25519 = bytes.fromhex(
            "4c62bd6d6f76294f3c14d7e79dbf56e4bf82cb1fb803accfaf2a59c1663a8843"
        )
        epk = bytes.fromhex("0ec7210a4aa22bb75af9243f95a6ccf857e872efbe5e77e8e917b56178fa473f")
        pk = bytes.fromhex("1e9d4f72d56cef589864e102c6d6fa86cd3ac5163839556f7555ad083f37b03b")
        expected_ss = bytes.fromhex(
            "21ee673fdeac21dd78ef13bc8432a50c0ac31893cbe97d14c0e82f5fe4a28d98"
        )
        assert _kem_combine(ss_mlkem, ss_x25519, epk, pk) == expected_ss

    def test_combiner_different_inputs_different_output(self):
        r1 = _kem_combine(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, b"\x04" * 32)
        r2 = _kem_combine(b"\x05" * 32, b"\x02" * 32, b"\x03" * 32, b"\x04" * 32)
        assert r1 != r2

    def test_combiner_label_is_lamps_draft(self):
        """Label must be the exact LAMPS id-MLKEM768-X25519-SHA3-256 bytes."""
        assert COMBINER_LABEL == b"\x5c\x2e\x2f\x2f\x5e\x5c"
        assert len(COMBINER_LABEL) == 6


class TestHKDF:
    def test_info_string_bytes(self):
        assert _HKDF_INFO_PREFIX + b"aes-256-gcm-key" == (
            b"pqc-mcp-v1|mlkem768-x25519-sha3-256|aes-256-gcm-key"
        )
        assert _HKDF_INFO_PREFIX + b"aes-256-gcm-nonce" == (
            b"pqc-mcp-v1|mlkem768-x25519-sha3-256|aes-256-gcm-nonce"
        )

    def test_derive_produces_correct_lengths(self):
        aes_key, nonce = _derive_aead_key_and_nonce(b"\x01" * 32)
        assert len(aes_key) == 32
        assert len(nonce) == 12

    def test_derive_is_deterministic(self):
        k1, n1 = _derive_aead_key_and_nonce(b"\xab" * 32)
        k2, n2 = _derive_aead_key_and_nonce(b"\xab" * 32)
        assert k1 == k2
        assert n1 == n2

    def test_domain_separation(self):
        """AES key and nonce must differ (different HKDF info)."""
        aes_key, nonce = _derive_aead_key_and_nonce(b"\x01" * 32)
        assert aes_key[:12] != nonce


class TestAAD:
    def test_aad_construction(self):
        epk = b"\xaa" * 32
        ct = b"\xbb" * 100
        aad = _build_aad(epk, ct)
        prefix = b"pqc-mcp-v1|mlkem768-x25519-sha3-256|"
        assert len(prefix) == 36
        assert aad.startswith(prefix)
        assert aad[36:68] == epk
        assert aad[68:] == ct

    def test_aad_is_deterministic(self):
        epk = b"\x01" * 32
        ct = b"\x02" * 50
        assert _build_aad(epk, ct) == _build_aad(epk, ct)


class TestKeygen:
    def test_keygen_returns_suite(self):
        result = hybrid_keygen()
        assert result["suite"] == SUITE

    def test_keygen_x25519_keys_are_32_bytes(self):
        result = hybrid_keygen()
        pk = base64.b64decode(result["classical"]["public_key"])
        sk = base64.b64decode(result["classical"]["secret_key"])
        assert len(pk) == 32
        assert len(sk) == 32

    def test_keygen_pqc_keys_exist(self):
        result = hybrid_keygen()
        assert result["pqc"]["algorithm"] == "ML-KEM-768"
        pk = base64.b64decode(result["pqc"]["public_key"])
        sk = base64.b64decode(result["pqc"]["secret_key"])
        assert len(pk) > 0
        assert len(sk) > 0

    def test_keygen_includes_fingerprints(self):
        result = hybrid_keygen()
        assert len(result["classical"]["fingerprint"]) == 64
        assert len(result["pqc"]["fingerprint"]) == 64
        # Fingerprint must match SHA3-256 of the public key
        pk = base64.b64decode(result["classical"]["public_key"])
        assert result["classical"]["fingerprint"] == hashlib.sha3_256(pk).hexdigest()

    def test_keygen_unique(self):
        r1 = hybrid_keygen()
        r2 = hybrid_keygen()
        assert r1["classical"]["public_key"] != r2["classical"]["public_key"]
        assert r1["pqc"]["public_key"] != r2["pqc"]["public_key"]


class TestEncapDecap:
    def test_encap_decap_roundtrip(self):
        keys = hybrid_keygen()
        encap_result = hybrid_encap(
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
        )
        assert encap_result["suite"] == SUITE
        assert len(base64.b64decode(encap_result["shared_secret"])) == 32
        assert len(base64.b64decode(encap_result["x25519_ephemeral_public_key"])) == 32

        decap_result = hybrid_decap(
            base64.b64decode(keys["classical"]["secret_key"]),
            base64.b64decode(keys["pqc"]["secret_key"]),
            base64.b64decode(encap_result["x25519_ephemeral_public_key"]),
            base64.b64decode(encap_result["pqc_ciphertext"]),
        )
        assert decap_result["shared_secret"] == encap_result["shared_secret"]
        assert decap_result["shared_secret_hex"] == encap_result["shared_secret_hex"]

    def test_wrong_key_decap_implicit_rejection(self):
        """ML-KEM performs implicit rejection: returns a deterministic but
        incorrect shared secret rather than an explicit error."""
        k1 = hybrid_keygen()
        k2 = hybrid_keygen()
        encap_result = hybrid_encap(
            base64.b64decode(k1["classical"]["public_key"]),
            base64.b64decode(k1["pqc"]["public_key"]),
        )
        decap_wrong = hybrid_decap(
            base64.b64decode(k2["classical"]["secret_key"]),
            base64.b64decode(k2["pqc"]["secret_key"]),
            base64.b64decode(encap_result["x25519_ephemeral_public_key"]),
            base64.b64decode(encap_result["pqc_ciphertext"]),
        )
        assert decap_wrong["shared_secret"] != encap_result["shared_secret"]

    def test_x25519_key_length_validation(self):
        keys = hybrid_keygen()
        with pytest.raises(ValueError, match="must be exactly 32 bytes"):
            hybrid_encap(b"\x01" * 31, base64.b64decode(keys["pqc"]["public_key"]))


class TestSealOpen:
    def test_seal_open_string_roundtrip(self):
        keys = hybrid_keygen()
        envelope = hybrid_seal(
            b"Hello, quantum world!",
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
        )
        assert envelope["version"] == "pqc-mcp-v1"
        assert envelope["suite"] == SUITE
        assert "ciphertext" in envelope
        assert "nonce" not in envelope  # nonce is derived, not transmitted

        result = hybrid_open(
            envelope,
            base64.b64decode(keys["classical"]["secret_key"]),
            base64.b64decode(keys["pqc"]["secret_key"]),
        )
        assert result["plaintext"] == "Hello, quantum world!"
        assert result["suite"] == SUITE

    def test_seal_open_binary_roundtrip(self):
        keys = hybrid_keygen()
        binary_data = bytes(range(256))
        envelope = hybrid_seal(
            binary_data,
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
        )
        result = hybrid_open(
            envelope,
            base64.b64decode(keys["classical"]["secret_key"]),
            base64.b64decode(keys["pqc"]["secret_key"]),
        )
        assert base64.b64decode(result["plaintext_base64"]) == binary_data

    def test_seal_open_non_utf8_binary(self):
        keys = hybrid_keygen()
        non_utf8 = b"\x80\x81\x82\xff\xfe"
        envelope = hybrid_seal(
            non_utf8,
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
        )
        result = hybrid_open(
            envelope,
            base64.b64decode(keys["classical"]["secret_key"]),
            base64.b64decode(keys["pqc"]["secret_key"]),
        )
        assert result["plaintext"] is None
        assert base64.b64decode(result["plaintext_base64"]) == non_utf8

    def test_wrong_key_open_fails(self):
        from cryptography.exceptions import InvalidTag

        k1 = hybrid_keygen()
        k2 = hybrid_keygen()
        envelope = hybrid_seal(
            b"secret",
            base64.b64decode(k1["classical"]["public_key"]),
            base64.b64decode(k1["pqc"]["public_key"]),
        )
        with pytest.raises(InvalidTag):
            hybrid_open(
                envelope,
                base64.b64decode(k2["classical"]["secret_key"]),
                base64.b64decode(k2["pqc"]["secret_key"]),
            )

    def test_tampered_ciphertext_fails(self):
        from cryptography.exceptions import InvalidTag

        keys = hybrid_keygen()
        envelope = hybrid_seal(
            b"data",
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
        )
        ct = bytearray(base64.b64decode(envelope["ciphertext"]))
        ct[0] ^= 0xFF
        envelope["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        with pytest.raises(InvalidTag):
            hybrid_open(
                envelope,
                base64.b64decode(keys["classical"]["secret_key"]),
                base64.b64decode(keys["pqc"]["secret_key"]),
            )

    def test_tampered_pqc_ciphertext_fails(self):
        """Tampered ML-KEM ciphertext changes the AAD, causing GCM tag mismatch."""
        from cryptography.exceptions import InvalidTag

        keys = hybrid_keygen()
        envelope = hybrid_seal(
            b"data",
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
        )
        ct = bytearray(base64.b64decode(envelope["pqc_ciphertext"]))
        ct[0] ^= 0xFF
        envelope["pqc_ciphertext"] = base64.b64encode(bytes(ct)).decode()
        with pytest.raises(InvalidTag):
            hybrid_open(
                envelope,
                base64.b64decode(keys["classical"]["secret_key"]),
                base64.b64decode(keys["pqc"]["secret_key"]),
            )

    def test_tampered_epk_fails(self):
        """Tampered ephemeral key changes both ECDH shared secret and AAD."""
        from cryptography.exceptions import InvalidTag

        keys = hybrid_keygen()
        envelope = hybrid_seal(
            b"data",
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
        )
        epk = bytearray(base64.b64decode(envelope["x25519_ephemeral_public_key"]))
        epk[0] ^= 0xFF
        envelope["x25519_ephemeral_public_key"] = base64.b64encode(bytes(epk)).decode()
        with pytest.raises(InvalidTag):
            hybrid_open(
                envelope,
                base64.b64decode(keys["classical"]["secret_key"]),
                base64.b64decode(keys["pqc"]["secret_key"]),
            )

    def test_bad_version_rejected(self):
        keys = hybrid_keygen()
        envelope = hybrid_seal(
            b"data",
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
        )
        envelope["version"] = "pqc-mcp-v99"
        with pytest.raises(ValueError, match="Unsupported envelope version"):
            hybrid_open(
                envelope,
                base64.b64decode(keys["classical"]["secret_key"]),
                base64.b64decode(keys["pqc"]["secret_key"]),
            )

    def test_bad_suite_rejected(self):
        keys = hybrid_keygen()
        envelope = hybrid_seal(
            b"data",
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
        )
        envelope["suite"] = "mlkem512-x25519-sha3-256"
        with pytest.raises(ValueError, match="Unsupported envelope suite"):
            hybrid_open(
                envelope,
                base64.b64decode(keys["classical"]["secret_key"]),
                base64.b64decode(keys["pqc"]["secret_key"]),
            )

    def test_invalid_base64_in_envelope_rejected(self):
        keys = hybrid_keygen()
        envelope = hybrid_seal(
            b"data",
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
        )
        envelope["ciphertext"] = "not!valid@base64###"
        with pytest.raises(binascii.Error):
            hybrid_open(
                envelope,
                base64.b64decode(keys["classical"]["secret_key"]),
                base64.b64decode(keys["pqc"]["secret_key"]),
            )
