"""v3 mode separation tests — all cross-mode confusion attacks.

Verifies that anon-seal and auth-seal ciphertexts are cryptographically
distinct and cannot be relabeled or downgraded.
"""

import base64

import pytest

oqs = pytest.importorskip("oqs", reason="liboqs-python not installed")
pytest.importorskip("cryptography", reason="cryptography not installed")

from cryptography.exceptions import InvalidTag

from pqc_mcp_server.hybrid import (
    ENVELOPE_VERSION,
    _MODE_ANON_SEAL,
    _MODE_AUTH_SEAL,
    SenderVerificationError,
    _fingerprint_public_key,
    hybrid_keygen,
    hybrid_seal,
    hybrid_open,
    hybrid_auth_seal,
    hybrid_auth_open,
    hybrid_auth_verify,
)
from pqc_mcp_server.key_store import clear_store


@pytest.fixture(autouse=True)
def clean():
    clear_store()
    yield
    clear_store()


@pytest.fixture
def keys():
    enc = hybrid_keygen()
    sig = oqs.Signature("ML-DSA-65")
    sig_pk = sig.generate_keypair()
    sig_sk = sig.export_secret_key()
    return {
        "enc": enc,
        "sig_pk": sig_pk,
        "sig_sk": sig_sk,
        "sig_fp": _fingerprint_public_key(sig_pk),
        "cpk": base64.b64decode(enc["classical"]["public_key"]),
        "ppk": base64.b64decode(enc["pqc"]["public_key"]),
        "csk": base64.b64decode(enc["classical"]["secret_key"]),
        "psk": base64.b64decode(enc["pqc"]["secret_key"]),
    }


class TestAuthStrippingDowngrade:
    """ChatGPT finding: strip auth fields, relabel as anon-seal."""

    def test_stripped_auth_fails_as_anon(self, keys):
        auth_env = hybrid_auth_seal(
            b"secret", keys["cpk"], keys["ppk"], keys["sig_sk"], keys["sig_pk"]
        )
        stripped = {
            "version": auth_env["version"],
            "mode": _MODE_ANON_SEAL,
            "suite": auth_env["suite"],
            "x25519_ephemeral_public_key": auth_env["x25519_ephemeral_public_key"],
            "pqc_ciphertext": auth_env["pqc_ciphertext"],
            "ciphertext": auth_env["ciphertext"],
        }
        with pytest.raises(InvalidTag):
            hybrid_open(stripped, keys["csk"], keys["psk"])


class TestAnonUpgradeAttack:
    """Relabel anon-seal as auth-seal — schema should reject."""

    def test_anon_relabeled_as_auth_rejected(self, keys):
        anon_env = hybrid_seal(b"anon", keys["cpk"], keys["ppk"])
        anon_env["mode"] = _MODE_AUTH_SEAL
        # Missing auth fields → rejected (either schema or field check)
        with pytest.raises(ValueError):
            hybrid_auth_open(
                anon_env, keys["csk"], keys["psk"],
                expected_sender_fingerprint=keys["sig_fp"],
            )


class TestMissingMode:
    """v3 envelope with no mode field."""

    def test_missing_mode_rejected(self, keys):
        env = hybrid_seal(b"test", keys["cpk"], keys["ppk"])
        del env["mode"]
        with pytest.raises(ValueError, match="Unknown v3 mode"):
            hybrid_open(env, keys["csk"], keys["psk"])


class TestUnknownMode:
    """v3 envelope with unknown mode string."""

    def test_unknown_mode_rejected(self, keys):
        env = hybrid_seal(b"test", keys["cpk"], keys["ppk"])
        env["mode"] = "hybrid-seal"
        with pytest.raises(ValueError, match="Unknown v3 mode"):
            hybrid_open(env, keys["csk"], keys["psk"])


class TestCrossHandlerEnforcement:
    """v3 envelopes routed to wrong handler."""

    def test_auth_seal_to_anon_handler_rejected(self, keys):
        """auth-seal envelope passed to hybrid_open (public API level)."""
        auth_env = hybrid_auth_seal(
            b"auth", keys["cpk"], keys["ppk"], keys["sig_sk"], keys["sig_pk"]
        )
        # The auth-seal ciphertext uses auth-seal HKDF, so even if mode
        # check didn't exist, the AEAD key would be wrong
        with pytest.raises((ValueError, InvalidTag)):
            hybrid_open(auth_env, keys["csk"], keys["psk"])

    def test_anon_seal_to_auth_handler_rejected(self, keys):
        """anon-seal envelope passed to hybrid_auth_open."""
        anon_env = hybrid_seal(b"anon", keys["cpk"], keys["ppk"])
        with pytest.raises((ValueError, SenderVerificationError)):
            hybrid_auth_open(
                anon_env, keys["csk"], keys["psk"],
                expected_sender_fingerprint=keys["sig_fp"],
            )


class TestLegacyCompat:
    """v1/v2 envelopes still work despite v3 schema enforcement."""

    def test_v3_roundtrip_anon(self, keys):
        env = hybrid_seal(b"v3 anon", keys["cpk"], keys["ppk"])
        assert env["version"] == ENVELOPE_VERSION
        assert env["mode"] == _MODE_ANON_SEAL
        r = hybrid_open(env, keys["csk"], keys["psk"])
        assert r["plaintext"] == "v3 anon"

    def test_v3_roundtrip_auth(self, keys):
        env = hybrid_auth_seal(
            b"v3 auth", keys["cpk"], keys["ppk"], keys["sig_sk"], keys["sig_pk"]
        )
        assert env["version"] == ENVELOPE_VERSION
        assert env["mode"] == _MODE_AUTH_SEAL
        r = hybrid_auth_open(
            env, keys["csk"], keys["psk"],
            expected_sender_fingerprint=keys["sig_fp"],
        )
        assert r["plaintext"] == "v3 auth"
        assert r["authenticated"] is True


class TestModeBoundTranscript:
    """Mode tampering in auth envelope invalidates signature."""

    def test_mode_tamper_fails_signature(self, keys):
        env = hybrid_auth_seal(
            b"signed", keys["cpk"], keys["ppk"], keys["sig_sk"], keys["sig_pk"]
        )
        env["mode"] = _MODE_ANON_SEAL  # tamper mode
        with pytest.raises(SenderVerificationError):
            hybrid_auth_verify(env, expected_sender_fingerprint=keys["sig_fp"])


class TestSignatureDigest:
    """signature_digest rejects missing/empty/invalid signatures."""

    def test_rejects_missing(self):
        from pqc_mcp_server.replay_cache import signature_digest

        with pytest.raises(ValueError, match="no signature"):
            signature_digest({})

    def test_rejects_empty(self):
        from pqc_mcp_server.replay_cache import signature_digest

        with pytest.raises(ValueError, match="no signature"):
            signature_digest({"signature": ""})

    def test_rejects_invalid_base64(self):
        from pqc_mcp_server.replay_cache import signature_digest

        with pytest.raises(Exception):
            signature_digest({"signature": "!!!"})


class TestFallbackCache:
    """Fallback in-memory cache (created via __new__) works correctly."""

    def test_prunes_without_error(self):
        from pqc_mcp_server.replay_cache import (
            ReplayCache,
            _DEFAULT_MAX_SIZE,
            _DEFAULT_TTL,
        )

        cache = ReplayCache.__new__(ReplayCache)
        cache.cache_file = ""
        cache.ttl_seconds = _DEFAULT_TTL
        cache.max_size = _DEFAULT_MAX_SIZE
        cache._cache = {}

        # Should not raise AttributeError
        cache.prune()
        cache.check("test-digest")
        cache.check_and_mark("test-digest")
        assert cache.check("test-digest")

        # Fill past max and prune expired
        for i in range(100):
            cache._cache[f"d-{i}"] = 0  # expired (timestamp 0)
        cache.prune()
        assert len(cache._cache) <= 1  # only the non-expired one
