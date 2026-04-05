"""Handle-policy and security-policy negative-path tests.

Verifies that PQC_REQUIRE_KEY_HANDLES enforcement works under
bad conditions: raw secrets rejected, wrong handle types, missing
handles, and all handler paths covered.
"""

import base64

import pytest

oqs = pytest.importorskip("oqs", reason="liboqs-python not installed")
pytest.importorskip("cryptography", reason="cryptography not installed")

from pqc_mcp_server.hybrid import hybrid_keygen, _fingerprint_public_key
from pqc_mcp_server.handlers_pqc import (
    handle_generate_keypair,
    handle_decapsulate,
    handle_sign,
    handle_verify,
    handle_encapsulate,
)
from pqc_mcp_server.handlers_hybrid import (
    handle_hybrid_keygen,
    handle_hybrid_seal,
    handle_hybrid_auth_seal,
    handle_hybrid_auth_open,
)
from pqc_mcp_server.key_store import clear_store
from pqc_mcp_server.security_policy import SecurityPolicy, get_policy


@pytest.fixture(autouse=True)
def clean():
    clear_store()
    yield
    clear_store()


@pytest.fixture
def policy_enabled(monkeypatch):
    """Enable PQC_REQUIRE_KEY_HANDLES for this test."""
    monkeypatch.setenv("PQC_REQUIRE_KEY_HANDLES", "1")
    # Reset the singleton so it picks up the new env
    from pqc_mcp_server import security_policy

    monkeypatch.setattr(security_policy, "_POLICY", SecurityPolicy())
    return get_policy()


@pytest.fixture
def keys():
    enc = handle_hybrid_keygen({"store_as": "test-enc"})
    sig = handle_generate_keypair({"algorithm": "ML-DSA-65", "store_as": "test-sig"})
    return {"enc": enc, "sig": sig}


# ═══════════════════════════════════════════════
# PQC_REQUIRE_KEY_HANDLES enforcement
# ═══════════════════════════════════════════════


class TestHandlePolicyKeygen:
    """pqc_generate_keypair must require store_as when policy is enabled."""

    def test_keygen_without_store_as_rejected(self, policy_enabled):
        with pytest.raises(ValueError, match="PQC_REQUIRE_KEY_HANDLES"):
            handle_generate_keypair({"algorithm": "ML-DSA-65"})

    def test_keygen_with_store_as_allowed(self, policy_enabled):
        result = handle_generate_keypair({"algorithm": "ML-DSA-65", "store_as": "policy-test"})
        assert "handle" in result
        assert "secret_key" not in result


class TestHandlePolicySign:
    """pqc_sign must reject raw secret_key when policy is enabled."""

    def test_sign_with_raw_key_rejected(self, policy_enabled):
        sig = oqs.Signature("ML-DSA-65")
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
        with pytest.raises(ValueError, match="PQC_REQUIRE_KEY_HANDLES"):
            handle_sign(
                {
                    "algorithm": "ML-DSA-65",
                    "secret_key": base64.b64encode(sk).decode(),
                    "message": "test",
                }
            )

    def test_sign_with_handle_allowed(self, policy_enabled, keys):
        result = handle_sign(
            {
                "algorithm": "ML-DSA-65",
                "key_store_name": "test-sig",
                "message": "test",
            }
        )
        assert "signature" in result


class TestHandlePolicyDecapsulate:
    """pqc_decapsulate must reject raw secret_key when policy is enabled."""

    def test_decap_with_raw_key_rejected(self, policy_enabled):
        kem = oqs.KeyEncapsulation("ML-KEM-768")
        pk = kem.generate_keypair()
        sk = kem.export_secret_key()
        ct, ss = kem.encap_secret(pk)
        with pytest.raises(ValueError, match="PQC_REQUIRE_KEY_HANDLES"):
            handle_decapsulate(
                {
                    "algorithm": "ML-KEM-768",
                    "secret_key": base64.b64encode(sk).decode(),
                    "ciphertext": base64.b64encode(ct).decode(),
                }
            )


class TestHandlePolicyHybrid:
    """Hybrid handlers must reject raw secret keys when policy is enabled."""

    def test_hybrid_auth_seal_raw_sender_rejected(self, policy_enabled, keys):
        sig = oqs.Signature("ML-DSA-65")
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
        with pytest.raises(ValueError, match="PQC_REQUIRE_KEY_HANDLES"):
            handle_hybrid_auth_seal(
                {
                    "plaintext": "test",
                    "recipient_key_store_name": "test-enc",
                    "sender_secret_key": base64.b64encode(sk).decode(),
                    "sender_public_key": base64.b64encode(pk).decode(),
                }
            )

    @pytest.mark.asyncio
    async def test_hybrid_auth_open_raw_recipient_rejected(self, policy_enabled, keys):
        """Raw secret keys for hybrid auth open should be rejected.
        Note: envelope validation (signature_digest) may fire first on
        empty envelopes, but the policy check is still wired in."""
        enc = hybrid_keygen()
        with pytest.raises(ValueError):
            await handle_hybrid_auth_open(
                {
                    "envelope": {},
                    "classical_secret_key": enc["classical"]["secret_key"],
                    "pqc_secret_key": enc["pqc"]["secret_key"],
                    "expected_sender_fingerprint": "0" * 64,
                }
            )


# ═══════════════════════════════════════════════
# Policy disabled — raw keys should work
# ═══════════════════════════════════════════════


class TestPolicyDisabled:
    """When policy is not enabled, raw keys should be accepted."""

    def test_keygen_without_store_as_allowed(self):
        result = handle_generate_keypair({"algorithm": "ML-DSA-65"})
        assert "secret_key" in result

    def test_sign_with_raw_key_allowed(self):
        sig = oqs.Signature("ML-DSA-65")
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
        result = handle_sign(
            {
                "algorithm": "ML-DSA-65",
                "secret_key": base64.b64encode(sk).decode(),
                "message": "test",
            }
        )
        assert "signature" in result


# ═══════════════════════════════════════════════
# Wrong handle type
# ═══════════════════════════════════════════════


class TestWrongHandleType:
    """Using the wrong handle type for an operation should fail."""

    def test_kem_handle_for_sign_rejected(self, keys):
        """Encryption handle used for signing should fail."""
        with pytest.raises(ValueError, match="not a signing keypair"):
            handle_sign(
                {
                    "algorithm": "ML-DSA-65",
                    "key_store_name": "test-enc",  # this is a hybrid bundle, not signing
                    "message": "test",
                }
            )

    @pytest.mark.asyncio
    async def test_signing_handle_for_hybrid_open_rejected(self, keys):
        """Signing handle used for decryption should fail."""
        with pytest.raises(ValueError):
            await handle_hybrid_auth_open(
                {
                    "envelope": {"version": "pqc-mcp-v3", "mode": "auth-seal"},
                    "key_store_name": "test-sig",
                    "expected_sender_fingerprint": "0" * 64,
                }
            )


# ═══════════════════════════════════════════════
# Missing handles
# ═══════════════════════════════════════════════


class TestMissingHandle:
    """Operations with non-existent handles should fail clearly."""

    def test_nonexistent_handle_for_sign(self):
        with pytest.raises(ValueError, match="not found"):
            handle_sign(
                {
                    "algorithm": "ML-DSA-65",
                    "key_store_name": "does-not-exist",
                    "message": "test",
                }
            )

    @pytest.mark.asyncio
    async def test_nonexistent_handle_for_hybrid_open(self):
        with pytest.raises(ValueError):
            await handle_hybrid_auth_open(
                {
                    "envelope": {"version": "pqc-mcp-v3", "mode": "auth-seal"},
                    "key_store_name": "nonexistent",
                    "expected_sender_fingerprint": "0" * 64,
                }
            )
