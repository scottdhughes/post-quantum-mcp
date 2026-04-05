"""Tests for pre-dispatch input validation and exception handling.

Covers pentest findings:
- Malformed argument types (HIGH): list as envelope, None as plaintext, etc.
- Unbounded input sizes (MEDIUM): oversized plaintext, message, key_data
- Replay cache TOCTOU (MEDIUM): same envelope rejected on second auth_open
- Key store policy bypass (HIGH): secret smuggling via key_store_save
"""

import pytest

oqs = pytest.importorskip("oqs", reason="liboqs-python not installed")
pytest.importorskip("cryptography", reason="cryptography not installed")

from pqc_mcp_server import _validate_arguments, HAS_LIBOQS
from pqc_mcp_server.key_store import clear_store, handle_key_store_save
from pqc_mcp_server.replay_cache import get_replay_cache
from pqc_mcp_server.security_policy import SecurityPolicy, get_policy
from pqc_mcp_server.handlers_hybrid import (
    handle_hybrid_keygen,
    handle_hybrid_auth_seal,
    handle_hybrid_auth_open,
)
from pqc_mcp_server.handlers_pqc import handle_generate_keypair

requires_liboqs = pytest.mark.skipif(
    not HAS_LIBOQS,
    reason="liboqs not installed",
)


@pytest.fixture(autouse=True)
def clean():
    clear_store()
    cache = get_replay_cache()
    cache._cache.clear()
    yield
    clear_store()
    cache._cache.clear()


# ═══════════════════════════════════════════════
# Type mismatch tests (Finding #7 — Codex HIGH)
# Tests call _validate_arguments directly since MCP's own
# JSON Schema validation may intercept first at protocol layer.
# ═══════════════════════════════════════════════


class TestValidateArguments:
    """_validate_arguments must reject malformed types before handler dispatch."""

    def test_envelope_as_list(self):
        with pytest.raises(ValueError, match="must be a JSON object"):
            _validate_arguments({"envelope": [1, 2, 3]})

    def test_plaintext_as_int(self):
        with pytest.raises(ValueError, match="must be a string"):
            _validate_arguments({"plaintext": 12345})

    def test_message_as_bool(self):
        with pytest.raises(ValueError, match="must be a string"):
            _validate_arguments({"message": True})

    def test_name_as_int(self):
        with pytest.raises(ValueError, match="must be a string"):
            _validate_arguments({"name": 42})

    def test_algorithm_as_bool(self):
        with pytest.raises(ValueError, match="must be a string"):
            _validate_arguments({"algorithm": True})

    def test_key_data_as_list(self):
        with pytest.raises(ValueError, match="must be a JSON object"):
            _validate_arguments({"key_data": [1, 2]})

    def test_public_key_as_int(self):
        with pytest.raises(ValueError, match="must be a string"):
            _validate_arguments({"public_key": 999})

    def test_overwrite_as_string(self):
        with pytest.raises(ValueError, match="must be a boolean"):
            _validate_arguments({"overwrite": "yes"})

    def test_iterations_as_string(self):
        with pytest.raises(ValueError, match="must be a number"):
            _validate_arguments({"iterations": "fast"})

    def test_bool_as_int_rejected(self):
        """bool is subclass of int — must be explicitly rejected for int fields."""
        with pytest.raises(ValueError, match="must be a number"):
            _validate_arguments({"iterations": True})
        with pytest.raises(ValueError, match="must be a number"):
            _validate_arguments({"max_age_seconds": False})

    def test_arguments_not_dict(self):
        with pytest.raises(ValueError, match="must be a JSON object"):
            _validate_arguments("not a dict")  # type: ignore

    def test_none_values_pass(self):
        """None values should be silently skipped (optional absent fields)."""
        _validate_arguments({"plaintext": None, "envelope": None})

    def test_unknown_fields_pass(self):
        """Unknown fields should not be rejected (future-proof)."""
        _validate_arguments({"some_future_field": 42})

    def test_valid_arguments_pass(self):
        """Valid arguments should not raise."""
        _validate_arguments(
            {
                "algorithm": "ML-DSA-65",
                "message": "hello",
                "iterations": 10,
                "overwrite": True,
            }
        )


# ═══════════════════════════════════════════════
# Size limit tests (Finding #9 — Codex MEDIUM)
# ═══════════════════════════════════════════════


class TestSizeLimits:
    """Oversized string inputs must be rejected by _validate_arguments."""

    def test_oversized_plaintext(self):
        with pytest.raises(ValueError, match="size limit"):
            _validate_arguments({"plaintext": "A" * 2_000_000})

    def test_oversized_message(self):
        with pytest.raises(ValueError, match="size limit"):
            _validate_arguments({"message": "B" * 2_000_000})

    def test_oversized_public_key(self):
        with pytest.raises(ValueError, match="size limit"):
            _validate_arguments({"public_key": "C" * 200_000})

    def test_valid_size_passes(self):
        _validate_arguments({"plaintext": "Hello PQC"})


# ═══════════════════════════════════════════════
# Replay TOCTOU closure test (Finding #8 — Codex MEDIUM)
# ═══════════════════════════════════════════════


@requires_liboqs
class TestReplayTOCTOU:
    """Same envelope must be rejected on second auth_open call."""

    @pytest.mark.asyncio
    async def test_replay_rejected_on_second_open(self):
        """After a successful auth_open, replaying the same envelope raises."""
        enc = handle_hybrid_keygen({"store_as": "replay-enc"})
        sig = handle_generate_keypair({"algorithm": "ML-DSA-65", "store_as": "replay-sig"})

        envelope_result = handle_hybrid_auth_seal(
            {
                "plaintext": "replay test message",
                "recipient_key_store_name": "replay-enc",
                "sender_key_store_name": "replay-sig",
            }
        )
        envelope = envelope_result["envelope"]

        # First open — should succeed
        result = await handle_hybrid_auth_open(
            {
                "envelope": envelope,
                "key_store_name": "replay-enc",
                "expected_sender_fingerprint": sig["fingerprint"],
            }
        )
        assert "plaintext" in result

        # Second open — same envelope — must be rejected
        with pytest.raises(ValueError, match="[Rr]eplay|[Dd]uplicate"):
            await handle_hybrid_auth_open(
                {
                    "envelope": envelope,
                    "key_store_name": "replay-enc",
                    "expected_sender_fingerprint": sig["fingerprint"],
                }
            )


# ═══════════════════════════════════════════════
# Key store policy bypass tests (Finding #6 — Codex HIGH)
# ═══════════════════════════════════════════════


@pytest.fixture
def policy_enabled(monkeypatch):
    """Enable PQC_REQUIRE_KEY_HANDLES for this test."""
    monkeypatch.setenv("PQC_REQUIRE_KEY_HANDLES", "1")
    from pqc_mcp_server import security_policy

    monkeypatch.setattr(security_policy, "_POLICY", SecurityPolicy())
    return get_policy()


class TestKeyStorePolicyBypass:
    """key_store_save must reject raw secrets when PQC_REQUIRE_KEY_HANDLES=1."""

    def test_flat_key_with_secret_rejected(self, policy_enabled):
        with pytest.raises(ValueError, match="secret_key"):
            handle_key_store_save(
                {
                    "name": "smuggled",
                    "key_data": {
                        "algorithm": "ML-DSA-65",
                        "type": "signature",
                        "public_key": "AAAA",
                        "secret_key": "BBBB",
                    },
                }
            )

    def test_hybrid_bundle_with_secrets_rejected(self, policy_enabled):
        with pytest.raises(ValueError, match="secret_key"):
            handle_key_store_save(
                {
                    "name": "smuggled-hybrid",
                    "key_data": {
                        "suite": "mlkem768-x25519-sha3-256",
                        "classical": {
                            "algorithm": "X25519",
                            "public_key": "AAAA",
                            "secret_key": "BBBB",
                        },
                        "pqc": {
                            "algorithm": "ML-KEM-768",
                            "public_key": "CCCC",
                            "secret_key": "DDDD",
                        },
                    },
                }
            )

    def test_public_only_key_accepted(self, policy_enabled):
        result = handle_key_store_save(
            {
                "name": "public-only",
                "key_data": {
                    "algorithm": "ML-DSA-65",
                    "type": "signature",
                    "public_key": "AAAA",
                },
            }
        )
        assert result["saved"] == "public-only"

    def test_save_allowed_without_policy(self):
        result = handle_key_store_save(
            {
                "name": "allowed",
                "key_data": {
                    "algorithm": "ML-DSA-65",
                    "type": "signature",
                    "public_key": "AAAA",
                    "secret_key": "BBBB",
                },
            }
        )
        assert result["saved"] == "allowed"


# ═══════════════════════════════════════════════
# key_data size limit test (Finding #5)
# ═══════════════════════════════════════════════


class TestKeyDataSizeLimit:
    """Oversized key_data must be rejected by handle_key_store_save."""

    def test_oversized_key_data_rejected(self):
        huge = {"junk": "X" * 200_000}
        with pytest.raises(ValueError, match="bytes"):
            handle_key_store_save({"name": "huge", "key_data": huge})

    def test_normal_size_key_data_accepted(self):
        result = handle_key_store_save(
            {
                "name": "normal",
                "key_data": {"algorithm": "ML-DSA-65", "type": "signature", "public_key": "AAAA"},
            }
        )
        assert result["saved"] == "normal"


# ═══════════════════════════════════════════════
# Schema allowlist tests (9-model consensus)
# ═══════════════════════════════════════════════


class TestSchemaAllowlist:
    """Unknown fields in key_data must be rejected when policy is active."""

    def test_unknown_top_level_key_rejected(self, policy_enabled):
        """Smuggling via unknown sub-dict like {"extra": {"secret_key": ...}}."""
        with pytest.raises(ValueError, match="unknown fields"):
            handle_key_store_save(
                {
                    "name": "smuggled",
                    "key_data": {
                        "algorithm": "ML-DSA-65",
                        "type": "signature",
                        "public_key": "AAAA",
                        "extra": {"secret_key": "BBBB"},
                    },
                }
            )

    def test_unknown_sub_key_rejected(self, policy_enabled):
        """Unknown field inside classical/pqc sub-dict."""
        with pytest.raises(ValueError, match="unknown fields"):
            handle_key_store_save(
                {
                    "name": "smuggled-sub",
                    "key_data": {
                        "suite": "mlkem768-x25519-sha3-256",
                        "classical": {
                            "algorithm": "X25519",
                            "public_key": "AAAA",
                            "metadata": {"secret_key": "raw"},
                        },
                        "pqc": {
                            "algorithm": "ML-KEM-768",
                            "public_key": "CCCC",
                        },
                    },
                }
            )

    def test_valid_hybrid_bundle_accepted(self, policy_enabled):
        """Legitimate hybrid bundle (public-only) should pass schema check."""
        result = handle_key_store_save(
            {
                "name": "valid-hybrid",
                "key_data": {
                    "suite": "mlkem768-x25519-sha3-256",
                    "classical": {
                        "algorithm": "X25519",
                        "public_key": "AAAA",
                        "fingerprint": "abcd1234",
                    },
                    "pqc": {
                        "algorithm": "ML-KEM-768",
                        "public_key": "CCCC",
                        "fingerprint": "efgh5678",
                    },
                },
            }
        )
        assert result["saved"] == "valid-hybrid"

    def test_unknown_keys_allowed_without_policy(self):
        """Without policy, unknown keys should still be accepted (backwards compat)."""
        result = handle_key_store_save(
            {
                "name": "flexible",
                "key_data": {
                    "algorithm": "ML-DSA-65",
                    "type": "signature",
                    "public_key": "AAAA",
                    "custom_metadata": "whatever",
                },
            }
        )
        assert result["saved"] == "flexible"
