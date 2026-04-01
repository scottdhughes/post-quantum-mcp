"""Tests for secret-handle keyring functionality."""

import base64
import pytest

oqs = pytest.importorskip("oqs", reason="liboqs-python not installed")
pytest.importorskip("cryptography", reason="cryptography not installed")

from pqc_mcp_server.key_store import (
    store_from_keygen,
    _resolve_from_store,
    _require_hybrid_bundle,
    _require_flat_signature,
    _require_flat_kem,
    _require_mldsa65,
    handle_key_store_load,
    handle_key_store_save,
    handle_key_store_list,
    handle_key_store_delete,
    clear_store,
)
from pqc_mcp_server.hybrid import hybrid_keygen
from pqc_mcp_server.handlers_pqc import handle_generate_keypair
from pqc_mcp_server.handlers_hybrid import _resolve_sender
from pqc_mcp_server.tools import PQC_TOOLS


@pytest.fixture(autouse=True)
def clean():
    clear_store()
    yield
    clear_store()


class TestStoreFromKeygen:
    def test_store_hybrid_and_resolve(self):
        keys = hybrid_keygen()
        store_from_keygen("alice", keys)
        resolved = _resolve_from_store("alice")
        assert resolved["suite"] == keys["suite"]
        assert "secret_key" in resolved["classical"]

    def test_store_flat_and_resolve(self):
        keys = handle_generate_keypair({"algorithm": "ML-DSA-65"})
        store_from_keygen("bob-sig", keys)
        resolved = _resolve_from_store("bob-sig")
        assert resolved["algorithm"] == "ML-DSA-65"
        assert "secret_key" in resolved

    def test_collision_without_overwrite_fails(self):
        keys = hybrid_keygen()
        store_from_keygen("alice", keys)
        with pytest.raises(ValueError, match="already exists"):
            store_from_keygen("alice", keys)

    def test_collision_with_overwrite_succeeds(self):
        keys1 = hybrid_keygen()
        keys2 = hybrid_keygen()
        store_from_keygen("alice", keys1)
        store_from_keygen("alice", keys2, overwrite=True)
        resolved = _resolve_from_store("alice")
        assert resolved["classical"]["public_key"] == keys2["classical"]["public_key"]

    def test_resolve_nonexistent_raises(self):
        with pytest.raises(ValueError, match="not found"):
            _resolve_from_store("ghost")


class TestHandleLoad:
    def test_handle_entry_returns_public_only(self):
        keys = hybrid_keygen()
        store_from_keygen("alice", keys)
        loaded = handle_key_store_load({"name": "alice"})
        assert loaded["stored_as_handle"] is True
        assert loaded["type"] == "hybrid"
        assert "public_key" in loaded["classical"]
        assert "fingerprint" in loaded["classical"]
        assert "secret_key" not in loaded.get("classical", {})
        assert "secret_key" not in loaded.get("pqc", {})

    def test_handle_flat_entry_returns_public_only(self):
        keys = handle_generate_keypair({"algorithm": "ML-DSA-65"})
        store_from_keygen("bob", keys)
        loaded = handle_key_store_load({"name": "bob"})
        assert loaded["stored_as_handle"] is True
        assert "public_key" in loaded
        assert "fingerprint" in loaded
        assert "fingerprint_algorithm" in loaded
        assert "secret_key" not in loaded

    def test_explicit_save_returns_full_data(self):
        keys = hybrid_keygen()
        handle_key_store_save({"name": "raw", "key_data": keys})
        loaded = handle_key_store_load({"name": "raw"})
        assert "secret_key" in loaded["classical"]


class TestHandleList:
    def test_list_shows_stored_as_handle(self):
        keys = hybrid_keygen()
        store_from_keygen("alice", keys)
        handle_key_store_save({"name": "raw", "key_data": keys})
        result = handle_key_store_list({})
        by_name = {k["name"]: k for k in result["keys"]}
        assert by_name["alice"]["stored_as_handle"] is True
        assert by_name["raw"]["stored_as_handle"] is False


class TestTypeValidators:
    def test_require_hybrid_rejects_flat(self):
        keys = handle_generate_keypair({"algorithm": "ML-DSA-65"})
        with pytest.raises(ValueError, match="not a hybrid bundle"):
            _require_hybrid_bundle(keys, "test")

    def test_require_hybrid_accepts_hybrid(self):
        keys = hybrid_keygen()
        _require_hybrid_bundle(keys, "test")  # should not raise

    def test_require_flat_sig_rejects_hybrid(self):
        keys = hybrid_keygen()
        with pytest.raises(ValueError, match="hybrid bundle"):
            _require_flat_signature(keys, "test")

    def test_require_flat_sig_rejects_kem(self):
        keys = handle_generate_keypair({"algorithm": "ML-KEM-768"})
        with pytest.raises(ValueError, match="KEM keypair, not a signing"):
            _require_flat_signature(keys, "test")

    def test_require_flat_sig_accepts_signature(self):
        keys = handle_generate_keypair({"algorithm": "ML-DSA-65"})
        _require_flat_signature(keys, "test")  # should not raise

    def test_require_flat_kem_rejects_signature(self):
        keys = handle_generate_keypair({"algorithm": "ML-DSA-65"})
        with pytest.raises(ValueError, match="Signature keypair, not a KEM"):
            _require_flat_kem(keys, "test")

    def test_require_flat_kem_accepts_kem(self):
        keys = handle_generate_keypair({"algorithm": "ML-KEM-768"})
        _require_flat_kem(keys, "test")  # should not raise


class TestDeleteHandle:
    def test_delete_handle_entry(self):
        keys = hybrid_keygen()
        store_from_keygen("temp", keys)
        handle_key_store_delete({"name": "temp"})
        with pytest.raises(ValueError, match="not found"):
            _resolve_from_store("temp")


from pqc_mcp_server.handlers_hybrid import (
    handle_hybrid_keygen,
    handle_hybrid_seal,
    handle_hybrid_open,
    handle_hybrid_encap,
    handle_hybrid_decap,
    handle_hybrid_auth_seal,
    handle_hybrid_auth_open,
)
from pqc_mcp_server.hybrid import _fingerprint_public_key
import oqs as oqs_mod


def _make_sender():
    sig = oqs_mod.Signature("ML-DSA-65")
    pk = sig.generate_keypair()
    sk = sig.export_secret_key()
    return sk, pk


class TestHybridKeygenStoreAs:
    def test_store_as_returns_no_secrets(self):
        result = handle_hybrid_keygen({"store_as": "alice"})
        assert result["handle"] == "alice"
        assert "secret_key" not in result.get("classical", {})
        assert "secret_key" not in result.get("pqc", {})
        assert "fingerprint" in result["classical"]
        assert "fingerprint" in result["pqc"]

    def test_store_as_collision_fails(self):
        handle_hybrid_keygen({"store_as": "bob"})
        with pytest.raises(ValueError, match="already exists"):
            handle_hybrid_keygen({"store_as": "bob"})

    def test_store_as_overwrite_succeeds(self):
        handle_hybrid_keygen({"store_as": "charlie"})
        result = handle_hybrid_keygen({"store_as": "charlie", "overwrite": True})
        assert result["handle"] == "charlie"

    def test_no_store_as_returns_secrets(self):
        result = handle_hybrid_keygen({})
        assert "secret_key" in result["classical"]


class TestHybridResolution:
    def test_seal_with_store_name(self):
        handle_hybrid_keygen({"store_as": "recipient"})
        result = handle_hybrid_seal(
            {
                "plaintext": "hello",
                "recipient_key_store_name": "recipient",
            }
        )
        assert "envelope" in result

    def test_open_with_store_name(self):
        keys = handle_hybrid_keygen({"store_as": "recipient"})
        # Need full keys for seal (use raw for seal, store for open)
        full_keys = hybrid_keygen()
        store_from_keygen("r2", full_keys, overwrite=True)
        envelope = handle_hybrid_seal(
            {
                "plaintext": "test",
                "recipient_key_store_name": "r2",
            }
        )["envelope"]
        result = handle_hybrid_open(
            {
                "envelope": envelope,
                "key_store_name": "r2",
            }
        )
        assert result["plaintext"] == "test"

    def test_encap_with_store_name(self):
        handle_hybrid_keygen({"store_as": "enc-r"})
        result = handle_hybrid_encap({"key_store_name": "enc-r"})
        assert "shared_secret" in result

    def test_decap_with_store_name(self):
        full_keys = hybrid_keygen()
        store_from_keygen("dec-r", full_keys, overwrite=True)
        encap_result = handle_hybrid_encap({"key_store_name": "dec-r"})
        decap_result = handle_hybrid_decap(
            {
                "key_store_name": "dec-r",
                "x25519_ephemeral_public_key": encap_result["x25519_ephemeral_public_key"],
                "pqc_ciphertext": encap_result["pqc_ciphertext"],
            }
        )
        assert decap_result["shared_secret"] == encap_result["shared_secret"]

    def test_auth_seal_with_both_store_names(self):
        handle_hybrid_keygen({"store_as": "auth-r"})
        sender_sk, sender_pk = _make_sender()
        keys = handle_generate_keypair({"algorithm": "ML-DSA-65"})
        store_from_keygen("auth-s", keys, overwrite=True)
        result = handle_hybrid_auth_seal(
            {
                "plaintext": "authenticated",
                "recipient_key_store_name": "auth-r",
                "sender_key_store_name": "auth-s",
            }
        )
        assert "envelope" in result
        assert result["envelope"]["sender_signature_algorithm"] == "ML-DSA-65"

    def test_auth_open_with_store_name(self):
        full_keys = hybrid_keygen()
        store_from_keygen("ao-r", full_keys, overwrite=True)
        sender_keys = handle_generate_keypair({"algorithm": "ML-DSA-65"})
        store_from_keygen("ao-s", sender_keys, overwrite=True)
        envelope = handle_hybrid_auth_seal(
            {
                "plaintext": "auth test",
                "recipient_key_store_name": "ao-r",
                "sender_key_store_name": "ao-s",
            }
        )["envelope"]
        result = handle_hybrid_auth_open(
            {
                "envelope": envelope,
                "key_store_name": "ao-r",
                "expected_sender_public_key": sender_keys["public_key"],
            }
        )
        assert result["plaintext"] == "auth test"
        assert result["authenticated"] is True


class TestHybridConflicts:
    def test_seal_conflict_store_and_raw(self):
        handle_hybrid_keygen({"store_as": "conflict"})
        with pytest.raises(ValueError, match="not both"):
            handle_hybrid_seal(
                {
                    "plaintext": "x",
                    "recipient_key_store_name": "conflict",
                    "recipient_classical_public_key": "AAAA",
                }
            )

    def test_open_conflict_store_and_raw(self):
        with pytest.raises(ValueError, match="not both"):
            handle_hybrid_open(
                {
                    "envelope": {},
                    "key_store_name": "x",
                    "classical_secret_key": "AAAA",
                }
            )

    def test_auth_seal_sender_conflict(self):
        handle_hybrid_keygen({"store_as": "sc-r"})
        with pytest.raises(ValueError, match="not both"):
            handle_hybrid_auth_seal(
                {
                    "plaintext": "x",
                    "recipient_key_store_name": "sc-r",
                    "sender_key_store_name": "sc-s",
                    "sender_secret_key": "AAAA",
                }
            )


class TestFullRoundtripViaStore:
    def test_seal_open_no_raw_keys(self):
        """Full roundtrip with zero raw keys in any call."""
        full_keys = hybrid_keygen()
        store_from_keygen("rt-recipient", full_keys, overwrite=True)
        envelope = handle_hybrid_seal(
            {
                "plaintext": "store-only roundtrip",
                "recipient_key_store_name": "rt-recipient",
            }
        )["envelope"]
        result = handle_hybrid_open(
            {
                "envelope": envelope,
                "key_store_name": "rt-recipient",
            }
        )
        assert result["plaintext"] == "store-only roundtrip"

    def test_auth_seal_open_no_raw_keys(self):
        """Authenticated roundtrip with zero raw keys except sender binding."""
        full_keys = hybrid_keygen()
        store_from_keygen("art-r", full_keys, overwrite=True)
        sender_keys = handle_generate_keypair({"algorithm": "ML-DSA-65"})
        store_from_keygen("art-s", sender_keys, overwrite=True)
        fp = _fingerprint_public_key(base64.b64decode(sender_keys["public_key"]))
        envelope = handle_hybrid_auth_seal(
            {
                "plaintext": "auth store roundtrip",
                "recipient_key_store_name": "art-r",
                "sender_key_store_name": "art-s",
            }
        )["envelope"]
        result = handle_hybrid_auth_open(
            {
                "envelope": envelope,
                "key_store_name": "art-r",
                "expected_sender_fingerprint": fp,
            }
        )
        assert result["plaintext"] == "auth store roundtrip"
        assert result["authenticated"] is True


class TestGenerateKeypairStoreAs:
    def test_store_as_sig_returns_no_secret(self):
        result = handle_generate_keypair({"algorithm": "ML-DSA-65", "store_as": "gen-sig"})
        assert result["handle"] == "gen-sig"
        assert "secret_key" not in result
        assert "secret_key_size" not in result
        assert "fingerprint" in result
        assert result["fingerprint_algorithm"] == "SHA3-256"

    def test_store_as_kem_returns_no_secret(self):
        result = handle_generate_keypair({"algorithm": "ML-KEM-768", "store_as": "gen-kem"})
        assert result["handle"] == "gen-kem"
        assert "secret_key" not in result
        assert "fingerprint" in result

    def test_store_as_collision_fails(self):
        handle_generate_keypair({"algorithm": "ML-DSA-65", "store_as": "gen-col"})
        with pytest.raises(ValueError, match="already exists"):
            handle_generate_keypair({"algorithm": "ML-DSA-65", "store_as": "gen-col"})

    def test_no_store_as_returns_secrets(self):
        result = handle_generate_keypair({"algorithm": "ML-DSA-65"})
        assert "secret_key" in result


class TestGenericPQCResolution:
    def test_sign_with_store_name(self):
        from pqc_mcp_server.handlers_pqc import handle_sign

        handle_generate_keypair({"algorithm": "ML-DSA-65", "store_as": "signer"})
        result = handle_sign(
            {
                "algorithm": "ML-DSA-65",
                "key_store_name": "signer",
                "message": "hello",
            }
        )
        assert "signature" in result

    def test_verify_with_store_name(self):
        from pqc_mcp_server.handlers_pqc import handle_sign, handle_verify

        handle_generate_keypair({"algorithm": "ML-DSA-65", "store_as": "sv"})
        signed = handle_sign(
            {
                "algorithm": "ML-DSA-65",
                "key_store_name": "sv",
                "message": "hello",
            }
        )
        verified = handle_verify(
            {
                "algorithm": "ML-DSA-65",
                "key_store_name": "sv",
                "message": "hello",
                "signature": signed["signature"],
            }
        )
        assert verified["valid"] is True

    def test_encapsulate_with_store_name(self):
        from pqc_mcp_server.handlers_pqc import handle_encapsulate

        handle_generate_keypair({"algorithm": "ML-KEM-768", "store_as": "kem-enc"})
        result = handle_encapsulate(
            {
                "algorithm": "ML-KEM-768",
                "key_store_name": "kem-enc",
            }
        )
        assert "shared_secret" in result

    def test_decapsulate_with_store_name(self):
        from pqc_mcp_server.handlers_pqc import handle_encapsulate, handle_decapsulate

        keys = handle_generate_keypair({"algorithm": "ML-KEM-768"})
        store_from_keygen("kem-dec", keys, overwrite=True)
        encap = handle_encapsulate(
            {
                "algorithm": "ML-KEM-768",
                "key_store_name": "kem-dec",
            }
        )
        decap = handle_decapsulate(
            {
                "algorithm": "ML-KEM-768",
                "key_store_name": "kem-dec",
                "ciphertext": encap["ciphertext"],
            }
        )
        assert decap["shared_secret"] == encap["shared_secret"]

    def test_sign_verify_roundtrip_via_store(self):
        from pqc_mcp_server.handlers_pqc import handle_sign, handle_verify

        handle_generate_keypair({"algorithm": "ML-DSA-65", "store_as": "svrt"})
        signed = handle_sign(
            {
                "algorithm": "ML-DSA-65",
                "key_store_name": "svrt",
                "message": "roundtrip",
            }
        )
        verified = handle_verify(
            {
                "algorithm": "ML-DSA-65",
                "key_store_name": "svrt",
                "message": "roundtrip",
                "signature": signed["signature"],
            }
        )
        assert verified["valid"] is True


class TestGenericPQCConflicts:
    def test_sign_conflict_store_and_raw(self):
        from pqc_mcp_server.handlers_pqc import handle_sign

        handle_generate_keypair({"algorithm": "ML-DSA-65", "store_as": "sc"})
        with pytest.raises(ValueError, match="not both"):
            handle_sign(
                {
                    "algorithm": "ML-DSA-65",
                    "key_store_name": "sc",
                    "secret_key": "AAAA",
                    "message": "x",
                }
            )


class TestGenericPQCTypeMismatch:
    def test_kem_key_on_sign_fails(self):
        from pqc_mcp_server.handlers_pqc import handle_sign

        handle_generate_keypair({"algorithm": "ML-KEM-768", "store_as": "kem-for-sign"})
        with pytest.raises(ValueError, match="KEM keypair, not a signing"):
            handle_sign(
                {
                    "algorithm": "ML-KEM-768",
                    "key_store_name": "kem-for-sign",
                    "message": "x",
                }
            )

    def test_sig_key_on_encapsulate_fails(self):
        from pqc_mcp_server.handlers_pqc import handle_encapsulate

        handle_generate_keypair({"algorithm": "ML-DSA-65", "store_as": "sig-for-enc"})
        with pytest.raises(ValueError, match="Signature keypair, not a KEM"):
            handle_encapsulate(
                {
                    "algorithm": "ML-DSA-65",
                    "key_store_name": "sig-for-enc",
                }
            )

    def test_algorithm_mismatch_fails(self):
        from pqc_mcp_server.handlers_pqc import handle_sign

        handle_generate_keypair({"algorithm": "ML-DSA-65", "store_as": "alg-mis"})
        with pytest.raises(ValueError, match="Algorithm mismatch"):
            handle_sign(
                {
                    "algorithm": "ML-DSA-44",
                    "key_store_name": "alg-mis",
                    "message": "x",
                }
            )


# ---------------------------------------------------------------------------
# Task 1: Schema tests — raw key fields must not appear in `required`
# ---------------------------------------------------------------------------

RAW_KEY_FIELDS = {
    "public_key",
    "secret_key",
    "classical_public_key",
    "pqc_public_key",
    "classical_secret_key",
    "pqc_secret_key",
    "recipient_classical_public_key",
    "recipient_pqc_public_key",
    "sender_secret_key",
    "sender_public_key",
}

HANDLE_ONLY_TOOLS = {
    "pqc_encapsulate",
    "pqc_decapsulate",
    "pqc_sign",
    "pqc_verify",
    "pqc_hybrid_encap",
    "pqc_hybrid_decap",
    "pqc_hybrid_open",
    "pqc_hybrid_auth_seal",
    "pqc_hybrid_auth_open",
}


class TestSchemaAllowsHandleOnly:
    """Verify that no raw key field is listed as required for the 9 handle-capable tools.

    MCP clients enforce JSON Schema `required` before the handler runs, so any
    raw key field in `required` makes handle-only workflows impossible.
    """

    @pytest.mark.parametrize("tool_name", sorted(HANDLE_ONLY_TOOLS))
    def test_no_raw_key_in_required(self, tool_name):
        tool = next((t for t in PQC_TOOLS if t.name == tool_name), None)
        assert tool is not None, f"Tool {tool_name!r} not found in PQC_TOOLS"
        required = tool.inputSchema.get("required", [])
        overlap = RAW_KEY_FIELDS & set(required)
        assert not overlap, (
            f"Tool {tool_name!r} lists raw key field(s) {overlap!r} in required; "
            "these must be removed so handle-only workflows are possible"
        )


# ---------------------------------------------------------------------------
# Task 2: ML-DSA-65 algorithm validation
# ---------------------------------------------------------------------------


class TestAlgorithmValidation:
    """_resolve_sender must reject non-ML-DSA-65 signing keys."""

    def test_falcon_key_rejected_for_auth_seal(self):
        """A Falcon-512 signing key must be rejected with a clear ML-DSA-65 message."""
        falcon_keys = handle_generate_keypair({"algorithm": "Falcon-512"})
        store_from_keygen("falcon-sender", falcon_keys, overwrite=True)
        with pytest.raises(ValueError, match="ML-DSA-65"):
            _resolve_sender({"sender_key_store_name": "falcon-sender"})

    def test_mldsa65_key_accepted_for_auth_seal(self):
        """An ML-DSA-65 signing key must be accepted without raising."""
        mldsa_keys = handle_generate_keypair({"algorithm": "ML-DSA-65"})
        store_from_keygen("mldsa-sender", mldsa_keys, overwrite=True)
        sk, pk = _resolve_sender({"sender_key_store_name": "mldsa-sender"})
        assert len(sk) > 0
        assert len(pk) > 0

    def test_kem_key_rejected_for_auth_seal(self):
        """A KEM key must be rejected with a 'signing keypair' error (existing behavior)."""
        kem_keys = handle_generate_keypair({"algorithm": "ML-KEM-768"})
        store_from_keygen("kem-sender", kem_keys, overwrite=True)
        with pytest.raises(ValueError, match="signing keypair"):
            _resolve_sender({"sender_key_store_name": "kem-sender"})
