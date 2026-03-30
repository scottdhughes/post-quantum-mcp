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
    handle_key_store_load,
    handle_key_store_save,
    handle_key_store_list,
    handle_key_store_delete,
    clear_store,
)
from pqc_mcp_server.hybrid import hybrid_keygen
from pqc_mcp_server.handlers_pqc import handle_generate_keypair


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
