"""Tests for key store, benchmark, and envelope inspection tools."""

import base64
import pytest

oqs = pytest.importorskip("oqs", reason="liboqs-python not installed")
pytest.importorskip("cryptography", reason="cryptography not installed")

from pqc_mcp_server.key_store import (
    handle_key_store_save,
    handle_key_store_load,
    handle_key_store_list,
    handle_key_store_delete,
    clear_store,
)
from pqc_mcp_server.handlers_pqc import handle_benchmark
from pqc_mcp_server.handlers_hybrid import handle_envelope_inspect
from pqc_mcp_server.hybrid import (
    ENVELOPE_VERSION,
    hybrid_keygen,
    hybrid_seal,
    hybrid_auth_seal,
    _fingerprint_public_key,
)
import oqs as oqs_mod


@pytest.fixture(autouse=True)
def clean_store():
    """Clear the key store before and after each test."""
    clear_store()
    yield
    clear_store()


class TestKeyStore:
    def test_save_and_load_hybrid_keys(self):
        keys = hybrid_keygen()
        result = handle_key_store_save({"name": "alice", "key_data": keys})
        assert result["saved"] == "alice"
        assert result["type"] == "hybrid"

        loaded = handle_key_store_load({"name": "alice"})
        assert loaded["suite"] == keys["suite"]
        assert loaded["classical"]["public_key"] == keys["classical"]["public_key"]

    def test_save_and_load_signing_keys(self):
        sig = oqs_mod.Signature("ML-DSA-65")
        pk = sig.generate_keypair()
        sk = sig.export_secret_key()
        key_data = {
            "algorithm": "ML-DSA-65",
            "type": "Signature",
            "public_key": base64.b64encode(pk).decode(),
            "secret_key": base64.b64encode(sk).decode(),
        }
        result = handle_key_store_save({"name": "alice-sig", "key_data": key_data})
        assert result["saved"] == "alice-sig"
        assert result["type"] == "signature"

        loaded = handle_key_store_load({"name": "alice-sig"})
        assert loaded["algorithm"] == "ML-DSA-65"

    def test_load_nonexistent_returns_error(self):
        result = handle_key_store_load({"name": "nonexistent"})
        assert "error" in result

    def test_list_empty(self):
        result = handle_key_store_list({})
        assert result["count"] == 0
        assert result["keys"] == []

    def test_list_with_keys(self):
        keys = hybrid_keygen()
        handle_key_store_save({"name": "alice", "key_data": keys})
        handle_key_store_save({"name": "bob", "key_data": keys})
        result = handle_key_store_list({})
        assert result["count"] == 2
        names = [k["name"] for k in result["keys"]]
        assert "alice" in names
        assert "bob" in names
        # List should include fingerprints but not secret keys
        for k in result["keys"]:
            assert "classical_fingerprint" in k
            assert "secret_key" not in k

    def test_delete(self):
        keys = hybrid_keygen()
        handle_key_store_save({"name": "temp", "key_data": keys})
        result = handle_key_store_delete({"name": "temp"})
        assert result["deleted"] == "temp"
        assert "error" in handle_key_store_load({"name": "temp"})

    def test_delete_nonexistent_returns_error(self):
        result = handle_key_store_delete({"name": "ghost"})
        assert "error" in result

    def test_overwrite_existing_key(self):
        keys1 = hybrid_keygen()
        keys2 = hybrid_keygen()
        handle_key_store_save({"name": "alice", "key_data": keys1})
        handle_key_store_save({"name": "alice", "key_data": keys2})
        loaded = handle_key_store_load({"name": "alice"})
        assert loaded["classical"]["public_key"] == keys2["classical"]["public_key"]

    def test_save_rejects_non_dict(self):
        with pytest.raises(ValueError, match="must be a JSON object"):
            handle_key_store_save({"name": "bad", "key_data": "not a dict"})


class TestBenchmark:
    def test_benchmark_kem(self):
        result = handle_benchmark({"algorithm": "ML-KEM-768", "iterations": 3})
        assert result["algorithm"] == "ML-KEM-768"
        assert result["type"] == "KEM"
        assert "keygen" in result["timing_ms"]
        assert "encap" in result["timing_ms"]
        assert "decap" in result["timing_ms"]
        assert result["sizes_bytes"]["public_key"] > 0
        assert result["iterations"] == 3

    def test_benchmark_signature(self):
        result = handle_benchmark({"algorithm": "ML-DSA-65", "iterations": 3})
        assert result["algorithm"] == "ML-DSA-65"
        assert result["type"] == "Signature"
        assert "keygen" in result["timing_ms"]
        assert "sign" in result["timing_ms"]
        assert "verify" in result["timing_ms"]
        assert result["sizes_bytes"]["signature"] > 0

    def test_benchmark_caps_iterations(self):
        result = handle_benchmark({"algorithm": "ML-KEM-768", "iterations": 999})
        assert result["iterations"] == 100

    def test_benchmark_default_iterations(self):
        result = handle_benchmark({"algorithm": "ML-KEM-768"})
        assert result["iterations"] == 10


class TestEnvelopeInspect:
    def test_inspect_anonymous_envelope(self):
        keys = hybrid_keygen()
        envelope = hybrid_seal(
            b"test data",
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
        )
        result = handle_envelope_inspect({"envelope": envelope})
        assert result["version"] == ENVELOPE_VERSION
        assert result["suite"] == "mlkem768-x25519-sha3-256"
        assert result["authenticated"] is False
        assert result["ciphertext_size"] > 0
        assert result["plaintext_size_approx"] > 0
        assert result["pqc_ciphertext_size"] > 0
        assert result["x25519_ephemeral_public_key_size"] == 32

    def test_inspect_authenticated_envelope(self):
        keys = hybrid_keygen()
        sig = oqs_mod.Signature("ML-DSA-65")
        sender_pk = sig.generate_keypair()
        sender_sk = sig.export_secret_key()
        envelope = hybrid_auth_seal(
            b"auth test",
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
            sender_sk,
            sender_pk,
        )
        result = handle_envelope_inspect({"envelope": envelope})
        assert result["authenticated"] is True
        assert result["sender_signature_algorithm"] == "ML-DSA-65"
        assert result["sender_key_fingerprint"] == _fingerprint_public_key(sender_pk)
        assert result["signature_size"] > 0
        assert "recipient_classical_key_fingerprint" in result
        assert "recipient_pqc_key_fingerprint" in result
