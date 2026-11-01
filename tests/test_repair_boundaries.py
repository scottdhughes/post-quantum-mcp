"""Regressions for byte budgets, native cleanup, and accurate tool labels."""

import base64

import pytest
import oqs

from pqc_mcp_server.handlers_pqc import (
    handle_hash,
    handle_security_analysis,
    handle_encapsulate,
    handle_decapsulate,
)
from pqc_mcp_server.hybrid import hybrid_keygen, hybrid_seal, hybrid_open


def test_large_locally_accepted_seal_opens_its_own_envelope():
    keys = hybrid_keygen()
    d = base64.b64decode
    envelope = hybrid_seal(
        b"a" * 800000, d(keys["classical"]["public_key"]), d(keys["pqc"]["public_key"])
    )
    assert (
        hybrid_open(envelope, d(keys["classical"]["secret_key"]), d(keys["pqc"]["secret_key"]))[
            "plaintext"
        ]
        == "a" * 800000
    )


def test_seal_rejects_decoded_payload_over_one_mebibyte():
    keys = hybrid_keygen()
    d = base64.b64decode
    with pytest.raises(ValueError, match="size|limit"):
        hybrid_seal(
            "é".encode() * 600000, d(keys["classical"]["public_key"]), d(keys["pqc"]["public_key"])
        )


def test_hash_rejects_unimplemented_algorithm_instead_of_mislabeling_sha3():
    with pytest.raises(ValueError, match="algorithm"):
        handle_hash({"message": "test", "algorithm": "NOT-A-HASH"})


def test_security_category_is_not_a_standardization_claim():
    result = handle_security_analysis({"algorithm": "ML-DSA-44"})
    assert result["nist_security_level"] == 2
    assert result["security_bits"] == 128
    assert "SHA-256" in result["classical_security"]
    assert result["standardization_status"] == "FIPS 204"
    assert "not a per-algorithm" in result["quantum_security"]


def test_generic_kem_rejects_truncated_public_key():
    with pytest.raises(ValueError, match="length|bytes"):
        handle_encapsulate(
            {"algorithm": "ML-KEM-768", "public_key": base64.b64encode(b"\0" * 32).decode()}
        )


def test_generic_kem_rejects_truncated_ciphertext():
    with oqs.KeyEncapsulation("ML-KEM-768") as kem:
        kem.generate_keypair()
        sk = kem.export_secret_key()
    with pytest.raises(ValueError, match="length|bytes"):
        handle_decapsulate(
            {
                "algorithm": "ML-KEM-768",
                "secret_key": base64.b64encode(sk).decode(),
                "ciphertext": "AA==",
            }
        )


def test_hybrid_keygen_closes_native_key_material(monkeypatch):
    freed = []
    original = oqs.KeyEncapsulation.free

    def free(self):
        freed.append(self.details["name"])
        return original(self)

    monkeypatch.setattr(oqs.KeyEncapsulation, "free", free)
    hybrid_keygen()
    assert freed == ["ML-KEM-768"]
