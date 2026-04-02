"""Tests for KEM (Key Encapsulation Mechanism) operations.

Requires liboqs to be installed — skipped otherwise.
"""

import base64
import pytest

from tests.conftest import requires_liboqs

KEM_ALGORITHMS = ["ML-KEM-512", "ML-KEM-768", "ML-KEM-1024"]


@requires_liboqs
class TestKEMKeypair:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("algorithm", KEM_ALGORITHMS)
    async def test_generate_keypair(self, call_tool, algorithm):
        result = await call_tool("pqc_generate_keypair", {"algorithm": algorithm})
        assert result["algorithm"] == algorithm
        assert result["type"] == "KEM"
        assert result["public_key_size"] > 0
        assert result["secret_key_size"] > 0
        # Keys should be valid base64
        base64.b64decode(result["public_key"])
        base64.b64decode(result["secret_key"])

    @pytest.mark.asyncio
    async def test_keypair_uniqueness(self, call_tool):
        r1 = await call_tool("pqc_generate_keypair", {"algorithm": "ML-KEM-768"})
        r2 = await call_tool("pqc_generate_keypair", {"algorithm": "ML-KEM-768"})
        assert r1["public_key"] != r2["public_key"]

    @pytest.mark.asyncio
    async def test_invalid_algorithm(self, call_tool):
        result = await call_tool("pqc_generate_keypair", {"algorithm": "NOT-A-REAL-ALG"})
        assert "error" in result


@requires_liboqs
class TestKEMEncapDecap:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("algorithm", KEM_ALGORITHMS)
    async def test_encap_decap_roundtrip(self, call_tool, algorithm):
        """Generate keys, encapsulate, decapsulate — shared secrets must match."""
        keypair = await call_tool("pqc_generate_keypair", {"algorithm": algorithm})

        encap = await call_tool(
            "pqc_encapsulate",
            {"algorithm": algorithm, "public_key": keypair["public_key"]},
        )
        assert "shared_secret" in encap
        assert "ciphertext" in encap

        decap = await call_tool(
            "pqc_decapsulate",
            {
                "algorithm": algorithm,
                "secret_key": keypair["secret_key"],
                "ciphertext": encap["ciphertext"],
            },
        )
        assert decap["shared_secret"] == encap["shared_secret"]
        assert decap["shared_secret_hex"] == encap["shared_secret_hex"]

    @pytest.mark.asyncio
    async def test_wrong_secret_key_produces_different_secret(self, call_tool):
        """Decapsulating with the wrong key should not produce the same shared secret."""
        alg = "ML-KEM-768"
        k1 = await call_tool("pqc_generate_keypair", {"algorithm": alg})
        k2 = await call_tool("pqc_generate_keypair", {"algorithm": alg})

        encap = await call_tool(
            "pqc_encapsulate", {"algorithm": alg, "public_key": k1["public_key"]}
        )

        # Decapsulate with wrong key
        decap_wrong = await call_tool(
            "pqc_decapsulate",
            {
                "algorithm": alg,
                "secret_key": k2["secret_key"],
                "ciphertext": encap["ciphertext"],
            },
        )
        # ML-KEM uses implicit rejection — wrong key produces a different secret, not an error
        assert decap_wrong["shared_secret"] != encap["shared_secret"]
