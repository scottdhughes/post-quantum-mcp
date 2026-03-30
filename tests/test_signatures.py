"""Tests for digital signature operations.

Requires liboqs to be installed — skipped otherwise.
"""

import base64
import json
import pytest

from tests.conftest import requires_liboqs


SIG_ALGORITHMS = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87"]


@requires_liboqs
class TestSignatureKeypair:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("algorithm", SIG_ALGORITHMS)
    async def test_generate_keypair(self, call_tool, algorithm):
        result = await call_tool("pqc_generate_keypair", {"algorithm": algorithm})
        assert result["algorithm"] == algorithm
        assert result["type"] == "Signature"
        assert result["public_key_size"] > 0
        assert result["secret_key_size"] > 0
        base64.b64decode(result["public_key"])
        base64.b64decode(result["secret_key"])


@requires_liboqs
class TestSignVerify:
    @pytest.mark.asyncio
    @pytest.mark.parametrize("algorithm", SIG_ALGORITHMS)
    async def test_sign_verify_roundtrip(self, call_tool, algorithm):
        keypair = await call_tool("pqc_generate_keypair", {"algorithm": algorithm})

        signed = await call_tool(
            "pqc_sign",
            {
                "algorithm": algorithm,
                "secret_key": keypair["secret_key"],
                "message": "Hello, quantum world!",
            },
        )
        assert "signature" in signed
        assert signed["signature_size"] > 0

        verified = await call_tool(
            "pqc_verify",
            {
                "algorithm": algorithm,
                "public_key": keypair["public_key"],
                "message": "Hello, quantum world!",
                "signature": signed["signature"],
            },
        )
        assert verified["valid"] is True

    @pytest.mark.asyncio
    async def test_wrong_message_fails_verification(self, call_tool):
        alg = "ML-DSA-65"
        keypair = await call_tool("pqc_generate_keypair", {"algorithm": alg})

        signed = await call_tool(
            "pqc_sign",
            {"algorithm": alg, "secret_key": keypair["secret_key"], "message": "original"},
        )

        verified = await call_tool(
            "pqc_verify",
            {
                "algorithm": alg,
                "public_key": keypair["public_key"],
                "message": "tampered",
                "signature": signed["signature"],
            },
        )
        assert verified["valid"] is False

    @pytest.mark.asyncio
    async def test_wrong_key_fails_verification(self, call_tool):
        alg = "ML-DSA-65"
        k1 = await call_tool("pqc_generate_keypair", {"algorithm": alg})
        k2 = await call_tool("pqc_generate_keypair", {"algorithm": alg})

        signed = await call_tool(
            "pqc_sign",
            {"algorithm": alg, "secret_key": k1["secret_key"], "message": "test"},
        )

        verified = await call_tool(
            "pqc_verify",
            {
                "algorithm": alg,
                "public_key": k2["public_key"],
                "message": "test",
                "signature": signed["signature"],
            },
        )
        assert verified["valid"] is False

    @pytest.mark.asyncio
    async def test_empty_message(self, call_tool):
        alg = "ML-DSA-44"
        keypair = await call_tool("pqc_generate_keypair", {"algorithm": alg})

        signed = await call_tool(
            "pqc_sign",
            {"algorithm": alg, "secret_key": keypair["secret_key"], "message": ""},
        )

        verified = await call_tool(
            "pqc_verify",
            {
                "algorithm": alg,
                "public_key": keypair["public_key"],
                "message": "",
                "signature": signed["signature"],
            },
        )
        assert verified["valid"] is True
