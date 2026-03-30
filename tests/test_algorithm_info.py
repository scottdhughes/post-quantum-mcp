"""Tests for algorithm info and security analysis tools.

Requires liboqs to be installed — skipped otherwise.
"""

import pytest

from tests.conftest import requires_liboqs


@requires_liboqs
class TestListAlgorithms:
    @pytest.mark.asyncio
    async def test_list_all(self, call_tool):
        result = await call_tool("pqc_list_algorithms", {"type": "all"})
        assert "kem_algorithms" in result
        assert "sig_algorithms" in result
        assert "nist_standards" in result
        assert len(result["kem_algorithms"]) > 0
        assert len(result["sig_algorithms"]) > 0

    @pytest.mark.asyncio
    async def test_list_kem_only(self, call_tool):
        result = await call_tool("pqc_list_algorithms", {"type": "kem"})
        assert "kem_algorithms" in result
        assert "sig_algorithms" not in result

    @pytest.mark.asyncio
    async def test_list_sig_only(self, call_tool):
        result = await call_tool("pqc_list_algorithms", {"type": "sig"})
        assert "sig_algorithms" in result
        assert "kem_algorithms" not in result

    @pytest.mark.asyncio
    async def test_default_is_all(self, call_tool):
        result = await call_tool("pqc_list_algorithms", {})
        assert "kem_algorithms" in result
        assert "sig_algorithms" in result


@requires_liboqs
class TestAlgorithmInfo:
    @pytest.mark.asyncio
    async def test_kem_info(self, call_tool):
        result = await call_tool("pqc_algorithm_info", {"algorithm": "ML-KEM-768"})
        assert result["type"] == "KEM (Key Encapsulation Mechanism)"
        assert result["public_key_size"] > 0
        assert result["ciphertext_size"] > 0
        assert result["shared_secret_size"] > 0

    @pytest.mark.asyncio
    async def test_sig_info(self, call_tool):
        result = await call_tool("pqc_algorithm_info", {"algorithm": "ML-DSA-65"})
        assert result["type"] == "Digital Signature"
        assert result["public_key_size"] > 0
        assert result["signature_size"] > 0

    @pytest.mark.asyncio
    async def test_unknown_algorithm(self, call_tool):
        result = await call_tool("pqc_algorithm_info", {"algorithm": "FAKE-ALG"})
        assert "error" in result


@requires_liboqs
class TestSecurityAnalysis:
    @pytest.mark.asyncio
    async def test_kem_analysis(self, call_tool):
        result = await call_tool("pqc_security_analysis", {"algorithm": "ML-KEM-768"})
        assert result["quantum_resistant"] is True
        assert result["nist_security_level"] in [1, 2, 3, 4, 5]
        assert "classical_security" in result
        assert "quantum_security" in result

    @pytest.mark.asyncio
    async def test_sig_analysis(self, call_tool):
        result = await call_tool("pqc_security_analysis", {"algorithm": "ML-DSA-65"})
        assert result["type"] == "Signature"
        assert result["quantum_resistant"] is True

    @pytest.mark.asyncio
    async def test_unknown_algorithm(self, call_tool):
        result = await call_tool("pqc_security_analysis", {"algorithm": "NOPE"})
        assert "error" in result
