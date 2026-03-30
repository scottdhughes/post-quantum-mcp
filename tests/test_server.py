"""Tests for PQC MCP server tool registration and basic plumbing."""

import json
import pytest

from mcp.types import ListToolsRequest
from pqc_mcp_server import server, HAS_LIBOQS

EXPECTED_TOOLS = [
    "pqc_list_algorithms",
    "pqc_algorithm_info",
    "pqc_generate_keypair",
    "pqc_encapsulate",
    "pqc_decapsulate",
    "pqc_sign",
    "pqc_verify",
    "pqc_hash_to_curve",
    "pqc_security_analysis",
]


async def _list_tools():
    """Get tool list via the MCP request handler."""
    req = ListToolsRequest(method="tools/list")
    handler = server.request_handlers.get(type(req))
    assert handler is not None
    result = await handler(req)
    return result.root.tools if hasattr(result, "root") else result.tools


@pytest.mark.asyncio
async def test_list_tools_returns_all_expected():
    tools = await _list_tools()
    names = [t.name for t in tools]
    for expected in EXPECTED_TOOLS:
        assert expected in names, f"Missing tool: {expected}"


@pytest.mark.asyncio
async def test_list_tools_have_input_schemas():
    tools = await _list_tools()
    for tool in tools:
        assert tool.inputSchema is not None
        assert tool.inputSchema["type"] == "object"


@pytest.mark.asyncio
async def test_unknown_tool_returns_error(call_tool):
    result = await call_tool("nonexistent_tool", {})
    assert "error" in result
    assert "Unknown tool" in result["error"]


@pytest.mark.asyncio
async def test_hash_to_curve_sha3_256(call_tool):
    """Hash tool doesn't need liboqs — uses stdlib hashlib."""
    result = await call_tool("pqc_hash_to_curve", {"message": "hello", "algorithm": "SHA3-256"})
    assert result["algorithm"] == "SHA3-256"
    assert result["digest_size"] == 32
    assert len(result["digest_hex"]) == 64


@pytest.mark.asyncio
async def test_hash_to_curve_sha3_512(call_tool):
    result = await call_tool("pqc_hash_to_curve", {"message": "hello", "algorithm": "SHA3-512"})
    assert result["digest_size"] == 64


@pytest.mark.asyncio
async def test_hash_to_curve_shake128(call_tool):
    result = await call_tool("pqc_hash_to_curve", {"message": "hello", "algorithm": "SHAKE128"})
    assert result["digest_size"] == 32


@pytest.mark.asyncio
async def test_hash_to_curve_shake256(call_tool):
    result = await call_tool("pqc_hash_to_curve", {"message": "hello", "algorithm": "SHAKE256"})
    assert result["digest_size"] == 64


@pytest.mark.asyncio
async def test_hash_to_curve_default_algorithm(call_tool):
    result = await call_tool("pqc_hash_to_curve", {"message": "test"})
    assert result["algorithm"] == "SHA3-256"


@pytest.mark.asyncio
async def test_hash_to_curve_deterministic(call_tool):
    r1 = await call_tool("pqc_hash_to_curve", {"message": "deterministic"})
    r2 = await call_tool("pqc_hash_to_curve", {"message": "deterministic"})
    assert r1["digest_hex"] == r2["digest_hex"]


@pytest.mark.asyncio
async def test_hash_to_curve_different_inputs(call_tool):
    r1 = await call_tool("pqc_hash_to_curve", {"message": "aaa"})
    r2 = await call_tool("pqc_hash_to_curve", {"message": "bbb"})
    assert r1["digest_hex"] != r2["digest_hex"]
