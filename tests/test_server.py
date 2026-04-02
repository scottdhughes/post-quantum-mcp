"""Tests for PQC MCP server tool registration and basic plumbing."""

import base64
import pytest

from mcp.types import ListToolsRequest
from pqc_mcp_server import server

EXPECTED_TOOLS = [
    "pqc_list_algorithms",
    "pqc_algorithm_info",
    "pqc_generate_keypair",
    "pqc_encapsulate",
    "pqc_decapsulate",
    "pqc_sign",
    "pqc_verify",
    "pqc_hash",
    "pqc_security_analysis",
    "pqc_hybrid_keygen",
    "pqc_hybrid_encap",
    "pqc_hybrid_decap",
    "pqc_hybrid_seal",
    "pqc_hybrid_open",
    "pqc_hybrid_auth_seal",
    "pqc_hybrid_auth_open",
    "pqc_hybrid_auth_verify",
    "pqc_fingerprint",
    "pqc_envelope_inspect",
    "pqc_benchmark",
    "pqc_key_store_save",
    "pqc_key_store_load",
    "pqc_key_store_list",
    "pqc_key_store_delete",
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
async def test_hash_sha3_256(call_tool):
    """Hash tool doesn't need liboqs — uses stdlib hashlib."""
    result = await call_tool("pqc_hash", {"message": "hello", "algorithm": "SHA3-256"})
    assert result["algorithm"] == "SHA3-256"
    assert result["digest_size"] == 32
    assert len(result["digest_hex"]) == 64


@pytest.mark.asyncio
async def test_hash_sha3_512(call_tool):
    result = await call_tool("pqc_hash", {"message": "hello", "algorithm": "SHA3-512"})
    assert result["digest_size"] == 64


@pytest.mark.asyncio
async def test_hash_shake128(call_tool):
    result = await call_tool("pqc_hash", {"message": "hello", "algorithm": "SHAKE128"})
    assert result["digest_size"] == 32


@pytest.mark.asyncio
async def test_hash_shake256(call_tool):
    result = await call_tool("pqc_hash", {"message": "hello", "algorithm": "SHAKE256"})
    assert result["digest_size"] == 64


@pytest.mark.asyncio
async def test_hash_default_algorithm(call_tool):
    result = await call_tool("pqc_hash", {"message": "test"})
    assert result["algorithm"] == "SHA3-256"


@pytest.mark.asyncio
async def test_hash_deterministic(call_tool):
    r1 = await call_tool("pqc_hash", {"message": "deterministic"})
    r2 = await call_tool("pqc_hash", {"message": "deterministic"})
    assert r1["digest_hex"] == r2["digest_hex"]


@pytest.mark.asyncio
async def test_hash_different_inputs(call_tool):
    r1 = await call_tool("pqc_hash", {"message": "aaa"})
    r2 = await call_tool("pqc_hash", {"message": "bbb"})
    assert r1["digest_hex"] != r2["digest_hex"]


@pytest.mark.asyncio
async def test_hybrid_open_wrong_key_returns_structured_error(call_tool):
    """MCP handler should return structured JSON error, not leak an exception."""
    k1_result = await call_tool("pqc_hybrid_keygen", {})
    k2_result = await call_tool("pqc_hybrid_keygen", {})
    seal_result = await call_tool(
        "pqc_hybrid_seal",
        {
            "plaintext": "secret message",
            "recipient_classical_public_key": k1_result["classical"]["public_key"],
            "recipient_pqc_public_key": k1_result["pqc"]["public_key"],
        },
    )
    open_result = await call_tool(
        "pqc_hybrid_open",
        {
            "envelope": seal_result["envelope"],
            "classical_secret_key": k2_result["classical"]["secret_key"],
            "pqc_secret_key": k2_result["pqc"]["secret_key"],
        },
    )
    assert "error" in open_result
    assert "Decryption failed" in open_result["error"]


@pytest.mark.asyncio
async def test_hybrid_encap_malformed_base64_returns_structured_error(call_tool):
    """MCP handler should return structured JSON error for invalid base64."""
    result = await call_tool(
        "pqc_hybrid_encap",
        {
            "classical_public_key": "not!valid@base64###",
            "pqc_public_key": "also!bad###",
        },
    )
    assert "error" in result
    assert "Invalid base64" in result["error"]


@pytest.mark.asyncio
async def test_hybrid_auth_seal_open_happy_path(call_tool):
    """MCP handler: authenticated seal + open roundtrip."""
    # Generate sender signing keys
    sender = await call_tool("pqc_generate_keypair", {"algorithm": "ML-DSA-65"})
    recipient = await call_tool("pqc_hybrid_keygen", {})

    seal_result = await call_tool(
        "pqc_hybrid_auth_seal",
        {
            "plaintext": "authenticated message",
            "recipient_classical_public_key": recipient["classical"]["public_key"],
            "recipient_pqc_public_key": recipient["pqc"]["public_key"],
            "sender_secret_key": sender["secret_key"],
            "sender_public_key": sender["public_key"],
        },
    )
    assert "envelope" in seal_result
    assert seal_result["envelope"]["sender_signature_algorithm"] == "ML-DSA-65"

    open_result = await call_tool(
        "pqc_hybrid_auth_open",
        {
            "envelope": seal_result["envelope"],
            "classical_secret_key": recipient["classical"]["secret_key"],
            "pqc_secret_key": recipient["pqc"]["secret_key"],
            "expected_sender_public_key": sender["public_key"],
        },
    )
    assert open_result["plaintext"] == "authenticated message"
    assert open_result["authenticated"] is True


@pytest.mark.asyncio
async def test_hybrid_auth_open_wrong_sender_returns_structured_error(call_tool):
    """MCP handler: wrong sender key returns structured JSON error."""
    sender = await call_tool("pqc_generate_keypair", {"algorithm": "ML-DSA-65"})
    other_sender = await call_tool("pqc_generate_keypair", {"algorithm": "ML-DSA-65"})
    recipient = await call_tool("pqc_hybrid_keygen", {})

    seal_result = await call_tool(
        "pqc_hybrid_auth_seal",
        {
            "plaintext": "secret",
            "recipient_classical_public_key": recipient["classical"]["public_key"],
            "recipient_pqc_public_key": recipient["pqc"]["public_key"],
            "sender_secret_key": sender["secret_key"],
            "sender_public_key": sender["public_key"],
        },
    )
    open_result = await call_tool(
        "pqc_hybrid_auth_open",
        {
            "envelope": seal_result["envelope"],
            "classical_secret_key": recipient["classical"]["secret_key"],
            "pqc_secret_key": recipient["pqc"]["secret_key"],
            "expected_sender_public_key": other_sender["public_key"],
        },
    )
    assert "error" in open_result
    assert "Sender verification failed" in open_result["error"]


@pytest.mark.asyncio
async def test_hybrid_auth_open_missing_sender_binding_returns_error(call_tool):
    """MCP handler: missing sender identity returns structured JSON error."""
    sender = await call_tool("pqc_generate_keypair", {"algorithm": "ML-DSA-65"})
    recipient = await call_tool("pqc_hybrid_keygen", {})

    seal_result = await call_tool(
        "pqc_hybrid_auth_seal",
        {
            "plaintext": "test",
            "recipient_classical_public_key": recipient["classical"]["public_key"],
            "recipient_pqc_public_key": recipient["pqc"]["public_key"],
            "sender_secret_key": sender["secret_key"],
            "sender_public_key": sender["public_key"],
        },
    )
    open_result = await call_tool(
        "pqc_hybrid_auth_open",
        {
            "envelope": seal_result["envelope"],
            "classical_secret_key": recipient["classical"]["secret_key"],
            "pqc_secret_key": recipient["pqc"]["secret_key"],
            # No expected_sender_public_key or expected_sender_fingerprint
        },
    )
    assert "error" in open_result
    assert "Sender verification failed" in open_result["error"]


@pytest.mark.asyncio
async def test_hybrid_auth_open_wrong_recipient_returns_decrypt_error(call_tool):
    """MCP handler: wrong recipient key returns decrypt failure, not auth failure."""
    sender = await call_tool("pqc_generate_keypair", {"algorithm": "ML-DSA-65"})
    r1 = await call_tool("pqc_hybrid_keygen", {})
    r2 = await call_tool("pqc_hybrid_keygen", {})

    seal_result = await call_tool(
        "pqc_hybrid_auth_seal",
        {
            "plaintext": "test",
            "recipient_classical_public_key": r1["classical"]["public_key"],
            "recipient_pqc_public_key": r1["pqc"]["public_key"],
            "sender_secret_key": sender["secret_key"],
            "sender_public_key": sender["public_key"],
        },
    )
    open_result = await call_tool(
        "pqc_hybrid_auth_open",
        {
            "envelope": seal_result["envelope"],
            "classical_secret_key": r2["classical"]["secret_key"],
            "pqc_secret_key": r2["pqc"]["secret_key"],
            "expected_sender_public_key": sender["public_key"],
        },
    )
    assert "error" in open_result
    assert "Decryption failed" in open_result["error"]


@pytest.mark.asyncio
async def test_hybrid_auth_seal_malformed_base64_returns_error(call_tool):
    """MCP handler: malformed base64 in auth_seal returns structured error."""
    result = await call_tool(
        "pqc_hybrid_auth_seal",
        {
            "plaintext": "test",
            "recipient_classical_public_key": "not!valid###",
            "recipient_pqc_public_key": "also!bad###",
            "sender_secret_key": "bad!key###",
            "sender_public_key": "bad!key###",
        },
    )
    assert "error" in result
    assert "Invalid base64" in result["error"]


@pytest.mark.asyncio
async def test_hybrid_auth_seal_exactly_one_plaintext(call_tool):
    """MCP handler: both plaintext and plaintext_base64 returns error."""
    sender = await call_tool("pqc_generate_keypair", {"algorithm": "ML-DSA-65"})
    recipient = await call_tool("pqc_hybrid_keygen", {})
    result = await call_tool(
        "pqc_hybrid_auth_seal",
        {
            "plaintext": "hello",
            "plaintext_base64": base64.b64encode(b"hello").decode(),
            "recipient_classical_public_key": recipient["classical"]["public_key"],
            "recipient_pqc_public_key": recipient["pqc"]["public_key"],
            "sender_secret_key": sender["secret_key"],
            "sender_public_key": sender["public_key"],
        },
    )
    assert "error" in result
    assert "exactly one" in result["error"]


@pytest.mark.asyncio
async def test_fingerprint_tool(call_tool):
    """pqc_fingerprint computes SHA3-256 hex fingerprint."""
    keys = await call_tool("pqc_hybrid_keygen", {})
    result = await call_tool("pqc_fingerprint", {"public_key": keys["classical"]["public_key"]})
    assert "fingerprint" in result
    assert len(result["fingerprint"]) == 64  # SHA3-256 hex
    assert result["algorithm"] == "SHA3-256"
    # Must match the fingerprint already in keygen output
    assert result["fingerprint"] == keys["classical"]["fingerprint"]


@pytest.mark.asyncio
async def test_fingerprint_tool_malformed_base64(call_tool):
    result = await call_tool("pqc_fingerprint", {"public_key": "not!valid###"})
    assert "error" in result
    assert "Invalid base64" in result["error"]


@pytest.mark.asyncio
async def test_keygen_includes_fingerprints(call_tool):
    """pqc_hybrid_keygen now returns fingerprints for both key types."""
    keys = await call_tool("pqc_hybrid_keygen", {})
    assert "fingerprint" in keys["classical"]
    assert "fingerprint" in keys["pqc"]
    assert len(keys["classical"]["fingerprint"]) == 64
    assert len(keys["pqc"]["fingerprint"]) == 64


@pytest.mark.asyncio
async def test_store_as_via_mcp_returns_handle(call_tool):
    """store_as through MCP handler returns no secrets."""
    result = await call_tool("pqc_hybrid_keygen", {"store_as": "mcp-alice"})
    assert result["handle"] == "mcp-alice"
    assert "secret_key" not in result.get("classical", {})
    assert "secret_key" not in result.get("pqc", {})


@pytest.mark.asyncio
async def test_key_store_name_via_mcp_resolves(call_tool):
    """key_store_name through MCP handler resolves correctly."""
    # Generate and store
    await call_tool("pqc_hybrid_keygen", {"store_as": "mcp-bob"})
    # Seal using store name
    seal_result = await call_tool(
        "pqc_hybrid_seal",
        {
            "plaintext": "mcp store test",
            "recipient_key_store_name": "mcp-bob",
        },
    )
    assert "envelope" in seal_result


@pytest.mark.asyncio
async def test_store_name_error_via_mcp(call_tool):
    """Nonexistent store name returns structured JSON error via MCP."""
    result = await call_tool(
        "pqc_hybrid_seal",
        {
            "plaintext": "x",
            "recipient_key_store_name": "nonexistent",
        },
    )
    assert "error" in result
    assert "not found" in result["error"]


@pytest.mark.asyncio
async def test_conflict_error_via_mcp(call_tool):
    """Both store name and raw keys returns structured JSON error via MCP."""
    await call_tool("pqc_hybrid_keygen", {"store_as": "mcp-conflict"})
    result = await call_tool(
        "pqc_hybrid_seal",
        {
            "plaintext": "x",
            "recipient_key_store_name": "mcp-conflict",
            "recipient_classical_public_key": "AAAA",
        },
    )
    assert "error" in result
    assert "not both" in result["error"]
