"""End-to-end MCP transport integration tests.

Launches the actual MCP server as a subprocess over stdio and drives it
with a real MCP ClientSession. Proves the full transport path works,
not just the Python handler functions.

Requires liboqs and cryptography installed.
"""

import base64
import os
import pytest

oqs_mod = pytest.importorskip("oqs", reason="liboqs-python not installed")
pytest.importorskip("cryptography", reason="cryptography not installed")

from mcp import ClientSession
from mcp.client.stdio import stdio_client, StdioServerParameters


def _server_params() -> StdioServerParameters:
    """Build params to launch the PQC MCP server as a subprocess."""
    env = dict(os.environ)
    # Ensure liboqs shared library is findable
    home = os.path.expanduser("~")
    extra_paths = f"{home}/.local/lib:/usr/local/lib:/opt/homebrew/lib"
    env["DYLD_LIBRARY_PATH"] = extra_paths + ":" + env.get("DYLD_LIBRARY_PATH", "")
    env["LD_LIBRARY_PATH"] = extra_paths + ":" + env.get("LD_LIBRARY_PATH", "")

    return StdioServerParameters(
        command="uv",
        args=["run", "python", "-m", "pqc_mcp_server"],
        env=env,
    )


async def _call(session: ClientSession, tool_name: str, arguments: dict) -> dict:
    """Call a tool and parse the JSON result."""
    import json

    result = await session.call_tool(tool_name, arguments)
    assert len(result.content) >= 1
    return json.loads(result.content[0].text)


@pytest.mark.asyncio
async def test_anonymous_seal_open_over_stdio():
    """Full anonymous envelope roundtrip over real MCP stdio transport."""
    async with stdio_client(_server_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Generate recipient keys
            keys = await _call(session, "pqc_hybrid_keygen", {})
            assert keys["suite"] == "mlkem768-x25519-sha3-256"
            assert "fingerprint" in keys["classical"]

            # Seal
            seal_result = await _call(
                session,
                "pqc_hybrid_seal",
                {
                    "plaintext": "Hello over MCP stdio!",
                    "recipient_classical_public_key": keys["classical"]["public_key"],
                    "recipient_pqc_public_key": keys["pqc"]["public_key"],
                },
            )
            assert "envelope" in seal_result

            # Open
            open_result = await _call(
                session,
                "pqc_hybrid_open",
                {
                    "envelope": seal_result["envelope"],
                    "classical_secret_key": keys["classical"]["secret_key"],
                    "pqc_secret_key": keys["pqc"]["secret_key"],
                },
            )
            assert open_result["plaintext"] == "Hello over MCP stdio!"


@pytest.mark.asyncio
async def test_authenticated_seal_open_over_stdio():
    """Full authenticated envelope roundtrip over real MCP stdio transport."""
    async with stdio_client(_server_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Generate sender signing keys
            sender = await _call(session, "pqc_generate_keypair", {"algorithm": "ML-DSA-65"})

            # Generate recipient hybrid keys
            recipient = await _call(session, "pqc_hybrid_keygen", {})

            # Auth seal
            seal_result = await _call(
                session,
                "pqc_hybrid_auth_seal",
                {
                    "plaintext": "Authenticated over MCP!",
                    "recipient_classical_public_key": recipient["classical"]["public_key"],
                    "recipient_pqc_public_key": recipient["pqc"]["public_key"],
                    "sender_secret_key": sender["secret_key"],
                    "sender_public_key": sender["public_key"],
                },
            )
            assert "envelope" in seal_result
            assert seal_result["envelope"]["sender_signature_algorithm"] == "ML-DSA-65"

            # Auth open with expected sender key
            open_result = await _call(
                session,
                "pqc_hybrid_auth_open",
                {
                    "envelope": seal_result["envelope"],
                    "classical_secret_key": recipient["classical"]["secret_key"],
                    "pqc_secret_key": recipient["pqc"]["secret_key"],
                    "expected_sender_public_key": sender["public_key"],
                },
            )
            assert open_result["plaintext"] == "Authenticated over MCP!"
            assert open_result["authenticated"] is True


@pytest.mark.asyncio
async def test_wrong_sender_rejection_over_stdio():
    """Wrong sender key returns structured error, not crash, over MCP transport."""
    async with stdio_client(_server_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            sender = await _call(session, "pqc_generate_keypair", {"algorithm": "ML-DSA-65"})
            other = await _call(session, "pqc_generate_keypair", {"algorithm": "ML-DSA-65"})
            recipient = await _call(session, "pqc_hybrid_keygen", {})

            seal_result = await _call(
                session,
                "pqc_hybrid_auth_seal",
                {
                    "plaintext": "test",
                    "recipient_classical_public_key": recipient["classical"]["public_key"],
                    "recipient_pqc_public_key": recipient["pqc"]["public_key"],
                    "sender_secret_key": sender["secret_key"],
                    "sender_public_key": sender["public_key"],
                },
            )

            # Try to open with wrong sender key
            open_result = await _call(
                session,
                "pqc_hybrid_auth_open",
                {
                    "envelope": seal_result["envelope"],
                    "classical_secret_key": recipient["classical"]["secret_key"],
                    "pqc_secret_key": recipient["pqc"]["secret_key"],
                    "expected_sender_public_key": other["public_key"],
                },
            )
            assert "error" in open_result
            assert "Sender verification failed" in open_result["error"]


@pytest.mark.asyncio
async def test_malformed_base64_rejection_over_stdio():
    """Malformed base64 returns structured error over MCP transport."""
    async with stdio_client(_server_params()) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            result = await _call(
                session,
                "pqc_hybrid_encap",
                {
                    "classical_public_key": "not!valid@base64###",
                    "pqc_public_key": "also!bad###",
                },
            )
            assert "error" in result
            assert "Invalid base64" in result["error"]
