"""Shared fixtures for PQC MCP server tests."""

import json
import pytest

from pqc_mcp_server import server, HAS_LIBOQS

requires_liboqs = pytest.mark.skipif(
    not HAS_LIBOQS,
    reason="liboqs not installed — install liboqs and liboqs-python to run crypto tests",
)


@pytest.fixture
def call_tool():
    """Helper to call a tool and parse the JSON response."""

    async def _call(name: str, arguments: dict) -> dict:
        result = await server.call_tool(name, arguments)
        assert len(result) == 1
        return json.loads(result[0].text)

    return _call
