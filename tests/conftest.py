"""Shared fixtures for PQC MCP server tests."""

import json
import pytest

from mcp.types import CallToolRequest, CallToolRequestParams
from pqc_mcp_server import server, HAS_LIBOQS

requires_liboqs = pytest.mark.skipif(
    not HAS_LIBOQS,
    reason="liboqs not installed — install liboqs and liboqs-python to run crypto tests",
)


@pytest.fixture
def call_tool():
    """Helper to call a tool via the MCP request handler and parse the JSON response."""

    async def _call(name: str, arguments: dict) -> dict:
        req = CallToolRequest(
            method="tools/call",
            params=CallToolRequestParams(name=name, arguments=arguments),
        )
        handler = server.request_handlers.get(type(req))
        assert handler is not None, f"No handler registered for {type(req)}"
        result = await handler(req)
        content = result.root.content if hasattr(result, "root") else result.content
        assert len(content) >= 1
        return json.loads(content[0].text)

    return _call
