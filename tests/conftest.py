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
        payload = result.root if hasattr(result, "root") else result
        content = payload.content
        if payload.isError:
            return {"error": content[0].text}
        assert len(content) >= 1
        return json.loads(content[0].text)

    return _call


@pytest.fixture(autouse=True)
def isolated_replay_state(monkeypatch, tmp_path):
    """Tests never read or modify the user's persistent replay database."""
    from pqc_mcp_server import replay_cache

    monkeypatch.setenv("PQC_STATE_DIR", str(tmp_path / "server-state"))

    monkeypatch.setattr(
        replay_cache,
        "_CACHE",
        replay_cache.SqliteReplayCache(str(tmp_path / "_handler-replay.sqlite3")),
    )
