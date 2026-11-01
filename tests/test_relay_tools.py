"""Tests for relay_tools.py — Tool definitions and handler functions.

TDD suite:
- TestRelayToolDefinitions: 3 tools defined with correct names and schemas
- TestEnvelopeValidation: _validate_envelope_shape helper
- TestHandleRelayDeposit: deposit handler happy path and error paths
- TestHandleRelayFetch: fetch handler happy path and cursor forwarding
- TestHandleRelayAck: ack handler happy path
- TestGetRelayConfig: _get_relay_config() startup config helper

Use canonical imports; configuration tests never replace global modules.
"""

from __future__ import annotations

import os
import sys
import unittest
from unittest.mock import MagicMock, patch

import pytest

from pqc_mcp_server.relay_tools import (
    RELAY_TOOLS,
    handle_relay_deposit,
    handle_relay_fetch,
    handle_relay_ack,
    _validate_envelope_shape,
)
from pqc_mcp_server.relay_client import RelayAllowlistError, RelayError, RelayConfigError

# A valid 64-char hex fingerprint for use across tests
VALID_FP = "a" * 64
# A valid UUID for use across tests
VALID_MID = "550e8400-e29b-41d4-a716-446655440000"
# A valid envelope
VALID_ENVELOPE = {"version": "pqc-mcp-v3", "ciphertext": "abc123"}


# ---------------------------------------------------------------------------
# TestRelayToolDefinitions
# ---------------------------------------------------------------------------


class TestRelayToolDefinitions(unittest.TestCase):
    """RELAY_TOOLS must define exactly 3 tools with correct names and schemas."""

    def test_three_tools_defined(self):
        assert len(RELAY_TOOLS) == 3

    def test_tool_names(self):
        names = {t.name for t in RELAY_TOOLS}
        assert names == {"pqc_relay_deposit", "pqc_relay_fetch", "pqc_relay_ack"}

    def _get_tool(self, name: str):
        for t in RELAY_TOOLS:
            if t.name == name:
                return t
        raise KeyError(name)

    # --- pqc_relay_deposit ---

    def test_deposit_required_fields(self):
        tool = self._get_tool("pqc_relay_deposit")
        required = tool.inputSchema.get("required", [])
        assert "relay_url" in required
        assert "recipient_fingerprint" in required
        assert "envelope" in required

    def test_deposit_envelope_is_object_type(self):
        tool = self._get_tool("pqc_relay_deposit")
        props = tool.inputSchema["properties"]
        assert props["envelope"]["type"] == "object"

    def test_deposit_envelope_mentions_version(self):
        tool = self._get_tool("pqc_relay_deposit")
        desc = tool.inputSchema["properties"]["envelope"].get("description", "")
        assert "version" in desc.lower()

    # --- pqc_relay_fetch ---

    def test_fetch_required_fields(self):
        tool = self._get_tool("pqc_relay_fetch")
        required = tool.inputSchema.get("required", [])
        assert "relay_url" in required
        assert "recipient_fingerprint" in required

    def test_fetch_cursor_is_optional(self):
        tool = self._get_tool("pqc_relay_fetch")
        required = tool.inputSchema.get("required", [])
        assert "cursor" not in required
        # But cursor should still be a defined property
        props = tool.inputSchema.get("properties", {})
        assert "cursor" in props

    def test_fetch_cursor_is_string(self):
        tool = self._get_tool("pqc_relay_fetch")
        props = tool.inputSchema["properties"]
        assert props["cursor"]["type"] == "string"

    # --- pqc_relay_ack ---

    def test_ack_required_fields(self):
        tool = self._get_tool("pqc_relay_ack")
        required = tool.inputSchema.get("required", [])
        assert "relay_url" in required
        assert "recipient_fingerprint" in required
        assert "message_id" in required


# ---------------------------------------------------------------------------
# TestEnvelopeValidation
# ---------------------------------------------------------------------------


class TestEnvelopeValidation(unittest.TestCase):
    """_validate_envelope_shape must enforce dict + non-empty string version."""

    def test_valid_envelope_returns_none(self):
        result = _validate_envelope_shape({"version": "pqc-mcp-v3", "payload": "x"})
        assert result is None

    def test_rejects_non_dict(self):
        result = _validate_envelope_shape("a string")
        assert result is not None
        assert isinstance(result, str)

    def test_rejects_list(self):
        result = _validate_envelope_shape([{"version": "pqc-mcp-v3"}])
        assert result is not None

    def test_rejects_none(self):
        result = _validate_envelope_shape(None)
        assert result is not None

    def test_rejects_missing_version_key(self):
        result = _validate_envelope_shape({"payload": "abc"})
        assert result is not None

    def test_rejects_version_not_string(self):
        result = _validate_envelope_shape({"version": 3})
        assert result is not None

    def test_rejects_empty_string_version(self):
        result = _validate_envelope_shape({"version": ""})
        assert result is not None

    def test_version_whitespace_only_rejected(self):
        result = _validate_envelope_shape({"version": "   "})
        assert result is not None


# ---------------------------------------------------------------------------
# TestHandleRelayDeposit
# ---------------------------------------------------------------------------


class TestHandleRelayDeposit(unittest.TestCase):
    """handle_relay_deposit must validate envelope shape and proxy to client."""

    def _make_client(self):
        """Return a mock RelayClient with deposit returning success."""
        mock = MagicMock()
        mock.deposit.return_value = {
            "message_id": VALID_MID,
            "deposit_timestamp": "2026-01-01T00:00:00Z",
        }
        return mock

    def test_deposit_accepts_valid_envelope(self):
        client = self._make_client()
        args = {
            "relay_url": "https://relay.example.com",
            "recipient_fingerprint": VALID_FP,
            "envelope": VALID_ENVELOPE,
        }
        result = handle_relay_deposit(args, client)
        assert result["message_id"] == VALID_MID
        client.deposit.assert_called_once_with(
            "https://relay.example.com",
            VALID_FP,
            VALID_ENVELOPE,
        )

    def test_deposit_rejects_envelope_without_version(self):
        client = self._make_client()
        args = {
            "relay_url": "https://relay.example.com",
            "recipient_fingerprint": VALID_FP,
            "envelope": {"payload": "no-version-here"},
        }
        result = handle_relay_deposit(args, client)
        assert "error" in result
        assert result["failure_class"] == "validation_error"
        client.deposit.assert_not_called()

    def test_deposit_rejects_envelope_not_dict(self):
        client = self._make_client()
        args = {
            "relay_url": "https://relay.example.com",
            "recipient_fingerprint": VALID_FP,
            "envelope": "not-a-dict",
        }
        result = handle_relay_deposit(args, client)
        assert "error" in result
        assert result["failure_class"] == "validation_error"
        client.deposit.assert_not_called()

    def test_deposit_rejects_version_not_string(self):
        client = self._make_client()
        args = {
            "relay_url": "https://relay.example.com",
            "recipient_fingerprint": VALID_FP,
            "envelope": {"version": 42},
        }
        result = handle_relay_deposit(args, client)
        assert "error" in result
        assert result["failure_class"] == "validation_error"
        client.deposit.assert_not_called()

    def test_deposit_maps_allowlist_error(self):
        client = MagicMock()
        client.deposit.side_effect = RelayAllowlistError("not in allowlist")
        args = {
            "relay_url": "https://evil.example.com",
            "recipient_fingerprint": VALID_FP,
            "envelope": VALID_ENVELOPE,
        }
        result = handle_relay_deposit(args, client)
        assert "error" in result
        assert result["failure_class"] == "allowlist_rejected"

    def test_deposit_maps_relay_error(self):
        client = MagicMock()
        client.deposit.side_effect = RelayError(
            "server error", "relay_server_error", {"status": 500}
        )
        args = {
            "relay_url": "https://relay.example.com",
            "recipient_fingerprint": VALID_FP,
            "envelope": VALID_ENVELOPE,
        }
        result = handle_relay_deposit(args, client)
        assert "error" in result
        assert result["failure_class"] == "relay_server_error"
        assert result["detail"] == {"status": 500}

    def test_deposit_maps_network_error(self):
        client = MagicMock()
        client.deposit.side_effect = RelayError("timeout", "network_error")
        args = {
            "relay_url": "https://relay.example.com",
            "recipient_fingerprint": VALID_FP,
            "envelope": VALID_ENVELOPE,
        }
        result = handle_relay_deposit(args, client)
        assert "error" in result
        assert result["failure_class"] == "network_error"


# ---------------------------------------------------------------------------
# TestHandleRelayFetch
# ---------------------------------------------------------------------------


class TestHandleRelayFetch(unittest.TestCase):
    """handle_relay_fetch must proxy to client and return envelope list."""

    def _make_client(self, envelopes=None):
        mock = MagicMock()
        mock.fetch.return_value = {
            "envelopes": envelopes or [],
            "next_cursor": None,
            "count": len(envelopes or []),
        }
        return mock

    def test_fetch_returns_envelope_list(self):
        env = [
            {
                "message_id": VALID_MID,
                "envelope": VALID_ENVELOPE,
                "deposited_at": "2026-01-01T00:00:00Z",
            }
        ]
        client = self._make_client(envelopes=env)
        args = {
            "relay_url": "https://relay.example.com",
            "recipient_fingerprint": VALID_FP,
        }
        result = handle_relay_fetch(args, client)
        assert result["count"] == 1
        assert len(result["envelopes"]) == 1
        assert result["envelopes"][0]["message_id"] == VALID_MID

    def test_fetch_without_cursor_passes_none(self):
        client = self._make_client()
        args = {
            "relay_url": "https://relay.example.com",
            "recipient_fingerprint": VALID_FP,
        }
        handle_relay_fetch(args, client)
        client.fetch.assert_called_once_with(
            "https://relay.example.com",
            VALID_FP,
            cursor=None,
        )

    def test_fetch_passes_cursor_when_provided(self):
        client = self._make_client()
        args = {
            "relay_url": "https://relay.example.com",
            "recipient_fingerprint": VALID_FP,
            "cursor": "cursor-xyz",
        }
        handle_relay_fetch(args, client)
        client.fetch.assert_called_once_with(
            "https://relay.example.com",
            VALID_FP,
            cursor="cursor-xyz",
        )

    def test_fetch_maps_relay_error(self):
        client = MagicMock()
        client.fetch.side_effect = RelayError("timeout", "network_error")
        args = {
            "relay_url": "https://relay.example.com",
            "recipient_fingerprint": VALID_FP,
        }
        result = handle_relay_fetch(args, client)
        assert "error" in result
        assert result["failure_class"] == "network_error"

    def test_fetch_maps_allowlist_error(self):
        client = MagicMock()
        client.fetch.side_effect = RelayAllowlistError("blocked")
        args = {
            "relay_url": "https://evil.example.com",
            "recipient_fingerprint": VALID_FP,
        }
        result = handle_relay_fetch(args, client)
        assert "error" in result
        assert result["failure_class"] == "allowlist_rejected"


# ---------------------------------------------------------------------------
# TestHandleRelayAck
# ---------------------------------------------------------------------------


class TestHandleRelayAck(unittest.TestCase):
    """handle_relay_ack must proxy to client and return acknowledged."""

    def _make_client(self):
        mock = MagicMock()
        mock.ack.return_value = {"acknowledged": True, "message_id": VALID_MID}
        return mock

    def test_ack_returns_acknowledged(self):
        client = self._make_client()
        args = {
            "relay_url": "https://relay.example.com",
            "recipient_fingerprint": VALID_FP,
            "message_id": VALID_MID,
        }
        result = handle_relay_ack(args, client)
        assert result["acknowledged"] is True
        assert result["message_id"] == VALID_MID
        client.ack.assert_called_once_with(
            "https://relay.example.com",
            VALID_FP,
            VALID_MID,
        )

    def test_ack_maps_relay_error(self):
        client = MagicMock()
        client.ack.side_effect = RelayError("server error", "relay_server_error", {"status": 503})
        args = {
            "relay_url": "https://relay.example.com",
            "recipient_fingerprint": VALID_FP,
            "message_id": VALID_MID,
        }
        result = handle_relay_ack(args, client)
        assert "error" in result
        assert result["failure_class"] == "relay_server_error"

    def test_ack_maps_allowlist_error(self):
        client = MagicMock()
        client.ack.side_effect = RelayAllowlistError("blocked")
        args = {
            "relay_url": "https://evil.example.com",
            "recipient_fingerprint": VALID_FP,
            "message_id": VALID_MID,
        }
        result = handle_relay_ack(args, client)
        assert "error" in result
        assert result["failure_class"] == "allowlist_rejected"


# ---------------------------------------------------------------------------
# TestGetRelayConfig — startup configuration helper in __init__.py
# ---------------------------------------------------------------------------


class TestGetRelayConfig(unittest.TestCase):
    """_get_relay_config() must gate on PQC_RELAY_ENABLED and validate config."""

    def _load_get_relay_config(self):
        """Configuration is evaluated per call; use the real module identity."""
        from pqc_mcp_server import _get_relay_config

        return _get_relay_config

    def test_returns_none_when_not_enabled(self):
        _get_relay_config = self._load_get_relay_config()
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("PQC_RELAY_ENABLED", None)
            result = _get_relay_config()
        assert result is None

    def test_returns_none_when_enabled_zero(self):
        _get_relay_config = self._load_get_relay_config()
        with patch.dict(os.environ, {"PQC_RELAY_ENABLED": "0"}):
            result = _get_relay_config()
        assert result is None

    def test_raises_relay_config_error_when_enabled_empty_allowlist(self):
        _get_relay_config = self._load_get_relay_config()
        with patch.dict(os.environ, {"PQC_RELAY_ENABLED": "1"}, clear=False):
            os.environ.pop("PQC_RELAY_ALLOWED_URLS", None)
            with pytest.raises(RelayConfigError, match="PQC_RELAY_ALLOWED_URLS is empty"):
                _get_relay_config()

    def test_raises_relay_config_error_when_allowlist_empty_string(self):
        _get_relay_config = self._load_get_relay_config()
        with patch.dict(
            os.environ,
            {"PQC_RELAY_ENABLED": "1", "PQC_RELAY_ALLOWED_URLS": ""},
        ):
            with pytest.raises(RelayConfigError, match="PQC_RELAY_ALLOWED_URLS is empty"):
                _get_relay_config()

    def test_returns_config_dict_with_valid_urls(self):
        _get_relay_config = self._load_get_relay_config()
        with patch.dict(
            os.environ,
            {
                "PQC_RELAY_ENABLED": "1",
                "PQC_RELAY_ALLOWED_URLS": "https://relay.example.com",
            },
        ):
            result = _get_relay_config()
        assert result is not None
        assert "allowed_urls" in result
        assert "https://relay.example.com" in result["allowed_urls"]

    def test_config_dict_has_timeout_keys(self):
        _get_relay_config = self._load_get_relay_config()
        with patch.dict(
            os.environ,
            {
                "PQC_RELAY_ENABLED": "1",
                "PQC_RELAY_ALLOWED_URLS": "https://relay.example.com",
            },
        ):
            result = _get_relay_config()
        assert "timeout_connect" in result
        assert "timeout_read" in result
        assert "timeout_write" in result

    def test_custom_timeout_env_vars_parsed(self):
        _get_relay_config = self._load_get_relay_config()
        with patch.dict(
            os.environ,
            {
                "PQC_RELAY_ENABLED": "1",
                "PQC_RELAY_ALLOWED_URLS": "https://relay.example.com",
                "PQC_RELAY_TIMEOUT_CONNECT": "3.0",
                "PQC_RELAY_TIMEOUT_READ": "20.0",
                "PQC_RELAY_TIMEOUT_WRITE": "7.5",
            },
        ):
            result = _get_relay_config()
        assert result["timeout_connect"] == 3.0
        assert result["timeout_read"] == 20.0
        assert result["timeout_write"] == 7.5


def test_relay_config_loading_preserves_existing_crypto_modules():
    import pqc_mcp_server.hybrid as hybrid

    before = sys.modules["pqc_mcp_server.hybrid"]
    TestGetRelayConfig()._load_get_relay_config()
    assert sys.modules["pqc_mcp_server.hybrid"] is before
    assert sys.modules["pqc_mcp_server.hybrid"].ENVELOPE_VERSION == hybrid.ENVELOPE_VERSION
