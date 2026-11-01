"""Tests for relay_client — URL allowlist, HTTPS enforcement, and relay operations.

TDD suite written before implementation:
- TestParseRelayAllowlist: URL parsing, normalization, rejection rules
- TestAllowlistBypass: security/spoofing attack vectors
- TestRelayClientDeposit: deposit() happy path and error paths
- TestRelayClientFetch: fetch() happy path, empty mailbox, cursor
- TestRelayClientAck: ack() success, idempotent 404, invalid message_id

Use canonical imports so exception and module identities remain stable.
"""

import re
import unittest
from unittest.mock import MagicMock, patch

import pytest

from pqc_mcp_server.relay_client import (
    RelayAllowlistError,
    RelayClient,
    RelayConfigError,
    RelayError,
    _validate_fingerprint,
    _validate_message_id,
    check_allowlist,
    parse_relay_allowlist,
)

# A valid 64-char hex fingerprint for use across tests
VALID_FP = "a" * 64
# A valid UUID for use across tests
VALID_MID = "550e8400-e29b-41d4-a716-446655440000"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_allowed(urls):
    """Build a frozenset allowlist without triggering HTTPS enforcement."""
    return frozenset(urls)


# ---------------------------------------------------------------------------
# TestParseRelayAllowlist
# ---------------------------------------------------------------------------


class TestParseRelayAllowlist(unittest.TestCase):
    """parse_relay_allowlist must normalise and validate relay base URLs."""

    def test_single_url(self):
        result = parse_relay_allowlist("https://relay.example.com")
        assert result == frozenset({"https://relay.example.com"})

    def test_multiple_comma_separated(self):
        raw = "https://relay.example.com,https://backup.example.com"
        result = parse_relay_allowlist(raw)
        assert result == frozenset({"https://relay.example.com", "https://backup.example.com"})

    def test_trailing_slash_stripped(self):
        result = parse_relay_allowlist("https://relay.example.com/")
        assert result == frozenset({"https://relay.example.com"})

    def test_hostname_lowercased(self):
        result = parse_relay_allowlist("https://RELAY.EXAMPLE.COM")
        assert result == frozenset({"https://relay.example.com"})

    def test_rejects_http_by_default(self):
        with pytest.raises(RelayConfigError, match="https"):
            parse_relay_allowlist("http://relay.example.com")

    def test_allows_http_with_escape_hatch(self):
        result = parse_relay_allowlist("http://relay.example.com", allow_http=True)
        assert "http://relay.example.com" in result

    def test_rejects_url_with_path(self):
        with pytest.raises(RelayConfigError, match="path"):
            parse_relay_allowlist("https://relay.example.com/some/path")

    def test_rejects_query_string(self):
        with pytest.raises(RelayConfigError, match="query|unexpected"):
            parse_relay_allowlist("https://relay.example.com?foo=bar")

    def test_rejects_fragment(self):
        with pytest.raises(RelayConfigError, match="fragment|unexpected"):
            parse_relay_allowlist("https://relay.example.com#section")

    def test_rejects_userinfo(self):
        with pytest.raises(RelayConfigError, match="userinfo|credentials|unexpected"):
            parse_relay_allowlist("https://user:pass@relay.example.com")

    def test_rejects_no_scheme(self):
        with pytest.raises(RelayConfigError, match="scheme|https"):
            parse_relay_allowlist("relay.example.com")

    def test_empty_string_raises(self):
        with pytest.raises(RelayConfigError):
            parse_relay_allowlist("")

    def test_whitespace_trimmed(self):
        raw = "  https://relay.example.com  ,  https://backup.example.com  "
        result = parse_relay_allowlist(raw)
        assert result == frozenset({"https://relay.example.com", "https://backup.example.com"})

    def test_port_preserved(self):
        """Non-default port must be preserved in canonical form."""
        result = parse_relay_allowlist("https://relay.example.com:8443")
        assert "https://relay.example.com:8443" in result


# ---------------------------------------------------------------------------
# TestAllowlistBypass
# ---------------------------------------------------------------------------


class TestAllowlistBypass(unittest.TestCase):
    """Allowlist check must resist known URL-spoofing / SSRF attack patterns."""

    def setUp(self):
        self.allowed = frozenset({"https://relay.example.com"})

    def test_suffix_attack(self):
        """relay.example.com.evil.com must not match relay.example.com."""
        with pytest.raises(RelayAllowlistError):
            check_allowlist("https://relay.example.com.evil.com", self.allowed)

    def test_url_encoding_attack(self):
        """Percent-encoded hostname characters must not bypass the allowlist."""
        with pytest.raises(RelayAllowlistError):
            check_allowlist("https://example%2ecom", self.allowed)

    def test_case_variation_normalised(self):
        """HTTPS://RELAY.EXAMPLE.COM must match https://relay.example.com."""
        # Provide a normalised URL (as parse_relay_allowlist would produce)
        check_allowlist("https://RELAY.EXAMPLE.COM", self.allowed)  # should not raise

    def test_path_injection(self):
        """URL with path component must not bypass the allowlist."""
        with pytest.raises(RelayAllowlistError):
            check_allowlist("https://relay.example.com/../admin", self.allowed)

    def test_trailing_slash_normalised(self):
        """Trailing slash must be stripped before comparison."""
        # Should not raise — trailing slash normalises away
        check_allowlist("https://relay.example.com/", self.allowed)

    def test_subdomain_not_matched(self):
        """sub.relay.example.com must not match relay.example.com."""
        with pytest.raises(RelayAllowlistError):
            check_allowlist("https://sub.relay.example.com", self.allowed)

    def test_exact_match_succeeds(self):
        """Exact allowlisted URL must pass without error."""
        check_allowlist("https://relay.example.com", self.allowed)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


class TestValidateFingerprint(unittest.TestCase):
    def test_valid_fingerprint(self):
        _validate_fingerprint(VALID_FP)  # must not raise

    def test_too_short(self):
        with pytest.raises(ValueError, match="fingerprint"):
            _validate_fingerprint("a" * 63)

    def test_too_long(self):
        with pytest.raises(ValueError, match="fingerprint"):
            _validate_fingerprint("a" * 65)

    def test_uppercase_rejected(self):
        with pytest.raises(ValueError, match="fingerprint"):
            _validate_fingerprint("A" * 64)

    def test_non_hex_rejected(self):
        with pytest.raises(ValueError, match="fingerprint"):
            _validate_fingerprint("z" * 64)

    def test_empty_rejected(self):
        with pytest.raises(ValueError, match="fingerprint"):
            _validate_fingerprint("")


class TestValidateMessageId(unittest.TestCase):
    def test_valid_uuid(self):
        _validate_message_id(VALID_MID)  # must not raise

    def test_invalid_format(self):
        with pytest.raises(ValueError, match="message_id"):
            _validate_message_id("not-a-uuid")

    def test_empty_rejected(self):
        with pytest.raises(ValueError, match="message_id"):
            _validate_message_id("")


# ---------------------------------------------------------------------------
# TestRelayClientDeposit
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "url",
    [
        "https://relay.example.com?x=1",
        "https://relay.example.com#fragment",
        "https://user@relay.example.com",
        "https://",
        "https://relay.example.com:bad",
    ],
)
def test_runtime_urls_reject_components_that_change_routing(url):
    with pytest.raises(RelayAllowlistError):
        check_allowlist(url, frozenset({"https://relay.example.com"}))


def test_mailbox_credentials_are_sent_only_to_configured_origin():
    import httpx

    origin = "https://relay.example.com"
    seen = []

    def handle(request):
        seen.append(request)
        return httpx.Response(200, json={"messages": [], "next_cursor": None, "count": 0})

    real_client = httpx.Client
    client = RelayClient(
        frozenset({origin}), mailbox_tokens={(origin, VALID_FP): "test-private-token"}
    )
    with patch(
        "pqc_mcp_server.relay_client.httpx.Client",
        lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw),
    ):
        assert client.fetch(origin.upper() + "/", VALID_FP)["count"] == 0
    assert str(seen[0].url) == origin + "/mailboxes/" + VALID_FP
    assert seen[0].headers["Authorization"] == "Bearer test-private-token"


def test_deposits_include_a_stable_envelope_idempotency_key():
    import httpx

    requests = []

    def handle(request):
        requests.append(request)
        return httpx.Response(201, json={"id": VALID_MID, "received_at": "2026-11-01T00:00:00Z"})

    real_client = httpx.Client
    client = RelayClient(frozenset({"https://relay.example.com"}))
    with patch(
        "pqc_mcp_server.relay_client.httpx.Client",
        lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw),
    ):
        client.deposit(
            "https://relay.example.com", VALID_FP, {"version": "v3", "ciphertext": "test"}
        )
        client.deposit(
            "https://relay.example.com", VALID_FP, {"ciphertext": "test", "version": "v3"}
        )
    assert requests[0].headers["Idempotency-Key"] == requests[1].headers["Idempotency-Key"]
    assert len(requests[0].headers["Idempotency-Key"]) == 64


def test_oversized_relay_response_is_rejected():
    import httpx

    real_client = httpx.Client

    def handle(request):
        return httpx.Response(200, content=b"x" * (6 * 1024 * 1024))

    with patch(
        "pqc_mcp_server.relay_client.httpx.Client",
        lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw),
    ):
        with pytest.raises(RelayError, match="size|large"):
            RelayClient(frozenset({"https://relay.example.com"})).fetch(
                "https://relay.example.com", VALID_FP
            )


@pytest.mark.parametrize(
    "method,status,failure",
    [
        ("POST", 400, "relay_client_error"),
        ("POST", 500, "relay_server_error"),
        ("GET", 401, "relay_client_error"),
        ("DELETE", 403, "relay_client_error"),
        ("GET", 302, "relay_client_error"),
    ],
)
def test_http_errors_are_structured_without_echoing_response_secrets(method, status, failure):
    import httpx

    real_client = httpx.Client

    def handle(request):
        return httpx.Response(status, json={"error": "private-token-must-not-leak"})

    client = RelayClient(frozenset({"https://relay.example.com"}))
    with patch(
        "pqc_mcp_server.relay_client.httpx.Client",
        lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw),
    ):
        with pytest.raises(RelayError) as error:
            client._request(method, "https://relay.example.com", VALID_FP)
    assert error.value.failure_class == failure
    assert error.value.detail == {"status": status}
    assert "private-token" not in str(error.value)


@pytest.mark.parametrize("error_type", ["ConnectError", "ReadTimeout", "ReadError"])
def test_transport_errors_have_safe_network_classification(error_type):
    import httpx

    real_client = httpx.Client

    def handle(request):
        raise getattr(httpx, error_type)("private-request-detail")

    with patch(
        "pqc_mcp_server.relay_client.httpx.Client",
        lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw),
    ):
        with pytest.raises(RelayError) as error:
            RelayClient(frozenset({"https://relay.example.com"})).fetch(
                "https://relay.example.com", VALID_FP
            )
    assert error.value.failure_class == "network_error"
    assert "private-request-detail" not in str(error.value)


def test_fetch_maps_messages_and_passes_cursor_and_ack_is_idempotent():
    import httpx

    real_client = httpx.Client

    def handle(request):
        if request.method == "DELETE":
            return httpx.Response(404)
        assert request.url.params["after"] == "cursor-xyz"
        return httpx.Response(
            200,
            json={
                "messages": [
                    {"id": VALID_MID, "envelope": {"ciphertext": "test"}, "received_at": "today"}
                ],
                "next_cursor": None,
            },
        )

    client = RelayClient(frozenset({"https://relay.example.com"}))
    with patch(
        "pqc_mcp_server.relay_client.httpx.Client",
        lambda **kw: real_client(transport=httpx.MockTransport(handle), **kw),
    ):
        data = client.fetch("https://relay.example.com", VALID_FP, cursor="cursor-xyz")
        assert data["envelopes"] == [
            {"message_id": VALID_MID, "envelope": {"ciphertext": "test"}, "deposited_at": "today"}
        ]
        assert client.ack("https://relay.example.com", VALID_FP, VALID_MID)["acknowledged"]
