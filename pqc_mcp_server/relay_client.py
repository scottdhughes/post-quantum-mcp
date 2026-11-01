"""HTTPS client for RELAY-SPEC-compliant relay servers.

The relay stores opaque post-quantum-encrypted envelopes in transactional mailboxes.
It never sees plaintext or keys. This client only constructs
/mailboxes/:fp paths with fixed HTTP verbs — no arbitrary request
building is possible.

URL security model:
- All relay_url arguments are checked against a pre-configured allowlist
  before any HTTP call is made.
- HTTPS is required by default; http:// is only permitted with the explicit
  allow_http=True escape hatch (test environments only).
- Allowlist entries are normalised at parse time (trailing slash stripped,
  hostname lowercased) so that runtime check_allowlist() is an exact match.
"""

from __future__ import annotations

import re
import hashlib
import json
import math
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlparse

import httpx

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class RelayConfigError(Exception):
    """Startup-fatal configuration error (bad allowlist, missing env var, etc.)."""


class RelayAllowlistError(Exception):
    """Raised when a relay_url is not in the configured allowlist."""


class RelayError(Exception):
    """Relay communication error with structured failure context.

    Attributes:
        failure_class: One of "validation_error", "network_error",
                       "relay_client_error" (4xx), "relay_server_error" (5xx).
        detail: Optional dict with additional context (e.g. {"status": N, "body": ...}).
    """

    def __init__(
        self,
        message: str,
        failure_class: str,
        detail: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.failure_class = failure_class
        self.detail = detail


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

_FP_RE = re.compile(r"^[a-f0-9]{64}$")
# Simplified UUID pattern — matches standard 8-4-4-4-12 hex groups.
_UUID_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    re.IGNORECASE,
)


def _validate_fingerprint(fp: str) -> None:
    """Raise ValueError if fp is not a 64-char lowercase hex string."""
    if not isinstance(fp, str) or not _FP_RE.fullmatch(fp):
        raise ValueError(f"Invalid fingerprint {fp!r}: must match ^[a-f0-9]{{64}}$")


def _validate_message_id(mid: str) -> None:
    """Raise ValueError if mid is not a UUID-format string."""
    if not isinstance(mid, str) or not _UUID_RE.fullmatch(mid):
        raise ValueError(
            f"Invalid message_id {mid!r}: must be UUID format "
            "(xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)"
        )


# ---------------------------------------------------------------------------
# URL allowlist
# ---------------------------------------------------------------------------


def _normalise_relay_url(raw: str, *, allow_http: bool = False) -> str:
    """Validate once and return the only origin that may build request URLs."""
    if not isinstance(raw, str) or not raw or any(c.isspace() for c in raw):
        raise RelayConfigError("Invalid relay URL")
    try:
        parsed = urlparse(raw)
        if parsed.scheme not in ("https", "http"):
            raise RelayConfigError("Relay URL requires an https scheme")
        if parsed.scheme == "http" and not allow_http:
            raise RelayConfigError("Only https:// is allowed")
        if parsed.username is not None or parsed.password is not None:
            raise RelayConfigError("Relay URL userinfo credentials are not allowed")
        if "?" in raw:
            raise RelayConfigError("Relay URL query is not allowed")
        if "#" in raw:
            raise RelayConfigError("Relay URL fragment is not allowed")
        if parsed.path not in ("", "/") or parsed.params:
            raise RelayConfigError("Relay URL path is not allowed")
        host = parsed.hostname
        port = parsed.port
        if not host or "%" in host or "\\" in host or port == 0:
            raise RelayConfigError("Invalid relay host or port")
        host = host.lower()
        if ":" in host:
            host = f"[{host}]"
        return f"{parsed.scheme}://{host}" + (f":{port}" if port else "")
    except ValueError as exc:
        raise RelayConfigError("Invalid relay host or port") from exc


def parse_relay_allowlist(raw: str, *, allow_http: bool = False) -> frozenset[str]:
    if not isinstance(raw, str) or not raw.strip():
        raise RelayConfigError("relay allowlist is empty — at least one URL required")
    result = frozenset(
        _normalise_relay_url(x.strip(), allow_http=allow_http) for x in raw.split(",") if x.strip()
    )
    if not result:
        raise RelayConfigError("relay allowlist is empty after parsing")
    return result


def check_allowlist(relay_url: str, allowed: frozenset[str]) -> None:
    try:
        canonical = _normalise_relay_url(relay_url, allow_http=True)
    except RelayConfigError as exc:
        raise RelayAllowlistError(str(exc)) from exc
    if canonical not in allowed:
        raise RelayAllowlistError("Relay URL is not in the configured allowlist")


# ---------------------------------------------------------------------------
# RelayClient
# ---------------------------------------------------------------------------


class RelayClient:
    """Bounded HTTPS relay client; credentials are configured outside tool arguments."""

    def __init__(
        self,
        allowed_urls: frozenset[str],
        *,
        timeout_connect: float = 5.0,
        timeout_read: float = 15.0,
        timeout_write: float = 10.0,
        mailbox_tokens: Mapping[tuple[str, str], str] | None = None,
    ) -> None:
        self._allowed_urls = allowed_urls
        for value in (timeout_connect, timeout_read, timeout_write):
            if not math.isfinite(value) or value <= 0:
                raise RelayConfigError("Relay timeouts must be finite positive numbers")
        self._timeout = httpx.Timeout(
            connect=timeout_connect, read=timeout_read, write=timeout_write, pool=timeout_connect
        )
        self._tokens: dict[tuple[str, str], str] = {}
        for (origin, fp), token in (mailbox_tokens or {}).items():
            check_allowlist(origin, allowed_urls)
            _validate_fingerprint(fp)
            if (
                not isinstance(token, str)
                or not token
                or len(token) > 512
                or any(c.isspace() for c in token)
            ):
                raise RelayConfigError("Invalid mailbox credential")
            self._tokens[(_normalise_relay_url(origin, allow_http=True), fp)] = token

    def _request(
        self,
        method: str,
        relay_url: str,
        fp: str,
        *,
        message_id: str | None = None,
        envelope: dict | None = None,
        cursor: str | None = None,
    ) -> dict[str, Any]:
        _validate_fingerprint(fp)
        check_allowlist(relay_url, self._allowed_urls)
        origin = _normalise_relay_url(relay_url, allow_http=True)
        url = f"{origin}/mailboxes/{fp}"
        headers: dict[str, str] = {}
        params: dict[str, str] = {}
        body: bytes | None = None
        if message_id is not None:
            _validate_message_id(message_id)
            url += f"/{message_id}"
        if method in ("GET", "DELETE"):
            token = self._tokens.get((origin, fp))
            if token:
                headers["Authorization"] = f"Bearer {token}"
        if envelope is not None:
            body = json.dumps(
                envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
            ).encode("utf-8")
            if len(body) > 51200:
                raise RelayError(
                    "Envelope exceeds relay size limit (51200 bytes)", "validation_error"
                )
            headers["Content-Type"] = "application/json"
            headers["Idempotency-Key"] = hashlib.sha256(body).hexdigest()
        if cursor is not None:
            if not isinstance(cursor, str) or len(cursor) > 256:
                raise RelayError("Invalid relay cursor", "validation_error")
            params["after"] = cursor
        try:
            with httpx.Client(
                timeout=self._timeout, follow_redirects=False, trust_env=False
            ) as client:
                with client.stream(
                    method, url, headers=headers, params=params, content=body
                ) as response:
                    status = response.status_code
                    if method == "DELETE" and status == 404:
                        return {}
                    # Do not reflect untrusted error bodies; servers can echo credentials.
                    if not 200 <= status < 300:
                        failure = "relay_server_error" if status >= 500 else "relay_client_error"
                        raise RelayError(
                            f"Relay returned HTTP {status}", failure, {"status": status}
                        )
                    chunks: list[bytes] = []
                    size = 0
                    for chunk in response.iter_bytes():
                        size += len(chunk)
                        if size > 6_000_000:
                            raise RelayError(
                                "Relay response exceeds size limit", "relay_server_error"
                            )
                        chunks.append(chunk)
            data = json.loads(b"".join(chunks))
            if not isinstance(data, dict):
                raise ValueError("Expected object")
            return data
        except httpx.HTTPError as exc:
            raise RelayError("Relay network request failed", "network_error") from exc
        except (ValueError, UnicodeError) as exc:
            raise RelayError("Relay returned invalid JSON", "relay_server_error") from exc

    def deposit(self, relay_url: str, recipient_fp: str, envelope: dict) -> dict[str, Any]:
        data = self._request("POST", relay_url, recipient_fp, envelope=envelope)
        if not isinstance(data.get("id"), str) or not isinstance(data.get("received_at"), str):
            raise RelayError("Invalid deposit response", "relay_server_error")
        _validate_message_id(data["id"])
        return {"message_id": data["id"], "deposit_timestamp": data["received_at"]}

    def fetch(self, relay_url: str, recipient_fp: str, cursor: str | None = None) -> dict[str, Any]:
        data = self._request("GET", relay_url, recipient_fp, cursor=cursor)
        messages = data.get("messages")
        next_cursor = data.get("next_cursor")
        if (
            not isinstance(messages, list)
            or len(messages) > 100
            or (next_cursor is not None and not isinstance(next_cursor, str))
        ):
            raise RelayError("Invalid fetch response", "relay_server_error")
        envelopes = []
        for msg in messages:
            if (
                not isinstance(msg, dict)
                or not isinstance(msg.get("id"), str)
                or not isinstance(msg.get("envelope"), dict)
            ):
                raise RelayError("Invalid message response", "relay_server_error")
            _validate_message_id(msg["id"])
            envelopes.append(
                {
                    "message_id": msg["id"],
                    "envelope": msg["envelope"],
                    "deposited_at": msg.get("received_at"),
                }
            )
        return {"envelopes": envelopes, "next_cursor": next_cursor, "count": len(envelopes)}

    def ack(self, relay_url: str, recipient_fp: str, message_id: str) -> dict[str, Any]:
        self._request("DELETE", relay_url, recipient_fp, message_id=message_id)
        return {"acknowledged": True, "message_id": message_id}
