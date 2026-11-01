"""MCP Tool definitions and handler functions for relay transport operations.

Provides three relay tools:
  - pqc_relay_deposit: POST an encrypted envelope to a relay mailbox
  - pqc_relay_fetch: GET messages from a relay mailbox
  - pqc_relay_ack: DELETE (acknowledge) a message from a relay mailbox

All handlers accept (arguments: dict, client: RelayClient) and return a
structured dict (never raise). Errors are returned as:
  {"error": "...", "failure_class": "...", "detail": {...}}
"""

from __future__ import annotations

from typing import Any

from mcp.types import Tool

from pqc_mcp_server.relay_client import RelayAllowlistError, RelayError, RelayClient

# ---------------------------------------------------------------------------
# Tool definitions
# ---------------------------------------------------------------------------

RELAY_TOOLS: list[Tool] = [
    Tool(
        name="pqc_relay_deposit",
        description=(
            "Deposit a post-quantum-encrypted envelope into a relay mailbox. "
            "The relay stores the opaque envelope without seeing plaintext or keys."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "relay_url": {
                    "type": "string",
                    "description": "Base URL of the RELAY-SPEC-compliant relay server (must be in the server allowlist)",
                },
                "recipient_fingerprint": {
                    "type": "string",
                    "description": "64-character lowercase hex fingerprint of the recipient key",
                },
                "envelope": {
                    "type": "object",
                    "description": (
                        "Encrypted envelope object to deposit. "
                        "Must include a 'version' field (e.g. 'pqc-mcp-v3') "
                        "and the opaque ciphertext payload."
                    ),
                },
            },
            "required": ["relay_url", "recipient_fingerprint", "envelope"],
        },
    ),
    Tool(
        name="pqc_relay_fetch",
        description=(
            "Fetch pending encrypted envelopes from a relay mailbox. "
            "Returns a list of envelopes waiting for the recipient. "
            "An empty mailbox returns an empty list (not an error)."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "relay_url": {
                    "type": "string",
                    "description": "Base URL of the RELAY-SPEC-compliant relay server (must be in the server allowlist)",
                },
                "recipient_fingerprint": {
                    "type": "string",
                    "description": "64-character lowercase hex fingerprint of the recipient key",
                },
                "cursor": {
                    "type": "string",
                    "description": "Opaque pagination cursor from a previous fetch response (optional)",
                },
            },
            "required": ["relay_url", "recipient_fingerprint"],
        },
    ),
    Tool(
        name="pqc_relay_ack",
        description=(
            "Acknowledge (delete) a message from a relay mailbox after it has been "
            "decrypted and processed. Idempotent — acknowledging an already-deleted "
            "message succeeds silently."
        ),
        inputSchema={
            "type": "object",
            "properties": {
                "relay_url": {
                    "type": "string",
                    "description": "Base URL of the RELAY-SPEC-compliant relay server (must be in the server allowlist)",
                },
                "recipient_fingerprint": {
                    "type": "string",
                    "description": "64-character lowercase hex fingerprint of the recipient key",
                },
                "message_id": {
                    "type": "string",
                    "description": "UUID of the message to acknowledge (from deposit or fetch response)",
                },
            },
            "required": ["relay_url", "recipient_fingerprint", "message_id"],
        },
    ),
]


# ---------------------------------------------------------------------------
# Envelope validation helper
# ---------------------------------------------------------------------------


def _validate_envelope_shape(envelope: Any) -> str | None:
    """Validate that envelope is a dict with a non-empty string 'version' field.

    Returns:
        None if the envelope is valid.
        An error message string if invalid.
    """
    if not isinstance(envelope, dict):
        return f"envelope must be a JSON object, got {type(envelope).__name__}"

    version = envelope.get("version")
    if version is None:
        return "envelope must have a 'version' field"

    if not isinstance(version, str):
        return f"envelope 'version' must be a string, got {type(version).__name__}"

    if not version.strip():
        return "envelope 'version' must be a non-empty string"

    return None


# ---------------------------------------------------------------------------
# Handler functions
# ---------------------------------------------------------------------------


def handle_relay_deposit(arguments: dict[str, Any], client: RelayClient) -> dict[str, Any]:
    """Validate envelope shape, then proxy to client.deposit().

    Returns structured dict on success or error — never raises.
    """
    relay_url = arguments.get("relay_url", "")
    recipient_fp = arguments.get("recipient_fingerprint", "")
    envelope = arguments.get("envelope")

    # Envelope shape validation before any network call
    err_msg = _validate_envelope_shape(envelope)
    if err_msg is not None:
        return {
            "error": err_msg,
            "failure_class": "validation_error",
            "detail": {},
        }

    assert isinstance(envelope, dict)  # established by shape validation above
    try:
        return client.deposit(relay_url, recipient_fp, envelope)
    except RelayAllowlistError as e:
        return {
            "error": str(e),
            "failure_class": "allowlist_rejected",
            "detail": {},
        }
    except RelayError as e:
        return {
            "error": str(e),
            "failure_class": e.failure_class,
            "detail": e.detail or {},
        }
    except Exception as e:
        return {
            "error": str(e),
            "failure_class": "relay_client_error",
            "detail": {},
        }


def handle_relay_fetch(arguments: dict[str, Any], client: RelayClient) -> dict[str, Any]:
    """Fetch envelopes from a relay mailbox, proxy to client.fetch().

    Returns structured dict on success or error — never raises.
    """
    relay_url = arguments.get("relay_url", "")
    recipient_fp = arguments.get("recipient_fingerprint", "")
    cursor = arguments.get("cursor", None)

    try:
        return client.fetch(relay_url, recipient_fp, cursor=cursor)
    except RelayAllowlistError as e:
        return {
            "error": str(e),
            "failure_class": "allowlist_rejected",
            "detail": {},
        }
    except RelayError as e:
        return {
            "error": str(e),
            "failure_class": e.failure_class,
            "detail": e.detail or {},
        }
    except Exception as e:
        return {
            "error": str(e),
            "failure_class": "relay_client_error",
            "detail": {},
        }


def handle_relay_ack(arguments: dict[str, Any], client: RelayClient) -> dict[str, Any]:
    """Acknowledge a relay message, proxy to client.ack().

    Returns structured dict on success or error — never raises.
    """
    relay_url = arguments.get("relay_url", "")
    recipient_fp = arguments.get("recipient_fingerprint", "")
    message_id = arguments.get("message_id", "")

    try:
        return client.ack(relay_url, recipient_fp, message_id)
    except RelayAllowlistError as e:
        return {
            "error": str(e),
            "failure_class": "allowlist_rejected",
            "detail": {},
        }
    except RelayError as e:
        return {
            "error": str(e),
            "failure_class": e.failure_class,
            "detail": e.detail or {},
        }
    except Exception as e:
        return {
            "error": str(e),
            "failure_class": "relay_client_error",
            "detail": {},
        }
