"""
Post-Quantum Cryptography MCP Server

Provides MCP tools for post-quantum cryptographic operations using:
- ML-KEM for key encapsulation (FIPS 203)
- ML-DSA for digital signatures (FIPS 204)
- SLH-DSA for hash-based signatures (FIPS 205)
- Hybrid X25519 + ML-KEM-768 key exchange
- Sender-authenticated envelopes (ML-DSA-65)

Uses liboqs (Open Quantum Safe) as the cryptographic backend.
Research/prototyping only — not recommended for production.
"""

import binascii
import json
from typing import Any
import asyncio

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from pqc_mcp_server.tools import PQC_TOOLS

# --- Dependency availability flags ---

try:
    import oqs  # noqa: F401

    HAS_LIBOQS = True
except (ImportError, RuntimeError, OSError):
    HAS_LIBOQS = False

try:
    from cryptography.exceptions import InvalidTag
    from pqc_mcp_server.hybrid import SenderVerificationError

    HAS_HYBRID = True
except (ImportError, RuntimeError, OSError):
    HAS_HYBRID = False

    class InvalidTag(Exception):  # type: ignore[no-redef]
        pass

    class SenderVerificationError(Exception):  # type: ignore[no-redef]
        pass


# --- Handler registry ---

# PQC handlers (require liboqs only)
_PQC_HANDLERS: dict[str, Any] = {}
# Hybrid handlers (require liboqs + cryptography)
_HYBRID_HANDLERS: dict[str, Any] = {}

if HAS_LIBOQS:
    from pqc_mcp_server.handlers_pqc import (
        handle_list_algorithms,
        handle_algorithm_info,
        handle_generate_keypair,
        handle_encapsulate,
        handle_decapsulate,
        handle_sign,
        handle_verify,
        handle_hash,
        handle_security_analysis,
        handle_benchmark,
    )

    _PQC_HANDLERS = {
        "pqc_list_algorithms": handle_list_algorithms,
        "pqc_algorithm_info": handle_algorithm_info,
        "pqc_generate_keypair": handle_generate_keypair,
        "pqc_encapsulate": handle_encapsulate,
        "pqc_decapsulate": handle_decapsulate,
        "pqc_sign": handle_sign,
        "pqc_verify": handle_verify,
        "pqc_hash": handle_hash,
        "pqc_hash_to_curve": handle_hash,  # deprecated alias
        "pqc_security_analysis": handle_security_analysis,
        "pqc_benchmark": handle_benchmark,
    }

if HAS_HYBRID:
    from pqc_mcp_server.handlers_hybrid import (
        handle_fingerprint,
        handle_hybrid_keygen,
        handle_hybrid_encap,
        handle_hybrid_decap,
        handle_hybrid_seal,
        handle_hybrid_open,
        handle_hybrid_auth_seal,
        handle_hybrid_auth_open,
        handle_hybrid_auth_verify,
        handle_envelope_inspect,
    )
    from pqc_mcp_server.key_store import (
        handle_key_store_save,
        handle_key_store_load,
        handle_key_store_list,
        handle_key_store_delete,
    )

    _HYBRID_HANDLERS = {
        "pqc_fingerprint": handle_fingerprint,
        "pqc_hybrid_keygen": handle_hybrid_keygen,
        "pqc_hybrid_encap": handle_hybrid_encap,
        "pqc_hybrid_decap": handle_hybrid_decap,
        "pqc_hybrid_seal": handle_hybrid_seal,
        "pqc_hybrid_open": handle_hybrid_open,
        "pqc_hybrid_auth_seal": handle_hybrid_auth_seal,
        "pqc_hybrid_auth_open": handle_hybrid_auth_open,
        "pqc_hybrid_auth_verify": handle_hybrid_auth_verify,
        "pqc_envelope_inspect": handle_envelope_inspect,
        "pqc_key_store_save": handle_key_store_save,
        "pqc_key_store_load": handle_key_store_load,
        "pqc_key_store_list": handle_key_store_list,
        "pqc_key_store_delete": handle_key_store_delete,
    }

# --- Pre-dispatch input validation ---

# Size limits (bytes/chars)
_MAX_PLAINTEXT_SIZE = 1_048_576  # 1 MB
_MAX_MESSAGE_SIZE = 1_048_576  # 1 MB
_MAX_KEY_FIELD_SIZE = 102_400  # 100 KB

# Expected types by field name
_STRING_FIELDS = frozenset(
    {
        "algorithm",
        "public_key",
        "secret_key",
        "ciphertext",
        "message",
        "signature",
        "plaintext",
        "plaintext_base64",
        "name",
        "store_as",
        "key_store_name",
        "classical_public_key",
        "pqc_public_key",
        "classical_secret_key",
        "pqc_secret_key",
        "x25519_ephemeral_public_key",
        "pqc_ciphertext",
        "sender_secret_key",
        "sender_public_key",
        "expected_sender_public_key",
        "expected_sender_fingerprint",
        "sender_key_store_name",
        "recipient_key_store_name",
        "type",
    }
)
_DICT_FIELDS = frozenset({"envelope", "key_data"})
_BOOL_FIELDS = frozenset({"overwrite", "include_secret_key"})
_INT_FIELDS = frozenset({"iterations", "max_age_seconds"})

_SIZE_LIMITS: dict[str, int] = {
    "plaintext": _MAX_PLAINTEXT_SIZE,
    "plaintext_base64": _MAX_PLAINTEXT_SIZE,
    "message": _MAX_MESSAGE_SIZE,
    "public_key": _MAX_KEY_FIELD_SIZE,
    "secret_key": _MAX_KEY_FIELD_SIZE,
    "classical_public_key": _MAX_KEY_FIELD_SIZE,
    "pqc_public_key": _MAX_KEY_FIELD_SIZE,
    "classical_secret_key": _MAX_KEY_FIELD_SIZE,
    "pqc_secret_key": _MAX_KEY_FIELD_SIZE,
    "sender_secret_key": _MAX_KEY_FIELD_SIZE,
    "sender_public_key": _MAX_KEY_FIELD_SIZE,
    "ciphertext": _MAX_PLAINTEXT_SIZE,
    "x25519_ephemeral_public_key": _MAX_KEY_FIELD_SIZE,
    "pqc_ciphertext": _MAX_KEY_FIELD_SIZE,
    "expected_sender_public_key": _MAX_KEY_FIELD_SIZE,
    "signature": _MAX_PLAINTEXT_SIZE,
}


def _validate_arguments(arguments: dict[str, Any]) -> None:
    """Validate argument types and sizes before handler dispatch.

    Raises ValueError on type mismatch or size violation.
    Unknown fields pass through silently (future-proof).
    """
    if not isinstance(arguments, dict):
        raise ValueError("arguments must be a JSON object")

    for key, value in arguments.items():
        if value is None:
            continue  # Optional fields may be absent/null

        if key in _STRING_FIELDS:
            if not isinstance(value, str):
                raise ValueError(f"Parameter '{key}' must be a string, got {type(value).__name__}")
            limit = _SIZE_LIMITS.get(key)
            if limit is not None and len(value) > limit:
                raise ValueError(f"Parameter '{key}' exceeds size limit ({limit} chars)")
        elif key in _DICT_FIELDS:
            if not isinstance(value, dict):
                raise ValueError(
                    f"Parameter '{key}' must be a JSON object, got {type(value).__name__}"
                )
        elif key in _BOOL_FIELDS:
            if not isinstance(value, bool):
                raise ValueError(f"Parameter '{key}' must be a boolean, got {type(value).__name__}")
        elif key in _INT_FIELDS:
            # bool is a subclass of int in Python — reject it explicitly
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"Parameter '{key}' must be a number, got {type(value).__name__}")


# --- MCP Server ---

server = Server("pqc-mcp-server")


def _json_response(data: dict[str, Any]) -> list[TextContent]:
    return [TextContent(type="text", text=json.dumps(data, indent=2))]


@server.list_tools()
async def list_tools() -> list[Tool]:
    return PQC_TOOLS


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    # Pre-dispatch input validation (type checks + size limits)
    try:
        _validate_arguments(arguments)
    except (ValueError, TypeError) as e:
        return _json_response({"error": str(e)})

    if not HAS_LIBOQS:
        return _json_response(
            {
                "error": "liboqs not installed",
                "install": "pip install liboqs-python",
                "docs": "https://github.com/open-quantum-safe/liboqs-python",
            }
        )

    # Check PQC handlers first
    if name in _PQC_HANDLERS:
        try:
            return _json_response(_PQC_HANDLERS[name](arguments))
        except Exception as e:
            return _json_response({"error": str(e)})

    # Check hybrid handlers
    if name in _HYBRID_HANDLERS:
        if not HAS_HYBRID:
            return _json_response(
                {
                    "error": "Hybrid dependencies unavailable or failed to import. "
                    "Install liboqs-python and cryptography>=42.0.0."
                }
            )
        try:
            result = _HYBRID_HANDLERS[name](arguments)
            # Support async handlers (e.g., handle_hybrid_auth_open uses asyncio.Lock)
            if asyncio.iscoroutine(result):
                result = await result
            return _json_response(result)
        except binascii.Error as e:
            return _json_response({"error": f"Invalid base64 input: {e}"})
        except SenderVerificationError as e:
            return _json_response({"error": f"Sender verification failed: {e}"})
        except ValueError as e:
            return _json_response({"error": str(e)})
        except InvalidTag:
            return _json_response(
                {"error": "Decryption failed: ciphertext, key, or envelope metadata is invalid"}
            )
        except (TypeError, AttributeError, KeyError) as e:
            return _json_response({"error": f"Invalid argument type: {e}"})
        except RuntimeError as e:
            return _json_response({"error": f"Internal error: {e}"})
        except OSError as e:
            return _json_response({"error": f"I/O error: {e}"})

    return _json_response({"error": f"Unknown tool: {name}"})


async def run_server() -> None:
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main() -> None:
    asyncio.run(run_server())


if __name__ == "__main__":
    main()
