"""Server-enforced security policies.

Moves security-critical checks from skill instructions ("promptware")
into the server, where they cannot be bypassed by a misbehaving agent.

Controlled by environment variables:
- PQC_REQUIRE_KEY_HANDLES: if "1", reject raw secret keys in tool calls
  (force use of store_as / key_store_name for all secret-key operations)
"""

import os
from typing import Any


def _env_bool(name: str, default: bool = False) -> bool:
    return os.environ.get(name, "1" if default else "0") == "1"


class SecurityPolicy:
    """Runtime security policy for the MCP server."""

    def __init__(self) -> None:
        self.require_key_handles = _env_bool("PQC_REQUIRE_KEY_HANDLES", default=False)

    def keygen_handle(self, arguments: dict[str, Any]) -> str | None:
        """Validate before generating keys; policy mode never returns raw secrets."""
        if "store_as" not in arguments:
            if self.require_key_handles:
                raise ValueError("PQC_REQUIRE_KEY_HANDLES requires a non-empty store_as handle")
            return None
        return validate_key_name(arguments["store_as"])

    def check_no_raw_secrets(self, arguments: dict[str, Any], secret_fields: list[str]) -> None:
        """Reject tool calls that pass raw secret keys when policy requires handles.

        Raises ValueError if require_key_handles is True and any secret_field
        is present in arguments (meaning the caller passed raw key bytes
        instead of using a key_store_name handle).
        """
        if not self.require_key_handles:
            return
        for field in secret_fields:
            if field in arguments:
                raise ValueError(
                    f"Raw secret key '{field}' rejected by server policy. "
                    "Set PQC_REQUIRE_KEY_HANDLES=0 to allow raw keys, "
                    "or use key_store_name / store_as for opaque handle access."
                )


# Module-level singleton
_POLICY = SecurityPolicy()


def get_policy() -> SecurityPolicy:
    """Get the current server security policy."""
    return _POLICY


def validate_key_name(name: Any) -> str:
    """Names are bounded, unambiguous opaque handles, not filesystem paths."""
    if not isinstance(name, str) or not name.strip() or len(name) > 128:
        raise ValueError("Key handle must be a non-blank string of at most 128 characters")
    return name
