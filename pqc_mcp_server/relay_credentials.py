"""Load mailbox credentials from an operator-selected owner-only file."""

import json
import os
import stat
from typing import Any

from pqc_mcp_server.relay_client import (
    RelayConfigError,
    _normalise_relay_url,
    _validate_fingerprint,
    check_allowlist,
)


def load_mailbox_tokens(path: str | None, allowed: frozenset[str]) -> dict[tuple[str, str], str]:
    if not path:
        return {}
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        with os.fdopen(fd, "r") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
                raise ValueError("Credential file must be an owner-only regular file")
            if hasattr(os, "getuid") and info.st_uid != os.getuid():
                raise ValueError("Credential file must belong to the server user")
            raw = stream.read(1_048_577)
            if len(raw) > 1_048_576:
                raise ValueError("Credential file exceeds size limit")
        entries: Any = json.loads(raw)
        if not isinstance(entries, list):
            raise ValueError("Credential file must contain a list")
        tokens: dict[tuple[str, str], str] = {}
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {"relay_url", "fingerprint", "token"}:
                raise ValueError("Invalid credential record")
            origin = _normalise_relay_url(entry["relay_url"], allow_http=True)
            check_allowlist(origin, allowed)
            fp, token = entry["fingerprint"], entry["token"]
            _validate_fingerprint(fp)
            if (
                not isinstance(token, str)
                or not token
                or len(token) > 512
                or any(c.isspace() for c in token)
            ):
                raise ValueError("Invalid credential")
            if (origin, fp) in tokens:
                raise ValueError("Duplicate credential")
            tokens[(origin, fp)] = token
        return tokens
    except (OSError, ValueError, TypeError, KeyError, RelayConfigError) as exc:
        # Never include the bad value or JSON decoder's document in user-facing errors.
        raise RelayConfigError("Could not load valid owner-only mailbox credential file") from exc
