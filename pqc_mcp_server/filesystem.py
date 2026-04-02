"""Secure filesystem helpers for PQC key material and envelopes.

Enforces restrictive permissions on directories and files that contain
cryptographic material, contacts, or envelopes.

These helpers are intended for use by the skill layer (quantum-seal plugin)
and external code that manages ~/.pqc/ paths. The MCP server itself does
not write to the filesystem — skills orchestrate file I/O via Claude's
Write tool and should call these helpers to enforce permissions afterward.
"""

import os
import stat


def ensure_secure_directory(path: str) -> None:
    """Create directory with 0o700 permissions (owner-only access)."""
    os.makedirs(path, exist_ok=True)
    os.chmod(path, stat.S_IRWXU)  # 0o700


def ensure_secure_file(path: str) -> None:
    """Set file permissions to 0o600 (owner read/write only)."""
    if not os.path.exists(path):
        return
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0o600
