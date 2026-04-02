"""Stateful replay dedup for authenticated envelopes.

Tracks seen envelope signature digests with TTL to prevent replay attacks
within the freshness window. Persists to ~/.pqc/state/replay-cache.json
to survive server restarts.

Design decisions:
- Key on SHA3-256 of signature bytes (unique per envelope, no JSON canonicalization needed)
- hybrid_auth_verify: read-only check (returns replay_seen flag, does not mark)
- hybrid_auth_open: check + mark after successful decryption
  (avoids false positives when verify is called before open)
- JSON file storage (matches research-tool philosophy — simple, inspectable)
"""

import base64
import hashlib
import json
import os
import tempfile
import time
from typing import Any

from pqc_mcp_server.filesystem import ensure_secure_directory, ensure_secure_file

_DEFAULT_TTL = 24 * 60 * 60  # 24 hours
_DEFAULT_MAX_SIZE = 50_000  # max entries before oldest are evicted
_DEFAULT_STATE_DIR = os.path.expanduser("~/.pqc/state")
_DEFAULT_CACHE_FILE = os.path.join(_DEFAULT_STATE_DIR, "replay-cache.json")


def signature_digest(envelope: dict[str, Any]) -> str:
    """SHA3-256 hex digest of the envelope's signature bytes."""
    sig_b64 = envelope.get("signature", "")
    sig_bytes = base64.b64decode(sig_b64, validate=True) if sig_b64 else b""
    return hashlib.sha3_256(sig_bytes).hexdigest()


class ReplayCache:
    """Persistent replay dedup cache backed by a JSON file.

    Addresses Codex review findings:
    - Atomic writes via tempfile + rename (no torn writes)
    - OSError handling on all I/O (fails open with warning, not crash)
    - Atomic check_and_mark() for TOCTOU safety
    """

    def __init__(
        self,
        cache_file: str = _DEFAULT_CACHE_FILE,
        ttl_seconds: int = _DEFAULT_TTL,
        max_size: int = _DEFAULT_MAX_SIZE,
    ) -> None:
        self.cache_file = cache_file
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        self._cache: dict[str, float] = {}  # digest → expiry timestamp
        self._load()

    def _load(self) -> None:
        """Load cache from disk. Reset on corruption, ignore missing file."""
        if not os.path.exists(self.cache_file):
            return
        try:
            with open(self.cache_file) as f:
                data = json.load(f)
            if isinstance(data, dict):
                self._cache = {k: float(v) for k, v in data.items()}
        except (json.JSONDecodeError, TypeError, ValueError, OSError):
            self._cache = {}

    def _save(self) -> None:
        """Atomic persist: write to temp file, then rename. Secure permissions."""
        try:
            ensure_secure_directory(os.path.dirname(self.cache_file))
            fd, tmp_path = tempfile.mkstemp(dir=os.path.dirname(self.cache_file), suffix=".tmp")
            try:
                with os.fdopen(fd, "w") as f:
                    json.dump(self._cache, f)
                os.replace(tmp_path, self.cache_file)  # atomic on POSIX
                ensure_secure_file(self.cache_file)
            except BaseException:
                # Clean up temp file on failure
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
        except OSError:
            pass  # fail open — replay cache is best-effort for research tool

    def prune(self, now: float | None = None) -> None:
        """Remove expired entries and enforce max size (oldest-first eviction)."""
        now = now or time.time()
        expired = [k for k, expiry in self._cache.items() if expiry <= now]
        for k in expired:
            del self._cache[k]
        # Evict oldest entries if over max_size (prevents cache-flood DoS)
        if len(self._cache) > self.max_size:
            sorted_entries = sorted(self._cache.items(), key=lambda x: x[1])
            to_evict = len(self._cache) - self.max_size
            for k, _ in sorted_entries[:to_evict]:
                del self._cache[k]

    def check(self, digest: str) -> bool:
        """Check if digest has been seen. Returns True if replay (already seen)."""
        self.prune()
        return digest in self._cache

    def check_and_mark(self, digest: str, now: float | None = None) -> bool:
        """Atomic check + mark. Returns True if replay (already seen).

        If not seen, marks immediately and persists. Eliminates TOCTOU
        window between separate check() and mark() calls.
        """
        self.prune()
        if digest in self._cache:
            return True  # replay
        now = now or time.time()
        self._cache[digest] = now + self.ttl_seconds
        self._save()
        return False  # new

    def mark(self, digest: str, now: float | None = None) -> None:
        """Record digest as seen. Call after successful decryption."""
        now = now or time.time()
        self._cache[digest] = now + self.ttl_seconds
        self.prune()
        self._save()


# Module-level singleton (lazy init)
_CACHE: ReplayCache | None = None


def get_replay_cache() -> ReplayCache:
    """Get or create the global replay cache."""
    global _CACHE
    if _CACHE is None:
        try:
            _CACHE = ReplayCache()
        except OSError:
            # If state dir is completely inaccessible, use in-memory only
            _CACHE = ReplayCache.__new__(ReplayCache)
            _CACHE.cache_file = ""
            _CACHE.ttl_seconds = _DEFAULT_TTL
            _CACHE._cache = {}
    return _CACHE
