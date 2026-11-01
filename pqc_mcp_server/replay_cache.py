"""Replay deduplication: strict SQLite production storage and legacy JSON diagnostics.

The notes below describe the legacy ReplayCache class only. Production uses
SqliteReplayCache, which fails closed and coordinates local processes.

Stateful replay dedup for authenticated envelopes.

Tracks seen envelope signature digests with TTL to prevent replay attacks
within the freshness window. Persists to ~/.pqc/state/replay-cache.json
to survive server restarts.

Process/concurrency boundary:
    Replay dedup is guaranteed only within the current single-process
    runtime model. The cache uses atomic file writes (tempfile + os.replace)
    for crash safety, but does NOT use file locking. Under multi-process
    contention, two concurrent opens of the same valid envelope can both
    succeed — this is a documented operational tradeoff, not a protocol flaw.
    For multi-process one-time-delivery guarantees, add file locking or a
    reserve/finalize pattern at the handler layer.

Design decisions:
- Key on SHA3-256 of signature bytes (unique per envelope, no JSON canonicalization)
- hybrid_auth_verify: read-only check (returns replay_seen flag, does not mark)
- hybrid_auth_open: check before verify, mark after successful decrypt
  (prevents junk pre-blocking; accepts TOCTOU under single-process async)
- JSON file storage (simple, inspectable, atomic writes via tempfile+rename)
- Corrupted cache resets to empty on load (fails open — best-effort dedup)
- Max 50K entries with oldest-first eviction (prevents cache-flood DoS)
"""

import base64
import hashlib
import json
import os
import tempfile
import time
import math
import stat
import sqlite3
from contextlib import contextmanager
from typing import Any

from pqc_mcp_server.filesystem import ensure_secure_directory, ensure_secure_file

_DEFAULT_TTL = 24 * 60 * 60  # 24 hours
_DEFAULT_MAX_SIZE = 50_000  # max entries before oldest are evicted
_DEFAULT_STATE_DIR = os.path.expanduser(os.environ.get("PQC_STATE_DIR", "~/.pqc/state"))
_DEFAULT_CACHE_FILE = os.path.join(_DEFAULT_STATE_DIR, "replay-cache.json")


def signature_digest(envelope: dict[str, Any]) -> str:
    """SHA3-256 hex digest of the envelope's signature bytes.

    Raises ValueError if signature is missing or empty — prevents silent
    hashing of b"" which would collide across all unsigned envelopes.
    """
    sig_b64 = envelope.get("signature", "")
    if not sig_b64:
        raise ValueError("Cannot compute replay digest: envelope has no signature")
    sig_bytes = base64.b64decode(sig_b64, validate=True)
    if not sig_bytes:
        raise ValueError("Cannot compute replay digest: signature decodes to empty")
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


class SqliteReplayCache:
    """Strict, transactional deduplication shared by local server processes.

    Unlike the legacy JSON diagnostic cache above, corruption, persistence
    failure, and exhausted capacity fail closed. Live entries are never evicted.
    """

    def __init__(
        self,
        cache_file: str,
        ttl_seconds: int = _DEFAULT_TTL,
        max_size: int = _DEFAULT_MAX_SIZE,
        legacy_json: str | None = None,
    ) -> None:
        self.cache_file = cache_file
        self.ttl_seconds = ttl_seconds
        self.max_size = max_size
        if ttl_seconds <= 0 or max_size <= 0:
            raise ValueError("Replay TTL and capacity must be positive")
        try:
            directory = os.path.dirname(os.path.abspath(cache_file))
            ensure_secure_directory(directory)
            fd = os.open(cache_file, os.O_CREAT | os.O_RDWR | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or (
                    hasattr(os, "getuid") and info.st_uid != os.getuid()
                ):
                    raise OSError("Replay database must be owned by the server user")
                os.fchmod(fd, 0o600)
            finally:
                os.close(fd)
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "CREATE TABLE IF NOT EXISTS seen (digest TEXT PRIMARY KEY, expiry REAL NOT NULL)"
                )
                db.execute("CREATE INDEX IF NOT EXISTS seen_expiry ON seen(expiry)")
                db.execute(
                    "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
                )
                if not db.execute("SELECT 1 FROM metadata WHERE key='legacy_imported'").fetchone():
                    if legacy_json and os.path.exists(legacy_json):
                        with open(legacy_json) as stream:
                            raw = stream.read(10_000_001)
                        if len(raw) > 10_000_000:
                            raise ValueError("Legacy replay state exceeds size limit")
                        data = json.loads(raw)
                        if not isinstance(data, dict):
                            raise ValueError("Invalid legacy replay state")
                        for digest, expiry in data.items():
                            value = float(expiry)
                            if not isinstance(digest, str) or not math.isfinite(value):
                                raise ValueError("Invalid legacy replay entry")
                            if value > time.time():
                                db.execute(
                                    "INSERT OR IGNORE INTO seen VALUES (?,?)", (digest, value + 301)
                                )
                    db.execute("INSERT INTO metadata VALUES ('legacy_imported','1')")
        except (OSError, sqlite3.Error, ValueError, TypeError) as exc:
            raise RuntimeError(
                "Replay database initialization failed; refusing to reset replay state"
            ) from exc

    @contextmanager
    def _connection(self):
        db = sqlite3.connect(self.cache_file, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def check(self, digest: str) -> bool:
        try:
            with self._connection() as db:
                return (
                    db.execute(
                        "SELECT 1 FROM seen WHERE digest=? AND expiry>?", (digest, time.time())
                    ).fetchone()
                    is not None
                )
        except sqlite3.Error as exc:
            raise RuntimeError("Replay database read failed") from exc

    def check_and_mark(self, digest: str, now: float | None = None) -> bool:
        now = time.time() if now is None else now
        try:
            with self._connection() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("DELETE FROM seen WHERE expiry<=?", (now,))
                if db.execute("SELECT 1 FROM seen WHERE digest=?", (digest,)).fetchone():
                    return True
                if db.execute("SELECT COUNT(*) FROM seen").fetchone()[0] >= self.max_size:
                    raise RuntimeError(
                        "Replay database capacity reached; refusing to evict live entries"
                    )
                db.execute("INSERT INTO seen VALUES (?,?)", (digest, now + self.ttl_seconds + 301))
                return False
        except sqlite3.Error as exc:
            raise RuntimeError("Replay database write failed") from exc


# Production uses strict SQLite persistence; ReplayCache remains a legacy
# diagnostic/public compatibility class, never a silent production fallback.
_CACHE: SqliteReplayCache | ReplayCache | None = None


def get_replay_cache() -> SqliteReplayCache | ReplayCache:
    global _CACHE
    if _CACHE is None:
        _CACHE = SqliteReplayCache(
            os.path.join(_DEFAULT_STATE_DIR, "replay-cache.sqlite3"),
            legacy_json=_DEFAULT_CACHE_FILE,
        )
    return _CACHE
