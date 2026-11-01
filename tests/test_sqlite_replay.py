"""Strict replay persistence must coordinate processes and fail closed."""

from concurrent.futures import ThreadPoolExecutor
import importlib

import pytest


def cache_class():
    module = importlib.import_module("pqc_mcp_server.replay_cache")
    assert hasattr(
        module, "SqliteReplayCache"
    ), "Production replay persistence must be transactional"
    return module.SqliteReplayCache


def test_independent_cache_instances_atomically_accept_only_once(tmp_path):
    cls = cache_class()
    path = str(tmp_path / "replay.sqlite3")
    caches = [cls(path, ttl_seconds=60, max_size=10) for _ in range(8)]
    with ThreadPoolExecutor(8) as executor:
        results = list(executor.map(lambda c: c.check_and_mark("a" * 64), caches))
    assert results.count(False) == 1
    assert results.count(True) == 7
    assert cls(path).check("a" * 64)


def test_replay_store_does_not_evict_live_entries_to_accept_new_messages(tmp_path):
    cls = cache_class()
    cache = cls(str(tmp_path / "replay.sqlite3"), max_size=1)
    assert cache.check_and_mark("a" * 64) is False
    with pytest.raises(RuntimeError, match="capacity"):
        cache.check_and_mark("b" * 64)
    assert cache.check("a" * 64)


def test_corrupted_replay_store_fails_closed(tmp_path):
    path = tmp_path / "replay.sqlite3"
    path.write_bytes(b"not a sqlite database")
    with pytest.raises(RuntimeError, match="replay|Replay"):
        cache_class()(str(path))


def test_legacy_json_import_is_once_only_and_preserves_unexpired_entries(tmp_path):
    import json, time

    cls = cache_class()
    old = tmp_path / "old.json"
    new = str(tmp_path / "replay.sqlite3")
    old.write_text(json.dumps({"a" * 64: time.time() + 300}))
    assert cls(new, legacy_json=str(old)).check("a" * 64)
    old.write_text("corrupted historical file")
    assert cls(new, legacy_json=str(old)).check("a" * 64)


def _process_claim(path, queue):
    try:
        queue.put(cache_class()(path).check_and_mark("c" * 64))
    except Exception as error:
        queue.put(type(error).__name__)


def test_processes_share_atomic_replay_acceptance(tmp_path):
    import multiprocessing

    ctx = multiprocessing.get_context("spawn")
    queue = ctx.Queue()
    path = str(tmp_path / "replay.sqlite3")
    cache_class()(path)
    workers = [ctx.Process(target=_process_claim, args=(path, queue)) for _ in range(4)]
    for process in workers:
        process.start()
    for process in workers:
        process.join(15)
        assert process.exitcode == 0
    results = [queue.get(timeout=5) for _ in workers]
    assert results.count(False) == 1
    assert results.count(True) == 3


def test_replay_retention_covers_the_permitted_future_clock_skew(tmp_path, monkeypatch):
    from pqc_mcp_server import replay_cache

    now = [1000.0]
    monkeypatch.setattr(replay_cache.time, "time", lambda: now[0])
    cache = cache_class()(str(tmp_path / "skew.sqlite3"), ttl_seconds=60)
    assert cache.check_and_mark("d" * 64) is False
    now[0] = 1360.0
    assert cache.check("d" * 64), "Envelope timestamps may be up to 300 seconds ahead"
