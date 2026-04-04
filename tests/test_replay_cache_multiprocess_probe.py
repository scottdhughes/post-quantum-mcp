"""Diagnostic probe: multi-process replay cache behavior.

NOT a pass/fail security test — characterizes the documented
multi-process tradeoff. Should not crash; may reveal duplicate
first-accepts without file locking.
"""

import base64
import multiprocessing as mp

import pytest

oqs = pytest.importorskip("oqs", reason="liboqs-python not installed")

from pqc_mcp_server.hybrid import (
    _fingerprint_public_key,
    hybrid_auth_seal,
    hybrid_keygen,
)
from pqc_mcp_server.replay_cache import ReplayCache, signature_digest


def _worker(cache_file: str, digest: str, q):
    cache = ReplayCache(cache_file=cache_file, ttl_seconds=300, max_size=100)
    seen = cache.check_and_mark(digest)
    q.put(seen)


def test_multiprocess_replay_cache_probe(tmp_path):
    enc = hybrid_keygen()
    sig = oqs.Signature("ML-DSA-65")
    sig_pk = sig.generate_keypair()
    sig_sk = sig.export_secret_key()

    cpk = base64.b64decode(enc["classical"]["public_key"])
    ppk = base64.b64decode(enc["pqc"]["public_key"])

    env = hybrid_auth_seal(b"probe", cpk, ppk, sig_sk, sig_pk)
    digest = signature_digest(env)

    cache_file = str(tmp_path / "replay-cache.json")
    q = mp.Queue()

    procs = [mp.Process(target=_worker, args=(cache_file, digest, q)) for _ in range(8)]
    for p in procs:
        p.start()
    for p in procs:
        p.join()

    results = [q.get() for _ in procs]
    false_count = sum(1 for r in results if r is False)
    true_count = sum(1 for r in results if r is True)

    print({"new": false_count, "replay": true_count})
    assert false_count >= 1
    assert true_count >= 0
