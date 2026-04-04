"""Security regression tests — ChatGPT-specified test cases.

These are the highest-value tests after the v3 mode separation work:
1. Repeat-encryption uniqueness
2. Sender key/fingerprint inconsistency
3. Recipient fingerprint tamper
4. Strict anon schema
5. Replay cache persistence + expiry
6. Future timestamp probe
"""

import base64
import time

import pytest

oqs = pytest.importorskip("oqs", reason="liboqs-python not installed")
pytest.importorskip("cryptography", reason="cryptography not installed")

from pqc_mcp_server.hybrid import (
    SenderVerificationError,
    _fingerprint_public_key,
    hybrid_auth_open,
    hybrid_auth_seal,
    hybrid_auth_verify,
    hybrid_keygen,
    hybrid_open,
    hybrid_seal,
)
from pqc_mcp_server.key_store import clear_store
from pqc_mcp_server.replay_cache import ReplayCache


@pytest.fixture(autouse=True)
def clean():
    clear_store()
    yield
    clear_store()


@pytest.fixture
def keys():
    enc = hybrid_keygen()
    sig = oqs.Signature("ML-DSA-65")
    sig_pk = sig.generate_keypair()
    sig_sk = sig.export_secret_key()
    return {
        "enc": enc,
        "sig_pk": sig_pk,
        "sig_sk": sig_sk,
        "sig_fp": _fingerprint_public_key(sig_pk),
        "cpk": base64.b64decode(enc["classical"]["public_key"]),
        "ppk": base64.b64decode(enc["pqc"]["public_key"]),
        "csk": base64.b64decode(enc["classical"]["secret_key"]),
        "psk": base64.b64decode(enc["pqc"]["secret_key"]),
    }


def test_repeat_same_plaintext_produces_distinct_v3_anon_envelopes(keys):
    """Same plaintext to same recipient twice should not repeat epk/pqc_ct/ciphertext."""
    env1 = hybrid_seal(b"same plaintext", keys["cpk"], keys["ppk"])
    env2 = hybrid_seal(b"same plaintext", keys["cpk"], keys["ppk"])

    assert env1["x25519_ephemeral_public_key"] != env2["x25519_ephemeral_public_key"]
    assert env1["pqc_ciphertext"] != env2["pqc_ciphertext"]
    assert env1["ciphertext"] != env2["ciphertext"]

    r1 = hybrid_open(env1, keys["csk"], keys["psk"])
    r2 = hybrid_open(env2, keys["csk"], keys["psk"])
    assert r1["plaintext"] == "same plaintext"
    assert r2["plaintext"] == "same plaintext"


def test_sender_public_key_fingerprint_inconsistency_is_rejected(keys):
    """Embedded sender_public_key must match embedded sender_key_fingerprint."""
    env = hybrid_auth_seal(
        b"auth message", keys["cpk"], keys["ppk"], keys["sig_sk"], keys["sig_pk"]
    )

    other_sig = oqs.Signature("ML-DSA-65")
    other_pk = other_sig.generate_keypair()

    # Tamper sender public key, leave original fingerprint/signature in place.
    env["sender_public_key"] = base64.b64encode(other_pk).decode()

    with pytest.raises(SenderVerificationError, match="inconsistent"):
        hybrid_auth_verify(env, expected_sender_fingerprint=keys["sig_fp"])


def test_recipient_fingerprint_tamper_invalidates_auth_signature(keys):
    """Recipient fingerprints are in the signed transcript; tampering must fail verify."""
    env = hybrid_auth_seal(
        b"auth message", keys["cpk"], keys["ppk"], keys["sig_sk"], keys["sig_pk"]
    )

    env["recipient_classical_key_fingerprint"] = "0" * 64

    with pytest.raises(SenderVerificationError):
        hybrid_auth_verify(env, expected_sender_fingerprint=keys["sig_fp"])


def test_v3_anon_rejects_auth_only_fields(keys):
    """Strict v3 anon schema should reject auth-only fields."""
    env = hybrid_seal(b"anon", keys["cpk"], keys["ppk"])

    # An anon envelope should not carry auth-only fields.
    env["timestamp"] = str(int(time.time()))

    with pytest.raises(ValueError):
        hybrid_open(env, keys["csk"], keys["psk"])


def test_replay_cache_persists_and_expires(tmp_path):
    """ReplayCache should survive reload and prune expired entries."""
    cache_file = tmp_path / "replay-cache.json"
    now = time.time()

    cache1 = ReplayCache(cache_file=str(cache_file), ttl_seconds=5, max_size=10)
    digest = "a" * 64

    # Mark with current time — expiry will be now+5
    assert cache1.check_and_mark(digest, now=now) is False
    assert cache1.check(digest) is True

    # Fresh instance should load persisted state.
    cache2 = ReplayCache(cache_file=str(cache_file), ttl_seconds=5, max_size=10)
    assert cache2.check(digest) is True

    # After expiry, prune should remove it.
    cache2.prune(now=now + 6.0)
    assert cache2.check(digest) is False


def test_fallback_cache_prunes_without_error():
    """Fallback cache created via __new__ must handle prune/evict without AttributeError."""
    from pqc_mcp_server.replay_cache import (
        _DEFAULT_MAX_SIZE,
        _DEFAULT_TTL,
        ReplayCache,
    )

    cache = ReplayCache.__new__(ReplayCache)
    cache.cache_file = ""
    cache.ttl_seconds = _DEFAULT_TTL
    cache.max_size = _DEFAULT_MAX_SIZE
    cache._cache = {}

    cache.prune()
    cache.check("digest-1")
    cache.check_and_mark("digest-1")
    assert cache.check("digest-1") is True

    for i in range(100):
        cache._cache[f"expired-{i}"] = 0.0

    cache.prune()
    assert len(cache._cache) <= 1


def test_future_dated_auth_envelope_is_rejected(keys, monkeypatch):
    """
    Probe test: future-dated envelopes should not verify successfully.

    If this FAILS (i.e. the envelope verifies), that is likely a real gap:
    the freshness check is not rejecting future timestamps.
    """
    now = int(time.time())
    future = now + 3600  # 1 hour ahead

    monkeypatch.setattr("pqc_mcp_server.hybrid.time.time", lambda: future)
    env = hybrid_auth_seal(
        b"future message", keys["cpk"], keys["ppk"], keys["sig_sk"], keys["sig_pk"]
    )

    # Restore "current" time for verification.
    monkeypatch.setattr("pqc_mcp_server.hybrid.time.time", lambda: now)

    with pytest.raises((ValueError, SenderVerificationError)):
        hybrid_auth_verify(
            env,
            expected_sender_fingerprint=keys["sig_fp"],
            max_age_seconds=300,
        )
