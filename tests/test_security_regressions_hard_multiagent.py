"""Hard-mode multi-agent security regression suite.

Three-agent ring turns with concurrent adversarial interleaving,
cross-turn splicing attacks, stale/fresh turn transitions,
replay cache corruption recovery, and eviction ordering.
"""

import base64
import copy
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import pytest

oqs = pytest.importorskip("oqs", reason="liboqs-python not installed")
pytest.importorskip("cryptography", reason="cryptography not installed")

from cryptography.exceptions import InvalidTag

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
from pqc_mcp_server.replay_cache import ReplayCache, signature_digest

BLOCKED = (InvalidTag, ValueError, SenderVerificationError)


@pytest.fixture(autouse=True)
def clean():
    clear_store()
    yield
    clear_store()


@pytest.fixture
def agents():
    out = {}
    for name in ("alice", "bob", "carol"):
        enc = hybrid_keygen()
        sig = oqs.Signature("ML-DSA-65")
        sig_pk = sig.generate_keypair()
        sig_sk = sig.export_secret_key()
        out[name] = {
            "enc": enc,
            "sig_pk": sig_pk,
            "sig_sk": sig_sk,
            "sig_fp": _fingerprint_public_key(sig_pk),
            "cpk": base64.b64decode(enc["classical"]["public_key"]),
            "ppk": base64.b64decode(enc["pqc"]["public_key"]),
            "csk": base64.b64decode(enc["classical"]["secret_key"]),
            "psk": base64.b64decode(enc["pqc"]["secret_key"]),
        }
    return out


def _flip_b64(b64s: str) -> str:
    raw = bytearray(base64.b64decode(b64s, validate=True))
    if not raw:
        raise ValueError("Cannot flip empty decoded bytes")
    raw[0] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


def _auth_strip(env: dict) -> dict:
    return {
        "version": env["version"],
        "mode": "anon-seal",
        "suite": env["suite"],
        "x25519_ephemeral_public_key": env["x25519_ephemeral_public_key"],
        "pqc_ciphertext": env["pqc_ciphertext"],
        "ciphertext": env["ciphertext"],
    }


def _verify_or_open_attack(name, env, sender, recipient):
    if name == "auth_strip":
        stripped = _auth_strip(env)
        return hybrid_open(stripped, recipient["csk"], recipient["psk"])
    if name == "mode_unknown":
        tampered = copy.deepcopy(env)
        tampered["mode"] = "hybrid-seal"
        return hybrid_auth_open(
            tampered,
            recipient["csk"],
            recipient["psk"],
            expected_sender_fingerprint=sender["sig_fp"],
            max_age_seconds=300,
        )
    if name == "sender_pk_swap":
        tampered = copy.deepcopy(env)
        other = oqs.Signature("ML-DSA-65")
        other_pk = other.generate_keypair()
        tampered["sender_public_key"] = base64.b64encode(other_pk).decode()
        return hybrid_auth_verify(
            tampered,
            expected_sender_fingerprint=sender["sig_fp"],
            max_age_seconds=300,
        )
    if name == "recipient_fp_tamper":
        tampered = copy.deepcopy(env)
        tampered["recipient_classical_key_fingerprint"] = "0" * 64
        return hybrid_auth_verify(
            tampered,
            expected_sender_fingerprint=sender["sig_fp"],
            max_age_seconds=300,
        )
    if name == "signature_bitflip":
        tampered = copy.deepcopy(env)
        tampered["signature"] = _flip_b64(tampered["signature"])
        return hybrid_auth_verify(
            tampered,
            expected_sender_fingerprint=sender["sig_fp"],
            max_age_seconds=300,
        )
    if name == "ciphertext_bitflip":
        tampered = copy.deepcopy(env)
        tampered["ciphertext"] = _flip_b64(tampered["ciphertext"])
        return hybrid_auth_open(
            tampered,
            recipient["csk"],
            recipient["psk"],
            expected_sender_fingerprint=sender["sig_fp"],
            max_age_seconds=300,
        )
    if name == "epk_bitflip":
        tampered = copy.deepcopy(env)
        tampered["x25519_ephemeral_public_key"] = _flip_b64(tampered["x25519_ephemeral_public_key"])
        return hybrid_auth_open(
            tampered,
            recipient["csk"],
            recipient["psk"],
            expected_sender_fingerprint=sender["sig_fp"],
            max_age_seconds=300,
        )
    if name == "version_downgrade":
        tampered = copy.deepcopy(env)
        tampered["version"] = "pqc-mcp-v2"
        tampered.pop("mode", None)
        return hybrid_auth_open(
            tampered,
            recipient["csk"],
            recipient["psk"],
            expected_sender_fingerprint=sender["sig_fp"],
            max_age_seconds=300,
        )
    raise AssertionError(f"Unknown attack {name}")


def test_three_agent_ring_turns_with_concurrent_adversarial_interleaving(agents):
    turns = [
        ("alice", "bob", "turn-1: alice -> bob"),
        ("bob", "carol", "turn-2: bob -> carol"),
        ("carol", "alice", "turn-3: carol -> alice"),
        ("alice", "carol", "turn-4: alice -> carol"),
        ("carol", "bob", "turn-5: carol -> bob"),
        ("bob", "alice", "turn-6: bob -> alice"),
    ]
    attacks = (
        "auth_strip",
        "mode_unknown",
        "sender_pk_swap",
        "recipient_fp_tamper",
        "signature_bitflip",
        "ciphertext_bitflip",
        "epk_bitflip",
        "version_downgrade",
    )

    for sender_name, recipient_name, msg in turns:
        sender = agents[sender_name]
        recipient = agents[recipient_name]
        env = hybrid_auth_seal(
            msg.encode(),
            recipient["cpk"],
            recipient["ppk"],
            sender["sig_sk"],
            sender["sig_pk"],
        )

        with ThreadPoolExecutor(max_workers=len(attacks) + 1) as ex:
            futures = {}
            futures[
                ex.submit(
                    hybrid_auth_open,
                    copy.deepcopy(env),
                    recipient["csk"],
                    recipient["psk"],
                    expected_sender_fingerprint=sender["sig_fp"],
                    max_age_seconds=300,
                )
            ] = ("legit", True)

            for attack in attacks:
                futures[
                    ex.submit(
                        _verify_or_open_attack,
                        attack,
                        copy.deepcopy(env),
                        sender,
                        recipient,
                    )
                ] = (attack, False)

            legit_seen = False
            for fut in as_completed(futures):
                name, is_legit = futures[fut]
                if is_legit:
                    result = fut.result()
                    assert result["plaintext"] == msg
                    assert result["authenticated"] is True
                    legit_seen = True
                else:
                    with pytest.raises(BLOCKED):
                        fut.result()
            assert legit_seen is True


def test_cross_turn_splicing_attacks_fail(agents):
    alice, bob, carol = agents["alice"], agents["bob"], agents["carol"]
    env_ab = hybrid_auth_seal(
        b"alice to bob", bob["cpk"], bob["ppk"], alice["sig_sk"], alice["sig_pk"]
    )
    env_cb = hybrid_auth_seal(
        b"carol to bob", bob["cpk"], bob["ppk"], carol["sig_sk"], carol["sig_pk"]
    )

    spliced_ct = copy.deepcopy(env_ab)
    spliced_ct["ciphertext"] = env_cb["ciphertext"]
    with pytest.raises(BLOCKED):
        hybrid_auth_open(
            spliced_ct,
            bob["csk"],
            bob["psk"],
            expected_sender_fingerprint=alice["sig_fp"],
            max_age_seconds=300,
        )

    spliced_sig = copy.deepcopy(env_ab)
    spliced_sig["signature"] = env_cb["signature"]
    with pytest.raises(BLOCKED):
        hybrid_auth_verify(
            spliced_sig, expected_sender_fingerprint=alice["sig_fp"], max_age_seconds=300
        )

    spliced_epk = copy.deepcopy(env_ab)
    spliced_epk["x25519_ephemeral_public_key"] = env_cb["x25519_ephemeral_public_key"]
    with pytest.raises(BLOCKED):
        hybrid_auth_open(
            spliced_epk,
            bob["csk"],
            bob["psk"],
            expected_sender_fingerprint=alice["sig_fp"],
            max_age_seconds=300,
        )


def test_stale_turn_is_rejected_but_fresh_followup_still_succeeds(agents, monkeypatch):
    bob, carol = agents["bob"], agents["carol"]
    now = int(time.time())

    monkeypatch.setattr("pqc_mcp_server.hybrid.time.time", lambda: now - 1200)
    stale_env = hybrid_auth_seal(b"stale", carol["cpk"], carol["ppk"], bob["sig_sk"], bob["sig_pk"])

    monkeypatch.setattr("pqc_mcp_server.hybrid.time.time", lambda: now)
    with pytest.raises(BLOCKED):
        hybrid_auth_open(
            stale_env,
            carol["csk"],
            carol["psk"],
            expected_sender_fingerprint=bob["sig_fp"],
            max_age_seconds=300,
        )

    fresh_env = hybrid_auth_seal(b"fresh", carol["cpk"], carol["ppk"], bob["sig_sk"], bob["sig_pk"])
    result = hybrid_auth_open(
        fresh_env,
        carol["csk"],
        carol["psk"],
        expected_sender_fingerprint=bob["sig_fp"],
        max_age_seconds=300,
    )
    assert result["plaintext"] == "fresh"
    assert result["authenticated"] is True


def test_replay_cache_corruption_recovery_and_persistence_across_turns(tmp_path, agents):
    cache_file = tmp_path / "replay-cache.json"
    cache_file.write_text("{ this is not valid json ")
    cache = ReplayCache(cache_file=str(cache_file), ttl_seconds=300, max_size=20)

    turns = [("alice", "bob", "t1"), ("bob", "carol", "t2"), ("carol", "alice", "t3")]
    digests = []
    for idx, (s, r, msg) in enumerate(turns, start=1):
        sender, recipient = agents[s], agents[r]
        env = hybrid_auth_seal(
            msg.encode(), recipient["cpk"], recipient["ppk"], sender["sig_sk"], sender["sig_pk"]
        )
        digest = signature_digest(env)
        assert cache.check(digest) is False
        result = hybrid_auth_open(
            env,
            recipient["csk"],
            recipient["psk"],
            expected_sender_fingerprint=sender["sig_fp"],
            max_age_seconds=300,
        )
        assert result["plaintext"] == msg
        cache.mark(digest)
        digests.append(digest)

    reloaded = ReplayCache(cache_file=str(cache_file), ttl_seconds=300, max_size=20)
    for digest in digests:
        assert reloaded.check(digest) is True


def test_replay_cache_oldest_first_eviction_across_turns(tmp_path, agents):
    cache_file = tmp_path / "replay-cache.json"
    cache = ReplayCache(cache_file=str(cache_file), ttl_seconds=1000, max_size=3)

    digests = []
    pairs = [
        ("alice", "bob"),
        ("bob", "carol"),
        ("carol", "alice"),
        ("alice", "carol"),
        ("bob", "alice"),
    ]
    for i, (s, r) in enumerate(pairs, start=1):
        sender, recipient = agents[s], agents[r]
        env = hybrid_auth_seal(
            f"evict-{i}".encode(),
            recipient["cpk"],
            recipient["ppk"],
            sender["sig_sk"],
            sender["sig_pk"],
        )
        digest = signature_digest(env)
        now = time.time()
        cache.mark(digest, now=now + i)
        digests.append(digest)

    reloaded = ReplayCache(cache_file=str(cache_file), ttl_seconds=1000, max_size=3)
    # Oldest 2 evicted (max_size=3), newest 3 remain
    assert reloaded.check(digests[0]) is False
    assert reloaded.check(digests[1]) is False
    assert reloaded.check(digests[2]) is True
    assert reloaded.check(digests[3]) is True
    assert reloaded.check(digests[4]) is True
