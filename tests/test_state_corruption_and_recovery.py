"""State corruption and recovery tests.

Verifies deterministic behavior when state files are malformed,
missing, truncated, or unreadable. The system should either:
- Fail open with predictable reset (best-effort state like replay cache)
- Fail closed with clear error (security-critical state)
- Never crash unpredictably or silently weaken guarantees
"""

import json
import os
import stat

import pytest

oqs = pytest.importorskip("oqs", reason="liboqs-python not installed")
pytest.importorskip("cryptography", reason="cryptography not installed")

from pqc_mcp_server.replay_cache import ReplayCache, signature_digest
from pqc_mcp_server.filesystem import ensure_secure_directory, ensure_secure_file

# ═══════════════════════════════════════════════
# Replay Cache Corruption
# ═══════════════════════════════════════════════


class TestReplayCacheCorruption:
    """Replay cache must handle corrupted state predictably."""

    def test_malformed_json(self, tmp_path):
        """Malformed JSON resets to empty — does not crash."""
        cache_file = tmp_path / "replay.json"
        cache_file.write_text("{ this is not valid json !!!")
        cache = ReplayCache(cache_file=str(cache_file), ttl_seconds=60, max_size=10)
        assert len(cache._cache) == 0
        # Should still function normally after reset
        assert cache.check_and_mark("test-digest") is False
        assert cache.check("test-digest") is True

    def test_empty_file(self, tmp_path):
        """Empty file resets to empty — does not crash."""
        cache_file = tmp_path / "replay.json"
        cache_file.write_text("")
        cache = ReplayCache(cache_file=str(cache_file), ttl_seconds=60, max_size=10)
        assert len(cache._cache) == 0

    def test_truncated_json(self, tmp_path):
        """Truncated JSON (partial write simulation) resets cleanly."""
        cache_file = tmp_path / "replay.json"
        cache_file.write_text('{"abc": 12345')  # missing closing brace
        cache = ReplayCache(cache_file=str(cache_file), ttl_seconds=60, max_size=10)
        assert len(cache._cache) == 0

    def test_json_array_instead_of_dict(self, tmp_path):
        """Wrong JSON type (array instead of dict) resets cleanly."""
        cache_file = tmp_path / "replay.json"
        cache_file.write_text("[1, 2, 3]")
        cache = ReplayCache(cache_file=str(cache_file), ttl_seconds=60, max_size=10)
        assert len(cache._cache) == 0

    def test_json_with_non_numeric_values(self, tmp_path):
        """Values that can't be converted to float reset cleanly."""
        cache_file = tmp_path / "replay.json"
        cache_file.write_text('{"digest1": "not_a_number", "digest2": null}')
        cache = ReplayCache(cache_file=str(cache_file), ttl_seconds=60, max_size=10)
        assert len(cache._cache) == 0

    def test_missing_cache_file(self, tmp_path):
        """Non-existent file starts empty — no error."""
        cache_file = tmp_path / "does_not_exist.json"
        cache = ReplayCache(cache_file=str(cache_file), ttl_seconds=60, max_size=10)
        assert len(cache._cache) == 0

    def test_missing_state_directory(self, tmp_path):
        """Non-existent parent directory — save creates it."""
        cache_file = tmp_path / "nonexistent" / "subdir" / "replay.json"
        cache = ReplayCache(cache_file=str(cache_file), ttl_seconds=60, max_size=10)
        cache.check_and_mark("test")
        # Directory should have been created by _save
        assert os.path.exists(str(cache_file))

    def test_recovery_after_corruption(self, tmp_path):
        """Cache recovers and persists correctly after corruption."""
        cache_file = tmp_path / "replay.json"

        # Start corrupted
        cache_file.write_text("CORRUPTED!!!")
        cache = ReplayCache(cache_file=str(cache_file), ttl_seconds=300, max_size=10)
        assert len(cache._cache) == 0

        # Add entries — should persist cleanly
        cache.check_and_mark("digest-a")
        cache.check_and_mark("digest-b")

        # Reload — should find both entries
        cache2 = ReplayCache(cache_file=str(cache_file), ttl_seconds=300, max_size=10)
        assert cache2.check("digest-a") is True
        assert cache2.check("digest-b") is True

    def test_binary_garbage_file(self, tmp_path):
        """Binary garbage in cache file resets cleanly."""
        cache_file = tmp_path / "replay.json"
        cache_file.write_bytes(os.urandom(256))
        cache = ReplayCache(cache_file=str(cache_file), ttl_seconds=60, max_size=10)
        assert len(cache._cache) == 0


# ═══════════════════════════════════════════════
# Filesystem Helper Edge Cases
# ═══════════════════════════════════════════════


class TestFilesystemHelperEdgeCases:
    """Filesystem security helpers under adverse conditions."""

    def test_secure_dir_nested_creation(self, tmp_path):
        """Creates nested directories with 0700."""
        target = str(tmp_path / "a" / "b" / "c")
        ensure_secure_directory(target)
        assert os.path.isdir(target)
        mode = stat.S_IMODE(os.stat(target).st_mode)
        assert mode == 0o700

    def test_secure_dir_already_exists(self, tmp_path):
        """Existing directory gets permissions tightened."""
        target = str(tmp_path / "existing")
        os.makedirs(target, mode=0o755)
        ensure_secure_directory(target)
        mode = stat.S_IMODE(os.stat(target).st_mode)
        assert mode == 0o700

    def test_secure_file_nonexistent_is_noop(self, tmp_path):
        """Non-existent file — does not create, does not crash."""
        target = str(tmp_path / "nonexistent.json")
        ensure_secure_file(target)
        assert not os.path.exists(target)

    def test_secure_file_tightens_permissions(self, tmp_path):
        """Existing file gets permissions tightened to 0600."""
        target = tmp_path / "loose.json"
        target.write_text("{}")
        os.chmod(str(target), 0o644)
        ensure_secure_file(str(target))
        mode = stat.S_IMODE(os.stat(str(target)).st_mode)
        assert mode == 0o600


# ═══════════════════════════════════════════════
# Identity/Contact Card Corruption
# ═══════════════════════════════════════════════


class TestIdentityCardCorruption:
    """Malformed identity/contact cards should be detected, not silently accepted."""

    def test_malformed_contact_fingerprint_detected(self):
        """A contact with inconsistent fingerprint should be detectable."""
        import base64
        from pqc_mcp_server.hybrid import _fingerprint_public_key

        sig = oqs.Signature("ML-DSA-65")
        pk = sig.generate_keypair()
        real_fp = _fingerprint_public_key(pk)

        # Tampered card: real key but wrong fingerprint
        card = {
            "name": "tampered",
            "signing": {
                "public_key": base64.b64encode(pk).decode(),
                "fingerprint": "0" * 64,  # wrong
            },
        }

        pk_bytes = base64.b64decode(card["signing"]["public_key"])
        computed_fp = _fingerprint_public_key(pk_bytes)
        assert computed_fp != card["signing"]["fingerprint"]
        assert computed_fp == real_fp

    def test_empty_contact_card_fields(self):
        """Empty public key in contact card should be caught by validation."""
        import base64
        from pqc_mcp_server.hybrid import _validate_mlkem768_pk

        with pytest.raises(ValueError, match="exactly"):
            _validate_mlkem768_pk(b"", "empty_pk")

        with pytest.raises(ValueError, match="exactly"):
            _validate_mlkem768_pk(b"\x00" * 100, "short_pk")
