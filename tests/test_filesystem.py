"""Tests for secure filesystem helpers."""

import os
import stat


from pqc_mcp_server.filesystem import ensure_secure_directory, ensure_secure_file


class TestEnsureSecureDirectory:
    def test_creates_directory_with_700(self, tmp_path):
        target = str(tmp_path / "secure_dir")
        ensure_secure_directory(target)
        assert os.path.isdir(target)
        mode = stat.S_IMODE(os.stat(target).st_mode)
        assert mode == 0o700

    def test_existing_directory_gets_700(self, tmp_path):
        target = str(tmp_path / "loose_dir")
        os.makedirs(target, mode=0o755)
        ensure_secure_directory(target)
        mode = stat.S_IMODE(os.stat(target).st_mode)
        assert mode == 0o700

    def test_nested_creation(self, tmp_path):
        target = str(tmp_path / "a" / "b" / "c")
        ensure_secure_directory(target)
        assert os.path.isdir(target)


class TestEnsureSecureFile:
    def test_existing_file_gets_600(self, tmp_path):
        f = tmp_path / "secret.json"
        f.write_text("{}")
        os.chmod(str(f), 0o644)
        ensure_secure_file(str(f))
        mode = stat.S_IMODE(os.stat(str(f)).st_mode)
        assert mode == 0o600

    def test_nonexistent_file_is_noop(self, tmp_path):
        f = str(tmp_path / "missing.json")
        ensure_secure_file(f)  # should not raise
        assert not os.path.exists(f)
