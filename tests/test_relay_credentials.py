"""Credentials are read from server-owned configuration, never model arguments."""

import json
import os

import pytest

from pqc_mcp_server import _get_relay_config
from pqc_mcp_server.relay_client import RelayConfigError

FP = "a" * 64


def configure(monkeypatch, tmp_path, data):
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps(data))
    path.chmod(0o600)
    monkeypatch.setenv("PQC_RELAY_ENABLED", "1")
    monkeypatch.setenv("PQC_RELAY_ALLOWED_URLS", "https://relay.example")
    monkeypatch.setenv("PQC_RELAY_TOKEN_FILE", str(path))
    return path


def test_credentials_are_scoped_by_origin_and_mailbox(monkeypatch, tmp_path):
    configure(
        monkeypatch,
        tmp_path,
        [{"relay_url": "https://relay.example/", "fingerprint": FP, "token": "private-test-token"}],
    )
    assert _get_relay_config()["mailbox_tokens"] == {
        ("https://relay.example", FP): "private-test-token"
    }


def test_insecure_credential_file_is_rejected_without_disclosing_contents(monkeypatch, tmp_path):
    path = configure(monkeypatch, tmp_path, [{"token": "private-test-token"}])
    path.chmod(0o644)
    with pytest.raises(RelayConfigError) as error:
        _get_relay_config()
    assert "private-test-token" not in str(error.value)


@pytest.mark.parametrize("value", ["nan", "inf", "0", "-1"])
def test_timeout_configuration_rejects_nonpositive_or_nonfinite_values(monkeypatch, value):
    monkeypatch.setenv("PQC_RELAY_ENABLED", "1")
    monkeypatch.setenv("PQC_RELAY_ALLOWED_URLS", "https://relay.example")
    monkeypatch.setenv("PQC_RELAY_TIMEOUT_READ", value)
    with pytest.raises(RelayConfigError):
        _get_relay_config()
