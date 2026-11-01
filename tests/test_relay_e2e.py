"""Opt-in integration against an explicitly selected disposable relay deployment.

Set PQC_RELAY_E2E_URL and PQC_RELAY_E2E_ADMIN_TOKEN, then run pytest -m e2e.
No public service is selected or modified by default.
"""

import base64
import hashlib
import os

import httpx
import pytest

from pqc_mcp_server.relay_client import RelayClient, parse_relay_allowlist
from pqc_mcp_server.hybrid import (
    hybrid_keygen,
    hybrid_auth_seal,
    hybrid_auth_verify,
    hybrid_auth_open,
)

pytestmark = pytest.mark.e2e


@pytest.fixture
def relay():
    url = os.environ.get("PQC_RELAY_E2E_URL")
    if not url:
        pytest.skip("PQC_RELAY_E2E_URL is required for explicit relay integration")
    admin = os.environ.get("PQC_RELAY_E2E_ADMIN_TOKEN")
    if not admin:
        pytest.fail("PQC_RELAY_E2E_ADMIN_TOKEN is required for disposable test mailboxes")
    allowed = parse_relay_allowlist(
        url, allow_http=os.environ.get("PQC_RELAY_E2E_ALLOW_HTTP") == "1"
    )
    origin = next(iter(allowed))
    fp = hashlib.sha256(os.urandom(32)).hexdigest()
    with httpx.Client(trust_env=False, follow_redirects=False) as operator:
        registration = operator.post(
            f"{origin}/mailboxes/{fp}/register", headers={"Authorization": f"Bearer {admin}"}
        )
        registration.raise_for_status()
        token = registration.json()["token"]
    client = RelayClient(allowed, mailbox_tokens={(origin, fp): token})
    try:
        yield client, origin, fp
    finally:
        for message in client.fetch(origin, fp)["envelopes"]:
            client.ack(origin, fp, message["message_id"])


def test_authenticated_mailbox_transport(relay):
    client, origin, fp = relay
    envelope = {"version": "pqc-mcp-v3", "suite": "test", "ciphertext": "dGVzdA=="}
    assert client.fetch(origin, fp)["count"] == 0
    first = client.deposit(origin, fp, envelope)
    assert client.deposit(origin, fp, envelope)["message_id"] == first["message_id"]
    messages = client.fetch(origin, fp)["envelopes"]
    assert len(messages) == 1
    assert messages[0]["envelope"] == envelope
    assert client.ack(origin, fp, first["message_id"])["acknowledged"]
    assert client.ack(origin, fp, first["message_id"])["acknowledged"]
    assert client.fetch(origin, fp)["count"] == 0


def test_full_authenticated_crypto_lifecycle(relay):
    import oqs

    client, origin, fp = relay
    keys = hybrid_keygen()
    d = base64.b64decode
    with oqs.Signature("ML-DSA-65") as signer:
        sender_pk = signer.generate_keypair()
        sender_sk = signer.export_secret_key()
    envelope = hybrid_auth_seal(
        b"authenticated integration message",
        d(keys["classical"]["public_key"]),
        d(keys["pqc"]["public_key"]),
        sender_sk,
        sender_pk,
    )
    receipt = client.deposit(origin, fp, envelope)
    fetched = client.fetch(origin, fp)["envelopes"][0]["envelope"]
    assert hybrid_auth_verify(fetched, expected_sender_public_key=sender_pk)["verified"]
    result = hybrid_auth_open(
        fetched,
        d(keys["classical"]["secret_key"]),
        d(keys["pqc"]["secret_key"]),
        expected_sender_public_key=sender_pk,
    )
    assert result["plaintext"] == "authenticated integration message"
    assert client.ack(origin, fp, receipt["message_id"])["acknowledged"]
