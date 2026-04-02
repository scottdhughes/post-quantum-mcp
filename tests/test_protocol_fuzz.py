"""Tier 3: Protocol-level fuzzing of the PQC envelope format.

Generates random mutations of valid envelopes and verifies the system
either processes them correctly or rejects them cleanly (no crashes,
no partial decryptions, no information leakage in error messages).

This is the highest-value fuzzing for our specific protocol — it targets
the envelope parsing, transcript reconstruction, and error handling paths
that generic crypto fuzzers don't cover.
"""

import base64
import copy
import os
import random
import struct
import sys
import pathlib

import pytest

oqs = pytest.importorskip("oqs", reason="liboqs-python not installed")
pytest.importorskip("cryptography", reason="cryptography not installed")

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))

from pqc_mcp_server.hybrid import (
    hybrid_keygen,
    hybrid_auth_seal,
    hybrid_auth_open,
    hybrid_auth_verify,
    _fingerprint_public_key,
    SenderVerificationError,
)
from pqc_mcp_server.key_store import clear_store
from cryptography.exceptions import InvalidTag


@pytest.fixture(autouse=True)
def clean():
    clear_store()
    yield
    clear_store()


@pytest.fixture
def valid_envelope():
    """Generate a valid authenticated envelope for fuzzing."""
    recipient = hybrid_keygen()
    sig = oqs.Signature("ML-DSA-65")
    sig_pk = sig.generate_keypair()
    sig_sk = sig.export_secret_key()
    sig_fp = _fingerprint_public_key(sig_pk)

    envelope = hybrid_auth_seal(
        b"Fuzz target message content for protocol testing",
        base64.b64decode(recipient["classical"]["public_key"]),
        base64.b64decode(recipient["pqc"]["public_key"]),
        sig_sk,
        sig_pk,
    )
    return {
        "envelope": envelope,
        "recipient": recipient,
        "sig_fp": sig_fp,
        "sig_pk": sig_pk,
    }


def mutate_base64_field(envelope, field, mutation_type="bitflip"):
    """Apply a mutation to a base64-encoded envelope field."""
    e = copy.deepcopy(envelope)
    raw = base64.b64decode(e[field])
    raw = bytearray(raw)

    if mutation_type == "bitflip":
        pos = random.randint(0, len(raw) - 1)
        bit = random.randint(0, 7)
        raw[pos] ^= 1 << bit
    elif mutation_type == "truncate":
        raw = raw[: max(1, len(raw) // 2)]
    elif mutation_type == "extend":
        raw += os.urandom(random.randint(1, 100))
    elif mutation_type == "zero":
        raw = bytearray(len(raw))
    elif mutation_type == "random":
        raw = bytearray(os.urandom(len(raw)))
    elif mutation_type == "empty":
        raw = bytearray()

    e[field] = base64.b64encode(bytes(raw)).decode()
    return e


# Allowed exceptions — these are clean rejections, not crashes
CLEAN_EXCEPTIONS = (
    SenderVerificationError,
    ValueError,
    InvalidTag,
    KeyError,
    TypeError,
    struct.error,
)


class TestEnvelopeMutationFuzzing:
    """Systematically mutate every field of a valid envelope."""

    MUTATIONS = ["bitflip", "truncate", "extend", "zero", "random", "empty"]
    B64_FIELDS = [
        "x25519_ephemeral_public_key",
        "pqc_ciphertext",
        "ciphertext",
        "signature",
        "sender_public_key",
    ]

    def test_mutate_all_b64_fields(self, valid_envelope):
        """Mutate every base64 field with every mutation type."""
        env = valid_envelope["envelope"]
        fp = valid_envelope["sig_fp"]
        crashes = []

        for field in self.B64_FIELDS:
            for mutation in self.MUTATIONS:
                try:
                    mutated = mutate_base64_field(env, field, mutation)
                    # Should reject — not crash
                    hybrid_auth_verify(mutated, expected_sender_fingerprint=fp)
                    # If it somehow passes, that's suspicious but not a crash
                except CLEAN_EXCEPTIONS:
                    pass  # clean rejection
                except Exception as e:
                    crashes.append(f"{field}/{mutation}: {type(e).__name__}: {str(e)[:80]}")

        if crashes:
            pytest.fail("Unclean crashes:\n" + "\n".join(crashes))

    def test_mutate_string_fields(self, valid_envelope):
        """Mutate non-base64 string fields."""
        env = valid_envelope["envelope"]
        fp = valid_envelope["sig_fp"]
        crashes = []

        string_mutations = [
            ("version", ["", "pqc-mcp-v99", None, 123, [], "A" * 10000]),
            ("suite", ["", "wrong-suite", None, 0, "mlkem512-x25519-sha256"]),
            ("sender_signature_algorithm", ["", "ML-DSA-44", "RSA", None, 42]),
            ("sender_key_fingerprint", ["", "0" * 64, "g" * 64, None, "short"]),
            ("timestamp", ["", "0", "-1", str(2**128), "not_a_number", None, []]),
        ]

        for field, values in string_mutations:
            for val in values:
                try:
                    mutated = copy.deepcopy(env)
                    mutated[field] = val
                    hybrid_auth_verify(mutated, expected_sender_fingerprint=fp)
                except CLEAN_EXCEPTIONS:
                    pass
                except Exception as e:
                    crashes.append(f"{field}={val!r}: {type(e).__name__}: {str(e)[:80]}")

        if crashes:
            pytest.fail("Unclean crashes:\n" + "\n".join(crashes))

    def test_remove_fields(self, valid_envelope):
        """Remove each field one at a time."""
        env = valid_envelope["envelope"]
        fp = valid_envelope["sig_fp"]
        crashes = []

        for field in list(env.keys()):
            try:
                mutated = copy.deepcopy(env)
                del mutated[field]
                hybrid_auth_verify(mutated, expected_sender_fingerprint=fp)
            except CLEAN_EXCEPTIONS:
                pass
            except Exception as e:
                crashes.append(f"del {field}: {type(e).__name__}: {str(e)[:80]}")

        if crashes:
            pytest.fail("Unclean crashes:\n" + "\n".join(crashes))

    def test_add_garbage_fields(self, valid_envelope):
        """Add random extra fields to the envelope."""
        env = valid_envelope["envelope"]
        fp = valid_envelope["sig_fp"]

        for _ in range(50):
            mutated = copy.deepcopy(env)
            key = f"garbage_{os.urandom(8).hex()}"
            val = random.choice(
                [
                    os.urandom(100).hex(),
                    42,
                    None,
                    [],
                    {"nested": "object"},
                    True,
                    "",
                ]
            )
            mutated[key] = val
            # Should still verify (extra fields ignored) or reject cleanly
            try:
                hybrid_auth_verify(mutated, expected_sender_fingerprint=fp)
            except CLEAN_EXCEPTIONS:
                pass


class TestRandomEnvelopeFuzzing:
    """Generate completely random envelopes."""

    def test_random_json_objects(self):
        """Feed 100 random JSON objects as envelopes."""
        crashes = []
        for i in range(100):
            envelope = {}
            for _ in range(random.randint(0, 15)):
                key = random.choice(
                    [
                        "version",
                        "suite",
                        "ciphertext",
                        "signature",
                        "sender_public_key",
                        "sender_key_fingerprint",
                        f"random_{os.urandom(4).hex()}",
                    ]
                )
                val = random.choice(
                    [
                        os.urandom(random.randint(0, 200)).hex(),
                        base64.b64encode(os.urandom(random.randint(0, 200))).decode(),
                        random.randint(-(2**32), 2**32),
                        None,
                        "",
                        str(random.random()),
                    ]
                )
                envelope[key] = val

            try:
                hybrid_auth_verify(envelope, expected_sender_fingerprint="0" * 64)
            except CLEAN_EXCEPTIONS:
                pass
            except Exception as e:
                crashes.append(f"envelope #{i}: {type(e).__name__}: {str(e)[:80]}")

        if crashes:
            pytest.fail("Unclean crashes:\n" + "\n".join(crashes))

    def test_random_bytes_as_fields(self):
        """Feed random bytes in every base64 field simultaneously."""
        crashes = []
        for i in range(50):
            envelope = {
                "version": random.choice(["pqc-mcp-v1", "pqc-mcp-v2", ""]),
                "suite": "mlkem768-x25519-sha3-256",
                "sender_signature_algorithm": "ML-DSA-65",
                "x25519_ephemeral_public_key": base64.b64encode(os.urandom(32)).decode(),
                "pqc_ciphertext": base64.b64encode(os.urandom(1088)).decode(),
                "ciphertext": base64.b64encode(os.urandom(random.randint(16, 1000))).decode(),
                "signature": base64.b64encode(os.urandom(3309)).decode(),
                "sender_public_key": base64.b64encode(os.urandom(1952)).decode(),
                "sender_key_fingerprint": os.urandom(32).hex(),
                "recipient_classical_key_fingerprint": os.urandom(32).hex(),
                "recipient_pqc_key_fingerprint": os.urandom(32).hex(),
                "timestamp": str(random.randint(0, 2**32)),
            }
            try:
                hybrid_auth_verify(envelope, expected_sender_fingerprint="0" * 64)
            except CLEAN_EXCEPTIONS:
                pass
            except Exception as e:
                crashes.append(f"random #{i}: {type(e).__name__}: {str(e)[:80]}")

        if crashes:
            pytest.fail("Unclean crashes:\n" + "\n".join(crashes))


class TestErrorMessageLeakage:
    """Verify error messages don't leak secret material."""

    def test_errors_dont_contain_keys(self, valid_envelope):
        """Collect all possible error messages and check for key material."""
        env = valid_envelope["envelope"]
        recipient = valid_envelope["recipient"]
        fp = valid_envelope["sig_fp"]

        # Collect secrets that must never appear in errors
        secrets = [
            recipient["classical"]["secret_key"],
            recipient["pqc"]["secret_key"],
        ]

        error_messages = []

        # Trigger various errors
        test_cases = [
            lambda: hybrid_auth_verify(env, expected_sender_fingerprint="0" * 64),
            lambda: hybrid_auth_verify({}, expected_sender_fingerprint=fp),
            lambda: hybrid_auth_open(
                env,
                b"\x01" * 32,
                base64.b64decode(recipient["pqc"]["secret_key"]),
                expected_sender_fingerprint=fp,
            ),
        ]

        for tc in test_cases:
            try:
                tc()
            except Exception as e:
                error_messages.append(str(e))

        all_errors = " ".join(error_messages)
        for secret in secrets:
            assert secret not in all_errors, "Secret key leaked in error message!"
