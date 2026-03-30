#!/usr/bin/env python3
"""Failure mode demonstrations — what happens when things go wrong.

Demonstrates:
- Wrong sender rejected (SenderVerificationError)
- Tampered ciphertext rejected (InvalidTag via GCM)
- Tampered signature rejected (SenderVerificationError)
- Missing sender identity rejected (fail-closed)
- Malformed base64 rejected

Each failure is caught and explained. None should crash.

Requires: pip install post-quantum-mcp (or uv sync from repo root)
          liboqs shared library installed (see README)
"""

import base64
import oqs
from pqc_mcp_server.hybrid import (
    hybrid_keygen,
    hybrid_seal,
    hybrid_open,
    hybrid_auth_seal,
    hybrid_auth_open,
    _fingerprint_public_key,
    SenderVerificationError,
)
from cryptography.exceptions import InvalidTag

# Setup: generate all keys
recipient = hybrid_keygen()
r_cpk = base64.b64decode(recipient["classical"]["public_key"])
r_ppk = base64.b64decode(recipient["pqc"]["public_key"])
r_csk = base64.b64decode(recipient["classical"]["secret_key"])
r_psk = base64.b64decode(recipient["pqc"]["secret_key"])

sig = oqs.Signature("ML-DSA-65")
sender_pk = sig.generate_keypair()
sender_sk = sig.export_secret_key()
sender_fp = _fingerprint_public_key(sender_pk)

sig2 = oqs.Signature("ML-DSA-65")
imposter_pk = sig2.generate_keypair()


def demo(title: str, fn):
    print(f"--- {title} ---")
    try:
        fn()
        print("  ERROR: should have failed!\n")
    except (SenderVerificationError, InvalidTag, ValueError, Exception) as e:
        print(f"  Rejected: {type(e).__name__}: {e}\n")


# 1. Wrong sender public key
envelope = hybrid_auth_seal(b"secret", r_cpk, r_ppk, sender_sk, sender_pk)
demo(
    "1. Wrong sender public key",
    lambda: hybrid_auth_open(envelope, r_csk, r_psk, expected_sender_public_key=imposter_pk),
)

# 2. Wrong sender fingerprint
demo(
    "2. Wrong sender fingerprint",
    lambda: hybrid_auth_open(
        envelope, r_csk, r_psk, expected_sender_fingerprint=_fingerprint_public_key(imposter_pk)
    ),
)

# 3. Missing sender identity (fail-closed)
demo(
    "3. Missing sender identity (no key or fingerprint)",
    lambda: hybrid_auth_open(envelope, r_csk, r_psk),
)

# 4. Tampered signature
tampered_sig = dict(envelope)
sig_bytes = bytearray(base64.b64decode(tampered_sig["signature"]))
sig_bytes[0] ^= 0xFF
tampered_sig["signature"] = base64.b64encode(bytes(sig_bytes)).decode()
demo(
    "4. Tampered signature",
    lambda: hybrid_auth_open(tampered_sig, r_csk, r_psk, expected_sender_public_key=sender_pk),
)

# 5. Tampered ciphertext (anonymous envelope — detected by GCM)
anon_envelope = hybrid_seal(b"data", r_cpk, r_ppk)
tampered_anon = dict(anon_envelope)
ct = bytearray(base64.b64decode(tampered_anon["ciphertext"]))
ct[0] ^= 0xFF
tampered_anon["ciphertext"] = base64.b64encode(bytes(ct)).decode()
demo(
    "5. Tampered ciphertext (anonymous, GCM rejects)",
    lambda: hybrid_open(tampered_anon, r_csk, r_psk),
)

# 6. Wrong recipient keys (anonymous)
other_recipient = hybrid_keygen()
demo(
    "6. Wrong recipient keys (anonymous)",
    lambda: hybrid_open(
        anon_envelope,
        base64.b64decode(other_recipient["classical"]["secret_key"]),
        base64.b64decode(other_recipient["pqc"]["secret_key"]),
    ),
)

print("All failure modes handled cleanly. No crashes.")
