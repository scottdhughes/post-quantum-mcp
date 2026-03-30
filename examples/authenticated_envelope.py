#!/usr/bin/env python3
"""Authenticated hybrid sealed envelope — end-to-end example.

Demonstrates:
- Hybrid keypair generation for recipient
- ML-DSA-65 signing keypair generation for sender
- Authenticated seal (sender signs a canonical transcript)
- Authenticated open with fingerprint pinning
- Sender verification before decryption

Suite: mlkem768-x25519-sha3-256
Sender signature: ML-DSA-65 (FIPS 204)

Requires: pip install post-quantum-mcp (or uv sync from repo root)
          liboqs shared library installed (see README)
"""

import base64
import oqs
from pqc_mcp_server.hybrid import (
    hybrid_keygen,
    hybrid_auth_seal,
    hybrid_auth_open,
    _fingerprint_public_key,
)

# --- Recipient generates hybrid keypair ---
print("1. Generating recipient hybrid keypair...")
recipient = hybrid_keygen()
print(f"   X25519 fingerprint: {recipient['classical']['fingerprint']}")
print(f"   ML-KEM fingerprint: {recipient['pqc']['fingerprint']}")
print()

# --- Sender generates ML-DSA-65 signing keypair ---
print("2. Generating sender ML-DSA-65 signing keypair...")
sig = oqs.Signature("ML-DSA-65")
sender_pk = sig.generate_keypair()
sender_sk = sig.export_secret_key()
sender_fp = _fingerprint_public_key(sender_pk)
print(f"   Sender fingerprint: {sender_fp}")
print()

# --- Out-of-band: sender shares fingerprint with recipient ---
print(f"3. Out-of-band: sender shares fingerprint with recipient")
print(f"   '{sender_fp}'")
print()

# --- Sender seals + signs ---
message = "This message is from Scott. Quantum-resistant and sender-verified."
print(f"4. Sealing + signing: {message!r}")
envelope = hybrid_auth_seal(
    message.encode(),
    base64.b64decode(recipient["classical"]["public_key"]),
    base64.b64decode(recipient["pqc"]["public_key"]),
    sender_sk,
    sender_pk,
)
print(f"   Sender algorithm:   {envelope['sender_signature_algorithm']}")
print(f"   Sender fingerprint: {envelope['sender_key_fingerprint']}")
print(f"   Envelope has {len(envelope)} fields (includes signature)")
print()

# --- Recipient verifies sender + decrypts ---
print("5. Verifying sender + decrypting (using fingerprint pinning)...")
result = hybrid_auth_open(
    envelope,
    base64.b64decode(recipient["classical"]["secret_key"]),
    base64.b64decode(recipient["pqc"]["secret_key"]),
    expected_sender_fingerprint=sender_fp,
)
print(f"   Authenticated: {result['authenticated']}")
print(f"   Sender FP:     {result['sender_key_fingerprint']}")
print(f"   Plaintext:     {result['plaintext']}")
print()
print("Done. Sender-authenticated hybrid confidentiality with ciphertext integrity.")
