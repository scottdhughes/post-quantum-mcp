#!/usr/bin/env python3
"""Anonymous hybrid sealed envelope — end-to-end example.

Demonstrates:
- Hybrid keypair generation (X25519 + ML-KEM-768)
- Anonymous seal (anyone with public keys can encrypt)
- Open (recipient decrypts with private keys)

Suite: mlkem768-x25519-sha3-256
No sender authentication — see authenticated_envelope.py for that.

Requires: pip install post-quantum-mcp (or uv sync from repo root)
          liboqs shared library installed (see README)
"""

import base64
from pqc_mcp_server.hybrid import hybrid_keygen, hybrid_seal, hybrid_open

# --- Recipient generates a hybrid keypair ---
print("1. Generating recipient hybrid keypair...")
recipient = hybrid_keygen()
print(f"   Suite:              {recipient['suite']}")
print(f"   X25519 fingerprint: {recipient['classical']['fingerprint']}")
print(f"   ML-KEM fingerprint: {recipient['pqc']['fingerprint']}")
print()

# --- Sender encrypts a message (no identity needed) ---
message = "The quantum computers are coming. Prepare accordingly."
print(f"2. Sealing message: {message!r}")
envelope = hybrid_seal(
    message.encode(),
    base64.b64decode(recipient["classical"]["public_key"]),
    base64.b64decode(recipient["pqc"]["public_key"]),
)
print(f"   Version: {envelope['version']}")
print(f"   Suite:   {envelope['suite']}")
print(f"   Envelope has {len(envelope)} fields (no nonce — deterministically derived)")
print()

# --- Recipient decrypts ---
print("3. Opening envelope...")
result = hybrid_open(
    envelope,
    base64.b64decode(recipient["classical"]["secret_key"]),
    base64.b64decode(recipient["pqc"]["secret_key"]),
)
print(f"   Plaintext: {result['plaintext']}")
print(f"   Match:     {result['plaintext'] == message}")
print()
print("Done. Anonymous hybrid confidentiality with ciphertext integrity.")
