"""MCP tool definitions for the PQC server.

Each tool is a Tool object with name, description, and inputSchema.
Separated from handlers for clarity.
"""

from mcp.types import Tool

PQC_TOOLS: list[Tool] = [
    Tool(
        name="pqc_list_algorithms",
        description="List all available post-quantum cryptographic algorithms (KEMs and signatures)",
        inputSchema={
            "type": "object",
            "properties": {
                "type": {
                    "type": "string",
                    "enum": ["all", "kem", "sig"],
                    "description": "Filter by algorithm type",
                    "default": "all",
                }
            },
        },
    ),
    Tool(
        name="pqc_algorithm_info",
        description="Get detailed information about a specific PQC algorithm including security level, key sizes, and performance characteristics",
        inputSchema={
            "type": "object",
            "properties": {
                "algorithm": {
                    "type": "string",
                    "description": "Algorithm name (e.g., 'ML-KEM-768', 'ML-DSA-65')",
                }
            },
            "required": ["algorithm"],
        },
    ),
    Tool(
        name="pqc_generate_keypair",
        description="Generate a post-quantum key pair for KEM or signature algorithm",
        inputSchema={
            "type": "object",
            "properties": {
                "algorithm": {
                    "type": "string",
                    "description": "Algorithm name (e.g., 'ML-KEM-768', 'ML-DSA-65')",
                },
                "store_as": {
                    "type": "string",
                    "description": "Optional name to store the keypair handle (secret key never returned)",
                },
                "overwrite": {
                    "type": "boolean",
                    "description": "If true, overwrite an existing stored key with the same name",
                },
            },
            "required": ["algorithm"],
        },
    ),
    Tool(
        name="pqc_encapsulate",
        description="Encapsulate a shared secret using a KEM public key (key encapsulation)",
        inputSchema={
            "type": "object",
            "properties": {
                "algorithm": {"type": "string", "description": "KEM algorithm name"},
                "public_key": {"type": "string", "description": "Base64-encoded public key"},
                "key_store_name": {
                    "type": "string",
                    "description": "Name of stored KEM keypair",
                },
            },
            "required": ["algorithm"],
        },
    ),
    Tool(
        name="pqc_decapsulate",
        description="Decapsulate a shared secret using a KEM secret key",
        inputSchema={
            "type": "object",
            "properties": {
                "algorithm": {"type": "string", "description": "KEM algorithm name"},
                "secret_key": {"type": "string", "description": "Base64-encoded secret key"},
                "ciphertext": {
                    "type": "string",
                    "description": "Base64-encoded ciphertext from encapsulation",
                },
                "key_store_name": {
                    "type": "string",
                    "description": "Name of stored KEM keypair",
                },
            },
            "required": ["algorithm", "ciphertext"],
        },
    ),
    Tool(
        name="pqc_sign",
        description="Sign a message using a PQC signature algorithm",
        inputSchema={
            "type": "object",
            "properties": {
                "algorithm": {
                    "type": "string",
                    "description": "Signature algorithm name (e.g., 'ML-DSA-65')",
                },
                "secret_key": {
                    "type": "string",
                    "description": "Base64-encoded secret/signing key",
                },
                "message": {
                    "type": "string",
                    "description": "Message to sign (will be UTF-8 encoded)",
                },
                "key_store_name": {
                    "type": "string",
                    "description": "Name of stored signing keypair",
                },
            },
            "required": ["algorithm", "message"],
        },
    ),
    Tool(
        name="pqc_verify",
        description="Verify a signature using a PQC signature algorithm",
        inputSchema={
            "type": "object",
            "properties": {
                "algorithm": {"type": "string", "description": "Signature algorithm name"},
                "public_key": {
                    "type": "string",
                    "description": "Base64-encoded public/verification key",
                },
                "message": {"type": "string", "description": "Original message"},
                "signature": {"type": "string", "description": "Base64-encoded signature"},
                "key_store_name": {
                    "type": "string",
                    "description": "Name of stored signing keypair",
                },
            },
            "required": ["algorithm", "message", "signature"],
        },
    ),
    Tool(
        name="pqc_hash",
        description="Compute a quantum-safe hash digest (SHA3-256, SHA3-512, SHAKE128, SHAKE256)",
        inputSchema={
            "type": "object",
            "properties": {
                "message": {"type": "string", "description": "Message to hash"},
                "algorithm": {
                    "type": "string",
                    "enum": ["SHA3-256", "SHA3-512", "SHAKE128", "SHAKE256"],
                    "default": "SHA3-256",
                },
            },
            "required": ["message"],
        },
    ),
    Tool(
        name="pqc_security_analysis",
        description="Educational estimate of security properties: maps NIST levels to classical/quantum equivalents. This is a static lookup, not a formal per-algorithm analysis.",
        inputSchema={
            "type": "object",
            "properties": {"algorithm": {"type": "string", "description": "Algorithm to analyze"}},
            "required": ["algorithm"],
        },
    ),
    Tool(
        name="pqc_hybrid_keygen",
        description="Generate a hybrid X25519 + ML-KEM-768 keypair bundle (suite: mlkem768-x25519-sha3-256). Research/prototyping only.",
        inputSchema={
            "type": "object",
            "properties": {
                "store_as": {
                    "type": "string",
                    "description": "Optional name to store the keypair handle (secret key never returned)",
                },
                "overwrite": {
                    "type": "boolean",
                    "description": "If true, overwrite an existing stored key with the same name",
                },
            },
        },
    ),
    Tool(
        name="pqc_hybrid_encap",
        description="Perform hybrid X25519 + ML-KEM-768 key encapsulation. Returns combined shared secret + ciphertexts.",
        inputSchema={
            "type": "object",
            "properties": {
                "classical_public_key": {
                    "type": "string",
                    "description": "Base64-encoded raw 32-byte X25519 public key",
                },
                "pqc_public_key": {
                    "type": "string",
                    "description": "Base64-encoded ML-KEM-768 public key",
                },
                "key_store_name": {
                    "type": "string",
                    "description": "Name of stored hybrid key bundle",
                },
            },
        },
    ),
    Tool(
        name="pqc_hybrid_decap",
        description="Recover hybrid shared secret using both secret keys.",
        inputSchema={
            "type": "object",
            "properties": {
                "classical_secret_key": {
                    "type": "string",
                    "description": "Base64-encoded raw 32-byte X25519 secret key",
                },
                "pqc_secret_key": {
                    "type": "string",
                    "description": "Base64-encoded ML-KEM-768 secret key",
                },
                "x25519_ephemeral_public_key": {
                    "type": "string",
                    "description": "Base64-encoded raw 32-byte ephemeral public key from encap",
                },
                "pqc_ciphertext": {
                    "type": "string",
                    "description": "Base64-encoded ML-KEM-768 ciphertext from encap",
                },
                "key_store_name": {
                    "type": "string",
                    "description": "Name of stored hybrid key bundle",
                },
            },
            "required": [
                "x25519_ephemeral_public_key",
                "pqc_ciphertext",
            ],
        },
    ),
    Tool(
        name="pqc_hybrid_seal",
        description="Encrypt plaintext using hybrid X25519 + ML-KEM-768 + AES-256-GCM. Anonymous sealed-box. Research/prototyping only.",
        inputSchema={
            "type": "object",
            "properties": {
                "plaintext": {
                    "type": "string",
                    "description": "UTF-8 string to encrypt (mutually exclusive with plaintext_base64)",
                },
                "plaintext_base64": {
                    "type": "string",
                    "description": "Base64-encoded binary data (mutually exclusive with plaintext)",
                },
                "recipient_classical_public_key": {
                    "type": "string",
                    "description": "Base64-encoded raw 32-byte X25519 public key",
                },
                "recipient_pqc_public_key": {
                    "type": "string",
                    "description": "Base64-encoded ML-KEM-768 public key",
                },
                "recipient_key_store_name": {
                    "type": "string",
                    "description": "Name of stored hybrid key bundle",
                },
            },
        },
    ),
    Tool(
        name="pqc_hybrid_open",
        description="Decrypt a hybrid sealed envelope using both secret keys.",
        inputSchema={
            "type": "object",
            "properties": {
                "envelope": {
                    "type": "object",
                    "description": "Sealed envelope from pqc_hybrid_seal",
                },
                "classical_secret_key": {
                    "type": "string",
                    "description": "Base64-encoded raw 32-byte X25519 secret key",
                },
                "pqc_secret_key": {
                    "type": "string",
                    "description": "Base64-encoded ML-KEM-768 secret key",
                },
                "key_store_name": {
                    "type": "string",
                    "description": "Name of stored hybrid key bundle",
                },
            },
            "required": ["envelope"],
        },
    ),
    Tool(
        name="pqc_hybrid_auth_seal",
        description="Encrypt + sign: sender-authenticated hybrid sealed envelope using ML-DSA-65. Research/prototyping only.",
        inputSchema={
            "type": "object",
            "properties": {
                "plaintext": {
                    "type": "string",
                    "description": "UTF-8 string to encrypt (mutually exclusive with plaintext_base64)",
                },
                "plaintext_base64": {
                    "type": "string",
                    "description": "Base64-encoded binary data (mutually exclusive with plaintext)",
                },
                "recipient_classical_public_key": {
                    "type": "string",
                    "description": "Base64-encoded raw 32-byte X25519 public key",
                },
                "recipient_pqc_public_key": {
                    "type": "string",
                    "description": "Base64-encoded ML-KEM-768 public key",
                },
                "sender_secret_key": {
                    "type": "string",
                    "description": "Base64-encoded ML-DSA-65 secret/signing key",
                },
                "sender_public_key": {
                    "type": "string",
                    "description": "Base64-encoded ML-DSA-65 public/verification key",
                },
                "recipient_key_store_name": {
                    "type": "string",
                    "description": "Name of stored hybrid key bundle for recipient",
                },
                "sender_key_store_name": {
                    "type": "string",
                    "description": "Name of stored signing keypair for sender",
                },
            },
        },
    ),
    Tool(
        name="pqc_hybrid_auth_open",
        description="Verify sender + decrypt: authenticated hybrid envelope. Requires expected sender identity. Signature verified before decryption.",
        inputSchema={
            "type": "object",
            "properties": {
                "envelope": {
                    "type": "object",
                    "description": "Authenticated envelope from pqc_hybrid_auth_seal",
                },
                "classical_secret_key": {
                    "type": "string",
                    "description": "Base64-encoded raw 32-byte X25519 secret key",
                },
                "pqc_secret_key": {
                    "type": "string",
                    "description": "Base64-encoded ML-KEM-768 secret key",
                },
                "expected_sender_public_key": {
                    "type": "string",
                    "description": "Base64-encoded ML-DSA-65 public key (exactly one of this or expected_sender_fingerprint required)",
                },
                "expected_sender_fingerprint": {
                    "type": "string",
                    "description": "SHA3-256 hex fingerprint of sender public key",
                },
                "key_store_name": {
                    "type": "string",
                    "description": "Name of stored hybrid key bundle",
                },
            },
            "required": ["envelope"],
        },
    ),
    Tool(
        name="pqc_fingerprint",
        description="Compute SHA3-256 fingerprint of a public key. Returns lowercase hex.",
        inputSchema={
            "type": "object",
            "properties": {
                "public_key": {
                    "type": "string",
                    "description": "Base64-encoded public key (any algorithm)",
                },
            },
            "required": ["public_key"],
        },
    ),
    Tool(
        name="pqc_envelope_inspect",
        description="Inspect a sealed or authenticated envelope's metadata without decrypting. No secret keys needed.",
        inputSchema={
            "type": "object",
            "properties": {
                "envelope": {
                    "type": "object",
                    "description": "Envelope from pqc_hybrid_seal, pqc_hybrid_open, pqc_hybrid_auth_seal, or pqc_hybrid_auth_open",
                },
            },
            "required": ["envelope"],
        },
    ),
    Tool(
        name="pqc_benchmark",
        description="Benchmark a PQC algorithm: timed keygen, encap/sign, decap/verify, and key/ciphertext/signature sizes.",
        inputSchema={
            "type": "object",
            "properties": {
                "algorithm": {
                    "type": "string",
                    "description": "Algorithm name (e.g., 'ML-KEM-768', 'ML-DSA-65')",
                },
                "iterations": {
                    "type": "integer",
                    "description": "Number of iterations to average (default 10, max 100)",
                    "default": 10,
                },
            },
            "required": ["algorithm"],
        },
    ),
    Tool(
        name="pqc_key_store_save",
        description="Save a keygen output by name for convenient reference. Session-scoped, no persistence.",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Name for this key (e.g., 'alice-signing', 'bob-hybrid')",
                },
                "key_data": {
                    "type": "object",
                    "description": "Key data object (output of pqc_hybrid_keygen or pqc_generate_keypair)",
                },
            },
            "required": ["name", "key_data"],
        },
    ),
    Tool(
        name="pqc_key_store_load",
        description="Load a stored key by name.",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Name of the stored key"},
            },
            "required": ["name"],
        },
    ),
    Tool(
        name="pqc_key_store_list",
        description="List all stored keys with metadata (names, types, fingerprints). No secret material shown.",
        inputSchema={"type": "object", "properties": {}},
    ),
    Tool(
        name="pqc_key_store_delete",
        description="Delete a stored key by name.",
        inputSchema={
            "type": "object",
            "properties": {
                "name": {"type": "string", "description": "Name of the key to delete"},
            },
            "required": ["name"],
        },
    ),
]
