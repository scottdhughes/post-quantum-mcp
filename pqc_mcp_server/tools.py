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
                }
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
            },
            "required": ["algorithm", "public_key"],
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
            },
            "required": ["algorithm", "secret_key", "ciphertext"],
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
            },
            "required": ["algorithm", "secret_key", "message"],
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
            },
            "required": ["algorithm", "public_key", "message", "signature"],
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
        inputSchema={"type": "object", "properties": {}},
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
            },
            "required": ["classical_public_key", "pqc_public_key"],
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
            },
            "required": [
                "classical_secret_key",
                "pqc_secret_key",
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
            },
            "required": ["recipient_classical_public_key", "recipient_pqc_public_key"],
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
            },
            "required": ["envelope", "classical_secret_key", "pqc_secret_key"],
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
            },
            "required": [
                "recipient_classical_public_key",
                "recipient_pqc_public_key",
                "sender_secret_key",
                "sender_public_key",
            ],
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
            },
            "required": ["envelope", "classical_secret_key", "pqc_secret_key"],
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
]
