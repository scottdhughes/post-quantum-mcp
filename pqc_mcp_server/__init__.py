"""
Post-Quantum Cryptography MCP Server

Provides MCP tools for post-quantum cryptographic operations using:
- ML-KEM (Kyber) for key encapsulation
- ML-DSA (Dilithium) for digital signatures
- SLH-DSA (SPHINCS+) for hash-based signatures
- FrodoKEM for conservative KEM

Uses liboqs (Open Quantum Safe) as the cryptographic backend.
"""

import json
import base64
import hashlib
from typing import Any
import asyncio

try:
    import oqs
    from oqs import MechanismNotSupportedError, MechanismNotEnabledError

    HAS_LIBOQS = True
except ImportError:
    HAS_LIBOQS = False
    MechanismNotSupportedError = Exception
    MechanismNotEnabledError = Exception

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Initialize MCP server
server = Server("pqc-mcp-server")

# NIST PQC Algorithm mappings
KEM_ALGORITHMS = {
    "ML-KEM-512": "ML-KEM-512",
    "ML-KEM-768": "ML-KEM-768",
    "ML-KEM-1024": "ML-KEM-1024",
    "Kyber512": "Kyber512",
    "Kyber768": "Kyber768",
    "Kyber1024": "Kyber1024",
    "FrodoKEM-640-SHAKE": "FrodoKEM-640-SHAKE",
    "FrodoKEM-976-SHAKE": "FrodoKEM-976-SHAKE",
    "FrodoKEM-1344-SHAKE": "FrodoKEM-1344-SHAKE",
    "HQC-128": "HQC-128",
    "HQC-192": "HQC-192",
    "HQC-256": "HQC-256",
}

SIG_ALGORITHMS = {
    "ML-DSA-44": "ML-DSA-44",
    "ML-DSA-65": "ML-DSA-65",
    "ML-DSA-87": "ML-DSA-87",
    "Dilithium2": "Dilithium2",
    "Dilithium3": "Dilithium3",
    "Dilithium5": "Dilithium5",
    "Falcon-512": "Falcon-512",
    "Falcon-1024": "Falcon-1024",
    "SPHINCS+-SHA2-128f-simple": "SPHINCS+-SHA2-128f-simple",
    "SPHINCS+-SHA2-128s-simple": "SPHINCS+-SHA2-128s-simple",
    "SPHINCS+-SHA2-192f-simple": "SPHINCS+-SHA2-192f-simple",
    "SPHINCS+-SHA2-256f-simple": "SPHINCS+-SHA2-256f-simple",
}


def get_available_algorithms() -> dict:
    """Get available algorithms from liboqs."""
    if not HAS_LIBOQS:
        return {"error": "liboqs not installed"}

    return {
        "kem_algorithms": oqs.get_enabled_kem_mechanisms(),
        "sig_algorithms": oqs.get_enabled_sig_mechanisms(),
    }


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available PQC tools."""
    return [
        Tool(
            name="pqc_list_algorithms",
            description="List all available post-quantum cryptographic algorithms (KEMs and signatures)",
            inputSchema={
                "type": "object",
                "properties": {
                    "type": {
                        "type": "string",
                        "enum": ["all", "kem", "sig"],
                        "description": "Filter by algorithm type: 'kem' for key encapsulation, 'sig' for signatures, 'all' for both",
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
                        "description": "Algorithm name (e.g., 'ML-KEM-768', 'ML-DSA-65', 'SPHINCS+-SHA2-128f-simple')",
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
            name="pqc_hash_to_curve",
            description="Hash a message to a point suitable for PQC operations (SHA3-256)",
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
            description="Analyze security properties and compare classical vs quantum security levels",
            inputSchema={
                "type": "object",
                "properties": {
                    "algorithm": {"type": "string", "description": "Algorithm to analyze"}
                },
                "required": ["algorithm"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Handle tool calls."""

    if not HAS_LIBOQS:
        return [
            TextContent(
                type="text",
                text=json.dumps(
                    {
                        "error": "liboqs not installed",
                        "install": "pip install liboqs-python",
                        "docs": "https://github.com/open-quantum-safe/liboqs-python",
                    },
                    indent=2,
                ),
            )
        ]

    try:
        if name == "pqc_list_algorithms":
            filter_type = arguments.get("type", "all")
            result = get_available_algorithms()

            if filter_type == "kem":
                result = {"kem_algorithms": result.get("kem_algorithms", [])}
            elif filter_type == "sig":
                result = {"sig_algorithms": result.get("sig_algorithms", [])}

            # Add NIST standard mappings
            result["nist_standards"] = {
                "ML-KEM": "FIPS 203 (formerly CRYSTALS-Kyber)",
                "ML-DSA": "FIPS 204 (formerly CRYSTALS-Dilithium)",
                "SLH-DSA": "FIPS 205 (formerly SPHINCS+)",
                "HQC": "Round 4 finalist, standardization in progress",
            }

            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "pqc_algorithm_info":
            alg = arguments["algorithm"]

            # Try as KEM first
            try:
                kem = oqs.KeyEncapsulation(alg)
                info = {
                    "name": alg,
                    "type": "KEM (Key Encapsulation Mechanism)",
                    "public_key_size": kem.details["length_public_key"],
                    "secret_key_size": kem.details["length_secret_key"],
                    "ciphertext_size": kem.details["length_ciphertext"],
                    "shared_secret_size": kem.details["length_shared_secret"],
                    "nist_level": kem.details.get("claimed_nist_level", "Unknown"),
                    "is_ind_cca": kem.details.get("is_ind_cca", True),
                }
                return [TextContent(type="text", text=json.dumps(info, indent=2))]
            except MechanismNotSupportedError:
                pass

            # Try as signature
            try:
                sig = oqs.Signature(alg)
                info = {
                    "name": alg,
                    "type": "Digital Signature",
                    "public_key_size": sig.details["length_public_key"],
                    "secret_key_size": sig.details["length_secret_key"],
                    "signature_size": sig.details["length_signature"],
                    "nist_level": sig.details.get("claimed_nist_level", "Unknown"),
                    "is_euf_cma": sig.details.get("is_euf_cma", True),
                }
                return [TextContent(type="text", text=json.dumps(info, indent=2))]
            except MechanismNotSupportedError:
                pass

            return [
                TextContent(
                    type="text", text=json.dumps({"error": f"Unknown algorithm: {alg}"}, indent=2)
                )
            ]

        elif name == "pqc_generate_keypair":
            alg = arguments["algorithm"]

            # Try as KEM
            try:
                kem = oqs.KeyEncapsulation(alg)
                public_key = kem.generate_keypair()
                secret_key = kem.export_secret_key()

                result = {
                    "algorithm": alg,
                    "type": "KEM",
                    "public_key": base64.b64encode(public_key).decode(),
                    "secret_key": base64.b64encode(secret_key).decode(),
                    "public_key_size": len(public_key),
                    "secret_key_size": len(secret_key),
                }
                return [TextContent(type="text", text=json.dumps(result, indent=2))]
            except MechanismNotSupportedError:
                pass

            # Try as signature
            try:
                sig = oqs.Signature(alg)
                public_key = sig.generate_keypair()
                secret_key = sig.export_secret_key()

                result = {
                    "algorithm": alg,
                    "type": "Signature",
                    "public_key": base64.b64encode(public_key).decode(),
                    "secret_key": base64.b64encode(secret_key).decode(),
                    "public_key_size": len(public_key),
                    "secret_key_size": len(secret_key),
                }
                return [TextContent(type="text", text=json.dumps(result, indent=2))]
            except Exception as e:
                return [TextContent(type="text", text=json.dumps({"error": str(e)}, indent=2))]

        elif name == "pqc_encapsulate":
            alg = arguments["algorithm"]
            public_key = base64.b64decode(arguments["public_key"])

            kem = oqs.KeyEncapsulation(alg)
            ciphertext, shared_secret = kem.encap_secret(public_key)

            result = {
                "algorithm": alg,
                "ciphertext": base64.b64encode(ciphertext).decode(),
                "shared_secret": base64.b64encode(shared_secret).decode(),
                "shared_secret_hex": shared_secret.hex(),
                "ciphertext_size": len(ciphertext),
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "pqc_decapsulate":
            alg = arguments["algorithm"]
            secret_key = base64.b64decode(arguments["secret_key"])
            ciphertext = base64.b64decode(arguments["ciphertext"])

            kem = oqs.KeyEncapsulation(alg, secret_key)
            shared_secret = kem.decap_secret(ciphertext)

            result = {
                "algorithm": alg,
                "shared_secret": base64.b64encode(shared_secret).decode(),
                "shared_secret_hex": shared_secret.hex(),
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "pqc_sign":
            alg = arguments["algorithm"]
            secret_key = base64.b64decode(arguments["secret_key"])
            message = arguments["message"].encode("utf-8")

            sig = oqs.Signature(alg, secret_key)
            signature = sig.sign(message)

            result = {
                "algorithm": alg,
                "message_hash": hashlib.sha3_256(message).hexdigest(),
                "signature": base64.b64encode(signature).decode(),
                "signature_size": len(signature),
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "pqc_verify":
            alg = arguments["algorithm"]
            public_key = base64.b64decode(arguments["public_key"])
            message = arguments["message"].encode("utf-8")
            signature = base64.b64decode(arguments["signature"])

            sig = oqs.Signature(alg)
            is_valid = sig.verify(message, signature, public_key)

            result = {
                "algorithm": alg,
                "valid": is_valid,
                "message_hash": hashlib.sha3_256(message).hexdigest(),
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "pqc_hash_to_curve":
            message = arguments["message"].encode("utf-8")
            alg = arguments.get("algorithm", "SHA3-256")

            if alg == "SHA3-256":
                digest = hashlib.sha3_256(message).digest()
            elif alg == "SHA3-512":
                digest = hashlib.sha3_512(message).digest()
            elif alg == "SHAKE128":
                digest = hashlib.shake_128(message).digest(32)
            elif alg == "SHAKE256":
                digest = hashlib.shake_256(message).digest(64)
            else:
                digest = hashlib.sha3_256(message).digest()

            result = {
                "algorithm": alg,
                "input": arguments["message"],
                "digest_hex": digest.hex(),
                "digest_base64": base64.b64encode(digest).decode(),
                "digest_size": len(digest),
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "pqc_security_analysis":
            alg = arguments["algorithm"]

            # Security level mappings
            security_levels = {
                1: {"classical": "AES-128", "quantum": "AES-64 equivalent", "bits": 128},
                2: {"classical": "SHA-256", "quantum": "AES-80 equivalent", "bits": 192},
                3: {"classical": "AES-192", "quantum": "AES-96 equivalent", "bits": 192},
                4: {"classical": "SHA-384", "quantum": "AES-112 equivalent", "bits": 256},
                5: {"classical": "AES-256", "quantum": "AES-128 equivalent", "bits": 256},
            }

            # Try to get algorithm details
            nist_level = None
            alg_type = None
            details = {}

            try:
                kem = oqs.KeyEncapsulation(alg)
                nist_level = kem.details.get("claimed_nist_level", 3)
                alg_type = "KEM"
                details = kem.details
            except MechanismNotSupportedError:
                try:
                    sig = oqs.Signature(alg)
                    nist_level = sig.details.get("claimed_nist_level", 3)
                    alg_type = "Signature"
                    details = sig.details
                except MechanismNotSupportedError:
                    return [
                        TextContent(
                            type="text",
                            text=json.dumps({"error": f"Unknown algorithm: {alg}"}, indent=2),
                        )
                    ]

            level_info = security_levels.get(nist_level, security_levels[3])

            result = {
                "algorithm": alg,
                "type": alg_type,
                "nist_security_level": nist_level,
                "classical_security": level_info["classical"],
                "quantum_security": level_info["quantum"],
                "security_bits": level_info["bits"],
                "quantum_resistant": True,
                "grover_resistance": f"Grover's algorithm reduces security by ~50% to {level_info['bits'] // 2} bits",  # type: ignore[operator]
                "shor_resistance": "Resistant to Shor's algorithm (not based on factoring/DLP)",
                "recommendation": (
                    "NIST approved for post-quantum security" if nist_level else "Experimental"
                ),
            }
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        else:
            return [
                TextContent(
                    type="text", text=json.dumps({"error": f"Unknown tool: {name}"}, indent=2)
                )
            ]

    except Exception as e:
        return [TextContent(type="text", text=json.dumps({"error": str(e)}, indent=2))]


async def run_server():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


def main():
    """Entry point."""
    asyncio.run(run_server())


if __name__ == "__main__":
    main()
