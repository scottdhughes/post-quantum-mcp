# Hybrid X25519 + ML-KEM-768 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement hybrid X25519 + ML-KEM-768 key exchange and anonymous sealed-box encryption as described in the [v4 design spec](../specs/2026-03-29-hybrid-key-exchange-design.md), delivered across three PRs.

**Architecture:** Single named suite `mlkem768-x25519-sha3-256` using the LAMPS SHA3-256 KEM combiner for key establishment, HKDF for AEAD key derivation, AES-256-GCM for the sealed envelope. Crypto logic in `hybrid.py`, MCP wiring in `__init__.py`.

**Tech Stack:** Python 3.10+, liboqs-python (ML-KEM-768), cryptography (X25519, HKDFExpand, AESGCM), stdlib hashlib (SHA3-256), stdlib hmac (HKDF-Extract)

**Spec:** `docs/superpowers/specs/2026-03-29-hybrid-key-exchange-design.md` (v4, approved)

---

## PR 1: Infrastructure Credibility

The working tree already has unstaged changes from earlier work (run.sh, __init__.py, pyproject.toml) plus untracked files (CHANGELOG.md, tests/). This PR stages those, adds the remaining infra items, and commits.

### Task 1: Create GitHub Actions CI workflow

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Write the CI workflow**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install black mypy
      - run: black --check pqc_mcp_server/ tests/
      - run: mypy pqc_mcp_server/

  test:
    runs-on: ${{ matrix.os }}
    strategy:
      matrix:
        os: [ubuntu-latest, macos-latest]
        python-version: ["3.10", "3.11", "3.12", "3.13"]
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install liboqs (Ubuntu)
        if: runner.os == 'Linux'
        run: |
          sudo apt-get update
          sudo apt-get install -y cmake ninja-build
          git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
          cd /tmp/liboqs && mkdir build && cd build
          cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local ..
          ninja && sudo ninja install
          sudo ldconfig

      - name: Install liboqs (macOS)
        if: runner.os == 'macOS'
        run: |
          brew install cmake ninja
          git clone --depth 1 --branch 0.15.0 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs
          cd /tmp/liboqs && mkdir build && cd build
          cmake -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_INSTALL_PREFIX=/usr/local ..
          ninja && sudo ninja install

      - name: Install Python dependencies
        run: |
          pip install --upgrade pip
          pip install ".[dev]"

      - name: Run tests
        env:
          LD_LIBRARY_PATH: /usr/local/lib
          DYLD_LIBRARY_PATH: /usr/local/lib
        run: pytest tests/ -v --tb=short
```

- [ ] **Step 2: Verify the YAML is valid**

Run: `python3 -c "import yaml; yaml.safe_load(open('.github/workflows/ci.yml'))" 2>&1 || python3 -c "import json; print('yaml not installed, check manually')"`

### Task 2: Tighten dependency version floors

**Files:**
- Modify: `pyproject.toml:39-42`

- [ ] **Step 1: Update dependency floors**

Change the dependencies section in `pyproject.toml`:

```toml
dependencies = [
    "mcp>=1.6.0,<2.0.0",
    "liboqs-python>=0.10.0",
]
```

Raises `mcp` floor to 1.6.0 (earliest version with stable tool/stdio APIs we rely on) and adds an upper bound. `liboqs-python` stays with `>=0.10.0` since the API has been stable across 0.10-0.14.

- [ ] **Step 2: Generate constraints file**

```bash
pip freeze --exclude-editable > constraints.txt
```

This captures the exact versions tested. Commit alongside pyproject.toml so CI and contributors can reproduce.

### Task 3: Add liboqs research-use warning to README

**Files:**
- Modify: `README.md:1-10`

- [ ] **Step 1: Add warning banner after the badges**

Insert after line 7 (the MCP badge), before the description paragraph:

```markdown
> **Research and Prototyping Only.** This server uses [liboqs](https://github.com/open-quantum-safe/liboqs), which is explicitly not recommended for production use or for protecting sensitive data. Secret keys and shared secrets appear in tool output, which may enter model context, client logs, or transcripts. Suitable for experimentation, education, and interoperability testing.
```

### Task 4: Commit PR 1

**Files:**
- All modified and untracked files from Tasks 1-3 plus earlier work

- [ ] **Step 1: Stage all PR 1 files**

```bash
git add pqc_mcp_server/__init__.py pyproject.toml run.sh CHANGELOG.md tests/ .github/ README.md
```

- [ ] **Step 2: Commit**

```bash
git commit -m "feat: add tests, CI, portable run.sh, tighten deps, security warning

- Portable run.sh (no hardcoded paths, OS-aware library path)
- Replace bare except: with MechanismNotSupportedError
- Add pytest suite: server plumbing, KEM, signatures, algorithm info
- Add GitHub Actions CI (Python 3.10-3.13, Ubuntu + macOS)
- Add CHANGELOG.md
- Tighten mcp dependency upper bound
- Add research-use warning to README top"
```

- [ ] **Step 3: Verify clean state**

Run: `git status`
Expected: clean working tree, branch ahead of origin

---

## PR 2: Naming, Docs, Security Cleanup

### Task 5: Rename pqc_hash_to_curve to pqc_hash

**Files:**
- Modify: `pqc_mcp_server/__init__.py` (tool name in list_tools and call_tool)
- Modify: `tests/test_server.py` (EXPECTED_TOOLS list and test function names)

- [ ] **Step 1: Update tool name in __init__.py list_tools**

In `pqc_mcp_server/__init__.py`, find the Tool definition with `name="pqc_hash_to_curve"` and change to:

```python
        Tool(
            name="pqc_hash",
            description="Compute a quantum-safe hash digest (SHA3-256, SHA3-512, SHAKE128, SHAKE256)",
            inputSchema={
                "type": "object",
                "properties": {
                    "message": {
                        "type": "string",
                        "description": "Message to hash"
                    },
                    "algorithm": {
                        "type": "string",
                        "enum": ["SHA3-256", "SHA3-512", "SHAKE128", "SHAKE256"],
                        "default": "SHA3-256"
                    }
                },
                "required": ["message"]
            }
        ),
```

- [ ] **Step 2: Update call_tool handler**

Change `elif name == "pqc_hash_to_curve":` to `elif name == "pqc_hash":`.

- [ ] **Step 3: Update tests**

In `tests/test_server.py`, change `"pqc_hash_to_curve"` to `"pqc_hash"` in `EXPECTED_TOOLS` and in every `call_tool("pqc_hash_to_curve", ...)` call. Also rename the test functions from `test_hash_to_curve_*` to `test_hash_*`.

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_server.py -v`
Expected: all hash tests pass with new name

- [ ] **Step 5: Commit**

```bash
git add pqc_mcp_server/__init__.py tests/test_server.py
git commit -m "refactor: rename pqc_hash_to_curve to pqc_hash

The tool computes SHA3/SHAKE digests, not RFC 9380 hash-to-curve."
```

### Task 6: Label pqc_security_analysis as educational

**Files:**
- Modify: `pqc_mcp_server/__init__.py` (tool description)

- [ ] **Step 1: Update tool description**

Change the `pqc_security_analysis` Tool description to:

```python
            description="Educational estimate of security properties: maps NIST levels to classical/quantum equivalents. This is a static lookup, not a formal per-algorithm analysis.",
```

- [ ] **Step 2: Commit**

```bash
git add pqc_mcp_server/__init__.py
git commit -m "docs: label pqc_security_analysis as educational estimate"
```

### Task 7: Update algorithm naming in README

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the features section**

Replace references to "Kyber", "Dilithium", "SPHINCS+" as primary names. Use ML-KEM, ML-DSA, SLH-DSA as first-class names. Keep legacy names only in parenthetical compatibility notes. Remove hardcoded counts like "32 KEMs" and "221 Signature Algorithms" — replace with "KEMs and signature algorithms available via liboqs" or similar dynamic language.

- [ ] **Step 2: Update the algorithm tables**

In the Supported Algorithms section, lead with ML-KEM / ML-DSA / SLH-DSA names. Add a note: "Legacy names (Kyber, Dilithium, SPHINCS+) are accepted as aliases for compatibility."

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: update algorithm naming to ML-KEM/ML-DSA/SLH-DSA

Legacy names retained as compatibility aliases. Remove hardcoded
algorithm counts that drift with liboqs versions."
```

---

## PR 3: Hybrid X25519 + ML-KEM-768

This is the main feature. TDD: tests first, then implementation.

### Task 8: Add cryptography dependency

**Files:**
- Modify: `pyproject.toml:39-42`

- [ ] **Step 1: Add cryptography to dependencies**

```toml
dependencies = [
    "mcp>=1.0.0,<2.0.0",
    "liboqs-python>=0.10.0",
    "cryptography>=42.0.0",
]
```

- [ ] **Step 2: Commit**

```bash
git add pyproject.toml
git commit -m "build: add cryptography>=42.0.0 for hybrid key exchange"
```

### Task 9: Implement hybrid.py — validation helpers and combiner

**Files:**
- Create: `pqc_mcp_server/hybrid.py`

- [ ] **Step 1: Write test for X25519 key validation**

Create `tests/test_hybrid.py`:

```python
"""Tests for hybrid X25519 + ML-KEM-768 key exchange.

Requires both liboqs and cryptography to be installed.
Module import errors fail loudly — no silent skips.
"""

import base64
import binascii
import hashlib
import pytest

oqs = pytest.importorskip("oqs", reason="liboqs-python not installed")
pytest.importorskip("cryptography", reason="cryptography not installed")

from pqc_mcp_server.hybrid import (
    SUITE,
    COMBINER_LABEL,
    _validate_x25519_key,
    _check_x25519_shared_secret,
    _kem_combine,
    _build_aad,
    _derive_aead_key_and_nonce,
)


class TestValidation:
    def test_valid_x25519_key(self):
        _validate_x25519_key(b"\x01" * 32, "test key")

    def test_x25519_key_too_short(self):
        with pytest.raises(ValueError, match="test key must be exactly 32 bytes"):
            _validate_x25519_key(b"\x01" * 31, "test key")

    def test_x25519_key_too_long(self):
        with pytest.raises(ValueError, match="test key must be exactly 32 bytes"):
            _validate_x25519_key(b"\x01" * 33, "test key")

    def test_all_zero_shared_secret_rejected(self):
        with pytest.raises(ValueError, match="all-zero"):
            _check_x25519_shared_secret(b"\x00" * 32)

    def test_nonzero_shared_secret_accepted(self):
        _check_x25519_shared_secret(b"\x01" + b"\x00" * 31)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_hybrid.py::TestValidation -v`
Expected: ImportError — `hybrid` module doesn't exist yet

- [ ] **Step 3: Write the validation helpers and combiner**

Create `pqc_mcp_server/hybrid.py`:

```python
"""Hybrid X25519 + ML-KEM-768 key exchange.

Suite: mlkem768-x25519-sha3-256
Combiner: SHA3-256(ss_mlkem || ss_x25519 || epk_x25519 || pk_x25519 || label)
Following LAMPS composite ML-KEM draft (id-MLKEM768-X25519-SHA3-256).

This is an anonymous sealed-box construction providing hybrid confidentiality
with ciphertext integrity. It is NOT forward-secret against recipient key
compromise, and it is NOT authenticated (anyone with recipient public keys
can seal an envelope).

liboqs is research/prototyping software and is not recommended for production.
"""

import base64
import hashlib
import hmac
from typing import Any

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
    PrivateFormat,
    NoEncryption,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import oqs

SUITE = "mlkem768-x25519-sha3-256"
COMBINER_LABEL = b"\x5c\x2e\x2f\x2f\x5e\x5c"  # \.//^\ — LAMPS id-MLKEM768-X25519-SHA3-256
_HKDF_INFO_PREFIX = b"pqc-mcp-v1|mlkem768-x25519-sha3-256|"


def _validate_x25519_key(key_bytes: bytes, label: str) -> None:
    if len(key_bytes) != 32:
        raise ValueError(f"{label} must be exactly 32 bytes, got {len(key_bytes)}")


def _check_x25519_shared_secret(ss: bytes) -> None:
    if ss == b"\x00" * 32:
        raise ValueError(
            "X25519 shared secret is all-zero (small-order public key input per RFC 7748)"
        )


def _kem_combine(
    ss_mlkem: bytes,
    ss_x25519: bytes,
    epk_x25519: bytes,
    pk_x25519: bytes,
) -> bytes:
    """SHA3-256 KEM combiner per LAMPS id-MLKEM768-X25519-SHA3-256.

    combined_ss = SHA3-256(ss_mlkem || ss_x25519 || epk_x25519 || pk_x25519 || label)
    """
    return hashlib.sha3_256(
        ss_mlkem + ss_x25519 + epk_x25519 + pk_x25519 + COMBINER_LABEL
    ).digest()


def _derive_aead_key_and_nonce(combined_ss: bytes) -> tuple[bytes, bytes]:
    """HKDF Extract+Expand to derive AES-256-GCM key and deterministic nonce."""
    salt = b"\x00" * 32
    prk = hmac.new(key=salt, msg=combined_ss, digestmod=hashlib.sha256).digest()

    aes_key = HKDFExpand(
        algorithm=SHA256(), length=32, info=_HKDF_INFO_PREFIX + b"aes-256-gcm-key"
    ).derive(prk)

    nonce = HKDFExpand(
        algorithm=SHA256(), length=12, info=_HKDF_INFO_PREFIX + b"aes-256-gcm-nonce"
    ).derive(prk)

    return aes_key, nonce


def _build_aad(epk_x25519: bytes, pqc_ciphertext: bytes) -> bytes:
    """Canonical AAD: version|suite|epk|pqc_ct."""
    return (
        b"pqc-mcp-v1"
        + b"|mlkem768-x25519-sha3-256|"
        + epk_x25519
        + pqc_ciphertext
    )
```

- [ ] **Step 4: Run validation tests**

Run: `pytest tests/test_hybrid.py::TestValidation -v`
Expected: all 5 pass

- [ ] **Step 5: Commit**

```bash
git add pqc_mcp_server/hybrid.py tests/test_hybrid.py
git commit -m "feat(hybrid): add validation helpers and SHA3-256 KEM combiner

Suite: mlkem768-x25519-sha3-256
Combiner follows LAMPS id-MLKEM768-X25519-SHA3-256."
```

### Task 10: Implement combiner and HKDF byte-for-byte tests

**Files:**
- Modify: `tests/test_hybrid.py`

- [ ] **Step 1: Add combiner and info string tests**

Append to `tests/test_hybrid.py`:

```python
class TestCombiner:
    def test_combiner_output_is_32_bytes(self):
        result = _kem_combine(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, b"\x04" * 32)
        assert len(result) == 32

    def test_combiner_is_deterministic(self):
        args = (b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, b"\x04" * 32)
        assert _kem_combine(*args) == _kem_combine(*args)

    def test_combiner_byte_for_byte(self):
        """Verify exact SHA3-256 output for known inputs."""
        ss_mlkem = b"\xaa" * 32
        ss_x25519 = b"\xbb" * 32
        epk = b"\xcc" * 32
        pk = b"\xdd" * 32
        expected_input = ss_mlkem + ss_x25519 + epk + pk + COMBINER_LABEL
        assert len(expected_input) == 134  # 32+32+32+32+6
        expected = hashlib.sha3_256(expected_input).digest()
        assert _kem_combine(ss_mlkem, ss_x25519, epk, pk) == expected

    def test_combiner_different_inputs_different_output(self):
        r1 = _kem_combine(b"\x01" * 32, b"\x02" * 32, b"\x03" * 32, b"\x04" * 32)
        r2 = _kem_combine(b"\x05" * 32, b"\x02" * 32, b"\x03" * 32, b"\x04" * 32)
        assert r1 != r2

    def test_combiner_label_is_lamps_draft(self):
        """Label must be the exact LAMPS id-MLKEM768-X25519-SHA3-256 bytes."""
        assert COMBINER_LABEL == b"\x5c\x2e\x2f\x2f\x5e\x5c"
        assert len(COMBINER_LABEL) == 6


class TestHKDF:
    def test_info_string_bytes(self):
        assert _HKDF_INFO_PREFIX + b"aes-256-gcm-key" == (
            b"pqc-mcp-v1|mlkem768-x25519-sha3-256|aes-256-gcm-key"
        )
        assert _HKDF_INFO_PREFIX + b"aes-256-gcm-nonce" == (
            b"pqc-mcp-v1|mlkem768-x25519-sha3-256|aes-256-gcm-nonce"
        )

    def test_derive_produces_correct_lengths(self):
        aes_key, nonce = _derive_aead_key_and_nonce(b"\x01" * 32)
        assert len(aes_key) == 32
        assert len(nonce) == 12

    def test_derive_is_deterministic(self):
        k1, n1 = _derive_aead_key_and_nonce(b"\xab" * 32)
        k2, n2 = _derive_aead_key_and_nonce(b"\xab" * 32)
        assert k1 == k2
        assert n1 == n2

    def test_domain_separation(self):
        """AES key and nonce must differ (different HKDF info)."""
        aes_key, nonce = _derive_aead_key_and_nonce(b"\x01" * 32)
        assert aes_key[:12] != nonce


class TestAAD:
    def test_aad_construction(self):
        epk = b"\xaa" * 32
        ct = b"\xbb" * 100
        aad = _build_aad(epk, ct)
        assert aad.startswith(b"pqc-mcp-v1|mlkem768-x25519-sha3-256|")
        assert aad[38:70] == epk
        assert aad[70:] == ct

    def test_aad_is_deterministic(self):
        epk = b"\x01" * 32
        ct = b"\x02" * 50
        assert _build_aad(epk, ct) == _build_aad(epk, ct)
```

- [ ] **Step 2: Run tests**

Run: `pytest tests/test_hybrid.py -v`
Expected: all combiner, HKDF, and AAD tests pass

- [ ] **Step 3: Commit**

```bash
git add tests/test_hybrid.py
git commit -m "test(hybrid): add byte-for-byte combiner, HKDF, and AAD tests"
```

### Task 11: Implement hybrid_keygen

**Files:**
- Modify: `pqc_mcp_server/hybrid.py`
- Modify: `tests/test_hybrid.py`

- [ ] **Step 1: Write keygen test**

Append to `tests/test_hybrid.py`:

```python
from pqc_mcp_server.hybrid import hybrid_keygen

class TestKeygen:
    def test_keygen_returns_suite(self):
        result = hybrid_keygen()
        assert result["suite"] == SUITE

    def test_keygen_x25519_keys_are_32_bytes(self):
        result = hybrid_keygen()
        pk = base64.b64decode(result["classical"]["public_key"])
        sk = base64.b64decode(result["classical"]["secret_key"])
        assert len(pk) == 32
        assert len(sk) == 32

    def test_keygen_pqc_keys_exist(self):
        result = hybrid_keygen()
        assert result["pqc"]["algorithm"] == "ML-KEM-768"
        pk = base64.b64decode(result["pqc"]["public_key"])
        sk = base64.b64decode(result["pqc"]["secret_key"])
        assert len(pk) > 0
        assert len(sk) > 0

    def test_keygen_unique(self):
        r1 = hybrid_keygen()
        r2 = hybrid_keygen()
        assert r1["classical"]["public_key"] != r2["classical"]["public_key"]
        assert r1["pqc"]["public_key"] != r2["pqc"]["public_key"]
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_hybrid.py::TestKeygen -v`
Expected: ImportError — `hybrid_keygen` not defined yet

- [ ] **Step 3: Implement hybrid_keygen**

Append to `pqc_mcp_server/hybrid.py`:

```python
def hybrid_keygen() -> dict[str, Any]:
    """Generate a hybrid X25519 + ML-KEM-768 keypair bundle."""
    x_sk = X25519PrivateKey.generate()
    x_pk = x_sk.public_key()

    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pqc_pk = kem.generate_keypair()
    pqc_sk = kem.export_secret_key()

    return {
        "suite": SUITE,
        "classical": {
            "algorithm": "X25519",
            "public_key": base64.b64encode(
                x_pk.public_bytes(Encoding.Raw, PublicFormat.Raw)
            ).decode(),
            "secret_key": base64.b64encode(
                x_sk.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
            ).decode(),
        },
        "pqc": {
            "algorithm": "ML-KEM-768",
            "public_key": base64.b64encode(pqc_pk).decode(),
            "secret_key": base64.b64encode(pqc_sk).decode(),
        },
    }
```

- [ ] **Step 4: Run keygen tests**

Run: `pytest tests/test_hybrid.py::TestKeygen -v`
Expected: all 4 pass

- [ ] **Step 5: Commit**

```bash
git add pqc_mcp_server/hybrid.py tests/test_hybrid.py
git commit -m "feat(hybrid): implement hybrid_keygen"
```

### Task 12: Implement hybrid_encap and hybrid_decap

**Files:**
- Modify: `pqc_mcp_server/hybrid.py`
- Modify: `tests/test_hybrid.py`

- [ ] **Step 1: Write encap/decap tests**

Append to `tests/test_hybrid.py`:

```python
from pqc_mcp_server.hybrid import hybrid_encap, hybrid_decap

class TestEncapDecap:
    def test_encap_decap_roundtrip(self):
        keys = hybrid_keygen()
        encap_result = hybrid_encap(
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
        )
        assert encap_result["suite"] == SUITE
        assert len(base64.b64decode(encap_result["shared_secret"])) == 32
        assert len(base64.b64decode(encap_result["x25519_ephemeral_public_key"])) == 32

        decap_result = hybrid_decap(
            base64.b64decode(keys["classical"]["secret_key"]),
            base64.b64decode(keys["pqc"]["secret_key"]),
            base64.b64decode(encap_result["x25519_ephemeral_public_key"]),
            base64.b64decode(encap_result["pqc_ciphertext"]),
        )
        assert decap_result["shared_secret"] == encap_result["shared_secret"]
        assert decap_result["shared_secret_hex"] == encap_result["shared_secret_hex"]

    def test_wrong_key_decap_implicit_rejection(self):
        """ML-KEM performs implicit rejection: returns a deterministic but
        incorrect shared secret rather than an explicit error."""
        k1 = hybrid_keygen()
        k2 = hybrid_keygen()
        encap_result = hybrid_encap(
            base64.b64decode(k1["classical"]["public_key"]),
            base64.b64decode(k1["pqc"]["public_key"]),
        )
        decap_wrong = hybrid_decap(
            base64.b64decode(k2["classical"]["secret_key"]),
            base64.b64decode(k2["pqc"]["secret_key"]),
            base64.b64decode(encap_result["x25519_ephemeral_public_key"]),
            base64.b64decode(encap_result["pqc_ciphertext"]),
        )
        assert decap_wrong["shared_secret"] != encap_result["shared_secret"]

    def test_x25519_key_length_validation(self):
        keys = hybrid_keygen()
        with pytest.raises(ValueError, match="must be exactly 32 bytes"):
            hybrid_encap(b"\x01" * 31, base64.b64decode(keys["pqc"]["public_key"]))
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hybrid.py::TestEncapDecap -v`
Expected: ImportError — `hybrid_encap` not defined

- [ ] **Step 3: Implement hybrid_encap and hybrid_decap**

Append to `pqc_mcp_server/hybrid.py`:

```python
def hybrid_encap(classical_pk: bytes, pqc_pk: bytes) -> dict[str, Any]:
    """Perform hybrid encapsulation. Returns combined shared secret + ciphertexts."""
    _validate_x25519_key(classical_pk, "classical_public_key")

    # X25519: generate ephemeral keypair and perform ECDH
    eph_sk = X25519PrivateKey.generate()
    eph_pk = eph_sk.public_key()
    eph_pk_bytes = eph_pk.public_bytes(Encoding.Raw, PublicFormat.Raw)

    recipient_x_pk = X25519PublicKey.from_public_bytes(classical_pk)
    ss_x25519 = eph_sk.exchange(recipient_x_pk)
    _check_x25519_shared_secret(ss_x25519)

    # ML-KEM-768: encapsulate
    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pqc_ct, ss_mlkem = kem.encap_secret(pqc_pk)

    # Combine via SHA3-256
    combined_ss = _kem_combine(ss_mlkem, ss_x25519, eph_pk_bytes, classical_pk)

    return {
        "suite": SUITE,
        "shared_secret": base64.b64encode(combined_ss).decode(),
        "shared_secret_hex": combined_ss.hex(),
        "x25519_ephemeral_public_key": base64.b64encode(eph_pk_bytes).decode(),
        "pqc_ciphertext": base64.b64encode(pqc_ct).decode(),
    }


def hybrid_decap(
    classical_sk: bytes,
    pqc_sk: bytes,
    x25519_epk: bytes,
    pqc_ct: bytes,
) -> dict[str, Any]:
    """Recover the combined shared secret."""
    _validate_x25519_key(classical_sk, "classical_secret_key")
    _validate_x25519_key(x25519_epk, "x25519_ephemeral_public_key")

    # X25519: ECDH with ephemeral public key
    sk = X25519PrivateKey.from_private_bytes(classical_sk)
    peer_pk = X25519PublicKey.from_public_bytes(x25519_epk)
    ss_x25519 = sk.exchange(peer_pk)
    _check_x25519_shared_secret(ss_x25519)

    # Derive recipient's own public key for the combiner
    pk_x25519 = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # ML-KEM-768: decapsulate
    kem = oqs.KeyEncapsulation("ML-KEM-768", pqc_sk)
    ss_mlkem = kem.decap_secret(pqc_ct)

    # Combine via SHA3-256
    combined_ss = _kem_combine(ss_mlkem, ss_x25519, x25519_epk, pk_x25519)

    return {
        "suite": SUITE,
        "shared_secret": base64.b64encode(combined_ss).decode(),
        "shared_secret_hex": combined_ss.hex(),
    }
```

- [ ] **Step 4: Run encap/decap tests**

Run: `pytest tests/test_hybrid.py::TestEncapDecap -v`
Expected: all 3 pass

- [ ] **Step 5: Commit**

```bash
git add pqc_mcp_server/hybrid.py tests/test_hybrid.py
git commit -m "feat(hybrid): implement hybrid_encap and hybrid_decap"
```

### Task 13: Implement hybrid_seal and hybrid_open

**Files:**
- Modify: `pqc_mcp_server/hybrid.py`
- Modify: `tests/test_hybrid.py`

- [ ] **Step 1: Write seal/open tests**

Append to `tests/test_hybrid.py`:

```python
from pqc_mcp_server.hybrid import hybrid_seal, hybrid_open

class TestSealOpen:
    def test_seal_open_string_roundtrip(self):
        keys = hybrid_keygen()
        envelope = hybrid_seal(
            b"Hello, quantum world!",
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
        )
        assert envelope["version"] == "pqc-mcp-v1"
        assert envelope["suite"] == SUITE
        assert "ciphertext" in envelope
        assert "nonce" not in envelope  # nonce is derived, not transmitted

        result = hybrid_open(
            envelope,
            base64.b64decode(keys["classical"]["secret_key"]),
            base64.b64decode(keys["pqc"]["secret_key"]),
        )
        assert result["plaintext"] == "Hello, quantum world!"
        assert result["suite"] == SUITE

    def test_seal_open_binary_roundtrip(self):
        keys = hybrid_keygen()
        binary_data = bytes(range(256))
        envelope = hybrid_seal(
            binary_data,
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
        )
        result = hybrid_open(
            envelope,
            base64.b64decode(keys["classical"]["secret_key"]),
            base64.b64decode(keys["pqc"]["secret_key"]),
        )
        assert base64.b64decode(result["plaintext_base64"]) == binary_data

    def test_seal_open_non_utf8_binary(self):
        keys = hybrid_keygen()
        non_utf8 = b"\x80\x81\x82\xff\xfe"
        envelope = hybrid_seal(
            non_utf8,
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
        )
        result = hybrid_open(
            envelope,
            base64.b64decode(keys["classical"]["secret_key"]),
            base64.b64decode(keys["pqc"]["secret_key"]),
        )
        assert result["plaintext"] is None
        assert base64.b64decode(result["plaintext_base64"]) == non_utf8

    def test_wrong_key_open_fails(self):
        from cryptography.exceptions import InvalidTag
        k1 = hybrid_keygen()
        k2 = hybrid_keygen()
        envelope = hybrid_seal(
            b"secret",
            base64.b64decode(k1["classical"]["public_key"]),
            base64.b64decode(k1["pqc"]["public_key"]),
        )
        with pytest.raises(InvalidTag):
            hybrid_open(
                envelope,
                base64.b64decode(k2["classical"]["secret_key"]),
                base64.b64decode(k2["pqc"]["secret_key"]),
            )

    def test_tampered_ciphertext_fails(self):
        from cryptography.exceptions import InvalidTag
        keys = hybrid_keygen()
        envelope = hybrid_seal(
            b"data",
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
        )
        ct = bytearray(base64.b64decode(envelope["ciphertext"]))
        ct[0] ^= 0xFF
        envelope["ciphertext"] = base64.b64encode(bytes(ct)).decode()
        with pytest.raises(InvalidTag):
            hybrid_open(
                envelope,
                base64.b64decode(keys["classical"]["secret_key"]),
                base64.b64decode(keys["pqc"]["secret_key"]),
            )

    def test_tampered_pqc_ciphertext_fails(self):
        """Tampered ML-KEM ciphertext changes the AAD, causing GCM tag mismatch."""
        from cryptography.exceptions import InvalidTag
        keys = hybrid_keygen()
        envelope = hybrid_seal(
            b"data",
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
        )
        ct = bytearray(base64.b64decode(envelope["pqc_ciphertext"]))
        ct[0] ^= 0xFF
        envelope["pqc_ciphertext"] = base64.b64encode(bytes(ct)).decode()
        with pytest.raises(InvalidTag):
            hybrid_open(
                envelope,
                base64.b64decode(keys["classical"]["secret_key"]),
                base64.b64decode(keys["pqc"]["secret_key"]),
            )

    def test_tampered_epk_fails(self):
        """Tampered ephemeral key changes both ECDH shared secret and AAD."""
        from cryptography.exceptions import InvalidTag
        keys = hybrid_keygen()
        envelope = hybrid_seal(
            b"data",
            base64.b64decode(keys["classical"]["public_key"]),
            base64.b64decode(keys["pqc"]["public_key"]),
        )
        epk = bytearray(base64.b64decode(envelope["x25519_ephemeral_public_key"]))
        epk[0] ^= 0xFF
        envelope["x25519_ephemeral_public_key"] = base64.b64encode(bytes(epk)).decode()
        with pytest.raises(InvalidTag):
            hybrid_open(
                envelope,
                base64.b64decode(keys["classical"]["secret_key"]),
                base64.b64decode(keys["pqc"]["secret_key"]),
            )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_hybrid.py::TestSealOpen -v`
Expected: ImportError — `hybrid_seal` not defined

- [ ] **Step 3: Implement hybrid_seal and hybrid_open**

Append to `pqc_mcp_server/hybrid.py`:

```python
def hybrid_seal(
    plaintext_bytes: bytes,
    recipient_classical_pk: bytes,
    recipient_pqc_pk: bytes,
) -> dict[str, Any]:
    """Encrypt plaintext using hybrid encapsulation + AES-256-GCM.

    Anonymous sealed-box: anyone with recipient public keys can seal.
    Single-shot: one encapsulation, one AEAD encryption.
    """
    _validate_x25519_key(recipient_classical_pk, "recipient_classical_public_key")

    # Encapsulate (raw bytes, not base64)
    eph_sk = X25519PrivateKey.generate()
    eph_pk = eph_sk.public_key()
    eph_pk_bytes = eph_pk.public_bytes(Encoding.Raw, PublicFormat.Raw)

    recipient_x_pk = X25519PublicKey.from_public_bytes(recipient_classical_pk)
    ss_x25519 = eph_sk.exchange(recipient_x_pk)
    _check_x25519_shared_secret(ss_x25519)

    kem = oqs.KeyEncapsulation("ML-KEM-768")
    pqc_ct, ss_mlkem = kem.encap_secret(recipient_pqc_pk)

    combined_ss = _kem_combine(ss_mlkem, ss_x25519, eph_pk_bytes, recipient_classical_pk)

    # Derive AEAD key + nonce
    aes_key, nonce = _derive_aead_key_and_nonce(combined_ss)

    # Encrypt with AAD
    aad = _build_aad(eph_pk_bytes, pqc_ct)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, plaintext_bytes, aad)

    return {
        "version": "pqc-mcp-v1",
        "suite": SUITE,
        "x25519_ephemeral_public_key": base64.b64encode(eph_pk_bytes).decode(),
        "pqc_ciphertext": base64.b64encode(pqc_ct).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }


def hybrid_open(
    envelope: dict[str, Any],
    classical_sk: bytes,
    pqc_sk: bytes,
) -> dict[str, Any]:
    """Decrypt a sealed envelope."""
    # Validate transmitted header fields before any crypto
    if envelope.get("version") != "pqc-mcp-v1":
        raise ValueError(f"Unsupported envelope version: {envelope.get('version')}")
    if envelope.get("suite") != SUITE:
        raise ValueError(f"Unsupported envelope suite: {envelope.get('suite')}")

    _validate_x25519_key(classical_sk, "classical_secret_key")

    epk_bytes = base64.b64decode(envelope["x25519_ephemeral_public_key"], validate=True)
    pqc_ct = base64.b64decode(envelope["pqc_ciphertext"], validate=True)
    ciphertext = base64.b64decode(envelope["ciphertext"], validate=True)

    _validate_x25519_key(epk_bytes, "x25519_ephemeral_public_key")

    # X25519 ECDH
    sk = X25519PrivateKey.from_private_bytes(classical_sk)
    peer_pk = X25519PublicKey.from_public_bytes(epk_bytes)
    ss_x25519 = sk.exchange(peer_pk)
    _check_x25519_shared_secret(ss_x25519)

    # Derive recipient's own public key for combiner
    pk_x25519 = sk.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    # ML-KEM-768 decapsulate
    kem = oqs.KeyEncapsulation("ML-KEM-768", pqc_sk)
    ss_mlkem = kem.decap_secret(pqc_ct)

    # Combine + derive AEAD key + nonce
    combined_ss = _kem_combine(ss_mlkem, ss_x25519, epk_bytes, pk_x25519)
    aes_key, nonce = _derive_aead_key_and_nonce(combined_ss)

    # Decrypt with AAD verification
    aad = _build_aad(epk_bytes, pqc_ct)
    aesgcm = AESGCM(aes_key)
    plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, aad)

    # Try UTF-8 decode
    try:
        plaintext_str = plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError:
        plaintext_str = None

    return {
        "suite": SUITE,
        "plaintext": plaintext_str,
        "plaintext_base64": base64.b64encode(plaintext_bytes).decode(),
    }
```

- [ ] **Step 4: Run seal/open tests**

Run: `pytest tests/test_hybrid.py::TestSealOpen -v`
Expected: all 7 pass

- [ ] **Step 5: Run all hybrid tests**

Run: `pytest tests/test_hybrid.py -v`
Expected: all tests pass (validation + combiner + hkdf + aad + keygen + encap/decap + seal/open)

- [ ] **Step 6: Commit**

```bash
git add pqc_mcp_server/hybrid.py tests/test_hybrid.py
git commit -m "feat(hybrid): implement hybrid_seal and hybrid_open

Anonymous sealed-box: AES-256-GCM with full-header AAD binding.
Deterministic nonce derived from PRK, not transmitted in envelope."
```

### Task 14: Wire hybrid tools into MCP server

**Files:**
- Modify: `pqc_mcp_server/__init__.py`

- [ ] **Step 1: Add HAS_CRYPTOGRAPHY flag and imports**

At the top of `pqc_mcp_server/__init__.py`, after the liboqs import block, add:

```python
try:
    from pqc_mcp_server.hybrid import (
        hybrid_keygen,
        hybrid_encap,
        hybrid_decap,
        hybrid_seal,
        hybrid_open,
        SUITE as HYBRID_SUITE,
    )
    HAS_HYBRID = True
except ImportError:
    HAS_HYBRID = False
```

- [ ] **Step 2: Add 5 hybrid Tool definitions to list_tools**

Append to the tool list in `list_tools()`, before the closing `]`:

```python
        Tool(
            name="pqc_hybrid_keygen",
            description=f"Generate a hybrid X25519 + ML-KEM-768 keypair bundle (suite: {HYBRID_SUITE if HAS_HYBRID else 'mlkem768-x25519-sha3-256'}). Anonymous sealed-box — research/prototyping only.",
            inputSchema={"type": "object", "properties": {}}
        ),
        Tool(
            name="pqc_hybrid_encap",
            description="Perform hybrid X25519 + ML-KEM-768 key encapsulation. Returns combined shared secret + ciphertexts.",
            inputSchema={
                "type": "object",
                "properties": {
                    "classical_public_key": {"type": "string", "description": "Base64-encoded raw 32-byte X25519 public key"},
                    "pqc_public_key": {"type": "string", "description": "Base64-encoded ML-KEM-768 public key"},
                },
                "required": ["classical_public_key", "pqc_public_key"]
            }
        ),
        Tool(
            name="pqc_hybrid_decap",
            description="Recover hybrid shared secret using both secret keys.",
            inputSchema={
                "type": "object",
                "properties": {
                    "classical_secret_key": {"type": "string", "description": "Base64-encoded raw 32-byte X25519 secret key"},
                    "pqc_secret_key": {"type": "string", "description": "Base64-encoded ML-KEM-768 secret key"},
                    "x25519_ephemeral_public_key": {"type": "string", "description": "Base64-encoded raw 32-byte ephemeral public key from encap"},
                    "pqc_ciphertext": {"type": "string", "description": "Base64-encoded ML-KEM-768 ciphertext from encap"},
                },
                "required": ["classical_secret_key", "pqc_secret_key", "x25519_ephemeral_public_key", "pqc_ciphertext"]
            }
        ),
        Tool(
            name="pqc_hybrid_seal",
            description="Encrypt plaintext using hybrid X25519 + ML-KEM-768 + AES-256-GCM. Anonymous sealed-box — anyone with recipient public keys can seal. Research/prototyping only.",
            inputSchema={
                "type": "object",
                "properties": {
                    "plaintext": {"type": "string", "description": "UTF-8 string to encrypt (mutually exclusive with plaintext_base64)"},
                    "plaintext_base64": {"type": "string", "description": "Base64-encoded binary data to encrypt (mutually exclusive with plaintext)"},
                    "recipient_classical_public_key": {"type": "string", "description": "Base64-encoded raw 32-byte X25519 public key"},
                    "recipient_pqc_public_key": {"type": "string", "description": "Base64-encoded ML-KEM-768 public key"},
                },
                "required": ["recipient_classical_public_key", "recipient_pqc_public_key"]
            }
        ),
        Tool(
            name="pqc_hybrid_open",
            description="Decrypt a hybrid sealed envelope using both secret keys.",
            inputSchema={
                "type": "object",
                "properties": {
                    "envelope": {"type": "object", "description": "Sealed envelope from pqc_hybrid_seal"},
                    "classical_secret_key": {"type": "string", "description": "Base64-encoded raw 32-byte X25519 secret key"},
                    "pqc_secret_key": {"type": "string", "description": "Base64-encoded ML-KEM-768 secret key"},
                },
                "required": ["envelope", "classical_secret_key", "pqc_secret_key"]
            }
        ),
```

- [ ] **Step 3: Add hybrid tool handlers to call_tool**

In the `call_tool` function, add handlers before the `else: Unknown tool` branch:

```python
        elif name == "pqc_hybrid_keygen":
            if not HAS_HYBRID:
                return [TextContent(type="text", text=json.dumps({"error": "cryptography package not installed", "install": "pip install cryptography>=42.0.0"}, indent=2))]
            result = hybrid_keygen()
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "pqc_hybrid_encap":
            if not HAS_HYBRID:
                return [TextContent(type="text", text=json.dumps({"error": "cryptography package not installed"}, indent=2))]
            result = hybrid_encap(
                base64.b64decode(arguments["classical_public_key"], validate=True),
                base64.b64decode(arguments["pqc_public_key"], validate=True),
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "pqc_hybrid_decap":
            if not HAS_HYBRID:
                return [TextContent(type="text", text=json.dumps({"error": "cryptography package not installed"}, indent=2))]
            result = hybrid_decap(
                base64.b64decode(arguments["classical_secret_key"], validate=True),
                base64.b64decode(arguments["pqc_secret_key"], validate=True),
                base64.b64decode(arguments["x25519_ephemeral_public_key"], validate=True),
                base64.b64decode(arguments["pqc_ciphertext"], validate=True),
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]

        elif name == "pqc_hybrid_seal":
            if not HAS_HYBRID:
                return [TextContent(type="text", text=json.dumps({"error": "cryptography package not installed"}, indent=2))]
            if "plaintext" in arguments and "plaintext_base64" in arguments:
                return [TextContent(type="text", text=json.dumps({"error": "Provide exactly one of plaintext or plaintext_base64, not both"}, indent=2))]
            if "plaintext" in arguments:
                pt_bytes = arguments["plaintext"].encode("utf-8")
            elif "plaintext_base64" in arguments:
                pt_bytes = base64.b64decode(arguments["plaintext_base64"], validate=True)
            else:
                return [TextContent(type="text", text=json.dumps({"error": "Provide plaintext or plaintext_base64"}, indent=2))]
            envelope = hybrid_seal(
                pt_bytes,
                base64.b64decode(arguments["recipient_classical_public_key"], validate=True),
                base64.b64decode(arguments["recipient_pqc_public_key"], validate=True),
            )
            return [TextContent(type="text", text=json.dumps({"envelope": envelope}, indent=2))]

        elif name == "pqc_hybrid_open":
            if not HAS_HYBRID:
                return [TextContent(type="text", text=json.dumps({"error": "cryptography package not installed"}, indent=2))]
            result = hybrid_open(
                arguments["envelope"],
                base64.b64decode(arguments["classical_secret_key"], validate=True),
                base64.b64decode(arguments["pqc_secret_key"], validate=True),
            )
            return [TextContent(type="text", text=json.dumps(result, indent=2))]
```

- [ ] **Step 4: Update test_server.py EXPECTED_TOOLS**

Add the 5 new tools to the `EXPECTED_TOOLS` list in `tests/test_server.py`:

```python
EXPECTED_TOOLS = [
    "pqc_list_algorithms",
    "pqc_algorithm_info",
    "pqc_generate_keypair",
    "pqc_encapsulate",
    "pqc_decapsulate",
    "pqc_sign",
    "pqc_verify",
    "pqc_hash",
    "pqc_security_analysis",
    "pqc_hybrid_keygen",
    "pqc_hybrid_encap",
    "pqc_hybrid_decap",
    "pqc_hybrid_seal",
    "pqc_hybrid_open",
]
```

- [ ] **Step 5: Run all tests**

Run: `pytest tests/ -v`
Expected: all tests pass

- [ ] **Step 6: Commit**

```bash
git add pqc_mcp_server/__init__.py tests/test_server.py
git commit -m "feat(hybrid): wire 5 hybrid tools into MCP server

Tools: pqc_hybrid_keygen, pqc_hybrid_encap, pqc_hybrid_decap,
pqc_hybrid_seal, pqc_hybrid_open"
```

### Task 15: Update README and CHANGELOG

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add hybrid section to README**

After the existing "Available Tools" section, add a "Hybrid Key Exchange" subsection documenting the 5 new tools with input/output examples. Add example Claude prompts:

```markdown
## Hybrid Key Exchange (X25519 + ML-KEM-768)

Suite: `mlkem768-x25519-sha3-256` — aligned with the LAMPS composite ML-KEM draft.

This is an **anonymous sealed-box** construction providing hybrid confidentiality with ciphertext integrity. It is not forward-secret against recipient key compromise, and it is not sender-authenticated.

### `pqc_hybrid_keygen`
Generate a hybrid keypair bundle. No parameters needed.

### `pqc_hybrid_encap` / `pqc_hybrid_decap`
Building-block key encapsulation. Returns a combined shared secret derived via the suite's SHA3-256 combiner.

### `pqc_hybrid_seal` / `pqc_hybrid_open`
Encrypt/decrypt plaintext using hybrid encapsulation + AES-256-GCM. Full-header AAD binding. Deterministic nonce.

### Example Usage

> "Generate a hybrid keypair and seal a message for me"

> "Perform a hybrid key exchange and show me the shared secret"

> "Encrypt 'classified data' using hybrid PQC and then decrypt it"
```

- [ ] **Step 2: Update CHANGELOG**

Add to the `[Unreleased]` section:

```markdown
### Added
- Hybrid X25519 + ML-KEM-768 key exchange (suite: `mlkem768-x25519-sha3-256`)
- 5 new tools: `pqc_hybrid_keygen`, `pqc_hybrid_encap`, `pqc_hybrid_decap`, `pqc_hybrid_seal`, `pqc_hybrid_open`
- SHA3-256 KEM combiner following LAMPS composite ML-KEM draft
- AES-256-GCM sealed envelope with full-header AAD binding
- `cryptography>=42.0.0` dependency for X25519, HKDFExpand, AESGCM
```

- [ ] **Step 3: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: add hybrid key exchange to README and CHANGELOG"
```

### Task 16: Final verification

- [ ] **Step 1: Run full test suite**

Run: `pytest tests/ -v --tb=short`
Expected: all tests pass

- [ ] **Step 2: Run black**

Run: `python3 -m black --check pqc_mcp_server/ tests/`
Expected: clean (or fix formatting issues)

- [ ] **Step 3: Verify git log**

Run: `git log --oneline`
Expected: clean commit history matching the PR roadmap
