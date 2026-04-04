# Multi-Model Adversarial Security Review

> **Internal hardening review — not an external third-party audit.**

**Review Period:** April 1–3, 2026

## Executive Summary
This audit reviewed the `post-quantum-mcp` repository as a research/prototyping MCP server for post-quantum cryptography, with emphasis on hybrid X25519 + ML-KEM-768 envelopes, ML-DSA-65 sender authentication, replay handling, secret-key exposure controls, and supporting tests. Scope included `CHANGELOG.md`, `ROADMAP.md`, the `pqc_mcp_server` package, and the test corpus. Overall, the codebase shows solid research-grade security engineering and clear hardening progress, but it is not production-ready because accepted architectural risks remain around transport, forward secrecy, and legacy compatibility.

## Scope
Reviewed materials included project change history and roadmap, core implementation modules (`hybrid.py`, `handlers_hybrid.py`, `replay_cache.py`, `security_policy.py`, `key_store.py`, `filesystem.py`), tool definitions, examples, README security notes, and the automated test suite.

## Methodology
The review used a three-model adversarial process: Claude Opus 4.6, Codex GPT-5.4, and Qwen 3.5 35B local. Analysis combined source review with Wycheproof vector execution, Hypothesis property-based fuzzing, protocol mutation fuzzing, and prompt injection testing focused on tool boundaries and server-enforced policy paths.

## Findings
**25 findings total: 19 fixed, 6 accepted.**

### Critical
- `C-01 [Fixed] Ghost Timestamp Replay`: v2 envelopes now require signed timestamps and freshness checks.
- `C-02 [Fixed] Key Type Confusion`: ML-DSA-65 key-size validation rejects wrong-key signing inputs.
- `C-03 [Fixed] Pre-Verify Cache Marking`: replay cache marks only after successful authenticated open.

### Medium
- `M-01 [Fixed] ML-KEM pk validation`: encapsulation rejects malformed ML-KEM-768 public keys.
- `M-02 [Fixed] Cache-Flood DoS`: replay cache prunes expired entries and caps growth.
- `M-03 [Fixed] Fingerprint/public-key mismatch`: embedded sender fingerprints are recomputed and checked.
- `M-04 [Fixed] Sender binding ambiguity`: exactly one expected sender identifier is required.
- `M-05 [Fixed] Verify-before-decrypt enforcement`: authenticated envelopes are refused by anonymous-open paths.
- `M-06 [Fixed] Raw secret exposure`: handle mode redacts secrets from key-generation responses.
- `M-07 [Fixed] Server policy enforcement`: raw secret inputs can be rejected by `PQC_REQUIRE_KEY_HANDLES`.
- `M-08 [Fixed] Handle/raw argument mixing`: conflicting secret sources are rejected.
- `M-09 [Fixed] Algorithm alias confusion`: canonical liboqs comparison prevents mismatch bugs.
- `M-10 [Fixed] Replay-cache persistence safety`: writes are atomic and permission-hardened.
- `M-11 [Fixed] Cache corruption recovery`: unreadable cache state resets cleanly instead of crashing.
- `M-12 [Fixed] Timestamp parse hardening`: malformed timestamps fail closed without unsafe exceptions.
- `M-13 [Accepted] Network transport gap`: delivery remains local and Phase 3 transport is still outstanding.
- `M-14 [Accepted] Residual doc/test drift`: some examples and compatibility prose lag current v2 behavior.

### Low
- `L-01 [Accepted] Timing oracle`: sender binding can fail faster than signature verification.
- `L-02 [Accepted] Combiner input boundary`: fixed-width concatenation is safe now but future-sensitive.
- `L-03 [Accepted] v1 backwards compat`: v1 remains accepted and skips freshness enforcement.
- `L-04 [Accepted] No forward secrecy`: single-shot envelopes are not ratcheted or session-based.
- `L-05 [Fixed] All-zero X25519 rejection`: small-order ECDH outputs are rejected.
- `L-06 [Fixed] Transcript boundary clarity`: authenticated transcripts use length-prefixed fields.
- `L-07 [Fixed] Future clock-skew bound`: envelopes more than five minutes ahead are rejected.
- `L-08 [Fixed] Error-path leakage`: fuzzing showed clean failures with no key disclosure.

## Testing Results
Aggregate audit testing covered approximately 15,750 inputs across all tiers. Recorded results were zero crashes and zero key leaks. Wycheproof coverage passed 834+ vectors; Hypothesis passed 530+ random inputs; and protocol mutation fuzzing handled 650+ mutations cleanly.

## Known Operational Tradeoffs

**Replay-cache process boundary:** Replay dedup is guaranteed only within the current single-process runtime model. The cache uses atomic file writes for crash safety but does not use file locking. Under multi-process contention, two concurrent opens of the same valid envelope can both succeed. This is a documented operational tradeoff, not a protocol flaw. The multiprocess diagnostic probe (`test_replay_cache_multiprocess_probe.py`) characterizes this behavior.

**liboqs version mismatch:** The C library (0.15.0) and Python wrapper (0.14.1) produce a cosmetic `UserWarning` at import. All algorithms used by this project work correctly under this pairing. See Tested Compatibility in the README for the supported version matrix.

**v1/v2 backwards compatibility:** Legacy envelopes are accepted for decryption with loud warnings. v1 envelopes lack timestamps and skip freshness checks entirely. v2 envelopes lack mode binding. Both are treated as deprecated — the protocol is frozen at v3.

## Recommendations
Phase 3 work should prioritize a real network transport with authenticated delivery semantics and replay-state coordination, then add forward secrecy through PQXDH or a ratcheting session design. In parallel, publish a dated deprecation plan for `pqc-mcp-v1` so freshness checks become universal and documentation can converge on the v3 envelope model.
