# Roadmap — post-quantum-mcp + quantum-seal

Generated 2026-04-02 via three-model adversarial review (Claude Opus 4.6, Codex GPT-5.4, Qwen 3.5).

## Current State (post v0.7.0 / pqc-mcp-v3)

| Area | Score (1-10) | Notes |
|------|-------------|-------|
| Cryptographic correctness | 9.0 | v3 mode-bound envelopes, LP AAD, full validation, 5-model review |
| Code quality & architecture | 9.0 | Clean layering, shared _core_encrypt, _verify_authenticated_envelope |
| Test coverage | 9.0 | Unit + Wycheproof + Hypothesis + protocol fuzz + mode separation tests |
| Documentation | 8.0 | Coherence session in progress — README/CHANGELOG being aligned |
| Security posture | 8.5 | v3 mode separation, replay cache, handle-only policy, content safety |
| Usability / DX | 8.0 | Handle-first examples, verify tool, parameterized config |
| Completeness vs goals | 8.5 | Full authenticated envelope protocol, missing network transport |
| **Overall** | **A-** | |

## Phase 1: Quick Wins (~6 hours)

Priority: fix secret exposure and tool gaps before adding features.

- [x] **pyproject.toml version sync** — bumped through 0.5.0 → 0.6.0 → 0.7.0
- [x] **`.mcp.json` relative paths** — parameterized with PQC_MCP_PATH env var
- [x] **`pqc_hybrid_auth_verify` tool** — verify signature without decrypting, with replay_seen advisory
- [x] **Gate raw secret exposure** — PQC_REQUIRE_KEY_HANDLES now enforced across all handlers

## Phase 2: Medium Effort (~5-7 days)

Priority: move security from promptware to server-enforced, prove it with tests.

- [x] **Server-enforced security policies** — move fingerprint verification, timestamp checks, and permission enforcement from skill instructions into the MCP server (2-3 days, Security +1.0, Architecture +0.5; depends on Phase 1 tool fixes)
- [x] **Behavioral plugin tests** — end-to-end tests exercising full skill flows (keygen → seal → open → verify) via MCP protocol, replacing file-presence checks (1-2 days, Tests +1.0; depends on server enforcement)
- [x] **Stateful replay dedup** — envelope digest cache with TTL, keyed by SHA3-256 of signature bytes (1 day, Security +0.5; depends on server enforcement)
- [x] **liboqs install automation** — `scripts/install-liboqs.sh` or Docker-based dev environment to reduce setup friction (4 hrs, UX +0.5)

## Phase 3: Architecture (~3-5 weeks)

Priority: make it usable beyond a single machine, then add forward secrecy.

- [ ] **Network transport** — Cloudflare Worker relay, shared S3 bucket, or WebSocket bridge for cross-machine envelope delivery. Replace filesystem-only `~/.pqc/inboxes/` with pluggable transport backend (1-2 weeks, Completeness +1.0, UX +1.0; depends on Phase 2 server enforcement + replay dedup)
- [ ] **Forward secrecy** — PQXDH or session ratchet protocol for ephemeral session keys. Each message uses a fresh shared secret derived from a ratcheting state (2-3 weeks, Security +1.5, Crypto +1.0; depends on network transport)

## Projected Scores After All Phases

| Area | Current | After Phase 1 | After Phase 2 | After Phase 3 |
|------|---------|--------------|--------------|--------------|
| Cryptographic correctness | 8.3 | 8.3 | 8.5 | 9.5 |
| Code quality & architecture | 8.3 | 8.3 | 9.0 | 9.0 |
| Test coverage | 8.0 | 8.0 | 9.0 | 9.0 |
| Documentation | 8.7 | 9.0 | 9.0 | 9.0 |
| Security posture | 7.3 | 8.0 | 8.8 | 9.5 |
| Usability / DX | 7.7 | 8.2 | 8.7 | 9.0 |
| Completeness vs goals | 8.3 | 8.6 | 8.8 | 9.5 |
| **Overall** | **B+/A-** | **A-** | **A** | **A+** |

## Key Design Decisions

**Ordering rationale** (per Codex): close the secret-exposure gap first, then enforce policy server-side and prove it with behavioral tests, then add replay protection, and only then invest in transport and forward secrecy.

**"Promptware" problem**: The quantum-seal plugin's security-critical flows (handshake, fingerprint verification, file permissions) are skill instructions that Claude follows — nothing enforces correctness. Phase 2's server enforcement is the single highest-leverage change, moving security from "the AI is told to do the right thing" to "the server won't let it do the wrong thing."

**Forward secrecy is last**: It's the only item that changes cryptographic properties rather than engineering hardening. Transport is more impactful for usability. Forward secrecy is for when you have real users.

## Review Methodology

Three-model adversarial review process:
1. Each model independently reviewed the full codebase
2. Findings cross-verified against actual source code
3. Fixes implemented with consensus from all three models
4. Adversarial code review of every change before commit
5. Stale references and doc drift caught and fixed

Models: Claude Opus 4.6 (1M context), Codex GPT-5.4, Qwen 3.5 35B MoE (local, Ollama on RTX 4090)
