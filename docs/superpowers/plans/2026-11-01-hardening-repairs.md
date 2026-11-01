# Hardening Repairs Implementation Plan

> **For agentic workers:** Execute inline with the test-driven-development and verification-before-completion workflows.

**Goal:** Implement the authorized repair order from the November 1 repository review.

**Architecture:** Preserve the v3 envelope format. Enforce validated handles before generating secrets. Use transactional per-mailbox Durable Objects for durable authorization, quotas, message expiration, and retry deduplication; use per-IP Durable Objects for fixed-window rate limits. Credentials enter the Python relay client through server configuration, never tool arguments. Live deployment and legacy-data migration are separate operational steps.

**Tech Stack:** Python, liboqs, MCP, httpx; TypeScript Cloudflare Workers/Durable Objects.

**Spec:** `docs/reviews/2026-11-01-repository-review.md` and the user's approved repair order.

## Global constraints

- Keep v3 wire cryptography stable; forward secrecy follows these repairs as a separate protocol design.
- Do not disclose credentials or generated private keys in logs.
- Preserve the historical review; record current validation separately.
- Unknown/unregistered mailboxes fail closed in the repaired relay; existing KV data is not silently imported without authorization.
- No live deployment, credential rotation, or destructive data migration in this work.

## Review focus

- Missing, null, empty, whitespace, and oversized handles must never expose secrets in policy mode.
- Tests must restore preexisting imported modules even after exceptions.
- Expiration and concurrent deposits must not remove credentials or overrun mailbox quotas.
- Lost responses and retried deposits must retain one message within the deduplication window.
- Rejected URLs and absent credentials must fail before network calls; invalid bodies must produce bounded structured errors.

## Tasks

### 1. Key handling and isolation

- [x] Add dispatch regression cases for invalid handles and a module-restoration case; observe failures.
- [x] Share handle validation in policy/store paths; replace relay-config import stubs with scoped loading.
- [x] Run the complete offline Python suite.

### 2. Mailbox authorization and consistency

- [x] Add runnable local Worker tests for missing/valid/rotated auth, message TTL, concurrency, quota, idempotency, malformed bodies, and limiter failure.
- [x] Add transactional Durable Object mailbox and limiter classes; route through explicit bindings and remove deployable development credentials.
- [x] Add private configuration for Python mailbox tokens, canonical URL construction and async dispatch offloading for relay network calls.
- [x] Run local Node tests, typecheck, Worker tests where supported, and dry-run build.

### 3. Boundary and resource repairs

- [x] Reproduce oversized seal/open mismatch and unsupported hash behavior in tests.
- [x] Align decoded byte budgets, enforce generic oqs lengths, clean native resources with context managers, and correct security-status reporting.
- [x] Run crypto regressions and fuzz/property tests.

### 4. Dependencies and verification pipeline

- [x] Resolve verified maintained dependency versions if network access permits; do not hand-edit lockfiles to pretend resolution succeeded.
- [x] Declare Hypothesis, enforce frozen lockfiles, supported Node, offline default tests, and explicit live-test opt-in.
- [x] Run formatting, types, full suites, package build/install, and advisory checks where available.

### 5. Documentation and handoff

- [x] Update version/changelog/README/relay contract and current status with exact results and migration instructions.
- [x] Record any environment-blocked upgrade or test explicitly.
- [x] Document the subsequent forward-secrecy protocol milestone without claiming it exists.

Validated implementation and remaining operational actions: `docs/reviews/2026-11-01-repair-status.md`.
