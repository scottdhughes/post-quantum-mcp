# Forward secrecy — next protocol milestone

The repaired v3 envelope protocol still uses long-term recipient X25519 and
ML-KEM keys. Captured envelopes can be decrypted after both recipient secrets
are compromised. Fresh sender ephemeral keys and authenticated timestamps do
not change that property. Message TTL is API policy, not cryptographic erasure.

The next milestone is a separate session protocol with explicit identity,
recipient prekeys, single-use consumption, ratchet state, and key deletion.
Keep its version and tool surface separate from `pqc-mcp-v3` so compatibility
cannot silently downgrade session guarantees.

Before implementing, select an existing reviewed protocol/implementation and
check its license, binding support, state persistence, and precise guarantees.
Primary design references are Signal's PQXDH and Double Ratchet specification,
including its Sparse Post-Quantum Ratchet and Triple Ratchet sections:

- https://signal.org/docs/specifications/pqxdh/
- https://signal.org/docs/specifications/doubleratchet/

PQ authentication, classical forward secrecy, post-quantum forward secrecy, and
post-compromise recovery are separate claims. A classical Double Ratchet alone
must not be advertised as giving the post-quantum ratchet's stronger guarantees.
Do not invent a new combiner or ratchet to avoid selecting an implementation.

Required acceptance evidence:

1. A written threat model distinguishes passive capture, later recipient/sender
   key compromise, active relay compromise, device rollback, and concurrent sessions.
2. Peer identity is authenticated independently of relay registration. Prekey
   retrieval authenticates ownership; one-time prekeys are consumed atomically.
3. Session state advances durably before acknowledgment. Crashes, retries,
   out-of-order messages, skipped-key limits, and multi-process races have tests.
4. Tests demonstrate that archived ciphertext cannot be decrypted from the
   explicitly defined later-compromise state, with each quantum/classical
   assumption stated separately. Negative controls omit deletion or roll back
   state and must demonstrate the expected failure of the security property.
5. Key deletion claims account for Python immutable copies, native buffers,
   database journals, backups, and logs. Logical deletion is not a guarantee
   of forensic erasure.
6. Protocol changes receive independent specialist review and interoperability
   checks before any production security claim.

These are requirements for the follow-on work. No ratchet, session API, or
forward-secrecy guarantee is implemented by the hardening release.
