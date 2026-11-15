# ADR-0002: Unified CSPRNG Policy (getrandom::fill Reads the OS Entropy Source Directly)

- Status: Accepted

- Date: 2026-09-21

- Related code: `src/web/csrf.rs`, `src/oauth2_server/authorize.rs`, `src/oauth2_server/token.rs`, `src/account/credential/backup_code.rs`, `src/listener/audit_chain.rs`

- Related dependency: `getrandom 0.4` (optional, enabled transitively by the consumer's feature)

## Context

Every random-number use in an identity framework is **security-sensitive**: CSRF tokens, OAuth2 authorization codes, refresh tokens, backup codes, audit-chain salts. Weakened randomness (insufficiently seeded user-space PRBG, buffer reuse) directly leads to predictable tokens.

The fragmented state of random-number crate versions in the Rust ecosystem is a real constraint: `rand 0.10` removed the `OsRng` struct (rand_core 0.10 moved system entropy to getrandom); `rsa 0.9` is built on the rand_core 0.6 traits (it ships its own `rsa::rand_core::OsRng`); this project previously carried rand 0.8/0.9-style call sites at the same time.

## Decision

1. **All secure-random paths uniformly use `getrandom::fill(&mut bytes)`** — each call issues a system call directly to read the OS CSPRNG (getrandom(2) / BCryptGenRandom / SecRandomCopyBytes), **without introducing a user-space DRBG buffer**, eliminating seed-quality and state-leak classes of defects.

2. **The `rand` crate is allowed only for non-security purposes** (e.g. test data generation); it must never appear on token/key/salt generation paths.

3. **The `rsa::rand_core::OsRng` boundary**: rsa 0.9's keygen/signing internally uses the rand_core 0.6 traits; using its re-exported OsRng is the **only exception** kept for version compatibility (see `src/protocol/sso/oidc.rs`, `src/protocol/sso/saml.rs`); it is still the OS entropy source in essence, so the stance is consistent.

4. **No downgrade modes**: `rand::thread_rng()`, `SmallRng`, timestamp/UUID concatenation and other pseudo-random schemes are forbidden on secure paths; code review and future Semgrep rules can build on this constraint.

## Consequences

**Positive:**

- One single secure-random primitive, small audit surface (`grep getrandom::fill` enumerates every secure-random site).

- No user-space buffer → no state-leak/rollback risk; no coupling to rand versions.

**Negative / cost:**

- Per-call syscall overhead (microsecond level) — token generation is not a hot path (relative to hashing), acceptable.

- The rsa path keeps the rand_core 0.6 compatibility exception, which must be re-reviewed when upgrading the rsa crate.

**Follow-ups:**

- Every new secure-random call site must use `getrandom::fill`; likewise, the constant-time comparison of ADR-0003 forms part of the "cryptographic hygiene principles".
