# ADR-0003: Unified Constant-Time Comparison Primitive (secure-ct-eq)

- Status: Accepted

- Date: 2026-09-21

- Related code: `src/secure/ct_eq.rs` (the public primitive), `Cargo.toml` (the `secure-ct-eq` feature)

- Related dependency: `subtle 2.6` (`ConstantTimeEq`)

## Context

If key/credential comparison uses `==` (a short-circuit comparison that returns early), it exposes a **timing side channel** (CWE-208): an attacker can guess the correct value byte by byte by measuring comparison time. Affected surfaces include HMAC verification, digest responses, API Key secrets, audit-chain verification — any path that "compares key-grade data".

In the project's early days each module copied subtle calls on its own, which risked implementation drift (a stray `==` somewhere is hard to spot).

## Decision

1. **One unified public primitive**: `secure::ct_eq::constant_time_eq(a: &[u8], b: &[u8]) -> bool` (based on `subtle::ConstantTimeEq`), exported by the `secure-ct-eq` feature.

2. **Every feature that needs constant-time comparison depends on that feature**; modules must not copy local implementations (eliminating the second implementation); `audit-log`, `oauth2-server` and others already declare the dependency this way.

3. **List of applicable paths** (new comparison paths must be checked against this list and added):
   - OAuth2 `code_verifier` ↔ `code_challenge` (the S256 digest comparison is a hash comparison; the verifier matching path)
   - HTTP Digest `response` field verification
   - API Key `key_secret` hash comparison (CWE-208 + CWE-916 combined defense)
   - Audit-chain hash verification (`audit-log`)
   - SimpleTokenStyle HMAC signature verification (`secure-simple-token`)

4. **Non-applicability**: password-hash verify (Argon2/bcrypt) guarantees constant-time behavior inside the libraries and does not go through this primitive; comparing non-sensitive data (e.g. configuration strings) needs no constant-time comparison (avoiding performance anxiety from misuse).

## Consequences

**Positive:**

- Single-point implementation + type-level constraints (subtle's `Choice` type prevents accidental conversion to bool with early return).

- Applicable paths are enumerable and testable (regression `acc_sec_020_ct_eq_constant_time_semantics` in `tests/acceptance/security.rs`).

**Negative / cost:**

- `secure-ct-eq` becomes a shared dependency of several security features (feature propagation surface +1).

- Constant-time semantics rely on the correctness of `subtle`'s platform implementation (maintained by RustCrypto; the trust assumption matches the primitive trust of ADR-0002).

**Follow-ups:**

- New code review checklist item: any code that "compares keys/tokens/digests" must go through `ct_eq`; consider adding a custom clippy lint or a Semgrep rule in later changes to detect bare `==` on sensitive paths.
