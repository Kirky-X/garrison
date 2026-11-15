# ADR-0001: Argon2id Password Hashing Policy

- Status: Accepted

- Date: 2026-09-21

- Related code: `src/account/credential/password.rs` (`Argon2Hasher` / `BcryptHasher`)

- Related configuration: the `password_hasher` section (see `docs/CONFIGURATION.md`)

## Context

As an authentication and authorization framework, Garrison treats password hashing as a security baseline. Comparison of the candidate options:

| Dimension | Argon2id | bcrypt | scrypt | PBKDF2 |
|------|----------|--------|--------|--------|
| GPU/ASIC resistance | Strong (memory hardness) | Medium (controllable memory but low ceiling) | Strong | Weak (pure CPU iteration) |
| Side channels (time/cache) | Low (Argon2id mixes data-independent and block-independent access) | Low | Medium | Low |
| Current OWASP Password Storage Cheat Sheet recommendation | **Preferred** | Acceptable (work factor ≥10) | Acceptable | FIPS-compliance scenarios only |
| Rust ecosystem | `argon2` crate (RustCrypto, PHC format) | `bcrypt` crate | Mature | Mature |

Two requirements must be satisfied at the same time: migrating historical passwords (legacy systems with stored bcrypt hashes) and memory-constrained environments (a memory budget of 19 MiB × concurrent requests).

## Decision

1. **Argon2id is the default algorithm**, with default parameters **m=19456 KiB (19 MiB) / t=2 / p=1** — the minimum secure configuration recommended by OWASP (the second recommended tier referenced to 2024+ hardware: m=19 MiB, t=2, p=1).

2. **Locking tests pin the defaults**: `src/account/credential/tests.rs` asserts that `Argon2Hasher::default()` parameters and the PHC output prefix are `$argon2id$v=19$m=19456,t=2,p=1` — silent drift of the default policy is blocked by CI.

3. **Configurable but with a floor**: the `password_hasher` section exposes `argon2_m_cost/t_cost/p_cost`; `validate_core` enforces m_cost ≥ 19456 (going below the floor requires an explicit risk-acceptance field), preventing businesses from unintentionally weakening parameters for throughput.

4. **The verify path parses parameters from the PHC string**: `Argon2::default()` is used only for construction; the actual cost parameters are read from the `$argon2id$m=...,t=...,p=1` hash string — historical hashes (with different parameters) can be verified without migration, and parameter upgrades follow the natural evolution of "re-hash on new password / re-login".

5. **bcrypt compatibility is kept** (default cost=12, configurable and validated 10≤cost≤15): used only for verifying existing bcrypt hashes; all new hashes use Argon2id.

## Consequences

**Positive:**

- The default configuration equals the OWASP recommendation — secure out of the box.

- Parameter evolution does not break existing passwords (PHC is self-describing).

- Default drift has a test anchor; configuration weakening has a validation gate.

**Negative / cost:**

- 19 MiB × concurrency memory footprint: high-concurrency login scenarios must evaluate the memory budget (offloaded via `spawn_blocking`, so the async reactor is not blocked, but memory is still occupied at concurrency peaks).

- Configurability adds validation branch complexity (floor + risk-acceptance flag).

**Follow-ups:**

- A parameter upgrade (e.g. the m=47104 tier) as a minor-version default change must be prominently noted in the CHANGELOG (verify stays compatible; only new hashes are affected).

- If FIPS-compliant scenarios are needed in the future, evaluate a PBKDF2 hasher as an optional `PasswordHasher` implementation (the trait is already abstracted; the cost is manageable).
