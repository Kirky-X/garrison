# 🧪 Garrison Test Scenario Matrix

> Applicable version: Garrison **0.9.0** (MSRV 1.97.1 — `rust-version` in `Cargo.toml`, hard constraints in the table below; the repository has no `rust-toolchain.toml` (deleted in rc.3), the local toolchain follows rustup's default channel, and CI pins per workflow via `scripts/setup_rust.sh`: main jobs pin 1.97.1, with the test matrix legs at `1.97.1 / stable / beta`)
> Basis of compilation (read-only verification): `Cargo.toml [features]` and `[[test]]` registrations, the `tests/acceptance.rs` domain entry, `tests/acceptance/*.rs`, `tests/acceptance/migrated/*.rs`, `examples/tests/`, `.github/workflows/ci.yml`, `.github/workflows/feature-matrix.yml`, `scripts/e2e_matrix.sh`, `scripts/e2e_run.sh`, `benches/garrison_benchmark.rs`.
> This document merges the former "E2E Feature Combination Test Suite" document (`E2E_TESTING.md`, deleted) and adds the scenario inventory based on the real test suites.
> Scale figures are grep counts of `#[test]` / `#[tokio::test]` attributes (including `#[tokio::test(flavor = ...)]` forms), as of 2026-09-15.

## 📋 Table of Contents

- [Reading Conventions](#-reading-conventions)
- [Test System Overview](#️-test-system-overview)
- [Test Scale Statistics](#-test-scale-statistics)
- [Acceptance Scenario Matrix](#-acceptance-scenario-matrix)
- [Feature Dependency Analysis](#-feature-dependency-analysis)
- [Test Matrix Design](#-test-matrix-design)
- [Usage Guide](#-usage-guide)
- [Quality Gates](#-quality-gates)
- [Known Issues and Disposition Records](#-known-issues-and-disposition-records)
- [Related Documents](#-related-documents)

---

## 🎯 Reading Conventions

- Scenarios are organized by "domain"; each domain corresponds to one file under `tests/acceptance/`, with "happy path + error path" covered in pairs within a domain.
- Scenario numbering follows the in-code comment convention `ACC-<domain>-<seq>` (e.g. `ACC-ENV-001`, see `tests/acceptance/environment.rs`); the "scenario count" in this document's tables is the grep count of test attributes, with a few auxiliary cases (harness self-checks) counted into their containing file.
- `#[ignore]` cases are performance baselines (the `perf_*` prefix) and need an explicit `--ignored` run; external-service-gated cases automatically `[SKIP]` when the service is unreachable (fail-skip), never silently degrading — stage S0 of `e2e_matrix.sh` guarantees the real services are in place.
- Feature-face abbreviations: `full` = the full-capability aggregate; `testing` = the acceptance-matrix companion feature (test helper facilities gated by `garrison/testing`); `S3kc` / `S3hibp` = e2e_matrix stages adding the `keycloak-oidc` / `policy-hibp` faces on top of `full`.

---

## 🗺️ Test System Overview

<div align="center">

<img src="../assets/testing-pyramid.svg" alt="Testing pyramid" width="800">

</div>

The testing pyramid and the three quality defense lines:

| Layer | Location | Feature face | Trigger |
|----|------|--------|------|
| Unit tests | inline `#[cfg(test)]` modules in `src/` (237 sites) | default and full feature faces | `ci.yml` test job / `e2e_matrix.sh` S2 |
| Acceptance/integration tests | `tests/acceptance` (main target) + `acceptance_db_postgres` / `acceptance_db_mysql` (db-specific targets) + `macros_ui` (trybuild) | `full testing` and the db faces | `ci.yml` integration-test job / S3 |
| Example-level integration tests | `examples/tests/` (one per `examples/src/bin/`) | `-p garrison-examples --all-features` | `e2e_matrix.sh` S4 |
| UI/compile-failure tests | `tests/ui/` (trybuild, via `tests/macros_ui.rs`) | `annotation-macros` | `ci.yml` (Linux/MSRV legs) |
| Benchmarks | `benches/garrison_benchmark.rs` (Criterion, harness = false) | full | `e2e_matrix.sh` S6 |
| Doc tests | rustdoc examples of public APIs (including the runnable doctest at the top of `lib.rs`) | `full,audit-log` | `ci.yml` (Linux/MSRV legs) |
| Feature-combination compile matrix | `ci.yml` test-compile-guard + `feature-matrix.yml` + `e2e_matrix.sh` S5 | aggregates + the web×db grid + targeted combinations | PR gate / weekly backstop / local full run |

The three quality defense lines:

| Layer | Trigger | Scope |
|----|------|------|
| `.github/workflows/ci.yml` | push / PR | default/full/production compilation, fmt, clippy, the three-platform test matrix, guard combinations, doc, deny, integration tests (services: redis/postgres), coverage ≥85% |
| `.github/workflows/feature-matrix.yml` | weekly Mon 03:00 UTC | each-feature full scan + targeted pairs + examples |
| `scripts/e2e_matrix.sh` | manual / local / pre-release | the local equivalent of all the above + **real-service acceptance** (compose with health checks and deterministic cleanup) + **performance baselines** + **HTTP E2E penetration** |

---

## 📊 Test Scale Statistics

> The unit and acceptance columns are `cargo test -- --list` measured counts under the CI feature faces (full / full+testing); examples and proc macros are static counts of `#[test]` / `#[tokio::test]` attributes; as of 2026-11-16 (measured on the v0.9.0 workspace).

| Category | Location | Count |
|------|------|------|
| Unit tests | `src/` inline (`cargo test --features full --lib -- --list`) | 5469 |
| Acceptance / integration / UI tests | `tests/` (`cargo test --test acceptance --features "full testing" -- --list`) | 416 |
| Example-level integration tests | `examples/tests/` (65 files, one per example bin) | about 116 |
| Proc-macro tests | `macros/` | 8 |
| Total | — | **about 6009** |
| Criterion benchmarks | `benches/garrison_benchmark.rs` | 6 scenarios |
| Line-coverage gate | the `ci.yml` coverage job | `--fail-under-lines 95` (measured about 95.15% on 2026-10-14) |

> Coverage follows the existing recorded value; this round re-measured and refreshed the test counts (full face 5469 / acceptance face 416); line coverage was not re-measured.

---

## 🧪 Acceptance Scenario Matrix

`tests/acceptance.rs` is the acceptance-matrix entry, organizing `tests/acceptance/*.rs` by domain; this target requires the `full` + `testing` features (`Cargo.toml` `required-features`). Scenario counts per domain (grep counts):

### Happy-path domains

| Domain file | Scenarios | Coverage |
|--------|:------:|----------|
| `authentication.rs` | 19 | The main login flow (login / logout / kickout / token styles) |
| `session.rs` | 19 | Dual-mode sessions (Account-Session / Token-Session), concurrency and sharing policies |
| `rbac.rs` | 18 | RBAC permission checks and role hierarchy |
| `protocol_jwt.rs` | 19 | JWT issuance / verification / refresh rotation |
| `protocol_oauth2.rs` | 19 | OAuth2 four grants (against a real Keycloak 26) |
| `protocol_mixed.rs` | 23 | Multi-protocol mixed scenarios (JWT/OAuth2/SSO crossings) |
| `server.rs` | 34 | The standalone authentication server (auth-server endpoint behavior) |
| `web_axum.rs` | 25 | axum route interception and annotations |
| `web_actix.rs` | 8 | actix-web middleware |
| `web_warp.rs` | 6 | warp filters |
| `bw_ac.rs` | 6 | ABAC (Cedar DSL) attribute access control |
| `repository.rs` | 30 | Repository layer (13 traits) CRUD and tenant isolation |
| `keycloak_fixture.rs` | 3 | The real Keycloak login-form-flow fixture self-check |
| `web_smoke.rs` | 3 | Three-framework web smoke |
| `storage.rs` | 16 | Storage backend behavior (TTL / expiry / persistence) |
| `harness.rs` | 5 | Acceptance harness self-check |

### Error and boundary domains

| Domain file | Scenarios | Coverage |
|--------|:------:|----------|
| `security.rs` | 30 | Penetration-test attack surfaces (token forgery / injection / CSRF; the former pentest suite ACC-SEC-021..030 merged in) |
| `resilience.rs` | 12 | Failure resilience (timeouts / disconnections / circuit breaking / fail-closed) |
| `qrlogin.rs` | 7 | First-party QR login (Web displays QR + App confirms, two-ticket separation) |
| `concurrency.rs` | 9 | Race conditions (including 3 `#[ignore]` performance-baseline `perf_*` cases) |
| `environment.rs` | 10 | External-service environment gates (Redis DAO / Postgres migrations / MySQL testcontainers, auto [SKIP] when unreachable) |

### Migrated archive domains (`tests/acceptance/migrated/`)

| File | Scenarios | Coverage |
|------|:------:|----------|
| `annotation_macros.rs` | 25 | Annotation-macro expansion behavior |
| `strategy_registry.rs` | 19 | The strategy registry |
| `axum.rs` | 11 | axum integration (migrated cases) |
| `jwt_modes.rs` | 16 | The three JWT modes |
| `plugin_listener.rs` | 15 | Plugins and listeners |
| `login_password.rs` | 9 | Password login |
| `annotation.rs` | 9 | Annotations (migrated cases) |
| `refresh_token.rs` | 2 | RefreshToken rotation |
| `keycloak_oidc.rs` | 1 | The full OIDC RP flow (real Keycloak) |
| `tenant_isolation.rs` | 1 | Multi-tenant isolation |

### db-specific acceptance targets

dbnexus uses `compile_error!` to forbid embedded (sqlite) and server-side (postgres/mysql) drivers from coexisting, while the `full` aggregate includes `db-sqlite` — hence database-specific scenarios compile and run via separate targets, closing the coverage gap:

| Target | Feature face | Coverage |
|--------|--------|----------|
| `acceptance_db_postgres` | `--no-default-features --features db-postgres` | Connection + 10 core-table migrations + UserRepository CRUD (ACC-ENV-005..006) |
| `acceptance_db_mysql` | `--no-default-features --features db-mysql` | MySQL migrations and CRUD (ACC-ENV-007..008, dynamically raised via testcontainers) |

### Example-level integration tests (`examples/tests/`)

65 test files correspond one-to-one with `examples/src/bin/` (basic_login, axum_integration, oauth2_flow, sso_server, jwt_modes, firewall_defense, account_security, etc.), running with `cargo test -p garrison-examples --all-features`, about 116 test attributes in total. Among them `readme_quickstart.rs` mirrors the README "Minimal Example" verbatim, preventing doc drift.

---

## 🔀 Feature Dependency Analysis

### Scale overview

- `cargo metadata` statistics: **143 named features**, with the aggregates
  `full` aggregating 104 items, `production` 42, `config-full` 13, `db-base` 14.
- Module layering: core (no switches, always compiled) + 9 major optional domains + 3 aggregate features.

### Domains and dependency structure

```text
Core (always on): core / stp / annotation / router / dao / strategy /
                   session / config / context / json / exception / manager / plugin

Core extensions ── core-advanced ← authorize-api ← manager-explicit
         └─ tenant-isolation ⇒ limiteron/multi-tenant (limiteron's 0.3 stable line changed the Identifier-import gating to any(parallel-checker, ban-manager, multi-tenant), no companion feature carrier needed)

Config enhancements ── config-{encryption,validation,hot-reload,interpolation,dynamic,
             toggle,yaml,audit,consul,etcd,distributed,schema} → confers/* passthrough
         └─ config-full = the 12 items above

Cache backends ── cache-memory ⇒ oxcache/{memory,serialization,metrics,bloom}
         ├─ cache-redis  ⇒ cache-memory + oxcache/{redis,lua,compression} + redis
         ├─ cache-lock   ⇒ cache-redis + oxcache/lock
         └─ cache-batch  ⇒ cache-memory + oxcache/batch

Database backends ── db-base (dbnexus + 15 sub-features + sea-orm)
          ├─ db-sqlite   = db-base + dbnexus/sqlite            (embedded)
          ├─ db-postgres = db-base + dbnexus/postgres + embedded-migrations
          ├─ db-mysql    = db-base + dbnexus/mysql             (server-side)
          ├─ db-retry    = db-base + dbnexus/retry
          ├─ db-sharding = db-base + dbnexus/{sharding,distributed-id,scatter-gather}
          ├─ db-replica  = db-base + dbnexus/replica-routing
          └─ db-saga     = db-sharding + dbnexus/saga

Protocol layer ── protocol-oauth2 (reqwest/sha2/base64/percent-encoding)
       ├─ protocol-jwt (jsonwebtoken)          [implied by sso/oidc/oauth2-server]
       ├─ protocol-sso  ⇒ protocol-jwt          (OIDC id_token mandatory verification, fail-closed)
       ├─ protocol-oidc ⇒ jwt + oauth2 + subtle
       ├─ protocol-saml ⇒ sso + rsa             (XML signature verification)
       ├─ protocol-sign / apikey(⇒secure-ct-eq+dao-key-index) / temp / invitation
       ├─ protocol-httpbasic / httpdigest / zeroize
       ├─ oauth2-scope-handler ⇒ oauth2
       └─ protocol-sso-server ⇒ sso

Security modules ── secure-totp / secure-sign / secure-confusable / secure-masking
         ├─ secure-xss / secure-sanitize / secure-ct-eq
         └─ sms-rate-limit / email-verification ⇒ email-verification-smtp

Account security ── account-credential (argon2/bcrypt/rand/sha2/base32)
         ├─ credential-zeroize ⇒ credential + zeroize
         ├─ account-policy ⇒ credential + regex
         ├─ account-lockout ⇒ firewall
         └─ account-authflow ⇒ credential + policy + lockout + ipnetwork

Web adapters ── web-axum / web-actix / web-warp (three frameworks, independent and coexistable)
         ├─ web-cors / csrf / security-headers ⇒ web-security (aggregate)
         ├─ annotation-macros ⇒ web-axum (the macro wrapper generates axum Responses)
         ├─ tls ⇒ axum-server + rustls + auth-server
         └─ tls-cert-watch ⇒ tls + confers/watch (certificate/key file hot reload)

Firewall ── firewall (foundation)
       ├─ bruteforce(⇒ddos+limiteron/ban-manager) / ratelimit / anomalous
       ├─ geoip ⇒ limiteron/geo-matching; maxminddb ⇒ geoip+anomalous
       ├─ waf ⇒ web-axum; ddos; gcra/tower/quota/admission/event/monitoring/
       │  parallel ⇒ limiteron/* passthrough
       ├─ rate-limit-redis ⇒ ratelimit + cache-redis
       └─ anomalous-detector-dual ⇒ listener + dao-key-index

Server ── http (the sdforge macro bridge, cfg-only, must not be renamed)
       ├─ auth-server-sdforge ⇒ http
       ├─ auth-server ⇒ web-axum + backend-embedded + sdforge + subtle
       │                + secure-simple-token + mimalloc
       └─ server-health-check / server-graceful-shutdown ⇒ auth-server

Backend architecture ── backend-embedded (default) / backend-remote (reqwest + limiteron circuit breaking)
        ├─ backend-kit ⇒ trait-kit/{lifecycle,health,observer}; backend-shutdown ⇒ kit
        ├─ abac ⇒ cedar-policy + cache-memory
        └─ oauth2-server ⇒ oauth2 + jwt + argon2 + secure-ct-eq (under SQLite,
           RefreshTokenRotation depends on protocol-jwt, hence implied)

Security alerting ── security-extra ← security-alert (compat alias) ← device-binding /
         session-hijack-detection (the latter also ⇒ auth-server)

Observability ── listener ← credit-metering / audit-log(⇒masking+ct-eq)
        ├─ tracing-log / metrics-prometheus / otlp (independent heavy-dependency isolation)
        ├─ grpc ⇒ tonic + tonic-health + tower + sdforge/grpc
        └─ audit-inklog ⇒ inklog/{fast-masking,compression}; -http ⇒ inklog/http

i18n ── i18n (the base layer compiles unconditionally; the feature gates tests only) ⇒ i18n-icu (the ICU4X 7 crates)

Aggregates ── full (95 items) / production (35 items, db-postgres-oriented) / development
        (= cache-memory + db-sqlite + web-axum; default = backend-embedded)
```

### Hard constraints (the combination matrix must obey)

| Constraint | Reason |
|------|------|
| `db-sqlite` ⊕ `db-postgres`/`db-mysql` | dbnexus 0.4 uses `compile_error!` to forbid embedded and server-side drivers coexisting (multi-DB is legal only under "pick one at deployment time" semantics) |
| `--all-features` unusable | A corollary of the exclusivity above; CI always uses explicit aggregates (`full`/`production`) |
| `protocol-sso` ⇒ `protocol-jwt` | OIDC `exchange_code` must verify the `id_token` signature (a security-audit fail-open → fail-closed fix) |
| The `http` bridge feature must not be renamed | The sdforge `#[forge]` macro hard-codes `#[cfg(feature = "http")]`; renaming = all dynamic routes 404 |
| `security-alert` must land in `security-extra` | It was historically a zero-dependency dead feature, making device-binding fail to compile alone |
| MSRV | 1.97.1 (`rust-version` in `Cargo.toml`) — the sibling-ecosystem crates (the stable lines of oxcache / dbnexus / confers / sdforge / limiteron / inklog / trait-kit) require rustc ≥1.97.1, hence the declaration; the CI matrix's MSRV leg and `clippy.toml`'s `msrv` share the value, asserted by the `msrv_guard` guard test |

---

## 🧩 Test Matrix Design

### Three-dimensional coverage (matching user-scenario dimensions)

| Dimension | Carriers | Scale |
|------|------|------|
| **Happy paths** | `acceptance/authentication` (JWT/OAuth2/SSO login flows), `rbac`, `session`, `protocol_jwt`/`protocol_oauth2`/`protocol_mixed`, `web_{axum,actix,warp}`, `server`, `bw_ac` (ABAC) | Acceptance scenarios / 19 domains (matrix above) |
| **Errors and boundaries** | `resilience` (timeouts/disconnections/circuit breaking), `security` (token forgery/injection/CSRF), `concurrency` (race conditions), `environment` (fail-closed service gates), `storage`/`repository` (storage faults and migrations) | Same as above |
| **Combination scenarios** | the `web_{axum,actix,warp}` × `db_{sqlite,postgres,mysql}` compile-level grid (below) + runtime acceptance of the three web frameworks under the `full` face | 15 grid combinations + 13 targeted combinations |

### Runtime matrix (real services)

Bootstrapped by `S0` compose + executed by `S3`:

- **Redis** (compose :16379): DAO read/write/TTL/atomic-method guards (ACC-ENV-001..004),
  distributed rate limiting, the cache-redis backend.
- **The Redis rate-limit backend (`rate-limit-redis`)**: `tests/redis_limiter_backend.rs` covers dual-instance
  shared login-failure counters / sliding windows / TTL expiry / captcha answers across instances / `reset_prefix` /
  unreachable fail-closed; `GARRISON_TEST_REDIS_URL` defaults to DB 15, auto [SKIP] when Redis is unreachable.
- **PostgreSQL** (compose :15432, credentials matching test defaults): connection + 10 core-table migrations +
  UserRepository CRUD (ACC-ENV-005..006).
- **MySQL** (compose :13306 for manual verification; automation raises it dynamically via testcontainers,
  ACC-ENV-007..008): docker-probe gated, auto [SKIP] when unreachable.
- **Keycloak 26** (compose :18090; S0 provisions the `garrison` realm idempotently via `scripts/keycloak_provision.py`:
  client `garrison-cli` / user `alice`): the OAuth2 four grants, authorization-code PKCE, introspection, RFC 7009 revocation, and the OIDC RP (the `keycloak-oidc` face, S3kc) all hit a real IdP; authorization codes are obtained by driving the real login-form flow via keycloak_fixture (a 2026-09 user ruling: the acceptance layer forbids mocks; the former wiremock simulation face was removed/pushed down to the unit layer; auto [SKIP] when unreachable).
- **HIBP** (the `policy-hibp` face, S3hibp): breached/clean password queries hit the real
  api.pwnedpasswords.com (k-anonymity uploads only a 5-hex prefix); auto [SKIP] offline.

> **db-specific acceptance targets**: dbnexus uses `compile_error!` to forbid embedded (sqlite) and
> server-side (postgres/mysql) drivers from coexisting, while the `full` aggregate includes `db-sqlite` —
> so ACC-ENV-005..008 were cfg-stripped under the full face and historically never actually ran. Suite stage S3
> compiles and runs them via the separate targets `acceptance_db_postgres` / `acceptance_db_mysql`
> (`--no-default-features --features db-postgres|db-mysql`),
> closing that coverage gap (`tests/acceptance_db_*.rs`).

Address coverage conventions (defaults unchanged, backward compatible):

| Environment variable | Default | compose value |
|---|---|---|
| `GARRISON_TEST_REDIS_ADDR` | `127.0.0.1:6379` | `127.0.0.1:16379` |
| `GARRISON_TEST_REDIS_URL` | derived from ADDR | `redis://127.0.0.1:16379` |
| `GARRISON_TEST_POSTGRES_ADDR` | `127.0.0.1:5432` | `127.0.0.1:15432` |
| `GARRISON_TEST_POSTGRES_URL` | `postgres://garrison:garrison@localhost:5432/garrison_test` | port `15432` |
| `GARRISON_TEST_KEYCLOAK_URL` | `http://127.0.0.1:18090` | port `18090` |

### The compile-level matrix (the combination-conflict defense line)

Stage `S5` runs `cargo check` + `cargo test --lib --no-run` for every combination
(the latter specifically guards against the "test-code feature-gating drift" recorded in 2026-09):

1. **Aggregate features**: `default` / `development` / `production` / `full` / the zero-feature minimal;
2. **The web × db grid**: `{web-axum, web-actix, web-warp}` × `{db-sqlite, db-postgres,
   db-mysql}` (9 combos) + the three webs coexisting × one db (3 combos) — obeying the dbnexus exclusivity constraint;
3. **Targeted pairwise combinations** (13, from historical incident surfaces and the ci.yml guard list):
   `db-mysql+embedded-migrations`, `db-sqlite+protocol-apikey`,
   `db-postgres+three-tier-cache`, `protocol-jwt+secure-ct-eq`,
   `protocol-saml+protocol-oidc`, `web-warp+annotation-macros`,
   `web-actix+web-security`, `auth-server+backend-remote`,
   `oauth2-server+cache-redis`, `tenant-isolation+firewall-bruteforce`,
   `db-web-policy-listener`, `email-credential-authflow`, `full+testing`;
4. **The each-feature full scan** (`--full-matrix`, hundreds of combinations × compilation, hours):
   `cargo hack check --each-feature --exclude-all-features` + per-feature test compilation
   (aggregates excluded; the weekly CI `feature-matrix.yml` runs the same logic as the backstop).
   Two cargo-hack invocation caveats (recorded 2026-09-10):
   - `--no-dev-deps` temporarily rewrites the manifest, mutually exclusive with `--locked` (the lockfile would need updating);
   - `--exclude-all-features` is mandatory — the dbnexus exclusivity makes the all-features baseline fail by design,
     an expected constraint rather than a regression (the CI feature-matrix.yml weekly compile job was fixed in sync).
   Local verification record: **130/130 feature combinations compile independently, all green** (rustc 1.98.1 + `-D warnings`).

> The full powerset is O(2^108), mathematically infeasible; this suite samples on four layers —
> "single feature alone + targeted pairs + aggregates + the grid" — sharing the same methodology as CI.

---

## 📖 Usage Guide

```bash
# Daily full run (recommended): compose bootstrap + static gates + all tests + quick matrix + bench + HTTP E2E
bash scripts/e2e_matrix.sh

# Pre-release deep scan: adds the each-feature full compile scan (hours)
bash scripts/e2e_matrix.sh --full-matrix

# Fast iteration (skips bench and HTTP E2E)
bash scripts/e2e_matrix.sh --skip-bench --skip-e2e-http

# Debugging: keep the middleware environment
bash scripts/e2e_matrix.sh --keep-env
docker compose -f docker/docker-compose.e2e.yml down -v --remove-orphans   # manual cleanup
```

One-shot HTTP E2E (a process-level black-box smoke of auth_server_serve):

```bash
# standalone run: the script's default ports are 8080 / 8081
EXAMPLE_INTERNAL_API_KEY=$(openssl rand -hex 16) bash scripts/e2e_run.sh
# artifacts: logs/perf.jsonl + logs/e2e_final_report.md
```

> Ports 18080 / 18081 are the high ports exported by stage S7 of `scripts/e2e_matrix.sh` (avoiding 8080 being occupied by resident dev-machine services) — they are not `e2e_run.sh`'s defaults; running the script standalone uses 8080 / 8081.

Report output: `logs/e2e_matrix_report.md` (per-stage logs under `logs/e2e_matrix/`).
Exit codes: `0` all pass; `1` some stage failed (read `logs/e2e_matrix_report.md` first,
then `logs/e2e_matrix/<stage>.log`).

### Environment requirements

- Rust stable ≥ 1.97.1 (the sibling-ecosystem crates' MSRV constraint, not a lockfile field — `Cargo.lock` carries no `rust-version`; with a lagging domestic mirror, temporarily
  `RUSTUP_DIST_SERVER=https://static.rust-lang.org rustup update stable`)
- Docker (daemon reachable; testcontainers pulling the MySQL image needs the network or a local cache)
- protoc (an sdforge build dependency), cargo-hack (needed only by `--full-matrix`)

---

## 🚦 Quality Gates

| Gate | Command | Pass criteria |
|------|------|---------|
| Format | `cargo fmt --all -- --check` | Zero diff |
| Lint | `cargo clippy --no-default-features --features "default" -- -D warnings`<br>`cargo clippy --features "full" -- -D warnings` | Zero warnings |
| Dependency security | `cargo deny --all-features --locked check` | Advisories/licenses/banned sources/duplicate deps all pass |
| Tests | S2~S4 | All green; service-gated scenarios must not silently degrade (S0 guarantees real services in place) |
| Coverage | `cargo llvm-cov --features "full" --fail-under-lines 95` | Line coverage no lower than 95% (the CI coverage job) |
| Performance | `cargo bench --bench garrison_benchmark --features full --locked -- --quick --save-baseline e2e` | No `Regressed` verdict from criterion; the baseline lives in `target/criterion` for later comparison |
| HTTP E2E | `scripts/e2e_run.sh` (external 18080 / internal 18081) | happy path / errors / boundary / perf / pentest all green + the Markdown report generated |

---

## 📝 Known Issues and Disposition Records

- **Toolchain**: the sibling-ecosystem crates (the stable lines of confers / dbnexus / oxcache / sdforge / limiteron / inklog /
  trait-kit) require rustc ≥1.97.1; the aliyun mirror may lag, so update stable from the official source
  (`RUSTUP_DIST_SERVER=https://static.rust-lang.org rustup update stable`).
- **e2e target remnants**: the migration deleted examples' `--test e2e`
  target, but `scripts/e2e_run.sh` still referenced it — rewritten to point at the current `tests/acceptance`
  (pentest→the security domain; perf→the `#[ignore]` cases of the concurrency domain), keeping
  the auth_server_serve process-level black-box smoke + health probing.
- **MySQL migration 1064**: `011_add_soft_delete.sql` once used a `DELIMITER //` stored procedure
  for CLI idempotency — `DELIMITER` is a mysql CLI client directive, not SQL, so dbnexus/sqlx's multi-statement batch execution path reported 1064 directly; it lay dormant because ACC-ENV-007/008 were previously unreachable.
  Now plain DDL (the migrator applies once per version; no stored-procedure idempotency needed).
- **The bench tenant context**: `benches/garrison_benchmark.rs`'s permission_check
  panicked under `tenant-isolation` (the full face) for lack of a `TENANT.scope` —
  the benchmark now explicitly enters the default tenant 0 context (equivalent to the server middleware behavior).
- **Port policy**: the suite fixes high ports (16379/15432/13306/18080/18081/18090),
  with zero collision against common defaults and resident dev-machine containers; cleanup only touches the compose project `garrison-e2e`.
- **Bench invocation**: a bare `cargo bench` also runs lib unittests under the bench profile,
  which do not understand criterion arguments (`Unrecognized option: 'quick'`) — the suite fixes
  `cargo bench --bench garrison_benchmark`.
- **The perf baseline's debug/release dual mode**: `assert_perf_baseline` is a soft warning under debug builds
  (`cfg!(debug_assertions)`) (login involves argon2/bcrypt, so a P99 ~1.1s in debug is expected), and a hard panic under release. Release hard verdicts require
  an externally started release service injected via `GARRISON_E2E_EXTERNAL_URL/INTERNAL_URL/API_KEY`
  (the `RemoteContext::connect_env` path). Report-side parity:
  below-target `profile=debug` items are marked ⚠️ soft warning in `logs/e2e_final_report.md`
  (`scripts/e2e_analyze.py`), no longer contradicting the tests' (passing) verdicts.
- **The perf_login baseline recalibration (2026-09-11)**: the original test drove a single account `perf_user`
  at concurrency 100, hitting the login path's per-login_id mutex
  (`GarrisonSession::with_login_lock`, a TOCTOU fix, **by design** — protecting
  the same account's Account-Session read-modify-write atomicity), so single-account concurrency inevitably serializes (measured
  P99 ~700ms). Now 100 accounts rotate (`LoadRunner::with_body_fn`), measuring
  system throughput under realistic multi-user traffic; same-account concurrency correctness is covered by the concurrency domain's race tests. Troubleshooting methodology on record: a wchan snapshot located the futex herd waiting → gdb symbolization pinned `with_login_lock` → a feature-elimination experiment (minimal vs full differing 90×) cleared the middleware of suspicion → the multi-user control experiment confirmed it.
- **e2e_run.sh false "not ready" on cold builds (2026-10-13)**: the 30×1s readiness budget covered only process startup; on first runs (`target/` lacking the `auth_server_serve` binary) `cargo run`'s full compilation exceeded the budget, so the script exited "not ready within 30s", while `.cargo/config.toml`'s `[term] quiet = true` suppressed cargo's progress output and the diagnostic block's stderr was empty, pointing the wrong way. Split into a standalone `cargo build` step (explicit error on failure) + a start/readiness probe; after prebuilding, the same script passes end to end.
- **chaos_redis.sh Sentinel cold-topology guaranteed failure (2026-10-13)**: Sentinel learns replicas only via the primary's
  `INFO` (default refresh period 10s); drilling immediately after a fresh compose start, the script had already paused the primary, and Sentinel aborted with `-failover-abort-no-good-slave` (the replica appears only after the old primary unpauses). Added a pre-injection `num-slaves ≥ 1` wait (≤60s; failing the assertion refuses injection and fails explicitly); the failure/interruption branches reclaim the `garrison-chaos-*` topology via an EXIT trap (capturing the Sentinel log before removal), leaving no leftover containers. A second hardening the same day: host event-loop stalls trigger Sentinel TILT (information collection only, no action; measured 90s+), while the replica promotion-eligibility window is only `down_after_period × 10` (`sentinelSelectSlave`,
  `src/sentinel.c`) — at the 3s tier the 30s window was exhausted by detection latency and every failover aborted; compose's `down-after-milliseconds` relaxed to 30s (window 300s),
  promotion wait 120s → 240s.

---

## 📚 Related Documents

| Document | Description |
|------|------|
| [📖 User Guide](USER_GUIDE.md) | The complete tutorial from installation to advanced usage |
| [📘 API Reference](API_REFERENCE.md) | Public API and module reference |
| [🏗️ Architecture](ARCHITECTURE.md) | Design principles, module layout, and data flow |
| [⚡ Performance](PERFORMANCE.md) | Performance targets, benchmarks, and optimization advice |
| [🛠️ Development](DEVELOPMENT.md) | TDD workflow, code standards, and debugging tips |
| [🚀 Deployment](DEPLOYMENT.md) | Production deployment notes |
