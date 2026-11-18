# 📋 Changelog

This file records all notable changes to the Garrison project.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and versioning follows [Semantic Versioning](https://semver.org/).

## 📋 Table of Contents

- [1.0.0 (Unreleased)](#100---unreleased)
- [0.9.0](#090---2026-11-14)
- [0.9.0-rc.5](#090-rc5---2026-11-01)
- [0.9.0-rc.4](#090-rc4---2026-10-20)
- [0.9.0-rc.3](#090-rc3---2026-10-14)
- [0.9.0-rc.2](#090-rc2---2026-08-26)
- [0.9.0-rc.1](#090-rc1---2026-08-25)

---

## [1.0.0] - Unreleased

### Breaking — Secure-by-Default Profile

The library default posture now matches the hardened reference deployment. These flips are visible to embedders that relied on the old defaults:

- **Bind addresses default to loopback**: `AuthServerConfig::default().external_bind` and `internal_bind` move from `0.0.0.0` to `127.0.0.1`.
- **`strict_security` defaults to `true`**: short internal API keys (<32 bytes) and un-ACKed external login exposure are now rejected by `validate()` at startup rather than only warned about.
- **`require_tenant_bound_jwt` defaults to `true`**: stateless JWTs without the `tid` tenant-binding claim are rejected in a tenant context (`stp-check-login-tenant-unbound`).
- **`require_session_tenant_binding` defaults to `true`**: sessions without a tenant binding are rejected in a tenant context (`stp-check-login-session-tenant-unbound`).

### Migration Actions

1. **Container / network deployments**: the framework now binds `127.0.0.1` by default. Set `GARRISON_EXTERNAL_BIND=0.0.0.0` (and `GARRISON_INTERNAL_BIND=0.0.0.0` when needed) explicitly, or call `with_external_bind`/`with_internal_bind`, to preserve wildcard binding. The image compose example sets these variables explicitly.
2. **Embedded deployments with existing credentials/sessions**: rotate the internal API key to at least 32 bytes. Migrate or invalidate legacy unbound sessions and stateless tokens before upgrading, or use the single-version rollback switches for one release: `GARRISON_STRICT_SECURITY=false`, `GARRISON_REQUIRE_TENANT_BOUND_JWT=false`, `GARRISON_REQUIRE_SESSION_TENANT_BINDING=false`. These rollback switches are removed in 1.1.

### Added

- **`garrison doctor` static security audit (`cli-ops`)**: a read-only command that aggregates the framework's existing validators into a nine-item ✓/✗/! posture report with stable Finding IDs. `--profile strict` makes any Warn exit nonzero for CI gates and container startup probes. No new security rules, no config writeback, no runtime dependency probing. See [DEPLOYMENT.md](DEPLOYMENT.md) · Static security posture audit and [CONFIGURATION.md](CONFIGURATION.md) · Doctor checks.

---

## [0.9.0] - 2026-11-14

The 0.9.0 stable release: no breaking API or behavior changes relative to 0.9.0-rc.5. The in-house dependency face fully moved from the rc line to stable lines (confers 0.6.0 / trait-kit 0.5.0 / oxcache 0.5.0 / dbnexus 0.6.0 / inklog 0.3.0 / sdforge 0.5.0 / limiteron 0.3.1), and the `garrison-macros` pin moved to `0.9` with the finalization.

### Changed

- **In-house dependency-face stabilization (rc → stable lines)**: the seven-library pins moved from rc full-version precision to minor precision — `confers "0.6"` / `trait-kit "0.5"` / `oxcache "0.5"` / `dbnexus "0.6"` / `inklog "0.3"` / `sdforge "0.5"` / `limiteron "0.3"`, resolving to confers 0.6.0 / trait-kit 0.5.0 / oxcache 0.5.0 / dbnexus 0.6.0 / inklog 0.3.0 / sdforge 0.5.0 / limiteron 0.3.1; the `garrison-macros` workspace pin `0.9.0-rc.5` → `0.9`; the `fuzz` sub-workspace lock synced to 0.9.0. MSRV comments dropped the rc wording in sync.
- **The supply-chain baseline aligned with dependency stabilization (vet + deny)**: `supply-chain/audits.toml` gained source-level self-audit entries for the 11 in-house crates' stable versions — downloading the rc↔stable crates.io packages per crate and diffing file by file for evidence: confers-macros / dbnexus-limiter-port / sdforge / trait-kit src show zero diffs; dbnexus-macros / sdforge-macros only clean up comment separators; confers's diffs are i18n-foundation exception comments and cli main.rs relocation; dbnexus / inklog / limiteron / oxcache evolve per the upstream CHANGELOG finalization sections (external-connection accounting / masking pushed down into trait-kit / sdforge dependencies made optional / i18n unification); the `supply-chain/config.toml` exemption baseline aligned with the lock (86 entries upgraded, 92 added, 21 removed as out-of-graph; fluent / icu_* leaving the graph matches the i18n unification). `cargo vet check --locked` green (14 fully audited / 788 exempted).
- **The libsqlite3-sys RUSTSEC-2026-0459 explicit exemption (bundled SQLite CVE-2026-119375)**: the affected range is 0.6.0–0.38.2 (the bundled face), the fix needs ≥0.39.0, while the dependency chain's sqlx-sqlite 0.9.0 declares `>=0.30.1,<0.38.0`, and sqlx 0.9.0 / sea-orm 2.0.4 / dbnexus 0.6.0 are all the latest releases — no patched path exists in the graph. `deny.toml` [advisories] registers the exemption per the in-repo precedents (RUSTSEC-2026-0387 / RUSTSEC-2023-0071), with an exposure analysis (only bundled builds opened to a low-trust process that can write the -wal file are affected; db-sqlite is an embedded application-local database, and production combinations use db-postgres and never touch the sqlite face) and removal conditions (sqlx >0.9.0, or mechanical removal after dbnexus/sea-orm migrate to libsqlite3-sys ≥0.39). `cargo deny --all-features --locked check` fully green on all four checks.
- **i18n unification (fluent direct → family-unified supply)**: the translation layer moved from fluent 0.17 direct usage to sdforge::i18n host registration; the ICU layer's own `icu_*`×6 dependencies are now supplied uniformly by trait-kit's `i18n` feature (`i18n-icu` → trait-kit I18nFormatter for plurals/dates/numbers), and this repo no longer depends directly on icu_* components.
- **The single-root garrison binary**: serve / cli / healthcheck merged into sdforge CliBuilder subcommands (src/main.rs is a single-root auto-discovery with no [[bin]] section; subcommand faces trim per feature: serve=auth-server+cache-memory, the ops group=cli-ops and its dependencies, healthcheck unconditional — subcommands missing their feature report unrecognized explicitly).

- **CI toolchain installation moved to `scripts/setup_rust.sh` (removing `dtolnay/rust-toolchain`)**: 24 call sites (7 workflows) switched to `bash scripts/setup_rust.sh <toolchain> [components...]`; the script's behavior mirrors the removed action's composite steps (install `--profile minimal` → install components → set default → disable incremental compilation → enable colored output), additionally writing `RUSTUP_TOOLCHAIN` to pin the toolchain explicitly (immune to a future directory-level `rust-toolchain.toml` override — that file was previously deleted because a directory-level `channel="stable"` silently overrode all workflow pins). One fewer third-party action in the supply chain. **Root cause**: the action's repository has no version tags and force-pushes rewritten branches on every Rust release — pinning by SHA necessarily departs from upstream ref history, making supply-chain audits impossible; only switching to runner-built-in capability is a real cure.
- **Third-party action pin-comment suffixes changed to the upstream real tags** (92 sites): zizmor requires the comment to be exactly the version number (`# v7.0.1`); any suffix (`# v7.0.1, nosemgrep`) is judged "comment without a version"; the old `# v2.88.0 (cargo-deny)`-style comments mismatched the actual tags (v2.87.29) and were corrected together.
- **`softprops/action-gh-release` replaced with the runner-built-in `gh release`**: preserving softprops' upsert semantics (an existing release on the tag is rewritten rather than duplicated), and the later uniqueness assertion still pins exactly 1 release.
- **zizmor moved from a non-blocking baseline to a blocking gate**: after clearing to zero, `continue-on-error` was removed — future unpinned-uses / ref-version-mismatch / template-injection findings go red in CI immediately instead of accumulating as untriaged alerts; the new `.github/zizmor.yml` writes "third-party actions must pin by full commit SHA" explicitly into the repository (the policy was already the upstream default; once written into the repo, changing it requires the repository's explicit upgrade process rather than taking effect silently).

### Fixed

- **GitHub Security page alerts cleared to zero (4 Dependabot + 111 code scanning)**: `fuzz/Cargo.lock`'s rustls was stuck at 0.23.45, triggering 4 GHSAs (1 medium + 3 low, including master-secret leakage, Brotli decompression memory exhaustion, application-data leakage after ECH rejection, and KX-group downgrade) — the main crate was already at 0.23.46 and only the fuzz sub-crate lagged; `build(deps): bump rustls from 0.23.45 to 0.23.46 in /fuzz` (PR #68) closed them, with all 4 alerts turning `fixed`. The 111 code-scanning alerts all came from zizmor; three root-cause classes were characterized item by item and fixed:
  - `ref-version-mismatch` ×90 (**real defect**): the previous round cleaned the action pin comments to `# line-pinned`, mismatching the pins — Dependabot consequently **silently stops updating** such comments, and version labels drift indefinitely. Now the 92 pin comments use the upstream real tags (each verified SHA↔tag via `git ls-remote --tags`), and Dependabot maintains comment and SHA together.
  - `impostor-commit` ×24 (**false positive**; evidence: author/committer both `David Tolnay <dtolnay@gmail.com>`, commit messages matching the purpose, `git fetch origin <sha>` fetches directly from upstream; the commits are just no longer in any current ref history — `dtolnay/rust-toolchain` has only 1 tag `v1` repo-wide, no version tags, and force-pushes rewritten branches on every Rust release, so SHA pinning necessarily departs from upstream ref history, making `impostor-commit` (requires reachability) and `stale-action-refs` (requires a tag) **structurally unsatisfiable**): switched to the runner-built-in rustup for toolchain installation, removing the action at the root.
  - `superfluous-actions` ×1 (note level): `softprops/action-gh-release` duplicates the runner-preinstalled `gh`; switched to `gh release create/edit`.
  - Plus 3 `template-injection` fixes: static matrix values (`matrix.rust` / `matrix.flags` / `matrix.target`) are now passed into run blocks via `env:` instead of `${{ }}` interpolation.
- **The PR-level public-API diff job failing randomly with nightly drift**: `api-surface.yml` / `api-surface-diff.yml` used an **unpinned rolling `nightly`**, so success depended on the day's nightly — the 2026-10-31 nightly (1.101.0-nightly f9ceb4a4d) hit `error[E0391]` (an async drop query cycle) compiling the dependency `sea-orm 2.0.4`; cargo exited 101, so PR #69 carried a red cross (that job is report-only and does not block merging). Now pinned to `nightly-2026-10-29` (the nightly verified passing in PR #68); the nightly capabilities rustdoc JSON needs are unaffected, and results are reproducible (the same principle as the repository's Reproducible Build gate).

## [0.9.0-rc.5] - 2026-11-01

### Fixed

- **Supply-chain audit entries aligned with the committed `Cargo.lock` (the CI `cargo vet` gate turned green)**: a dependency upgrade (`chore(deps): garrison 升级 base 依赖到最新 rc`) introduced 19 unaudited versions; `cargo vet check --locked` failed for missing `safe-to-deploy` and the Security workflow went red. Following the existing practice: `supply-chain/audits.toml` gained **source-level self-audit** entries for the 11 in-house crates' (confers / confers-macros / dbnexus / dbnexus-limiter-port / dbnexus-macros / inklog / limiteron / oxcache / sdforge / sdforge-macros / trait-kit) new versions — written after diffing each crate's source against the previous version (including the YAML backend's serde_yaml_ng→serde-saphyr replacement, oxcache's Redis Lua 5s response timeout and EVAL circuit breaking, limiteron's quota-path 5s eval timeout, inklog's SSN-masking extension, dbnexus's default-off `retry_busy_writes`, and sdforge/trait-kit test-key and i18n determinism adjustments); `supply-chain/config.toml` gained `safe-to-deploy` exemptions for the 6 third-party crates newly entering the dependency tree (annotate-snippets 0.12.16 / arraydeque 0.5.1 / encoding_rs_io 0.1.8 / granit-parser 1.3.0 / nohash-hasher 0.2.0 / serde-saphyr 1.3.0) marked pending audit in the backlog, with this repo's `garrison` / `garrison-macros` exemption versions advanced rc.3→rc.4.
- **Dead-exemption cleanup after the YAML parsing backend switch (RUSTSEC-2024-0449)**: with the in-house crates switched to `serde-saphyr`, `serde_yaml_ng` / `unsafe-libyaml` left the dependency graph and the original "reachable dependency risk acceptance" rationale and ignore entries all lapsed — keeping them would trigger cargo-deny's `advisory-not-detected` dead-exemption warning. `deny.toml` [advisories] and `.cargo/audit.toml` removed the `RUSTSEC-2024-0449` ignore entry and the old-chain rationale in sync; `supply-chain/config.toml` cleaned the three stale exemptions not in `Cargo.lock` (`serde_yaml_ng` / `unsafe-libyaml` / `untrusted 0.7.1`); `SECURITY.md` §6 was rewritten as "the old chain left the graph + risk acceptance for the new YAML stack (serde-saphyr / granit-parser, third-party and **not source-audited**)" — the reachability discussion was corrected per measurement: `serde-saphyr` enters **all** feature combinations' artifacts via limiteron's **non-optional** dependency chain, so the risk acceptance rests not on "not in the dependency graph" but on **runtime call sites and input sources** (the `config-yaml` face parses deployer-local configuration; the `full` / `config-full` faces' `config-consul` / `config-etcd` remote sources sniff and parse as YAML — deployer-managed infrastructure input), plus the new stack's built-in parsing budgets (`max_depth` 64 / `max_nodes` 250 000 / alias-ratio guards); the two regression anchors are kept — "introducing untrusted-YAML parsing capability requires re-assessment" and "after the new stack is audited, replace the backlog exemptions with real audit entries". `SECURITY.md`'s supply-chain section notes that this repo's own crates (`garrison` / `garrison-macros`) are recorded as exemption entries rather than self-audit entries. `docs/SECURITY_AUDIT.md` and `scripts/security_evidence.sh`'s supply-chain audit command scope aligned to the CI's actual `cargo vet check --locked`; the script's sentence "exemption entries need a re-review date" did not match the repository's real state (795 exemptions with none), changed to "exemption entries need a rationale".
- Verification: local `cargo vet check --locked` passes (Vetting Succeeded — 12 fully audited, 795 exempted) and `cargo deny --all-features --locked check` shows no `advisory-not-detected` warnings.

### Fixed

- **The `loom-test` gate command compiled no race cases (the gate was a shell)**: the `loom-test` feature was only `dep:loom`; feature transitivity is AND semantics and does not imply `protocol-jwt` / `db-sqlite`, so `cargo test --features loom-test` **did not compile** the RefreshTokenRotation concurrency cases (measured `--list` hit 0) — a green gate command did not mean the cases ran. Now `loom-test = ["dep:loom", "protocol-temp", "protocol-jwt", "db-sqlite"]`, and `cargo test --features loom-test` truly compiles and runs `protocol::jwt::refresh::db_sqlite_tests::concurrent_rotate_same_token_*` and `protocol::temp::tests::loom_consume_same_key_exactly_once`.
- **The RefreshTokenRotation concurrency cases lacked coverage strength**: the original case sampled one round of dual threads, so "exactly one success" held only by luck when the narrow CAS window was missed. Now barrier-synchronized starts + 16 rounds of dual-thread races + 4-party concurrency races, each round with a fresh token (avoiding the previous round's reuse disposal `revoke_chain` polluting the verdict), asserting per round exactly one success with all others hitting the consumed marker (`jwt-refresh-token-consumed`) or reuse detection (`TokenRevoked` / `jwt-refresh-reuse-rejected`).

### Added

- **`scripts/perf_compare.sh` supports archived markdown baselines**: the original implementation only recognized local `target/criterion/**/<baseline>/estimates.json` (not committed), so the in-repo archived `docs/cn/benchmarks-v1.0-baseline.md` **could not drive comparisons** and baseline refresh had no SOP. The script now resolves the baseline source in three tiers — explicit `BASELINE_MD` → a local criterion baseline → an archived markdown auto-matched by "baseline name" under `docs/cn/` — parsing the archived md's criterion output for the baseline values (unknown type shapes error explicitly with exit 2, never silently passing); added `--help` / `--baseline` / `--threshold` / `--baseline-md` arguments and the baseline refresh-and-archive SOP (`docs/cn/PERFORMANCE.md`).
- **The API diff now detects signature-level changes**: `scripts/api_surface.py`'s `modified` previously only detected kind changes at the same path — **signature/type changes of existing public items were completely invisible**. Now every public item gets a signature fingerprint (function parameters and return types, struct public fields and inherent methods, trait method signatures, type alias / constant / static types), `modified` covers both kind changes and signature-fingerprint changes, and the structured JSON adds `kind_changed` / `signature_changed` plus both sides' signature text.
- **`scripts/api_surface.sh` gained `--help` and structured diff path overrides**: added `--help` (prints usage and exits 0 at the argument-parsing stage, no longer triggering the full rustdoc build by mistake), explicit `--diff` / `--diff-json` arguments; the `--diff-json` output path is overridable via the `API_SURFACE_DIFF_JSON` environment variable, with the default unchanged (`logs/api-surface-diff.json`).

### Changed

- **The public-surface baseline file format gains the signature fingerprint (an artifact format change)**: `logs/api-surface.txt` moved from two columns ("kind + public path") to three ("kind + public path + signature fingerprint") (`scripts/api_surface.py` updated in sync). PR-level diffs generate both sides with the same script version, so behavior is unchanged; when **old two-column baselines** (historical archived artifacts) compare against new baselines, signature-level changes are undetectable — the script prints an explicit warning instead of silently reporting "no change".

## [0.9.0-rc.4] - 2026-10-20

### Changed

- **Cookie security defaults tightened (breaking-change note)**: non-`development` profiles keep `DEFAULT_COOKIE_SECURE = true`; when the `development` aggregate feature is enabled the default becomes `false` to support local HTTP debugging. Embedders relying on the old behavior must set `GarrisonConfig::cookie_secure` explicitly; `HttpOnly`, `SameSite=Lax`, and the `SameSite=None` non-Secure downgrade remain enforced at the single construction point.

### Security

- **Redis rate-limit connection errors leak no credentials**: connection/cache-build failure errors carry only the masked endpoint (reusing `RateLimitBackend`'s `Debug`) and stable oxcache error codes, never the raw URL text.
- **Session-credential storage key names SHA-256 digested (upgrade note: all legacy sessions invalidated once)**: the storage-key remainders of Token-Sessions and anonymous Sessions changed from the raw token to lowercase-hex SHA-256 digests (`token:session:{sha256(token)}` / `token:session:anon:{sha256(token)}`, constructed at the single point `session::token_key`; aligned with field-encryption's existing principle that "raw bearer tokens must not remain in storage key names") — under a database/backup leak, reading key names no longer recovers live session credentials. **Upgrade semantics**: old raw-key rows are no longer addressed; after upgrading, all existing sessions invalidate once (users re-login, anonymous tokens re-acquire); leftover raw-key rows converge per their `expire_at` via `vacuum_expired` / `garrison-cli vacuum-kv`, with no read-time legacy dual-read (hot-path dual-read costs, unreliable digest/plain-shape discrimination, and sessions' short lifetimes make invalidation cheap). `sha2` moved from optional to a core dependency (digestion applies unconditionally; the security fix does not depend on a feature switch). Residual risk honestly disclosed: session values embed tokens (`TokenSession.token` / `AccountSession.tokens`) and are not encrypted by this change — multi-replica session-backend deployments should enable `field-encryption` full-value encryption.

### Fixed

- **The `DbnexusKvDao::set_if_absent` expiry-takeover race (a trait-contract violation)**: the original implementation, on INSERT conflict with an expired existing row, took DELETE→set as two steps; within the inter-statement window a concurrent writer could insert a new row that the second step's unconditional upsert overwrote (double `true` + silent value loss), violating `GarrisonDao::set_if_absent`'s contract that "for concurrent calls on one key exactly one write succeeds, and get+set two-step compositions are forbidden". Rewritten as an atomic takeover (the SQLite/PG arms use a single-statement conditional upsert `ON CONFLICT (k) DO UPDATE ... WHERE` with the expiry predicate; the MySQL arm uses a transaction + a `SELECT ... FOR UPDATE` row lock and writes after deciding inside it — ODKU's affected-rows tri-state collapses to undecidable under sqlx's unconditional CLIENT_FOUND_ROWS handshake, proven against real databases in acceptance), with the `compare_and_swap(None)` delegation path inheriting atomicity automatically.
- **`DbnexusKvDao`'s `set_if_absent` was unusable on PostgreSQL**: the original `_` dialect arm used SQLite-specific `INSERT OR IGNORE` syntax (unparsable by PostgreSQL, erroring at runtime); after the single-statement rewrite, SQLite/PG share one legal source and the defect closed.
- **`DbnexusKvDao::ensure_table` failed to create tables on MySQL**: the inline DDL used bare `VARCHAR` (MySQL requires a length; syntax error 1064) — SQLite/PG happened to coincide so it never surfaced against real databases; now branched per backend (MySQL `VARCHAR(255)`), aligned with the `migrations/mysql/core/018_kv_store.sql` migration file.

### Added

- **The rate-limit backend configuration actually drives the switch (candidate B: the rate limiter alone on Redis)**: with `rate_limit_backend=redis`, the login firewall hook and `RateLimitStrategy` use an independent Redis rate-limit runtime (oxcache `RedisBackend` + limiteron `RedisDistributedLimiter` Lua atomic counting/sliding windows) while session / token / geo / device data still go through the original DAO. Added the `LimiterBackend` / `LimiterRuntime` abstractions, `RateLimitStrategy::from_garrison_config` / `with_runtime`, and `GarrisonFirewallCheckHookDefault::with_limiter_backend`; the manager establishes the connection before `BUILD_LOCK` (fail-closed on startup failure), and `auth_server` writes `GARRISON_RATE_LIMIT_BACKEND` into `GarrisonConfig` (previously validated but not applied). `reset()` now goes through `LimiterBackend::reset_prefix`, letting the Redis backend clear cross-instance counters. The real-Redis dual-instance acceptance is in `tests/redis_limiter_backend.rs`. Coverage and non-coverage are in `docs/cn/ROADMAP.md` · rc.4 known limitations.
- **The v1.0 gate repository-side artifacts complete**: added `docs/cn/API_FREEZE_CANDIDATES.md`, `.github/workflows/api-surface-diff.yml` (a PR-level report-only structured API diff), `docs/cn/benchmarks-v1.0-baseline.md` and `scripts/perf_compare.sh` (regression-threshold verdicts); `scripts/api_surface.py --diff` emits added/removed/modified public-item JSON; cookie safe-by-default and the `loom-test` RefreshTokenRotation concurrency cases landed. The ROADMAP marks the 1.0 gates as "repository-side artifacts complete / third-party audit pending external"; this round releases **0.9.0-rc.4**, not 1.0.0.
- **The `vacuum_expired` expired-row cleanup primitive + `garrison-cli vacuum-kv`**: `GarrisonDao` gained `vacuum_expired()` (the trait default is a no-op: native-TTL backends are cleaned by the engine; `DbnexusKvDao` overrides with a `DELETE ... WHERE expire_at <= now` full-table cleanup, `GarrisonDaoDbnexus` delegates transparently, `GarrisonSession` forwards by the same name), deleting only expired rows, leaving `expire_at IS NULL` permanent rows untouched, idempotent, returning the deleted count; `garrison-cli` gained the offline `vacuum-kv --db-url` command (zh/en message keys complete), with `--sweep-legacy-session-keys` explicitly sweeping raw-key rows left over from the upgrade (rows under the `token:session:` prefix whose remainder is not 64 lowercase hex chars, including `timeout=0` permanent leftovers — expiry convergence never removes them; the heuristic errs conservative, zero false-deletion surface for digest-shaped rows). No in-library background scheduler — the cleanup trigger cadence (cron / in-process periodic) is the deployer's decision.
- **`DbnexusKvDao` joins the DAO conformance contract net**: the `dbnexus_kv_sqlite` conformance instance landed (previously the `dbnexus_sqlite` instance's KV delegation was the in-process `InMemoryDao`, so SQL KV had zero contract coverage and the set_if_absent race escaped); conformance adds expiry-takeover (set_if_absent / CAS(None)), 8-writer concurrent contention, and vacuum-count contract cases, effective for all backends.

### Changed

- **The `rate-limit-redis` / `production` presets include the Redis rate-limit backend**: `rate-limit-redis` moved from "config selection only" to actually driving the runtime switch of the login hook + `RateLimitStrategy`; the `production` preset adds `rate-limit-redis` (the default remains Memory, behavior unchanged).
- **`GarrisonConfig::rate_limit_backend` semantics updated**: `redis` requires `rate-limit-redis` + `GARRISON_REDIS_URL`; non-TLS `redis://` is subject to oxcache policy (production `rediss://`; dev/test `OXCACHE_ALLOW_INSECURE_REDIS=I_UNDERSTAND_THE_RISKS`). Details in `docs/cn/CONFIGURATION.md`.

## [0.9.0-rc.3] - 2026-10-14

> R01–R18 security-audit remediation + the unified error model (request-id / Retry-After) + at-rest field encryption + WebAuthn/Passkey + password reset + MFA/step-up orchestration + OIDC back-channel logout + multi-tenant hardening + tightened reference-deployment security baselines.

### Security

- **Multi-tenant session-tenant binding (FINDING-025)**: session creation (`create_token_session_inner`) binds the session to the tenant when a tenant context exists (the `TENANT` task_local resolved by `tenant_resolution_middleware`) (the TokenSession attr `__garrison_tenant_id`, key retained as `SESSION_TENANT_ATTR_KEY`); `check_login` validates the binding against the request's tenant when a tenant context exists and the session is bound, rejecting mismatches explicitly (`stp-check-login-tenant-mismatch`) — the client-controlled `X-Tenant-Id` can no longer carry another tenant's session across tenants. The stateless-JWT patch: tokens issued within a tenant context carry the `tid` claim (`TenantBoundJwtClaims`; the payload is the existing format + `tid`, byte-identical when issued without a tenant context), and `check_login_stateless` validates `tid` against the request's tenant after successful verify and before the blocklist check (closing the revocation escape where the jti blocklist's physical namespace shifts with the request's tenant; the blocklist key remains `jwt:blacklist:{jti}`, with the cross-tenant escape closed by the binding check). Unbound legacy sessions (upgrade compatibility) and deployments without a tenant context behave unchanged; binding semantics converge gradually as sessions rotate. The contract is in `src/context/tenant.rs`; regression tests in `src/stp/session/tests.rs` (the binding / cross-tenant rejection / stateless `tid` series).
- **RBAC tenant-dimension threading**: `GarrisonInterface` adds `get_permission_list_in_tenant` / `get_role_list_in_tenant` (delegating to the global callbacks by default, behavior unchanged; overriding businesses gain tenant-scoped data, so cross-tenant duplicate `login_id`s do not cross-contaminate); the `PermissionChecker::authorize` default implementation consumes `AuthRequest.tenant_id` (non-0 takes the `has_permission_in_tenant` tenant-aware path, 0 unchanged); `GarrisonPermissionStrategyDefault::check_permission_in_tenant` scopes both the data source and the cache keys to the request-level tenant, and `check_role_in_tenant` moves from "ignore the tenant, delegate to the global `check_role`" to real tenant-scoped decisions via `get_role_list_in_tenant` (including the role_hierarchy expansion semantics, aligned with `check_role`).
- **Cross-tenant invalidation of the permission/role decision caches (the invalidation-version mechanism)**: `DefaultPermissionStrategy::invalidate_permission_cache` moved from "enumerate-and-delete by the builder's tenant segment via `keys()`" to incrementing the invalidation-version key `garrison:decision:ver:{login_id}` (atomic via `dao.incr`, backend-consistent, independent of feature-gated enumeration); the permission and role decision cache keys embed a version segment `…:cache:v{ver}:{tenant}:{enc(login_id)}:{enc(component)}` — after the version increments, old Allows in **all tenant segments** become unreachable immediately (fixing the invalidation gap where request-level tenant-segment writes could not be cleared), old keys expire naturally with their TTL (300s), and the version key's TTL ≥ 2× the decision TTL (no revival); cache-key components are disambiguation-encoded with `%`→`%25`, `:`→`%3A` (old keys' 4th segment is the tenant, new keys' is always the `v<number>` version segment — disjoint and non-colliding), eliminating the same-key poisoning surface between `(login="a:b", perm="c")` and `(login="a", perm="b:c")`.
- **The kickout / logout_by_login_id race closed**: "token snapshot → jti blocklist → session deletion" converges into one per-login_id lock critical section (`logout_by_login_id_inner` split + `blacklist_all_jwt_jti_locked` snapshotting inside the lock, taking the snapshot from the DAO's AccountSession rather than a possibly stale in-memory index), eliminating the TOCTOU window where "a concurrently logged-in new token's session is deleted while its jti misses the blocklist" (under Stateless such a token would have survived until natural expiry); a failed blocklist-snapshot read warns explicitly without interrupting logout.
- **Session precondition checks for the second-factor family (GAR-02 / R2-1)**: `check_safe` / `check_disable` gain the shared session precondition `check_session_precondition` — when the context carries a token but the session is invalid/revoked (forged, expired, kicked), an explicit `Err(GarrisonError::Session)` is returned (the trait default and the `GarrisonLogicDefault` override agree; no longer merged with "MFA not enabled" / "not banned" into a lenient result); for valid sessions the "no MFA configured counts as pass" semantics are unchanged; no-token contexts (authflow orchestration) keep the existing pass-through. The embedded `AuthBackend::check_safe` / `check_disable` bool adaptation passes `Session` errors through unchanged (not folded into the business bool, and `check_disable`'s missing-TokenSession defensive branch goes fail-closed in sync).
- **The login-identifier registry and device-interface tenant isolation**: `UserIdentifierRepository::register`'s unique-constraint conflict re-check now goes through the new `find_owner_in_tenant` (the SQL carrying a `tenant_id` predicate) — same-tenant conflicts return `Taken { by_user_id }` (the same trust domain), hitting another tenant's row returns the neutral `Registered` (leaking no user_id to the other tenant); `find_owner`'s docs note the global-dimension leakage warning (multi-tenant deployments with untrusted input must use the tenant-scoped re-check); `UserDeviceRepository::block_device` / `unblock_device` signatures gain `tenant_id` (SQL `WHERE tenant_id = ? AND id = ?`; a cross-tenant `device_id` hits 0 rows, a no-op, closing the cross-tenant ban primitive); password reset writes the code-tenant binding when issuing the token (`pwdreset:bindt:{jti}`), and `reset` validates the request's tenant against the issuing tenant (a missing binding fails closed, and the mismatch error carries no ownership information — both checks precede any credential write).
- **Tightened reference-deployment (the auth_server bin) security baseline**: the default bind address tightened from `0.0.0.0` to `127.0.0.1` (`GARRISON_EXTERNAL_BIND` / `GARRISON_INTERNAL_BIND`, accepting only IPv4/IPv6 literals; invalid values refuse startup); the internal API Key forced ≥32 bytes (the management plane's sole credential, aligned with jwt_secret's HS256 floor); `GARRISON_TRUSTED_PROXIES` accepts only loopback/RFC1918/link-local/IPv6 ULA addresses (public values refuse startup; XFF parsing activates only after configuration); with the external login enabled and a non-loopback external bind, an explicit `GARRISON_EXTERNAL_LOGIN_ACK=i-understand-no-credential-check` is required (exact case-sensitive match, otherwise startup is refused); `GARRISON_MAX_LOGIN_COUNT` defaults to 10 (the earliest session is kicked beyond it; explicit 0 = unlimited). The Docker image presets `GARRISON_EXTERNAL_BIND`/`GARRISON_INTERNAL_BIND=0.0.0.0` (needed for container port mapping; the external exposure surface is governed by ports/firewalls).
- **Internal API Key auth-failure lockout and multi-value header rejection (GAR-25 / GAR-28)**: new `ApiKeyLockout` — after same-source-IP consecutive auth failures (missing/wrong/duplicate `X-API-Key`) reach the threshold (default 10, 0 = disabled), the window (default 300s) answers uniformly with 429 + `Retry-After`; any successful authentication resets it, and the Nth failure locks immediately without waiting for another; purely in-memory state (single-instance semantics; cross-instance bans need `firewall-bruteforce`/`ban-sync`), with an entry cap preventing memory exhaustion. Duplicate multi-value `X-API-Key` headers fail closed with 401 (eliminating the gateway-dependent first-value/last-value split).
- **SSO hardening (GAR-15 / R2-3)**: `SsoClient::new` / `DefaultSsoServer::new` force the HMAC secret ≥32 bytes (`sso-client-secret-too-short` / `sso-server-secret-too-short`; a short secret lets a ticket-holding attacker brute-force it offline and forge ticket signatures, aligned with the qrlogin/protocol-sign floors); `SsoServer::push_message` wraps business messages into the HMAC-SHA256 envelope `SsoMessageEnvelope{payload, hmac, seq}` on the publish side (seq monotonically increasing within the publishing instance), and subscribers consume via `verify_sso_message` (verify first, then check seq — `seq <= last_seq` rejects as replay; cross-instance deployments must maintain last_seq per topic × publishing instance) — the pub/sub channel is open to any subscriber/publisher with no transport-layer authentication, and messages without the envelope or failing verification are untrusted.
- **SAML Destination / Audience validation strict by default (GAR-31)**: `XmlSecSamlProvider` refuses when the expected Destination/Audience is unconfigured (fail-closed; previously warned and allowed); dev/test exemptions require explicit opt-out via `allow_unvalidated_destination()` / `allow_unvalidated_audience()` (`#[must_use]`, warns and allows; production must configure `with_expected_*`); `DefaultSamlProvider` (no verification implementation, Assertions always stripped fail-closed) stays warn-only (no cross-SP assertion survival surface).
- **Config-layer JWT key and CSRF switch convergence**: the `token_style=simple` `jwt_secret` shorter than 32 bytes upgraded from warn to a startup error (`config-jwt-secret-too-short` — the simple-style key is the HMAC-SHA256 signing key and brute-forceable offline); the jwt/simple key-consuming styles gain weak-key blocklist validation (16 common weak keys, whole-string comparison after trimming padding + case-insensitive, `config-jwt-secret-weak`, no substring matching so high-entropy keys are not falsely hit); the `config-security-rules` rule set wires into `GarrisonConfig::validate()` (JWT key strength + the CORS credentials×wildcard combination check + a warn for wildcard origins without credentials; zero behavior change when the feature is off); `GARRISON_CSRF_ENABLED` accepts only `true`/`false` (case-insensitive), with any other value erroring at startup (`config-csrf-enabled-unsupported` — the former truthy habits "1"/"yes"/"on" silently disabled CSRF protection).
- **login_id input invariants (fail-closed at the issuance source)**: the HTTP wire layer's `LoginRequest.login_id` validates during deserialization (non-empty after trim, no `\x1f` or control characters, byte length ≤ `DEFAULT_LOGIN_ID_MAX_LEN` 255 — the error never echoes the input, 422 rejection); the stp login choke points (`login` / `login_with_token` / `login_by_token`) uniformly go through `validate_login_id` (error codes sharing the wire layer's source; the length cap `config.login_id_max_len` may tighten or relax, 0 = no framework cap while the wire layer still caps at the constant), running before the firewall hooks (invalid values consume no rate-limit/brute-force counting resources).
- **`remember_me_enabled` now actually takes effect**: the stp login choke point (`create_session_with_quota`) downgrades a client-submitted `remember_me=true` to false when `remember_me_enabled=false` (`effective_timeout` never writes 90 days; issuance follows the global `timeout`, the downgrade only debug-logged) — the "disable long sessions" config was previously never consumed on the HTTP login call chain.
- **The auth-server aggregate feature includes `web-security-headers`**: the reference deployment's external routes carry security response headers by default (X-Content-Type-Options / X-Frame-Options / HSTS / Cache-Control), no longer depending on the business to enable them explicitly.
- **Reference-deployment information-leak convergence (GAR-14 / GAR-27 / GAR-29 / GAR-23)**: the external-port health probe exposes only the minimal `/healthz` (the response contains only `{"status":"healthy"}`, echoing no sdforge version; `/readyz` mounts internal only); the internal `/readyz`'s `checks[].details` is stripped by default to name/healthy only (may contain internal dependency topology; `GARRISON_HEALTH_DETAILS=true` or `with_health_details(true)` enables explicitly); Json extractor rejections (the 400/415/422 text/plain diagnostic bodies) are uniformly sanitized into JSON error bodies (echoing no internal Rust type names/field names/byte offsets, effective on both external and internal routes); an oversized login read body (>256KB) returns a 413 unified JSON error body (the old forwarding of an empty body produced a misleading 400 EOF); the internal `get_token_info` / `get_session`'s `caller_login_id` is forced required at the route layer (missing → 400 fail-closed; previously optional with a warn and a skipped ownership check — an internal API Key leak could silently enumerate any live token's owner).
- **Audit-masking patch (Partial mode)**: non-string values (Number/Bool/Null/Array) of blocklist-hit fields are masked whole as `***` (previously only `Value::String` matched, so numeric/boolean sensitive values bypassed masking into storage, aligned with Full-mode semantics); `mask_metadata` logs a `warn` on invalid JSON and returns as-is (the return-value semantics are unchanged — the audit chain is not interrupted, but the skipped masking is observable, no longer silent).
- **`GarrisonAuthServer::listen()` configurable bind address + the 413 normalization for non-login paths**: `AuthServerConfig` gains the `external_bind` / `internal_bind` fields (defaulting **0.0.0.0** for backward compatibility) and the `with_external_bind` / `with_internal_bind` builders; listen()'s TCP and TLS paths both bind per configuration (previously hard-coded 0.0.0.0, leaving downstream unable to close the bind surface); the reference-deployment bin drops its "self-built TcpListener + axum::serve" replica and re-enters the framework's listen() with the bootstrap-resolved bind address injected via the builder (the 127.0.0.1 default and the `GARRISON_EXTERNAL_LOGIN_ACK` gate semantics unchanged; graceful shutdown handled by the framework's server-graceful-shutdown path). `sanitize_json_rejection_middleware`'s status set adds 413 — axum's bare 413 text/plain diagnostic body for oversized non-login bodies ("Failed to buffer the request body") is normalized to the `{"error":"payload_too_large",...}` JSON error body shared with the login read-body cap (the constant is shared, no second implementation); business JSON and empty-body responses are untouched.

### Added

- **Consent-reconcile startup wiring + the WebAuthn provider's full-flow penetration test (post-archival gap fixes of p1p2-absorption)**: `GarrisonAuthServer::listen()` (in deployments with oauth2_state injected) automatically runs `reconcile_consents` at startup, cleaning orphan consent rows of deleted clients — a maintenance operation that is fail-open (failure only warns and does not block startup; the next startup or an explicit ops call retries; completing the T092/R-consent-004 startup semantics — previously a public API with no in-framework call site); new startup-wiring tests (orphan cleanup / surviving rows kept, DAO failure fail-open) and a monolithic full-flow WebAuthn penetration test (register the factor → record a real assertion → `process` yields `Verified{webauthn, aal:2}`, with the harness reusing protocol::webauthn's recorded vectors via `pub(crate)` to avoid vector-copy drift). The archival reconciliation and fix records are in `specmark/archive/2026-09-30-p1p2-absorption/specs-reconciliation.md`.
- **Docker deliverables directory-ized**: `Dockerfile` / `Dockerfile.distroless` / `docker-compose.example.yml` / `docker-compose.e2e.yml` moved into the `docker/` subdirectory (the build context remains the repo root; `.dockerignore` stays at the root); the CI `docker-build` job and all doc/script/test comment references updated in sync. Path changes: `-f docker/Dockerfile[.distroless]`, `-f docker/docker-compose.*.yml`.
- **The garrison-cli ops subcommand face (R16)**: a new standalone ops bin `src/bin/garrison-cli.rs` (the `cli-ops` feature + clap derive, default-features=false) — `healthcheck` (sharing `src/health/probe.rs`'s pure-std decision function with the probe bin, keeping the probe bin zero-dependency), `key-rotate` (an OS-CSPRNG 256-bit signing key + paste-ready config snippets, with `--session-key` for an independent session key), `user-hash` (Argon2id hashing via `Argon2Hasher::with_pool` reusing the R02 concurrency token pool, emitting env/CLI/YAML snippets, aligned with tinyauth `create_user.go:85-128`), `one-time-access-token` (issues short-lived login credentials per user; the `app_user_ext` registry row is the mount point for the business to wire one-shot consumption; expired/disabled/unknown users error explicitly); the R17 field-encryption wiring: the `change-key` (batched full re-encryption — non-transactional, row-level atomic, idempotent re-runs with the old key converge; reports scanned/reencrypted/failed/legacy counts; an empty scan set errors explicitly to prevent false success) and `check-key` (decryptability validation, corrupt rows explicit) subcommands; keys support the `GARRISON_FIELD_ENCRYPTION_KEYS` environment variable (the same format as the server, avoiding the argv leakage surface). `one-time-access-token`'s one-shot consumption semantics require the business to wire registry-row deletion into the login path (the framework does not auto-consume; the output includes wiring notes). `export/import` is explicitly out of scope; the compatibility rationale with the R03 decision is in [DEVELOPMENT.md](DEVELOPMENT.md)'s garrison-cli section.
- **OIDC Back-Channel Logout persistent delivery (R15)**: the new `backchannel-logout` feature and the `oauth2_server::backchannel` module — the logout token reuses protocol/jwt issuance (with the `events: {"http://schemas.openid.net/event/backchannel-logout": {}}` claim and no identity claims beyond optional sid; TTL 120s); the persistent queue table `oauth2_backchannel_queue` (id/client_id/logout_token/status/pending_retries/next_attempt_at/created_at/max_ttl_at, the four-dialect migration `017_oauth2_backchannel_queue.sql`); triggered on the session-logout path — transactional contexts buffer via `GarrisonEventTx::on_commit` and enqueue after commit (rollbacks never enqueue), while auto-commit paths take the Immediately tier with an explanatory comment. The deliverer: a 5s per-RP timeout cap, **redirects never followed** (a 302 counts as undelivered, preventing a POST downgrade to GET losing the token, aligned with dex `backchannel.go:191-203`'s `CheckRedirect → ErrUseLastResponse` semantics); failures increment the retry counter and push the next attempt back with exponential backoff (backlogged rows do not enter the batch, failed rows do not block healthy ones), and past MaxTtl (default 24h) rows become `failed` with an explicit warn (never silently dropped); the background drain task takes batches of 32, idempotent, never double-delivering. RPs' back-channel endpoints are configured per client by the deployer (this module does no RP discovery fetch and no push-subscription management plane); ops notes in [DEPLOYMENT.md](DEPLOYMENT.md), architecture in [ARCHITECTURE.md](ARCHITECTURE.md).
- **The deprecated-config-key registry — the smooth 0.x→1.0 upgrade path (R12)**: new `src/config/deprecation.rs` — a per-key `Deprecation{key, since_version, new_key, auto_map, map_fn}` registry + load-time handling (after env/toml parsing, before validation): auto-mappable keys migrate to the new key + a `tracing::warn` (including the since version and the new key name; the new key is written only when missing from the tree **or** still equal to the default — explicitly configured new keys are never overwritten); non-auto-mappable keys warn with migration guidance and pass while `current_version < 1.0.0`. The 1.0 gate: from `current_version ≥ 1.0.0` the deprecation grace closes — hitting any registered key is an explicit `GarrisonError` (including auto-mappable keys; 1.0 no longer migrates on the user's behalf); a `map_fn` returning Err counts as an error (un-migratable values are never silently dropped); a version that cannot be parsed, with any hit fails closed. The first registered entries come from the CHANGELOG Breaking section's real deprecated keys (`waf_config`, deprecated since 0.9.0, no auto-mapping); fictitious keys are never registered; with no hits, the version is not parsed and the tree is untouched (zero hot-path cost). The deprecated-key registry is in [CONFIGURATION.md](CONFIGURATION.md).
- **The password-reset flow — anti-enumeration / anti-race / verified-identity binding (R14)**: the new `account-password-reset` feature and the `account::password_reset` module — (1) anti-enumeration at the request entrance: unknown identifiers walk the same path with a dummy token issued for [`DUMMY_RESET_SUBJECT`] and discarded (aligned with authgear `forgotpassword/service.go:121-128`); the response shapes of existing vs nonexistent identifiers are indistinguishable and both count toward rate limiting; lockout beyond limits (default window 1 hour, the same scope as email-verification); (2) ActionToken: a self-contained JWT (sub/purpose=password_reset/jti/exp, reusing protocol/jwt, with the `password_owner`/`password_purpose` extension claims — always None on login tokens); the jti registers one-shot via DAO `set_if_absent` + atomic consumption (exactly one of concurrent attempts succeeds); (3) two-phase race protection: after verification the credential operation is authorized first (the restricted-session marker), then the token consumed — a failed consumption rolls back the credential operation (no residual changes); (4) the code-subject binding is stored in the authflow session (preventing cross-user password changes) + an `app_password_history` append (the four-dialect migration `016_password_history.sql`; HistoryRule's reuse detection rejects historical passwords, and an append failure rolls back the credential write); (5) restricted sessions can only reach the password-change endpoint (everything else 403); (6) the email channel reuses email-verification's sending facilities and masking conventions. 21 tests cover anti-enumeration / rate limiting / the two-phase flow / cross-user / history reuse / rollback. Configuration in [CONFIGURATION.md](CONFIGURATION.md), the threat surface in [THREAT.md](THREAT.md).
- **The two-phase authorize ticket + OAuth2 consent memory (R18)**: after authorize validation passes, a 32-char random ticket is issued (Alphanumeric ≈190 bits, ThreadRng) staging the full request (DAO `set_if_absent`, TTL 600s aligned with tinyauth `oidc_service.go:923-927`); after login, the ticket resumes the flow (`GET /oauth2/authorize/resume`, atomic consumption — a second consumption / expiry / unknown all reject explicitly; the user_id comes from the session, never the query, so a hijacked ticket causes only flow disturbance, not identity impersonation); consent persistence (the key `oauth2:consent:{tenant}:{user}:{client}`) + scope superset merging (requested ⊆ granted skips prompting, add-only); a dual-granularity attribute-snapshot hash (ATTRIBUTE_NAME / ATTRIBUTE_VALUE, SHA-512, aligned with cas `DefaultConsentDecisionBuilder.java:60-82`); a snapshot that cannot be parsed fail-safes into re-prompting; granularity configurable; `reconcile_consents` cleans orphan consent rows of deleted clients (idempotent); the prompt=none semantics (no valid consent → an explicit `interaction_required` failure) / prompt=login (a forced re-authentication round-trip). 51 tests lock the ticket lifecycle / scope merging / snapshot branches / reconcile idempotency / prompt semantics. The flow is documented in [API_REFERENCE.md](API_REFERENCE.md).
- **The MFA/step-up orchestration foundation (R09)**: `stp::mfa` upgraded into an orchestration foundation — (1) the session factor ledger `AmrEntry{method, aal, completed_at}` (login seeds the primary factor `pwd`/aal 1 and `auth_time`), with issuance mapping the RFC 8176 `amr` claim (deduplicated in completion order) and the OIDC `auth_time` claim via `sign_with_amr`; (2) per-client MFA chains with three states (`mfa.global_chain` as the global default / a missing `per_client_chains` key falls back to the global, an empty array disables explicitly, a non-empty array is a mandatory set), and a chain referencing an unknown factor fails closed at startup (`validate_mfa_chains`); (3) the `RequiredActionProvider` three-phase trait (evaluate → challenge → process) + the TOTP provider implementation (reusing the existing TOTP facilities) + the WebAuthn provider (the protocol-webauthn feature; `process` calls the R07 service's authentication ceremony, taking the verification function from the `webauthn_factor` registry — unregistered fails closed); (4) the freshness assertion `assert_freshness` (fresh sessions skip a second challenge; expired sessions trigger a Required Action); (5) recovery codes: batch one-shot generation, verify and consume separated, consume atomically marking used via DAO `compare_and_swap` (exactly one concurrent consumption succeeds), the `recovery_misuse_tolerance` (default 0) misuse-exemption counter, and lockout beyond it fail-closed; (6) the MFA remember cookie: HMAC-bound (stage+credential_id+exp), produced through R01's `build_set_cookie_value` single construction point (HttpOnly constant, the SameSite allowlist fail-fast, the None→Lax downgrade, production prefixes automatic); a valid cookie skips repeated challenges, is not portable across credentials, and expires. 40 tests cover the three-state semantics, fail-closed, concurrent consumption, misuse lockout, the two freshness branches, and cookie semantics. Configuration in [CONFIGURATION.md](CONFIGURATION.md), architecture in [ARCHITECTURE.md](ARCHITECTURE.md).
- **The credit activity write-path throttle aggregation (R13)**: under the `credit-metering` feature, the new `credit::throttle::ActivityWriteThrottle` (a debounce window + bounded, explicit-drop aggregator for high-frequency write paths), **enabled by default** in `CreditMeter::new` — persist_history's SQL ledger writes move from per-entry async writes to throttled aggregation: per key (`{tenant}:{resource}`) only the first consumption in a debounce window enqueues and persists as the window's first-consumption snapshot (deduplication does not refresh the window anchor, so sustained activity never starves accounting); on expiry a background `tokio::interval` persists the batch (the flush loop starts automatically with the first enqueue; `spawn_activity_flush_loop()` can start it explicitly earlier, idempotent); the pending-entry cap is 1000 — when full, new keys are dropped non-blockingly with a `tracing::warn` drop counter (a drop = skipping this persistence, rewritten outside the window; explicit, never silent; the background loop summarizes drop deltas per window), each persistence write times out at 3s, and failed/timed-out entries are cleaned without retry (warned explicitly). The three constants align with pomerium `access_tracker.go:20-24` (1000 / 10s / 3s). **Semantics and compatibility statement**: consumption counting (KV incr) and consumption decisions are unaffected by throttling — only ledger persistence aggregates (one first-snapshot row per key per window; the reconciliation scope changes: the ledger is no longer per-entry complete); pending entries live in memory only and are not persisted on process exit (heartbeats are idempotent; the next activity rewrites); deployments needing per-entry ledger reconciliation disable it explicitly with `CreditMeter::without_activity_throttle()`, restoring per-entry async persistence (`with_activity_throttle()` can inject custom parameters / a shared throttle). Zero new dependencies.
- **The unified error model: request-id echo + the `Retry-After` header + module-prefixed error codes (R04)**: `GarrisonError` adds the `RateLimited { retry_after_secs }` core variant (HTTP 429) and the public APIs `prefixed_code()` (module-prefixed codes `<module>.<snake>`, e.g. `auth.not_login`) and `retry_after_secs()` (delta-seconds integers, floor 1); the unified error body gains the `error_id` and `request_id` fields (the latter carried within the request-id task-local scope, omitted when absent — omitempty), while the legacy `error_code` freezes at its original values and coexists without deprecation (the old→new mapping table is in [API_REFERENCE.md](API_REFERENCE.md)'s error-model section; the decision record is [ADR-0004](adr-0004-unified-error-model-request-id-retry-after.md)). The new `context::request_id` task-local and the three frameworks' `X-Request-ID` middlewares (axum `web::request_id::request_id_middleware` / actix `RequestIdMiddleware` / warp `with_request_id`): a legal inbound id (non-empty, ≤128 bytes, visible ASCII) echoes as-is, an illegal one is discarded and a UUID v4 regenerated (defending CRLF / header / log injection); both success and error responses echo the header, handlers read it via `Extension<RequestId>` / request extensions, and the middleware emits structured logs carrying `request_id`; because warp's `wrap_fn` cannot wrap the inner execution, the error body's `request_id` uses post-hoc back-fill (collect-inject on 4xx/5xx JSON, zero buffering for successes), converging all three frameworks to the same final shape. The `server` rate-limit middleware's 429 branch now goes through `GarrisonError::RateLimited` (the `Retry-After` taken from limiteron's snapshot `reset_secs` — advisory semantics, allowed stale, since a refill window exists between the allow decision and the second snapshot), removing the self-built `{"error":"rate_limited"}` envelope; the OIDC endpoints keep their self-built error bodies with the RFC 6749 `error` key untouched, and `/oauth2/token` rate-limit errors (the `rate_limited` message-prefix contract) bridge into `RateLimited` and emit the `Retry-After` header (the conservative hint of the limiter's configured window upper bound — the sliding window's exact remaining seconds are unavailable). The header names `X-Request-ID` / `Retry-After` are constants, not configuration (ADR-0004 decision 4). **Compatibility statement**: the existing `error_code` values and all public signatures (`code()` / `response_parts` / `response_parts_i18n`) are unchanged; the body's new `error_id` / `request_id` fields are a superset change — consumers parsing strictly by field name are unaffected.
- **The Argon2 concurrency token pool (R02 memory-DoS protection)**: the `PasswordHasher` trait gains the default-`None` `concurrency_gate()` extension point (zero changes for custom implementations), and `Argon2Hasher::with_pool(n)` assembles the concurrency token pool; `verify_pooled` uniformly wraps "async permit acquisition → spawn_blocking → the permit moved into the closure" — the permit's lifetime == the hash execution, so when the caller's future is cancelled the orphaned blocking task keeps holding the permit until completion; the Argon2 memory-residency upper bound equals `pool_size × m_cost` under any cancellation ordering (no oversell); waiting callers queue asynchronously, never rejected; after the semaphore's `close()`, the explicit `account-argon2-pool-closed` error returns. All production call sites (`PasswordCredential::verify` + the three `login_with_password` sites) are wired; bcrypt stays out of the pool (a KB-scale workspace, no memory-protection benefit from pooling — the decision is fixed by tests).
- **The `password_hasher.argon2_pool_size` configuration**: the Argon2 concurrency token-pool size, default 1 (secure-by-default — the default configuration already carries memory-DoS protection), range `[1, 256]` (0 = zero permits, permanent starvation, fail-fast; 256 × 19 MiB ≈ 4.8 GiB is the misconfiguration upper bound), via the environment variable `GARRISON_PASSWORD_HASHER__ARGON2_POOL_SIZE`; the capacity model and tuning advice in [CONFIGURATION.md](CONFIGURATION.md).
- **`protocol-qrlogin` hardening (security-audit-remediation)**: the create response gains `bind_token` (the poll's second ticket, delivered only to the Web side's owner; the qr_id is encoded in the publicly displayed QR ticket, and the two-ticket exchange defends against shoulder-surfing/screenshot hijacking); `confirm` enforces confirmer identity == scanner identity (a mismatch returns the same error as an invalid token, preventing enumeration); the HMAC secret is forced ≥32 bytes (aligned with the JWT HS256 floor); scan/confirm events carry the App side's IP/UA context; the module docs add the inherent login-CSRF risk and mitigations.
- **`UserIdentifierRepository` (the `app_user_identifier` table)**: database-level atomic uniqueness for phone/email login identifiers — the `(id_type, id_value)` primary-key unique constraint backstops concurrent registrations, and `register`'s conflict re-check returns `RegisterOutcome::Taken { by_user_id }`. The four-dialect migration `012_user_identifier.sql`. **Wiring boundary**: the framework's login/registration chains do not call it automatically — businesses must wire `register` explicitly into their registration/binding flows for uniqueness (capability supply, not automatic effect).
- **Permission-cache logout linkage**: `GarrisonPermissionStrategy` gains the default no-op `invalidate_login_cache`; `DefaultPermissionStrategy` overrides it to delete `garrison:perm:cache:<tenant>:<login_id>:*`; `logout`/`kickout` call it automatically (after permission revocation, old Allows no longer survive to the 300s TTL).
- **Multi-stage containerized deliverables (R03)**: two image lines — `Dockerfile` (debian:bookworm-slim) and `Dockerfile.distroless` (gcr.io/distroless/cc-debian12:nonroot) — with cargo-chef's three-stage dependency caching + reproducible `--locked` compilation + non-root runtime (uid 1000 / 65532) + OCI labels (`VERSION`/`GIT_SHA` only in labels; no runtime version endpoint and no fake injection) + a built-in HEALTHCHECK; the new pure-std zero-dependency probe bin `garrison-healthcheck` (auto-discovered in src/bin; probes the external port's sdforge `/healthz` liveness — 2xx→exit 0, otherwise→exit 1 with a one-line stderr reason; connect/read-write timeouts of 2s each (the inner layer as a platform backstop, overall aligned with the 5s HEALTHCHECK budget); the port follows `GARRISON_EXTERNAL_PORT`; the default feature face includes `server-health-check` so the probe route exists); the new `.dockerignore` (the build-needed locales/migrations/examples/macros/Cargo.lock explicitly kept) and `docker-compose.example.yml` (`GARRISON_INTERNAL_API_KEY:?required` fail-loud, healthcheck, an optional commented Redis block); CI adds the `docker-build` job (dual-variant builds + compose validation + an in-container probe smoke loop); DEPLOYMENT.md's "Docker deployment" section rewritten around buildable artifacts (the old image references had no build source — stale placeholders). **Supply-chain risk record (explicitly accepted)**: the base images (debian:bookworm-slim / distroless cc-debian12:nonroot), the cargo-chef base image (the `latest-rust-1` rolling tag), and rustup stable are rolling sources, so builds are not bit-level reproducible — release builds should pin by digest (the `CHEF_IMAGE` ARG is overridable; risks and mitigations in DEPLOYMENT.md's "building images" section).
- **Transaction-bound event dispatch with OnCommit semantics (R05)**: the new `GarrisonEventTx` transaction guard (needs the `listener` feature + any db backend feature; `dao::GarrisonEventTx`) — `begin` obtains an independent Session from the `DbPool` and opens a transaction; `on_commit(event)` buffers events; `execute(sql)` writes in-transaction via `Session::execute_raw`'s in-tx route (existing DAO/Repository SQL through `session.connection()` on auto-commit **does not join** this transaction); `commit(mut self)` dispatches the buffered events FIFO only after the DB commit succeeds, returning `DispatchOutcome { dispatched, failed }` (listener `Err`/panic counts into `failed`, making audit-chain gaps explicit, with `dispatched + failed == the event total`); a commit failure (including dbnexus `Arc::try_unwrap` concurrency conflicts) returns `Err` and the buffered events drop with the guard. `rollback(mut self)` discards buffered events; dropping without commit/rollback, or a commit failure, backstops with a `Drop` warn of the dropped count and event-type summary (distinguishing uncommitted / commit-failed reasons; explicit, no panic, no spawned async rollback); opening the transaction relies on dbnexus Session cascading rollback. `execute(sql)` is the admin privileged direct channel (dbnexus skips all table-level permission checks for the admin role and likewise passes on SQL parse failure), so the SQL content itself is the permission boundary — the docs state the injection warning explicitly: concatenating untrusted input is forbidden. `commit`/`rollback` consume `self`, expressing "unusable after commit" at the type level. `GarrisonListenerManager`'s docs declare the two dispatch tiers: the **Immediately tier** (the existing `broadcast`, behavior and signature unchanged) and the **OnCommit tier** (`broadcast_after_commit`, sharing `dispatch_one` with Immediately under the same isolation promise: one listener's `Err`/panic does not interrupt subsequent listeners or events). **Wiring boundary**: this change delivers the mechanism only and does not force-migrate existing call sites (the 33 `broadcast` sites stay on the Immediately tier; "login-log SQL write + the Login event" is the later wiring target); zero new dependencies.
- **The DAO contract test suite (one ruler for all backends)**: the new `dao::testing` module (running under `cfg(test)` with the unit tests; the `testing` feature build face open to downstream custom backends) — the group-assertion function library `run_basic` / `run_atomic` / `run_concurrent` / `run_ttl` / `run_keys` + the wiring macro `dao_conformance_tests!` (backend + the async make constructor closure + the caps capability-tier list; undeclared tiers are trimmed at macro expansion and generate no tests; optional `serial: true` / `ignore: "..."`). The built-in matrix: `InMemoryDao` (all tiers), `GarrisonDaoOxcache` (`keys` needs `dao-key-index` attached separately), `GarrisonDaoDbnexus` (sqlite actually runs; postgres `#[ignore]` + `DATABASE_URL` fail-loud), and `AloneCache`. The concurrency tier organizes exact-count assertions by security property: SETNX exactly-one-winner (against concurrent duplicate bindings), GETDEL one-shot consumption (against ticket double-spending), the incr/decr return permutations of exactly one (no lost updates and no skipped decrements — the SMS rate-limit flaky regression signature), CAS-if-greater's final value exactly max (Digest nc monotonicity), and compare_and_swap exactly-one-winner (against backup-code double-spending). Zero new dependencies; the existing per-backend unit tests remain side by side (deduplication deferred to a later change).

### Security

- **The constant-time comparison primitive choke-point closure (ADR-0003 decision 2 fully landed)**: eliminating the remaining local constant-time comparison second implementations and `dep:subtle` direct usage — (1) `protocol-httpdigest`: deleted `src/secure/httpdigest/auth.rs`'s `pub(super) fn constant_time_eq` local copy (a verbatim copy of `a.ct_eq(b)`), with the response/uri/nonce-mac three checks unified onto `crate::secure::ct_eq::constant_time_eq`; (2) `secure-simple-token`: `SimpleTokenStyle::verify/parse`'s HMAC comparison moved from `use subtle::ConstantTimeEq` direct usage to the public primitive; (3) `secure-sign`: `Signer::verify_hmac_sha256`'s hand-written `Choice` aggregation loop now delegates to the public primitive (signature-verification semantics unchanged; the timing test `verify_hmac_sha256_constant_time_no_early_return` regression passes); (4) `web-csrf`: `validate_csrf_token`'s length + byte-wise hand-written comparison now delegates to the public primitive, keeping the "empty token is invalid input" semantics (non-short-circuit `&` aggregation — no early return introduced in the comparison phase); (5) `server::middleware` (`auth-server`): the API Key middleware's local implementation became the "fixed-length 256-byte zero-padded + public primitive" combination (keeping fixed work and the length-hiding hardening, renamed `api_key_ct_eq`), and the `auth-server` feature's `dep:subtle` changed to depend on `secure-ct-eq`; (6) `email-verification` / `sms-rate-limit`: deleted the `#[cfg(not(secure-ct-eq))]` hand-written fallback second implementations (the email side's included a length early-return drift), with both features now depending on `secure-ct-eq` and verification-code comparison unified onto the public primitive; (7) `listener::audit_chain`: the audit-chain HMAC verification moved from subtle direct usage to the public primitive. The feature graph: `protocol-httpdigest` / `secure-sign` / `secure-simple-token` / `web-csrf` changed from `dep:subtle` to depending on `secure-ct-eq` (subtle is now introduced only by `secure-ct-eq`; the fixed-length non-secret comparisons of `protocol-saml` / `protocol-oidc` / `protocol-qrlogin` keep `dep:subtle` direct — outside ADR-0003 decision 3's list). Two new guard tests (`secure::ct_eq`): a whole-`src/` scan forbidding a second `fn constant_time_eq(` implementation, plus sensitive-path feature-declaration and `subtle::ConstantTimeEq` direct-usage allowlist checks (negative validation: planting a second implementation / direct usage makes the guards fail); a new `simple_token_tampered_hmac_rejected` behavior test (a tampered/truncated HMAC segment → verify None + parse InvalidToken).
- **The WebAuthn/Passkey credential SPI and registration/authentication ceremonies (R07)**: the new `protocol-webauthn` feature and the `protocol::webauthn` module (webauthn-rs 0.5, default-features=false; its MSRV ≥ 1.88 noted in the Cargo.toml comment) — the credential model `WebauthnCredential` (credential_id uniqueness / public key / sign_count / backup flags / attestation; the table `app_webauthn_credential`, the four-dialect migration `014_webauthn_credentials.sql`); challenges stage via DAO `set_if_absent` + TTL (default 120s), consumed with an atomic read-delete (RowsAffected==0 flags replay, aligned with pocket-id's DELETE...RETURNING semantics); the registration ceremony (attestation parsing, `ExcludeCredentials` against double-binding one authenticator — the database unique constraint backstops concurrency, and the conflict re-check carries the original occupant without leaking other rows); the authentication ceremony (sign_count monotonicity — count ≤ the last recorded value flags a clone and rejects, backup flags updated to storage, and assertion replay rejected via one-shot challenge consumption); the RP configuration derives from the issuer (rp_id = the URL host, origins = [issuer]; rp_id follows issuer changes; an invalid issuer rejects explicitly); passwordless and 2FA as separate policies (`WebauthnConfig.passwordless` / `second_factor`; disabled purposes reject explicitly); the 2FA wiring point `stp::mfa::webauthn_factor` (a process-level factor-verification-function registry; full MFA orchestration belongs to R09). Ceremony tests use real authenticator-recorded vectors from webauthn-rs's upstream test set (MPL-2.0); the repository contract joins the DAO conformance suite (the create conflict re-check reuses the same connection — fixing the structural hazard of nested sessions reading an empty database under the multi-connection in-memory library). The threat surface is in [THREAT.md](THREAT.md), configuration in [CONFIGURATION.md](CONFIGURATION.md).
- **The OIDC discovery endpoint + multi-kid JWKS rotation (R08)**: the dual discovery endpoints `GET /.well-known/openid-configuration` (OIDC Discovery 1.0) and `GET /.well-known/oauth-authorization-server` (RFC 8414) — an unconfigured issuer or `oidc_discovery_enabled` off returns 404 (fail-closed), with metadata derived from actual capabilities (not a static template): `grant_types_supported` per the token endpoint's real capabilities (`password` appears only after the deployer advertises it), `scopes_supported` the union of registered client scopes (derivation failure is an explicit 500, never a silent downgrade), `jwks_uri`/`jwks_algorithms` appearing only when a JWKS is actually published (against dead links), and PKCE `S256` only. JWKS upgraded to multi-kid three-state key management: `Active` (signing) / `Passive` (retired but kept for verification, still published) / `Disabled` (removed from publishing and verification), with three-view semantics — signing takes Active, verification takes Active∪Passive (a `kid` hitting a Passive old key verifies; a missing kid falls back to Active; an unknown kid errors explicitly), and the JWKS output takes Active∪Passive; rotation commits through a DAO `compare_and_swap` ledger (of concurrent rotations exactly one wins and the loser reads the winner-consistent state, defending multi-instance split-brain); a Passive key past `jwks_retention_secs` (the new config, default 7200 = 2× the access token TTL; 0 fail-fasts at startup) becomes Disabled and leaves the JWKS; the JWKS endpoint's `Cache-Control: max-age` computes dynamically as half the retention. Concurrent-rotation exactly-one-winner, over-age retirement, the `kid` three views, and discovery 404/derivation are all locked by tests (keystore 28 / discovery 11 / jwks 22).
- **The refresh-token reuse three-tier classification and concurrent-race tolerance (R06)**: `RefreshTokenRotation`'s reuse detection upgraded from the single tier "consumed = theft" to a three-tier classification — `RecentPrev` (the submitted token hits the surviving chain head's `parent_token_hash`, 1 hop back; the typical concurrent-double-send/network-retry shape), `OrphanedBranch` (>1 hop back hitting an earlier ancestor), `StaleLineage` (no surviving lineage). The disposal dispatch: `StaleLineage` **always revokes the whole chain as theft** (not configurable; semantics consistent with existing behavior); `RecentPrev`/`OrphanedBranch` dispatch per the new `recent_reuse_behaviour` config — `TheftDetected` (default: revoke the whole chain + `TokenRevoked`) / `Unauthorised` (only reject this request without revoking the chain; invalid values fail-fast at startup). Concurrent-double-refresh race tolerance: the `refresh_grace_period_secs` (default 0 = off) + `refresh_grace_max_uses` (default 1) grace window — within the window, an already-rotated old token presented again returns the **existing new token** issued at rotation (no re-rotation; redeemed credentials stage in-process without persistence, so in multi-instance deployments only the issuing instance can redeem, with the others falling back to the regular reuse disposal), and replays inside the window after the budget is exhausted dispose per `recent_reuse_behaviour` (revoking the whole chain by default); the concurrent loser (missing the consumption rights and missing the grace redemption) gets `InvalidToken` without chain revocation; outside the window, disposal follows `recent_reuse_behaviour`. A mid-rotation INSERT failure compensates: delete the half-built child row and return the old token to unconsumed (the original chain stays usable; the error is tagged `rolled-back` / `insert-and-compensate-failed`; if the compensation itself fails, consumed-state fail-closed holds — new and old tokens are never valid simultaneously). DAO: `refresh_tokens` gains the `rotated_at` column (the migration `013_refresh_tokens_rotated_at.sql`, four dialects sqlite/postgres/mysql/duckdb), and the rotation write path joins the DAO conformance suite. The three-tier classification, the grace window's concurrent double refresh, write-failure compensation, and StaleLineage's config independence are all locked by tests.
- **The password-hash migration layer — lazy login-time upgrades and import-parameter ceilings (R11)**: the `PasswordHasher` trait gains the default-implemented `verify_and_rehash(password, hash) -> GarrisonResult<(bool, Option<String>)>` (the default = verify + `None`; zero breakage for custom implementations); `Argon2Hasher` implements it — on successful verify with stored parameters below the current configured tier, a new hash is produced (the re-hash occupies the R02 Argon2 concurrency token pool, leaving the memory-residency bound unchanged); `stp/password.rs`'s main login path wires it: when rehash returns `Some`, the credential storage updates + an audit event (the upgrade is best-effort — failure logs and does not block login; failed logins do not trigger upgrades). The import validation gate `validate_imported_hash`: the format allowlist (only `$argon2id$` / `$2b$` / `$2a$` / `$2y$`) + parameter ceilings (`ARGON2_IMPORT_MAX_M_COST` = 1 GiB, `ARGON2_IMPORT_MAX_T` = 10, `ARGON2_IMPORT_MAX_P` = 4, bcrypt cost ≤ 15 — against per-login OOM / CPU DoS, aligned with zitadel passwap's `ValidateEncodedHash` defensive intent); all bulk-import / credential-write entrances wired, with over-limit hashes rejected whole and errors explicit (never silently skipped). The import constraints and ceiling table are in [CONFIGURATION.md](CONFIGURATION.md).
- **At-rest AES-GCM encryption of sensitive stored fields (R17)**: the new `field-encryption` feature and the `secure::encryption` module — the `CryptoValue` encoding `enc:v1:<key_id>:<base64(nonce|ciphertext)>`, AES-256-GCM, AAD bound to `garrison:{tenant}:{table}:{key}` (ciphertext moved to another row/column fails decryption, defending relocation replay, aligned with authelia `encryption_aad.go:78-85`); keys inject via the existing config-encryption facilities (multi key_id, taking the key per the injected key_id), and enabling the feature without a key is a fail-closed Err at startup. The DAO transparently encrypts/decrypts the selected sensitive columns (`oauth2:atoken:` / `oauth2:rtoken:` / `oauth2:codeused:` / `totp:seed:`): the read path dual-reads (an `enc:v1:` prefix decrypts; no prefix returns as-is — legacy plaintext rows readable during migration), the write path encrypts fully; bearer-credential-class keys are SHA-256 digested before storage. The companion `change_key` (transactional batched full re-encryption to a new key_id) and `check_key` (a decryptability validation report) ops interfaces (the garrison-cli subcommand wiring is in R16). Encryption/decryption failures error explicitly and never return plaintext placeholders; the threat model and deployment controls are in [THREAT.md](THREAT.md).
- **XFF parsing moved to rightmost-untrusted**: in trusted-proxy scenarios, from "take the leftmost value" to "the first untrusted hop from the right" — a client-pre-forged leftmost `X-Forwarded-For` can no longer bypass rate limiting/bans (the rate-limit keys and `inject_client_ip` both use the new parsing).
- **The qrlogin 4 endpoints join the external middleware stack**: axum merge does not inherit layers, so the qrlogin router explicitly mounts rate_limit / inject_client_ip / inject_user_agent / audit_log before the merge in `external_router()` (under the original assembly the endpoints bypassed all rate limiting and auditing).
- **stp password login joins account-dimension brute-force lockout**: under the `firewall-bruteforce` feature, `login_with_password` gains a pre-lockout check + failure counting (the keys `bf:acct:<login_id>:count`, the lock marker `bf:acct:<login_id>:lock`; 5 failures lock 300s; when the request context has an IP, the IP dimension `bf:<ip>:*` stacks) + reset on success; nonexistent users / wrong passwords / malformed hashes all count. **A known trade-off**: nonexistent usernames also count and lock (preventing "did it lock" from becoming an existence oracle) — an attacker can persistently lock any login_id for 300s; deployments should stack captchas/risk control; `hooks::reset` (the `fw:*` keys) does not cover `bf:*` keys — locks expire only by TTL.
- **Password change / logout-by-subject writing the JWT blocklist**: `logout_by_login_id` / `revoke_token` / `revoke_all_sessions` complete the `blacklist_jwt_jti` (the same pattern as kickout) — under Stateless, old access tokens die immediately after a password change.
- **The legacy refresh path revoking the old token**: `TokenLogic::refresh_token` writes the old token's jti to the blocklist after issuing the new one (eliminating the window where both are valid; the full rotation with leakage-reuse detection still recommends `RefreshTokenRotation`).
- **The API Key global verify disabled by default**: `ApiKeyHandler` gains `allow_global_verify` (default false) — `verify()` could verify any key across namespaces via the reverse index, conflicting with tenant isolation; `verify_with_namespace` is enforced by default, while the `rotate`/`update_last_used` management operations are unaffected.
- **Hash-format errors merged into the unified anti-enumeration**: a legacy user's password_hash parse failure no longer returns the distinguishable `stp-unsupported-hash-format` (an account-existence oracle); it now returns the unified `stp-invalid-password` and counts toward failure.
- **Email verification-code error-log masking**: error logs now mask full email addresses (aligned with the SMS side's mask_phone, CWE-532).
- **A deployment warning for the Memory rate-limit backend**: with `rate_limit_backend=Memory` (in-process counting), config validation emits a warn — in multi-instance deployments the effective limit scales with the instance count; switch to Redis.
- **Set-Cookie converged onto the single construction point (R01)**: all write paths (the axum / actix / warp adapters, the axum renewal middleware, the CSRF middleware) produce uniformly through the `context::cookie` construction point (`CookieType` × `CookieScope` × `CookiePath` → `build_set_cookie_value`); write sites no longer assemble attribute strings themselves. The invariants: (1) the SameSite allowlist fail-fast (legal values correspond one-to-one with `COOKIE_SAME_SITE_VALUES`; invalid values produce no Set-Cookie); (2) in non-Secure contexts (`cookie_secure=false` as the deterministic signal), `SameSite=None` auto-downgrades to `Lax` (warn once), fixing the renewal write site's previous direct `SameSite=None` emission (without Secure, browsers reject the cookie entirely); (3) the renewal / CSRF write sites gain `validate_cookie_name_value` injection validation + path/domain character discipline (the path rejects `;` and control characters, the domain allows only hostname characters) — token values or path/domain containing `;` or other injection characters produce no Set-Cookie (failures warn, explicit); (4) the `production` feature + Secure contexts force the `__Host-` / `__Secure-` prefixes (Path=/ with no Domain → `__Host-<name>`; a limited path or cross-subdomain → `__Secure-<name>`; an http downgrade emits no prefix), absorbing Keycloak's `DefaultCookieProvider` and Pocket-ID's prefix naming. **A one-time migration**: under production builds cookie names carry prefixes — after upgrading, online users' old cookies invalidate and they must log in once more; the framework's read and write sides (the read-side uniform entry `token_cookie_name` / the CSRF parsed name) parse in sync, and business code reading cookies itself must switch to the same-name parsing or it will not see the new cookies.

### Changed

- **A full dependency-tree refresh (96 packages updated within constraints)**: `cargo update` refreshed the lockfile — actix-http 3.13→3.18, hyper 1.11→1.12, arrow 58→60, tokio 1.53.2, h2 0.4.20 etc.; the 7 in-house crates stay at their published latest versions. Supply-chain gates synced: `config.toml` adds 28 exemptions (including the toml family's new versions with build metadata, and trybuild under the safe-to-run scope) and prunes stale old-version exemptions — **local `cargo vet check` green for the first time** (the previous 68 missing entries were local-vs-CI version-state differences, resolved by the refresh); the macro companion crates (confers-macros / sdforge-macros) rose to rc.7 under caret constraints (the parent crates remain the published latest rc.6, verified compatible by the green test matrix). The 7-combination test matrix and both clippy gates all green.
- **Upgrade regression fix: DAO-layer TTL exactness broken by oxcache rc.6's default jitter**: oxcache rc.6 changed the builder's `ttl_jitter_factor` default from `0.0` (rc.5) to `0.1`, and `GarrisonDaoOxcache::new` did not pin it explicitly → all DAO writes' TTLs silently jittered ±10% (exposed by the conformance suite's `get_with_ttl ≤ requested` and `incr` first-TTL assertions flaking under the production combination). **Security impact** (early expiry = loosened limits, verified by inspection): the ban records' three keys (record/times/history) each taking independent jitter would break the "times and record remaining-TTL alignment" design invariant; the disable record's TTL=max(duration, until-remainder) anti-early-release margin erodes; rate-limit counters and OAuth2 token-record windows shorten. Fix: DAO construction pins `.ttl_jitter(0.0)` explicitly, restoring rc.5 exact semantics, plus a deterministic regression lock (20 keys × ttl=60 asserting `max(get_timeout) ≤ 60s`, dropping the single-assertion miss rate from ~1/2 to ~1e-6). Trade-off disclosed: de-jittering the DAO layer loses the avalanche-flattening of "same-TTL batch writes expiring together" — that protection remains in garrison's own three_tier (L1 explicitly `ttl_jitter(0.1)`; L2 applies garrison-side jitter per base-TTL hash via `l2_ttl_with_jitter`, not DAO jitter). The production combination's 3380 tests all green (2 failures before the fix).
- **Upgrade regression fix: the `rate-limit-redis` production path broken by limiteron rc.6's sliding-window script contract change**: rc.6 rewrote SLIDING_WINDOW_SCRIPT to fix "same-millisecond members overwriting each other, bypassing the limit" (ZCARD under-counting) — adding `KEYS[2]` (a seq key, INCR generating unique member ordinals) and removing `ARGV[3]` (the clock now taken in-script from Redis TIME). garrison's callers still passed per the rc.5 contract → the script errored on real Redis for missing KEYS[2]; the MockDao/InMemoryDao simulators dispatched by the "contains INCR+EXPIRE → the INCR pattern" priority, and rc.6's script contains both signatures so it mis-dispatched (incrementing `threshold` as a TTL, so from the 2nd request everything was wrongly blocked — 6 rate_limit tests failing deterministically under full). Fix: call sites adapted to the rc.6 contract (`KEYS=[window key, "{key}:seq"]`, `ARGV=[window_ms, threshold]`); the simulator dispatch order inverted (checking ZREMRANGEBYSCORE first — BruteForce's INCR+EXPIRE script lacks that signature, so the inversion does not affect its dispatch) and the sliding-window simulator upgraded to the rc.6 contract (2 ARGVs, the clock from the system wall clock, KEYS[2] required validation); related tests adapted in sync. rate_limit 15/15, dao::tests 162/162, full 5346 all green.
- **The field-encryption degenerate-key gate (`is_weak_key`'s local equivalent check, asymmetric semantics)**: `StaticFieldKeyProvider::new` strictly rejects single-byte-repeated keys for the **master key** (the first entry, always used for new writes) (all-zero / all-0xFF / single-char fills, `weak-key:<key_id>`); **non-master keys** (used only to decrypt legacy ciphertext) downgrade to a `tracing::warn` pass — otherwise deployments holding retired weak keys could never remove them via garrison-cli's `change-key` re-encryption with the old key (the migration exit would be locked fail-closed). `with_primary` refuses promoting a degenerate key to master; `FieldCipher::new` applies the same master-key check to custom providers (`weak-primary-key:<key_id>`; the non-master asymmetry is recorded: custom-provider paths' non-master weak keys are not enumerated-blocked, since new writes always use the gated master). Such keys were previously accepted silently (confers' `is_weak_key` was unreachable cross-crate — its module is `pub(crate)` — hence the local equivalent). Test fixtures single-sourced to `crypto_value::test_key(seed)` (previously cipher/dao/rekey/crypto_value had 5 `[u8;32]`-style dummy-key sites, including adapter tests).
- **`repository/mod.rs` interface isolation fully closed (rule 14's implementation functions to zero)**: following `dialect.rs` (the SQL dialect conversion), the import-hash validation gate (the `ARGON2_IMPORT_MAX_*` / `BCRYPT_IMPORT_MAX_COST` constants, `validate_imported_hash` and its parameter-parsing helpers, and the two test groups) moved to the new `repository/hash_import.rs` — `repository/mod.rs` now has zero implementation functions, keeping only the Row data structures, the Repository trait interfaces, module declarations, and re-exports (the public paths `repository::{validate_imported_hash, ARGON2_IMPORT_*}` and the docs/cn/CONFIGURATION.md references unchanged).
- **The `convert_placeholders` byte-level optimization experiment: a negative result, keeping the original implementation**: a byte-scanning replacement for the per-character implementation was tried; multiple full-scope sampling benchmarks showed no statistically significant gain (±10-40% noise bands overlapping, medians unimproved), rolled back per "evidence first + implementation simplicity" — the function's ~600ns-scale cost is dominated by DB round-trips on real DAO paths; the existing 12 tests and the benchmark scenario remain as behavior/performance locks.
- **Benchmark coverage completed (the upgrade-adaptation surfaces)**: `benches/garrison_benchmark.rs` adds two microbenchmarks wired into S6's performance-gate log echo — `convert_placeholders` (the SQL dialect conversion every Statement construction passes through) and `circuit_execute_closed_passthrough` (the circuit-breaker wrapper passthrough overhead every backend-remote remote call passes through; `iter_custom` drives one block_on, removing the executor constant). Performance verdicts follow the repository's existing relative-baseline mechanism (`--save-baseline e2e` comparison), publishing no absolute timing figures (criterion intervals vary by machine).
- **In-house dependency new-feature absorption (the first batch, the specmark change absorb-dep-new-features)**:
  - **The audit-inklog outbound secret-scan gate**: `audit-inklog` passes through `inklog/secret-scan` (inklog rc.7), and `init_inklog_logging` enables `console_secret_scan` — log text written via the console sink is scanned for high-entropy key/secret shapes and masked before emission, a second defense layer alongside the audit layer's `mask_metadata` (guarding event metadata); inklog's built-in file channel is explicitly disabled (its masker has no scan gate — unscanned text hitting disk contradicts the masking semantics; re-evaluate once the upstream file channel supports a scan gate).
  - **`firewall-admission` name matches reality**: moved from the expedient `limiteron/adaptive-limiting` to rc.6's genuinely implemented `limiteron/admission-control` (a concurrency+rate dual-gate admission; in the rc.4 era admission-control was a no-op placeholder, which is why adaptive-limiting was wired then).
  - **`firewall-event` drops the webhook compile-time workaround**: since limiteron rc.6 the event dispatcher's webhook call sites are cfg-gated, so `limiteron/webhook` is removed per the Cargo.toml plan — the event system no longer drags in the reqwest/hmac/sha2/hex dependency chain (garrison registers no webhook URL, so runtime behavior is unchanged).
  - **Cache hot-key observability**: the new `cache-hotkey` feature (off by default, passing through `oxcache/hotkey`); `UserCacheService`'s L1 read paths (get_permissions/get_roles/get_user) instrument `HotKeyTracker::record`, and the new `hot_keys_top(k)` top-k diagnostic method (shard-sampled counters, a diagnostic view).
  - **The non-TLS graceful-shutdown drain cap (a defect fix)**: under `server-graceful-shutdown`, the two non-TLS paths (axum::serve) for external/internal previously waited indefinitely for in-flight connections after the signal — stuck connections could stall shutdown indefinitely; now aligned with the TLS path's existing axum_server cap — after the signal the drain lasts at most 30s (`SHUTDOWN_DRAIN_TIMEOUT_SECS`), timing out with a warn and force-aborting in-flight connections.
  - **The ttl_jitter pinning comment aligned**: three_tier L1's explicit `.ttl_jitter(0.1)` matches oxcache rc.6's default; the comment updated to "explicitly pinned against upstream default drift" (zero behavior change).
  - **Evaluated but not absorbed this round**: confers `is_weak_key` (its module is `pub(crate)`, unreachable externally — correcting the Explore conclusion), confers RemappedConfigProvider / oxcache Sentinel / sdforge ReadinessRenderer and idempotency (listed as later candidates, in the specmark change's Non-Goals).
- **The `tenant-isolation` compile-combination fix (long misjudged as an unfixable upstream issue) + the CI matrix unlocked**: the root cause was limiteron rc.6's `governor.rs` — `use crate::matchers::Identifier` is gated by `#[cfg(any(parallel-checker, ban-manager))]` while the multi-tenant block uses that type, so enabling `multi-tenant` alone missed the import (15 E0425/E0433). garrison uses the zero-dependency `limiteron/ban-manager` (already used by the firewall) as the compile-time companion feature: `tenant-isolation = ["limiteron/multi-tenant", "limiteron/ban-manager"]` — the combination now compiles with zero warnings and 1560 tests green; the feature-matrix CI's each-feature and single-leg test compilations removed the `tenant-isolation` exclusions in sync (the old note's rc.5 defect no longer applies). Once upstream gates multi-tenant's imports properly, the companion can be dropped (noted in the Cargo.toml comment).
- **Automated regression locks added for the non-TLS shutdown drain cap**: the two paths' drain timing logic extracted into the injectable-timeout `drive_with_drain_deadline(serve, drain_signal, timeout)` (private, shared by external/internal; both sites take the 30s production constant via `drain_timeout()`), with 4 new tests in the `graceful_shutdown_tests` module — locking "the production 30s cap is wired", "without a signal, serve completes normally (the timeout counts only from the signal)", "completes within the limit after the signal", and "after the signal, a stuck serve returns None under the injected short timeout". Previously the defect fix had only compile + regression-suite coverage, with no targeted regression lock.
- **In-house dependencies batch-upgraded to the crates.io latest**: `confers`/`dbnexus` 0.6.0-rc.5→**rc.6**, `oxcache`/`sdforge` 0.5.0-rc.5→**rc.6**, `trait-kit` 0.5.0-rc.6→**rc.7**, `inklog` 0.3.0-rc.5→**rc.7**, `limiteron` 0.3.0-rc.5→**rc.6** (including their macros companions and transitive updates: inklog rc.7's i18n dependency switched from fluent-bundle+icu to fancy-regex 0.19.2, dbnexus split out the `dbnexus-limiter-port` sub-crate, uuid 1.26.1→1.27.0). Supply-chain audits follow the bumps: `supply-chain/audits.toml` adds 8 in-house audits (including the brand-new dbnexus-limiter-port crate), and `config.toml` adds the fancy-regex third-party exemption. Two upstream API-change adaptations: limiteron rc.6's circuit breaker (`ErrorClassifier` renamed to the generic `FailureClassifier<E>`, `execute`'s error type becoming `CircuitCallError<E>`); confers rc.6's config-file loading adds the `allowed_extensions` extension-allowlist pre-gate (the next entry). Lib tests: 1556 by default / 2446 with features, all green.
- **The circuit-open rejection's external error variant changed (the limiteron rc.6 migration)**: `BackendRemote`'s fast rejection while the circuit is open moved from `GarrisonError::FirewallBlocked("circuit-limited::…")` (HTTP 403 / `FIREWALL_BLOCKED`) to `GarrisonError::Network("circuit-open::circuit breaker is open")` (HTTP 502 / `NETWORK_ERROR`). The rc.5 implementation actually produced FirewallBlocked (the documented `circuit-open::` Network contract never took effect under rc.5 because the `CircuitBreakerError` arm was unreachable); rc.6 split open-rejections into the `CircuitCallError::Open` variant, so after migration the behavior **matches the module-doc contract for the first time**. No garrison-internal code consumed the old variant (a repo-wide grep finds 0 matches); downstream monitoring `FIREWALL_BLOCKED`/403 or the `circuit-limited::` prefix for circuit events must adjust its scope in sync (the `circuit-open::` prefix + the Network variant are locked by unit tests).
- **Config-file loading explicitly pins the TOML format (the confers rc.6 adaptation)**: since confers rc.6, the `allowed_extensions` extension allowlist runs before path validation (extension-less/unknown-extension file sources are rejected first); garrison's `FileSource` declares `Format::Toml` explicitly (the upstream documented exemption channel), restoring the rc.5 order of the path-traversal/directory/special-file security checks. The cost: config files with `.yaml`/`.json`/`.ini` extensions are no longer parsed per their own format (always TOML, fail-closed) — garrison's file-config contract is TOML (CONFIGURATION.md), so the narrowing matches the promise; LoaderConfig's security items (symlink checks / the 10MB cap / error-path redaction / URL-encoded traversal scanning) are all preserved.
- **Dead-code cleanup and `dead_code` exemption closure (a codenexus + compile-matrix joint review)**: deleted `protocol::oauth2`'s `read_limited_text` (no production callers — the error path deliberately does not read the response body, preventing `client_secret` leakage via a malicious server's echo; `sso::oidc` keeps a local copy that is in use) and its E2 tests; `#[allow(dead_code)]` converged per the real call surfaces — `stp/default_impl`'s `dao()` cfg list narrowed to the real callers (`protocol-jwt` / `firewall-bruteforce`; the other features' consumers go through `session.dao()` directly), `firewall_hook_injected` moved to `cfg(all(test, firewall-bruteforce))` full isolation, the `auth_server` bin's `parse_field_encryption_keys` and `sso::oidc`'s `Jwk` / `JwksResponse` upgraded from `cfg_attr` exemptions to `cfg` full isolation (unrelated builds do not compile them), and `core/token`'s `secret` field exemption narrowed to `secure-simple-token` (the HMAC path's only consumer); three stale exemptions removed (`session::dao()` in fact has callers under every feature, `context::validate_cookie_name_value` is consumed by the always-compiled `pub` cookie write side, and the `config` tests' RSA fixture is always consumed). Zero behavior change; multi-feature combinations (default / jwt / apikey / the db series / cache-redis / firewall / qrlogin / sso / the web series / production) compile with zero warnings.
- **Complexity hotspot refactoring (behavior unchanged, locked by tests)**: `convert_placeholders` (the SQL placeholder dialect conversion, cognitive complexity 41→4) — the main loop only recognizes lexical-context starts, with string literals / line comments / nested block comments copied whole, split into three atomic helpers; `UserLockoutStrategy::record_failure` (39→20) separates the CAS retry loop from state advancement — extracting the pure `advance_failure_state` function (window reset → counter increment → threshold trigger), with the locked type made explicit as the `LockoutTrigger` enum replacing the cfg-gated dual booleans; `extract_token_from_request_parts` (38→23) splits the body-extraction sub-flow (the C7 method restriction → the 1MB parse guard → the JSON field extraction) into `extract_token_from_body`. The SAML/JWT/Keycloak protocol parsing hotspots (`parse_tag_inner` / `validate_id_token_impl` / `verify_id_token`) stay as-is after evaluation: the security-critical paths just completed penetration-test fixes, and refactoring's regression risk outweighs the benefit.

### Fixed

- **The release doc check aligned with rustdoc 1.99 (`redundant-explicit-links`)**: the `protocol::sign::handler` module docs dropped the redundant explicit link targets (``[`SignHandler`](crate::protocol::sign::SignHandler)`` → ``[`SignHandler]``) — the label already resolves to the same target via the module's `use super::SignHandler`, and rustdoc 1.99+ judges this form redundant (the diagnostic has no source span, CI logs show no location, and the local rustdoc 1.97 face does not trigger), blocking the release doc check under `-D warnings`; both the MSRV (1.97.1) and 1.99.0 toolchains verified the doc builds with zero warnings locally.
- **CI toolchain determinism restored (deleting `rust-toolchain.toml`)**: that file declared `channel = "stable"`, overriding each workflow's `dtolnay/rust-toolchain` pins at directory-level priority — the MSRV 1.97.1 / stable / beta three-tier test-matrix legs and the release doc check all actually ran the runner image's built-in stable (measured 1.99.0; the release gates drifted silently with the image — this round's release failure exposed exactly that). After deletion, the per-workflow pins take effect again. The matrix/fuzz toolchain wiring fixed in the same pass: the version-branch snapshot used (1.97.1) hard-codes the toolchain in-source and declares no `toolchain` input (a passed input is ignored with a runner warning, and all three legs actually fell back to the same toolchain) — the test matrix now pins the stable branch snapshot (declaring the `toolchain` input) and installs per `${{ matrix.rust }}` leg, and the security/fuzz-weekly nightly legs pin nightly branch snapshots; README (both languages) / CONTRIBUTING / DEVELOPMENT / TROUBLESHOOTING toolchain wording updated in sync — the local toolchain now follows rustup's default channel (≥ MSRV 1.97.1 required).
- **Manifest hygiene (clearing cargo 1.100 beta notices)**: removed the `package.homepage` / `workspace.package.homepage` duplicating `repository`, 12 orphan entries in `[workspace.dependencies]` inherited by no member (serde / tokio / async-trait / parking_lot / inventory / md5 / jsonwebtoken / totp-rs / bcrypt / zeroize / regex / serial_test — both the root package and examples declare them directly), and `[workspace.package]`'s uninherited `keywords` / `categories`; `.gitignore` adds `lcov_*.info` and `*.cdx.json` (local coverage / SBOM artifacts). `cargo metadata --locked` and the MSRV / beta dual-tier `cargo check --locked` re-verified.
- **Release-pipeline convergence and idempotency**: the GitHub Release stage removed CycloneDX SBOM generation and SLSA Build Provenance attestation (including the `id-token` / `attestations` / `artifact-metadata` permissions), keeping only GitHub's auto-generated source archives as Release assets; `cargo publish` (garrison-macros and garrison) gained `--locked` (`Cargo.lock` ships with the package, verifying the build matches the committed lock) and idempotency (skipping when crates.io already has the version) — release re-runs no longer abort on "already uploaded" and can converge half-released states; the release-order comment's garrison-macros version corrected from the stale 0.7 to 0.9.0-rc.3.

### Breaking

- **The auth_server bind defaults to `127.0.0.1`** (formerly `0.0.0.0`): bare-host runs needing external access must set `GARRISON_EXTERNAL_BIND=0.0.0.0` explicitly (the image presets the ENV); explicitly configured non-IPv4/IPv6 literals refuse startup.
- **The internal API Key ≥32 bytes**: enforced at auth_server bin startup (formerly only non-empty); generate with `openssl rand -hex 32`.
- **The external-login exposure acknowledgement**: with `GARRISON_EXTERNAL_LOGIN_ENABLED=true` and a non-loopback external bind, startup is refused unless `GARRISON_EXTERNAL_LOGIN_ACK=i-understand-no-credential-check` (exact match) is set.
- **`SsoClient::new` / `DefaultSsoServer::new` secrets ≥32 bytes**: shorter constructions return `InvalidParam` (formerly only the empty string was rejected).
- **SSO pub/sub message payloads become HMAC envelopes**: `SsoServer::push_message` publishes the JSON of `SsoMessageEnvelope{payload, hmac, seq}`, no longer the business plaintext (auto-wrapped on the publish side, no off switch) — subscribers parsing plaintext directly will receive envelope strings. Migration: subscribers switch to `protocol::sso::server::verify_sso_message(secret, raw, &mut last_seq)` to verify and recover the `payload` (an illegal envelope format / an HMAC mismatch / a `seq <= last_seq` replay all return Err); the secret reuses the SSO ticket-signing key; with multi-instance publishing, `last_seq` must be maintained per topic × publishing instance (each instance's seq counts independently).
- **`XmlSecSamlProvider` Destination / Audience strict by default**: validation rejects when `with_expected_destination` / `with_expected_audience` are unconfigured (formerly warned and allowed); genuine exemptions require explicitly calling `allow_unvalidated_destination()` / `allow_unvalidated_audience()`.
- **`token_style=simple` short keys move from warn to a startup error**: `jwt_secret` < 32 bytes refuses startup (formerly warned only); weak-key blocklist hits refuse too (effective for both the `token_style=jwt` HS family and the simple style).
- **An invalid `GARRISON_CSRF_ENABLED` value errors at startup**: only `true`/`false` accepted (case-insensitive); any non-`true` value (including "1"/"yes") previously disabled CSRF silently.
- **The internal `get_token_info` / `get_session`'s `caller_login_id` is required**: missing returns 400 (formerly optional with a warn and a skipped ownership check).
- **`UserDeviceRepository::block_device` / `unblock_device` signatures gain the `tenant_id` parameter**: implementers must update in sync (a cross-tenant `device_id` hits 0 rows).
- **A multi-value `X-API-Key` header returns 401**: duplicate `X-API-Key` request headers fail closed uniformly (formerly a take-single-value comparison).

- **`protocol-qrlogin`: first-party QR-code login**: the new `protocol::qrlogin` module (a two-ticket separated state machine: the web side displays the QR, the app side scans and confirms, the web side exchanges for a session). qr_ticket is an HMAC-SHA256-signed ticket (`{64_hex}.{hmac_b64}`, the same format as SSO tickets); confirm_token is consumed once atomically (`get_and_delete`) with only its SHA-256 digest stored in the session; the `allowed_domains` domain allowlist (validated at scan) suppresses QR-replacement phishing (Quishing); the confirmation-page summary is masked (a short UA label, never the raw IP or full UA). The HTTP side adds 4 endpoints (`POST /qrlogin/create|poll|scan|confirm`, wired via `GarrisonAuthServer::with_qrlogin`; scan/confirm force a Bearer App session); poll's Confirmed branch atomically exchanges with the server-stored confirmer login_id and issues the session through the `QrLoginSessionIssuer` port (the same path as password login, fully inheriting permissions / kicking / renewal / auditing). The new `GarrisonEvent::QrLoginCreated/Scanned/Confirmed/Cancelled` events (qr_id masked; the audit side covers all variants exhaustively).

### Security

- **OAuth2 state / OIDC nonce absence fails closed (adversarial-test driven)**: `OAuth2Client::exchange_code_with_pkce` rejects an empty-string state (the two-empty equality used to pass, letting CSRF injection through silently); `OidcHandler::verify_id_token` rejects an empty-string expected nonce (the empty-equals-empty pass invalidated the anti-replay anchor). The redirect_uri exact match / the state's old-callback replay / the nonce absence — three shapes locked by acceptance tests (`tests/acceptance/protocol_oauth2.rs`).
- **The refresh-token rotation degraded path made explicit**: when `OAuth2State::new` has no `RefreshTokenRotation` injected, a structural warn is emitted (including the consequences of unavailable reuse detection), and the DAO degraded branch warns per refresh request — no more silent degradation.
- **The external login endpoint fails closed (Critical, C-1)**: `AuthServerConfig` gains `external_login_enabled` (default **false**). The framework's login endpoint does not verify credentials (the responsibility boundary: credential verification belongs to the business layer; the framework only issues sessions); when disabled, `POST /api/v1/auth/login` returns 404; when enabled, a startup warn is emitted. The `auth_server` bin enables it explicitly via `GARRISON_EXTERNAL_LOGIN_ENABLED`; the tests/examples depending on external login have opted in explicitly.
- **Password-login timing side-channel alignment (High, H-1)**: the user-not-exists branch performs one equal-cost dummy Argon2id verify (`DUMMY_ARGON2_HASH`), eliminating the response-time bimodality versus the wrong-password branch, defending username enumeration.
- **OAuth2 password-grant rate limiting fails closed (M-3)**: `PasswordRateLimiter::check` and `TokenRateLimiter::check_username` (the username dimension, credential-stuffing protection) now reject on DAO failure; `check_client` (client QPS) stays fail-open.
- **JWT blocklist write-failure retry + alerting**: revocation writes retry up to 3 times (100/300ms intervals); a final failure escalates to an `error` log (with the jti and the attempt count); externally it stays idempotently successful.

### Breaking

- **`JwtHandler::with_algorithm`'s illegal-combination semantics adjusted (fail-open → fail-closed)**: construction no longer fails immediately — an algorithm mismatched to the key type is intercepted at the `sign`/`verify` entrance by `validate_algorithm_match`; for construction-time fail-fast prefer `try_with_algorithm`. The existing HS usages (14 call sites) are behaviorally unchanged.
- **Event payload tokens masked uniformly (CWE-532)**: the token fields of the Login / Logout / Kickout / Replaced / TokenExpired / TokenRefresh events take the `listener::mask_token_for_event` masked form (the first 8 chars + `***`); custom listeners can no longer obtain the full token from events (the `SessionExpiryListener` callback parameter is unchanged — apply `mask_token_for_event` before logging).
- **`PasswordCredential::new`'s hasher parameter `Box<dyn PasswordHasher>` → `Arc<dyn PasswordHasher>`**: enabling `spawn_blocking` inside verify.
- **The `server-graceful-shutdown` feature's semantics landed**: formerly an empty shell (reverse-depending on `auth-server`), now a real gate; the `auth-server` aggregate includes it by default.
- **The release profile's `panic = "unwind"` (formerly `abort`)**: restoring the `catch_unwind` task-isolation semantics (listener broadcast / the SSO channel) — one listener's panic no longer terminates the whole auth node.
- **Removing the `firewall-quota` feature and the `GarrisonDaoQuotaStorage` adapter**: zero callers repo-wide (SMS's actual rate limiting goes through `GarrisonDaoDistributedLimiter`'s dual-window counting), removed together with the `limiteron/quota-control` passthrough; downstream needing quota control uses limiteron's `QuotaController` directly.
- **The RateLimit sliding-window storage format changed (a comma string → a Redis Sorted Set)**: the Lua script now uses limiteron's `oxcache_lua::SLIDING_WINDOW_SCRIPT` (the ZSET version, O(1) memory per entry). After upgrading, legacy `rl:*` keys are incompatible with ZSET commands (WRONGTYPE) and expire naturally within `window_seconds + 1s`; requests hitting old keys during the transition fail closed (never wrongly allowed).
- **`pub mod limiteron` compiles unconditionally**: `GarrisonDaoDistributedLimiter` is the public foundation of invitation brute-force counting under any feature face (limiteron itself is a non-optional dependency); the ban/circuit/fallback submodules keep their own feature gates, and the public API face widens accordingly.
- **The GeoIP backend migrated to limiteron's GeoMatcher**: the hand-written `geo::maxminddb` direct mmdb backend (no query cache) is deleted; the new `geo::matcher` delegates to limiteron's `GeoMatcher` (a built-in LRU query cache + batch queries + an off-library IP negative cache). Types renamed `GeoMatcherLookup` / `GeoMatcherCountryLookup`, construction `open` becomes async, and `from_bytes` is removed (zero production callers); the garrison `maxminddb` crate dependency is removed, with the `firewall-maxminddb` feature name unchanged.
- **Config-file loading migrated to confers `FileSource`**: the hand-written safe-loading block and `TomlContentSource` (the Windows-path workaround; confers 0.6.0-rc.4 allows drive-letter prefixes) are deleted. Security protections are carried by `LoaderConfig`: path-traversal/symlink validation, is_file special-file rejection, max_size 10MB + the take(max+1) double guard, and `redact_error_paths` error-path redaction. Config-file IO error messages keep their i18n outlet via `map_confers_build_error`; the orphaned FTL keys (config-metadata-failed etc., 5) are deleted.
- **Environment-variable injection migrated to confers `EnvSource`** (`separator("__")` keeping flat-key compatibility); the new `GARRISON_CORS_ALLOWED_ORIGINS` takes effect via explicit override logic (previously the raw comma string entering the generic collector broke the build); `EnvSource::exclude_keys` / `LoaderConfig::redact_error_paths` are confers 0.6.0-rc.5's new APIs, bridged to the local base repositories via the root Cargo.toml's `[patch.crates-io]` before release (removed after rc.5 ships).

### Performance

- **Slow hashing off the async executor**: every login-path call site of bcrypt / Argon2 hash / verify wraps `tokio::task::spawn_blocking` — login storms no longer block tokio workers.
- **`CURRENT_BACKEND` made lock-free**: the global backend reference moved from `std::sync::Mutex<Option<Arc<..>>>` to `ArcSwapOption` (the Sized wrapper `BackendHandle`), removing the global lock from the check_login / check_permission hot paths; concurrent initialization keeps CAS semantics.
- **TokenSession intra-request reuse**: `is_valid_with_session` returns a snapshot for hover reuse, eliminating duplicate reads within one request (3-4 → 1-2); the new task_local `CURRENT_LOGIN_ID` cache (scoped by the axum middleware and the grpc auth_layer) gives `get_login_id` / `check_permission` cache hits with zero DAO reads, invalidated immediately by logout/kickout/revoke.

### Fixed

- **The WebAuthn MySQL migration index over-length (found by real MySQL 8 acceptance via testcontainers)**: `014_webauthn_credentials.sql`'s composite primary key `(tenant_id, credential_id)` byte budget missed `tenant_id BIGINT`'s 8 bytes — `credential_id VARCHAR(768)` (768×4=3072) plus 8 bytes exceeds InnoDB's 3072-byte cap, so real MySQL 8 reports 1071 Specified key was too long and the migration fails, leaving the MySQL backend's WebAuthn table uncreatable (SQLite/Postgres have no such limit and are unaffected). `credential_id` narrowed to `VARCHAR(766)` (3064+8=3072, exactly at the cap), losing 2 characters of capacity (the spec's 1023-byte ceiling was never covered anyway, consistent with the existing design); locked by the testcontainers real-MySQL-8 acceptance (acc_env_007/008) turning from red to green.
- **cfg(test) helpers failing dead_code compilation under the webauthn/oauth2-without-db-sqlite combinations (found by the each-feature scan)**: `protocol::webauthn::WebauthnCredential::protocol_credential` (`#[cfg(test)]`)'s only caller is gated on `db-sqlite`; `server::oauth2_routes`'s `LogCapture`/`LogCaptureWriter` share the shape — combinations like `auth-server+oauth2-server` (without db-sqlite) failed `cargo test --lib --no-run` necessarily; `stp::mfa`'s top-level `Arc` import gating mismatched its actual usage surface (the non-test `mfa-recovery` code + a local use in the webauthn penetration test). The three gates now match their consumers; verified by compiling both the failing combinations and the consumer combinations.
- **Supply-chain audit-entry updates + an OIDC JWKS fetch transport retry + the role_hierarchy test-database race fix (exposed by Security/CI in the local environment)**: (1) the Security workflow's `cargo vet` gate audits the freshly resolved dependency universe by design — the in-house libraries' new releases (confers 0.6.0-rc.6 / confers-macros 0.6.0-rc.6 / trait-kit 0.5.0-rc.7) and new third-party patches (libc 0.2.190 / actix-server 2.9.8 / uuid 1.27.0) failed for missing audit entries; in-house audits and third-party exemptions added per the existing practice (coexisting with the old-version entries, compatible with both the committed lock and a fresh resolution); (2) `protocol::sso::oidc`'s JWKS fetch is an idempotent GET and retries transport-layer errors once, bounded (a 100ms backoff; non-2xx statuses and parse errors do not retry) — a loopback relay's low-probability truncated connection mid-authentication-flow (the state already consumed) would void the whole authentication, and the retry costs far less than the false kill; (3) `dao::repository::role_hierarchy`'s test database moved from bare `sqlite::memory:` to a uniquely named shared-cache in-memory database — an ordinary in-memory database's pool may allocate disjoint memory instances (the migration's table creation lands on connection A while queries hit B), which flaked Windows CI with "no such table".
- **The loopback transport-layer jitter-proof acceptance infrastructure (`tests/acceptance/relay.rs`)**: Docker Desktop's WSL2 loopback relay truncates loopback HTTP connections with low probability (`IncompleteMessage`, independent of load or reuse mode) and deterministically returns 503 for unbound ports — making "connection refused → Network error" assertions and high-frequency loopback acceptance unstable in local dev environments (the failure set drifting every round). `SendRelayRetry` extends bounded retries over transport-layer errors (≤3 tries, 100ms backoff; received responses return as-is), wired across the acceptance matrix; `introspect_token_network_error` switched to the RFC 2606 `.invalid` domain (environment-independent DNS-failure semantics); the circuit-breaker cases disable the slow-call dimension (the proxy 503 takes ~1s, over the 500ms slow-call threshold, tripping the breaker before the failure threshold) and target NXDOMAIN; the HIBP real-internet case retries bounded over its fail-open result. The full acceptance suite's 401 cases green for 3 consecutive rounds (5-10 drifting failures per round before the fix).
- **The `max_login_count` gate now reads the DAO**: it read the process-local `login_token_map`, so in shared-storage multi-node deployments the gate was short-circuited into a no-op; the DAO's AccountSession is now the authoritative source.
- **DbHealthCheck's real probing**: the new `DbHealthCheck::with_pool(pool)` runs a real SQL round-trip for readiness (`get_session` + `SELECT 1`); without a pool injected it returns `Degraded` (it previously probed the in-memory KV DAO, so readiness stayed Healthy with Postgres down and K8s eviction never fired).
- **The `l1_cache_capacity` config silently ineffective (in-house absorption)**: `GarrisonConfig::l1_cache_capacity` had a default and validation but was never wired into L1 (always the library default 10000); the new `UserCacheService::new_with_capacity` constructor receives it on the `GarrisonManagerBuilder` assembly path.
- **The listener ∧ ¬credit-metering combination's compile failure**: `audit.rs`'s event match lacked `#[cfg(feature = "credit-metering")]` on the `CreditConsumed`/`CreditAlert` arms (the enum variants are gated), so faces like `audit-log` without credit-metering failed to compile; gated per the existing `AnomalousLoginDetected` arm pattern.

### Added

- **JWT asymmetric signing end to end**: `JwtHandler`'s key-type-aware allowlist (`KeyMaterial`: Secret→HS family / RSA PEM→RS256/384/512 / EC PEM→ES256/384 / Ed PEM→EdDSA) with construction-time fail-fast (`try_with_algorithm` / `with_rsa_private_pem` / `with_ec_pem` / `with_ed_pem`); the config layer's `JWT_ALGORITHMS` allowlist extension + asymmetric private-key configuration (Debug-redacted, RSA ≥2048-bit validation); the `/oauth2/jwks.json` endpoint (RFC 7638 kid thumbprints; 404 fail-closed without asymmetric keys configured).
- **The `password_hasher` config section**: Argon2id (default m=19456/t=2/p=1, the OWASP-recommended tier) / bcrypt (cost range [10,15]) configurable, with `validate_core` floor validation + the explicit `allow_weak_argon2_params` risk-acceptance bit; the `build_hasher()` factory injected via `with_password_hasher`.
- **CI security gates and the supply-chain trust chain**: the new `security.yml` (Semgrep p/rust+p/secrets, gitleaks full history, cargo vet, the CycloneDX SBOM, fuzz corpus regression) and `fuzz-weekly.yml` (4 parsing-entry targets deep-scanned Mondays); `release.yml` adds Artifact Attestations (SLSA build provenance) + an SBOM Release asset; `supply-chain/`'s cargo vet audit records committed.
- **The security-documentation system**: `SECURITY.md` rooted (the GitHub Security tab's recognized location, with a redirect page left in docs/); `docs/THREAT.md`'s STRIDE six-dimension × framework-defense/business-responsibility matrix (mdbook chapters + README bilingual cross-links); `docs/adr/`'s three entries (the Argon2id selection, the unified CSPRNG policy, constant-time comparison); `docs/SECURITY_ASVS.md`'s OWASP ASVS 4.0 V2/V3 self-assessment on record; `docs/RELIABILITY.md`'s Redis failure-drill guide + `scripts/chaos_redis.sh`'s three-scenario script.
- **The OWASP Top 10 (2021) mapping document**: `docs/OWASP_TOP10.md` maps the ten risk categories item by item to framework mechanisms (with evidence links) and the business-responsibility boundaries, complementing THREAT.md / SECURITY_ASVS.md as a third view; SECURITY.md / THREAT.md / mdbook cross-linked.
- **Reproducible-build verification**: `scripts/verify_reproducible_build.sh` compares `libgarrison.rlib` byte by byte across two independent builds (SOURCE_DATE_EPOCH fixed + remap-path-prefix, with negative-control semantics); `security.yml` adds the `reproducible-build` job (anchored on every PR); RELEASING.md records the complementarity with Artifact Attestations. Locally measured PASS (rustc 1.97.1).
- **The data-compliance capability (the `data-erasure` feature)**: `compliance::DataErasureService` erases framework-jurisdiction data per login_id/IP (session indexes, lockout state, BF counters), with session erasure delegating to `logout_by_login_id` (delegating rather than copying the concurrency-lock semantics), producing the archived report (deleted keys + delegation results + business-residual hints); `docs/DATA_COMPLIANCE.md`'s data inventory / retention periods / exercising the right to erasure / localization guidance (HIBP is the only optional outbound call, sending only a 5-character hash prefix).
- **The Redis Sentinel failover drill**: compose adds the `chaos` profile (master/replica/sentinel, not started by default); `chaos_redis.sh` adds scenario 4 (inject after replication confirmation → automatic-promotion verification → old-primary demotion back → topology-convergence assertions, with the production-topology differences declared explicitly); RELIABILITY.md's scenario table and interpretation criteria synced.

## [0.9.0-rc.2] - 2026-08-26

### Breaking

- **`check_api_key` fail-closed (CRIT-008)**: when the `protocol-apikey` feature is off, calls generated by `#[check_api_key]` no longer silently return `Ok(())` (previously every request carrying any string passed verification).
  Now it returns `Err(GarrisonError::Config("check_api_key requires protocol-apikey feature"))`.
  If the macro is used in builds without that feature, enable `protocol-apikey` or remove the annotation.
- **`check_abac_with_policy` fail-closed (CRIT-009)**: when the `abac` feature is off and the endpoint declares an
  `abac` policy (`abac = "..."`), it returns `Err(GarrisonError::Config)` instead of silently allowing.
  Endpoints without a declared `abac` policy keep the no-op pass-through.
  The escape hatch: calling `garrison::abac::set_abac_missing_feature_policy(true)` switches to AllowWithWarn
  (allow + a `warn`), with Deny (fail-closed) as the default.
- **Firewall auto-wiring (CRIT-010)**: enabling any `firewall-*` feature makes `GarrisonManager::builder()`
  auto-inject `GarrisonFirewallCheckHookDefault` (sharing the DAO rate limiter), and adds brute-force counting (`record_failure`) on the `login` / `check_login` failure paths with reset on success. This protection was previously dead code.

### Changed

- `session::dao()`'s `pub(crate)` visibility extended to the `firewall-bruteforce` feature (for the login/check_login counting).
- The `GarrisonPermissionStrategy::firewall_hook_injected()` diagnostic method added (default `false`; the default implementation returns the actual injection state).

## [0.9.0-rc.1] - 2026-08-25

### Added

- authflow: `IpWhitelist` (a CIDR allowlist via `IpNetwork::contains`) and the `CustomConditionEvaluator` custom condition evaluator (registered at runtime; an unregistered condition name returns an explicit error)
- The `policy-hibp` feature: the HIBP k-anonymity breached-password check (a range query on the SHA-1's first 5 hex chars; when off, `check_hibp` returns an explicit `Err(HibpDisabled)`)
- `web-axum` guardrail wiring: garrison's `IpWhitelist`/evaluators gated behind the `axum` face

### Changed

- `MockDao` renamed `InMemoryDao` (`src/dao/in_memory.rs`; a `deprecated` alias transition, since removed)
- oauth2_server/secure/totp/dao tests and internal references fully migrated to the `InMemoryDao`/`Totp` new APIs
- The `totp-rs` 6.0 API migration (chained `Builder` construction; `check()` returning `Option<u64>` semantics)
- The `permission` provider's `health_check` semantics made real (memory: the policy-table capacity > 0; yaml: the policy file readable) + failure-path unit tests
- `session::dao()`'s `pub(crate)` gating extended to cover the `protocol-jwt` face
- rustdoc: three doc-link fixes + the `invalid-rust-codeblocks` lint declared explicitly

### Fixed

- `src/secure/totp/handler.rs`'s totp-rs 6 API compile errors
- `jwt_modes`' integration-test secret length aligned with the production 32-byte validation threshold
- `oauth2_server` tests referencing the `MockDao` alias renamed
- `policy-hibp` constants emit no unused warnings on the feature-off face

## [0.8.1] - 2026-07-24

### Security

- **The audit-log token-leak fix (CWE-532, found by the Qoder-methodology data-flow review)**:
  - **HIGH-1**: `AuditLogListener::to_audit_entry` truncates the `token` column uniformly after the match (the first 8 chars + "…", aligned with `apikey::public_key_ref`). Previously the Login/Logout/Kickout/TokenExpired/RevokeToken/SessionTimeout 6 event classes wrote live session tokens verbatim into `audit_logs.token` — an attacker gaining read access to audit_logs (an SQL-injection byproduct / backup leak / replica) could replay and impersonate sessions within exp.
  - **HIGH-2**: `TokenRefresh`'s `old_token`/`new_token` are masked as `***` uniformly by the new `BUILTIN_MASK_FIELDS` built-in blocklist in `mask_metadata` (no longer depending on the operator's `mask_fields` configuration).
  - **MEDIUM-1**: `TempCredentialConsumed`'s credential `value` no longer lands in audit metadata — only `value_len` is recorded (preventing replay of unconsumed credentials downstream).
  - **LOW-1**: the new `BUILTIN_MASK_FIELDS` (password/password_hash/secret/client_secret/token/old_token/new_token/refresh_token/access_token/id_token/old_key/new_key) + `effective_mask_fields` (the operator's mask_fields ∪ the built-ins). `mask_metadata` no longer skips when `mask_fields` is empty — a secure default with the built-in blocklist as the backstop.
  - **LOW-2**: both SAML providers (`DefaultSamlProvider`/`XmlSecSamlProvider`) get a 64KB input-size cap on `parse_response` (against oversized-payload memory DoS; quick_xml itself has no XXE/billion-laughs exposure).
  - Fix strategy: the write layer (`to_audit_entry`) backstops uniformly, not relying on each broadcast site's discipline — defense in depth.

## [0.8.0] - 2026-07-24

### Security

- **The constant-time comparison public primitive** (CWE-208 defense):
  - The new `secure-ct-eq` feature and the `src/secure/ct_eq.rs` module providing `pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool`, based on `subtle::ConstantTimeEq`.
  - `audit-log` / `oauth2-server` changed to depend on `secure-ct-eq` (no longer each carrying `dep:subtle`), eliminating the two duplicate implementations in `src/listener/audit.rs::constant_time_eq_bytes` and `src/oauth2_server/authorize.rs::constant_time_eq_str` (rule 7: read before writing).
  - `AuditLogListener::verify_signature_chain` now uses the public `constant_time_eq`, adding an HMAC-SHA256 hex length check (64 chars, against CPU DoS from oversized signatures, CWE-400).
  - `verify_pkce` now uses the public `constant_time_eq`, adding the S256 `code_challenge` length check (43 chars, against oversized-input DoS).
- **The `jwt_secret` weak-key rejection** (CWE-326 defense, **a breaking change**):
  - With `token_style=jwt`, length validation is enforced: HS256 ≥32 bytes, HS384 ≥48 bytes, HS512 ≥64 bytes (RFC 7518 §3.2).
  - `jwt_algorithm` gains allowlist validation (only HS256/HS384/HS512), preventing a typo from silently taking the 32-byte branch.
  - Under `token_style=simple`, a short jwt_secret is not force-rejected (avoiding breaking legacy configurations), but the `tracing::warn` hint is strengthened.
  - **Upgrade impact**: existing short jwt_secret configurations (e.g. the 11-byte `"test-secret"`) fail at startup and must be updated to ≥32 bytes.
- **CSPRNG unification**: `oauth2_server::authorize::generate_authorization_code` and `oauth2_server::token::generate_token` moved from `rand::thread_rng()` to `rand::rngs::OsRng`, consistent with the project's other modules (eliminating the reseed-state-machine attack surface).
- **The audit_log_written feature-gating fix**: the two versions of `audit_log_written` in `src/listener/audit.rs` (i18n-icu / non-i18n-icu) were gated only on `i18n-icu` but use the `AuditEntry` type (which needs `db-sqlite`), so enabling `audit-log` without `db-sqlite` failed to compile. The `db-sqlite` gate is added.
- **The API Key security-degradation fix (the nebulaid → garrison migration; details in `docs/decisions/A-011`)**:
  - **The CWE-916 plaintext-storage fix**: API Keys moved to the two-part `key_id.key_secret` format (32 hex each); `key_secret` never lands in storage — only its `sha256` hash is stored, verified with `subtle::ConstantTimeEq` constant-time comparison. The `protocol-apikey` feature adds the `dep:sha2` + `dep:subtle` dependencies.
  - **CWE-307 IP-level failure rate limiting**: the new `CURRENT_IP` task_local (`with_current_ip`/`current_ip`); `BruteForceStrategy` gains `is_blocked` (read-only, no counting) and `record_failure` (failure counting only, banning past the threshold); when `firewall-bruteforce` is enabled and an IP context exists, `check_api_key` verification failures count per IP into brute-force protection (successes write nothing; without an IP it is fail-open).
  - **IDOR multi-tenant isolation**: `ApiKeyInfo` gains `owner_id` (defaulting to `login_id`); `verify_with_namespace` enforces namespace ownership; combined with `tenant-isolation`'s DAO-layer prefix physical isolation.
  - **Credential/permission/key management enhancements**: the `ApiKeyScope` enum + `with_allowed_scopes` generation-time scope-allowlist validation; `with_last_used_tracking` throttled-recording `last_used_at`; `get_keys_older_than` stale-key identification; `generate_with_options` supporting explicit `owner_id`/`rate_limit`.
  - **`keys()` production-usable**: `GarrisonDaoOxcache`'s key-index mechanism generalized from the `anomalous-detector-dual` gate into the independent internal feature `dao-key-index` (transitively enabled by `protocol-apikey`/`anomalous-detector-dual`), so `list_by_namespace` no longer returns `NotImplemented`.
  - **Legacy keys fail closed** (**a breaking change**, the W8/CWE-916 hardening): `decode_and_check` rejects old-format keys with an empty `secret_hash` (the v0.4.1/v0.4.2 single tokens), returning `InvalidToken("apikey-legacy-secret-required")` with a `tracing::warn!` migration hint. **No opt-in compatibility switch is provided** (following the "no backward compatibility" rule) — legacy keys must migrate to the v0.7.x two-part format. The `with_allow_legacy_empty_secret` builder method is deleted.
- **The tech-review fix batch (the specmark `fix-tech-review-findings`)**:
  - **W3 real health-check probing + timeout**: with the network backends (`db-postgres`/`db-mysql`/`cache-redis`) enabled, `DbHealthCheck`/`CacheHealthCheck` perform a real `dao.get(HEALTH_PROBE_KEY)` probe wrapped in `tokio::time::timeout(2s)`, returning `Unhealthy` on timeout/failure (eliminating the former "always Healthy" false positive). Embedded backends (`db-sqlite`/`cache-memory`) keep the fast-path `Healthy`. `GarrisonSession::dao()`'s accessor feature gate extends to `db-postgres`/`db-mysql`/`cache-redis` for the health checks to reuse (`pub(crate)`).
  - **W2' singleflight lock cleanup** (CWE-770): `three_tier.rs`'s singleflight load path removes the corresponding key from `singleflight_locks` after dropping the write guard when `Arc::strong_count(&lock) == 1`, preventing unbounded growth.
  - **W1 SQL placeholder conversion**: `convert_placeholders` introduces an `in_string` state machine + `chars().peekable()` look-ahead, skipping `?` inside SQL string literals (replacing only quoted-outside `?` with `$n`) and handling `''` escapes correctly.
  - **W5 backend tests moved out**: `src/backend/mod.rs`'s inline `#[cfg(test)] mod tests` migrated to the standalone `src/backend/tests.rs`, following the mod.rs interface-isolation rule.
  - **C1 PG/MySQL gaining the 007 OAuth2-fields migration**: `migrations/postgres/core/007_refresh_tokens_oauth2_fields.sql` and `migrations/mysql/core/007_refresh_tokens_oauth2_fields.sql` add the `client_id`/`scopes`/`username`/`user_id` fields and the `idx_refresh_client` index, aligned with SQLite's 007.
  - **C2 the PostgreSQL Repository re-export alignment**: `src/dao/repository/postgres/mod.rs` adds 4 aliases (`AuthMethod`/`Session`/`LoginLog`/`UserExt`), fully symmetric with mysql/mod.rs (10 repositories).
- **CodeQL false-positive cleanup**: the new `.github/codeql-config.yml` configures `paths-ignore` excluding test-file paths (`tests/**`, `**/tests.rs`, `examples/**`, `benches/**`), avoiding `rust/hard-coded-cryptographic-value` false positives from hard-coded passwords/nonces in test code. 82 historical false positives were batch-dismissed via the GitHub API (all inside `#[cfg(test)] mod tests {}` inline blocks or standalone test files).
- **The codeql-action SHA pin**: the 3 `github/codeql-action/*@v3` references in `codeql.yml` changed to the SHA pin `@fb4bfd79bfa826ce96c90727ff8833835ba8aad0` (40 chars, verified via `gh api repos/github/codeql-action/git/refs/tags/v3 -q '.object.sha'`), consistent with ci.yml/docs.yml's SHA-pin policy, defending supply-chain attacks (cf. the 2026-03 Trivy action tag malicious-replacement incident).
- **Disabling CodeQL's `rust/unused-variable` rule**: CodeQL's tracking of variable usage inside Rust macros (`tracing::warn!`/`tracing::error!`/`tracing::info!`) is incomplete, systematically misreporting the `e` in `let Err(e) = ... { tracing::error!(error = %e, ...) }` patterns as unused. `.github/codeql-config.yml` adds a `query-filters` disabling that rule, and 13 false-positive alerts were batch-dismissed (numbers 83-95, across src/stp/util.rs, src/stp/session.rs, src/server/server_impl.rs, src/protocol/sso/channel.rs, src/listener/audit.rs, src/core/auth/default.rs). Local `cargo clippy`'s `unused_variables` lint correctly sees through macro expansion to identify usage, and CI enforces `-D warnings` — more accurate coverage without lowering security.

### Changed

- The `audit-log` / `oauth2-server` features' `dep:subtle` changed to depend on `secure-ct-eq`; subtle is still introduced solely by `secure-ct-eq`.
- **CI/CD dependency upgrades** (closing 5 dependabot PRs #19-#23, with the changes applied manually locally to avoid conflicts):
  - `Swatinem/rust-cache` v2.9.1's SHA upgraded to the official release commit (including the hash-computation regression fix), 12 sites across ci.yml + release.yml synced.
  - `codecov/codecov-action` v4.6.0 → v7.0.0.
  - `taiki-e/install-action`'s SHA unified to `d5b1c57492c40991d5b03b58d85d06c3626b7542` (cargo-deadlinks / cargo-llvm-cov / protoc sharing one commit), with all 14 call sites explicitly passing `with: tool: <name>` instead of relying on the SHA's `action.yml` defaults (the default changes dynamically per tool release — one root cause of the CI failures, see the Fixed section below).
  - `peaceiris/actions-mdbook` v2's SHA upgraded.
  - `actions/upload-pages-artifact` v3 → v5.0.0, adding the `include-hidden-files: true` parameter to keep `.nojekyll` (avoiding GitHub Pages running Jekyll and breaking static assets).
- **The coverage job's cache key made independent**: from `ci-full-deps` to `ci-coverage-deps`, preventing cargo-llvm-cov's instrumentation artifacts from polluting other jobs' caches.

### Fixed

- **A typo in codeql.yml's SHA**: the previous session's SHA pin was written as 38 characters (`fb4bfd79bfa826ce96c907ff8833835ba8aad0`, missing `27`), making the CodeQL workflow fail within 5 seconds (`Unable to resolve action ... unable to find version`). The correct 40-char SHA verified via `gh api repos/github/codeql-action/git/refs/tags/v3 -q '.object.sha'` is `fb4bfd79bfa826ce96c90727ff8833835ba8aad0`; 3 sites corrected. Lesson: after SHA-pinning, verify the length = 40.
- **ci.yml's coverage job installed the wrong tool**: the root cause was `taiki-e/install-action`'s `tool` parameter default changing with the SHA — v0.7.3's SHA `ea361d59...` had the `action.yml` default `cargo-llvm-cov` (which installed correctly), while HEAD's SHA `d5b1c574...` defaults to `protoc`, so the cargo-llvm-cov step actually installed protoc and CI reported `error: no such command: llvm-cov`. Fix: all 14 install-action calls across ci.yml + release.yml explicitly pass `with: tool: <name>`, no longer relying on SHA defaults, eliminating the risk of future SHA upgrades silently changing tool installation.
- **The README version badge's owner error**: `README.md` / `README_EN.md`'s version badge URL owner was written lowercase `kirky/garrison` (the actual GitHub owner is `Kirky-X`), and shields.io returned `version: repo not found`. Corrected to `Kirky-X/garrison`, and the badge now displays `version: v0.7.3` correctly.
- **A bug in release.yml's CHANGELOG body-extraction awk script**: the `version-consistency` job's "Extract CHANGELOG body" step failed (`CHANGELOG.md 中未提取到 ## [0.7.3] 章节内容`), failing the whole v0.7.3 release workflow chain. Root cause: the awk script's `$0 ~ "^" ver " "` uses regex matching, but the `[0.7.3]` in `ver="## \[0.7.3\]"` is interpreted by awk's regex as a **character class** (matching any of `0`/`.`/`7`/`3`), not the literal `[0.7.3]`, so the `## [0.7.3] - 2026-07-22` line never matched. Fix: `index($0, ver " ") == 1` string lookup replaces regex matching, matching the literal brackets correctly. Locally verified to extract the `### Added` section content.
- **A bug in release.yml's publish order**: the `publish-crates-io` job ran only `cargo publish` (the main crate), but garrison depends on `garrison-macros = "0.7"` (optional) while crates.io only had `garrison-macros = "0.5.1"`, so publishing garrison failed on unresolvable version constraints. Fix: `cargo publish --package garrison-macros` first, wait 15s for index propagation, then `cargo publish --package garrison`, following the workspace dependency order.
- **A bug in release.yml verify-release's curl User-Agent**: the `verify-release` job's "Verify crates.io publish" step queried the crates.io API with `curl -sS "https://crates.io/api/v1/crates/garrison"`, and all 6 retries returned empty responses, so verify-release misjudged the release as failed. Root cause: crates.io's anti-crawler policy rejects User-Agents containing "curl" (curl's default UA = `curl/x.x.x`). Fix: the curl command adds `-H "User-Agent: garrison-release-verify"`. Locally verified to return `"newest_version":"0.7.3"` after the fix. Note: the crate had actually published successfully — the bug affected only the verification script, not the release itself.
- **Fabricated contact information cleaned up**: a full scan found 3 fabricated/incorrect items and fixed them: (1) `docs/SECURITY.md:45`'s security contact email `security@kirky.org` was fabricated, corrected to the user-confirmed `Kirky-X@outlook.com`; (2) `mdbook/book.toml:12-13`'s repository URL owner was written `garrison-rs/garrison` (all other files use `Kirky-X/garrison`), corrected to `Kirky-X/garrison`; (3) `README.md`/`README_EN.md`'s test badge `tests-3852+ passed` was stale (a 0.7.2-era figure), updated to `tests-4116+ passed` (4116 actual tests at the 0.7.3 release = 4051 lib + 65 E2E).
- **`.env.example` inconsistent with the code defaults**: the 0.7.2 README default fix missed `.env.example`, leaving 3 inconsistencies: `GARRISON_TOKEN_NAME=garrison-token` (the code default is `garrison_token`, hyphen→underscore), `GARRISON_TOKEN_STYLE=random-64` (the code default is `uuid`, and `random-64` should be `random_64`), and `GARRISON_IS_SHARE=true` (the code default is `false`). All aligned to the code defaults.
- **`.env.example` missing auth_server's required environment variables**: `src/bin/auth_server.rs` hard-depends at startup on `GARRISON_INTERNAL_API_KEY` (fail-closed, `process::exit(1)` when unset), plus the optional `GARRISON_EXTERNAL_PORT`/`GARRISON_INTERNAL_PORT`/`GARRISON_RATE_LIMIT`, none documented in `.env.example`. The auth_server configuration section + the web-security configuration section (`GARRISON_CORS_ALLOWED_ORIGINS`/`GARRISON_CSRF_ENABLED`/`GARRISON_RATE_LIMIT_BACKEND`, with feature-gate comments) are added.
- **The pre-release review fixes (the v0.8.0 release gate: security SAST + code review)**:
  - **MEDIUM-1 lost-revoke (`protocol-apikey`)**: `maybe_touch_last_used` used to overwrite-write with the stale `info` JSON captured when `verify` entered, so a concurrent `revoke` could flip `revoked=true` back to false (a revoked key resurrecting — a core authentication-semantics defect). It now **re-reads the latest value** before writing back and abandons the update if `revoked`; the regression test `maybe_touch_does_not_resurrect_revoked_key` added. The residual micro-race window (`GarrisonDao` has no CAS/field-level update — an architectural ceiling) is converged by the 60s throttle + revoke priority; the doc comment records the trade-off.
  - **LOW-1 constant-time comparison unification**: deleted `protocol-apikey`'s local `constant_time_eq` copy; `decode_and_check` uses the public `crate::secure::ct_eq::constant_time_eq`; the `protocol-apikey` feature changed from `dep:subtle` to `secure-ct-eq` (eliminating the third duplicate implementation, rule 7).
  - **LOW-3 `sha256_hex` allocation**: the `format!` per-byte String allocation changed to `write!` into a preallocated buffer.
  - **LOW-4 `update_last_used` symmetry**: consistent with `verify`, returning `InvalidToken`/`ExpiredToken` for revoked/expired keys without writing the usage time; the regression test `update_last_used_rejects_revoked_key` added.
  - **LOW-5 `rotate` concurrency**: the doc comment notes `rotate` is not atomic (verify→revoke→generate across awaits); callers should add a distributed lock at the entrance — the library embeds no lock (a low-frequency management operation).
  - **LOW-2 `three_tier.rs` test numbering**: the backfill group's T51/T52 doc numbers duplicated the singleflight group's; changed to T55/T56.
  - **LOW-6 the `007` migration comment**: the sqlite/postgres/mysql dialects' header comments used to claim "003 already contains the fields, skip this migration", contradicting reality (003 lacks the OAuth2 fields); corrected to "both new and existing installations must run 007".
  - **LOW-7 audit length-first**: confirmed that `verify_signature_chain` early-falsifying non-64-char signatures is the reasonable CWE-400 (CPU DoS) vs CWE-208 (timing) trade-off; the comments suffice, logic unchanged.

### Docs

- README.md/README_EN.md's language-switch links moved from badges to plain text (`中文 | English`), so a badge load failure cannot block switching.
- README.md/README_EN.md's license badge moved from the static `shields.io/badge/license-Apache--2.0-green` to the dynamic `shields.io/github/license/Kirky-X/garrison`, reading the license type and color from the LICENSE file automatically (rule 26: dynamic preferred).

## [0.7.3] - 2026-07-22

### Added

- The new `#[check_disable]` proc macro (garrison-macros R-anno-006) — wrapping the `GarrisonUtil::check_disable()` / `check_disable_sync()` calls; annotated on axum handlers it automatically verifies whether the account is disabled. Typical scenario: before sensitive operations, check whether a violating account has been disabled by an administrator.
- The new `GarrisonUtil::check_disable_sync()` synchronous version — supporting blocking calls on the `#[check_disable]` macro's sync-fn path, consistent with the `check_safe_sync()` pattern (`block_in_place` + `Handle::current().block_on()`).
- The new internal `dao_session!` macro_rules! macro (src/dao/macros.rs) — eliminating the duplicated `pool.get_session("admin") + session.connection() + map_err` boilerplate in the 10 SQLite repositories (7-9 lines per site), migrating 53 call sites and saving about 350 lines net. The macro expands into two `let` statements, with callers supplying the `$session` / `$conn` idents to bypass macro_rules! hygiene constraints.

### Changed

- The garrison-macros version synced from 0.5.1 to 0.7.3 — aligned with the main crate's version number to remove ambiguity.
- The garrison main-crate version 0.7.2 → 0.7.3.
- The `garrison-macros` dependency constraint in garrison's Cargo.toml updated from `"0.5"` to `"0.7"`.

### Docs

- Fixed `src/lib.rs`'s proc-macro annotation module doc drift: the re-exported macro count corrected from "7" to "10", with version notes added for `#[check_mfa]` / `#[check_abac]` / `#[check_disable]`.
- Updated `garrison-macros/src/lib.rs`'s module docs: the macro count 9 → 10, with an "account-disabled state" row added to the coverage matrix.
- Extended `garrison-macros/tests/ui/`'s UI tests: sync_fn_pass.rs and async_fn_pass.rs gained `#[check_mfa]` / `#[check_disable]` / `#[check_abac]` cases, covering all 10 macros.

## [0.7.2] - 2026-07-21

### Fixed

- Fixed the Windows CI test failures: confers 0.4.1's `FileSource` unconditionally rejected `Component::Prefix` (the Windows drive letter `C:`) in `check_path_components()`, making all absolute paths unloadable on Windows. The new `TomlContentSource` (`src/config/source.rs`) bypasses path validation via the public `parse_content` API, achieving consistent cross-platform behavior.
- Split `TomlContentSource` into the standalone `source.rs` module (rule 25's mod/crate interface isolation).

### Security

- `GarrisonConfig::load` gains 7 security protections:
  1. Empty-path rejection (an `is_empty()` check)
  2. Path-traversal detection (rejecting `..` / `Component::ParentDir`)
  3. `File::open + file.metadata()` reusing the fd, eliminating the TOCTOU and symlink-attack windows
  4. An `is_file()` check rejecting special files (character devices like `/dev/zero`, FIFOs, directories)
  5. The file-size limit (a 10MB cap, against DoS)
  6. `take(MAX+1)` enforcing the byte cap at the I/O layer (against TOCTOU)
  7. Error messages containing only `file_name()`, leaking no server filesystem structure
- 6 new security integration tests covering the protections above (`tests.rs::load_rejects_*`).
- gitleaks secret-scanning integration added (`.gitleaks.toml` + the gitleaks hook in `.pre-commit-config.yaml`) — complementing `detect-private-key`, covering git-history scanning.
- The pre-commit `forbid-temp-dir` hook added — blocking temp/ third-party reference sources from entering the repository via `git add -f` bypassing .gitignore.
- The example `examples/src/infrastructure/config_loader.rs` uses the `tempfile` crate instead of `std::env::temp_dir()` fixed paths, eliminating the symlink/preemption attack window.

### Changed

- Synced 4 GitHub Actions workflows' `actions/checkout` v4.2.2 → v7.0.1 (Node.js 24 compatibility) and `Swatinem/rust-cache` v2.7.7 → v2.9.1.
- Corrected the wrong `ConfigLoader` references in `README.md` / `.env.example` / `docs/DEVELOPMENT.md` to the actual APIs `GarrisonConfig::load` / `confers`.
- Corrected the enum default-value casing of `replaced_login_exit_mode` / `overflow_logout_mode` / `audit_mask_mode` in `docs/CONFIGURATION.md` (`OldDevice` → `old_device` etc., consistent with `#[serde(rename_all = "snake_case")]`).
- Corrected `README.md`'s `token_name` (`garrison-token` → `garrison_token`), `token_style` (`random-64` → `random_64`), and `is_share` (`true` → `false`) defaults to match the code.

### Docs

- `README_EN.md` added (511 lines, structurally consistent with the Chinese version) — README.md's top gains the bidirectional language-switch badges.
- The `.security-audit/` directory added to `.gitignore`.

## [0.7.1] - 2026-07-21

### Overview

This is the **strix security-audit fix batch**, integrating fixes for the 21 vulnerabilities found across 3 rounds of strix penetration tests (`garrison_21a6` / `garrison_371b` / `garrison_6704`), covering six dimensions: authentication/authorization (A1–A11), OAuth2/OIDC (B1–B10), web security (C1–C7), cryptography (D1–D6), performance (E1–E4), and supply chain (F1–F4). All 21 vulnerabilities are fixed, with all CRITICALs fixed and passing the Convergence stage's code-doc consistency review.

> ⚠️ **A breaking change**: the crate name renamed from `bulwark` to `garrison`. Projects depending on `bulwark = "0.7.x"` must change Cargo.toml to `garrison = "0.7"` and change `use bulwark::*` in code to `use garrison::*`.

### Security

- **CRITICAL**: the ABAC expression-injection fix (A3, b28ef5c) — `validate_abac_expr()` rejects `true` / policy terminators / empty strings
- **CRITICAL**: the switch_to privilege-escalation + AccountSession auto-creation fix (A6, 43ab79c) — enforcing that the target user exists + caller ownership
- **CRITICAL**: the cross-user session-management unauthorized-access fix (A7, a1d6e8b) — the kickout endpoint enforces caller ownership checks
- **CRITICAL**: the login_with_token session-fixation/hijack fix (A8, 5648f2a) — validating at the entrance that the target token does not exist
- **CRITICAL**: the SimpleTokenStyle forgery fix (A11, 2084933) — HMAC-SHA256 signing + `subtle::ConstantTimeEq` constant-time comparison
- **CRITICAL**: OIDC id_token verification implemented (B1, 4e13b21) — KeycloakProvider JWKS signature verification
- **CRITICAL**: OAuth2 scope validation enforced (B3, c5a325b) — the ScopeHandler registry enforcing registration
- **CRITICAL**: the KeycloakProvider aud/iss validation fix (B9, 4e13b21) — strict audience + issuer dual checks
- **HIGH**: the ABAC engine's `Entities::empty()` fix (A1) — injecting the actual entity data
- **HIGH**: the tenant-isolation `tenant_id=0` fallback fix (A4) — explicitly rejecting requests without a tenant context
- **HIGH**: the renew_to_equivalent renewal-window fix (A9, 954ad49) — the swap ordering eliminating the DoS gap window
- **HIGH**: the device-fingerprint spoofing fix (A10, 81feb09) — `device_fingerprint_rich()` combining UA + IP + Accept-Language
- **HIGH**: CSRF/WAF enabled by default + Origin/Referer validation (C1, 6960b53)
- **HIGH**: the rate-limiter memory-leak + XFF-spoofing fix (C5)
- **HIGH**: the API Key timing side-channel fix (C6)
- **HIGH**: rate limiting on the OAuth2 /token endpoint (B5, 6a5c63b) — by client_id + username dual dimensions
- **HIGH**: timeouts on the reqwest client (E1, 65cc6b6) — the `build_safe_http_client()` helper
- **HIGH**: the reqwest body-size limit (E2, 65cc6b6) — a 4 MiB cap
- **HIGH**: the TOTP lock moved to oxcache's bounded cache (E3, accf1e1) — DashMap → atomic DAO incr
- **HIGH**: the API Key reverse index avoiding full scans (E4, 811ee10) — O(1) verify
- **HIGH**: the `with_dao()` injection point on the OAuth2 rate limiter (a diting HIGH, 844eaef) — production deployments can inject a distributed DAO
- **HIGH**: switch_to cleaning the original Account-Session token entries (H1, 24e1a1e) — preventing `logout_by_login_id` from kicking already-switched sessions beyond its authority
- **HIGH**: SimpleTokenStyle's `\x1f` separator supporting login_ids containing `-` (H2, 235e98b) — email/UUID/kebab-case login_ids no longer fail verify
- **HIGH**: the OIDC id_token `aud` supporting array form (H3, b21478b) — RFC 7519 compatible, supporting Google/Azure AD multi-audience scenarios
- **HIGH**: `OidcClaims.aud`'s type changed from `String` to the `OidcAudience` enum (**a breaking API change**, H3, b21478b) — RFC 7519 compatible; old code must compare with `aud.contains(&self.audience)`

### Added

- The new `secure-simple-token` feature (A11) — SimpleTokenStyle HMAC-SHA256 signing
- The new `validate_abac_expr()` function (A3) — Cedar policy-injection defense
- The new `compose_security_stack()` helper (C4) — the CORS-preflight bypassing WAF/CSRF fix
- The new `cookie_domain` config item (C3) — a CsrfConfig field
- The new `build_safe_http_client()` helper (E1) — unified timeout + body limits
- The new `device_fingerprint_rich()` function (A10) — a multi-dimensional device fingerprint
- `dep:subtle` added to the `secure-sign` feature (D1, b9312f0) — constant-time HMAC verification

### Changed

- The ABAC engine's uninitialized state moved from fail-open to fail-closed (A2)
- SimpleTokenStyle changed from a ZST to `struct { secret: String }`, **a breaking API change**
- `OidcClaims.aud`'s type changed from `String` to the `OidcAudience` enum, **a breaking API change** (old code's `claims.aud == self.audience` must use `claims.aud.contains(&self.audience)`)
- `require_secondary_auth` moved from a soft hint to a hard block (A10)

### Fixed

- The get-session internal endpoint lacked ownership validation (A5, 0d7a8fe)
- The get-token-info internal endpoint lacked ownership validation (A5, 0d7a8fe)
- The OIDC state parameter was unvalidated (B2, 4e13b21)
- The URL encoder missed the % character (B4, 4e13b21)
- An unencoded redirect_uri caused open redirects (B6, 4e13b21)
- The DAO fallback path did not rotate refresh tokens (B7, 4e13b21)
- HTTP Basic Auth was unsupported for transmitting client_secret (B8, 4e13b21)
- JWT did not validate nbf (B10, 1944271)
- The WAF did not check query parameters (C2, 04f8f66) — DangerousCharacter + DirectoryTraversal
- CORS preflight bypassed CSRF/WAF (C4, 72975a5)
- JSON body token injection (C7, 8903cd4) — body token extraction restricted to POST/PUT/PATCH
- The Signer HMAC verify timing side channel (D1, 4476395) — `subtle::ConstantTimeEq`
- HMAC keys lacked HKDF derivation (D2, 1599858)
- HTTP Digest defaulted to MD5 (D3, 0229d3f) — SHA-256 by default
- sanitize_input did not filter Unicode Cf characters (D4, 80d2f08)
- The XSS whitelist did not block `javascript:` URLs (D5, 45a3146)
- The custom mask did not actually mask (D6, a79b5a4)
- Removed the [patch.crates-io] local-path overrides (F1)
- Hard-coded API Keys in examples (F2, 8932f3e) — env vars instead
- Upgraded opentelemetry fixing CVE-2026-48504 (F3, 7037764)
- The SMS verification-code range excludes `000000` (F4, 87c62ba)

### Pre-release fixes for v0.7.1 (2026-07-21)

- **MEDIUM**: fixed vuln-0011 TokenRateLimiter's doc fail-open (544c92f) — the documentation corrected to fail-closed
- **MEDIUM**: fixed vuln-0012 HttpDigestAuth validate_nc's fail-open (544c92f) — all three paths return false + log sampling + the realm parameter
- **HIGH**: fixed the ABAC integration test's handler using pure-literal expressions (c4b9706) — `validate_abac_expr` rejects pure literals; switched to `principal == principal` / `principal != principal`
- **MEDIUM**: fixed `SensitiveDataMasker::mask_value`'s type inconsistency (c4b9706) — `mask_value` / `mask_field` / `mask_json` uniformly return `String`, with a Custom regex compile failure returning `"***"` as the safe fallback (fail-closed, preventing original-value leakage)
- **LOW**: fixed the sqlite repo session/connection phase error-message format inconsistency (b1635ee) — 41 map_err sites moved to kebab-case i18n format
- **LOW**: fixed ci.yml's deadlinks check (b1635ee) — removed continue-on-error, adding a regex filter for internal deadlinks
- **LOW**: fixed test-assertion i18n (f0622aa) — sign_edge_cases' assertions changed from the Chinese "签名" to the English "mismatch"
- **LOW**: fixed auth_server_integration.rs's kickout/switch_to API calls missing the caller_login_id field (f0622aa)

### Review verification (the Convergence stage)

- The code-doc consistency review completed
- tiangang SAST scan: 0 CRITICAL, 1 HIGH (the rsa crate CVE-2023-49092, isolated behind the `social-alipay` feature gate — acceptable)
- The diting architecture+performance review: HIGH #1 (the OAuth2 rate limiter hard-coding MockDao) fixed (844eaef)
- The kueiku bug analysis: 3 HIGHs (H1/H2/H3) fixed (24e1a1e / 235e98b / b21478b)
- Full tests: 2593 passed, 0 failed, 1 ignored
- clippy: zero warnings (`-D warnings`)
- The fix commit range: `811ee10`..`171b7bd` (6 commits)
- Fix dates: 2026-07-18

### The i18n migration completion (the specmark `i18n-hardcoded-to-icu`)

**Trigger**: after FIN1's full retest, 250+ missed hard-coded Chinese strings remained unmigrated, and the user required "all of it internationalized".

**The fixes** (4 commits):

- `4ae8b31` i18n(ftl-mock): completing the `dao-key-not-found` FTL key (11 code references but missing from FTL) + 2 Chinese migrations in `src/stp/mock.rs` + 2 dao-key-not-found in `src/protocol/{sign,apikey}/mock.rs` gaining the `::` suffix
- `c3935a7` i18n(stp-session-parameter): 17 hard-coded Chinese strings in `src/stp/session.rs` migrated to stp-* FTL keys + 2 in `src/stp/parameter.rs` + 4 stp-dao-find-by-id → dao-key-not-found unifications in `src/stp/session.rs` + 1 unknown token_style → stp-unknown-token-style + 5 SimpleTokenStyle feature gates in `src/stp/{tests,token}.rs` + 2 broken assertions fixed
- `93a9c23` fix(session): the `renew_resets_ttl` flaky test fix (TTL 3→5, margin 1→3, total sleep unchanged)
- `1bc963f` fix(i18n): the kueiku-review fixes — 4 stp-token-invalid-or-* in `src/stp/token.rs` missing the `::` suffix + 2 stp-token-not-found in `src/stp/safe.rs` missing the token parameter + 1 parameterized dao-key-not-found in `src/protocol/temp/tests.rs`

**The three-dimension review results**:

- tiangang SAST: 0 CRITICAL + 0 HIGH = ✅ pass
- diting architecture: HIGH-1 (15 stp- keys missing the `::` suffix) + 4 MEDIUMs, all fixed and passing
- diting performance: HIGH-1 (a Box::leak leak, pre-existing, non-blocking) + 3 MEDIUMs (acceptable)
- The kueiku bug analysis: 3 i18n bugs (1 MEDIUM + 2 LOW) all fixed

**Final verification**:

- `cargo test --features "db-sqlite,protocol-jwt,secure-simple-token"`: 1395 passed, 0 failed
- `cargo clippy --features "db-sqlite,protocol-jwt,secure-simple-token" -- -D warnings`: 0 warnings
- zh/en FTL keys 591 each, pairwise consistent (524 before the migration; 67 added this round)
- All 4 commits passing the pre-commit hooks (fmt + clippy×2 + cargo-deny + codespell + markdownlint)

### The strix garrison_e024 security-review fix batch

**Trigger**: 9 vulnerabilities in the strix penetration-test report `strix_runs/garrison_e024/` (4 CRITICAL + 3 HIGH + 2 MEDIUM) + tiangang SAST's 3 MEDIUM + 7 LOW.

**The fixes** (a single batch with parallel subagents):

- **CRITICAL**: SAML signature verification implemented (vuln-0001) — the new `XmlSecSamlProvider` + `verify_saml_signature()`, an RSA-SHA256 / ECDSA-SHA256 algorithm allowlist rejecting `rsa-1_5`, and the new `secure-saml` feature (`rsa` + `dep:base64`)
- **CRITICAL**: SAML Destination/Audience validation added (vuln-0002) — the `expected_destination` / `expected_audience` builders + fail-loud validation, with `build_authn_request` gaining the `idp_sso_endpoint` parameter
- **CRITICAL**: the Credential Repository IDOR fix (vuln-0004) — `find_by_user` / `update` / `delete` gain the `caller_login_id` parameter + ownership validation + the user_id immutability constraint + a `tracing::warn!` audit log
- **HIGH**: the SAML assertion-replay TOCTOU fix (vuln-0003) — `check_assertion_replay` moved to the atomic `dao.get_and_delete`
- **HIGH**: the temp-credential consume TOCTOU fix (vuln-0005) — `consume` moved to the atomic `dao.get_and_delete`
- **HIGH**: the rate-limit sliding-window TOCTOU fix (vuln-0009) — preferring the atomic `dao.eval_lua` Redis Lua script path, falling back to an `atomic_lock` guarding read-modify-write (in-process atomicity only; the cross-process limitation documented)
- **MEDIUM**: `compare_and_update_if_greater`'s `unwrap_or(0)` changed to an explicit error (violating rule 12) — the oxcache / MockDao implementations updated in sync
- **MEDIUM**: `compare_and_update_if_greater`'s trait default implementation changed to return `NotImplemented` (forcing backends to override with an atomic CAS) — `AloneCache` adds a forward to the inner DAO
- **MEDIUM**: the `fallback_counter` gains the capacity limit `MAX_FALLBACK_ENTRIES=10000` + LRU eviction (`FALLBACK_EVICT_BATCH=100`) — against unbounded growth during DAO failures
- **LOW**: `constant_time_eq` moved to `subtle::ConstantTimeEq` (eliminating the length leak)
- **LOW**: `verify_id_token`'s nonce comparison moved to `subtle::ConstantTimeEq`
- **LOW**: the `check_and_incr_fallback` window-boundary documentation (the DashMap shard lock makes it safe in practice)
- **LOW**: the `entry_count` O(n) traversal documented + the MAX cap protection
- **LOW**: `validate_inner` gains the `MAX_AUTHORIZATION_HEADER_LEN=8KB` input-length validation (DoS protection)
- **LOW**: `verify_id_token`'s error messages leak no token claim information
- **LOW**: `MockDao::keys`' O(n) complexity documented

**The three-dimension review results**:

- tiangang SAST: 0 CRITICAL + 0 HIGH = ✅ pass
- diting architecture: 3 CRITICALs (false positives) + 1 HIGH (false positive) + 1 MEDIUM + 1 LOW — the false positives came from the review not recognizing that all callers had been updated
- diting performance: 3 HIGHs (false positives) + 3 MEDIUMs + 2 LOWs — the false positives came from evict_oldest triggering only at the capacity cap (amortized cost)

**Final verification**:

- `cargo test --features "full" --lib`: 3756 passed, 0 failed, 5 ignored (34 new tests over the 3722 baseline)
- `cargo clippy --features "full" --lib --tests -- -D warnings`: 0 warnings
- 27 files changed (5 new, 22 existing)

### The strix garrison_0792 security-review fix batch

**Trigger**: 3 vulnerabilities in the strix penetration-test report `strix_runs/garrison_0792/` (1 HIGH + 2 MEDIUM).

**The fixes**:

- **HIGH (vuln-0011, CVSS 6.5, DOC)**: `oauth2_server::TokenRateLimiter`'s doc erroneously said "Fail-Open" (the actual behavior is fail-closed, provided by vuln-0007's fallback_counter) — the doc corrected to "Fail-Closed", removing the doc-behavior mismatch
- **MEDIUM (vuln-0012, CVSS 6.5, CODE)**: `secure::httpdigest::HttpDigestAuth::validate_nc` was fail-open on the DAO-error / no-tokio-runtime / current-thread-runtime three paths (returning true, permitting replay), violating RFC 7616 §3.4.6 — all three now fail closed (returning false and rejecting); the no-runtime fail-closed test case added; application log sampling (`DAO_ERROR_LOG_INTERVAL=100`) prevents log floods during sustained DAO failures; the docs add the dao=None path's security cost, worker-pool capacity planning, and ops P1 alerting notes
- **vuln-0001 (FALSE POSITIVE)**: strix reported `JwtHandler::with_algorithm` accepting `Algorithm::None` enabling signature bypass — on inspection, `jsonwebtoken 10.0.0`'s `Algorithm` enum has no `None` variant (only HS256/HS384/HS512/ES256/ES384/RS256/RS384/RS512/PS256/PS384/PS512/EdDSA); no fix needed

**The architecture fixes** (found by rule 26's three-dimension review):

- HIGH-1: strix's numbering vuln-0002/vuln-0003 clashed with the existing SAML vuln-0002/vuln-0003 — strix's findings renumbered to vuln-0011/vuln-0012
- MEDIUM-arch: removed `oauth2_server::token::PasswordRateLimiter::check/record_failure`'s doc cross-layer coupling references to `HttpDigestAuth::validate_nc` (the whole "fail policy explanation" paragraph) — each module describes only its own behavior
- MEDIUM-arch: removed mod.rs's implementation-detail docs of the `dao` field (key formats, TTL policies), pointing to `auth::validate_nc`'s docs instead (rule 25 interface isolation)
- MEDIUM-perf: DAO error-log sampling (one warn per 100, the rest demoted to debug)
- LOW-arch: clarifying the dao=None path's security cost (replayable within the 300s window) + capacity planning + ops notes
- LOW-sec: the no-runtime fail-closed test case added

**The three-dimension review results**:

- tiangang SAST: 0 CRITICAL + 0 HIGH = ✅ pass
- diting architecture: HIGH-1 (the vuln numbering clash) + 2 MEDIUMs (cross-layer coupling + interface-layer leakage) + 1 LOW, all fixed and passing
- diting performance: 1 MEDIUM (the log flood) fixed
- The kueiku bug analysis: no new bugs

**Final verification**:

- `cargo test --features "secure-httpdigest oauth2-server"`: all tests passing
- `cargo clippy --features "secure-httpdigest oauth2-server" -- -D warnings`: 0 warnings

### Changed (0.7.x - the cargo feature partitioning optimization)

This is the **cargo feature partitioning optimization (conservative, 0.7.x-compatible)**, implemented per the kueiku decision analysis (option B: layered refactoring + progressive migration). No breaking changes; backward compatible within 0.7.x.

#### Added

- The new base `i18n` feature (an empty stub) — an API-semantics placeholder allowing users to declare `features = ["i18n"]` in Cargo.toml to express "base internationalization enabled" semantics. The base layer (translate_error / the loc! macro / FTL file loading) compiles unconditionally, so this feature changes no compilation behavior.
- `i18n-icu` now depends on `i18n` explicitly (`i18n-icu = ["i18n", ...]`), forming a clear "base layer + enhancement layer" dependency.

#### Deprecated

- The `all-defaults` aggregate marked DEPRECATED — fully duplicating the `development` aggregate (both = `["cache-memory", "db-sqlite", "web-axum"]`). Deleted in 0.8.0; use `development`.

#### Documented

- The review confirmed that `protocol-apikey` / `protocol-temp` / `secure-xss` / `secure-sanitize` all carry real `#[cfg(feature = "...")]` gates (e.g. `src/protocol/mod.rs:32,36` / `src/secure/mod.rs:108,124`) — **not placeholder features**; enabling them compiles the corresponding modules. The draft had mislabeled them PLACEHOLDER; corrected back to normal feature comments.
- The `i18n` feature's annotation corrected to "enabling it compiles the i18n-related test code" (8 `#[cfg(feature = "i18n")]` test gates in src, unrelated to runtime behavior).

### The 0.8.0 rename-plan preview (breaking changes)

0.8.0 would re-partition the cargo features (option B's layered refactor), with these breaking changes (the old names kept as aliases until 0.9.0):

| 0.7.x old name            | 0.8.0 new name                  | Rationale                                      |
| ------------------------- | ------------------------------- | ---------------------------------------------- |
| `rate-limit-redis`        | `firewall-ratelimit-redis`      | Depends on firewall-ratelimit; unify the namespace |
| `anomalous-detector-dual` | `firewall-anomalous-detector`   | Depends on firewall; unify the namespace       |
| `secure-simple-token`     | `auth-server-simple-token`      | auth-server-specific; not in the secure-* namespace |
| `oauth2-scope-handler`    | `protocol-oauth2-scope-handler` | Unify the protocol-* namespace                 |
| `audit-log`               | `audit-log-listener`            | Distinguish from `audit-inklog` (event listening vs log management) |
| `all-defaults`            | (deleted)                       | Duplicates `development`                       |
| `firewall-maxminddb`      | (merged into `firewall-geoip`)  | The former is only the latter's production backend |

Details in `docs/decisions/A-011-cargo-feature-reorganization.md` (to be created in 0.8.0).

### Fixed (the 0.7.1 CI/CD fix batch)

**Trigger**: the v0.7.1 prerelease CI failed wholesale — root causes spanning cargo-audit/cargo-deny config drift, a rustc 1.85.1 compiler bug, and the sdforge `#[forge]` macro's cfg-context mismatch.

**The fixes** (6 commits):

- `d5759d9`..`b4d8ada` — ci.yml's workflow rebuilt: restoring the full CI pipeline + fixing the missing protoc / the cargo-deny-action SHA pin / cargo-audit's removed `--ignore-source` argument / `--test '*'` switched to `--tests` avoiding required-features errors
- `02a419b` — the redundant audit job deleted (cargo-deny already covers advisory checks) + deny.toml adds RUSTSEC-2026-0173 (proc-macro-error2 unmaintained) + Unicode-DFS-2016 removed (superseded by Unicode-3.0) + sdforge_routes.rs gets `#![allow(dead_code)]` suppressing the dead-code warnings of inventory-registered routes when compiling the lib
- `f26c707` — Token::generate switched to the UFCS full-path call, bypassing rustc 1.85.1's unused-import false positive on `use Trait as _` (fixed in 1.96.0)
- `6e1ba9a` — **CRITICAL**: fixing the sdforge `#[forge]` route registration failing: the `inventory::submit!(RouteRegistration::new(...))` generated by `#[forge]` was guarded by `#[cfg(feature = "http")]`, and that cfg evaluates in garrison's context (not sdforge's). garrison lacked the `http` feature → the submit calls were cfg-stripped → `sdforge::http::build()` collected no routes → all 29 sdforge_routes tests HTTP 404 (production code affected too). Fix: the `http = []` bridge feature added to `[features]` (a cfg flag only), with `auth-server-sdforge = ["http"]`. sdforge/http is already enabled unconditionally by the dependency declaration — this feature is only garrison's cfg switch.

**Final verification**:

- `cargo test --features full --lib`: 3787 passed, 0 failed, 5 ignored (previously 3755 passed / 32 failed)
- `RUSTFLAGS="-D warnings" cargo clippy --features full --lib --tests`: 0 warnings
- `cargo fmt --check`: clean
- `cargo deny check`: advisories ok, bans ok, licenses ok, sources ok
- `cargo check --no-default-features --features default`: passing (no sdforge dependency regression)

## [0.7.0] - 2026-07-17

### Overview

v0.7.0: the microservice architecture + ABAC/Cedar + the OAuth2 Server + dependency optimization + architecture hardening. Managed via the specmark change `v0.7.0-microservice-abac-oauth2-hardening`, with 252 TDD tasks across 7 capability domains. tiangang SAST 0 CRITICAL; diting 88/100 (0 CRITICAL + 0 HIGH); 2968 tests passing, meeting the release gates.

### Added

#### D1: Architecture hardening

- Unified error types: `GarrisonError` / `GarrisonResult` across the codebase, 0 violations
- mod.rs hardening: mock code moved to standalone `mock.rs` files; impl blocks moved to `impl.rs` / `*_impl.rs`
- The `secure-sanitize` feature: the general input-sanitization `sanitize_input()` function (null-byte / control-character removal + length limits)

#### D2: Dependency optimization

- clippy zero warnings (all modes + feature combinations)
- cargo doc zero warnings
- Feature-combination tests: all 10 combinations passing

#### D3: The microservice architecture

- The `backend-remote` feature: the remote backend adapter (HTTP API calls)
- The `backend-embedded` feature: the embedded backend mode (enabled by default)
- The `backend-kit` feature: trait-kit typestate DI construction
- `src/server/server_impl.rs` + `src/server/config.rs` + `src/server/middleware.rs` + `src/server/oauth2_routes.rs` + `src/server/sdforge_routes.rs`: the authentication-server routes and middleware
- `src/bin/auth_server.rs`: the standalone authentication-server binary
- The `GarrisonAuthServer::with_tenant_resolver` builder: injecting a `TenantResolver`, enabling `tenant_resolution_middleware` (gated by `tenant-isolation`)

#### D4: ABAC/Cedar DSL

- The `abac` feature: the Cedar DSL-based attribute access control engine
- `src/abac/engine.rs`: the ABAC engine core
- `src/abac/policy.rs`: policy parsing and evaluation

#### D5: The OAuth2 Server

- The `oauth2-server` feature: the full OAuth2 Server implementation
- `/oauth2/authorize`: the authorization-code flow + PKCE enforced (S256)
- `/oauth2/token`: the 4 grant types (authorization_code / refresh_token / client_credentials / password)
- `/oauth2/revoke`: RFC 7009 token revocation
- `/oauth2/introspect`: RFC 7662 token introspection
- The redirect_uri allowlist exact match + the state-parameter CSRF protection
- The `register_oauth2_client` helper: an e2e test helper wrapping the tenant context + `OAuth2ClientStore::create` (simplifying test-case client registration)

#### D7: Security review

- tiangang SAST: 0 CRITICAL (Semgrep's 331 rules + cargo-audit)
- The diting code review: 0 real HIGHs (an 88/100 score)
- All 10 dimensions of security.md's security checks passing
- Input sanitization `sanitize_input()` + the 4KB response-body limit + zeroizing sensitive data

### Optimized

#### D2: Dependency optimization

- clippy zero warnings (all modes + feature combinations)
- cargo doc zero warnings
- Feature-combination tests: all 10 combinations passing
- cargo-audit: the rsa Marvin Attack explicitly ignored (signing use only, never decryption)

#### D6: Quality improvements

- Feature-combination tests: the backend-embedded / backend-remote / auth-server / abac / oauth2-server combinations etc.
- clippy + doc warning cleanup
- 2968 tests passing (lib + examples + integration + doc-tests)

### Fixed

- 6 SessionData initializations missing the `dynamic_active_timeout` / `is_anon` fields
- The examples' dbnexus 0.3→0.4 upgrade + the dbnexus/sqlite feature passthrough
- The examples' oxcache/redis feature passthrough
- 11 clippy bool_assert_comparison warnings (a rust 1.96.0 new rule)
- `test_check_safe_default_returns_true` → `false` (the safe-auth feature's behavior change)
- GitHub Actions mutable-tag fixes (docs.yml SHA-pinned + codeql.yml nosemgrep)

## [0.6.7] - 2026-07-13

### Overview

v0.6.7's security and performance enhancements implement 5 capability domains: the forbid-priority semantics, the WAF-grade firewall, the three-tier cache architecture, progressive SMS-code rate limiting, and the AnomalousLoginDetector dual engine. Managed via the specmark change `v0.6.7-waf-safe-defaults-cache-sms-anomalous`, with 31 TDD tasks + audit fixes + consistency fixes. The consistency check scored 91% (29/31 requirements correctly implemented), fixing 3 inconsistencies (D3-1 logout cache-invalidation integration + D5-1 interval validation + D5-3 spec sync). diting's final audit scored 88 (0 CRITICAL + 0 HIGH) and tiangang SAST 0 CRITICAL, meeting the release gates.

### Added

#### D1: The forbid-priority semantics (the `safe-defaults` feature)

- `DecisionCombinator::combine` returns `Deny(NoMatchingPermission)` on an empty decision list (fail-closed)
- `GarrisonPermissionStrategyDefault` returns `Deny` rather than `Allow` when `check_permission` / `check_role` finds no record
- Secure-default semantics: resources not explicitly authorized are denied by default

#### D2: The WAF-grade firewall (the `firewall-waf` feature)

- The new `src/strategy/firewall/waf.rs` module: `WafEngine` + `WafContext` + `WafVerdict`
- The new `src/strategy/firewall/waf_hooks.rs` module: 9 WAF hooks
  - `WhitePathHook` / `BlackPathHook`: path allowlists/blocklists
  - `HostHook`: the Host header allowlist
  - `HttpMethodHook`: the HTTP method allowlist
  - `ParameterHook`: the parameter-name blocklist
  - `BannedCharacterHook` / `DangerCharacterHook`: dangerous-character detection
  - `DirectoryTraversalHook`: path-traversal detection (`../`, `./`, `//`, `%2e`, `%2f`, `%00`)
  - `HeaderHook`: request-header blocklist detection
- `WafEngine::evaluate` executes in hook registration order, with `AllowAndSkip` short-circuiting
- Audit fixes: WhitePathHook's percent-encoding fallback + BlackPathHook's prefix-confusion protection

#### D3: The three-tier cache architecture (the `three-tier-cache` feature)

- The new `src/cache/three_tier.rs` module: `UserCacheService`
- The L1 (oxcache memory cache) → L2 (the DAO persistent cache) → L3 (the interface callback) three-tier progressive lookup
- The `get_permissions` / `get_roles` / `get_user` three-tier cache methods
- `invalidate(login_id)` invalidating all of a user's caches (L1 + L2)
- `GarrisonConfig` gains `l1_cache_ttl_secs` (default 30) / `l2_cache_ttl_secs` (default 300) / `l1_cache_capacity` (default 10000)
- `GarrisonLogicDefault` gains the `user_cache_service` field + the `with_user_cache_service` builder
- `logout` / `logout_by_login_id` call `invalidate` to invalidate the user's caches when the `three-tier-cache` feature is enabled
- `GarrisonManager::init` constructs `UserCacheService` automatically and injects it

#### D4: Progressive SMS-code rate limiting (the `sms-rate-limit` feature)

- The new `src/secure/sms/mod.rs` module: `SmsCodeService` + `SmsRateLimiter`
- Dual-window rate limiting: a minute window (default 1) + an hour window (default 5)
- Progressive backoff: after exceeding the limit, the lockout duration escalates (30s → 60s → 300s → 1800s)
- Channel recycling: a channel is recycled after unverified codes exceed the threshold (default 3)
- `GarrisonDao::incr` atomically increments counters (`GarrisonDaoOxcache` rewritten with `atomic_lock`)
- Verification codes use `OsRng` cryptographically secure randomness
- Audit fixes: decrement_counter fault tolerance + phone validation hardening

#### D5: The AnomalousLoginDetector dual engine (the `anomalous-detector-dual` feature)

- The new `src/strategy/firewall/anomalous_analyzer.rs` module: `AnomalousLoginAnalyzer`
- The scheduled analysis engine: `tokio::spawn` + `tokio::time::interval` + a shutdown watch channel
- Three anomaly detections:
  - burst login detection (logins within a 1-hour window > `burst_threshold`)
  - geo-jump detection (different geos > 2)
  - device-fingerprint mutation detection (different devices > 3)
- `AnomalousLoginRecord` login-record persistence (TTL 24h; nanosecond-precision keys avoid same-second overwrites)
- The `GarrisonEvent::AnomalousLoginDetected` event variant + audit.rs recording
- `GarrisonDaoOxcache` gains `key_index: RwLock<HashSet<String>>` implementing `keys()` (oxcache 0.3.3 has no native iter API)
- `GarrisonConfig` gains `anomalous_analyzer_interval_secs` (default 3600) / `anomalous_analyzer_burst_threshold` (default 5)
- The `MAX_SCAN = 10000` DoS protection + an alert when a scan takes > 1s
- Audit fixes: the keys() implementation + scan monitoring + the nanosecond keys

### Fixed

- Consistency-check fixes:
  - D3-1 (P0): `logout` / `logout_by_login_id` integrate `UserCacheService::invalidate()` (R-three-tier-cache-005)
  - D5-1 (P1): `anomalous_analyzer_interval_secs` validation changed from `== 0` to `< 60` (aligned with spec R-007)
  - D5-3 (P2): spec R-001's storage-key description updated to nanosecond precision
- `audit.rs` handles the `AnomalousLoginDetected` event variant (a `_` wildcard + `#[cfg] if let` coverage)
- The listener block's `login_id` changed from move to `as_ref()`, avoiding a full-feature compile error
- The examples' `sso_server.rs` subscribe signature `Fn(&str)` → `Fn(String)`, aligned with the trait definition

### Tests

- `cargo test --features full --lib` → 2404 passed, 0 failed
- 6 new tests: 3 three-tier-cache integration tests + 3 config validate tests
- 27 new anomalous_analyzer tests

### Audits

- diting's final audit: 88/100 (0 CRITICAL + 0 HIGH), meeting the release gates
- tiangang SAST: 0 CRITICAL, meeting rule 19's release gate
- kueiku's FMEA cross-phase analysis: 12 failure modes identified, with the WAF case-sensitivity issue recorded as v0.6.8 tech debt

## [0.6.6] - 2026-07-12

### Overview

v0.6.6's session-management enhancements implement 6 capability domains: finer concurrent-login policies, reading the token from the request body, dynamic Active-Timeout, the login_token_map's two-layer persistence, anonymous sessions, and session search. Managed via the specmark change `v0.6.6-concurrent-login-session-search-anon-rotation`, with 33 TDD tasks + audit fixes. Audit 2 HIGHs (the persistent methods missing locks + last_active_at not updated) + audit 2 HIGHs (anonymous-token routing + the TOCTOU race) + audit 2 HIGHs (DoS protection + deserialization tolerance) — all fixed.

### Added

#### D1: Finer concurrent-login policies

- The `ReplacedLoginExitMode` enum (`OldDevice`/`NewDevice`): controlling behavior on new-device login when `is_concurrent=false`
- The `OverflowLogoutMode` enum (`Logout`/`Kickout`/`Replaced`): the policy when `max_login_count` is exceeded
- `GarrisonConfig` gains `replaced_login_exit_mode` (default `OldDevice`) + `overflow_logout_mode` (default `Logout`)
- Environment overrides `GARRISON_REPLACED_LOGIN_EXIT_MODE` / `GARRISON_OVERFLOW_LOGOUT_MODE`

#### D2: Reading the token from the request body

- `GarrisonConfig` gains the `is_read_body: bool` field (default false, backward compatible)
- The environment override `GARRISON_IS_READ_BODY`
- The three adapters' (axum/actix/warp) `extract_token` methods gain the body-reading branch
- With `Content-Type: application/json`, the token is extracted from the body JSON's `{token_name}` field

#### D3: Dynamic Active-Timeout (the `dynamic-active-timeout` feature)

- `TokenSession` gains the `dynamic_active_timeout: Option<i64>` field (feature-gated + `#[serde(default)]`)
- The `set_active_timeout(token, timeout_secs)` method: per-token custom active timeouts
- `check_active_timeout` prefers `dynamic_active_timeout`, falling back to the global `active_timeout` when `None`

#### D4: The login_token_map's two-layer persistence (the `login-token-map-persistence` feature)

- `GarrisonConfig` gains `login_token_map_persist_interval_secs: u64` (default 0 = synchronous writes)
- The `rebuild_login_token_map()` method: rebuilding the in-memory DashMap from the DAO (restart recovery)
- `add_login_token_persistent` / `remove_login_token_persistent`: dual writes to DAO + memory
- `create` / `logout` already implement the dual write (the DAO AccountSession.tokens + the in-memory DashMap)
- Audit fixes: the persistent methods wrapped with `with_login_lock` + updating `last_active_at`

#### D5: Anonymous sessions (the `anonymous-session` feature)

- The new `src/session/anon.rs` module
- `get_anon_token_session(token)`: getting or creating an anonymous session (`login_id=""`, `is_anon=true`)
- `is_anon(token)`: whether a token is an anonymous session
- `logout_anon(token)`: logging out an anonymous session (idempotent)
- Key-space isolation: `token:session:anon:{token}` vs login sessions' `token:session:{token}`
- `TokenSession` gains the `is_anon: bool` field (feature-gated + `#[serde(default)]`)
- `GarrisonConfig` gains `anon_session_timeout: u64` (default 1800 = 30 minutes)
- `logout`'s entrance detects anonymous tokens and routes to `logout_anon`
- Audit fixes: `get_anon_token_session` wrapped with `with_token_session_lock` + input validation

#### D6: Session search (the `session-search` feature)

- The new `src/session/search.rs` module
- The `SearchSortType` enum (`CreatedAsc`/`CreatedDesc`/`LastActiveAsc`/`LastActiveDesc`)
- `search_token_value(keyword, start, size, sort_type)`: searching Token-Sessions by token value
- `search_session_id(keyword, start, size, sort_type)`: searching Account-Sessions by login_id
- `search_token_session_id(keyword, start, size, sort_type)`: searching tokens by TokenSession.login_id
- Paging (start/size) and sorting supported, excluding anonymous sessions
- Audit fixes: the MAX_SCAN cap against DoS + deserialization-tolerance skipping + input validation

### Audit records

- **Audit 1** (diting 92/100 Approved)
- **Audit 2** (HIGH fixed: body-read security)
- **Audit 3** (diting 71/100 Approved with Changes)
- **Audit 4** (diting 85/100; the persistent methods missing locks + last_active_at not updated — fixed)
- **Audit 5** (diting 85/100; anonymous-token routing + the TOCTOU race — fixed)
- **Audit 6** (diting 66→passing after fixes; DoS protection + deserialization tolerance — fixed)

## [0.6.5] - 2026-07-12

### Overview

v0.6.5: security alerting + device binding + the ban ledger + second-factor auth + token cleanup, implementing 5 capability domains: the security-alerting system, device-binding policies, the ban-ledger implementation, second-factor transient markers, and login_token_map auto-cleanup. Managed via the specmark change `v0.6.5-security-alert-device-binding-disable-safe-auth-cleanup`, with 30 original tasks + the M-002 convergence fix. Audits found 2 HIGHs (service parameter validation + token leakage) + 3 MEDIUMs, all fixed.

### Added

#### D1: The security-alerting system (the `security-alert` feature)

- The new `src/strategy/alert/mod.rs` defining the `SecurityAlertEvent` enum (AnomalyLogin/NewDeviceLogin/DisableTriggered/PrivilegeEscalation/SensitiveOperation) + the `AnomalyType` enum (IpChanged/DeviceChanged/GeoJump/RapidSuccessiveLogin)
- The `AlertListener` trait + `AlertListenerManager`: broadcasting alert events; a single listener's failure only warns without interrupting
- The `AnomalyDetector` trait + `IpChangeDetector` (IP-change detection) + `RapidSuccessiveDetector` (rapid-successive-login detection)
- `TracingAlertListener`: recording alerts via tracing::warn!; `AuditAlertListener`: writing audit logs to the DAO
- Integrated into `session.rs`'s login/check_login; detection failures do not interrupt the main flow
- 34 unit tests

#### D2: Device-binding policies (the `device-binding` feature, depending on `security-alert`)

- The new `src/strategy/device_binding/mod.rs` defining the `DeviceBindingPolicy` trait
- 3 policies: `StrictBinding` (new devices trigger MFA), `LooseBinding` (new devices alert without blocking), `Disabled` (off)
- `LoginParams` gains the `require_mfa: bool` field
- Integrated into the login flow: a new device + require_secondary_auth=true sets require_mfa
- `GarrisonConfig` gains `device_binding_mode` (default "disabled")
- 24 unit tests

#### D3: The ban-ledger implementation

- The new `src/account/disable/mod.rs` + `repository.rs`, defining the `DisableEntry` struct + the `DisableRepository` trait
- `DefaultDisableRepository`: `disable`/`untie_disable`/`is_disable`/`get_disable_time`/`get_disable_level`
- Tiered bans: the `level` field supports graded blocking (level=0 normal; level=1/2/3 graded)
- The key format `disable:{service}:{login_id}`, with permanent bans duration_secs=0
- `MfaLogic::check_disable()`'s default implementation: querying the ban state from the `DisableRepository`
- `GarrisonManager` registers the `DisableRepository`, with the `disable_repository()` accessor
- 30 unit tests

#### D4: Second-factor transient markers (the `safe-auth` feature)

- `TokenSession` gains the `safe_services: HashMap<String, i64>` field (service → expiry timestamp)
- `GarrisonLogicDefault` inherent methods: `open_safe`/`is_safe`/`close_safe`
- Service-level transient markers: multiple services independent, overwriting updates, duration_secs=0 expiring immediately
- `check_safe()`'s default implementation now calls `is_safe("default")`
- Audit fixes: service empty-value validation + token-prefix masking (`&token[..8]`)
- 19 unit tests

#### D5: login_token_map auto-cleanup

- `GarrisonSession::cleanup_expired_tokens()`: scanning the login_token_map, removing expired/revoked tokens
- The DashMap strategy: collect a keys snapshot first, then check each, with retain keeping concurrently added tokens
- `spawn_cleanup_task()`: a tokio::spawn background periodic cleanup; interval_secs<=0 disables
- `GarrisonConfig` gains `token_map_cleanup_interval_secs` (default 300, -1 disabling)
- `GarrisonManager::init` integration: starting the background task, aborted on Drop/reset_for_test
- The audit fix M-002: aborting the old task moved before spawn, eliminating the overlap window
- 20 unit tests

### Reviews and fixes

#### Audit 4 (diting + tiangang)

- **The HIGH-001 fix**: `open_safe`/`is_safe`/`close_safe` did not validate service emptiness → `InvalidParam` validation added
- **The HIGH-002 fix**: error messages exposed the full token → the `&token[..8]` prefix masking (consistent with `core/auth/mod.rs`)
- tiangang SAST: 0 CRITICAL, 0 findings

#### Audit 5 (diting + tiangang)

- **The M-002 fix**: `init_with_factory_selector`'s old and new cleanup tasks briefly overlapped → abort moved before spawn
- M-001/M-003 deferred: adaptive cleanup frequency / cleanup-statistics metrics (non-blocking optimizations)
- tiangang SAST: 0 CRITICAL, 0 HIGH

### Breaking Changes

None. All new capabilities are feature-gated and off by default:

- `security-alert = []`
- `device-binding = ["security-alert"]`
- `safe-auth = []`

All registered in the `full` feature list.

## [0.6.4] - 2026-07-11

### Overview

v0.6.4: web-security middleware + distributed rate limiting, implementing 5 capability domains: WAF request-content validation, the CORS middleware, CSRF protection, automatic response-token writing, and the Redis rate-limit backend. Managed via the specmark change `v0.6.4-waf-cors-csrf-response-token-redis-ratelimit`, with 31 original tasks + 9 converge tasks (40 total). The diting review found 2 HIGHs (missing cookie security configuration) + 1 MEDIUM (silently ignored env vars), all fixed.

### Added

#### D1: WAF request-content validation (the `web-waf` feature)

- The new `src/web/waf.rs` module defining the `WafRule` trait (`async fn check(&self, ctx: &WafContext) -> GarrisonResult<()>`) + the `WafContext` struct
- 5 built-in rules: `DangerousCharacter` (detecting `//`/`\`/`%2e`/`%2f`/`;`/`\0`/`\n`/`\r`), `DirectoryTraversal` (`./`/`../`/`..%2f`/`..%5c`), `PathWhitelist`, `PathBlacklist`, `HttpMethodWhitelist`
- The `garrison_waf_middleware` axum middleware walking the rule chain, returning 400 on any rejection
- `GarrisonConfig` gains `waf_config: WafConfig` (enabled/path_whitelist/path_blacklist/check_dangerous_chars/check_directory_traversal/allowed_methods)
- 33 unit tests

#### D2: The CORS middleware (the `web-cors` feature)

- The new `src/web/cors.rs` module defining `CorsConfig` (allowed_origins/allowed_methods/allowed_headers/exposed_headers/allow_credentials/max_age_secs)
- `garrison_cors_middleware`: preflight (OPTIONS) requests get the `Access-Control-Allow-*` headers injected and return 204; actual requests get `Access-Control-Allow-Origin/Expose-Headers` injected
- `CorsConfig::validate()`: returning Err when `allow_credentials=true` and `allowed_origins` contains `*`
- `GarrisonConfig` gains `cors_config: CorsConfig`
- 29 unit tests

#### D3: CSRF protection (the `web-csrf` feature)

- The new `src/web/csrf.rs` module implementing the Double-Submit Cookie pattern
- `generate_csrf_token()`: 32 bytes of OsRng → URL-safe Base64 (~43 chars)
- `validate_csrf_token(header_token, cookie_token)`: constant-time comparison (no early return; length differences tracked separately)
- `garrison_csrf_middleware`: safe methods (GET/HEAD/OPTIONS) lazily generate the token and set the cookie; protected methods (POST/PUT/PATCH/DELETE) validate header==cookie, returning 403 on mismatch
- `CsrfConfig`: enabled/cookie_name/header_name/excluded_paths/protected_methods/cookie_secure
- `GarrisonConfig` gains `csrf_config: CsrfConfig`
- 25 unit tests

#### D4: Automatic response-token writing

- `src/stp/context.rs` gains `get_renewed_token() -> Option<String>` + `clear_renewed_token()`
- `GarrisonConfig` gains `is_write_cookie: bool` (default false; `is_write_header` already existed)
- The `garrison_middleware` fix: handler execution wrapped in `with_renewed_token_scope` (missed in v0.6.3, leaving the renewal task_local ineffective)
- Renewed tokens are written per `is_write_header`/`is_write_cookie` into the response header (`config.token_name`) or Set-Cookie (`HttpOnly; Path=/; SameSite=<config>; Secure=<config>`)
- 17 unit tests

#### D5: The Redis rate-limit backend (the `rate-limit-redis` feature)

- The new `src/strategy/rate_limiter_backend.rs` defining the `RateLimiterBackend` trait (`try_acquire` / `try_acquire_n`)
- The `RateLimitBackend` enum (Memory / Redis { redis_url })
- `TokenBucketRateLimiter` implements `RateLimiterBackend` (delegating to the existing methods)
- The new `src/strategy/redis_rate_limiter.rs`: `RedisRateLimiter` uses a Lua script's atomic token bucket (HMGET→refill→compare→HMSET→EXPIRE)
- `GarrisonConfig` gains `rate_limit_backend: RateLimitBackend` (default Memory)
- 30 unit tests

### Reviews and fixes

#### The diting full review

- **A1 [High] fixed**: `router/mod.rs`'s cookie write hard-coded `SameSite=Lax`, ignoring `config.cookie_secure` / `config.cookie_same_site` → reads config now
- **A2 [High] fixed**: `csrf.rs`'s `build_set_cookie` hard-coded no `Secure` flag → `CsrfConfig` gains the `cookie_secure` field, and `build_set_cookie` supports Secure
- **A4 [Medium] fixed**: `redis_rate_limiter.rs`'s `prepare_script_args` return value was discarded + timestamp inconsistency → `try_acquire_n` builds the arguments inline, with `prepare_script_args` marked `#[cfg(test)]`
- **A3 [Medium] deferred**: the WAF's per-request rule-chain rebuild heap-allocation optimization (non-blocking)
- **MED-001 [Medium] fixed**: `GARRISON_RATE_LIMIT_BACKEND`'s unknown values were silently ignored → now returns `GarrisonError::Config` (rule 12: failures must be explicit)

#### The specmark converge

Round 1's converge found 12 gaps, adding 9 convergence tasks; round 2 found none:

- CSRF empty tokens return false (checked explicitly before the constant-time comparison)
- HTTP methods case-sensitive (RFC 7230; `to_uppercase()` removed)
- CORS OPTIONS short-circuits with 204 (non-matching Origins do not passthrough)
- WafConfig supports `custom_rules: Vec<Arc<dyn WafRule>>`
- `validate()` validates the Redis `redis_url` is non-empty
- The Redis rate limiter's error type changed to `GarrisonError::Dao`
- The Lua else branch adds EXPIRE preventing key memory leaks
- Environment overrides (the CORS/CSRF/RateLimit 4 variables)
- The spec updated Set-Cookie to include SameSite/Secure (matching the safer code)

#### tiangang SAST

- 0 CRITICAL — the release gate passed
- 2 Highs both false positives (oidc.rs's test-mock JWT tokens)
- 18 Mediums: 17 GitHub Actions supply chain (pre-existing) + 1 RUSTSEC-2023-0071 rsa Marvin Attack (a pre-existing dependency vulnerability)

### Verification

- Full tests: 2295 passed, 0 failed, 90 ignored (+377 new vs v0.6.3's 1918)
- clippy: zero warnings on the full + production features
- cargo doc: zero warnings (fixing 26 unresolved links: 17 new in v0.6.4 + 9 pre-existing)
- pre-commit hooks: all passing
- specmark converge: 2 rounds, the second with 0 gaps, archived

### Known limitations

- The WAF middleware rebuilds the rule chain per request (Vec + Box heap allocations); high-traffic scenarios could optimize to a prebuilt `Arc<Vec<Box<dyn WafRule>>>`
- The Redis rate limiter's unit tests do not depend on a real Redis connection, validating only the Lua script logic and argument assembly
- RUSTSEC-2023-0071 (the rsa 0.9.10 Marvin Attack) is a pre-existing dependency vulnerability, not introduced by v0.6.4 — handled in later versions

## [0.6.3] - 2026-07-11

### Overview

v0.6.3's session-lifecycle enhancements implement 4 capability domains: automatic token renewal, concurrent-login control, the refresh-token rotation's public API, and device management. Managed via the specmark change `v0.6.3-token-renewal-concurrency-refresh-device`, with 27 tasks completed. The diting review found 2 HIGHs (the concurrent-renewal race + enforce-failure session leaks), both fixed.

### Added

#### D1: Automatic token renewal (`auto_renewal_threshold`)

- `GarrisonConfig` gains `auto_renewal_threshold: i64` (default -1 disabled; range -1 or 0-100)
- `GarrisonLogicDefault::check_and_renew` checks the remaining-TTL percentage in the `check_login` path, auto-renewing below the threshold
- The non-JWT mode calls `renew_to_equivalent`; the JWT mode calls `refresh_token`
- The renewal result reaches the web framework middleware via the `CURRENT_RENEWED_TOKEN` task_local
- `GarrisonJwtClaims` gains the `jti` (RFC 7519 §4.1.7) UUID claim, ensuring uniqueness of tokens issued within the same second
- The environment override `GARRISON_AUTO_RENEWAL_THRESHOLD` supported

#### D2: Concurrent-login control (`is_concurrent` / `is_share` / `max_login_count`)

- `GarrisonConfig` gains `is_concurrent: bool` (default true) / `is_share: bool` (default false) / `max_login_count: u32` (default 0 = unlimited)
- `validate()` enforces `is_concurrent=true` when `is_share=true`
- `is_share=true`: reuse the existing valid token (touch + return) without creating a new session
- `is_concurrent=false`: kick all existing sessions before login
- `max_login_count > 0`: enforce the maximum after login, kicking the oldest sessions by `last_active_at` ascending
- `GarrisonSession` gains the `login_token_map: DashMap<String, Vec<String>>` in-memory index for fast lookups

#### D3: The refresh-token rotation's public API

- The `SessionLogic` trait gains `refresh_access_token(&self, refresh_token: &str) -> GarrisonResult<(String, String)>`
- `GarrisonLogicDefault` implements it by delegating to `RefreshTokenRotation::rotate` (needing the `protocol-jwt` + `db-sqlite` features)
- The `with_refresh_token_rotation` builder method injects the `RefreshTokenRotation` instance
- Without injection it returns `GarrisonError::NotImplemented`

#### D4: Device management

- The new `src/session/device.rs` module (feature-gated: needs the sha2-enabling features)
- The `DeviceSession` struct: device/login_id/token/ip/user_agent/last_active_at
- `DeviceManager`: `list_devices` (listing an account's active devices), `kickout_device` (kicking by device)
- `device_fingerprint(user_agent, ip)`: the first 16 bytes of SHA-256(UA+IP) as hex = a 32-char fingerprint
- `login` auto-generates the fingerprint when `LoginParams.device` is None but `user_agent` + `ip` have values

### Breaking changes

- `SessionLogic::login`'s signature changed from `login(&self, login_id: &str)` to `login(&self, login_id: &str, params: &LoginParams)`
- The new `LoginParams` struct (device/ip/user_agent/remember_me, deriving Default)
- The `GarrisonUtil::login_simple(id)` convenience method uses `LoginParams::default()`, staying backward compatible
- All mock impls updated in sync

### Reviews and fixes

#### The diting full review

- **The HIGH-001 fix**: `check_and_renew`'s concurrent race caused "zombie sessions" — the new per-login_id `renewal_locks` (independent of `GarrisonSession::login_locks`), acquiring the lock before renewal + re-checking the TTL; the independent lock avoids the `renew_to_equivalent` → `logout` → `login_locks` deadlock
- **The HIGH-002 fix**: `enforce_max_login_count` failures leaked orphan sessions — `login_inner` rolls back on enforce failure (logging out the newly created token), with rollback failures logged at `tracing::error!`

#### tiangang SAST

- 0 CRITICAL, 0 HIGH — the release gate passed
- 2 MEDIUMs (DeviceSession.token exposing sensitive data / renewal failures swallowed silently) + 3 LOWs recorded as known limitations

### Verification

- Full tests: 1918 passed, 0 failed, 4 ignored (+45 new vs v0.6.2's 1873)
- clippy: zero warnings on the full + production features
- pre-commit hooks: all passing

### Known limitations

- `renewal_locks` is in-memory; in multi-instance deployments concurrent-renewal protection holds within a single instance only
- `device_fingerprint` is unsalted — the same UA+IP yields the same fingerprint (spoofable)
- The `DeviceSession.token` field exposes the plaintext token (CWE-200); the application layer should avoid serializing it to clients
- `max_login_count`'s enforce relies on `AccountSession.tokens` and `login_token_map` consistency; extreme concurrency may see brief divergence

## [0.6.2] - 2026-07-11

### Overview

The v0.6.x series' first batch of security Quick Wins, drawing on the cedar/QIdentity analysis results, implementing 6 security enhancements. Managed via the specmark change `v0.6.2-security-quick-wins`, with 21 tasks across 7 phases.

### Added

#### D1: Sensitive-data masking (the `secure-masking` feature)

- The `MaskType` enum (Phone/IdCard/Email/BankCard/Custom)
- The `SensitiveDataMasker` struct, supporting `mask_value` single-value masking and `mask_json` recursive JSON field masking
- 19 unit tests, including safe multi-byte-character handling

#### D2: The general token-bucket rate limiter

- `TokenBucket` + `TokenBucketRateLimiter`, lock-free via `DashMap` + `AtomicU64` CAS
- The `try_acquire` / `try_acquire_n` / `cleanup` methods
- 7 unit tests

#### D3: XSS protection (the `secure-xss` feature)

- The `XssMode` enum (EscapeAll / Whitelist(Vec<&'static str>))
- The `XssProtector::sanitize` method; EscapeAll escapes the 5 HTML special characters
- Whitelist mode keeps allowlisted tags and removes `on*` event-handler attributes
- Zero external dependencies; 12 unit tests

#### D4: Session hover-timeout kicks

- `GarrisonConfig` gains `session_hover_timeout` (default -1 disabled)
- `GarrisonSession` gains `last_active_time` + `check_hover_timeout` + `update_last_active`
- `check_login_mixin` / `check_login_simple` integrate the lazy check — kicking on timeout and broadcasting `SessionTimeout`
- 10 unit tests

#### D5: The cache warm-up service

- `CacheWarmupService::warmup()` scans `role:*` and `tenant:*` keys to trigger cache fills
- `DaoKeyPrefix` gains the `Role` variant
- DAO backends without `keys()` support (e.g. oxcache) degrade to zero statistics
- 5 unit tests

#### D6: The front/back separation config item

- `GarrisonConfig` gains `frontend_separation` (default false)
- `validate()` logs an info hint about Token Header mode when enabled
- The environment override `GARRISON_FRONTEND_SEPARATION` supported
- 3 unit tests

### Reviews and fixes

#### The diting full review + tiangang SAST

- **The H-1 fix**: the masking byte slices switched to `chars()`, avoiding panics on non-ASCII characters (a DoS risk)
- **The H-2 fix**: the warm-up catches `NotImplemented` and degrades to zero statistics, no longer erroring in production
- **The H-3 fix**: the XSS whitelist mode removes `on*` event-handler attributes, preventing unquoted-attribute bypass
- **The M-3 fix**: the hover check extracted into the `check_and_update_hover` helper, removing 24 lines of duplication
- **The M-4 fix**: logout errors use `tracing::warn!` instead of being swallowed silently

### Verification

- Full tests: 1873 passed, 0 failed, 4 ignored
- clippy: zero warnings on the full + production features
- pre-commit hooks: all passing
- diting: 0 Critical / 0 High (after fixes)
- tiangang SAST: 0 CRITICAL

### Known limitations

- `TokenBucketRateLimiter` has no Redis support (deferred to v0.6.3)
- `XssProtector`'s whitelist mode does not support attribute-allowlist filtering
- `last_active_time` is in-memory; multi-instance deployments need DAO persistence (deferred to v0.6.3)
- `frontend_separation` provides only the config item and a log hint; web-framework behavior changes await later versions
- The `MaskType::Custom` variant stores the pattern but implements no masking logic

## [0.6.1] - 2026-07-11

### Overview

This version contains two batches of changes:

1. **gap-closure-remaining**: closing the 11 gaps between the origin documents and the implementations, covering remember-me configuration, Redis deployment modes, identity switching, token replacement, OAuth2 annotations, route grouping, the session-expiry callback, the SAML 2.0 skeleton, the OIDC RP skeleton, and the Redis pub/sub SsoChannel. **With this, all gaps between the origin documents and the implementations are fully closed, zero residue.**

2. **v0.6.1-concurrency-syncfn-macro-enum**: fixing 4 core issues via the specmark change — concurrency safety, sync-fn macro support, the macro-coverage audit, and string-to-enum conversion.

### Added

#### The remember-me extended session timeout

- `GarrisonConfig` gains the `remember_me_enabled` (default false) and `remember_me_timeout` (default 7776000 seconds = 90 days) fields
- The `login` method supports the `remember_me=true` parameter, using `remember_me_timeout` as the session TTL when enabled
- The environment overrides `GARRISON_REMEMBER_ME_ENABLED` / `GARRISON_REMEMBER_ME_TIMEOUT` supported
- `validate()` validates: with `remember_me_enabled=true`, `remember_me_timeout` must be > `timeout`

#### The Redis deployment-mode enum

- The new `RedisDeploymentMode` enum (Single / Sentinel / Cluster / MasterSlave), covering the common production Redis topologies
- The new `RedisConfig` aggregate struct (mode + password + db + connection_timeout_secs + pool_size)
- A `Display` implementation emitting a human-readable deployment-mode description

#### Identity switching switch_to

- The `switch_to(login_id)` method: switching the login identity within the current session, preserving the original token and device info

#### Token replacement renew_to_equivalent

- The `renew_to_equivalent()` method: generating an equivalent new token and migrating session state, invalidating the old one

#### The OAuth2 annotations CheckAccessToken/CheckClientToken

- The `Annotation` enum gains the `CheckAccessToken` and `CheckClientToken` variants
- `pre_handle` returns `NotImplemented`, directing users to `protocol::oauth2::OAuth2Client` or a custom interceptor

#### The route-grouping group() method

- The `GarrisonRouter::group(prefix, annotation, f)` method: route grouping with prefix mounting
- Sub-routers inherit the parent router's interceptor and config
- With `Annotation::Ignore` the route annotation is overridden; otherwise the route's own annotation is kept

#### The session-expiry callback SessionExpiryListener

- The `SessionExpiryListener` trait: firing an async callback when a session expires
- The `add_expiry_listener` / `trigger_expiry_listeners` methods

#### The SAML 2.0 skeleton

- The `SamlProvider` trait: `build_authn_request` / `parse_response` / `validate_assertion`
- The `DefaultSamlProvider` implementation: a quick-xml pull reader parsing SAML Responses
- The data structures: `SamlAssertion` / `SamlResponse` / `SamlRequest`
- Feature gate: `protocol-sso`

#### The OIDC RP skeleton

- The `OidcProvider` trait: `get_authorization_url` / `exchange_code` / `get_user_info` / `validate_id_token`
- The `DefaultOidcProvider` implementation: a reqwest HTTP client + the discovery config
- The data structures: `OidcDiscoveryConfig` / `OidcUserInfo`
- The difference from `OidcHandler`: OidcHandler is Garrison as the IdP, while OidcProvider is Garrison as the RP

#### The Redis pub/sub SsoChannel

- `RedisPubSubSsoChannel` implements the `SsoChannel` trait
- `push(topic, message)`: publishing via `redis::cmd("PUBLISH")`
- `subscribe(topic, handler)`: spawns a tokio task + `catch_unwind` protecting handler panics
- Feature gates: `cache-redis` + `protocol-sso-server`
- Cargo.toml adds the `futures` / `redis` / `quick-xml` dependencies

### S1: The concurrency-safety fixes (v0.6.1-concurrency-syncfn-macro-enum)

#### The concurrency audit report

- 13 race-condition reports output to `specmark/changes/v0.6.1-concurrency-syncfn-macro-enum/concurrency-audit.md`
- R-001~R-004 were HIGH (the Account-Session's non-atomic read-modify-write sequences)
- Root cause: `GarrisonDao` provides only per-key atomic operations, with no cross-key transactions

#### The per-login_id operation locks

- `GarrisonSession` gains the `login_locks: DashMap<String, Arc<tokio::sync::Mutex<()>>>` field
- The `with_login_lock` async-closure method: serializing create/logout/logout_by_login_id per login_id
- `logout` split into `logout` (acquiring the lock) + `logout_inner` (lock-free, called by `kickout_by_device` to avoid deadlock)
- The new test `concurrent_login_same_user_creates_consistent_session` (a SlowDao wrapper amplifying the race window)

#### task_local context propagation

- The new `GarrisonContext` struct + `capture()` + `within(self, f)` methods
- Using `CURRENT_TOKEN.scope(token, f).await` to propagate task_locals across spawns
- 2 tests: `task_local_propagates_across_spawn` / `garrison_context_capture_without_token_propagates_none`

#### The plugin/listener thread-safety audit

- The audit report output to `specmark/changes/v0.6.1-concurrency-syncfn-macro-enum/plugin-listener-thread-safety.md`
- Conclusion: 0 races, 0 deadlock risks
- Plugins: immutable after init (no mutation methods)
- Listeners: the RwLock + snapshot pattern (cloning the Vec, releasing the lock, then iterating)

### S2: sync-fn macro support

#### The detect_asyncness enum

- `require_async()` replaced with `detect_asyncness(item_fn) -> Asyncness` (the `Async`/`Sync` variants)
- No longer rejecting sync fns, paving the way for generating sync paths later

#### GarrisonUtil's synchronous methods

- 7 new `check_*_sync()` methods: `check_login_sync` / `check_permission_sync(perm)` / `check_role_sync(role)` / `check_access_token_sync` / `check_client_token_sync` / `check_temp_token_sync` / `check_api_key_sync(ns)`
- The pattern: `task::block_in_place(|| Handle::current().block_on(Self::check_login()))`
- 8 tests covering the success and unauthenticated paths

#### expand_wrapper's sync-fn branch

- `expand_wrapper` gains the `asyncness: Asyncness` parameter
- The async path: generating an `async fn wrapper` + `.await` calls
- The sync path: generating a `fn wrapper` + `check_*_sync()` calls
- New trybuild compile tests: `sync_fn_pass.rs` + `async_fn_pass.rs` (8 cases each, covering all 7 macros + the api_key namespace)

### S3: The macro-coverage audit

#### The coverage matrix documented

- A `# Coverage Matrix` section added to `garrison-macros/src/lib.rs`'s module docs
- A table of the 7 macros × 13 feature domains' coverage
- No new macro code — documenting the status quo only

### S4: Hard-coded strings to enums

#### The DaoKeyPrefix enum

- The new `src/constants/mod.rs` + `src/constants/dao_keys.rs`
- The `DaoKeyPrefix` enum with 8 variants: Session / Token / Captcha / Saml / Cred / Lockout / BruteForce / Tenant
- `as_str()` (a const fn) / `build_key(id)` / a `Display` implementation
- 3 unit tests

#### The EventReason enum

- The new `src/constants/events.rs`
- The `EventReason` enum with 6 variants: InvalidCredentials / Expired / Revoked / Locked / Logout / Kickout
- `as_str()` (a const fn) / a `Display` implementation
- 2 unit tests

#### The DAO key-prefix replacement

- 20 `format!("prefix:{}", ...)` sites across 11 files replaced with `DaoKeyPrefix::Variant.build_key(...)`
- Files involved: session/security_listener, strategy/hooks, session/mod, firewall/captcha_provider, protocol/sso/saml, account/credential/{mod,backup_code}, account/lockout, firewall/brute_force, dao/repository/role_hierarchy, dao/mod

#### The event-reason replacement

- 2 `"invalid_credentials"` in `src/stp/password.rs` replaced with `EventReason::InvalidCredentials.to_string()`
- 1 `"管理员强制下线"` in `src/stp/session.rs` **kept as-is** (a user-facing display message, not a reason code)
- diting's HIGH Issue-001 caught and fixed a silent behavior change (Chinese → English)

### Verification (v0.6.1-concurrency-syncfn-macro-enum)

- `cargo test --features full --lib`: 1817 passed; 0 failed
- `cargo clippy --features full --lib --tests -- -D warnings`: zero warnings
- `cargo clippy --features production -- -D warnings`: zero warnings
- The diting full review: 0 Critical / 0 High (after fixes) / 3 Medium / 3 Low → Approved
- tiangang SAST: cargo-audit 0 CRITICAL (1 MEDIUM rsa with no fix) / semgrep 0 CRITICAL (2 ERROR false positives: test JWT tokens)
- All pre-commit hooks passing

### Changed

- `Cargo.toml` version 0.6.0 → 0.6.1
- `garrison-macros/Cargo.toml` version 0.5.0 → 0.5.1 (sync-fn macro support is a feature addition)

### Known limitations

- The `DashMap login_locks` has no cleanup mechanism; long-running processes may grow memory (diting MEDIUM Issue-002, deferred)
- `block_in_place` is unavailable on single-threaded runtimes; 4 concurrent sync fns may exhaust workers (diting LOW Issue-006, documented)
- SAML namespace checks are prefix-based rather than URI-based — defense-in-depth, not a complete solution (diting LOW Issue-005)

## [0.6.0] - 2026-07-09

### Overview

Garrison 0.6.0 is the "account-security-engine release", implementing 4 core capabilities (E-001/E-002/E-003/E-004) + 4 technical-debt cleanups (B-001/B-002/C-001/D-001) via the specmark change `v0-6-0-account-security-engine`. It introduces the `account/` module as the account-security capability hub, providing the Credential SPI, the password-policy engine, the user-lockout strategy, and the AuthenticationFlow DSL, plus the i18n social-login error messages and Prometheus metrics.

### Added

#### E-001: The account/ module skeleton + the Credential SPI

- The new top-level `account/` module (`account/credential/` + `account/policy/` + `account/lockout/` + `account/authflow/` + `account/metrics.rs`)
- The `Credential` trait as the unified credential-model SPI: `verify` / `store` / `load` / `update` / `metadata`
- The `PasswordCredential` implementation: password credentials based on `PasswordHasher`
- The `TotpCredential` implementation: RFC 6238 TOTP dynamic-code credentials
- `DaoCredentialRepository`: credential storage based on `GarrisonDao`
- `PasswordHasher` migrated from `src/secure/` to `account/credential/password.rs` (deleting the `secure-password` feature)

#### E-002: PasswordPolicyEngine

- The `PasswordPolicyRule` trait + `PasswordPolicyEngine` + `PasswordPolicyContext`
- 6 core password-policy rules: length / complexity / history / dictionary / username similarity / sequence detection
- 6 extension password-policy rules: repeated characters / keyboard patterns / dates / common passwords / context sensitivity / unique-character count

#### E-003: UserLockoutStrategy + GarrisonFirewallStrategy

- `UserLockoutConfig` + `WaitStrategy` + `LockoutState`
- `UserLockoutStrategy`: the user-based login-lockout strategy
- `GarrisonFirewallStrategy`: integrating UserLockoutStrategy into the GarrisonFirewall framework

#### E-004: The AuthenticationFlow DSL

- The `AuthStep` enum + `AuthenticationFlow` + `AuthContext` + `AuthResult`
- The `FlowBuilder` streaming-construction DSL
- The `FlowRegistry` based on inventory compile-time registration
- The `AuthExecutor` core executor (a 5-field constraint: builder/registry/dao/credential_repo/metrics)
- The `SocialProvider` + `SsoServer` step extensions
- The built-in `AuthenticationFlow`s: username_password / username_password_totp / social_wechat / social_alipay / sso

#### C-001: Fluent i18n for social-login error messages

- The new `loc!` macro: the `#[cfg(feature = "i18n")]` branch calls `translate_detail`, returning a fallback when disabled
- The new `translate_detail` function (`src/i18n.rs`): querying the fluent bundle by key
- 38 ftl keys (wechat 12 + alipay 8 + keycloak 18) in both Chinese and English
- 46 error-construction sites wired to the `loc!` macro (wechat 16 + alipay 12 + keycloak 18)

#### D-001: AccountMetrics Prometheus metrics

- The `AccountMetrics` struct (`#[cfg(feature = "metrics-prometheus")]`): 4 metrics
  - `credential_verify_duration` (a HistogramVec, label: credential_type)
  - `policy_validate_duration` (a HistogramVec, label: rule_name)
  - `lockout_triggered_total` (a CounterVec, label: lockout_type)
  - `authflow_execute_duration` (a HistogramVec, label: flow_name)
- The `register_to` / `observe_*` / `record_*` / `gather` methods
- When the feature is disabled, `type AccountMetrics = ()`

### Changed

- `Cargo.toml` version 0.5.0 → 0.6.0
- `AuthExecutor` keeps the 5-field constraint: metrics are passed via the `execute_with_metrics` method parameter, not a struct field
- `UserLockoutStrategy` gains the `metrics: Option<Arc<AccountMetrics>>` field + the `with_metrics` builder
- `PasswordPolicyEngine` gains the `metrics` field + the `with_metrics` builder, with per-rule timing inside `validate`
- `src/i18n.rs` gains the `translate_detail` function
- `src/protocol/mod.rs` gains the `loc!` macro definition
- `locales/zh.ftl` + `locales/en.ftl` gain 38 message keys

### Breaking changes

1. **The `PasswordHasher` migration**: moved from `src/secure/password.rs` to `account/credential/password.rs`, with the `secure-password` feature deleted (merged into the `account` feature)
2. **The `FirewallContext.login_id` type change**: `i64` → `String` (all FirewallStrategy implementations need signature updates)

### Fixed

#### B-001: Fixing cargo doc's 10 warnings

- 8 broken intra-doc links (`decision` / `JsonTestCase` / `MaxMindDbGeoLookup` / `MaxMindDbCountryLookup` / `RefreshTokenRecord` etc.)
- 2 unclosed HTML tags (`web_actix/mod.rs` / `web_warp/mod.rs`'s `Bearer <token>` changed to `` Bearer `<token>` ``)

#### B-002: The tenant_isolation integration-test fix

- 7 changes in `tests/integration/tenant_isolation.rs`: `login_id: i64` → `&str`, aligned with the `GarrisonInterface` signature
- `use garrison::{PermissionLogic, SessionLogic};` added (trait methods need the trait imported)

### Verification

- `cargo test --features full --lib`: 1463 passed; 0 failed
- `cargo clippy --features full --lib --tests -- -D warnings`: zero warnings
- `cargo doc --no-deps --features full`: zero warnings
- `cargo test --features "full audit-log" --test integration tenant_isolation`: 1 passed

### Known limitations

- `AuthExecutor` metrics are passed only explicitly via `execute_with_metrics`, not yet wired into `GarrisonManager`'s auto-injection chain (awaiting the v0.7.0+ Manager refactor)
- Flows registered in the `FlowRegistry` via inventory are fixed at compile time; runtime dynamic registration needs the `register` method (not auto-discovery)

## [0.5.3] - 2026-07-09

### Overview

Garrison 0.5.3 is the "feature-completion release", implementing 4 completions (A-015/A-014/A-012/A-013) via the specmark change `v0-5-3-feature-completion`. It closes the stp-split leftovers, the MySQL backend, and the Firewall MaxMindDb production backend, and upgrades oxcache.

### Changed

#### A-015: The oxcache upgrade + decision-doc sync

- The `oxcache` dependency upgraded to 0.3.3 (per-entry TTL + `ttl_sync()` queries)
- `docs/decisions/A-010-dao-keys-performance-evaluation.md` updated: the `CacheReader` trait still has no iter/keys methods
- `src/dao/mod.rs`'s comments updated: deferred until oxcache provides a native iter API

#### A-014: The full stp/mod.rs split

- The 164KB `src/stp/mod.rs` split into 11 responsibility files (adding `tests.rs` + `interface.rs` + `util.rs`)
- The 6 `impl trait for GarrisonLogicDefault` blocks moved to their sub-files
- 5 session helper methods moved from mod.rs to session.rs (meeting the mod.rs < 15KB target)
- mod.rs finally: 12.4KB / 284 lines (formerly 164KB / 4035 lines)

#### A-012: The MySQL backend enabled + testcontainers integration tests

- The `db-mysql` feature enabled (`dbnexus/mysql`)
- The `testcontainers = "0.27"` dev-dependency added
- `tests/db_mysql_testcontainers.rs` created: 11 `#[serial]` integration tests
- 6 MySQL-compatible migration files created under `migrations/mysql/core/`
- `src/dao/repository/mysql/mod.rs` created: MySQL-named aliases re-exporting the sqlite implementations
- `UserExtRepository::upsert`'s MySQL compatibility fixed (`ON DUPLICATE KEY UPDATE` replacing `ON CONFLICT`)
- **Deviation**: db-mysql is not in the `full` aggregate feature (dbnexus forbids db-sqlite and db-mysql simultaneously)

#### A-013: The Firewall MaxMindDb production backend

- The `maxminddb = "0.29"` dependency + the `firewall-maxminddb` feature added
- `MaxMindDbGeoLookup` implemented (GeoIP2-City: IP → GeoCoord, for AnomalousLoginStrategy)
- `MaxMindDbCountryLookup` implemented (GeoIP2-Country: IP → ISO country codes, for GeoIPStrategy)
- 14 tests: open/lookup/invalid_ip/private_ip + strategy integration tests
- GeoLite2-City/Country-Test.mmdb test data downloaded

### Verification results

- `cargo test --features full --lib`: 1336 passed; 0 failed
- `cargo clippy --features full --lib --tests -- -D warnings`: zero warnings
- `cargo test --features "db-mysql" --test db_mysql_testcontainers`: 11 passed (needs Docker)
- `cargo test --features "firewall-maxminddb" --lib maxminddb`: 14 passed

### Known limitations

- In `cargo test --features full --workspace`, `tests/integration/tenant_isolation.rs` has a pre-existing failure (left over from v0.5.2's LoginId migration, not introduced by v0.5.3)
- `cargo doc --no-deps --features full` has 10 pre-existing warnings (`src/core/permission/decision.rs`'s 8 broken intra-doc links + `src/web_actix/mod.rs` / `src/web_warp/mod.rs`'s 2 unclosed HTML tags, not introduced by v0.5.3)

## [0.5.2] - 2026-07-08

### Overview

Garrison 0.5.2 is the "architecture-refactor release", implementing 5 architecture refactorings (A-002/A-004/A-009/A-010/A-011) via the specmark change `v0-5-2-architecture-refactor`. This is the last refactoring window before the v1.0 API freeze, clearing the architecture debt completely.

> **A breaking change (no backward compatibility)**: the original plan was a `#[deprecated]` transition period, but at the apply stage the user decided on direct deletion, clearing the technical debt completely.

### Changed

#### A-002: The GarrisonLogic trait split

- The 21-method god trait `GarrisonLogic` split into 6 sub-traits:
  - `GarrisonCore` (the base, 1 method)
  - `SessionLogic: GarrisonCore` (10 methods)
  - `PermissionLogic: SessionLogic` (2 methods)
  - `TokenLogic: SessionLogic` (5 methods)
  - `MfaLogic: SessionLogic` (2 methods)
  - `PasswordLogic: SessionLogic` (1 method)
- **`GarrisonLogic` deleted directly** (no `#[deprecated]` transition, no type alias)
- The Manager holds the concrete type `Arc<GarrisonLogicDefault>` (not a trait object)
- Callers must explicitly `use crate::stp::SessionLogic` and the other sub-traits to resolve methods

#### A-004: The LoginId migration

- **The `LoginId` newtype deleted**, using `String`/`&str` across the stack
- All `login_id: i64` signatures migrated to `login_id: &str` (object-safe, usable as `dyn`)
- `get_login_id()` returns `Option<String>` (formerly `Option<i64>`)
- `verify_token()` returns `String` (formerly `i64`)
- `GarrisonUtil::login_id_to_i64` removed (no longer needed)
- `GarrisonUtil` keeps the `impl Into<String>` ergonomic entrances

#### A-009: The oxcache `_sync` API evaluation

- Conclusion: keep the `_sync` APIs (<1μs on the in-memory backend vs `spawn_blocking`'s 10-50μs)
- `GarrisonDaoOxcache`'s performance constraints documented (see `docs/decisions/A-009-oxcache-sync-api-evaluation.md`)
- Follow-up: switch to the async APIs when Redis/distributed backends arrive

#### A-010: The `keys()` performance evaluation

- Conclusion: defer to oxcache 0.5+ (`Cache.backend` is `pub(crate)`)
- `GarrisonDao::keys()`'s known limitations documented (see `docs/decisions/A-010-dao-keys-performance-evaluation.md`)
- The business's temporary workaround: maintain the key set yourself

#### A-011: Splitting `src/stp/mod.rs`

- The 164KB/4035-line single file split into 10 responsibility files:
  - `core.rs` / `session.rs` / `permission.rs` / `token.rs` / `mfa.rs` / `password.rs`
  - `interface.rs` / `util.rs` / `parameter.rs` / `mod.rs` (the re-exports)
- Each sub-file contains the trait definition + the `GarrisonLogicDefault` impl block + unit tests

### Breaking changes

1. **The `GarrisonLogic` trait deleted**: all `Arc<dyn GarrisonLogic>` users must migrate to `Arc<GarrisonLogicDefault>` + explicitly `use` the sub-traits
2. **The `LoginId` newtype deleted**: all `LoginId` users must migrate to `String`/`&str`
3. **The Manager's return type changed**: `GarrisonManager::logic()` returns `Arc<GarrisonLogicDefault>` (not `Arc<dyn GarrisonLogic>`)
4. **`get_login_id()`'s return type changed**: `Option<i64>` → `Option<String>`
5. **`verify_token()`'s return type changed**: `i64` → `String`
6. **The `login_id` parameter type changed**: `i64` → `&str` (all trait methods + `GarrisonInterface`)

### Verification

- `cargo test --features full --lib`: 1322 passed, 0 failed
- `cargo test --features full --tests`: 72 passed, 0 failed
- `cargo test --features "full manager-explicit" --lib -- manager::explicit`: 6 passed
- `cargo clippy --features full --lib --tests -- -D warnings`: zero warnings
- `cd examples && cargo check --features full`: passing

---

## [0.5.0] - 2026-07-06

### Overview

Garrison 0.5.0 is the "production-necessities release", implementing multi-tenant isolation, social login, audit logs, RefreshToken rotation, the protection suite, the role hierarchy, decision provenance, the Keycloak OIDC RP, SSO TOCTOU atomization, the annotation system, and the PostgreSQL backend adaptation via the specmark change
`v0-5-0-production-essentials`.

### Added

#### Multi-tenant isolation

- **The `tenant-isolation` feature**: the `TENANT` task_local + `TenantContext` +
  the `prefixed_key` function automatically prefixing cache keys with `tenant:{id}:`,
  ensuring multi-tenant data isolation. The `TenantResolution` middleware parses the tenant ID from Header/Query/Token.

#### Social login

- **The `social-wechat` feature**: `WechatProvider` implements WeChat QR login,
  supporting the access_token endpoint + user-info queries.
- **`SocialBindingService`**: social-account binding/unbinding + find_or_create semantics.

#### Audit logs

- **The `audit-log` feature**: `AuditLogListener` subscribes to 14 `GarrisonEvent`s,
  writing the `audit_logs` table (with tenant_id/login_id/event_type/mask_fields masking).
  `AuditQuery` supports compound-condition queries.

#### RefreshToken rotation

- **`protocol-jwt` (extended)**: the `RefreshTokenRotation` service provides
  `rotate()` + `detect_reuse()` + `revoke_chain()`. The `refresh_tokens` table uses a SHA-256 hash chain (token_hash + parent_token_hash).

#### Decision provenance

- **The `decision-trace` feature**: the `PermissionChecker` trait + the `authorize()` API
  returning `Decision { allowed, reason, errors }`, with the `DecisionReason` enum containing
  `ExplicitAllow`/`ExplicitDeny`/`NoMatchingPermission`/`RoleBased` etc.

#### The Keycloak OIDC RP

- **The `keycloak-oidc` feature**: `KeycloakProvider` implements the OIDC relying party,
  supporting `discover()` + `exchange_code()` +
  `verify_id_token()` (JWKS signature verification + KeycloakClaims parsing).

#### The protection suite

- **5 FirewallStrategy implementations**: `BruteForceStrategy`/`RateLimitStrategy`/
  `AnomalousLoginStrategy`/`DDoSStrategy`/`GeoIPStrategy`,
  reusing oxcache as the counting backend.

#### The role hierarchy

- **The `role_hierarchy` table**: `parents`/`indirect_ancestors` + TC precomputation,
  caching the permission union at login.

#### Database backends

- **The `db-postgres` feature**: the PostgreSQL backend adaptation, with `make_statement`/
  `convert_placeholders` implementing backend-agnostic SQL.

#### Integration tests

- **4 end-to-end integration tests** (`tests/integration_v0_5_0.rs`):
  multi-tenant isolation + audit logs + decision provenance / the full Keycloak OIDC RP flow /
  RefreshToken rotation + reuse detection / an RSA key-pair smoke test.

#### Examples

- **The `v0_5_0_demo` example**: demonstrating v0.5.0's core production capabilities (multi-tenancy + audit logs +
  decision provenance + the Keycloak RP + the WeChat social-login configuration).

### Verification

- `cargo test --features "full" --workspace` → all green
- `cargo clippy --features "full" --workspace -- -D warnings` → zero warnings
- `cargo doc --no-deps --features full --workspace` → done

## [0.4.2] - 2026-07-05

### Overview

Garrison 0.4.2 is the 0.4.x series' MINOR release, implementing the origin-doc-to-code alignment gap closure + new feature enhancements via the specmark change
`v0-4-2-gap-closure-and-features`.
16 phases (capabilities) completed, covering: the LoginId newtype, GarrisonDao extensions, password hashing,
the Repository layer, password login, multi-account isolation, the three JWT modes, API Key namespaces, the SSO TOCTOU fix,
kickout_by_device, event extensions, web adapters, the strategy registry, proc-macro annotations, OAuth 2.1 PKCE, and
token introspection.

### Added

#### Core types

- **The LoginId newtype**: `src/stp/login_id.rs` adds the `LoginId` enum
  (`Numeric(i64)` / `String(String)`), implementing `From<i64>`/`From<String>`/`From<&str>`/
  `as_str`/`as_i64`/`Display`/`Serialize`/`Deserialize`. The `stp`/`session`/
  `protocol/{jwt,oauth2,sso,apikey}` public method signatures change to `impl Into<LoginId>`, keeping i64
  compatible via `From<i64>` (`login_id_to_i64` becomes `pub(crate)` reuse)

#### The DAO layer

- **The GarrisonDao 4-method extension**: adding `set_permanent` (no TTL) / `get_timeout` (querying the remaining TTL) /
  `keys` (glob-pattern scanning) / `rename` (renaming keys), all with default implementations for backward compatibility.
  `GarrisonDaoOxcache` overrides `set_permanent`/`get_timeout`/`rename` using oxcache's native APIs to preserve TTLs (`set_with_ttl_sync(None)` / `ttl_sync()` / `get→ttl_sync→set_with_ttl_sync→delete`)

#### The security modules

- **PasswordHasher**: the new `secure-password` feature + the `PasswordHasher` trait +
  `Argon2Hasher` + `BcryptHasher` + `PasswordVerifier` (auto-detecting the hash format: argon2/bcrypt/BCrypt).
  Depends on argon2 0.5 + bcrypt 0.15 + rand 0.8
- **The three JWT modes**: the `JwtMode` enum (`Stateless`/`Mixin`/`Simple`),
  the `GarrisonLogicDefault::with_jwt_mode` builder, and `check_login` branching per mode:
  Stateless is JWT verify only / Mixin is JWT+session / Simple is session only

#### Data access

- **The Repository layer**: `db-sqlite` enables the `src/dao/repository/` module, defining 9
  repository traits (UserRepository/RoleRepository/PermissionRepository/UserRoleRepository/
  RolePermissionRepository/AuthMethodRepository/SessionRepository/LoginLogRepository/
  UserExtRepository), with every method's first parameter `tenant_id: i64`. 9 SqliteRepositories built on dbnexus
  DbPool + sea-orm

#### The authentication paths

- **Password login**: `GarrisonLogic::login_with_password(login_id, password)` as a default method,
  integrating `UserRepository::find_by_username` + `PasswordHasher::verify` + `login`.
  The `GarrisonLogicDefault::with_password_hasher` builder injects `Arc<dyn PasswordHasher>`
- **Multi-account login_type**: `GarrisonInterface` gains
  `get_permission_list_with_type(login_id, login_type)` + `get_role_list_with_type`,
  with the old methods delegating by default (login_type="default"). The `with_login_type` builder

#### The protocol layer

- **API Key namespaces**: `ApiKeyInfo` gains the `namespace: String` field
  (`#[serde(default = "default_namespace")]` filling "default"), with the key format upgraded to
  `garrison:apikey:<namespace>:<key>`. The `generate_with_namespace` method +
  `list_by_namespace` (depending on `GarrisonDao::keys`). `verify` is compatible with the old format
- **The SSO TOCTOU fix**: the atomic `GarrisonDao::get_and_delete(key)` method (the default implementation get→delete two steps, with `GarrisonDaoOxcache` guarding in-process atomicity via `parking_lot::Mutex`).
  `SsoClient::validate_ticket` / `DefaultSsoServer::validate_ticket` moved to atomic consumption, eliminating the race
- **OAuth 2.1 PKCE**: `OAuth2Client::generate_pkce_challenge` (the S256 method,
  verified against RFC 7636 test vectors) + `get_auth_url_with_pkce(state, code_verifier)` +
  `exchange_code_with_pkce(code, state, code_verifier)`. The old `get_auth_url`/`exchange_code` marked `#[deprecated]`
- **Token introspection**: the `OAuth2Client::introspect_token(token)` method
  (RFC 7662) and the `TokenIntrospectionResponse` struct (12 fields: active/scope/client_id/
  username/token_type/exp/iat/nbf/sub/aud/iss/jti). The `with_introspect_url` builder,
  with URL derivation (explicit → the token_url's `/token`→`/introspect` replacement → appending `/introspect`)

#### Session management

- **kickout_by_device**: the `GarrisonSession::kickout_by_device(login_id, device)`
  method — querying the account session → filtering by device → batch logout_by_token

#### Events and strategies

- **The GarrisonEvent 14 variants**: 8 new events (`LoginFailure`/`TokenRefresh`/
  `TokenRevoke`/`SessionTimeout`/`AccountLocked`/`FirewallBlock`/`ApiKeyRotate`/
  `TempCredentialConsumed`), with 8 broadcast integration points (login_with_password
  failures/refresh_token/revoke_token/check_login session timeouts/FirewallCheckHook lockouts/FirewallStrategy
  blocks/ApiKeyHandler::rotate/TempCredentialHandler::consume). `GarrisonEvent` derives
  `PartialEq`. The `ConfigReload` variant is not added because `ConfigLoader` has no reload method — awaiting v0.5.0+
- **The strategy registry**: `src/strategy/registry.rs` adds 6 strategy traits
  (`LoginHandler`/`LogoutHandler`/`PermissionHandler`/`TokenGenerator`/`SessionCreator`/
  `FirewallStrategy`) + 6 default implementations (delegating to `Arc<dyn GarrisonLogic>`) + the `Strategy` registry
  struct (18 register/get/remove methods). `GarrisonManager` holds
  `Arc<RwLock<Strategy>>`, with the `strategy()` getter + the `with_strategy` builder

#### The web adapters

- **ActixContext + WarpContext**: the new `web-actix` enables
  `src/context/actix_adapter.rs` (the ActixContext/ActixRequest/ActixResponse/
  ActixStorage 4-piece set, 34 tests, with the private `ActixRequestWrapper` struct bypassing lifetime limits).
  The new `web-warp` enables `src/context/warp_adapter.rs` (the WarpContext/WarpRequest/
  WarpResponse/WarpStorage 4-piece set, 33 tests, holding owned data). `strip_bearer_prefix` is case-insensitive (RFC 7235)

#### The proc macros

- **The garrison-macros crate**: the new workspace member `garrison-macros`, providing
  the `#[check_login]`/`#[check_permission]`/`#[check_role]` `#[proc_macro_attribute]`s.
  Enabled by the `annotation-macros` feature (depending on `web-axum`). The wrapper + inner function pattern:
  the original fn renamed `__garrison_inner_<name>`, and the wrapper taking the original name returns an `axum::response::Response`.
  `check_login`'s special handling: Ok(false) → 401, Err → forwarded. AND semantics: multiple arguments generate multiple calls.
  13 integration tests covering login/permission/role scenarios

### Changed

- `Cargo.toml` version 0.4.1 → 0.4.2
- `Cargo.toml`'s `[workspace].members` adds `"garrison-macros"`
- `Cargo.toml` adds 4 features: `secure-password` / `annotation-macros` / `web-actix` /
  `web-warp`, all in the `full` aggregate
- `Cargo.toml` adds dependencies: argon2 0.5 / bcrypt 0.15 / rand 0.8 / the garrison-macros path dependency;
  the `protocol-oauth2` feature adds the `sha2` + `base64` dependencies (reused by PKCE S256)
- The `GarrisonDao` trait gains 5 methods, all with default
  implementations for backward compatibility
- `SsoClient::validate_ticket` / `DefaultSsoServer::validate_ticket` moved to the two-step method
  (get validating the client_id → get_and_delete consuming atomically), not consuming the ticket on a client_id mismatch
- `OAuth2Client::get_auth_url` / `exchange_code` marked `#[deprecated]`
- `GarrisonEvent` derives `PartialEq`
- `ApiKeyInfo` gains the `namespace: String` field (`#[serde(default)]` backward compatible)

### Fixed

- **Resolving the SSO validate_ticket spec conflict**: the original implementation "consumed the ticket even on a client_id mismatch" (anti-brute-force)
  conflicted with the test expectation "a client_id mismatch does not delete the ticket" (allowing retries). Moved to the two-step method: first `get` validates the
  client_id, then `get_and_delete` consumes atomically on a match. Satisfying both "user-friendliness" (a wrong client_id does not consume)
  and "the TOCTOU fix" (of concurrent attempts exactly one succeeds)
- **The examples' apikey_management MockDao missing keys()**: after namespace isolation introduced
  `GarrisonDao::keys`, `examples/src/apikey_management.rs`'s MockDao did not implement `keys()`,
  making `ApiKeyHandler::verify`'s scan of new-format keys fail. The `keys()` implementation + a `glob_match` function added
  (consistent with `tests/protocol_apikey_edge_cases.rs`)
- **The RFC 7636 test-vector correction**: the spec's code_verifier `dBjftJeZ4CVP-mB92K29uhjUjUy5YGA`
  (31 chars) does not meet the 43-128 length requirement; replaced with RFC 7636 Appendix B's correct value
  `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk` (43 chars)

### Known limitations

- `GarrisonDao::keys`'s default implementation returns `NotImplemented`, and `GarrisonDaoOxcache` currently returns
  `NotImplemented` too (oxcache 0.3 has no key scan; awaiting the v0.5.0+ upgrade)
- `GarrisonDao::rename`'s default implementation is get→set_permanent→delete, three steps, non-atomic;
  `GarrisonDaoOxcache` overrides it as get→ttl_sync→set_with_ttl_sync→delete, four steps preserving the TTL,
  but still non-atomic (oxcache 0.3 has no atomic rename API; awaiting v0.5.0+)
- `GarrisonEvent::TokenRevoke` is already integrated with broadcast at `revoke_token` calls;
  the `ConfigReload` variant is not added (`ConfigLoader` has no reload method; the variant + broadcast integration await v0.5.0+)
- The `LoginId::String` form's internal-layer (i64) migration is incomplete — the public API accepts `impl Into<LoginId>`
  but `login_id_to_i64` returns `GarrisonError::Config` for the `String` form (the internal-layer migration awaits v0.5.0+)
- The strategy registry's `DefaultFirewallStrategy` is a no-op (`GarrisonLogic` has no
  `check_login_hooks` method), and `DefaultTokenGenerator::generate_token` delegates to `logic.login`
  (the closest method)
- Token introspection caches no results (each call queries the authorization server; caching awaits v0.5.0+)
- PKCE implements the S256 method only (the plain method is deprecated and not implemented)

### Docs and examples

- `garrison-macros/Cargo.toml` + `garrison-macros/src/lib.rs` created (the proc-macro crate
  manifest + the 3 `#[proc_macro_attribute]` implementations)
- `tests/annotation_macros_integration.rs` created (13 integration tests)
- `examples/src/oauth2_flow.rs` adds `#[allow(deprecated)]` for the old PKCE methods
- Test statistics: 1101 lib tests + 80+ integration tests, all passing; clippy zero warnings; fmt passing

## [0.4.0] - 2026-07-02

### Overview

Garrison 0.4.0 focused on closing the 0.2.0 protocol-layer gaps. Via the openspec change
`v0-2-0-protocol-layer-gap-closure`, 7 of the 8 gaps were implemented (gap #4's annotation system deferred to 0.5.0+ because the spec
erroneously referenced the nonexistent `OAuth2Client::validate_client_token`).

### Added

- **The OAuth2 RefreshToken grant type (gap #1)**: the `OAuth2Client::refresh_access_token` method
  supports the grant_type=refresh_token flow, with an optional scope parameter (narrowing/widening the grant)
- **OAuth2 OIDC support (gap #2)**: the new `protocol-oidc` feature + the `OidcHandler` struct
  (sign_id_token / verify_id_token / discovery_metadata), with id_tokens carrying the standard OIDC claims
  (iss/sub/aud/exp/iat/nonce/login_id) and triple validation (iss/aud/nonce) against replay
- **The OAuth2 scope-handler registry (gap #3)**: the new `oauth2-scope-handler` feature +
  the `ScopeHandler` trait + the `ScopeRegistry` struct (parking_lot::RwLock + HashMap);
  after `OAuth2Client::with_scope_registry` injection, the 3 token methods delegate validation before the HTTP request
- **The standalone SSO Server abstraction (gap #5)**: the new `protocol-sso-server` feature + the `SsoServer`
  trait + the `CenterIdConverter` trait + the `SsoChannel` trait + `DefaultSsoServer` +
  `IdentityCenterIdConverter` + `NoopSsoChannel`, communicating indirectly with SsoClients through a shared GarrisonDao
- **The AloneCache multi-Redis-instance isolation (gap #6)**: the new `alone-cache` feature + the `AloneCache`
  decorator (implementing GarrisonDao, prepending the key_prefix at the entrance and delegating to the inner dao) + `AloneCacheManager`
  (a RwLock + HashMap managing multiple instances)
- **The ParameterQuery parameterized query (gap #7)**: the new `parameter-query` feature +
  the `ParameterQuery` trait + the `ParameterQueryBuilder` (chained with_login_id/with_device/with_token
  - async check_permission/check_role), with the token context taking priority over the login_id

### Changed

- `Cargo.toml` adds 5 feature flags: `protocol-oidc` / `oauth2-scope-handler` /
  `protocol-sso-server` / `alone-cache` / `parameter-query`, all in the `full` aggregate
- `Cargo.toml` adds the `base64` dev-dependency (OIDC tests parsing the JWT header segment)
- `OAuth2Client` gains the `scope_registry: Option<Arc<ScopeRegistry>>` field (feature-gated)
- `OAuth2Client`'s 3 token methods gain `validate_scope` calls (feature-gated; skipped without injection)
- `src/protocol/oauth2/mod.rs`'s module docs updated ("three modes"→"four", adding RefreshToken)
- `specmark/specs/dao-oxcache-basic/spec.md` gains a Known Limitations section: oxcache 0.3
  supports standalone/sentinel/cluster, with master-slave covered by the sentinel mode

### Fixed (post-review, the full-dimension review pass)

- **M5 (MEDIUM)**: `SsoClient::validate_ticket` and `DefaultSsoServer::validate_ticket`'s error type on a
  `client_id` mismatch changed from `Config` to `InvalidToken` (authentication-failure semantics are more accurate —
  a ticket held by the wrong party is an authentication failure, not a configuration error). 2 integration-test assertions fixed in sync
  (`tests/protocol_sso_edge_cases.rs` / `tests/protocol_sso_integration.rs`)
- **M6 (MEDIUM)**: `SsoTicketData` was duplicated across `sso::mod.rs` and `sso::server.rs`;
  now exported `pub(crate)` + reused via `use super::SsoTicketData`, preventing format drift
- **M7 (MEDIUM)**: `ParameterQueryBuilder::check_permission` / `check_role` duplicated ~40 lines;
  extracted the `check_common` helper + the `CheckKind` enum, eliminating the duplication
- **M4 (MEDIUM)**: `OidcHandler::with_algorithm` accepted asymmetric algorithms while the implementation supports only symmetric keys;
  the new `require_hmac_algorithm()` validates at the `sign_id_token` / `verify_id_token` entrances,
  returning a `Config` error for asymmetric algorithms. 2 regression tests added
  (`sign_id_token_rejects_asymmetric_algorithm` /
  `verify_id_token_rejects_asymmetric_algorithm`)
- **L9 (LOW)**: the `verify_id_token_tampered_fails` test assertion was weak (only `is_err()`);
  strengthened to assert the `InvalidToken` error type
- **M1 (MEDIUM, a doc warning)**: SSO `validate_ticket`'s non-atomic get→delete has a TOCTOU race;
  explicit warnings added to the `SsoClient` and `SsoServer` trait doc comments, awaiting a unified fix once 0.5.0+ designs the atomic
  get-and-delete

### Docs and examples (completed post-review)

- **The examples cover all of 0.4.0's new features**: 5 new examples (`oidc_handler` / `scope_handler` /
  `sso_server` / `alone_cache` / `parameter_query`), each bin with its own `tests/<name>.rs` test file; `oauth2_flow` extended with a `refresh_access_token` demo section
- **examples/Cargo.toml**: 5 feature forwards added (`protocol-oidc` / `oauth2-scope-handler` /
  `protocol-sso-server` / `alone-cache` / `parameter-query`) + 5 `[[bin]]` sections,
  with the `full` aggregate updated in sync

### Rule-7 conflict exposure (not fixed)

- **M2/M3 (MEDIUM)**: `OAuth2Client::exchange_code`'s `_state` parameter and
  `OAuth2Client::get_password_token`'s `_scope` parameter are unused. They are intentionally kept
  forward-compat API parameters (explained in the doc comments); removing them would break 0.4.0's public API. Kept as-is

### Known limitations

- **Gap #4 (the OAuth2 @CheckAccessToken/@CheckClientToken annotations) deferred to 0.5.0+**: the spec erroneously
  referenced `OAuth2Client::validate_client_token` (a method absent from the codebase). A token
  introspection (RFC 7662) design or a `OidcHandler::verify_id_token` reuse plan was needed first
- **The SSO TOCTOU race (M1)**: `validate_ticket`'s non-atomic get→delete could theoretically allow replaying under concurrent calls on the same ticket. Impact is limited within the 60-second TTL window; security-sensitive scenarios should guard via outer locking or a single-point check.
  A unified fix awaited 0.5.0+ designing the atomic get-and-delete

## [0.3.0] - 2026-07-02

### Overview

Garrison 0.3.0 (the crate was named `bulwark` at release, with `Bulwark*` type prefixes; renamed to
`garrison` since 0.7.1) focused on ecosystem completion and observability: the observability trio (Prometheus metrics / structured JSON logs /
OTLP distributed tracing), the gRPC auth interceptor, fluent i18n for error messages, firewall strategy hooks, actix-web /
warp framework adaptation, and starting the mdbook docs site with CI quality gates.

> Note: this section is a backfill — the original CHANGELOG lacked a 0.3.0 section, and the content was rebuilt from the release commit `e9580a4f`.

### Added

- **The observability trio**:
  - the `metrics-prometheus` feature + `BulwarkMetrics` (now `GarrisonMetrics`):
    `record_login` / `observe_token_validation` / `record_permission_query` /
    `record_role_query`
  - Structured JSON logging: `init_json_logging()` (tracing-subscriber's JSON format)
  - The `observability-otlp` feature (now named `otlp`): `init_otlp_tracing(endpoint)` for OTLP
    distributed-tracing export (including the tracing-opentelemetry bridge at the time, removed in later versions)
- **The gRPC auth interceptor**: the `grpc` feature + `BulwarkGrpcInterceptor` (now
  `GarrisonGrpcInterceptor`, a `tonic::Interceptor` implementation): Bearer token extraction and format validation,
  injecting into request extensions for handlers on success
- **Error-message i18n**: the `i18n` feature (fluent + unic-langid) +
  `locales/{zh,en}.ftl` bilingual resources, with `translate_error` / `current_locale` /
  `set_locale` (`BulwarkLocale`, now `GarrisonLocale`)
- **Firewall strategy hooks**: `BulwarkFirewallCheckHookDefault` (now
  `GarrisonFirewallCheckHookDefault`) performing 5 pre-login checks: login frequency / brute force / anomalous-location login /
  token reuse / device anomaly detection
- **The actix-web / warp framework adapters**: the `web-actix` / `web-warp` features +
  `BulwarkRouter` (now `GarrisonRouter`) + extractors + `BulwarkMiddleware` (actix) +
  `BulwarkRejection`'s unified error responses
- **The mdbook docs site**: the new `mdbook/` documentation site
- **CI quality-gate enhancements**: codeql code scanning + the docs workflow + deny.toml supply-chain checks

### Test coverage

- 748 unit tests passing, 95.41% coverage, clippy + doc zero warnings (release-commit statistics)

## [0.2.1] - 2026-07-01

### Overview

Garrison 0.2.1 is 0.2.0's PATCH release, focused on: the auto-wire gap fix, protocol-layer boundary-scenario test completion,
examples engineering reorganization, and documentation. This version introduces no new protocols or features — only bug fixes and stability optimization.

### Fixed

- **The auto-wire gap (TG4+TG5)**: fixed `GarrisonManager::init` not injecting the PluginManager /
  ListenerManager / AuthLogic / PermissionChecker gap. `GarrisonLogicDefault` gains 4 optional fields
  and builder methods, and `login` / `logout` / `kickout` / `login_by_token` / `refresh_token` now automatically trigger
  plugin hooks and listener events. `GarrisonLogicFactoryFn`'s signature extended to receive `&GarrisonLogicFactoryContext`
  so factories can inject the manager.

### Added (tests and engineering)

- **Protocol-layer boundary-scenario tests (TG6-TG11)**: 6 new test files with 20 boundary-scenario tests
  - OAuth2: refresh_token invalidation / scope boundaries / code replay / expires_in=0
  - SSO: illegal ticket formats / missing centerId mappings / concurrent verification succeeding exactly once
  - JWT: none-algorithm injection rejection / future-iat tolerance / refresh expiry / empty claims
  - Sign: nonce-replay rejection / timestamp drift beyond the window / missing required parameters
  - APIKey: namespace isolation / expiry validation / illegal formats
  - Temp: one-shot credential invalidation / expiry validation / scope overreach
- **auto-wire integration tests (TG5.8)**: 3 new integration tests verifying that `GarrisonUtil::login/logout` automatically triggers
  plugins/listeners
- **examples engineering reorganization (TG2-TG3)**: examples reorganized from scattered `.rs` files into a workspace member
  (the `garrison-examples` crate, `publish = false`), each bin with its own `tests/<name>.rs` test file

### Changed

- `GarrisonLogicFactoryFn`'s type signature extended (a 4th parameter `&GarrisonLogicFactoryContext`)
  — an acceptable incompatibility at the 0.x.x stage; custom factories must adapt to the new signature
- `GarrisonLogicDefault` gains 4 fields (`plugin_manager` / `listener_manager` / `auth_logic` /
  `permission_checker`), all injected via builder methods, backward compatible (behavior identical to 0.2.0 when not injected)

### Docs

- Fixed the unclosed HTML tag `Request<Body>` in `examples/src/context_request.rs`'s module doc
- `cargo doc --no-deps --features full --workspace` zero warnings

### Tests

- 693 tests passing (+30 vs 0.2.0's 663)
- clippy zero warnings (`-D warnings`)
- 90%+ coverage (holding 0.2.0's level)

## [0.2.0] - 2026-07-01

### Overview

On top of 0.1.0's core infrastructure, Garrison 0.2.0 completed the 13 placeholder feature domains, covering all capabilities.
This version adds 17 capabilities, modifies 3, and adds 200+ unit tests + 32 integration tests,
with 92.56% coverage. All protocol and security modules were implemented through the spec-driven TDD workflow.

### Added (17 capabilities)

#### The protocol modules (6)

- **protocol-jwt**: JWT issuance and verification (HS256/HS512, custom claims, expiry validation);
  `JwtHandler` provides `sign(login_id, timeout)` / `verify(token)` / `refresh(token)`
- **protocol-oauth2**: the OAuth2 authorization-code mode, the client-credentials mode,
  and the password mode; `OAuth2Client` provides `exchange_code` / `get_client_credentials_token` /
  `get_password_token` / `get_auth_url`
- **protocol-sso**: the SSO single-sign-on ticket model (issue, verify, destroy), with 64-char random tickets,
  a 60-second TTL, one-shot use; `SsoClient` achieves SSO across subsystems via the shared `GarrisonDao`
- **protocol-sign**: API signature authentication (HMAC-SHA256 + nonce + timestamp anti-replay)
- **protocol-apikey**: API Key authentication (generate/verify/revoke/rotate)
- **protocol-temp**: temporary credentials (short-lived tokens, auto-expiring; issue/get/revoke/consume)

#### The security modules (4)

- **secure-totp**: TOTP dynamic codes (RFC 6238, a 30-second window, 6 digits);
  `TotpHandler` provides `generate(secret)` / `validate(secret, code)`
- **secure-sign**: secure signing utilities (HMAC-SHA256/SHA512, Base64 encoding, MD5 utilities)
- **secure-httpbasic**: HTTP Basic authentication (RFC 7617, Base64 codec)
- **secure-httpdigest**: HTTP Digest authentication (RFC 7616, MD5/SHA256)

#### The core modules (3)

- **core-auth**: the `AuthLogic` trait + `DefaultAuthLogic`, integrating login/verify/refresh
- **core-permission**: the `PermissionChecker` trait + `DefaultPermissionChecker`, supporting RBAC/ABAC
- **core-token**: the `Token` trait + `TokenStyleFactory`, supporting the uuid/random_64/simple/jwt styles

#### The support modules (4)

- **exception-system**: the `GarrisonException` exception-type system (carrying login_type, token_value and other context)
- **json-template**: the `GarrisonJsonTemplate` / `GarrisonSerializer` traits (the JSON template and serialization abstraction)
- **plugin-system**: the `GarrisonPlugin` trait + `GarrisonPluginManager` + inventory compile-time registration,
  with lifecycle hooks (on_login / on_logout / on_permission_check); plugin failures only `tracing::warn!`
- **listener-system**: the `GarrisonListener` trait + `GarrisonListenerManager` + event broadcasting,
  with 6 event variants (Login / Logout / Kickout / PermissionDenied / RoleDenied / TokenExpired)

### Changed (3 capabilities)

- **core-auth-api**: the `GarrisonLogic` trait extended with the `login_by_token` / `verify_token` / `refresh_token`
  default methods (backward compatible with 0.1.0); fixed `generate_token`'s support for the "jwt" style (delegating to `JwtHandler::sign`)
- **session-management**: `GarrisonSession` extended to support SSO-ticket and temporary-credential associations
- **permission-role-check**: `GarrisonFirewallStrategyDefault` extended, integrating `PermissionChecker`,
  supporting role hierarchy, plugin hooks, and permission-cache short-circuits

### Docs and examples

- **Crate-level docs**: the 0.2.0 module overview added, with the default-feature description corrected
- **Protocol/security module docs**: placeholder descriptions removed, implementation references added
- **Example code**:
  - `examples/jwt_login.rs`: the full JwtHandler sign/verify/refresh flow
  - `examples/oauth2_flow.rs`: OAuth2Client construction + get_auth_url
  - `examples/sso_flow.rs`: SsoClient ticket issue/verify/destroy (with InMemoryDao)
  - `examples/totp_login.rs`: TotpHandler generate/validate + Base32 decoding

### Integration tests

- **tests/protocol_jwt_integration.rs** (4 tests): the full JWT login/verify/refresh/logout flow
- **tests/protocol_oauth2_integration.rs** (7 tests): a wiremock mock authorization server,
  covering the Authorization Code / Client Credentials / Password flows
- **tests/protocol_sso_integration.rs** (9 tests): cross-subsystem ticket issue → verify → destroy,
  verifying one-shot use, client_id isolation, and cross-subsystem destroy effectiveness
- **tests/plugin_listener_integration.rs** (12 tests): inventory compile-time registration +
  hook invocation + event broadcasting + end-to-end lifecycle coordination

### Test coverage

- **lib tests**: 565
- **integration tests**: 43 (annotation 9 + axum 11 + dbnexus 10 + jwt 4 + oauth2 7 + sso 9 + plugin_listener 12)
  - Note: some tests recompile under multiple feature combinations; the full run reports 633 tests passed
- **doc-tests**: 6 passed, 9 ignored
- **Coverage**: 92.56% (1430/1545 lines), above the 90% target

### Feature domains

| Feature domain  | Status  | Notes                             |
| --------------- | ------- | --------------------------------- |
| Login authentication        | ✅ Done | Token-based session management             |
| Permission authorization        | ✅ Done | The RBAC permission model + PermissionChecker |
| Sessions    | ✅ Done | Dual-mode sessions + SSO/temp associations          |
| Route-interception auth    | ✅ Done | The axum web framework adapter                 |
| Pluggable extensions      | ✅ Done | GarrisonPlugin + inventory registration   |
| OAuth2          | ✅ Done | Three authorization modes                      |
| Single sign-on (SSO)  | ✅ Done | The ticket model + cross-subsystem            |
| JWT             | ✅ Done | HS256/HS512 + refresh             |
| Microservice gateway auth  | ✅ Done | API signature authentication                      |
| API endpoint auth    | ✅ Done | API Key authentication                      |
| TOTP dynamic codes | ✅ Done | RFC 6238                          |
| Basic auth      | ✅ Done | RFC 7617                          |
| Digest auth     | ✅ Done | RFC 7616                          |

### Known limitations

- **The auto-wire gap**: `GarrisonLogicDefault` currently holds no `GarrisonPluginManager` / `GarrisonListenerManager`,
  so `GarrisonUtil::login` does not automatically fire `on_login` / `Login` events — users must call the
  plugin/listener managers manually at the business layer. This auto-wire is implemented in deferred tasks 13.4/13.5
- **login_by_token's default implementation**: `GarrisonLogicDefault` does not override `login_by_token` (returning `NotImplemented`);
  the OAuth2/SSO scenarios need the protocol-layer clients directly
- **oxcache 0.3's `Cache<K,V>::update`**: cannot preserve per-entry TTL (as in 0.1.0)
- **dbnexus 0.2**: SQLite only (as in 0.1.0)

### The minimum supported Rust version

- Rust 1.85+ (as in 0.1.0)

## [0.1.0] - 2026-06-30

### Overview

Garrison 0.1.0 is the first milestone release, implementing the identity authentication framework's core infrastructure.
It provides token-based session management, the RBAC permission model,
and axum web framework integration.

### Added

#### Core infrastructure

- **The error-type system**: the `GarrisonError` enum, covering 12 variants
  (NotLogin / NotPermission / NotRole / InvalidToken / ExpiredToken / Dao / Config / Internal / Session / Annotation / Context)
- **The configuration system**: the `GarrisonConfig` global configuration, supporting the three-tier config sources of code defaults / a toml file / environment variables,
  with hot reload via `tokio::sync::watch`
- **The context abstraction**: the `GarrisonContext` / `GarrisonRequest` / `GarrisonResponse` / `GarrisonStorage` traits,
  decoupling web-framework dependencies; the axum adapters `AxumRequest` / `AxumResponse` / `AxumStorage` / `AxumContext` provided

#### The data-access layer

- **The DAO abstraction**: the `GarrisonDao` trait, providing the get / set / update / delete / expire five-operation set
- **The oxcache 0.3 integration**: the `GarrisonDaoOxcache` implementation supporting per-entry TTL,
  preserving the original TTL via `Cache<K,V>::ttl()` (depending on a local oxcache repository)
- **The dbnexus 0.2 integration**: `init_dbnexus` initialization + `GarrisonMigration`'s 8 core-table migrations
  (users / oauth2_accounts / roles / permissions / user_roles / user_permissions / sessions / user_ext)

#### Sessions and authentication

- **Dual-mode session management**: `GarrisonSession` supports Account-Sessions (indexed by login_id) + Token-Sessions (indexed by token)
- **The core authentication APIs**: the `GarrisonLogic` trait defining the full login / logout / check_login / kickout contract,
  with the `GarrisonLogicDefault` default implementation
- **The task_local context**: `with_current_token` / `current_token` for async request-level token access
- **The permission-check strategy**: the `GarrisonFirewallStrategy` trait + the `GarrisonFirewallStrategyDefault` default implementation

#### The global manager

- **The GarrisonManager singleton**: holding the `Arc<dyn GarrisonLogic>` global reference, supporting explicit `init()` initialization
  - Overwriting updates + `reset_for_test()` (cfg(test))
