# ⚡ Garrison Performance Guide

This guide summarizes Garrison's performance design points, benchmarking methodology, and optimization advice. Garrison's performance targets use the authentication framework's hot paths as the scope: the login chain (including password hashing) and per-request stateless verification (token validation, permission checks).

> Applicable version: 0.9.0 (rc.4 adds the Redis rate-limit backend). This document publishes no absolute timing figures (criterion interval estimates vary by machine); benchmarks are reproduced locally with `cargo bench`, and the acceptance performance baseline follows the `logs/perf.jsonl` produced by `scripts/e2e_run.sh`.

## 📋 Table of Contents

- [Performance Targets](#-performance-targets)
- [Benchmarks](#-benchmarks)
- [Acceptance Performance Baseline (E2E)](#-acceptance-performance-baseline-e2e)
- [Performance Design Points](#️-performance-design-points)
- [Optimization Advice](#️-optimization-advice)
- [v1.0 Performance Baseline Capture](#-v10-performance-baseline-capture)
- [Related Documents](#-related-documents)

---

## 🎯 Performance Targets

The following targets are defined at the top of [`benches/garrison_benchmark.rs`](../../benches/garrison_benchmark.rs) (design acceptance scope):

| Benchmark scenario | Target |
|----------|------|
| `login_flow` | ≤ 500ms (at 5000 TPS scope) |
| `token_verify_stateless` | ≤ 5ms (at 20000 TPS scope) |
| `permission_check` | ≤ 5ms (at 20000 TPS scope) |
| `oxcache_backend_switch` | Backend-switch overhead = 0 |
| `convert_placeholders` | SQL dialect conversion microbenchmark (upgrade-adaptation surface for in-house dependencies; no threshold target) |
| `circuit_execute_closed_passthrough` | Circuit-breaker wrapper passthrough-overhead microbenchmark (backend-remote path; no threshold target) |

The acceptance layer additionally carries an HTTP end-to-end performance baseline: **P99 < 200ms / 1000 RPS** (see "Acceptance Performance Baseline" below).

---

## 📊 Benchmarks

The Criterion benchmarks live in `benches/garrison_benchmark.rs` (registered via `[[bench]]`, `harness = false`), covering 6 scenarios: `login_flow`, `token_verify_stateless`, `permission_check`, `oxcache_backend_switch` (memory ↔ redis_mock backend switching), `convert_placeholders`, and `circuit_execute_closed_passthrough` (the last two are upgrade-adaptation microbenchmarks without threshold targets).

```bash
# Compile check (no run)
cargo bench --no-run

# Quick run (fewer samples)
cargo bench -- --quick

# Enable real JWT verification
cargo bench --features protocol-jwt

# Full-feature run
cargo bench --features full

# The actual invocation of e2e_matrix stage S6 (--bench limits to the criterion target;
# a bare cargo bench also runs lib unittests under the bench profile, which do not
# understand criterion arguments)
cargo bench --bench garrison_benchmark --features full --locked -- \
    --quick --save-baseline e2e
```

Pass criteria: no `Regressed` verdict from criterion; baselines live in `target/criterion` for later comparison. Note: `permission_check` under `tenant-isolation` (the full face) explicitly enters the default tenant 0 context (equivalent to the server middleware behavior), otherwise it panics for lack of a `TENANT.scope`.

---

## 📈 Acceptance Performance Baseline (E2E)

The performance baseline is fixed in the acceptance suite's `#[ignore]` cases (`tests/acceptance/concurrency.rs`, `perf_*` prefix), driving a real HTTP service and captured by the `LoadRunner` of the `perf_util` module over direct `reqwest` connections:

```bash
# Option 1: one shot (starts auth_server_serve → full acceptance → perf baseline → aggregate report)
EXAMPLE_INTERNAL_API_KEY=$(openssl rand -hex 16) bash scripts/e2e_run.sh

# Option 2: perf baseline only (appends to logs/perf.jsonl)
cargo test --test acceptance --features "full testing" perf_ -- \
    --nocapture --test-threads=1 --ignored

# Option 3: aggregate existing JSONL logs into a Markdown report
python3 scripts/e2e_analyze.py --log-dir logs
```

Artifacts: `logs/perf.jsonl` (one JSON sample per line) and `logs/e2e_final_report.md` (the combined report).

Verdict rules (`assert_perf_baseline`):

- **debug builds**: soft warning — the login chain involves argon2/bcrypt, so a P99 of about 1.1s under debug is expected and does not meet the target;
- **release builds**: hard failure (panic). Hard verdicts against an external release service are injected via `GARRISON_E2E_EXTERNAL_URL` / `GARRISON_E2E_INTERNAL_URL` / `GARRISON_E2E_API_KEY` (the `RemoteContext::connect_env` path).

Report-side parity: each sample in `logs/perf.jsonl` carries the build tier `profile`, and `scripts/e2e_analyze.py` marks below-target items with ⚠️ soft warning (non-blocking) for `profile=debug` and ❌ failure for the release tier — avoiding the discrepancy of "report says ❌, same-round tests passed".

Methodology record (`perf_login` baseline recalibration, 2026-09-11): the load test rotates 100 accounts (`LoadRunner::with_body_fn`) to measure realistic multi-user traffic rather than single-account concurrency — the login path has a per-login_id mutex (`GarrisonSession::with_login_lock`, a TOCTOU fix, by design: protecting read-modify-write atomicity of the same account's Account-Session), so single-account concurrency inevitably serializes (measured P99 about 700ms). Same-account concurrency correctness is covered by the concurrency-domain race tests.

---

## 🏗️ Performance Design Points

Every point below is traceable in the CHANGELOG and the source:

| Design | Location / source | Description |
|------|-------------|------|
| Lock-free global singleton | `GarrisonManager` (CHANGELOG) | The `logic` / `strategy` fields migrated from `parking_lot::RwLock<Option<Arc<..>>>` to `arc_swap::ArcSwapOption`; the hot path `GarrisonManager::logic()` (called per request in `backend/embedded.rs`) does a lock-free atomic load, eliminating cache-line contention at multi-core high QPS |
| Lock-free global backend reference | `CURRENT_BACKEND` | `Mutex<Option<Arc<..>>>` → `ArcSwapOption` (the `BackendHandle` Sized wrapper); the check_login / check_permission hot paths drop the global lock while concurrent initialization keeps CAS semantics |
| Slow hashing off the async executor | `spawn_blocking` | Every login-path call site of bcrypt / Argon2 hash / verify wraps `tokio::task::spawn_blocking`, so login storms never block tokio workers |
| Argon2 concurrency token pool (login-path memory capacity model) | `argon2_pool_size` (default 1) | Under login storms the Argon2 memory-residency upper bound = `pool_size × m_cost` KiB (default 1 × 19 MiB): the permit is acquired async before `spawn_blocking` and moved into the closure, its lifetime == the hash execution, so no cancellation ordering can oversell; waiting callers queue asynchronously (throughput degrades to serialized hashing instead of memory bloat). Together with login-QPS rate limiting it forms two-layer protection — rate limiting governs arrival rate, the pool governs memory residency; tune by `memory budget ÷ m_cost` while keeping `pool_size ≤ QPS rate-limit threshold` |
| Credit activity write-path throttling (persist-history write-amplification capacity model) | `ActivityWriteThrottle` (`credit-metering`, enabled by default in `CreditMeter`) | persist_history's SQL ledger INSERTs are aggregated by default through a debounce window: per key (`{tenant}:{resource}`) only one row lands per 10s window (first consumption in the window consumes the snapshot), reducing write amplification from one INSERT per request to ≤ 1 per key per 10s under high-frequency consumption. Capacity constraints: pending-entry cap of 1000 (check and insert are two synchronous operations, so multithreaded races may briefly exceed by one writer-window's soft bound; the enqueue path never blocks); when full, new keys are dropped non-blockingly with the drop count warned (drop = skip this persistence, rewrite outside the window); each persistence write times out at 3s, failed/timed-out entries are cleaned without retry; pending entries live in memory only and are not persisted on process exit (heartbeats are idempotent; the next activity rewrites). Constant provenance: pomerium `access_tracker.go:20-24` (1000 / 10s / 3s). Per-entry ledger reconciliation needs can disable it explicitly via `CreditMeter::without_activity_throttle()` |
| TokenSession intra-request reuse | — | `is_valid_with_session` returns a snapshot for hover reuse, cutting repeated reads within one request from 3-4 to 1-2; the task_local `CURRENT_LOGIN_ID` cache gives `get_login_id` / `check_permission` cache hits with zero DAO reads (logout / kickout / revoke invalidate immediately) |
| Compile-time registration | `inventory::submit!` | Plugin / listener factories register at compile time — zero runtime reflection, zero dynamic loading |
| Three-tier cache + TTL jitter | `oxcache` integration | The L1 memory layer expires per-entry with fine-grained TTL; L1 writes jitter ±10% automatically via oxcache `CacheBuilder::ttl_jitter`, and L2 jitters identically via `UserCacheService::l2_ttl_with_jitter`, preventing cache avalanches from mass simultaneous expiry |
| Configurable L1 capacity | `l1_cache_capacity` | `UserCacheService::new_with_capacity` wires `GarrisonConfig::l1_cache_capacity` (was silently ineffective, fixed) |
| Full feature gating | `Cargo.toml [features]` | Unenabled protocols / firewalls / web adapters do not compile, controlling build time and binary size |
| Distributed rate limiting | `limiteron` passthrough | Sliding window on Redis Sorted Sets (Lua scripts, O(1) memory per entry); GCRA / quotas go through limiteron sub-features |
| Redis rate-limit backend (`rate-limit-redis`) | `RedisLimiterBackend` | The login hook and `RateLimitStrategy` can switch to an independent Redis rate-limit runtime: counters run as atomic Lua EVAL, sliding windows on Sorted Sets; up to 4 Redis EVALs per login (2 record + 2 check), eval timeout 1s, fail-closed on faults. Compared with in-process counting it trades network RTT for multi-instance consistency; high-throughput deployments should split the rate-limit Redis from the business cache by instance/DB |

---

## 🛠️ Optimization Advice

1. **Pick the right storage backend**: use the `development` preset for development (in-memory DAO); use `cache-redis` + `db-postgres`/`db-mysql` for production, with the L1 memory layer absorbing hot-path reads. Note dbnexus's two compile-time `compile_error!` exclusivity constraints: (1) embedded (sqlite / duckdb) ⊕ server-side (postgres / mysql) cannot mix; (2) without an embedded backend, `postgres` and `mysql` are mutually exclusive — together: "at most one relational backend enabled".
2. **Enlarge the L1 cache**: for read-heavy, write-light scenarios set `l1_cache_capacity` explicitly (default 10000); the higher the hit rate, the fewer DAO round-trips.
3. **Run performance verification on release builds**: `assert_perf_baseline` hard-judges only under release; password hashing is naturally an order of magnitude slower in debug, so never evaluate login performance with debug numbers.
4. **Keep the feature surface minimal**: unenabled capabilities cost zero (compiled out); the aggregate `full` is for validation only — compose per need in production.
5. **Reuse intra-request snapshots in multi-tenant scenarios**: `get_login_id` / `check_permission` hit the task_local cache within the same request (zero DAO reads); avoid re-parsing tokens manually inside handlers.
6. **Load-test with multi-account rotation**: never load-test the login endpoint with a single account (it will be serialized by the per-login_id lock, see the methodology record above); rotate 100 accounts to simulate realistic traffic.
7. **Tune the Argon2 pool by memory budget**: raising `argon2_pool_size` improves login-storm throughput at the cost of a linearly growing memory-residency bound (`pool_size × m_cost`); fix the memory budget first and derive the pool size — do not raise blindly (range `[1, 256]`; 256 × 19 MiB ≈ 4.8 GiB).
8. **Build baseline comparisons**: before committing changes that may affect hot paths, `--save-baseline` a baseline; criterion auto-compares and reports `Regressed` afterward.
9. **Multi-instance rate-limit choice**: enable `rate-limit-redis` for multi-instance deployments in exchange for global counter consistency; keep `memory` (the default) on single-instance/edge nodes where login latency is paramount, avoiding network RTT for limits that never materialize.

---

## 📈 v1.0 Performance Baseline Capture

The v1.0 performance gate uses "same-machine relative baselines" and publishes no absolute timing figures:

```bash
bash scripts/perf_baseline.sh                 # capture the v1.0-pre baseline
BASELINE=v1.0-pre bash scripts/perf_baseline.sh --quick
```

The script records git SHA / rustc / cargo / CPU model, runs `cargo bench --features full --bench garrison_benchmark -- --save-baseline <name>`, and emits `logs/perf-baseline.md`; the criterion HTML report stays in `target/criterion` (not committed). For acceptance, re-run on the same machine and compare against the baseline, watching regression direction rather than absolute values.

### Regression verdict (`scripts/perf_compare.sh`)

`scripts/perf_compare.sh` captures the current criterion results and diffs them against the baseline, emitting a "percentage change + threshold verdict" summary table (artifact `logs/perf-compare.md`):

```bash
bash scripts/perf_compare.sh                                  # default baseline v1.0-pre, threshold 10%
BASELINE=v1.0-pre THRESHOLD=5 bash scripts/perf_compare.sh    # custom threshold
BASELINE_MD=docs/en/benchmarks-v1.0-baseline.md bash scripts/perf_compare.sh   # explicit archived baseline
bash scripts/perf_compare.sh --help                           # usage and exit-code semantics
```

The baseline source is resolved by priority: (1) the archived markdown named by `BASELINE_MD`; (2) a local criterion baseline (`target/criterion/**/<baseline>/estimates.json`, not committed); (3) when both are absent, the script auto-matches an archived markdown by "baseline name" under `docs/benchmarks/` — that directory no longer exists after the bilingual docs reorganization, so the auto-match currently always fails (explicit exit 2); pass the committed baseline explicitly via `BASELINE_MD=docs/en/<baseline>.md` instead.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | No regression beyond the threshold |
| 1 | Regressions beyond the threshold exist (count of `+N%` over-threshold items in the summary table) |
| 2 | No comparable data / capture failure / baseline parse failure (explicit error, never silently treated as pass) |

### Baseline refresh and archiving SOP

1. **Refresh**: on the target machine run `BASELINE=<new-baseline> bash scripts/perf_baseline.sh` (`--quick` for fast sampling, draft comparisons only); the artifact `logs/perf-baseline.md` records git SHA / toolchain / CPU.
2. **Archive**: copy `logs/perf-baseline.md` to `docs/en/<baseline>.md` (e.g. `docs/en/benchmarks-v1.0-baseline.md`) and commit — the archived markdown's "baseline name" field is `perf_compare.sh`'s auto-match key.
3. **Self-check**: run once with the archived baseline via `BASELINE_MD=docs/en/<baseline>.md bash scripts/perf_compare.sh`, confirming a comparison table is produced and the exit code matches expectations (a baseline parse failure exits 2 explicitly).
4. **Switching baselines**: when updating the default baseline name, also update `scripts/perf_compare.sh`'s `BASELINE` default, the archived file names under `docs/en/`, and the baseline references in `docs/en/ROADMAP.md` / `docs/en/CHANGELOG.md`.

---

## 📚 Related Documents

| Document | Description |
|------|------|
| [🧪 Test Scenarios](TEST_SCENARIOS.md) | Acceptance scenario inventory, performance baseline cases, and known-issue records |
| [🏗️ Architecture](ARCHITECTURE.md) | Module layout, data flow, and design decisions |
| [⚙️ Configuration](CONFIGURATION.md) | Cache / session / token strategy config items |
| [🚀 Deployment](DEPLOYMENT.md) | Production deployment notes (TLS, connection pools, caching) |
