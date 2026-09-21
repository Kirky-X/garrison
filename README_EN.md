<!-- markdownlint-disable MD041 -->
<div align="center">

<img src="docs/assets/logo.png" alt="Garrison Logo" width="200">

[![CI Status](https://github.com/Kirky-X/garrison/actions/workflows/ci.yml/badge.svg)](https://github.com/Kirky-X/garrison/actions/workflows/ci.yml) [![Version](https://img.shields.io/crates/v/garrison.svg)](https://crates.io/crates/garrison) [![Docs.rs](https://docs.rs/garrison/badge.svg)](https://docs.rs/garrison) [![Downloads](https://img.shields.io/crates/d/garrison.svg)](https://crates.io/crates/garrison) [![License](https://img.shields.io/crates/l/garrison.svg)](LICENSE) [![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/) [![Coverage](https://img.shields.io/badge/coverage-95%25%2B-brightgreen.svg)](https://github.com/Kirky-X/garrison)

[中文](README.md) | **English**

**One-stop authentication &amp; authorization framework for the Rust ecosystem**

[✨ Features](#-features) • [🚀 Quick Start](#-quick-start) • [📚 Documentation](#-documentation) • [💻 Examples](#-examples) • [🤝 Contributing](#-contributing)

</div>

---

<div align="center">

### 🎯 Annotate Guard Points, Call Stateless APIs

Inject your dependencies into `GarrisonManager` once at startup — from login to logout, the framework takes care of the rest:

<table style="width:100%; border-collapse: collapse">
<tr>
<td align="center" width="25%">🧩<br><b>Annotation-Driven</b><br><span style="color:#64748B">10 attribute macros · declarative wiring</span></td>
<td align="center" width="25%">🔀<br><b>Dual-Mode Sessions</b><br><span style="color:#64748B">Account-level · Token-level · Multi-device</span></td>
<td align="center" width="25%">🌐<br><b>Web Integration</b><br><span style="color:#64748B">axum · actix · warp</span></td>
<td align="center" width="25%">⚙️<br><b>Feature Gating</b><br><span style="color:#64748B">100+ flags · compile only what you need</span></td>
</tr>
</table>

</div>

---

## 📋 Table of Contents

- [✨ Features](#-features)
- [🚀 Quick Start](#-quick-start)
- [🎨 Feature Flags](#-feature-flags)
- [📚 Documentation](#-documentation)
- [💻 Examples](#-examples)
- [🏗️ Architecture](#️-architecture)
- [🧪 Testing](#-testing)
- [📊 Performance](#-performance)
- [🔒 Security](#-security)
- [🗺️ Roadmap](#️-roadmap)
- [🤝 Contributing](#-contributing)
- [📋 Changelog](#-changelog)
- [📄 License](#-license)
- [🙏 Acknowledgments](#-acknowledgments)
- [📞 Contact & Support](#-contact--support)
- [⭐ Star History](#-star-history)

---

## ✨ Features

<table style="width:100%; border-collapse: collapse">
<tr>
<td width="50%" style="vertical-align:top; padding: 12px">⚡ <b>Zero Runtime Overhead</b><br><span style="color:#64748B">Compile-time <code>inventory::submit!</code> factory registration — no reflection, no dynamic loading</span></td>
<td width="50%" style="vertical-align:top; padding: 12px">🔒 <b>Full Auth Chain</b><br><span style="color:#64748B">Login → Permission Check → Session Management → Route Interception, out of the box</span></td>
</tr>
<tr>
<td width="50%" style="vertical-align:top; padding: 12px">📦 <b>Multi-Backend Abstraction</b><br><span style="color:#64748B"><code>GarrisonDao</code> + <code>oxcache</code> + <code>dbnexus</code> — switch storage backends with zero business code changes</span></td>
<td width="50%" style="vertical-align:top; padding: 12px">🔧 <b>Pluggable Extensions</b><br><span style="color:#64748B">trait + Default pattern — replace any component (DAO / Strategy / Logic) without touching business code</span></td>
</tr>
<tr>
<td width="50%" style="vertical-align:top; padding: 12px">🎯 <b>Feature Gating</b><br><span style="color:#64748B">100+ feature flags — compile only what you need</span></td>
<td width="50%" style="vertical-align:top; padding: 12px">📊 <b>High Observability</b><br><span style="color:#64748B"><code>tracing</code> logging + <code>listener</code> event subscriptions + <code>prometheus</code> metrics (optional)</span></td>
</tr>
<tr>
<td width="50%" style="vertical-align:top; padding: 12px">🧪 <b>High Coverage</b><br><span style="color:#64748B">5300+ tests (≈4800 lib + ≈530 acceptance/integration/examples), 95%+ line coverage, clippy zero warnings</span></td>
<td width="50%" style="vertical-align:top; padding: 12px">🌐 <b>Web Framework Adapters</b><br><span style="color:#64748B">axum/actix/warp annotation-style extractors + proc macros</span></td>
</tr>
</table>

Beyond the core capabilities above, everything else (auth protocols, firewall, account security, multi-tenancy, observability, microservice building blocks, etc.) ships as independent, opt-in feature flags — see the [🎨 Feature Flags](#-feature-flags) section for the complete per-flag matrix.

---

## 🚀 Quick Start

### 📦 Installation

Add the following to your `Cargo.toml` (`development` preset = in-memory cache DAO + SQLite + axum adapter):

```toml
[dependencies]
garrison = { version = "0.9.0-rc.2", features = ["development"] }
async-trait = "0.1"
tokio = { version = "1", features = ["full"] }
```

Requires Rust 1.85 or later (MSRV, see `rust-version` in `Cargo.toml`).

> Pre-release versions require the full version number; `"0.9"` will not match prerelease. To enable all protocol and security modules: `features = ["full"]`.

| Preset | Installation | Use Case |
|--------|-------------|----------|
| Development | `features = ["development"]` | In-memory cache + SQLite + axum, quick validation |
| Production | `features = ["production"]` | Recommended production combination |
| Full | `features = ["full"]` | All capabilities |

### 💡 Minimal Example

The following example is adapted from [`examples/src/bin/readme_quickstart.rs`](examples/src/bin/readme_quickstart.rs) (complete business flow: initialize manager → log in → verify login state → log out):

```rust
use std::sync::Arc;
use garrison::prelude::*;
use async_trait::async_trait;

// 1. Implement GarrisonInterface (provides permission/role data)
struct MyInterface;
#[async_trait]
impl GarrisonInterface for MyInterface {
    async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec!["user:read".into(), "user:write".into()])
    }
    async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec!["user".into()])
    }
}

#[tokio::main]
async fn main() -> GarrisonResult<()> {
    // 2. Prepare dependencies
    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoOxcache::new().await?);
    let config = Arc::new(GarrisonConfig::default_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MyInterface);

    // 3. Initialize global manager
    GarrisonManager::builder()
        .dao(dao).config(config).interface(interface)
        .build().await?;

    // 4. Execute login in task_local context
    let token = garrison::stp::with_current_token(
        String::new(), GarrisonUtil::login("1001", &LoginParams::default()),
    ).await?;
    println!("Login successful, token = {}", &token[..8.min(token.len())]);

    // 5. Verify login state
    garrison::stp::with_current_token(token.clone(), GarrisonUtil::check_login()).await?;

    // 6. Verify permission
    garrison::stp::with_current_token(
        token.clone(), GarrisonUtil::check_permission("user:read"),
    ).await?;

    // 7. Log out
    garrison::stp::with_current_token(token.clone(), GarrisonUtil::logout()).await?;
    Ok(())
}
```

```bash
cargo run -p garrison-examples --bin readme_quickstart --features "cache-memory"
# Output: Login successful, token = <8-char random token prefix>
```

> This example is continuously validated by [examples/tests/readme_quickstart.rs](./examples/tests/readme_quickstart.rs) (runs with CI); its business code mirrors [`examples/src/web/readme_quickstart.rs`](examples/src/web/readme_quickstart.rs) verbatim.

### 🧭 Core Concepts

- **Global Singleton + Static API**: `GarrisonManager` injects dao / config / interface once at startup; business code then uses the stateless `GarrisonUtil` static API.
- **Token Context**: the token is carried via a task_local context (`garrison::stp::with_current_token`) that web middleware binds automatically, and static APIs read the current token automatically.
- **Dual-Mode Sessions**: Account-Session (account-level) and Token-Session (login-level) are controlled by `is_share` / `is_concurrent` for the multi-device policy.
- **Feature Gating**: every optional capability is an independent feature, so compiled artifacts only include what you enable.

> For deeper coverage (token context, dual abstraction storage, etc.), see the [📖 User Guide · Core Concepts](docs/USER_GUIDE.md#-核心概念).

---

## 🎨 Feature Flags

### 📋 Feature Matrix

The table below mirrors the `[features]` section of `Cargo.toml`, where `default = ["backend-embedded"]`.

<table style="width:100%; border-collapse: collapse">
<tr><th style="text-align:left">Feature</th><th style="text-align:center">Default</th><th style="text-align:left">Description</th></tr>
<tr><td><code>backend-embedded</code></td><td align="center">✅</td><td>Embedded backend mode (in-process auth, delegates to GarrisonManager)</td></tr>
<tr><td><code>backend-remote</code></td><td align="center">❌</td><td>Remote backend adapter (auth via HTTP to remote Auth Server)</td></tr>
<tr><td><code>backend-kit</code></td><td align="center">❌</td><td>trait-kit typestate DI construction</td></tr>
<tr><td><code>auth-server</code></td><td align="center">❌</td><td>Standalone auth server (sdforge declarative routing + TLS)</td></tr>
<tr><td><code>abac</code></td><td align="center">❌</td><td>Cedar DSL-based attribute-based access control engine</td></tr>
<tr><td><code>oauth2-server</code></td><td align="center">❌</td><td>Full OAuth2 Server 4 endpoints</td></tr>
<tr><td><code>cache-memory</code></td><td align="center">❌</td><td>In-memory cache backend (oxcache L1)</td></tr>
<tr><td><code>cache-redis</code></td><td align="center">❌</td><td>Redis cache backend (oxcache L2)</td></tr>
<tr><td><code>db-sqlite</code></td><td align="center">❌</td><td>SQLite database backend</td></tr>
<tr><td><code>db-postgres</code></td><td align="center">❌</td><td>PostgreSQL backend</td></tr>
<tr><td><code>db-mysql</code></td><td align="center">❌</td><td>MySQL backend</td></tr>
<tr><td><code>web-axum</code></td><td align="center">❌</td><td>axum Web framework adapter</td></tr>
<tr><td><code>web-actix</code></td><td align="center">❌</td><td>actix-web framework adapter</td></tr>
<tr><td><code>web-warp</code></td><td align="center">❌</td><td>warp framework adapter</td></tr>
<tr><td><code>web-waf</code> / <code>web-cors</code> / <code>web-csrf</code></td><td align="center">❌</td><td>WAF / CORS / CSRF middleware</td></tr>
<tr><td><code>protocol-jwt</code></td><td align="center">❌</td><td>JWT issuance &amp; validation (HS256/HS512 + refresh)</td></tr>
<tr><td><code>protocol-oauth2</code></td><td align="center">❌</td><td>OAuth2 four modes</td></tr>
<tr><td><code>protocol-sso</code> / <code>protocol-sso-server</code></td><td align="center">❌</td><td>SSO ticket / SSO Server abstraction</td></tr>
<tr><td><code>protocol-sign</code></td><td align="center">❌</td><td>API signing + nonce anti-replay</td></tr>
<tr><td><code>protocol-apikey</code></td><td align="center">❌</td><td>API Key auth</td></tr>
<tr><td><code>protocol-temp</code></td><td align="center">❌</td><td>Temporary credentials</td></tr>
<tr><td><code>protocol-oidc</code></td><td align="center">❌</td><td>OIDC id_token issuance/validation + discovery</td></tr>
<tr><td><code>protocol-httpbasic</code> / <code>protocol-httpdigest</code></td><td align="center">❌</td><td>HTTP Basic / Digest auth</td></tr>
<tr><td><code>protocol-saml</code></td><td align="center">❌</td><td>SAML 2.0 skeleton</td></tr>
<tr><td><code>protocol-zeroize</code></td><td align="center">❌</td><td>Protocol-layer key zeroization</td></tr>
<tr><td><code>secure-totp</code></td><td align="center">❌</td><td>TOTP (RFC 6238)</td></tr>
<tr><td><code>secure-sign</code></td><td align="center">❌</td><td>HMAC-SHA256/SHA512 utilities</td></tr>
<tr><td><code>secure-confusable</code> / <code>secure-masking</code> / <code>secure-xss</code> / <code>secure-sanitize</code></td><td align="center">❌</td><td>Security toolset</td></tr>
<tr><td><code>secure-simple-token</code> / <code>secure-ct-eq</code></td><td align="center">❌</td><td>Signing / constant-time comparison</td></tr>
<tr><td><code>account-credential</code> / <code>account-policy</code> / <code>account-lockout</code> / <code>account-authflow</code></td><td align="center">❌</td><td>Account security engine</td></tr>
<tr><td><code>firewall</code> / <code>firewall-*</code></td><td align="center">❌</td><td>Security suite (brute-force / rate-limit / anomalous / GeoIP / DDoS / WAF)</td></tr>
<tr><td><code>listener</code></td><td align="center">❌</td><td>Event listeners (15 event variants)</td></tr>
<tr><td><code>tracing-log</code> / <code>metrics-prometheus</code> / <code>otlp</code></td><td align="center">❌</td><td>Observability</td></tr>
<tr><td><code>annotation-macros</code></td><td align="center">❌</td><td>10 attribute macros</td></tr>
<tr><td><code>tenant-isolation</code></td><td align="center">❌</td><td>Multi-tenant logical isolation</td></tr>
<tr><td><code>social-wechat</code> / <code>social-alipay</code></td><td align="center">❌</td><td>Social login</td></tr>
<tr><td><code>core-advanced</code> / <code>session-extra</code></td><td align="center">❌</td><td>Core enhancements / Session enhancements merged</td></tr>
<tr><td><code>email-verification</code> / <code>email-verification-smtp</code></td><td align="center">❌</td><td>Email verification codes</td></tr>
<tr><td><code>config-*</code></td><td align="center">❌</td><td>Config file encryption/validation/hot-reload/interpolation/dynamic/toggle (confers passthrough)</td></tr>
<tr><td><code>i18n</code> / <code>i18n-icu</code></td><td align="center">❌</td><td>Internationalization</td></tr>
<tr><td><code>full</code> / <code>production</code> / <code>development</code></td><td align="center">❌</td><td>Aggregate features</td></tr>
</table>

> **v0.9.0 Feature Rename Mapping**:
>
> | Old Name (≤0.8.x) | New Name (≥0.9.0) | Description |
> |-------------------|--------------------|-------------|
> | `secure-saml` | `protocol-saml` | SAML 2.0 signature verification |
> | `secure-httpbasic` | `protocol-httpbasic` | HTTP Basic auth |
> | `secure-httpdigest` | `protocol-httpdigest` | HTTP Digest auth |
> | `observability-otlp` | `otlp` | OpenTelemetry OTLP |
> | `decision-trace` / `permission-registry` / `safe-defaults` | `core-advanced` | Core enhancements merged |
> | `dynamic-active-timeout` / `login-token-map-persistence` / `anonymous-session` / `session-search` | `session-extra` | Session enhancements merged |

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [📖 User Guide](docs/USER_GUIDE.md) | Complete tutorial from installation to advanced usage |
| [📘 API Reference](docs/API_REFERENCE.md) | Public API and module reference |
| [🏗️ Architecture](docs/ARCHITECTURE.md) | Design principles, module layout, and data flow |
| [⚙️ Configuration](docs/CONFIGURATION.md) | Three-tier config sources, full field reference, and hot-reload |
| [⚡ Performance](docs/PERFORMANCE.md) | Performance targets, benchmarks, and optimization advice |
| [🧪 Test Scenarios](docs/TEST_SCENARIOS.md) | Acceptance scenario matrix, feature combination matrix, and quality gates |
| [🔒 Security](SECURITY.md) | Security policy and vulnerability reporting process |
| [🛡️ Threat Model](docs/THREAT.md) | STRIDE analysis, framework defenses vs. operator responsibilities |
| [❓ FAQ](docs/FAQ.md) | Frequently asked questions |
| [🔧 Troubleshooting](docs/TROUBLESHOOTING.md) | Common issues and solutions |
| [🛠️ Development](docs/DEVELOPMENT.md) | TDD workflow, code standards, and debugging tips |
| [🚀 Deployment](docs/DEPLOYMENT.md) | Production deployment notes |
| [🗺️ Roadmap](docs/ROADMAP.md) | Version evolution plan |
| [📦 Release Workflow](docs/RELEASING.md) | Release process and gates |
| [🤝 Contributing](docs/CONTRIBUTING.md) | How to participate in project development |
| [📋 Changelog](docs/CHANGELOG.md) | Change records for every release |
| [📦 Online API Docs](https://docs.rs/garrison) | Latest documentation auto-generated on docs.rs |
| [📦 crates.io](https://crates.io/crates/garrison) | Release page |

---

## 💻 Examples

All 65 runnable examples live in the [`examples/`](examples/) directory (a standalone workspace member, the `garrison-examples` crate), each paired with a 1:1 dedicated test and grouped by theme (login / session / token basics, annotations and web integration, auth protocols, protection suites, observability and infrastructure). See [examples/README.md](examples/README.md) for the complete list and per-example feature requirements.

```bash
# Run a single example
cargo run -p garrison-examples --bin basic_login --features full

# Verify all examples compile
cargo build -p garrison-examples --features full
```

---

## 🏗️ Architecture

Garrison follows a **dual-abstraction-layer + global singleton** architecture: the `GarrisonDao` trait masks storage backend differences behind `dbnexus` (SQLite / PostgreSQL / MySQL) + `oxcache` (L1 in-memory / L2 redis); core modules are always on while optional capabilities (`protocol-*`, `secure-*`, `firewall-*`, `account-*`, `web-*`, etc.) are gated behind independent features; the core data path runs "business code → `GarrisonUtil` → `GarrisonManager` singleton → `GarrisonLogicDefault` → `GarrisonDao` / `GarrisonPermissionStrategy` → storage backend".

For the full module layering, trait relationships, and request-handling data flow, see the [🏗️ Architecture doc](docs/ARCHITECTURE.md).

---

## 🧪 Testing

### 🎯 Test Strategy

Tests are organized in three layers — unit (inline `#[cfg(test)]` in `src/`), acceptance / integration (`tests/acceptance/` organized by domain + dedicated db targets + trybuild UI tests), and example-level integration (`examples/tests/`, one file per example binary) — plus Criterion benchmarks, doc tests, and a feature-combination compile matrix (`ci.yml` test-compile-guard + weekly `feature-matrix.yml`). For the full scenario inventory, real-service matrix (Redis / PostgreSQL / MySQL / Keycloak 26 / HIBP), and feature dependency analysis, see the [🧪 Test Scenarios doc](docs/TEST_SCENARIOS.md).

### ▶️ Commands (matching CI)

```bash
# Unit tests (the two feature faces of the CI test job)
cargo test --no-default-features --features "default" --lib --locked
cargo test --features "full" --lib --locked

# Acceptance / integration tests (CI integration-test job; services include Redis and PostgreSQL)
cargo test --features "full" --tests --no-fail-fast

# Acceptance matrix (full + testing feature face)
cargo test --test acceptance --features "full testing"

# Performance baselines (#[ignore] perf_* cases in the concurrency domain)
cargo test --test acceptance --features "full testing" perf_ -- \
    --nocapture --test-threads=1 --ignored

# Doc tests (CI Linux/MSRV leg)
cargo test --features "full,audit-log" --doc --locked

# One-shot E2E (auth_server_serve smoke + full acceptance + perf baseline + report aggregation)
bash scripts/e2e_run.sh
# Local full pipeline (compose real-service bootstrap + static gates + all tests + feature matrix + bench)
bash scripts/e2e_matrix.sh

# Lint and format gates
cargo clippy --no-default-features --features "default" -- -D warnings
cargo clippy --features "full" -- -D warnings
cargo fmt --all -- --check

# Coverage gate: line coverage no lower than 85%
cargo llvm-cov --features "full" --fail-under-lines 85

# Dependency security gate
cargo deny --all-features --locked check

# Benchmarks (--bench limits to the criterion target, avoids also running lib unittests)
cargo bench --bench garrison_benchmark --features full --locked -- --quick
```

> Build dependency: `protoc` (required by the sdforge build script; CI installs it via taiki-e/install-action).

### 📊 Test Scale

About 5330 tests (≈4800 unit + ≈406 acceptance / integration / UI + ≈116 example-level + 8 proc macros) and 4 Criterion benchmark scenarios; the coverage gate is line coverage no lower than 85% (currently about 95.8%). For the counting methodology and details, see [🧪 Test Scenarios · Test Scale](docs/TEST_SCENARIOS.md#-测试规模统计).

---

## 📊 Performance

Benchmark scenarios and targets are defined in [`benches/garrison_benchmark.rs`](benches/garrison_benchmark.rs) (four Criterion scenarios: `login_flow` / `token_verify_stateless` / `permission_check` / `oxcache_backend_switch`), reproduced locally with `cargo bench`; the acceptance layer additionally carries an HTTP performance baseline (P99 < 200ms / 1000 RPS) captured and aggregated by `scripts/e2e_run.sh`. Performance design highlights (lock-free singleton reads, slow hashing offloaded via `spawn_blocking`, per-request snapshot reuse, cache TTL jitter, full feature gating) and itemized optimization advice live in the [⚡ Performance guide](docs/PERFORMANCE.md).

---

## 🔒 Security

### 🛡️ Security Design

Garrison applies defense-in-depth across the identity lifecycle: Argon2id / Bcrypt hashing offloaded via `spawn_blocking`, constant-time token comparison (`secure-ct-eq`, CWE-208), API Key hash storage and IP-level rate limiting (CWE-916 / CWE-307), multi-tenant IDOR protection, unified token masking in audit events (CWE-532), and fail-closed external login endpoints. Mechanism-level details live in the [Architecture doc](docs/ARCHITECTURE.md) and the [📖 User Guide · Security & Protection](docs/USER_GUIDE.md); security configuration best practices and the vulnerability handling process are covered by the [Security doc](SECURITY.md).

### ⛓️ Supply Chain and Gates

The CI and release pipelines enforce three supply-chain gates: `cargo deny check` (vulnerabilities / licenses / banned dependencies), `cargo audit` (RustSec advisory scanning), and pre-commit secret scanning with gitleaks. For gate criteria and handling details, see the [Security doc · Supply Chain and Gates](SECURITY.md).

### 🚨 Reporting Security Issues

Please do not report security vulnerabilities through public issues. Use the GitHub [Security Advisories](https://github.com/Kirky-X/garrison/security/advisories/new) private disclosure channel or email <Kirky-X@outlook.com>. The project commits to acknowledging reports within 48 hours and providing an initial assessment within 7 days. See the full policy in [SECURITY.md](SECURITY.md).

---

## 🗺️ Roadmap

<table style="width:100%; border-collapse: collapse">
<tr><th style="text-align:center">Status</th><th style="text-align:left">Area</th><th style="text-align:left">Items</th></tr>
<tr><td align="center">✅</td><td>Core engine</td><td>Login auth + permission check + dual-mode session + axum/actix/warp adapters</td></tr>
<tr><td align="center">✅</td><td>Protocol layer</td><td>JWT / OAuth2 / SSO / OIDC / SAML 2.0 / API Key / TOTP / Basic / Digest / Sign</td></tr>
<tr><td align="center">✅</td><td>Security and protection</td><td>Account security engine / firewall suite / multi-tenant / audit logging</td></tr>
<tr><td align="center">✅</td><td>Microservice architecture</td><td>backend-remote / Auth Server / ABAC / OAuth2 Server / gRPC</td></tr>
<tr><td align="center">✅</td><td>Observability</td><td>tracing / metrics-prometheus / OTLP / i18n</td></tr>
<tr><td align="center">🚧</td><td>Next-release security hardening</td><td>Fail-closed external login endpoints, password-login timing side-channel alignment, OAuth2 password grant rate-limit fail-closed, JWT blacklist write retry (see [docs/CHANGELOG.md](docs/CHANGELOG.md) · Unreleased)</td></tr>
<tr><td align="center">📋</td><td>v1.0.0 Stable</td><td>API freeze + performance benchmarks + production case studies</td></tr>
</table>

Full roadmap at [docs/ROADMAP.md](./docs/ROADMAP.md).

---

## 🤝 Contributing

For the detailed contribution workflow and code standards, see the [🤝 Contributing Guide](docs/CONTRIBUTING.md).

### 🛠️ Development Environment

The toolchain is Rust 1.85+ (pinned in `rust-toolchain.toml`); run `cargo fmt --all -- --check` and `cargo clippy --all-targets --all-features -- -D warnings` before committing; commit messages follow Conventional Commits (`feat`, `fix`, `docs`, etc.). For the full environment setup, see the [🤝 Contributing Guide · Development Environment](docs/CONTRIBUTING.md#-开发环境搭建).

### 💖 Ways to Contribute

<table style="width:100%; border-collapse: collapse">
<tr>
<td width="33%" align="center" style="padding: 16px">

### 🐛 Report Bugs

Found an issue?<br>
<a href="https://github.com/Kirky-X/garrison/issues/new">Create Issue</a>

</td>
<td width="33%" align="center" style="padding: 16px">

### 💡 Feature Suggestions

Have a great idea?<br>
<a href="https://github.com/Kirky-X/garrison/issues/new?template=feature_request.md">Submit Suggestion</a>

</td>
<td width="33%" align="center" style="padding: 16px">

### 🔧 Submit PR

Want to contribute code?<br>
<a href="https://github.com/Kirky-X/garrison/pulls">Fork & PR</a>

</td>
</tr>
</table>

---

## 📋 Changelog

For the full version history, see the [📋 Changelog](docs/CHANGELOG.md) (following the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) format and semantic versioning).

| Version | Date | Highlights |
|---------|------|------------|
| 0.9.0-rc.2 | 2026-08-26 | Fail-closed security hardening (check_api_key / check_abac); self-hosted crate rc.4 upgrade |
| 0.9.0-rc.1 | 2026-08-25 | Acceptance test system + DAO atomic contract + gRPC async auth layer |
| 0.8.1 | 2026-07-25 | Documentation consistency + dependency version alignment |

---

## 📄 License

This project is licensed under [Apache-2.0](LICENSE). Why Apache-2.0 instead of MIT: Apache-2.0 includes patent grant provisions, making it more suitable for enterprise-grade frameworks.

---

## 🙏 Acknowledgments

### 🌟 Core Dependencies

Garrison stands on the shoulders of these excellent open source projects:

| Dependency | Purpose |
|------------|---------|
| [axum](https://github.com/tokio-rs/axum) | tokio team's Rust web framework |
| [oxcache](https://github.com/Kirky-X/oxcache) | Rust multi-level cache library (L1 memory + L2 redis) |
| [dbnexus](https://github.com/Kirky-X/dbnexus) | Rust database abstraction layer (SQLite / PostgreSQL / MySQL) |
| [inventory](https://github.com/dtolnay/inventory) | David Tolnay's compile-time plugin registration library |
| [confers](https://github.com/Kirky-X/confers) | Rust configuration management library (zero boilerplate) |
| [sdforge](https://github.com/Kirky-X/sdforge) | Declarative web framework |
| [trait-kit](https://github.com/Kirky-X/trait-kit) | Trait utility toolkit |

### 💝 Special Thanks

- [Sa-Token](https://github.com/dromara/sa-token): Java ecosystem auth framework, whose domain modeling informed Garrison's early design
- Thanks to the Rust community and all [contributors](https://github.com/Kirky-X/garrison/graphs/contributors)

---

## 📞 Contact & Support

<table style="width:100%; max-width: 600px">
<tr>
<td align="center" width="33%">
<a href="https://github.com/Kirky-X/garrison/issues"><b style="color:#991B1B">Issues</b></a><br>
<span style="color:#64748B">Report bugs & issues</span>
</td>
<td align="center" width="33%">
<a href="docs/FAQ.md"><b style="color:#1E40AF">FAQ</b></a><br>
<span style="color:#64748B">Frequently asked questions</span>
</td>
<td align="center" width="33%">
<a href="https://github.com/Kirky-X/garrison"><b style="color:#1E293B">GitHub</b></a><br>
<span style="color:#64748B">View source code</span>
</td>
</tr>
</table>

---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Kirky-X/garrison&type=Date)](https://star-history.com/#Kirky-X/garrison&Date)

If you find this project useful, please consider giving it a ⭐️!

<b>Built by Kirky.X</b>

---

<sub>© 2026 Kirky.X. All rights reserved.</sub>
