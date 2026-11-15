<!-- markdownlint-disable MD041 -->
<div align="center">

<img src="docs/assets/garrison.png" alt="Garrison Logo" width="240">

[![Rust 2021](https://img.shields.io/badge/Rust-2021-edded?logo=rust&style=for-the-badge)](https://www.rust-lang.org/) [![Rustc 1.97.1+](https://img.shields.io/badge/rust-1.97.1%2B-orange.svg?style=for-the-badge)](https://www.rust-lang.org/) [![crates.io](https://img.shields.io/crates/v/garrison?style=for-the-badge)](https://crates.io/crates/garrison) [![docs.rs](https://img.shields.io/docsrs/garrison?style=for-the-badge)](https://docs.rs/garrison) [![downloads](https://img.shields.io/crates/d/garrison?style=for-the-badge)](https://crates.io/crates/garrison) [![CI](https://img.shields.io/github/actions/workflow/status/Kirky-X/garrison/ci.yml?branch=main&label=CI&style=for-the-badge)](https://github.com/Kirky-X/garrison/actions/workflows/ci.yml) [![coverage](https://img.shields.io/badge/coverage-95%25%2B-brightgreen.svg?style=for-the-badge)](https://github.com/Kirky-X/garrison) [![license](https://img.shields.io/crates/l/garrison?style=for-the-badge)](LICENSE)

[中文](README_CN.md) | **English**

**One-stop authentication &amp; authorization framework for the Rust ecosystem**

[✨ Features](#-features) • [🚀 Quick Start](#-quick-start) • [📚 Documentation](#-documentation) • [💻 Examples](#-examples) • [🤝 Contributing](#-contributing)

</div>

---

<div align="center">

### 🎯 Annotate Guard Points, Call Stateless APIs

Inject your dependencies into `GarrisonManager` once at startup — from login to logout, the framework takes care of the rest:

<table style="width:100%; border-collapse: collapse">
<tr>
<td align="center" width="25%">🧩<br><b>Annotation-Driven</b><br><span style="color:#64748B">13 attribute macros · declarative wiring</span></td>
<td align="center" width="25%">🔀<br><b>Dual-Mode Sessions</b><br><span style="color:#64748B">Account-level · Token-level · Multi-device</span></td>
<td align="center" width="25%">🌐<br><b>Web Integration</b><br><span style="color:#64748B">axum · actix · warp</span></td>
<td align="center" width="25%">⚙️<br><b>Feature Gating</b><br><span style="color:#64748B">100+ flags · compile only what you need</span></td>
</tr>
</table>

</div>

---

## 📋 Table of Contents

<details open>
<summary>📑 Table of Contents</summary>

- [✨ Features](#-features)
- [🚀 Quick Start](#-quick-start)
- [📚 Documentation](#-documentation)
- [💻 Examples](#-examples)
- [🔒 Security](#-security)
- [🤝 Contributing](#-contributing)
- [📄 License](#-license)
- [⭐ Star History](#-star-history)

</details>

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
<td width="50%" style="vertical-align:top; padding: 12px">🧪 <b>High Coverage</b><br><span style="color:#64748B">5990+ tests (≈5454 lib + ≈540 acceptance/integration/examples), 95%+ line coverage, clippy zero warnings</span></td>
<td width="50%" style="vertical-align:top; padding: 12px">🌐 <b>Web Framework Adapters</b><br><span style="color:#64748B">axum/actix/warp annotation-style extractors + proc macros</span></td>
</tr>
</table>

Beyond the core capabilities above, everything else (auth protocols, firewall, account security, multi-tenancy, observability, microservice building blocks, etc.) ships as independent, opt-in feature flags — see the [🎨 Feature Flags Matrix](docs/en/API_REFERENCE.md#feature-matrix) for a domain-grouped matrix (the full list is authoritative in `Cargo.toml`'s `[features]`).

---

## 🚀 Quick Start

### 📦 Installation

Add the following to your `Cargo.toml` (`development` preset = in-memory cache DAO + SQLite + axum adapter):

<details>
<summary>📄 Code · toml</summary>

```toml
[dependencies]
garrison = { version = "0.9", features = ["development"] }
async-trait = "0.1"
tokio = { version = "1", features = ["full"] }
```

</details>

Requires Rust **1.97.1 or later**; for the MSRV rationale and the three-tier CI verification matrix, see the [📖 User Guide · Installation Note](docs/en/USER_GUIDE.md#msrv-note).

> Pre-release versions require the full version number; `"0.9"` will not match prerelease. To enable all protocol and security modules: `features = ["full"]`.

<details>
<summary>📋 Table</summary>

| Preset | Installation | Use Case |
|--------|-------------|----------|
| Development | `features = ["development"]` | In-memory cache + SQLite + axum, quick validation |
| Production | `features = ["production"]` | Recommended production combination |
| Full | `features = ["full"]` | All capabilities |

</details>

### 💡 Minimal Example

The following example is adapted from [`examples/src/bin/readme_quickstart.rs`](examples/src/bin/readme_quickstart.rs) (complete business flow: initialize manager → log in → verify login state → log out):

<details>
<summary>📄 Code · rust</summary>

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

</details>

<details>
<summary>📄 Code · bash</summary>

```bash
cargo run -p garrison-examples --bin readme_quickstart --features "cache-memory"
# Output: Login successful, token = <8-char random token prefix>
```

</details>

> This example is continuously validated by [examples/tests/readme_quickstart.rs](./examples/tests/readme_quickstart.rs) (runs with CI); its business code mirrors [`examples/src/web/readme_quickstart.rs`](examples/src/web/readme_quickstart.rs) verbatim.

### 🧭 Core Concepts

For deeper coverage of the core concepts — global singleton + static API, token context, dual-mode sessions, and feature gating — see the [📖 User Guide · Core Concepts](docs/en/USER_GUIDE.md#-core-concepts).

---

## 📚 Documentation

<details>
<summary>📋 Table</summary>

| Document | Description |
|----------|-------------|
| [📖 User Guide](docs/en/USER_GUIDE.md) | Complete tutorial from installation to advanced usage |
| [📘 API Reference](docs/en/API_REFERENCE.md) | Public API and module reference (includes the feature flags matrix) |
| [🏗️ Architecture](docs/en/ARCHITECTURE.md) | Design principles, module layout, and data flow |
| [⚙️ Configuration](docs/en/CONFIGURATION.md) | Three-tier config sources, full field reference, and hot-reload |
| [⚡ Performance](docs/en/PERFORMANCE.md) | Performance targets, benchmarks, and optimization advice |
| [📊 Performance Baseline](docs/en/benchmarks-v1.0-baseline.md) | Pre-v1.0 benchmark capture data |
| [🧭 Architecture Decision Records (ADR ×4)](docs/en/adr-0001-argon2id-password-hashing.md) | Argon2id / CSPRNG / constant-time comparison / unified error model |
| [🧱 API Stability](docs/en/API_STABILITY.md) | v1.0 stability tiers, freeze checklist, and public API baseline |
| [🏭 Reference Deployments](docs/en/PRODUCTION_CASES.md) | Self-hosted reference cases and submission template |
| [🔎 Security Audit Readiness](docs/en/SECURITY_AUDIT.md) | Audit scope, evidence matrix, and third-party RFP checklist |
| [🧪 Test Scenarios](docs/en/TEST_SCENARIOS.md) | Acceptance scenario matrix, feature combination matrix, and quality gates |
| [🔒 Security](docs/en/SECURITY.md) | Security policy and vulnerability reporting process |
| [🛡️ Threat Model](docs/en/THREAT.md) | STRIDE analysis, framework defenses vs. operator responsibilities |
| [❓ FAQ](docs/en/FAQ.md) | Frequently asked questions |
| [🔧 Troubleshooting](docs/en/TROUBLESHOOTING.md) | Common issues and solutions |
| [🛠️ Development](docs/en/DEVELOPMENT.md) | TDD workflow, code standards, and debugging tips (includes CI-consistent test commands) |
| [🚀 Deployment](docs/en/DEPLOYMENT.md) | Production deployment notes |
| [🗺️ Roadmap](docs/en/ROADMAP.md) | Version evolution plan |
| [📦 Release Workflow](docs/en/RELEASING.md) | Release process and gates |
| [🤝 Contributing](docs/en/CONTRIBUTING.md) | How to participate in project development |
| [📋 Changelog](docs/en/CHANGELOG.md) | Change records for every release |
| [📦 Online API Docs](https://docs.rs/garrison) | Latest documentation auto-generated on docs.rs |
| [📦 crates.io](https://crates.io/crates/garrison) | Release page |

</details>

---

## 💻 Examples

All 65 runnable examples live in the [`examples/`](examples/) directory (a standalone workspace member, the `garrison-examples` crate), each paired with a 1:1 dedicated test and grouped by theme (login / session / token basics, annotations and web integration, auth protocols, protection suites, observability and infrastructure). See [examples/README.md](examples/README.md) for the complete list and per-example feature requirements.

<details>
<summary>📄 Code · bash</summary>

```bash
# Run a single example
cargo run -p garrison-examples --bin basic_login --features full

# Verify all examples compile
cargo build -p garrison-examples --features full
```

</details>

---

## 🔒 Security

Garrison applies defense-in-depth across the identity lifecycle: Argon2id / Bcrypt hashing offloaded via `spawn_blocking`, constant-time token comparison (`secure-ct-eq`, CWE-208), API Key hash storage and IP-level rate limiting (CWE-916 / CWE-307), multi-tenant IDOR protection, unified token masking in audit events (CWE-532), and fail-closed external login endpoints. Mechanism-level details live in the [🏗️ Architecture doc](docs/en/ARCHITECTURE.md) and the [📖 User Guide · Security &amp; Protection](docs/en/USER_GUIDE.md); security configuration best practices and the vulnerability handling process are covered by the [🔒 Security doc](docs/en/SECURITY.md).

The CI and release pipelines enforce two supply-chain gates (`cargo deny check` and gitleaks secret scanning); for gate criteria and handling details, see the [🔒 Security doc · Supply Chain and Gates](docs/en/SECURITY.md).

### 🚨 Reporting Security Issues

Please do not report security vulnerabilities through public issues. Use the GitHub [Security Advisories](https://github.com/Kirky-X/garrison/security/policy) private disclosure channel as the primary route (fall back to email <Kirky-X@outlook.com>, handled by Kirky.X, only if that channel is unavailable). The project commits to acknowledging reports within 48 hours and providing an initial assessment within 7 days. See the full policy in the [🔒 Security doc](docs/en/SECURITY.md).

---

## 🤝 Contributing

For the detailed contribution workflow and code standards, see the [🤝 Contributing Guide](docs/en/CONTRIBUTING.md).

### 🛠️ Development Environment

For toolchain requirements, pre-commit checks (`cargo fmt` / `cargo clippy`), and the Conventional Commits message convention, see the [🤝 Contributing Guide · Development Environment](docs/en/CONTRIBUTING.md#-development-environment-setup).

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
<a href="https://github.com/Kirky-X/garrison/pulls">Fork &amp; PR</a>

</td>
</tr>
</table>

### 🙏 Acknowledgments

For the core-dependency list and special thanks, see the [🤝 Contributing Guide · Acknowledgments](docs/en/CONTRIBUTING.md#acknowledgments).

---

## 📄 License

This project is licensed under [Apache-2.0](LICENSE). Why Apache-2.0 instead of MIT: Apache-2.0 includes patent grant provisions, making it more suitable for enterprise-grade frameworks.

---

## ⭐ Star History

[![Star History Chart](https://api.star-history.com/svg?repos=Kirky-X/garrison&type=Date)](https://star-history.com/#Kirky-X/garrison&Date)

If you find this project useful, please consider giving it a ⭐️!

<b>Built by Kirky.X</b>

---

<sub>© 2026 Kirky.X. All rights reserved.</sub>
