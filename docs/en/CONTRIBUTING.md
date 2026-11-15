# 🤝 Garrison Contributing Guide

<img src="../assets/garrison.png" alt="Garrison Logo" width="150">

First, thank you for your interest in and support of the Garrison project! This document walks you through the complete contribution workflow, from environment setup to submitting a Pull Request.

Garrison is a one-stop authentication and authorization framework for the Rust ecosystem. The project follows a TDD (test-driven development) workflow with strict quality requirements: 5469 lib tests passing + doc-tests, 95%+ coverage, clippy zero warnings, and `///` doc comments on all public APIs.

> Related documents: [🛠️ Development Standards](./DEVELOPMENT.md) | [🏗️ Architecture](./ARCHITECTURE.md) | [⚙️ Configuration Guide](./CONFIGURATION.md)

## 📋 Table of Contents

- [Welcome](#-welcome)
- [Development Environment Setup](#-development-environment-setup)
- [System Prerequisites](#-system-prerequisites)
- [Code Standards](#-code-standards)
- [TDD Workflow](#-tdd-workflow)
- [Commit Conventions](#-commit-conventions)
- [PR Process](#-pr-process)
- [Test Coverage Requirements](#-test-coverage-requirements)
- [Contact](#-contact)

---

## 👋 Welcome

Welcome to building **Garrison**!

**Ways to contribute:**

| Code | Docs | Tests | Community |
|:-----|:-----|:-----|:-----|
| Fix defects, add features | Improve docs and guides | Write tests, find issues | Help and support others |

---

## 🧰 Development Environment Setup

### 1. Fork and clone the repository

1. Fork [Kirky-X/garrison](https://github.com/Kirky-X/garrison) on GitHub to your personal account.
2. Clone your fork locally:

   ```bash
   git clone https://github.com/<your-username>/garrison.git
   cd garrison
   ```

3. Add the upstream remote to stay in sync:

   ```bash
   git remote add upstream https://github.com/Kirky-X/garrison.git
   git fetch upstream
   ```

### 2. Install the Rust toolchain

Garrison requires **Rust 1.97.1+**: `Cargo.toml` declares `rust-version = "1.97.1"`, taken from the `rust-version = "1.97.1"` declared by each sibling-ecosystem dependency on the rc line (confers / oxcache / dbnexus / sdforge / limiteron / inklog / trait-kit) — i.e. the lowest toolchain the dependency graph accepts; below that version `cargo check --locked` fails outright with `rustc ... is not supported by the following packages`. The local toolchain follows rustup's default channel (make sure it is ≥ 1.97.1); the CI test matrix explicitly pins `1.97.1` (the MSRV leg, same value as `rust-version`) / `stable` / `beta` (see `.github/workflows/ci.yml`).

To install/upgrade manually:

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update
rustup show  # verify the toolchain is ready
```

### 3. Clone local dependencies (optional)

Garrison's core dependencies `oxcache 0.5` and `dbnexus 0.6` are both published to crates.io, so **no local dependency clones are needed**. A normal `cargo build` fetches them automatically.

> If you need to validate local changes to the `oxcache` / `dbnexus` upstreams, you may `git clone` those repositories yourself and switch to `path` dependencies — but do not commit the `path` configuration in a PR.

### 4. Build the project

```bash
cargo build --features full
```

The first build fetches and compiles all dependencies and may take a few minutes. A successful, error-free compilation means the environment is ready.

### 5. Run tests to verify the environment

```bash
cargo test --features full
```

Expected output: 5469 lib tests passing + all doc-tests passing.

---

## 📦 System Prerequisites

Some development toolchains depend on system-level libraries; install them before building:

| Dependency | Purpose | Debian/Ubuntu install command |
|------|------|------------------------|
| `libssl-dev` | OpenSSL headers, used by reqwest / some TLS backends | `sudo apt-get install libssl-dev` |
| `pkg-config` | Locates system library paths at build time (needed by the build chain) | `sudo apt-get install pkg-config` |

> **macOS users**: OpenSSL is usually preinstalled; if you hit problems run `brew install openssl pkg-config`.
> **Windows users**: MSYS2 or vcpkg is recommended for the corresponding libraries.

---

## 📏 Code Standards

Garrison enforces strict code-quality standards; every submission must pass the following checks.

### clippy zero warnings

All code must pass clippy with warnings treated as errors:

```bash
cargo clippy --features full --lib --tests -- -D warnings
```

If warnings appear, fix them per clippy's hints; suppressing with `#[allow(...)]` is forbidden (unless there is a strong reason, explained in the PR).

### cargo fmt enforced

Code formatting must conform to the `rustfmt.toml` configuration:

```bash
cargo fmt --all -- --check
```

If the check fails, run `cargo fmt --all` to auto-format before committing.

### Doc-comment requirements

**All public APIs must have `///` doc comments** and pass `cargo doc` with zero warnings:

```bash
cargo doc --no-deps --features full
```

Doc-comment requirements:

- Every `pub fn`, `pub struct`, `pub enum`, `pub trait`, and `pub mod` needs a `///` comment.
- Comments should explain "what it does" and "why", not merely restate the function name.
- Complex logic should include `# Examples` code samples (executable via `cargo test --doc`).
- Cross-crate references use intra-doc links: `[`Foo`](crate::module::Foo)`.

### Global-singleton test serialization

Tests that touch the global `GarrisonManager` singleton (held in `std::sync::LazyLock`) must be annotated `#[serial_test::serial]` to avoid concurrent pollution:

```rust
#[cfg(test)]
mod tests {
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn test_global_manager_state() {
        // test code operating on the global singleton
    }
}
```

Global-singleton tests without `#[serial]` will fail randomly on CI — always check.

---

## 🔄 TDD Workflow

The project practices test-driven development; the standard loop is:

1. **Write the interface first**: define the trait, function signature, or type structure (with `///` doc comments).
2. **Write tests**: add unit/integration tests for the new interface; compilation succeeds but the tests fail.
3. **Implement**: write the implementation that makes the tests pass.
4. **Tests pass**: run `cargo test --features full` and confirm all new tests pass.
5. **Commit**: follow the Conventional Commits convention.

> "Implement first, backfill tests" is forbidden (except when reproducing known behavior while fixing a bug).

For detailed TDD steps and test-writing standards, see [DEVELOPMENT.md](./DEVELOPMENT.md).

---

## 📝 Commit Conventions

Garrison follows the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) convention; the message format is:

```text
<type>(<scope>): <subject>

<body optional>

<footer optional>
```

### Types

| type | Description | Example |
|------|------|------|
| `feat` | New feature | Add JWT issuance capability |
| `fix` | Bug fix | Fix session-renewal panic |
| `docs` | Documentation change | Expand CONTRIBUTING |
| `refactor` | Refactoring (no behavior change) | Split the context module |
| `test` | Tests added/changed | Add TOTP boundary cases |
| `chore` | Build/tooling/dependencies | Upgrade jsonwebtoken to 10 |

### Scopes

The scope names a module or functional domain; common values:

- Protocol layer: `protocol-jwt`, `protocol-oauth2`, `protocol-sso`, `protocol-sign`, `protocol-apikey`, `protocol-temp`
- Security modules: `secure-totp`, `secure-sign`, `protocol-httpbasic`, `protocol-httpdigest`
- Cache/database: `cache-memory`, `cache-redis`, `db-sqlite`
- Web adapters: `web-axum`, `web-actix`, `web-warp`
- Core modules: `core`, `stp`, `session`, `config`, `context`, `manager`, `router`, `dao`
- Others: `docs`, `ci`, `deps`

### Examples

```text
feat(protocol-jwt): implement JWT issuance and verification

- Add JwtIssuer and JwtValidator
- Integrate jsonwebtoken 10
- Cover with 12 unit tests

Closes #42
```

```text
fix(session): fix concurrent renewal race under is_share=true
```

```text
chore(deps): upgrade oxcache to 0.3 to enable per-entry TTL
```

---

## 🔧 PR Process

### 1. Create a feature branch

Always branch from the latest `main`; branch names should include the type and a short description:

```bash
git checkout main
git pull upstream main
git checkout -b feat/your-feature
```

Branch naming conventions:

- `feat/<scope>-<short-desc>`: new features, e.g. `feat/protocol-jwt-issuer`
- `fix/<scope>-<short-desc>`: bug fixes, e.g. `fix/session-race`
- `docs/<short-desc>`: docs, e.g. `docs/contributing-guide`

### 2. Commit code

Write commit messages per the [commit conventions](#-commit-conventions); each commit should focus on a single responsibility:

```bash
git add <relevant files>
git commit -m "feat(protocol-jwt): implement JWT issuance and verification"
```

### 3. Make sure all checks pass

Before opening a PR, all of the following checks must pass locally:

```bash
# Format check
cargo fmt --all -- --check

# clippy zero warnings
cargo clippy --features full --lib --tests -- -D warnings

# All tests pass
cargo test --features full

# Docs zero warnings
cargo doc --no-deps --features full
```

Only after all four checks pass may you open the PR.

### 4. Create the Pull Request

1. Push the branch to your fork: `git push origin feat/your-feature`
2. Open a Pull Request to `Kirky-X/garrison:main` on GitHub.
3. Fill in the PR template, including:
   - **Change description**: what this PR does and why.
   - **Linked issue**: e.g. `Closes #42`.
   - **Checklist**: tick that the four local checks pass.
   - **Breaking changes**: if the API changes incompatibly, mark it explicitly and describe the migration path.
4. Wait for CI and maintainer review; iterate on feedback.

---

## 📊 Test Coverage Requirements

Garrison requires test coverage of **≥ 95% line coverage** (the CI gate `cargo llvm-cov --features "full" --fail-under-lines 95`; measured about 95.15% on 2026-10-14). New code must not lower total coverage. Per-module expectations are in the table below.

Use `cargo-llvm-cov` to generate coverage reports (the same tool and scope as CI):

```bash
# Install (once only; llvm-cov needs the toolchain's llvm-tools component)
cargo install cargo-llvm-cov
rustup component add llvm-tools-preview

# Generate a local coverage report reusing the CI gate threshold (non-zero exit when line coverage < 95%)
cargo llvm-cov --features "full" --fail-under-lines 95

# For an Lcov report (e.g. uploading to Codecov): append --lcov --output-path lcov.info
```

Coverage rules in detail:

- **Core modules** (core/stp/session/config/context/manager): coverage ≥ 95%.
- **Protocol/security plugins**: coverage ≥ 90%.
- **Web adapter layer**: integration tests covering the main middleware paths suffice.
- 100% coverage is not the goal, but every branch must have a corresponding test case.
- Raising coverage by "not writing tests" is forbidden.

---

## 📞 Contact

- **GitHub Issues**: [https://github.com/Kirky-X/garrison/issues](https://github.com/Kirky-X/garrison/issues) — for bug reports and feature requests.
- **GitHub Discussions**: [https://github.com/Kirky-X/garrison/discussions](https://github.com/Kirky-X/garrison/discussions) — for design discussions, usage questions, and idea exchange.

For security issues, never discuss in public channels; see [SECURITY.md](./SECURITY.md).

---

Thank you again for your contribution! May Garrison grow more robust because of you.

---

<a id="acknowledgments"></a>

## 🙏 Acknowledgments (migrated from README)

### 🌟 Core Dependencies

Garrison stands on the shoulders of these excellent open source projects:

<details>
<summary>📋 Table</summary>

| Dependency | Purpose |
|------|------|
| [axum](https://github.com/tokio-rs/axum) | The tokio team's Rust web framework |
| [oxcache](https://github.com/Kirky-X/oxcache) | Rust multi-level cache library (L1 memory + L2 redis) |
| [dbnexus](https://github.com/Kirky-X/dbnexus) | Rust database abstraction layer (SQLite / PostgreSQL / MySQL) |
| [inventory](https://github.com/dtolnay/inventory) | David Tolnay's compile-time plugin registration library |
| [confers](https://github.com/Kirky-X/confers) | Rust configuration management library (zero boilerplate) |
| [sdforge](https://github.com/Kirky-X/sdforge) | Declarative web framework |
| [trait-kit](https://github.com/Kirky-X/trait-kit) | Trait utility toolkit |

</details>

### 💝 Special Thanks

- Thanks to the Rust community and all [contributors](https://github.com/Kirky-X/garrison/graphs/contributors)
