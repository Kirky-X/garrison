# 📖 Garrison User Guide

**Garrison** is a one-stop authentication and authorization framework for the Rust ecosystem: login authentication → permission checks → session management → route interception, out of the box. Implement one `GarrisonInterface` callback and inject one `GarrisonDao` storage backend to get the full auth capability; all optional capabilities (protocol layer, firewall, account security, etc.) are gated behind independent features, and compiled artifacts contain only what is enabled.

> Applicable version: 0.9.0-rc.4 (MSRV 1.97.1, `rust-version` in `Cargo.toml`). This document covers "how to use it"; for architecture see the [🏗️ Architecture doc](ARCHITECTURE.md), and for the full config table see the [⚙️ Configuration Guide](CONFIGURATION.md).

## 📋 Table of Contents

- [Quick Start](#-quick-start)
  - [Installation](#-installation)
  - [Minimal Example](#-minimal-example)
- [Core Concepts](#-core-concepts)
  - [Global Singleton and Static API](#-global-singleton-and-static-api)
  - [Dual-Mode Sessions](#-dual-mode-sessions)
  - [Token Context (task_local)](#-token-context-task_local)
  - [Dual Abstraction Layer Storage](#️-dual-abstraction-layer-storage)
- [Session Management](#-session-management)
- [Permissions and Roles](#-permissions-and-roles)
- [Web Framework Integration](#-web-framework-integration)
- [Authentication Protocols](#-authentication-protocols)
- [Configuration](#️-configuration)
- [Security and Protection](#️-security-and-protection)
- [Observability and Extensions](#-observability-and-extensions)
- [Best Practices](#-best-practices)
- [Further Reading](#-further-reading)

---

## 🚀 Quick Start

### 📦 Installation

Add the dependency in `Cargo.toml` (the `development` aggregate = in-memory cache DAO + SQLite + axum adapter):

```toml
[dependencies]
garrison = { version = "0.9.0-rc.4", features = ["development"] }
async-trait = "0.1"
tokio = { version = "1", features = ["full"] }
```

> Pre-release versions require the full version number; `"0.9"` will not match prerelease. To enable all protocol and security modules: `features = ["full"]`.

| Preset | Installation | Use case |
|------|----------|----------|
| Development | `features = ["development"]` | In-memory cache + SQLite + axum, quick validation |
| Production | `features = ["production"]` | Recommended production combination |
| Full | `features = ["full"]` | All capabilities |

### 💡 Minimal Example

Complete business flow: initialize the manager → log in → verify login state → verify permissions → log out.

```rust
use std::sync::Arc;
use garrison::prelude::*;
use async_trait::async_trait;

// 1. The business implements GarrisonInterface (provides permission/role data)
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

    // 3. Initialize the global manager
    GarrisonManager::builder()
        .dao(dao).config(config).interface(interface)
        .build().await?;

    // 4. Execute login within the task_local context
    let token = garrison::stp::with_current_token(
        String::new(), GarrisonUtil::login("1001", &LoginParams::default()),
    ).await?;
    println!("Login successful, token = {}", &token[..8.min(token.len())]);

    // 5. Verify login state
    garrison::stp::with_current_token(token.clone(), GarrisonUtil::check_login()).await?;

    // 6. Verify permissions
    garrison::stp::with_current_token(
        token.clone(), GarrisonUtil::check_permission("user:read"),
    ).await?;

    // 7. Log out
    garrison::stp::with_current_token(token.clone(), GarrisonUtil::logout()).await?;
    Ok(())
}
```

> This example is continuously validated by [`examples/tests/readme_quickstart.rs`](../../examples/tests/readme_quickstart.rs) (runs with CI), mirroring it verbatim so it cannot drift from the API. The full runnable version is [`examples/src/bin/basic_login.rs`](../../examples/src/bin/basic_login.rs).

---

## 🧭 Core Concepts

### 🏢 Global singleton and static API

`GarrisonManager` is a global singleton; at startup the builder injects `dao` (storage), `config` (configuration), and `interface` (business callbacks) once, then `build()`. Afterwards business code uniformly uses the `GarrisonUtil` static API (login, logout, checks, etc.) with no handle passing. The singleton holds an `Arc<GarrisonLogicDefault>` internally (implementing `GarrisonCore` and 5 logic sub-traits: Session / Permission / Token / Mfa / Password), read lock-free via `arc_swap::ArcSwapOption`.

### 🧩 Dual-mode sessions

| Session type | Lifetime | Purpose |
|----------|----------|------|
| Account-Session | Account-level, long-lived | Account-level state (e.g. "is the account online"), the data source of the `max_login_count` gate |
| Token-Session | Login-level, temporary data | Each login's token data |

Multi-device login policy is controlled by the config items `is_share` (share token across devices) / `is_concurrent` (allow concurrent logins). Full field descriptions are in the [⚙️ Configuration Guide](CONFIGURATION.md).

### 🎯 Token context (task_local)

Garrison does not thread the token through every function signature; it carries it in a task_local context: `garrison::stp::with_current_token(token, future)` binds the token for the duration of the future, and static APIs like `GarrisonUtil::check_login()` inside read the current token automatically. The web adapter layers (axum/actix/warp middleware) complete the binding automatically, so handlers can call the static APIs directly.

### 🗄️ Dual abstraction layer storage

- **The `dbnexus` database abstraction layer**: SQLite / PostgreSQL / MySQL (the `db-sqlite` / `db-postgres` / `db-mysql` features), auto-migrate + a Repository layer (13 traits).
- **The `oxcache` cache abstraction layer**: L1 memory + L2 redis (the `cache-memory` / `cache-redis` features).
- Both are masked uniformly by the `GarrisonDao` trait — switching storage backends changes zero business code. Note the dbnexus constraint: embedded (sqlite) and server-side (postgres/mysql) drivers cannot compile together.

---

## 👤 Session Management

Session operations provided by `GarrisonUtil` (full signatures in the [📘 API Reference](API_REFERENCE.md)):

| API | Description |
|-----|------|
| `GarrisonUtil::login(id, &LoginParams)` | Logs in and returns a token; `LoginParams` can carry device, tenant, and other extension fields |
| `GarrisonUtil::login_simple(id)` | Login with default parameters |
| `GarrisonUtil::logout()` | Logs out the current token |
| `GarrisonUtil::logout_by_login_id(id)` | Logs out by login subject |
| `GarrisonUtil::kickout(id)` / `kickout_by_token(token)` | Kicks a user offline |
| `GarrisonUtil::check_login()` | Verifies login state (returns `GarrisonError::NotLogin` when not logged in) |
| `GarrisonUtil::get_login_id()` / `get_login_id_by_token(token)` | Reads the subject of the current / a given token |
| `GarrisonUtil::revoke_token(token)` | Revokes a token (RFC 7009 semantics) |
| `GarrisonUtil::refresh_token(token)` | RefreshToken rotation (`protocol-jwt`) |
| `GarrisonUtil::invalidate_sessions_after_password_change(...)` | Bulk-invalidates sessions after a password change |

The login style (token style) is config-driven; see [`examples/src/bin/token_styles.rs`](../../examples/src/bin/token_styles.rs) for token-style examples.

---

## 🔑 Permissions and Roles

- **Checks**: `GarrisonUtil::check_permission("user:read")` / `check_role("admin")` throw `NotPermission` / `NotRole` on failure; `has_permission` / `has_role` return booleans without throwing.
- **Data source**: the framework does not assume where permission data lives — the business implements `GarrisonInterface::get_permission_list` / `get_role_list` callbacks (query a database, read config, call an external service). Multi-account systems override `get_permission_list_with_type` to isolate permissions per subject `login_type` (e.g. admin / merchant).
- **Custom strategies**: the default `GarrisonPermissionStrategyDefault` does string matching; implement `GarrisonPermissionStrategy` to replace it for more complex decisions.
- **Role hierarchy**: `RoleHierarchyService` + `RoleHierarchyRecord` provide role inheritance (SQL backends adapt placeholders, `any(db-sqlite, db-postgres, db-mysql)`).
- **Decision provenance**: the `core-advanced` face provides `AuthRequest` / `Decision` / `DecisionReason`; `authorize()` returns a decision with reasons.
- **Annotation style**: under axum, the `#[check_login]` / `#[check_role("admin")]` / `#[check_permission("user:read")]` attribute macros are available (next section).

---

## 🌐 Web Framework Integration

The three framework adapters are independent and can coexist (`web-axum` / `web-actix` / `web-warp`):

**axum + annotation macros** (the `annotation-macros` feature, 13 attribute macros):

```rust
use garrison::annotation::*;

// annotate route handlers directly
#[check_login]
async fn profile() -> &'static str { "ok" }

#[check_role("admin")]
#[check_permission("user:write")]
async fn admin_write() -> &'static str { "ok" }
```

**actix-web**: `GarrisonRouter` + `GarrisonMiddleware` enter the tenant context before running authorization; `with_tenant_resolver(resolver)` / `with_header_tenant()` configure tenant extraction (the `tenant-isolation` scenario).

**Unified routing abstraction**: `GarrisonRouter` aggregates routes → `GarrisonInterceptor` interceptors → `GarrisonUtil` static APIs; the three frameworks share the same chain.

Full runnable examples: [`axum_integration.rs`](../../examples/src/web/axum_integration.rs) (a 213-line complete web app; `examples/src/bin/axum_integration.rs` is a 9-line shim calling it), [`macro_annotations.rs`](../../examples/src/bin/macro_annotations.rs), [`web_actix_example.rs`](../../examples/src/bin/web_actix_example.rs), [`web_warp_example.rs`](../../examples/src/bin/web_warp_example.rs).

---

## 🔐 Authentication Protocols

All protocol capabilities are feature-gated; once enabled, the APIs enter from the `protocol` module and `GarrisonUtil`:

| Protocol | Feature | Capability highlights | Examples |
|------|---------|----------|------|
| JWT | `protocol-jwt` | HS256/384/512, RS256/384/512, ES256/384, EdDSA + refresh rotation | `jwt_login.rs` / `jwt_modes.rs` |
| OAuth2 client | `protocol-oauth2` | Four grants, PKCE (OAuth 2.1), token introspection | `oauth2_flow.rs` / `oauth2_pkce.rs` |
| OAuth2 Server | `oauth2-server` | Full Server 4 endpoints | `oauth2_server_flow.rs` |
| OIDC | `protocol-oidc` | id_token issuance/verification + discovery + triple anti-replay | `oidc_handler.rs` |
| Keycloak RP | `keycloak-oidc` | Keycloak OIDC relying party | `keycloak_oidc.rs` |
| SSO | `protocol-sso` / `protocol-sso-server` | ticket flow / SsoServer abstraction / Redis pub/sub cross-instance | `sso_flow.rs` / `sso_server.rs` |
| SAML | `protocol-saml` | SAML 2.0 (XML signature verification) | — |
| API Key | `protocol-apikey` | Namespace management, secure storage | `apikey_management.rs` / `apikey_namespace.rs` |
| Temporary credentials | `protocol-temp` | Temporary token issuance | `temp_credential.rs` |
| QR-code login | `protocol-qrlogin` | First-party QR login (Web displays QR + App confirms): a two-ticket separated state machine (qr_ticket HMAC-SHA256-signed with a ≥32-byte secret; confirm_token one-shot with short TTL); inherent login-CSRF risk — any logged-in App user can scan someone else's QR code to log the victim into the attacker's account, so the scan response carries a masked summary of the pending login (device label + creation time) for the scanner to verify | — |
| API signing | `protocol-sign` | HMAC signature + nonce anti-replay | `sign_protocol.rs` |
| TOTP | `secure-totp` | RFC 6238 dynamic verification codes | `totp_login.rs` |
| Basic / Digest | `protocol-httpbasic` / `protocol-httpdigest` | Standard HTTP authentication | `httpbasic_login.rs` / `httpdigest_login.rs` |

> Note: `protocol-sso` implies `protocol-jwt` (OIDC id_token mandatory verification, fail-closed); `db-sqlite` and `db-postgres`/`db-mysql` are mutually exclusive. All constraints are in [🧪 Test Scenarios · Hard constraints](TEST_SCENARIOS.md#-hard-constraints-the-combination-matrix-must-obey).

---

## ⚙️ Configuration

`GarrisonConfig` manages all configuration uniformly and implements `serde::Serialize / Deserialize`:

- **Three-tier config-source merge**: code defaults → config file (TOML, loaded via confers `FileSource`, with path-traversal protection and a 10MB cap) → environment variables (confers `EnvSource`, flat keys separated by `__`).
- **Hot reload**: a `tokio::sync::watch` channel (the `config-hot-reload` face passes through confers).
- **Encryption**: the `config-encryption` face supports encrypted config files.

For the full config-item tables and TOML examples of session policy, token policy, anomalous behavior, cookie policy, multi-tenancy, remember-me etc., see the [⚙️ Configuration Guide](CONFIGURATION.md); the production environment-variable list is in `.env.example`.

---

## 🛡️ Security and Protection

| Capability | Feature | Description |
|------|---------|------|
| Password hashing | `account-credential` | Argon2id / Bcrypt, slow hashing offloaded off the async executor via `spawn_blocking`; Credential SPI + password policy (`account-policy`) + auth-flow DSL (`account-authflow`) |
| Firewall | `firewall` / `firewall-*` | Brute force / rate limiting / anomalous login / GeoIP / DDoS / WAF; enabling any `firewall-*` auto-wires the check hooks in the builder |
| Multi-tenant isolation | `tenant-isolation` | Logical isolation + IDOR protection; Header / Subdomain / Claim resolvers |
| Audit logging | `audit-log` | Audit listener + queries (`AuditConfig` / `AuditEntry` / `AuditQuery`), event payloads with unified token masking |
| Security toolkit | `secure-*` | Masking, XSS protection, constant-time comparison (`secure-ct-eq`, CWE-208), confusables, HMAC (`secure-sign`) |
| Email verification | `email-verification` (+`-smtp`) | Verification codes + SMTP sending + hourly rate limits |
| SMS rate limiting | `sms-rate-limit` | Hourly/daily dual-window rate limits and attempt controls |
| Invitation-code registration | `protocol-invitation` | Invitation-code credentials + DAO brute-force counters |

For security-configuration advice and the vulnerability reporting process see the [🔒 Security doc](SECURITY.md).

---

## 📡 Observability and Extensions

- **Event listening** (the `listener` feature, 31 event variants): implement the `GarrisonListener` trait (a single `async fn on_event` callback branching on `GarrisonEvent` variants) and register at compile time via `inventory::submit!`; login / logout / kick / replacement / expiry / refresh events call back in real time. Examples: [`event_listener.rs`](../../examples/src/bin/event_listener.rs), [`custom_plugin.rs`](../../examples/src/bin/custom_plugin.rs).
- **Plugins**: the `GarrisonPlugin` trait + inventory registration; inject logic in lifecycle hooks.
- **tracing logs** (`tracing-log`), **Prometheus metrics** (`metrics-prometheus`), **OTLP** (`otlp`): example [`observability_setup.rs`](../../examples/src/bin/observability_setup.rs).
- **gRPC interceptor** (`grpc`): a tonic auth layer. Example [`grpc_interceptor.rs`](../../examples/src/bin/grpc_interceptor.rs).
- **i18n** (`i18n` / `i18n-icu`): error messages switch between Chinese and English per locale (fluent + FTL resources, the `locales/` directory). Example [`i18n_usage.rs`](../../examples/src/bin/i18n_usage.rs).
- **Health checks** (`server-health-check`): `DbHealthCheck::with_pool` performs a real SQL round-trip probe. Example [`health_check.rs`](../../examples/src/bin/health_check.rs).
- **Microservices**: `backend-remote` (HTTP calls to a remote Auth Server + limiteron circuit breaking), `auth-server` (a standalone authentication server, sdforge declarative routing + TLS + graceful shutdown). Examples [`backend_remote.rs`](../../examples/src/bin/backend_remote.rs), [`auth_server.rs`](../../examples/src/bin/auth_server.rs).

---

## 🧬 Advanced Authentication Capabilities (0.9.0-rc.3)

The following capabilities landed with the rc.3 security-audit remediation batch, gated independently per feature; config items are in the corresponding sections of the [⚙️ Configuration Guide](CONFIGURATION.md), public APIs in the [📘 API Reference · rc.3 additions](API_REFERENCE.md), end-to-end usage in [examples/](../../examples/).

| Capability | Feature | Module | Config section |
|------|---------|------|--------|
| At-rest encryption of sensitive DB fields | `field-encryption` | `secure::encryption` | §2.9 |
| WebAuthn / Passkey authentication | `protocol-webauthn` | `protocol::webauthn` | §2.10 |
| MFA / step-up orchestration and recovery codes | `mfa-recovery` | `stp::mfa` | §2.11 |
| Password-reset flow | `account-password-reset` | `account::password_reset` | §2.12 |
| OIDC Back-Channel Logout | `backchannel-logout` | `oauth2_server::backchannel` | Architecture doc |
| Refresh-token reuse detection/grace | `oauth2-server` | `protocol::jwt::refresh` | §2.14 |
| Unified error model (request-id / Retry-After) | always-on | `context::request_id` / `error` | API "Unified error response body (R04)" |

---

## ✅ Best Practices

1. **Start with the `development` preset, then narrow the feature face step by step**: aggregate features are for quick validation; enable per need in production to cut build time and binary size.
2. **Cache inside the `GarrisonInterface` callbacks**: permission/role callbacks fire on every authorization; cache on the data-source side or use the Repository layer directly.
3. **Do not parse tokens manually in handlers**: the web middleware has completed the task_local binding; call the `GarrisonUtil` static APIs directly in handlers.
4. **Follow the dbnexus exclusivity constraints**: choose one of SQLite (embedded) vs PostgreSQL/MySQL (server-side); `--all-features` is unusable.
5. **Enable the firewall and auditing in production**: `firewall-bruteforce` etc. auto-wire when enabled; `audit-log` events already mask tokens uniformly — custom listeners must not log the full token.
6. **Read the Breaking sections of the [📋 Changelog](CHANGELOG.md) before upgrading**: v0.9.0 has feature renames and fail-closed behavior changes (`check_api_key` / `check_abac` etc.).
7. **When something breaks, check the [❓ FAQ](FAQ.md) and [🔧 Troubleshooting](TROUBLESHOOTING.md) first**.

---

## 📚 Further Reading

| Document | Description |
|------|------|
| [📘 API Reference](API_REFERENCE.md) | Public API and module reference |
| [🏗️ Architecture](ARCHITECTURE.md) | Design principles, module layout, and data flow |
| [⚙️ Configuration](CONFIGURATION.md) | Three-tier config sources, full config items, and hot reload |
| [🧪 Test Scenarios](TEST_SCENARIOS.md) | Acceptance scenario inventory and feature combination matrix |
| [⚡ Performance](PERFORMANCE.md) | Performance targets, benchmarks, and optimization advice |
| [🚀 Deployment](DEPLOYMENT.md) | Production deployment notes |
| [💻 Examples directory](../../examples/) | 65 runnable examples (`cargo run -p garrison-examples --bin <name> --features full`) |

---

<a id="msrv-note"></a>

## 📦 Installation Note: MSRV and Toolchain Requirements (migrated from README)

Requires Rust **1.97.1 or later** (`rust-version = "1.97.1"` in `Cargo.toml`): the sibling-ecosystem crates in the dependency set (the rc line of confers / oxcache / dbnexus / sdforge / limiteron / inklog / trait-kit) each declare `rust-version = "1.97.1"`, which is the lowest toolchain the dependency graph accepts — `cargo check` under an older toolchain fails outright (`rustc ... is not supported by the following packages`); the CI test matrix verifies `1.97.1` (the MSRV floor) / `stable` / `beta` explicitly.
