# ❓ Garrison FAQ

This file collects the questions most frequently asked about designing, using, and deploying the Garrison framework. If you are new to Garrison, we recommend reading this file before consulting the API docs.

> Project repository: <https://github.com/Kirky-X/garrison>
> Current version: 0.9.0 (2026-11-14) | Next version: 1.0.0 (gates started, 2027 Q2)

## 📋 Table of Contents

- [Design](#-design)
- [Usage](#-usage)
- [Deployment](#-deployment)

---

## 🧭 Design

### Q: Why model 13 feature domains?

A: The auth domain only becomes composable and trimmable when boundaries are clear and responsibilities are single. Garrison divides authentication and authorization into 13 feature domains, each with a clear boundary and a concise, intuitive API; this modular split fits the Rust ecosystem well — using Rust's type system, ownership, and feature gating for zero-cost abstraction. Compared with lightweight libraries that solve a single problem, such as Actix-Web's `actix-identity` or `axum-login`, full-scenario coverage better matches Garrison's goal as a "one-stop authentication and authorization framework".

### Q: Why a global singleton `GarrisonManager` instead of dependency injection?

A: This is Garrison's trade-off between engineering convenience and architectural purity. The global singleton lets us offer static APIs like `GarrisonUtil`, so business code can call `login`, `checkPermission` and other methods without threading an `Arc<Manager>` through every layer, greatly reducing cognitive cost. At the same time we keep the `GarrisonInterface` trait abstraction; combined with `GarrisonManager::reset_for_test()` (gated by `#[cfg(any(test, feature = "testing"))]`), unit tests can inject mock implementations without introducing any DI container dependency. In short: **production takes convenience from the singleton; tests take replaceability from the trait**.

### Q: Why `inventory` compile-time registration instead of runtime reflection?

A: Rust has no Java/C#-style runtime reflection and cannot scan types and register them automatically at runtime. The candidate options are `linkme` (link-time collection) and `inventory` (compile-time distributed slices), which are similar in approach. Garrison chose `inventory` because it:

- Has zero runtime overhead (no `OnceLock` initialization jitter);
- Registers across crates (a plugin crate only needs `inventory::submit!` to be discovered by the main framework);
- Is naturally compatible with cargo feature gating (a disabled feature means the corresponding submit macro is not compiled).

The cost is that registrations cannot be unloaded dynamically, but Garrison's plugins (Listener, Plugin, Strategy) are assembled at startup and immutable at runtime, so compile-time registration suffices.

### Q: Why `oxcache` + `dbnexus` instead of existing crates?

A: Existing crates each have limitations: `moka` lacks per-entry TTL; `cached` abstracts at too low a level; `sqlx` couples directly to database connection pools without abstracting backends. Garrison needs:

- **A unified abstraction layer**: the `GarrisonDao` trait masks backend differences; business code faces only the trait;
- **Per-entry TTL**: different tokens/sessions have different expiry times; entry-level expiry is a must;
- **Consistency with the framework design**: `oxcache` 0.5 provides per-entry TTL and layer abstraction, `dbnexus` 0.6 provides a unified interface over SQLite / PostgreSQL / MySQL — together they cover Garrison's "memory + persistence" two-tier cache needs, with no need to reinvent the wheel.

### Q: Why wrap `JwtHandler` instead of using `jsonwebtoken` directly?

A: Using `jsonwebtoken` directly has three pain points:

1. The claims structure is user-defined, so the framework cannot inject standard fields (like `sub`, `iss`, `garrison:*` namespace fields), forcing every integration to reinvent claims;
2. The error type is `jsonwebtoken::errors::Error`, not interoperable with the `GarrisonError` system, requiring `map_err` translation on the business side;
3. `jsonwebtoken` provides no high-level API for production needs like multi-algorithm support, key rotation, and kid headers.

The `JwtHandler` wrapper pre-populates the framework's standard fields in `GarrisonJwtClaims`, unifies error conversion into existing `GarrisonError` variants (there is no dedicated `Jwt` variant: signature/parsing failures → `InvalidToken`, expiry → `ExpiredToken`, key and algorithm configuration problems → `Config`, PEM/system-clock internal errors → `Internal`, see `src/protocol/jwt/handler.rs`), and offers one-stop `sign`/`verify`/`refresh` APIs. The business side extends custom fields by defining its own claims structure and passing it to `sign`/`verify`, without caring about algorithm details (the framework provides no extension trait like `GarrisonJwtClaimsExt` — `GarrisonJwtClaims` is a fixed struct).

---

## 💻 Usage

### Q: How do I switch token styles (uuid / random-64 / jwt)?

A: Configure the `token_style` field in `GarrisonConfig`:

```rust
let mut config = GarrisonConfig::default_config();
config.token_style = "uuid".to_string();        // 32-char UUID
// config.token_style = "random_64".to_string(); // 64-char random string
// config.token_style = "jwt".to_string();       // JWT (requires the protocol-jwt feature)
// Initialization must inject dao and interface (see "How do I customize the permission data source?" below)
GarrisonManager::builder()
    .dao(dao)
    .config(Arc::new(config))
    .interface(interface)
    .build()
    .await?;
```

Notes:

- `uuid` and `random_64` need no extra features;
- the `jwt` style requires the `protocol-jwt` feature (supported since 0.2.0);
- `token_style` is a string field; legal values are in the `TOKEN_STYLES` constant (`uuid` / `random_64` / `simple` / `jwt`);
- after switching styles, previously issued tokens remain valid until they naturally expire.

### Q: How do I implement mutual kick-out for multi-device login?

A: Set `is_concurrent = false`. Garrison allows concurrent multi-device login by default (e.g. Web + App simultaneously); when `is_concurrent` is off, a new login of the same account automatically kicks the old device's session, and the old device's next request receives `NotLoginException`.

```rust
let mut config = GarrisonConfig::default_config();
config.is_concurrent = false;
config.max_login_count = 5; // optional: keep at most 5 active tokens per account; overflow handled per overflow_logout_mode
```

For finer control (e.g. PCs kick each other but PC and App coexist), enable the `device-binding` feature (see the `device_binding_mode` field: `strict` / `loose` / `disabled`) and configure binding policies per device dimension.

### Q: How do I use Garrison in a non-axum framework (actix-web, warp, an in-house HTTP framework)?

A: Garrison's core logic is decoupled from HTTP frameworks; the axum integration is just the `web-axum` feature of the `garrison` crate. In other frameworks:

```rust
use garrison::stp::with_current_token;

// 1. Set the task_local manually in the request middleware
async fn auth_middleware(req: Request, next: Next) -> Response {
    let token = req.headers().get("Authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "));
    with_current_token(token.unwrap_or("").to_string(), next.run(req)).await
}

// 2. Call GarrisonUtil directly in handlers
async fn handler() -> &'static str {
    GarrisonUtil::check_login(); // reads the current token from task_local automatically
    "ok"
}
```

Only the `with_current_token` task-local injection layer is required. Garrison already ships official `web-actix` and `web-warp` adapter features (the ActixContext / WarpContext 4-piece Extractor adaptation since 0.4.2).

### Q: How do I customize the permission data source (RPC service, file, in-house permission center)?

A: Implement the `GarrisonInterface` trait and inject it at `GarrisonManager::builder().build().await`:

```rust
struct MyAuthSource;

#[async_trait]
impl GarrisonInterface for MyAuthSource {
    async fn get_permission_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        // fetch from your permission center via RPC
        let perms = rpc_client.query_permissions(login_id).await?;
        Ok(perms)
    }
    // implement other methods as needed
}

let config = Arc::new(GarrisonConfig::default_config());
let interface: Arc<dyn GarrisonInterface> = Arc::new(MyAuthSource);
GarrisonManager::builder()
    .dao(dao)
    .config(config)
    .interface(interface)
    .build()
    .await?;
```

`GarrisonInterface` provides Default implementations (returning empty collections); you only override the methods you care about. The trait returns `GarrisonResult` for every method, making it easy to funnel external errors into `GarrisonError`.

### Q: How do I disable "throw on not logged in" and return `false` or a custom error instead?

A: Set `throw_on_not_login = false`. By default `GarrisonUtil::check_login` returns `Err(GarrisonError::NotLogin)` when not logged in; after disabling, all check-series methods return `Ok(false)` when not logged in, allowing gentle branches like `if !GarrisonUtil::check_login().await? { ... }`.

```rust
let mut config = GarrisonConfig::default_config();
config.throw_on_not_login = false;
```

> Note: the current version only has `throw_on_not_login`; there is no separate `throw_on_not_permission` field. When not logged in, `check_permission` behaves like `check_login` (controlled by `throw_on_not_login`); when logged in but lacking permission it always returns `Ok(false)` without throwing.

To customize the error response body (rather than the default JSON of `GarrisonError::into_response()`), catch `GarrisonError` in your axum handler/middleware and construct the response yourself, or implement `axum::response::IntoResponse` for your custom error type.

### Q: How do I reset the global singleton `GarrisonManager` in tests?

A: Call `GarrisonManager::reset_for_test()`. The method is gated by `#[cfg(any(test, feature = "testing"))]` (`src/manager/impls.rs:89`) — it exists in test builds and builds that enable the public `testing` feature; it aborts the background cleanup task and clears the global logic / strategy references, returning the manager to its uninitialized state (requiring a fresh `builder().build()` afterwards), so every test case can start from a clean state:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn setup() {
        GarrisonManager::reset_for_test();
        // re-init your test config (inject the test dao / interface)
        let config = Arc::new(GarrisonConfig::default_config());
        GarrisonManager::builder()
    .dao(test_dao())
    .config(config)
    .interface(test_interface())
    .build()
    .await.unwrap();
    }

    #[test]
    fn test_login() {
        setup();
        // ... test logic
    }
}
```

Never call this method in production code — it unconditionally clears all online sessions. It is gated by `#[cfg(any(test, feature = "testing"))]`, so it is not "absent from release builds": release builds that explicitly enable the public `testing` feature (`Cargo.toml`) compile the symbol too.

---

## 🚀 Deployment

### Q: Which features should production enable?

A: The aggregate feature `production` is recommended; it includes the following sub-features:

```toml
[dependencies]
garrison = { version = "0.9.0", features = ["production"] }
```

`production` aggregates the following 41 features (the authoritative list is `[features] production` in `Cargo.toml`):

- `cache-redis` (Redis cache backend, includes `cache-memory`), `three-tier-cache` (three-tier cache architecture), `cache-batch`, `cache-audit`
- `db-postgres` (PostgreSQL persistence), `db-sharding`, `db-replica`
- `web-axum` (axum extractor + Router + Interceptor)
- `protocol-jwt` (JWT issuance and verification), `protocol-sign` (API signing + nonce anti-replay), `protocol-webauthn` (WebAuthn / Passkey), `backchannel-logout`
- `secure-sign` (HMAC signing utilities), `field-encryption`
- `listener` (event listeners for audit and logging)
- `tracing-log` (tracing logs), `metrics-prometheus` (Prometheus metrics export)
- `audit-inklog` (inklog structured audit logs)
- `tenant-isolation` (multi-tenant logical isolation)
- `security-alert` (security alerting), `session-hijack-detection`, `security-extra`
- `device-binding` (device-binding policy)
- `mfa-recovery`, `account-password-reset`
- `core-advanced` (decision provenance / permission registry / forbid-priority semantics)
- `firewall-waf` (WAF request content validation), `firewall-gcra`, `firewall-tower`, `firewall-monitoring`, `firewall-parallel`
- `sms-rate-limit` (progressive SMS-code rate limiting)
- `backend-embedded` (default embedded backend), `backend-kit` (trait-kit typestate DI construction)
- `auth-server` (standalone Auth Server mode), `auth-server-sdforge` (declarative routing)
- `abac` (Cedar DSL attribute-based access control engine)
- `api-docs`, `config-yaml`, `config-distributed`, `config-audit`

> Note: `email-verification` / `email-verification-smtp` are **not** in the `production` aggregate — they are only in the `full` face. Email verification codes are optional; append them explicitly as needed.

For other protocol features such as OAuth2 or SSO, append them separately:

```toml
features = ["production", "protocol-oauth2", "protocol-sso"]
```

For the OAuth2 Server (authorize / token / revoke / introspect endpoints + PKCE), append `oauth2-server`:

```toml
features = ["production", "protocol-oauth2", "oauth2-server"]
```

Note: `default = ["backend-embedded"]` (embedded backend only) — a plain `cargo build` without `--features` compiles only the core modules + the embedded backend, handy in environments without external dependencies (e.g. Edge, WASM).

### Q: Are PostgreSQL / MySQL supported?

A: **Yes.** Since 0.5.0, `dbnexus` 0.4+ provides a unified abstraction over SQLite / PostgreSQL / MySQL, selected via the `db-sqlite` / `db-postgres` / `db-mysql` features. The `production` aggregate defaults to `db-postgres`.

- PostgreSQL backend available since 0.5.0 (the `db-postgres` feature)
- MySQL backend available since 0.5.3 (the `db-mysql` feature)
- `dbnexus` has now been upgraded to 0.6 (see `Cargo.toml`)

Note: at most one relational backend may be enabled. dbnexus has two compile-time `compile_error!` constraints — (1) embedded (sqlite / duckdb) and server-side (postgres / mysql) cannot mix; (2) without an embedded backend, `postgres` and `mysql` are mutually exclusive. The MySQL backend's integration tests require Docker (via `testcontainers`).

### Q: Are distributed sessions supported?

A: In two layers — **distributed rate limiting is supported (since rc.4); distributed sessions are not currently supported**.

- **Rate limiting (supported)**: enable `rate-limit-redis` and set `GARRISON_RATE_LIMIT_BACKEND=redis`, `GARRISON_REDIS_URL=…`; the login firewall hook and `RateLimitStrategy` counters land in an independent Redis runtime shared across instances (coverage and failure semantics in the multi-instance rate-limiting section of [DEPLOYMENT.md](./DEPLOYMENT.md)).
- **Sessions / permission cache (not supported)**: runtime state such as sessions, tokens, and mutual kick-out still lives in each instance's local DAO and in-process oxcache. The cache-side Redis L2 interface (`cache-redis`'s `with_redis_config`) currently **only stores the configuration and does not actually wire a Redis backend** (see the M4 note in `src/dao/oxcache_impl.rs`), and `GARRISON_REDIS_URL` is not injected into the cache side either — multiple Garrison instances cannot form a session cluster by sharing one Redis. For cross-instance sessions use sticky sessions or stateless JWT; switching the whole DAO to Redis (candidate A) remains backlog in the [roadmap](./ROADMAP.md).

`RedisDeploymentMode` (Single / Sentinel / Cluster / PrimaryReplica since 0.6.1; the legacy value `MasterSlave` stays compatible via `#[serde(alias)]`) is the topology descriptor of the cache-side `RedisConfig`, passable only programmatically via `with_redis_config` (`GarrisonConfig` has **no** `cache` / `redis` fields; the config file cannot set them):

```rust
use garrison::dao::{RedisConfig, RedisDeploymentMode};

let redis = RedisConfig {
    mode: RedisDeploymentMode::Single {
        url: "redis://:password@10.0.0.1:6379/0".to_string(),
    },
    password: None,
    db: 0,
    connection_timeout_secs: 5,
    pool_size: 10,
};
// hand it to the cache builder (with_redis_config), not into GarrisonConfig
// note: in the current version this config is only stored (Redis L2 is not wired); the cache remains in-process memory
let dao = build_dao().with_redis_config(redis);
```

Note: single-machine `oxcache` in-memory mode cannot be shared across instances and suits single-instance deployments or development environments only.

### Q: How do I monitor framework runtime status (QPS, latency, failure rate, active sessions)?

A: Enable the `listener` and `metrics-prometheus` features:

```rust
// Cargo.toml: features = ["listener", "metrics-prometheus"]
let config = Arc::new(GarrisonConfig::default_config());
GarrisonManager::builder()
    .dao(dao)
    .config(config)
    .interface(interface)
    .build()
    .await?;
```

Then:

- **Listener**: implement the `GarrisonListener` trait and branch on the `GarrisonEvent` variants (31, e.g. `Login` / `Logout` / `Kickout` / `PermissionCheck`) in the single `async fn on_event(&self, event: &GarrisonEvent)` callback, logging or shipping to ELK;
- **Prometheus metrics**: the library does not mount any scrape endpoint automatically — the business must expose `GarrisonMetrics::gather()` (the `metrics-prometheus` feature) as a route itself (e.g. `Router::new().route("/metrics", get(handler))` under axum; see the mdbook "Observability · Metrics"). The reference deployment `auth_server`'s metrics endpoint is `/api/v1/metrics` (the `auth-server-sdforge` `#[forge]` route with `path = "/metrics"` + `version = "v1"`, auto-prefixed by the macro to `/api/{version}{path}`), and it returns a JSON-serialized string rather than standard Prometheus `text/plain`, so standard scrapers cannot parse it directly. The metric set includes:
  - `garrison_login_total{result}`
  - `garrison_token_validation_duration_seconds`
  - `garrison_permission_query_total`
  - `garrison_role_query_total`

Since 0.3.0, OpenTelemetry is integrated (the `otlp` feature), providing distributed tracing so Garrison's internal timings can join end-to-end trace spans.

---

> This FAQ is updated continuously with releases. For uncovered questions, please ask in [GitHub Discussions](https://github.com/Kirky-X/garrison/discussions).
