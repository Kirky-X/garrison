# 🔧 Troubleshooting

This file collects common issues, causes, and solutions from Garrison development and deployment, organized as Q&A.

- Repository: <https://github.com/Kirky-X/garrison>
- License: Apache-2.0
- MSRV: Rust 1.97.1+ (`rust-version` in `Cargo.toml`, matching the sibling-ecosystem rc-line dependencies' requirement)

> For environment setup see [🛠️ Development Standards](./DEVELOPMENT.md); for deployment issues see [🚀 Deployment Guide](./DEPLOYMENT.md).

## 📋 Table of Contents

- [Build Issues](#-build-issues)
- [Runtime Issues](#️-runtime-issues)
- [Testing Issues](#-testing-issues)

---

## 📦 Build Issues

### Q1.1 Build error `failed to load source for dependency oxcache`

**Symptom**:

```text
error: failed to load source for dependency `oxcache`
Caused by:
  failed to read `/home/kirky/projects/oxcache/Cargo.toml`
  No such file or directory (os error 2)
```

**Cause**: in early versions (≤ 0.5.3) `Cargo.toml` used a local `path` dependency for `oxcache`, but no project existed at that path. Since 0.9.0 the published crates.io `oxcache` is used and no local path dependency is needed.

**Fix**: upgrade to 0.9.0+; oxcache in `Cargo.toml` is now a crates.io dependency (currently on the stable line):

```toml
oxcache = { version = "0.5", optional = true, default-features = false }
```

> Note: version requirements like `"0.5"` cannot match prerelease versions; writing `"0.5"` fails to resolve or falls back to an older version. The rc line requires the full version number explicitly (see the `Cargo.toml` workspace dependency declarations).

If you are still on an old version, clone the oxcache repository to the expected path:

```bash
git clone https://github.com/Kirky-X/oxcache.git /home/kirky/projects/oxcache
```

---

### Q1.2 Build error `cannot find -lssl` (libssl-dev missing)

**Symptom**:

```text
error: linking with `cc` failed
= note: /usr/bin/ld: cannot find -lssl
```

**Cause**: the system lacks the OpenSSL development libraries and `pkg-config`.

**Fix**: install the system dependencies:

```bash
# Debian / Ubuntu
sudo apt install -y libssl-dev pkg-config

# CentOS / RHEL
sudo yum install -y openssl-devel pkgconfig

# macOS
brew install openssl pkg-config
```

---

### Q1.3 Build error `feature edition2024 is required`

**Symptom**:

```text
error: feature `edition2024` is required
The cargo feature `edition2024` requires nightly cargo
```

**Cause**: some dependencies (e.g. `inventory 0.3`) require `edition2024` (Rust 1.85+); the sibling-ecosystem crates on the rc line further require Rust 1.97.1+, which is why `Cargo.toml` takes the latter as MSRV.

**Fix**: update the Rust toolchain to 1.97.1+:

```bash
rustup update stable
rustc --version   # confirm >= 1.97.1
```

The local toolchain follows rustup's default channel; confirm the toolchain in use is ≥ 1.97.1 (the CI test matrix explicitly verifies `1.97.1` / `stable` / `beta`).

---

### Q1.4 Feature enabled but the module is not compiled

**Symptom**: the `protocol-jwt` feature was added in `Cargo.toml`, but `cargo build` reports the module does not exist.

**Cause**: `--features` was not passed on the command line, or the feature name is misspelled.

**Fix**:

```bash
# Check whether the feature is actually enabled
cargo tree --features full -e features | grep jwt

# Compile with the feature explicitly
cargo build --features protocol-jwt

# Or use the aggregate feature
cargo build --features full
```

> Note: `default = ["backend-embedded"]` (only the embedded backend) — a plain `cargo build` without `--features` compiles only the core modules + the embedded backend.

---

### Q1.5 clippy warnings failing CI

**Symptom**: the local build passes, but CI fails on clippy warnings.

**Cause**: CI uses `-D warnings` to treat warnings as errors.

**Fix**: run clippy locally to the CI standard and fix:

```bash
cargo clippy --features full --lib --tests -- -D warnings
```

Common warnings and fixes:

| Warning | Fix |
|------|------|
| `clippy::needless_return` | Remove the redundant `return` |
| `clippy::redundant_clone` | Remove the unnecessary `.clone()` |
| `clippy::unnecessary_unwrap` | Replace `unwrap()` with `if let` / `match` |
| `clippy::missing_docs` | Add `///` docs to the `pub` item |

---

## ⚠️ Runtime Issues

### Q2.1 Panic when calling the Garrison API: `GarrisonManager not initialized`

**Cause**: `GarrisonManager::builder().build().await` was not called at service startup.

**Fix**: call the initialization during service setup (after opening the database connection, before listening on the port):

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Open the database connection
    // 2. Run migrations
    // 3. Initialize GarrisonManager (must precede all API calls; synchronous API)
    let config = Arc::new(GarrisonConfig::default_config());
    GarrisonManager::builder()
    .dao(dao)
    .config(config)
    .interface(interface)
    .build()
    .await?;

    // 4. Start the axum service
    let app = Router::new()
        .route("/protected", get(protected_handler))
        .layer(GarrisonLayer::new());
    axum::serve(listener, app).await?;
    Ok(())
}
```

---

### Q2.2 `check_login` returns false although the user is logged in (token not taking effect)

**Symptom**: the user logged in via `login`, but `check_login()` keeps returning `false` in subsequent requests.

**Cause**: Garrison reads the current request's token from the task_local context. If the axum middleware did not extract the token and set it into task_local, the context is empty.

**Fix**: make sure routes are built through `GarrisonRouter` (which applies the token-extraction middleware automatically):

```rust
use garrison::router::GarrisonRouter;
use std::sync::Arc;

let app = GarrisonRouter::new(Arc::new(config))
    .route("/protected", get(protected_handler))
    .build();   // build() applies garrison_middleware automatically, extracting the token from the request header into task_local
```

Inside, `GarrisonRouter::build()` applies the middleware via `from_fn_with_state(state, garrison_middleware)`, extracting the token from the `garrison_token` header (or Cookie), resolving the session, and writing it into the task_local context, after which `check_login()` reads it correctly.

---

### Q2.3 Sessions expire immediately

**Symptom**: shortly after login (well before timeout) the session becomes invalid and re-login is required.

**Cause**: the `timeout` config is too small, or the unit was mistaken (configured in seconds but written as milliseconds).

**Fix**:

1. Check the environment variable `GARRISON_TIMEOUT` (unit: seconds):

   ```bash
   echo $GARRISON_TIMEOUT   # 30 days = 2592000
   ```

2. Check the unit of the `timeout` field (seconds) in `garrison.toml`.

3. Default reference:

   | Config | Default | Description |
   |--------|--------|------|
   | `timeout` | `2592000` (30 days) | Maximum session lifetime |
   | `active_timeout` | `-1` (follows timeout) | Active timeout |

---

### Q2.4 Permission check fails (permission denied)

**Symptom**: a logged-in user calling `check_permission("user:read")` always gets `false`.

**Cause**: the `GarrisonInterface` trait's `get_permission_list` implementation returns an empty list, or the data source grants that user no such permission.

**Fix**:

1. Check that the `GarrisonInterface` implementation actually queries the permission data source:

   ```rust
   #[async_trait]
   impl GarrisonInterface for MyInterface {
       async fn get_permission_list(&self, user_id: &str) -> GarrisonResult<Vec<String>> {
           // confirm this really queries the database rather than returning an empty Vec
           self.db.query_permissions(user_id).await
       }
   }
   ```

2. Check that the database's `app_permission` and `app_user_role` tables contain corresponding records (the framework schema uniformly carries the `app_` prefix; roles are defined in `app_role`, and role-permission mapping in `app_role_permission`).

3. Enable debug logging to see the actually returned permission list:

   ```bash
   RUST_LOG=garrison::core::permission=debug ./your-server
   ```

---

## 🧪 Testing Issues

### Q3.1 Test passes alone but fails in a full run (serial_test conflict)

**Symptom**: a test passes alone but fails intermittently during a full `cargo test` run.

**Cause**: the test mutates a global singleton (e.g. `GarrisonManager`) or environment variables (`std::env::set_var`), and concurrent multi-threaded execution pollutes them mutually.

**Fix**: annotate tests that mutate global state with `#[serial_test::serial]` to force serial execution:

```rust
use serial_test::serial;

#[tokio::test]
#[serial]
async fn test_init_manager() {
    GarrisonManager::reset_for_test();
    // init is a synchronous API, injecting the three params dao / config / interface
    GarrisonManager::builder()
    .dao(dao)
    .config(config)
    .interface(interface)
    .build()
    .await.unwrap();  // mutates the global singleton
    assert!(GarrisonManager::is_initialized());
}

#[test]
#[serial]
fn test_env_var_override() {
    std::env::set_var("GARRISON_TIMEOUT", "3600");
    // ...
    std::env::remove_var("GARRISON_TIMEOUT");
}
```

> **Rule of thumb**: as soon as a test calls `GarrisonManager::builder().build().await`, `std::env::set_var()`, or mutates a `once_cell` global, it must carry `#[serial]`.

---

### Q3.2 `cargo llvm-cov` errors or abnormal coverage results

**Symptom**: errors or abnormal results when running coverage.

**Cause**: the repository's coverage tool is `cargo-llvm-cov` (the CI coverage job and the common-command tables of `README` / `DEVELOPMENT` share this scope), not `cargo-tarpaulin` — there is no tarpaulin config in the repository. Common causes: `cargo-llvm-cov` not installed or the toolchain missing the `llvm-tools` component; using `--all-features` in the command (db-sqlite and db-postgres are mutually exclusive and dbnexus raises `compile_error!` directly); a sqlite file-database URL triggering `SQLITE_READONLY` under the llvm-cov instrumentation surface.

**Fix**:

1. Install the tool and component:

   ```bash
   cargo install cargo-llvm-cov
   rustup component add llvm-tools-preview
   ```

2. Run with the CI's feature scope (not `--all-features`):

   ```bash
   cargo llvm-cov --features "full" --fail-under-lines 95
   ```

3. If you hit `SQLITE_READONLY` (triggered by a sqlite file-database URL under the llvm-cov instrumentation surface; noted in the CI coverage job too), fall back to the in-memory database the way CI does:

   ```bash
   GARRISON_TEST_SQLITE_MEMORY=1 cargo llvm-cov --features "full" --fail-under-lines 95 --lcov --output-path coverage/lcov.info
   ```

---

### Q3.3 `inventory::iter` returns empty

**Symptom**: iterating `inventory::iter::<T>()` yields nothing although the code clearly calls `inventory::submit!`.

**Cause**: the test module lacks an explicit `use std::iter::Iterator`, or the module containing the registration is not compiled (feature not enabled).

**Fix**:

1. Add the `use` declarations:

   ```rust
   use std::iter::Iterator;
   use inventory::iter;

   for item in iter::<MyRegistration>() {
       // ...
   }
   ```

2. Confirm the module holding the registration is brought into the compilation unit by a `mod` declaration.
3. Confirm the feature flag enabling that module is on.

---

## 4. Configuration Issues

### Q4.1 Environment variables not taking effect

**Symptom**: `GARRISON_TIMEOUT` was set, but the config did not change.

**Cause**: the environment variable was not loaded correctly, or its priority is lower than expected.

**Fix**:

1. Confirm the variable is set and effective before process start:

   ```bash
   echo $GARRISON_TIMEOUT
   ```

2. Confirm the variable-name prefix is right (`GARRISON_`), e.g. `GARRISON_TOKEN_STYLE` rather than `TOKEN_STYLE`.
3. If a `.env` file is used, confirm the application loads `.env` with a crate like `dotenvy` (Garrison only reads process environment variables and does not load `.env` files itself).
4. Confirm the boolean format is valid (`true`/`false`/`1`/`0`/`yes`/`no`/`on`/`off` supported).

---

### Q4.2 toml config file parse error

**Symptom**: startup fails with `GarrisonError::Config: toml parse error`.

**Cause**: a syntax error in `garrison.toml`, e.g. misspelled field names or type mismatches.

**Fix**:

1. Check toml syntax (field names use underscores; strings use double quotes):

   ```toml
   # correct
   token_name = "garrison_token"
   token_style = "uuid"
   timeout = 2592000

   # wrong (hyphenated field name)
   # token-name = "garrison_token"
   ```

2. Check that `token_style` is a legal value (`uuid` / `random_64` / `simple` / `jwt`; note the underscore).
3. Check that `cookie_same_site` is a legal value (`Lax` / `Strict` / `None`).
4. Debug with `cargo expand` or by printing the parsed result in code.

---

### Q4.3 Config hot-reload not taking effect

**Symptom**: after calling `config.update()`, subscribers do not receive the new configuration.

**Cause**: the config instance never called `with_watcher()`, or the watcher was closed.

**Fix**:

1. Confirm the config instance was created via `default_config()` (which attaches the watcher automatically):

   ```rust
   let config = GarrisonConfig::default_config(); // watcher attached
   ```

2. If created via deserialization, call `with_watcher()` manually:

   ```rust
   let config: GarrisonConfig = toml::from_str(&toml_str)?;
   let config = config.with_watcher(); // attach the watcher manually
   ```

3. Check whether `update()` returned `Err` (invalid values are rejected by `validate()`).

---

## 5. Getting Help

If the above did not solve your problem, get help through these channels:

### 5.1 GitHub Issues

File a bug report or feature request: <https://github.com/Kirky-X/garrison/issues>

When filing an issue, please attach:

- The Garrison version (`garrison = "0.x"`)
- The list of enabled features
- The Rust version (`rustc --version`)
- The operating system and architecture
- A minimal reproduction or the complete error output

### 5.2 GitHub Discussions

For usage consultations, architecture discussions, and best-practice exchange: <https://github.com/Kirky-X/garrison/discussions>
