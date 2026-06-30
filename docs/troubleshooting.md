# 常见问题排查

本文件汇总 Bulwark 项目开发与部署中常见的问题、原因与解决方案，以 Q&A 格式组织。

- 仓库：<https://github.com/Kirky-X/bulwark>
- License：Apache-2.0
- MSRV：Rust 1.85+

> 开发环境搭建详见 [development.md](./development.md)；部署问题详见 [deployment.md](./deployment.md)。

---

## 1. 编译问题

### Q1.1 编译时报错 `failed to load source for dependency oxcache`

**现象**：

```
error: failed to load source for dependency `oxcache`
Caused by:
  failed to read `/home/kirky/projects/oxcache/Cargo.toml`
  No such file or directory (os error 2)
```

**原因**：`Cargo.toml` 中 `oxcache` 使用本地 `path` 依赖（`path = "/home/kirky/projects/oxcache"`），但该路径下不存在项目。crates.io 0.3.0 未暴露 `Cache<K,V>::ttl()`，本地仓库已暴露，故使用 path 依赖。

**解决**：将 oxcache 仓库克隆到指定路径：

```bash
git clone https://github.com/Kirky-X/oxcache.git /home/kirky/projects/oxcache
```

若希望放到其他路径，修改 `Cargo.toml`：

```toml
oxcache = { path = "/your/path/oxcache", optional = true }
```

---

### Q1.2 编译时报错 `cannot find -lssl`（libssl-dev 缺失）

**现象**：

```
error: linking with `cc` failed
= note: /usr/bin/ld: cannot find -lssl
```

**原因**：系统缺少 OpenSSL 开发库与 `pkg-config`。

**解决**：安装系统依赖：

```bash
# Debian / Ubuntu
sudo apt install -y libssl-dev pkg-config

# CentOS / RHEL
sudo yum install -y openssl-devel pkgconfig

# macOS
brew install openssl pkg-config
```

---

### Q1.3 编译时报错 `feature edition2024 is required`

**现象**：

```
error: feature `edition2024` is required
The cargo feature `edition2024` requires nightly cargo
```

**原因**：部分依赖（如 `inventory 0.3`）要求 `edition2024`，需要 Rust 1.85+。

**解决**：更新 Rust 工具链至 1.85+：

```bash
rustup update stable
rustc --version   # 确认 >= 1.85
```

项目根目录已配置 `rust-toolchain.toml` 锁定工具链版本，`rustup` 会自动安装所需版本。

---

### Q1.4 启用了 feature 但模块未编译

**现象**：在 `Cargo.toml` 中添加了 `protocol-jwt` feature，但 `cargo build` 时报模块不存在。

**原因**：未在命令行传递 `--features` 参数，或 feature 名称拼写错误。

**解决**：

```bash
# 检查 feature 是否正确启用
cargo tree --features full -e features | grep jwt

# 显式指定 feature 编译
cargo build --features protocol-jwt

# 或使用聚合 feature
cargo build --features full
```

> 注意：`default = []`（空），仅 `cargo build` 不带 `--features` 时只编译核心模块。

---

### Q1.5 clippy 警告导致 CI 失败

**现象**：本地编译通过，但 CI 中 clippy 报警告并失败。

**原因**：CI 使用 `-D warnings` 将警告视为错误。

**解决**：本地按 CI 标准运行 clippy 并修复：

```bash
cargo clippy --features full --lib --tests -- -D warnings
```

常见警告及修复：

| 警告 | 修复 |
|------|------|
| `clippy::needless_return` | 移除冗余 `return` |
| `clippy::redundant_clone` | 移除不必要的 `.clone()` |
| `clippy::unnecessary_unwrap` | 用 `if let` / `match` 替代 `unwrap()` |
| `clippy::missing_docs` | 为 `pub` 项补充 `///` 文档 |

---

## 2. 运行时问题

### Q2.1 调用 Bulwark API 时 panic：`BulwarkManager not initialized`

**原因**：未在服务启动时调用 `BulwarkManager::init()`。

**解决**：在服务初始化阶段（建立数据库连接后、监听端口前）调用初始化：

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 建立数据库连接
    // 2. 执行迁移
    // 3. 初始化 BulwarkManager（必须在所有 API 调用前）
    let config = BulwarkConfig::default_config();
    BulwarkManager::init(dao, config, interface).await?;

    // 4. 启动 axum 服务
    let app = Router::new()
        .route("/protected", get(protected_handler))
        .layer(BulwarkLayer::new());
    axum::serve(listener, app).await?;
    Ok(())
}
```

---

### Q2.2 `check_login` 返回 false 但用户已登录（token 不生效）

**现象**：用户已通过 `login` 登录，但后续请求中 `check_login()` 始终返回 `false`。

**原因**：Bulwark 通过 task_local 上下文读取当前请求的 token。若 axum middleware 未正确提取并设置 token 到 task_local，则上下文为空。

**解决**：确保 `BulwarkLayer` 已注册到路由：

```rust
use bulwark::axum::BulwarkLayer;

let app = Router::new()
    .route("/protected", get(protected_handler))
    .layer(BulwarkLayer::new());   // 必须注册，负责从请求头提取 token 并写入 task_local
```

`BulwarkLayer` 会从 `bulwark_token` 请求头（或 Cookie）提取 token，解析会话，并写入 task_local 上下文，后续 `check_login()` 即可正确读取。

---

### Q2.3 会话立即过期

**现象**：登录后短时间内（远未到 timeout）会话即失效，需重新登录。

**原因**：`timeout` 配置过小，或单位换算错误（配置成秒但误用毫秒）。

**解决**：

1. 检查环境变量 `BULWARK_TIMEOUT`（单位为秒）：

   ```bash
   echo $BULWARK_TIMEOUT   # 30 天 = 2592000
   ```

2. 检查 `bulwark.toml` 中 `timeout` 字段单位（秒）。

3. 默认值参考：

   | 配置项 | 默认值 | 说明 |
   |--------|--------|------|
   | `timeout` | `2592000`（30 天） | 会话最长有效期 |
   | `active_timeout` | `-1`（跟随 timeout） | 活跃超时 |

---

### Q2.4 权限校验失败（permission denied）

**现象**：已登录用户调用 `check_permission("user:read")` 始终返回 `false`。

**原因**：`BulwarkLogic` trait 的 `get_permission_list` 实现返回空列表，或数据源中该用户未被授予该权限。

**解决**：

1. 检查 `BulwarkInterface` 实现是否正确查询权限数据源：

   ```rust
   #[async_trait]
   impl BulwarkInterface for MyInterface {
       async fn get_permission_list(&self, user_id: &str) -> BulwarkResult<Vec<String>> {
           // 确认此处实际查询数据库而非返回空 Vec
           self.db.query_permissions(user_id).await
       }
   }
   ```

2. 检查数据库中 `user_permissions` 与 `user_roles` 表是否有对应记录。

3. 启用调试日志查看实际返回的权限列表：

   ```bash
   RUST_LOG=bulwark::core::permission=debug ./your-server
   ```

---

## 3. 测试问题

### Q3.1 单独运行测试通过，全量运行时失败（serial_test 冲突）

**现象**：单独运行某个测试通过，但 `cargo test` 全量运行时该测试间歇性失败。

**原因**：测试修改了全局单例（如 `BulwarkManager`）或环境变量（`std::env::set_var`），多线程并发执行时互相污染。

**解决**：为修改全局状态的测试添加 `#[serial_test::serial]` 注解，强制串行执行：

```rust
use serial_test::serial;

#[tokio::test]
#[serial]
async fn test_init_manager() {
    BulwarkManager::init(config).await;  // 修改全局单例
    assert!(BulwarkManager::is_initialized());
}

#[test]
#[serial]
fn test_env_var_override() {
    std::env::set_var("BULWARK_TIMEOUT", "3600");
    // ...
    std::env::remove_var("BULWARK_TIMEOUT");
}
```

> **经验法则**：只要测试中调用 `BulwarkManager::init()`、`std::env::set_var()`、或修改 `once_cell` 全局变量，就必须加 `#[serial]`。

---

### Q3.2 `cargo tarpaulin` 报错或覆盖率工具异常

**现象**：运行覆盖率测试时报错或结果异常。

**原因**：`cargo-tarpaulin` 依赖 `libssl-dev` 与 `pkg-config`，且对某些 feature 组合可能不兼容。

**解决**：

1. 确认系统依赖已安装：

   ```bash
   sudo apt install -y libssl-dev pkg-config
   ```

2. 使用推荐的 feature 组合运行覆盖率：

   ```bash
   cargo tarpaulin --features "default,db-sqlite" --lib --out Lcov
   ```

3. 若 `full` feature 下 tarpaulin 失败，降级为仅测试核心模块：

   ```bash
   cargo tarpaulin --features "cache-memory,db-sqlite,web-axum" --lib --out Lcov
   ```

---

### Q3.3 `inventory::iter` 返回空

**现象**：调用 `inventory::iter::<T>()` 迭代注册项时为空，但代码中确实调用了 `inventory::submit!`。

**原因**：未在测试模块中显式 `use std::iter::Iterator`，或注册项所在的模块未被编译（feature 未启用）。

**解决**：

1. 添加 `use` 声明：

   ```rust
   use std::iter::Iterator;
   use inventory::iter;

   for item in iter::<MyRegistration>() {
       // ...
   }
   ```

2. 确认注册项所在的模块已被 `mod` 声明引入编译单元。
3. 确认 feature flag 已启用对应模块。

---

## 4. 配置问题

### Q4.1 环境变量不生效

**现象**：设置了 `BULWARK_TIMEOUT` 环境变量，但配置未生效。

**原因**：环境变量未被正确加载，或优先级低于预期。

**解决**：

1. 确认环境变量已设置且在进程启动前生效：

   ```bash
   echo $BULWARK_TIMEOUT
   ```

2. 确认变量名前缀正确（`BULWARK_`），如 `BULWARK_TOKEN_STYLE` 而非 `TOKEN_STYLE`。
3. 若使用 `.env` 文件，确认应用使用了 `dotenvy` 之类的 crate 加载 `.env`（Bulwark 只读取进程环境变量，不主动加载 `.env` 文件）。
4. 确认布尔值格式正确（支持 `true`/`false`/`1`/`0`/`yes`/`no`/`on`/`off`）。

---

### Q4.2 toml 配置文件解析错误

**现象**：启动时报 `BulwarkError::Config: toml parse error`。

**原因**：`bulwark.toml` 语法错误，如字段名拼写错误、类型不匹配。

**解决**：

1. 检查 toml 语法（字段名使用下划线，字符串用双引号）：

   ```toml
   # 正确
   token_name = "bulwark_token"
   token_style = "uuid"
   timeout = 2592000

   # 错误（字段名用连字符）
   # token-name = "bulwark_token"
   ```

2. 检查 `token_style` 是否为合法值（`uuid` / `random_64` / `simple` / `jwt`，注意下划线）。
3. 检查 `cookie_same_site` 是否为合法值（`Lax` / `Strict` / `None`）。
4. 使用 `cargo expand` 或在代码中打印解析结果调试。

---

### Q4.3 配置热更新不生效

**现象**：调用 `config.update()` 后，订阅方未收到新配置。

**原因**：配置实例未调用 `with_watcher()`，或 watcher 已关闭。

**解决**：

1. 确认配置实例通过 `default_config()` 创建（自动附加 watcher）：

   ```rust
   let config = BulwarkConfig::default_config(); // 已附加 watcher
   ```

2. 若通过反序列化创建，需手动调用 `with_watcher()`：

   ```rust
   let config: BulwarkConfig = toml::from_str(&toml_str)?;
   let config = config.with_watcher(); // 手动附加 watcher
   ```

3. 检查 `update()` 返回值是否为 `Err`（非法值会被 `validate()` 拒绝）。

---

## 5. 获取帮助

若以上内容未能解决你的问题，可通过以下渠道获取帮助：

### 5.1 GitHub Issues

提交 Bug 报告或功能请求：<https://github.com/Kirky-X/bulwark/issues>

提交 Issue 时请附带：

- Bulwark 版本（`bulwark = "0.x"`）
- 启用的 feature 列表
- Rust 版本（`rustc --version`）
- 操作系统与架构
- 最小复现代码或完整报错信息

### 5.2 GitHub Discussions

进行使用咨询、架构讨论、最佳实践交流：<https://github.com/Kirky-X/bulwark/discussions>
