# 常见问题排查

本文件汇总 Bulwark 项目开发与部署中常见的问题、原因与解决方案。

- 仓库：<https://github.com/Kirky-X/bulwark>
- License：Apache-2.0
- MSRV：Rust 1.85+

---

## 1. 编译问题

### 1.1 oxcache path 依赖找不到

**现象**：编译时报错类似：

```
error: failed to load source for dependency `oxcache`
Caused by:
  failed to read `/home/kirky/projects/oxcache/Cargo.toml`
  No such file or directory (os error 2)
```

**原因**：`Cargo.toml` 中 `oxcache` 使用本地 `path` 依赖（`path = "/home/kirky/projects/oxcache"`），但该路径下不存在项目。

**解决**：将 oxcache 仓库克隆到指定路径：

```bash
git clone https://github.com/Kirky-X/oxcache.git /home/kirky/projects/oxcache
```

若希望放到其他路径，修改 `Cargo.toml`：

```toml
oxcache = { path = "/your/path/oxcache", optional = true }
```

---

### 1.2 cargo tarpaulin 报 libssl 缺失

**现象**：运行覆盖率测试时报错：

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

### 1.3 edition2024 错误

**现象**：编译时报错类似：

```
error: failed to parse manifest at `Cargo.toml`
Caused by:
  feature `edition2024` is required
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

### 1.4 clippy 警告导致 CI 失败

**现象**：本地编译通过，但 CI 中 clippy 报警告并失败。

**原因**：CI 使用 `-D warnings` 将警告视为错误。

**解决**：本地按 CI 标准运行 clippy 并修复：

```bash
cargo clippy --features full -- -D warnings
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

### 2.1 BulwarkManager 未初始化错误

**现象**：调用 Bulwark API 时 panic 或返回错误：

```
panic: BulwarkManager not initialized
```

**原因**：未在服务启动时调用 `BulwarkManager::init()`。

**解决**：在服务初始化阶段（建立数据库连接后、监听端口前）调用初始化：

```rust
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. 建立数据库连接
    let db = dbnexus::connect("sqlite:///data/bulwark.db").await?;

    // 2. 执行迁移
    bulwark::BulwarkMigration::run_migrations(&db).await?;

    // 3. 初始化 BulwarkManager（必须在所有 API 调用前）
    let config = bulwark::Config::from_env()?;
    bulwark::BulwarkManager::init(config, db).await?;

    // 4. 启动 axum 服务
    let app = bulwark::axum::router();
    axum::serve(listener, app).await?;
    Ok(())
}
```

---

### 2.2 check_login 返回 false 但用户已登录

**现象**：用户已通过 `login` 登录，但后续请求中 `check_login()` 始终返回 `false`。

**原因**：Bulwark 通过 task_local 上下文读取当前请求的 token。若 axum middleware 未正确提取并设置 token 到 task_local，则上下文为空。

**解决**：检查 axum middleware 是否正确启用，确保 `BulwarkLayer` 已注册到路由：

```rust
use bulwark::axum::BulwarkLayer;

let app = Router::new()
    .route("/protected", get(protected_handler))
    .layer(BulwarkLayer::new());   // 必须注册，负责从请求头提取 token 并写入 task_local
```

`BulwarkLayer` 会从 `Authorization` 请求头提取 token，解析会话，并写入 task_local 上下文，后续 `check_login()` 即可正确读取。

---

### 2.3 会话立即过期

**现象**：登录后短时间内（远未到 timeout）会话即失效，需重新登录。

**原因**：`timeout` 配置过小，或单位换算错误（配置成秒但误用毫秒）。

**解决**：

1. 检查环境变量 `BULWARK_TIMEOUT`：

   ```bash
   echo $BULWARK_TIMEOUT   # 单位为秒，30 天 = 2592000
   ```

2. 检查 TOML 配置文件 `[session] timeout` 字段单位

3. 默认值参考：

   | 配置项 | 默认值 | 说明 |
   |--------|--------|------|
   | `timeout` | `2592000`（30 天） | 会话最长有效期 |
   | `active_timeout` | `86400`（1 天） | 活跃超时（无操作后过期） |

---

### 2.4 permission denied

**现象**：已登录用户调用 `check_permission("user:read")` 始终返回 `false`，即使该用户应具有此权限。

**原因**：`BulwarkLogic` trait 的 `get_permission_list` 实现返回空列表，或数据源中该用户未被授予该权限。

**解决**：

1. 检查 `BulwarkLogic` 实现是否正确查询权限数据源：

   ```rust
   #[async_trait]
   impl BulwarkLogic for MyLogic {
       async fn get_permission_list(&self, user_id: &str) -> BulwarkResult<Vec<String>> {
           // 确认此处实际查询数据库而非返回空 Vec
           self.db.query_permissions(user_id).await
       }
   }
   ```

2. 检查数据库中 `user_permissions` 与 `user_roles` 表是否有对应记录

3. 启用调试日志查看实际返回的权限列表：

   ```bash
   RUST_LOG=bulwark::core::permission=debug ./your-server
   ```

---

## 3. 测试问题

### 3.1 测试相互干扰

**现象**：单独运行某个测试通过，但 `cargo test` 全量运行时该测试失败（间歇性）。

**原因**：测试修改了全局单例（如 `BulwarkManager`）或环境变量（`std::env::set_var`），多线程并发执行时互相污染。

**解决**：为修改全局状态的测试添加 `#[serial_test::serial]` 注解，强制串行执行：

```rust
use serial_test::serial;

#[test]
#[serial]
fn test_init_manager() {
    BulwarkManager::init(config);  // 修改全局单例
    assert!(BulwarkManager::is_initialized());
}

#[test]
#[serial]
fn test_reset_manager() {
    std::env::set_var("BULWARK_TIMEOUT", "3600");
    // ...
}
```

> 经验法则：只要测试中调用 `BulwarkManager::init()`、`std::env::set_var()`、或修改 `once_cell` 全局变量，就必须加 `#[serial]`。

---

### 3.2 inventory::iter 返回空

**现象**：调用 `inventory::iter::<T>()` 迭代注册项时为空，但代码中确实调用了 `inventory::submit!`。

**原因**：未在测试模块中显式 `use std::iter::Iterator`，导致迭代器 trait 方法不可用，或注册项所在的模块未被编译。

**解决**：

1. 添加 `use` 声明：

   ```rust
   use std::iter::Iterator;  // 必须显式引入
   use inventory::iter;

   for item in iter::<MyRegistration>() {
       // ...
   }
   ```

2. 确认注册项所在的模块已被 `mod` 声明引入编译单元

3. 确认 feature flag 已启用对应模块

---

### 3.3 dyn BulwarkLogic 不实现 Debug

**现象**：测试中调用 `.unwrap_err()` 时报错：

```
`dyn BulwarkLogic` doesn't implement `Debug`
```

**原因**：`unwrap_err()` 要求 `T: Debug`，而 `dyn BulwarkLogic` 默认不实现 `Debug`。

**解决**：用 `match` 替代 `unwrap_err()`：

```rust
// 错误（编译失败）
let err = result.unwrap_err();

// 正确
let err = match result {
    Ok(_) => panic!("expected error, got Ok"),
    Err(e) => e,
};
```

或在 trait 定义中要求 `Debug`（若所有实现都满足）：

```rust
pub trait BulwarkLogic: Send + Sync + std::fmt::Debug {
    // ...
}
```

---

## 4. 部署问题

### 4.1 cargo build --release 体积过大

**现象**：release 构建产物体积远超预期（如 > 50MB）。

**原因**：`profile.release` 优化项未生效，或引入了不必要的依赖。

**解决**：`Cargo.toml` 中已配置以下优化项，确认未被人误改：

```toml
[profile.release]
opt-level = 3
lto = true            # 链接时优化，消除死代码
codegen-units = 1     # 单编译单元，最大化优化
strip = true          # 移除调试符号
```

进一步排查：

```bash
# 查看二进制体积构成
cargo bloat --release --features production

# 使用 musl target 完全静态链接（更小）
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl --features production
```

---

### 4.2 Docker 镜像过大

**现象**：基于 `rust` 镜像构建的最终镜像体积 > 1GB。

**原因**：单阶段构建，最终镜像包含了 Rust 工具链与构建缓存。

**解决**：使用多阶段构建，最终镜像基于 `debian:bookworm-slim`：

```dockerfile
# 阶段 1：构建（基于 rust:1.85-slim）
FROM rust:1.85-slim AS builder
# ... 构建步骤 ...

# 阶段 2：运行（基于 debian:bookworm-slim，仅 ~80MB）
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/server /usr/local/bin/server
ENTRYPOINT ["/usr/local/bin/server"]
```

进一步优化：使用 `alpine` 镜像 + musl 静态链接，最终镜像可压缩至 < 20MB。

---

### 4.3 Redis 连接失败

**现象**：启用 `cache-redis` feature 后启动报错：

```
error: Redis connection failed: Connection refused (os error 111)
```

**原因**：Redis 服务未启动，或连接串配置错误，或网络不通。

**解决**：

1. 确认 Redis 服务已启动：

   ```bash
   redis-cli ping   # 应返回 PONG
   ```

2. 检查 `BULWARK_REDIS_URL` 环境变量：

   ```bash
   echo $BULWARK_REDIS_URL
   # 格式：redis://[:password@]host:port[/db]
   ```

3. Docker 网络场景下，确认容器与 Redis 在同一网络：

   ```bash
   docker network create bulwark-net
   docker run --network bulwark-net --name redis redis:7
   docker run --network bulwark-net \
     -e BULWARK_REDIS_URL=redis://redis:6379 \
     bulwark-app
   ```

4. 检查防火墙规则，确保 6379 端口可达

---

## 5. 调试技巧

### 5.1 启用调试日志

通过 `RUST_LOG` 环境变量控制日志级别：

```bash
# 仅 Bulwark 模块 debug 级别
RUST_LOG=bulwark=debug ./your-server

# 全局 debug + Bulwark trace
RUST_LOG=debug,bulwark=trace ./your-server

# 仅特定模块
RUST_LOG=bulwark::core::auth=trace,bulwark::session=debug ./your-server
```

### 5.2 打印完整堆栈

发生 panic 时打印完整调用栈，便于定位：

```bash
RUST_BACKTRACE=1 ./your-server

# 完整 backtrace（含依赖库栈帧）
RUST_BACKTRACE=full ./your-server
```

### 5.3 查看文档

生成并查看 crate 文档（包含全部 feature 的 API 文档）：

```bash
cargo doc --no-deps --features full --open
```

### 5.4 常用调试命令

| 目的 | 命令 |
|------|------|
| 查看展开后的宏 | `cargo expand --features full --lib` |
| 查看依赖树 | `cargo tree --features full` |
| 查看特性启用情况 | `cargo tree --features full -e features` |
| 检查未使用依赖 | `cargo machete` |
| 查看二进制体积构成 | `cargo bloat --release --features production` |

---

## 6. 获取帮助

若以上内容未能解决你的问题，可通过以下渠道获取帮助：

### 6.1 GitHub Issues

提交 Bug 报告或功能请求：

- 仓库：<https://github.com/Kirky-X/bulwark/issues>
- Bug 报告模板：`.github/ISSUE_TEMPLATE/bug_report.md`
- 功能请求模板：`.github/ISSUE_TEMPLATE/feature_request.md`

提交 Issue 时请附带：
- Bulwark 版本（`bulwark = "0.x"`）
- 启用的 feature 列表
- Rust 版本（`rustc --version`）
- 操作系统与架构
- 最小复现代码或完整报错信息

### 6.2 GitHub Discussions

进行使用咨询、架构讨论、最佳实践交流：

- 仓库 Discussions：<https://github.com/Kirky-X/bulwark/discussions>
