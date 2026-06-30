# 开发规范

本文件描述 Bulwark 项目的开发环境搭建、项目结构、TDD 工作流、代码规范与调试技巧。所有贡献者在提交代码前必须阅读本文档。

- 仓库：<https://github.com/Kirky-X/bulwark>
- License：Apache-2.0
- 作者：Kirky.X
- MSRV：Rust 1.85+
- 设计参考：Sa-Token v1.45.0

> 贡献流程详见 [CONTRIBUTING.md](./CONTRIBUTING.md)；架构设计详见 [architecture.md](./architecture.md)。

---

## 目录

- [1. 开发环境搭建](#1-开发环境搭建)
- [2. 项目结构说明](#2-项目结构说明)
- [3. TDD 工作流](#3-tdd-工作流)
- [4. 测试编写规范](#4-测试编写规范)
- [5. 代码风格](#5-代码风格)
- [6. Git 工作流](#6-git-工作流)
- [7. 调试技巧](#7-调试技巧)
- [8. 常用命令清单](#8-常用命令清单)

---

## 1. 开发环境搭建

### 1.1 Rust 工具链

Bulwark 最低支持 Rust 1.85（部分依赖如 `inventory 0.3` 要求 `edition2024`，需 Rust 1.85+）。推荐使用 rustup 安装 stable 工具链：

```bash
# 安装 rustup（若尚未安装）
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 安装 stable 工具链
rustup install stable
rustup default stable

# 验证版本（需 >= 1.85）
rustc --version
cargo --version
```

项目根目录已配置 `rust-toolchain.toml` 锁定工具链版本，`rustup` 会自动安装所需版本。

### 1.2 系统依赖

以下系统依赖用于 `cargo-tarpaulin` 覆盖率工具与构建链：

```bash
# Debian / Ubuntu
sudo apt update
sudo apt install -y libssl-dev pkg-config

# 验证
pkg-config --exists openssl && echo "openssl OK"
```

### 1.3 克隆仓库与本地依赖

Bulwark 通过 `path` 依赖引用本地的 `oxcache`（crates.io 0.3.0 未暴露 `Cache<K,V>::ttl()`，本地仓库已暴露），需先将其克隆到固定路径：

```bash
# 1. 克隆 oxcache 到本地（Cargo.toml 中配置为 path = /home/kirky/projects/oxcache）
git clone https://github.com/Kirky-X/oxcache.git /home/kirky/projects/oxcache

# 2. 克隆 Bulwark
git clone https://github.com/Kirky-X/bulwark.git
cd bulwark

# 3. 验证编译（启用全部 feature）
cargo build --features full
```

若 `oxcache` 路径不一致，请修改 `Cargo.toml` 中 `oxcache` 的 `path` 字段或建立软链。

### 1.4 验证

```bash
# 全量编译
cargo build --features full

# 全量测试（292 个单元测试 + 30 个集成测试应全部通过）
cargo test --features full

# Lint（零警告）
cargo clippy --features full -- -D warnings

# 格式化检查
cargo fmt --all -- --check
```

---

## 2. 项目结构说明

```
bulwark/
├── src/                      # 源码
│   ├── core/                 # 核心层：token / permission / auth
│   │   ├── token/mod.rs
│   │   ├── permission/mod.rs
│   │   └── auth/mod.rs
│   ├── stp/mod.rs            # StpUtil 风格门面（BulwarkLogic / BulwarkInterface / BulwarkUtil）
│   ├── session/mod.rs        # 会话管理（BulwarkSession）
│   ├── protocol/             # 协议层（feature 门控）
│   │   ├── jwt/mod.rs
│   │   ├── oauth2/mod.rs
│   │   ├── sso/mod.rs
│   │   ├── sign/mod.rs
│   │   ├── apikey/mod.rs
│   │   └── temp/mod.rs
│   ├── secure/               # 安全层（feature 门控）
│   │   ├── totp/mod.rs
│   │   ├── sign/mod.rs
│   │   ├── httpbasic/mod.rs
│   │   └── httpdigest/mod.rs
│   ├── dao/                  # 数据访问层
│   │   ├── mod.rs            # BulwarkDao trait
│   │   └── dbnexus_impl.rs   # dbnexus 实现
│   ├── context/              # 请求上下文抽象
│   │   ├── mod.rs
│   │   └── axum_adapter.rs   # axum 适配器
│   ├── config/mod.rs         # 配置系统（BulwarkConfig + ConfigLoader）
│   ├── annotation/mod.rs     # 注解系统
│   ├── router/mod.rs         # 路由权限（BulwarkRouter）
│   ├── strategy/mod.rs       # 策略模式（BulwarkFirewallStrategy）
│   ├── exception/mod.rs      # 异常系统
│   ├── listener/mod.rs       # 事件监听（feature 门控）
│   ├── plugin/mod.rs         # 插件系统
│   ├── manager/mod.rs        # BulwarkManager 全局管理器
│   ├── json/mod.rs           # JSON 模板
│   ├── error.rs              # 错误类型定义
│   ├── prelude.rs            # 预导出
│   └── lib.rs                # crate 入口
├── tests/                    # 集成测试（30 个）
├── examples/                 # 示例代码
│   ├── basic_login.rs        # init + login + check + logout
│   ├── axum_integration.rs   # BulwarkRouter + 4 路由 + 服务器
│   ├── config_loader.rs
│   ├── context_request.rs
│   ├── manager_lifecycle.rs
│   ├── session_management.rs
│   ├── strategy_firewall.rs
│   └── dao_operations.rs
├── migrations/sqlite/        # SQLite 迁移脚本
├── openspec/                 # 规格驱动变更管理
├── docs/                     # 文档
├── Cargo.toml
├── rust-toolchain.toml       # 锁定工具链
├── rustfmt.toml              # 格式化配置
└── README.md
```

### 源码分层说明

| 层 | 目录 | 职责 |
|----|------|------|
| 核心层 | `src/core/` | token 生成校验、权限校验、登录鉴权 |
| 门面层 | `src/stp/` | `BulwarkLogic` trait + `BulwarkUtil` 静态门面 |
| 协议层 | `src/protocol/` | OAuth2 / SSO / JWT / 签名 / API Key / 临时凭证 |
| 安全层 | `src/secure/` | TOTP / 签名 / HTTP Basic / HTTP Digest |
| 辅助层 | `src/dao/` `src/context/` `src/config/` 等 | 数据访问、上下文、配置、注解、路由、异常 |

---

## 3. TDD 工作流

Bulwark 强制采用测试驱动开发（TDD）。每个任务必须严格按以下 5 步执行，不得跳步：

### 3.1 五步流程

1. **定义接口** — 编写 `trait` 与 `struct` 签名（方法签名 + 类型），不写实现，含 `///` 文档注释
2. **编写测试** — 覆盖三类场景：
   - 正常路径（happy path）
   - 错误路径（error path）
   - 边界条件（boundary cases）
3. **实现代码** — 编写满足测试的最小实现
4. **运行测试通过** — `cargo test --features full` 必须全部通过
5. **格式化与 Lint** — `cargo fmt` + `cargo clippy --features full -- -D warnings`，然后 `git commit`

> 不得先写实现再补测试。覆盖率门槛 97.81%，新增代码需保持同等水准。

### 3.2 测试驱动示例

```rust
// 步骤 1：定义接口
/// 校验当前会话是否已登录。
pub async fn check_login() -> BulwarkResult<bool>;

// 步骤 2：编写测试
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn check_login_returns_true_when_session_valid() {
        // 正常路径
    }

    #[tokio::test]
    async fn check_login_returns_false_when_session_expired() {
        // 错误路径
    }

    #[tokio::test]
    async fn check_login_returns_false_when_token_empty() {
        // 边界条件
    }
}

// 步骤 3：实现
pub async fn check_login() -> BulwarkResult<bool> {
    // 最小实现使测试通过
}
```

---

## 4. 测试编写规范

### 4.1 测试串行化（#[serial_test::serial]）

修改全局单例（如 `BulwarkManager`）或环境变量（`std::env::set_var`）的测试必须标注 `#[serial_test::serial]`，避免多线程并发污染：

```rust
#[cfg(test)]
mod tests {
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn test_manager_init() {
        // 修改全局单例，必须串行
        BulwarkManager::init(config).await;
        assert!(BulwarkManager::is_initialized());
    }

    #[test]
    #[serial]
    fn test_env_var_override() {
        std::env::set_var("BULWARK_TIMEOUT", "3600");
        // ...
        std::env::remove_var("BULWARK_TIMEOUT");
    }
}
```

> **经验法则**：只要测试中调用 `BulwarkManager::init()`、`std::env::set_var()`、或修改 `once_cell` 全局变量，就必须加 `#[serial]`。

### 4.2 测试命名规范

测试函数命名采用 `snake_case`，建议遵循 `<被测方法>_<条件>_<期望结果>` 模式：

```rust
#[test]
fn validate_rejects_invalid_token_style() { ... }

#[test]
fn toml_overrides_multiple_fields() { ... }

#[test]
fn env_overrides_toml() { ... }
```

### 4.3 覆盖率要求

Bulwark 要求测试覆盖率 **≥ 90%**（当前 97.81%）：

| 模块类型 | 覆盖率要求 |
|---------|----------|
| 核心模块（core/stp/session/config/context/manager） | ≥ 95% |
| 协议/安全插件 | ≥ 90% |
| Web 适配层 | 集成测试覆盖主要中间件路径即可 |

- 292 个单元测试 + 30 个集成测试 + doc-tests
- 不追求 100% 覆盖率，但每个分支必须有对应测试用例
- 禁止通过「不写测试」来提高覆盖率的行为

---

## 5. 代码风格

### 5.1 命名约定

| 类型 | 风格 | 示例 |
|------|------|------|
| 函数 / 变量 | `snake_case` | `check_login`、`user_id` |
| 类型 / Struct / Enum / Trait | `CamelCase` | `BulwarkManager`、`BulwarkLogic` |
| 常量 / 静态变量 | `SCREAMING_SNAKE_CASE` | `DEFAULT_TIMEOUT`、`TOKEN_HEADER` |

### 5.2 文档注释

所有 `pub` 项（函数、结构体、枚举、trait、常量）必须配有 `///` 文档注释：

```rust
/// 校验当前会话是否已登录。
///
/// 通过 task_local 上下文读取当前 token，并查询会话有效性。
///
/// # 返回
/// - `Ok(true)`：已登录且会话未过期
/// - `Ok(false)`：未登录或会话已失效（当 `throw_on_not_login = false` 时）
/// - `Err(BulwarkError::NotLogin)`：未登录且 `throw_on_not_login = true` 时抛出
pub async fn check_login() -> BulwarkResult<bool> {
    // ...
}
```

### 5.3 错误处理

- 所有可能失败的操作返回 `BulwarkResult<T>`（即 `Result<T, BulwarkError>`）
- **禁止**在非测试代码中使用 `unwrap()` / `expect()`
- 使用 `?` 运算符传播错误
- 自定义错误类型实现 `thiserror::Error`

### 5.4 异步约定

trait 方法使用 `async_trait::async_trait` 宏声明：

```rust
#[async_trait]
pub trait BulwarkLogic: Send + Sync {
    async fn get_permission_list(&self, user_id: &str) -> BulwarkResult<Vec<String>>;
}
```

### 5.5 clippy 与 rustfmt

```bash
# clippy 零警告（CI 标准）
cargo clippy --features full --lib --tests -- -D warnings

# 格式化检查
cargo fmt --all -- --check

# 文档零警告
cargo doc --no-deps --features full
```

> 禁止使用 `#[allow(...)]` 抑制 clippy 警告（除非有充分理由并在 PR 中说明）。

---

## 6. Git 工作流

### 6.1 分支策略

| 分支 | 用途 | 命名规范 |
|------|------|---------|
| `main` | 主干，始终可发布 | - |
| 特性分支 | 新功能开发 | `feat/<scope>-<short-desc>` |
| 修复分支 | bug 修复 | `fix/<scope>-<short-desc>` |
| 文档分支 | 文档更新 | `docs/<short-desc>` |

### 6.2 Commit 规范

采用 [Conventional Commits](https://www.conventionalcommits.org/zh-hans/v1.0.0/)：

```
<type>(<scope>): <subject>
```

| type | 说明 |
|------|------|
| `feat` | 新功能 |
| `fix` | bug 修复 |
| `docs` | 文档变更 |
| `refactor` | 重构（不改变行为） |
| `test` | 测试新增/修改 |
| `chore` | 构建/工具/依赖 |

scope 常用值：`protocol-jwt`、`secure-totp`、`cache-memory`、`db-sqlite`、`web-axum`、`core`、`stp`、`session`、`config` 等。

详细提交规范与 PR 流程见 [CONTRIBUTING.md](./CONTRIBUTING.md)。

---

## 7. 调试技巧

### 7.1 cargo test

```bash
# 运行全部测试
cargo test --features full

# 运行单个测试
cargo test --features full test_name

# 运行并显示 println! 输出
cargo test --features full -- --nocapture

# 只运行集成测试
cargo test --features full --test axum_integration
```

### 7.2 cargo clippy

```bash
# 零警告检查
cargo clippy --features full --lib --tests -- -D warnings

# 查看具体建议
cargo clippy --features full --lib --tests
```

### 7.3 RUST_LOG 日志

通过 `RUST_LOG` 环境变量控制日志级别：

```bash
# 仅 Bulwark 模块 debug 级别
RUST_LOG=bulwark=debug ./your-server

# 全局 debug + Bulwark trace
RUST_LOG=debug,bulwark=trace ./your-server

# 仅特定模块
RUST_LOG=bulwark::core::auth=trace,bulwark::session=debug ./your-server
```

### 7.4 打印完整堆栈

发生 panic 时打印完整调用栈：

```bash
RUST_BACKTRACE=1 ./your-server

# 完整 backtrace（含依赖库栈帧）
RUST_BACKTRACE=full ./your-server
```

### 7.5 查看文档

生成并查看 crate 文档（包含全部 feature 的 API 文档）：

```bash
cargo doc --no-deps --features full --open
```

---

## 8. 常用命令清单

| 任务 | 命令 |
|------|------|
| 全量编译 | `cargo build --features full` |
| 仅默认特性编译 | `cargo build` |
| 运行全部测试 | `cargo test --features full` |
| 运行单个测试 | `cargo test --features full test_name` |
| Clippy 检查（零警告） | `cargo clippy --features full --lib --tests -- -D warnings` |
| 格式化 | `cargo fmt --all` |
| 格式化检查 | `cargo fmt --all -- --check` |
| 覆盖率测试 | `cargo tarpaulin --features "default,db-sqlite" --lib --out Lcov --output-dir coverage` |
| 生成文档 | `cargo doc --no-deps --features full --open` |
| 生产构建 | `cargo build --release --features production` |
| 检查依赖更新 | `cargo update --dry-run` |
| 查看展开后的宏 | `cargo expand --features full --lib` |
| 查看依赖树 | `cargo tree --features full` |
| 查看特性启用情况 | `cargo tree --features full -e features` |

### Feature 速查

| Feature | 说明 |
|---------|------|
| `default` | 空（无默认特性，需显式启用） |
| `all-defaults` | 等价于 `cache-memory + db-sqlite + web-axum` |
| `full` | 启用全部特性（开发首选） |
| `production` | 生产推荐组合（cache-redis + db-sqlite + web-axum + 协议/安全子集 + 可观测性） |
| `development` | 开发推荐组合（cache-memory + db-sqlite + web-axum） |

> 常见问题排查详见 [troubleshooting.md](./troubleshooting.md)。
