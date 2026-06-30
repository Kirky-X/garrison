# 开发规范

本文件描述 Bulwark 项目的开发环境搭建、项目结构、TDD 工作流、代码规范与 OpenSpec 变更管理流程。所有贡献者在提交代码前必须阅读本文档。

- 仓库：<https://github.com/Kirky-X/bulwark>
- License：Apache-2.0
- MSRV：Rust 1.85+
- 设计参考：Sa-Token v1.45.0

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

Bulwark 通过 `path` 依赖引用本地的 `oxcache`，需先将其克隆到固定路径：

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

# 全量测试（323 个测试应全部通过）
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
│   ├── stp/                  # StpUtil 风格门面
│   ├── session/              # 会话管理
│   ├── protocol/             # 协议层：oauth2 / sso / jwt / sign / apikey / temp
│   ├── secure/               # 安全层：totp / sign / httpbasic / httpdigest
│   ├── dao/                  # 数据访问层（oxcache + dbnexus 实现）
│   ├── context/              # 请求上下文抽象（含 axum 适配器）
│   ├── config/               # 配置系统
│   ├── annotation/           # 注解系统
│   ├── router/               # 路由权限
│   ├── strategy/             # 策略模式
│   ├── exception/            # 异常系统
│   ├── listener/             # 事件监听
│   ├── plugin/               # 插件系统
│   ├── manager/              # BulwarkManager 全局管理器
│   ├── json/                 # JSON 模板
│   ├── error.rs              # 错误类型定义
│   ├── prelude.rs            # 预导出
│   └── lib.rs                # crate 入口
├── tests/                    # 集成测试
│   ├── axum_integration.rs
│   ├── annotation_integration.rs
│   └── dbnexus_integration.rs
├── examples/                 # 示例代码
│   ├── basic_login.rs
│   ├── axum_integration.rs
│   ├── config_loader.rs
│   ├── context_request.rs
│   ├── manager_lifecycle.rs
│   ├── session_management.rs
│   ├── strategy_firewall.rs
│   └── dao_operations.rs
├── openspec/                 # 规格驱动变更管理
│   ├── changes/              # 进行中的变更
│   │   └── archive/          # 已归档的变更
│   └── specs/                # 已固化的规格
├── docs/                     # 文档
│   ├── origin/               # 原始设计文档（PRD / FRD / ADD）
│   └── archive/              # 历史归档
├── .github/                  # CI 配置 + Issue/PR 模板
│   ├── workflows/            # CI 流水线（ci.yml / release.yml）
│   ├── ISSUE_TEMPLATE/       # Issue 模板（bug_report / feature_request）
│   ├── PULL_REQUEST_TEMPLATE.md
│   ├── CODEOWNERS
│   └── dependabot.yml
├── Cargo.toml
├── rust-toolchain.toml       # 锁定工具链
├── rustfmt.toml              # 格式化配置
├── clippy.toml               # Clippy 配置
└── README.md
```

### 源码分层说明

| 层 | 目录 | 职责 |
|----|------|------|
| 核心层 | `src/core/` | token 生成校验、权限校验、登录鉴权 |
| 协议层 | `src/protocol/` | OAuth2 / SSO / JWT / 签名 / API Key / 临时凭证 |
| 安全层 | `src/secure/` | TOTP / 签名 / HTTP Basic / HTTP Digest |
| 辅助层 | `src/dao/` `src/context/` `src/config/` 等 | 数据访问、上下文、配置、注解、路由、异常 |

---

## 3. TDD 工作流（硬约束）

Bulwark 强制采用测试驱动开发（TDD）。每个任务必须严格按以下 7 步执行，不得跳步：

1. **定义接口** — 编写 `trait` 与 `struct` 签名（方法签名 + 类型），不写实现
2. **编写测试** — 覆盖三类场景：
   - 正常路径（happy path）
   - 错误路径（error path）
   - 边界条件（boundary cases）
3. **实现代码** — 编写满足测试的最小实现
4. **运行测试通过** — `cargo test --features full` 必须全部通过
5. **格式化与 Lint** — `cargo fmt` + `cargo clippy --features full -- -D warnings`
6. **提交** — `git commit`（遵循 Conventional Commits）
7. **进入下一任务** — 重复步骤 1

> 不得先写实现再补测试。覆盖率门槛 97.81%，新增代码需保持同等水准。

---

## 4. 代码规范

### 4.1 命名约定

| 类型 | 风格 | 示例 |
|------|------|------|
| 函数 / 变量 | `snake_case` | `check_login`、`user_id` |
| 类型 / Struct / Enum / Trait | `CamelCase` | `BulwarkManager`、`BulwarkLogic` |
| 常量 / 静态变量 | `SCREAMING_SNAKE_CASE` | `DEFAULT_TIMEOUT`、`TOKEN_HEADER` |

### 4.2 文档注释

所有 `pub` 项（函数、结构体、枚举、trait、常量）必须配有 `///` 文档注释，说明用途、参数、返回值：

```rust
/// 校验当前会话是否已登录。
///
/// 通过 task_local 上下文读取当前 token，并查询会话有效性。
///
/// # 返回
/// - `true`：已登录且会话未过期
/// - `false`：未登录或会话已失效
pub fn check_login() -> bool {
    // ...
}
```

### 4.3 错误处理

- 所有可能失败的操作返回 `BulwarkResult<T>`（即 `Result<T, BulwarkError>`）
- **禁止** 在非测试代码中使用 `unwrap()` / `expect()`
- 使用 `?` 运算符传播错误
- 自定义错误类型实现 `thiserror::Error`

```rust
// 正确
pub fn get_session(id: &str) -> BulwarkResult<Session> {
    DAO.get_session(id).ok_or(BulwarkError::SessionNotFound)?
}

// 错误（禁止）
pub fn get_session(id: &str) -> Session {
    DAO.get_session(id).unwrap() // panic 风险
}
```

### 4.4 异步约定

trait 方法使用 `async_trait::async_trait` 宏声明：

```rust
#[async_trait::async_trait]
pub trait BulwarkLogic: Send + Sync {
    async fn get_permission_list(&self, user_id: &str) -> BulwarkResult<Vec<String>>;
}
```

### 4.5 测试串行化

修改全局单例（如 `BulwarkManager`、环境变量）的测试必须标注 `#[serial_test::serial]`，避免多线程并发污染：

```rust
#[cfg(test)]
mod tests {
    use serial_test::serial;

    #[test]
    #[serial]
    fn test_manager_init() {
        // 修改全局单例，必须串行
        BulwarkManager::init(config);
        assert!(BulwarkManager::is_initialized());
    }
}
```

---

## 5. OpenSpec 工作流

Bulwark 使用 OpenSpec 进行规格驱动的变更管理。所有非平凡变更（新增模块、修改公开 API、架构调整）必须走 OpenSpec 流程。

### 5.1 四阶段流程

```
explore → propose → apply → archive
```

### 5.2 常用命令

```bash
# 创建一个新变更（自动生成目录骨架）
openspec new change "add-oidc-support"

# 生成 artifacts：proposal → design → specs → tasks
openspec propose

# 实施任务（按 tasks.md 逐条完成）
openspec apply

# 实施完成并验证后归档
openspec archive
```

### 5.3 目录结构

```
openspec/
├── changes/
│   └── add-oidc-support/
│       ├── .openspec.yaml     # 变更元数据
│       ├── proposal.md        # 变更提案（动机 / 范围 / 影响）
│       ├── design.md          # 设计方案（架构 / 折中 / 风险）
│       ├── tasks.md           # 实施任务清单（勾选式）
│       └── specs/             # 规格增量（delta specs）
│           └── oidc/
│               └── spec.md
└── specs/                     # 已固化的主规格（基线）
```

### 5.4 规范要点

- 每个 change 必须有 `proposal.md`、`design.md`、`tasks.md`，缺一不可
- `tasks.md` 中每项任务对应一次 TDD 循环
- 实施完成后运行 `openspec archive`，变更移入 `changes/archive/`，delta specs 合并入主 `specs/`

---

## 6. 常用命令清单

| 任务 | 命令 |
|------|------|
| 全量编译 | `cargo build --features full` |
| 仅默认特性编译 | `cargo build` |
| 运行全部测试 | `cargo test --features full` |
| 运行单个测试 | `cargo test --features full test_name` |
| Clippy 检查（零警告） | `cargo clippy --features full -- -D warnings` |
| 格式化 | `cargo fmt --all` |
| 格式化检查 | `cargo fmt --all -- --check` |
| 覆盖率测试 | `cargo tarpaulin --features "default,db-sqlite" --lib --out Lcov --output-dir coverage` |
| 生成文档 | `cargo doc --no-deps --features full --open` |
| 生产构建 | `cargo build --release --features production` |
| 检查依赖更新 | `cargo update --dry-run` |
| OpenSpec 新建变更 | `openspec new change "name"` |
| OpenSpec 实施任务 | `openspec apply` |
| OpenSpec 归档 | `openspec archive` |

### 6.1 Feature 速查

| Feature | 说明 |
|---------|------|
| `default` | 无（即空特性，需显式启用） |
| `all-defaults` | 等价于 `cache-memory + db-sqlite + web-axum` |
| `full` | 启用全部特性（开发首选） |
| `production` | 生产推荐组合（cache-redis + db-sqlite + web-axum + 协议/安全子集 + 可观测性） |
| `development` | 开发推荐组合（cache-memory + db-sqlite + web-axum） |
| `cache-memory` | 启用 oxcache（L1 moka） |
| `cache-redis` | 启用 oxcache（L2 redis） |
| `db-sqlite` | 启用 dbnexus + auto-migrate |
| `web-axum` / `web-actix` / `web-warp` | Web 框架适配 |
| `listener` | 事件监听器 |
| `tracing-log` | tracing 日志集成 |
| `metrics-prometheus` | Prometheus 指标导出 |
