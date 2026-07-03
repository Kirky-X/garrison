# Bulwark 贡献指南

首先，感谢你对 Bulwark 项目的关注与支持！本文档将引导你完成从环境搭建到提交 Pull Request 的完整贡献流程。

Bulwark 是一个面向 Rust 生态的身份认证鉴权框架，借鉴 Sa-Token v1.45.0 设计。项目采用 TDD（测试驱动开发）工作流，对代码质量有严格要求：292 个单元测试 + 30 个集成测试 + doc-tests、97.81% 覆盖率、clippy 零警告、所有 public API 均带 `///` 文档注释。

> 相关文档：[开发规范](./DEVELOPMENT.md) | [架构设计](./ARCHITECTURE.md) | [配置指南](./CONFIGURATION.md)

---

## 目录

- [开发环境搭建](#开发环境搭建)
- [前置系统依赖](#前置系统依赖)
- [代码规范](#代码规范)
- [TDD 工作流](#tdd-工作流)
- [提交规范](#提交规范)
- [PR 流程](#pr-流程)
- [测试覆盖率要求](#测试覆盖率要求)
- [联系方式](#联系方式)

---

## 开发环境搭建

### 1. Fork 与 Clone 仓库

1. 在 GitHub 上 Fork [Kirky-X/bulwark](https://github.com/Kirky-X/bulwark) 到你的个人账户。
2. Clone 你 Fork 的仓库到本地：

   ```bash
   git clone https://github.com/<你的用户名>/bulwark.git
   cd bulwark
   ```

3. 添加上游远程仓库以保持同步：

   ```bash
   git remote add upstream https://github.com/Kirky-X/bulwark.git
   git fetch upstream
   ```

### 2. 安装 Rust 工具链

Bulwark 的 MSRV（Minimum Supported Rust Version）为 **Rust 1.85+**。部分依赖（如 `inventory 0.3`）要求 `edition2024`，需 Rust 1.85+。项目根目录已包含 `rust-toolchain.toml`，执行任何 `cargo` 命令时 rustup 会自动安装对应版本。

如需手动安装/升级：

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup update
rustup show  # 验证 toolchain 已就绪
```

### 3. 克隆本地依赖（oxcache）

Bulwark 通过 `path` 依赖引用本地的 `oxcache`（crates.io 0.3.0 未暴露 `Cache<K,V>::ttl()`，本地仓库已暴露），需先将其克隆到固定路径：

```bash
git clone https://github.com/Kirky-X/oxcache.git /home/kirky/projects/oxcache
```

若路径不一致，请修改 `Cargo.toml` 中 `oxcache` 的 `path` 字段或建立软链。

### 4. 构建项目

```bash
cargo build --features full
```

首次构建会拉取全部依赖并编译，可能需要几分钟。若编译成功且无报错，说明环境搭建完成。

### 5. 运行测试验证环境

```bash
cargo test --features full
```

预期输出：292 个单元测试 + 30 个集成测试 + doc-tests 全部通过。

---

## 前置系统依赖

部分开发工具链依赖系统级库，请在构建前安装：

| 依赖 | 用途 | Debian/Ubuntu 安装命令 |
|------|------|------------------------|
| `libssl-dev` | OpenSSL 头文件，供 reqwest / 部分 TLS 后端使用 | `sudo apt-get install libssl-dev` |
| `pkg-config` | 编译期定位系统库路径，`cargo tarpaulin` 必需 | `sudo apt-get install pkg-config` |

> **macOS 用户**：通常预装 OpenSSL，如遇问题可执行 `brew install openssl pkg-config`。
> **Windows 用户**：建议使用 MSYS2 或 vcpkg 安装对应库。

---

## 代码规范

Bulwark 遵循严格的代码质量标准，所有提交必须通过以下检查。

### clippy 零警告

所有代码必须通过 clippy 检查，且将警告视为错误：

```bash
cargo clippy --features full --lib --tests -- -D warnings
```

若出现警告，请根据 clippy 提示修正，禁止使用 `#[allow(...)]` 抑制（除非有充分理由并在 PR 中说明）。

### cargo fmt 强制

代码格式必须符合 `rustfmt.toml` 配置：

```bash
cargo fmt --all -- --check
```

如检查失败，请执行 `cargo fmt --all` 自动格式化后再提交。

### 文档注释要求

**所有 public API 必须有 `///` 文档注释**，并通过 `cargo doc` 零警告校验：

```bash
cargo doc --no-deps --features full
```

文档注释要求：

- 每个 `pub fn`、`pub struct`、`pub enum`、`pub trait`、`pub mod` 均需 `///` 注释。
- 注释应说明「做什么」与「为什么」，而非仅复述函数名。
- 复杂逻辑应包含 `# Examples` 代码示例（可被 `cargo test --doc` 执行）。
- 跨 crate 引用使用 intra-doc 链接：`[`Foo`](crate::module::Foo)`。

### 全局单例测试串行化

修改全局 `BulwarkManager` 单例（位于 `once_cell::sync::Lazy`）的测试必须标注 `#[serial_test::serial]`，避免并发污染：

```rust
#[cfg(test)]
mod tests {
    use serial_test::serial;

    #[tokio::test]
    #[serial]
    async fn test_global_manager_state() {
        // 操作全局单例的测试代码
    }
}
```

未标注 `#[serial]` 的全局单例测试将在 CI 上随机失败，请务必检查。

---

## TDD 工作流

项目采用测试驱动开发，标准流程为：

1. **先写接口**：定义 trait、函数签名或类型结构（含 `///` 文档注释）。
2. **写测试**：为新接口编写单元/集成测试，此时编译通过但测试失败。
3. **实现**：编写实现代码使测试通过。
4. **测试通过**：运行 `cargo test --features full`，确认新增测试全部通过。
5. **commit**：遵循 Conventional Commits 规范提交。

> 禁止「先实现后补测试」的提交方式（除非是修复 bug 时复现已知行为）。

详细 TDD 步骤与测试编写规范见 [development.md](./DEVELOPMENT.md)。

---

## 提交规范

Bulwark 采用 [Conventional Commits](https://www.conventionalcommits.org/zh-hans/v1.0.0/) 规范，提交信息格式：

```text
<type>(<scope>): <subject>

<body 可选>

<footer 可选>
```

### 类型（type）

| type | 说明 | 示例 |
|------|------|------|
| `feat` | 新功能 | 新增 JWT 签发能力 |
| `fix` | bug 修复 | 修复会话续期 panic |
| `docs` | 文档变更 | 补充 CONTRIBUTING |
| `refactor` | 重构（不改变行为） | 拆分 context 模块 |
| `test` | 测试新增/修改 | 补充 TOTP 边界用例 |
| `chore` | 构建/工具/依赖 | 升级 jsonwebtoken 到 10 |

### 作用域（scope）

scope 对应模块或功能域，常用值：

- 协议层：`protocol-jwt`、`protocol-oauth2`、`protocol-sso`、`protocol-sign`、`protocol-apikey`、`protocol-temp`
- 安全模块：`secure-totp`、`secure-sign`、`secure-httpbasic`、`secure-httpdigest`
- 缓存/数据库：`cache-memory`、`cache-redis`、`db-sqlite`
- Web 适配：`web-axum`、`web-actix`、`web-warp`
- 核心模块：`core`、`stp`、`session`、`config`、`context`、`manager`、`router`、`dao`
- 其他：`docs`、`ci`、`deps`

### 示例

```text
feat(protocol-jwt): 实现 JWT 签发与验证

- 新增 JwtIssuer 与 JwtValidator
- 集成 jsonwebtoken 10
- 覆盖 12 个单元测试

Closes #42
```

```text
fix(session): 修复 is_share=true 下并发续期竞态
```

```text
chore(deps): 升级 oxcache 到 0.3 启用 per-entry TTL
```

---

## PR 流程

### 1. 创建特性分支

始终从最新的 `main` 创建分支，分支名建议包含 type 与简短描述：

```bash
git checkout main
git pull upstream main
git checkout -b feat/your-feature
```

分支命名约定：

- `feat/<scope>-<short-desc>`：新功能，如 `feat/protocol-jwt-issuer`
- `fix/<scope>-<short-desc>`：bug 修复，如 `fix/session-race`
- `docs/<short-desc>`：文档，如 `docs/contributing-guide`

### 2. 提交代码

按 [提交规范](#提交规范) 编写 commit message，建议每个 commit 聚焦单一职责：

```bash
git add <相关文件>
git commit -m "feat(protocol-jwt): 实现 JWT 签发与验证"
```

### 3. 确保所有检查通过

提交 PR 前必须在本地通过以下全部检查：

```bash
# 格式检查
cargo fmt --all -- --check

# clippy 零警告
cargo clippy --features full --lib --tests -- -D warnings

# 全部测试通过
cargo test --features full

# 文档零警告
cargo doc --no-deps --features full
```

四项检查全部通过后方可提交 PR。

### 4. 创建 Pull Request

1. 推送分支到你的 Fork：`git push origin feat/your-feature`
2. 在 GitHub 上向 `Kirky-X/bulwark:main` 发起 Pull Request。
3. 填写 PR 模板，包含：
   - **变更说明**：本次 PR 做了什么、为什么。
   - **关联 Issue**：如 `Closes #42`。
   - **检查清单**：勾选四项本地检查已通过。
   - **破坏性变更**：若涉及 API 不兼容变更，需明确标注并说明迁移路径。
4. 等待 CI 通过与 Maintainer review，根据反馈迭代。

---

## 测试覆盖率要求

Bulwark 要求测试覆盖率 **≥ 90%**（当前 97.81%）。新增代码不得使总覆盖率下降。

使用 `cargo-tarpaulin` 生成覆盖率报告：

```bash
# 安装 tarpaulin（仅需一次）
cargo install cargo-tarpaulin

# 生成 Lcov 格式覆盖率报告
cargo tarpaulin --features "default,db-sqlite" --lib --out Lcov
```

覆盖率要求细则：

- **核心模块**（core/stp/session/config/context/manager）：覆盖率 ≥ 95%。
- **协议/安全插件**：覆盖率 ≥ 90%。
- **Web 适配层**：集成测试覆盖主要中间件路径即可。
- 不追求 100% 覆盖率，但每个分支必须有对应测试用例。
- 禁止通过「不写测试」来提高覆盖率的行为。

---

## 联系方式

- **GitHub Issues**：[https://github.com/Kirky-X/bulwark/issues](https://github.com/Kirky-X/bulwark/issues) — 用于 bug 报告与功能请求。
- **GitHub Discussions**：[https://github.com/Kirky-X/bulwark/discussions](https://github.com/Kirky-X/bulwark/discussions) — 用于设计讨论、使用疑问与想法交流。

如遇安全问题，请勿在公开渠道讨论，参阅 [SECURITY.md](./SECURITY.md)。

---

再次感谢你的贡献！愿 Bulwark 因你而更稳健。
