<!-- markdownlint-disable MD041 -->
<div align="center">

<img src="docs/assets/garrison.png" alt="Garrison Logo" width="240">

[![Rust 2021](https://img.shields.io/badge/Rust-2021-edded?logo=rust&style=for-the-badge)](https://www.rust-lang.org/) [![Rustc 1.97.1+](https://img.shields.io/badge/rust-1.97.1%2B-orange.svg?style=for-the-badge)](https://www.rust-lang.org/) [![crates.io](https://img.shields.io/crates/v/garrison?style=for-the-badge)](https://crates.io/crates/garrison) [![docs.rs](https://img.shields.io/docsrs/garrison?style=for-the-badge)](https://docs.rs/garrison) [![downloads](https://img.shields.io/crates/d/garrison?style=for-the-badge)](https://crates.io/crates/garrison) [![CI](https://img.shields.io/github/actions/workflow/status/Kirky-X/garrison/ci.yml?branch=main&label=CI&style=for-the-badge)](https://github.com/Kirky-X/garrison/actions/workflows/ci.yml) [![coverage](https://img.shields.io/badge/coverage-95%25%2B-brightgreen.svg?style=for-the-badge)](https://github.com/Kirky-X/garrison) [![license](https://img.shields.io/crates/l/garrison?style=for-the-badge)](LICENSE)

[English](README.md) | 中文

<b>面向 Rust 生态的一站式身份认证鉴权框架</b>

[✨ 功能特性](#-功能特性) • [🚀 快速开始](#-快速开始) • [📚 文档](#-文档) • [💻 示例](#-示例) • [🤝 参与贡献](#-参与贡献)

</div>

---

<div align="center">

### 🎯 注解声明保护点，静态 API 零状态调用

启动时向 `GarrisonManager` 注入一次依赖，此后从登录到登出交给框架接管：

<table style="width:100%; border-collapse: collapse">
<tr>
<td align="center" width="25%">🧩<br><b>注解驱动</b><br><span style="color:#64748B">13 个属性宏 · 声明式接入</span></td>
<td align="center" width="25%">🔀<br><b>双模会话</b><br><span style="color:#64748B">账号级 · 登录级 · 多端策略</span></td>
<td align="center" width="25%">🌐<br><b>Web 集成</b><br><span style="color:#64748B">axum · actix · warp</span></td>
<td align="center" width="25%">⚙️<br><b>特性门控</b><br><span style="color:#64748B">100+ flag · 按需编译</span></td>
</tr>
</table>

</div>

---

## 📋 目录

<details open>
<summary>📑 目录</summary>

- [✨ 功能特性](#-功能特性)
- [🚀 快速开始](#-快速开始)
- [📚 文档](#-文档)
- [💻 示例](#-示例)
- [🔒 安全](#-安全)
- [🤝 参与贡献](#-参与贡献)
- [📄 许可证](#-许可证)
- [⭐ Star 历史](#-star-历史)

</details>

---

## ✨ 功能特性

<table style="width:100%; border-collapse: collapse">
<tr>
<td width="50%" style="vertical-align:top; padding: 12px">⚡ <b>零运行时开销</b><br><span style="color:#64748B">编译期 <code>inventory::submit!</code> 工厂注册，无反射、无动态加载</span></td>
<td width="50%" style="vertical-align:top; padding: 12px">🔒 <b>完整鉴权链</b><br><span style="color:#64748B">登录认证 → 权限校验 → 会话管理 → 路由拦截，开箱即用</span></td>
</tr>
<tr>
<td width="50%" style="vertical-align:top; padding: 12px">📦 <b>多后端抽象</b><br><span style="color:#64748B"><code>GarrisonDao</code> + <code>oxcache</code> + <code>dbnexus</code>，切换存储后端零业务代码改动</span></td>
<td width="50%" style="vertical-align:top; padding: 12px">🔧 <b>可插拔扩展</b><br><span style="color:#64748B">trait + Default 实现模式，替换任意组件（DAO / 策略 / 逻辑）无需改业务</span></td>
</tr>
<tr>
<td width="50%" style="vertical-align:top; padding: 12px">🎯 <b>Feature 门控</b><br><span style="color:#64748B">100+ 个特性 flag，按需编译减小体积</span></td>
<td width="50%" style="vertical-align:top; padding: 12px">📊 <b>高可观测</b><br><span style="color:#64748B"><code>tracing</code> 日志 + <code>listener</code> 事件订阅 + <code>prometheus</code> 指标（可选）</span></td>
</tr>
<tr>
<td width="50%" style="vertical-align:top; padding: 12px">🧪 <b>高覆盖</b><br><span style="color:#64748B">5990+ 个测试（lib 约 5454 + 验收/集成/示例约 540），95%+ 行覆盖率，clippy 零警告</span></td>
<td width="50%" style="vertical-align:top; padding: 12px">🌐 <b>Web 框架适配</b><br><span style="color:#64748B">axum/actix/warp 三框架注解式 extractor + 过程宏</span></td>
</tr>
</table>

除上述核心能力外，其余能力（认证协议、防火墙、账号安全、多租户、可观测性、微服务组件等）也均以独立特性标志提供、按需编译；按能力域汇总的功能矩阵见 [🎨 特性标志功能矩阵](docs/cn/API_REFERENCE.md#feature-matrix)（完整清单以 `Cargo.toml` 的 `[features]` 为准）。

---

## 🚀 快速开始

### 📦 安装

在 `Cargo.toml` 中添加依赖（`development` 聚合 = 内存缓存 DAO + SQLite + axum 适配）：

<details>
<summary>📄 代码 · toml</summary>

```toml
[dependencies]
garrison = { version = "0.9", features = ["development"] }
async-trait = "0.1"
tokio = { version = "1", features = ["full"] }
```

</details>

要求 Rust **1.97.1 及以上**，MSRV 依据与 CI 三档验证矩阵见 [📖 用户指南 · 安装补充](docs/cn/USER_GUIDE.md#msrv-note)。

> 预发布版本需显式写完整版本号，`"0.9"` 无法匹配 prerelease。如需启用全部协议层与安全模块：`features = ["full"]`。

<details>
<summary>📋 表格</summary>

| 预设 | 安装方式 | 适用场景 |
|------|----------|----------|
| 开发 | `features = ["development"]` | 内存缓存 + SQLite + axum，快速验证 |
| 生产 | `features = ["production"]` | 生产环境推荐组合 |
| 完整 | `features = ["full"]` | 全部能力 |

</details>

### 💡 最小示例

以下示例改编自 [`examples/src/bin/readme_quickstart.rs`](examples/src/bin/readme_quickstart.rs)（完整业务场景：初始化管理器 → 执行登录 → 校验登录状态 → 登出）：

<details>
<summary>📄 代码 · rust</summary>

```rust
use std::sync::Arc;
use garrison::prelude::*;
use async_trait::async_trait;

// 1. 业务方实现 GarrisonInterface（提供权限/角色数据）
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
    // 2. 准备依赖
    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoOxcache::new().await?);
    let config = Arc::new(GarrisonConfig::default_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MyInterface);

    // 3. 初始化全局管理器
    GarrisonManager::builder()
        .dao(dao).config(config).interface(interface)
        .build().await?;

    // 4. 在 task_local 上下文中执行登录
    let token = garrison::stp::with_current_token(
        String::new(), GarrisonUtil::login("1001", &LoginParams::default()),
    ).await?;
    println!("登录成功，token = {}", &token[..8.min(token.len())]);

    // 5. 校验登录状态
    garrison::stp::with_current_token(token.clone(), GarrisonUtil::check_login()).await?;

    // 6. 校验权限
    garrison::stp::with_current_token(
        token.clone(), GarrisonUtil::check_permission("user:read"),
    ).await?;

    // 7. 登出
    garrison::stp::with_current_token(token.clone(), GarrisonUtil::logout()).await?;
    Ok(())
}
```

</details>

<details>
<summary>📄 代码 · bash</summary>

```bash
cargo run -p garrison-examples --bin readme_quickstart --features "cache-memory"
# 输出: 登录成功，token = <8 位随机 token 前缀>
```

</details>

> 本示例已由 [examples/tests/readme_quickstart.rs](./examples/tests/readme_quickstart.rs) 持续验证（随 CI 运行），业务代码与 [`examples/src/web/readme_quickstart.rs`](examples/src/web/readme_quickstart.rs) 逐字对应。

### 🧭 核心概念

全局单例 + 静态 API、token 上下文、双模会话、特性门控等核心概念详解见 [📖 用户指南 · 核心概念](docs/cn/USER_GUIDE.md#-核心概念)。

---

## 📚 文档

<details>
<summary>📋 表格</summary>

| 文档 | 说明 |
|------|------|
| [📖 用户指南](docs/cn/USER_GUIDE.md) | 从安装到进阶的完整使用教程 |
| [📘 API 参考](docs/cn/API_REFERENCE.md) | 公开 API 与模块参考（含特性标志功能矩阵） |
| [🏗️ 架构文档](docs/cn/ARCHITECTURE.md) | 设计原则、模块划分与数据流 |
| [⚙️ 配置指南](docs/cn/CONFIGURATION.md) | 三级配置源、完整配置项与热更新 |
| [⚡ 性能指南](docs/cn/PERFORMANCE.md) | 性能目标、基准测试与优化建议 |
| [📊 性能基线](docs/cn/benchmarks-v1.0-baseline.md) | v1.0 前基准采集数据 |
| [🧭 架构决策记录（ADR ×4）](docs/cn/adr-0001-argon2id-password-hashing.md) | Argon2id 选型 / CSPRNG / 常量时间比较 / 统一错误模型 |
| [🧱 API 稳定性分级](docs/cn/API_STABILITY.md) | v1.0 稳定性层级、冻结清单与公共面基线 |
| [🏭 参考生产案例](docs/cn/PRODUCTION_CASES.md) | 自托管参考部署案例与提交模板 |
| [🔎 安全审计就绪包](docs/cn/SECURITY_AUDIT.md) | 审计范围、证据矩阵与第三方 RFP 清单 |
| [🧪 测试场景矩阵](docs/cn/TEST_SCENARIOS.md) | 验收场景穷举、特性组合矩阵与质量门禁 |
| [🔒 安全文档](docs/cn/SECURITY.md) | 安全策略、漏洞报告流程 |
| [🛡️ 威胁模型](docs/cn/THREAT.md) | STRIDE 分析、框架防御与业务方责任边界 |
| [❓ FAQ](docs/cn/FAQ.md) | 常见问题解答 |
| [🔧 问题排查](docs/cn/TROUBLESHOOTING.md) | 常见问题与解决方案 |
| [🛠️ 开发规范](docs/cn/DEVELOPMENT.md) | TDD 工作流、代码规范与调试技巧（含与 CI 一致的测试命令） |
| [🚀 部署指南](docs/cn/DEPLOYMENT.md) | 生产部署注意事项 |
| [🗺️ 路线图](docs/cn/ROADMAP.md) | 版本演进规划 |
| [📦 发布工作流](docs/cn/RELEASING.md) | 版本发布流程与门禁 |
| [🤝 贡献指南](docs/cn/CONTRIBUTING.md) | 如何参与项目开发 |
| [📋 更新日志](docs/cn/CHANGELOG.md) | 每个版本的变更记录 |
| [📦 在线 API 文档](https://docs.rs/garrison) | docs.rs 自动生成的最新文档 |
| [📦 crates.io](https://crates.io/crates/garrison) | 发布页面 |

</details>

---

## 💻 示例

全部 65 个可运行示例位于 [`examples/`](examples/) 目录（独立 workspace member，`garrison-examples` crate），每个示例配套 1:1 独立测试，按「登录 / 会话 / Token 基础、注解与 Web 集成、认证协议、安全防护、可观测性与基础设施」等主题分组，完整清单与各示例所需 feature 见 [examples/README.md](examples/README.md)。

<details>
<summary>📄 代码 · bash</summary>

```bash
# 运行单个示例
cargo run -p garrison-examples --bin basic_login --features full

# 验证全部示例可编译
cargo build -p garrison-examples --features full
```

</details>

---

## 🔒 安全

Garrison 围绕身份认证全生命周期做纵深防护：Argon2id / Bcrypt 慢哈希经 `spawn_blocking` 下沉、Token 常量时间比较（`secure-ct-eq`，CWE-208）、API Key 哈希存储与 IP 级限速（CWE-916 / CWE-307）、多租户 IDOR 防护、审计事件 token 统一掩码（CWE-532）、外网登录端点 fail-closed 等。逐项机制的代码级细节见 [🏗️ 架构文档](docs/cn/ARCHITECTURE.md) 与 [📖 用户指南 · 安全与防护](docs/cn/USER_GUIDE.md)，安全配置最佳实践与漏洞处理流程见 [🔒 安全文档](docs/cn/SECURITY.md)。

CI 与发布流程内置两道供应链门禁（`cargo deny check` 与 gitleaks 私钥扫描），门禁标准与处置细节见 [🔒 安全文档 · 供应链与门禁](docs/cn/SECURITY.md)。

### 🚨 报告安全漏洞

请勿通过公开 issue 报告安全漏洞。请优先使用 GitHub [Security Advisories](https://github.com/Kirky-X/garrison/security/policy) 私密披露通道提交报告（不可用时再发送邮件至 <Kirky-X@outlook.com>，受理人 Kirky.X）。项目承诺 48 小时内确认、7 天内给出初步评估。完整政策见 [🔒 安全文档](docs/cn/SECURITY.md)。

---

## 🤝 参与贡献

详细的贡献流程与代码规范请参阅 [🤝 贡献指南](docs/cn/CONTRIBUTING.md)。

### 🛠️ 开发环境

工具链要求、提交前检查（`cargo fmt` / `cargo clippy`）与 Conventional Commits 提交规范见 [🤝 贡献指南 · 开发环境搭建](docs/cn/CONTRIBUTING.md#-开发环境搭建)。

### 💖 贡献方式

<table style="width:100%; border-collapse: collapse">
<tr>
<td width="33%" align="center" style="padding: 16px">

### 🐛 报告 Bug

发现问题？<br>
<a href="https://github.com/Kirky-X/garrison/issues/new">创建 Issue</a>

</td>
<td width="33%" align="center" style="padding: 16px">

### 💡 功能建议

有好想法？<br>
<a href="https://github.com/Kirky-X/garrison/issues/new?template=feature_request.md">提交功能建议</a>

</td>
<td width="33%" align="center" style="padding: 16px">

### 🔧 提交 PR

想贡献代码？<br>
<a href="https://github.com/Kirky-X/garrison/pulls">Fork 并提交 PR</a>

</td>
</tr>
</table>

### 🙏 致谢

核心依赖与特别感谢名单见 [🤝 贡献指南 · 致谢](docs/cn/CONTRIBUTING.md#acknowledgments)。

---

## 📄 许可证

本项目基于 [Apache-2.0](LICENSE) 许可证开源。为何选择 Apache-2.0 而非 MIT：Apache-2.0 包含专利授权条款，更适合企业级框架使用。

---

## ⭐ Star 历史

[![Star History Chart](https://api.star-history.com/svg?repos=Kirky-X/garrison&type=Date)](https://star-history.com/#Kirky-X/garrison&Date)

如果这个项目对您有帮助，请考虑给它一个 ⭐️！

<b>由 Kirky.X 构建</b>

---

<sub>© 2026 Kirky.X. 保留所有权利。</sub>
