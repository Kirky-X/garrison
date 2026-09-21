<!-- markdownlint-disable MD041 -->
<div align="center">

<img src="docs/assets/logo.png" alt="Garrison Logo" width="200">

[![CI Status](https://github.com/Kirky-X/garrison/actions/workflows/ci.yml/badge.svg)](https://github.com/Kirky-X/garrison/actions/workflows/ci.yml) [![Version](https://img.shields.io/crates/v/garrison.svg)](https://crates.io/crates/garrison) [![Docs.rs](https://docs.rs/garrison/badge.svg)](https://docs.rs/garrison) [![Downloads](https://img.shields.io/crates/d/garrison.svg)](https://crates.io/crates/garrison) [![License](https://img.shields.io/crates/l/garrison.svg)](LICENSE) [![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/) [![Coverage](https://img.shields.io/badge/coverage-95%25%2B-brightgreen.svg)](https://github.com/Kirky-X/garrison)

**中文** | [English](README_EN.md)

<b>面向 Rust 生态的一站式身份认证鉴权框架</b>

[✨ 功能特性](#-功能特性) • [🚀 快速开始](#-快速开始) • [📚 文档](#-文档) • [💻 示例](#-示例) • [🤝 参与贡献](#-参与贡献)

</div>

---

<div align="center">

### 🎯 注解声明保护点，静态 API 零状态调用

启动时向 `GarrisonManager` 注入一次依赖，此后从登录到登出交给框架接管：

<table style="width:100%; border-collapse: collapse">
<tr>
<td align="center" width="25%">🧩<br><b>注解驱动</b><br><span style="color:#64748B">10 个属性宏 · 声明式接入</span></td>
<td align="center" width="25%">🔀<br><b>双模会话</b><br><span style="color:#64748B">账号级 · 登录级 · 多端策略</span></td>
<td align="center" width="25%">🌐<br><b>Web 集成</b><br><span style="color:#64748B">axum · actix · warp</span></td>
<td align="center" width="25%">⚙️<br><b>特性门控</b><br><span style="color:#64748B">100+ flag · 按需编译</span></td>
</tr>
</table>

</div>

---

## 📋 目录

- [✨ 功能特性](#-功能特性)
- [🚀 快速开始](#-快速开始)
- [🎨 特性标志](#-特性标志)
- [📚 文档](#-文档)
- [💻 示例](#-示例)
- [🏗️ 架构](#️-架构)
- [🧪 测试](#-测试)
- [📊 性能](#-性能)
- [🔒 安全](#-安全)
- [🗺️ 开发路线图](#️-开发路线图)
- [🤝 参与贡献](#-参与贡献)
- [📋 更新日志](#-更新日志)
- [📄 许可证](#-许可证)
- [🙏 致谢](#-致谢)
- [📞 联系与支持](#-联系与支持)
- [⭐ Star 历史](#-star-历史)

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
<td width="50%" style="vertical-align:top; padding: 12px">🧪 <b>高覆盖</b><br><span style="color:#64748B">5300+ 个测试（lib 约 4800 + 验收/集成/示例约 530），95%+ 行覆盖率，clippy 零警告</span></td>
<td width="50%" style="vertical-align:top; padding: 12px">🌐 <b>Web 框架适配</b><br><span style="color:#64748B">axum/actix/warp 三框架注解式 extractor + 过程宏</span></td>
</tr>
</table>

除上述核心能力外，其余能力（认证协议、防火墙、账号安全、多租户、可观测性、微服务组件等）也均以独立特性标志提供、按需编译；完整的逐项功能矩阵见 [🎨 特性标志](#-特性标志) 一节。

---

## 🚀 快速开始

### 📦 安装

在 `Cargo.toml` 中添加依赖（`development` 聚合 = 内存缓存 DAO + SQLite + axum 适配）：

```toml
[dependencies]
garrison = { version = "0.9.0-rc.2", features = ["development"] }
async-trait = "0.1"
tokio = { version = "1", features = ["full"] }
```

要求 Rust 1.85 及以上（MSRV，见 `Cargo.toml` 的 `rust-version`）。

> 预发布版本需显式写完整版本号，`"0.9"` 无法匹配 prerelease。如需启用全部协议层与安全模块：`features = ["full"]`。

| 预设 | 安装方式 | 适用场景 |
|------|----------|----------|
| 开发 | `features = ["development"]` | 内存缓存 + SQLite + axum，快速验证 |
| 生产 | `features = ["production"]` | 生产环境推荐组合 |
| 完整 | `features = ["full"]` | 全部能力 |

### 💡 最小示例

以下示例改编自 [`examples/src/bin/readme_quickstart.rs`](examples/src/bin/readme_quickstart.rs)（完整业务场景：初始化管理器 → 执行登录 → 校验登录状态 → 登出）：

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

```bash
cargo run -p garrison-examples --bin readme_quickstart --features "cache-memory"
# 输出: 登录成功，token = <8 位随机 token 前缀>
```

> 本示例已由 [examples/tests/readme_quickstart.rs](./examples/tests/readme_quickstart.rs) 持续验证（随 CI 运行），业务代码与 [`examples/src/web/readme_quickstart.rs`](examples/src/web/readme_quickstart.rs) 逐字对应。

### 🧭 核心概念

- **全局单例 + 静态 API**：`GarrisonManager` 启动时一次性注入 dao / config / interface，业务代码经 `GarrisonUtil` 静态 API 零状态调用。
- **token 上下文**：token 经 task_local 上下文（`garrison::stp::with_current_token`）携带，Web 中间件自动绑定，静态 API 自动读取当前 token。
- **双模会话**：Account-Session（账号级）与 Token-Session（登录级）双会话由 `is_share` / `is_concurrent` 控制多端策略。
- **特性门控**：全部可选能力均为独立 feature，编译产物只包含启用的部分。

> token 上下文、双抽象层存储等概念详解见 [📖 用户指南 · 核心概念](docs/USER_GUIDE.md#-核心概念)。

---

## 🎨 特性标志

### 📋 功能矩阵

下表逐项对应 `Cargo.toml` 的 `[features]` 定义，`default = ["backend-embedded"]`。

<table style="width:100%; border-collapse: collapse">
<tr><th style="text-align:left">特性</th><th style="text-align:center">默认</th><th style="text-align:left">说明</th></tr>
<tr><td><code>backend-embedded</code></td><td align="center">✅</td><td>内嵌后端模式（进程内认证，委托 GarrisonManager）</td></tr>
<tr><td><code>backend-remote</code></td><td align="center">❌</td><td>远程后端适配器（通过 HTTP 调用远程 Auth Server）</td></tr>
<tr><td><code>backend-kit</code></td><td align="center">❌</td><td>trait-kit typestate DI 构建</td></tr>
<tr><td><code>auth-server</code></td><td align="center">❌</td><td>独立认证服务器（sdforge 声明式路由 + TLS）</td></tr>
<tr><td><code>abac</code></td><td align="center">❌</td><td>基于 Cedar DSL 的属性访问控制引擎</td></tr>
<tr><td><code>oauth2-server</code></td><td align="center">❌</td><td>完整 OAuth2 Server 4 端点</td></tr>
<tr><td><code>cache-memory</code></td><td align="center">❌</td><td>内存缓存后端（oxcache 内存层）</td></tr>
<tr><td><code>cache-redis</code></td><td align="center">❌</td><td>Redis 缓存后端（oxcache L2）</td></tr>
<tr><td><code>db-sqlite</code></td><td align="center">❌</td><td>SQLite 数据库后端</td></tr>
<tr><td><code>db-postgres</code></td><td align="center">❌</td><td>PostgreSQL 后端</td></tr>
<tr><td><code>db-mysql</code></td><td align="center">❌</td><td>MySQL 后端</td></tr>
<tr><td><code>web-axum</code></td><td align="center">❌</td><td>axum Web 框架适配</td></tr>
<tr><td><code>web-actix</code></td><td align="center">❌</td><td>actix-web Web 框架适配</td></tr>
<tr><td><code>web-warp</code></td><td align="center">❌</td><td>warp Web 框架适配</td></tr>
<tr><td><code>web-waf</code> / <code>web-cors</code> / <code>web-csrf</code></td><td align="center">❌</td><td>WAF / CORS / CSRF 中间件</td></tr>
<tr><td><code>protocol-jwt</code></td><td align="center">❌</td><td>JWT 签发与验证（HS256/HS512 + refresh）</td></tr>
<tr><td><code>protocol-oauth2</code></td><td align="center">❌</td><td>OAuth2 四种模式</td></tr>
<tr><td><code>protocol-sso</code> / <code>protocol-sso-server</code></td><td align="center">❌</td><td>SSO ticket / SSO Server 抽象</td></tr>
<tr><td><code>protocol-sign</code></td><td align="center">❌</td><td>API 签名 + nonce 防重放</td></tr>
<tr><td><code>protocol-apikey</code></td><td align="center">❌</td><td>API Key 认证</td></tr>
<tr><td><code>protocol-temp</code></td><td align="center">❌</td><td>临时凭证</td></tr>
<tr><td><code>protocol-oidc</code></td><td align="center">❌</td><td>OIDC id_token 签发/验证 + discovery</td></tr>
<tr><td><code>protocol-httpbasic</code> / <code>protocol-httpdigest</code></td><td align="center">❌</td><td>HTTP Basic / Digest 认证</td></tr>
<tr><td><code>protocol-saml</code></td><td align="center">❌</td><td>SAML 2.0 骨架</td></tr>
<tr><td><code>protocol-zeroize</code></td><td align="center">❌</td><td>协议层密钥零化</td></tr>
<tr><td><code>secure-totp</code></td><td align="center">❌</td><td>TOTP 动态验证码 (RFC 6238)</td></tr>
<tr><td><code>secure-sign</code></td><td align="center">❌</td><td>HMAC-SHA256/SHA512 工具</td></tr>
<tr><td><code>secure-confusable</code> / <code>secure-masking</code> / <code>secure-xss</code> / <code>secure-sanitize</code></td><td align="center">❌</td><td>安全工具集</td></tr>
<tr><td><code>secure-simple-token</code> / <code>secure-ct-eq</code></td><td align="center">❌</td><td>签名 / 常量时间比较</td></tr>
<tr><td><code>account-credential</code> / <code>account-policy</code> / <code>account-lockout</code> / <code>account-authflow</code></td><td align="center">❌</td><td>账号安全引擎</td></tr>
<tr><td><code>firewall</code> / <code>firewall-*</code></td><td align="center">❌</td><td>安全防护套件（暴力破解/限流/异常/GeoIP/DDoS/WAF）</td></tr>
<tr><td><code>listener</code></td><td align="center">❌</td><td>事件监听器（15 个事件变体）</td></tr>
<tr><td><code>tracing-log</code> / <code>metrics-prometheus</code> / <code>otlp</code></td><td align="center">❌</td><td>可观测性</td></tr>
<tr><td><code>annotation-macros</code></td><td align="center">❌</td><td>10 个属性宏</td></tr>
<tr><td><code>tenant-isolation</code></td><td align="center">❌</td><td>多租户逻辑隔离</td></tr>
<tr><td><code>social-wechat</code> / <code>social-alipay</code></td><td align="center">❌</td><td>社交登录</td></tr>
<tr><td><code>core-advanced</code> / <code>session-extra</code></td><td align="center">❌</td><td>核心增强 / 会话增强合并</td></tr>
<tr><td><code>email-verification</code> / <code>email-verification-smtp</code></td><td align="center">❌</td><td>邮箱验证码</td></tr>
<tr><td><code>config-*</code></td><td align="center">❌</td><td>配置文件加密/校验/热更新/插值/动态/开关（confers 透传）</td></tr>
<tr><td><code>i18n</code> / <code>i18n-icu</code></td><td align="center">❌</td><td>国际化</td></tr>
<tr><td><code>full</code> / <code>production</code> / <code>development</code></td><td align="center">❌</td><td>聚合特性</td></tr>
</table>

> **v0.9.0 Feature 改名映射**：
>
> | 旧名称 (≤0.8.x) | 新名称 (≥0.9.0) | 说明 |
> |-----------------|-----------------|------|
> | `secure-saml` | `protocol-saml` | SAML 2.0 签名验证 |
> | `secure-httpbasic` | `protocol-httpbasic` | HTTP Basic 认证 |
> | `secure-httpdigest` | `protocol-httpdigest` | HTTP Digest 认证 |
> | `observability-otlp` | `otlp` | OpenTelemetry OTLP |
> | `decision-trace` / `permission-registry` / `safe-defaults` | `core-advanced` | 核心增强合并 |
> | `dynamic-active-timeout` / `login-token-map-persistence` / `anonymous-session` / `session-search` | `session-extra` | 会话增强合并 |

---

## 📚 文档

| 文档 | 说明 |
|------|------|
| [📖 用户指南](docs/USER_GUIDE.md) | 从安装到进阶的完整使用教程 |
| [📘 API 参考](docs/API_REFERENCE.md) | 公开 API 与模块参考 |
| [🏗️ 架构文档](docs/ARCHITECTURE.md) | 设计原则、模块划分与数据流 |
| [⚙️ 配置指南](docs/CONFIGURATION.md) | 三级配置源、完整配置项与热更新 |
| [⚡ 性能指南](docs/PERFORMANCE.md) | 性能目标、基准测试与优化建议 |
| [🧪 测试场景矩阵](docs/TEST_SCENARIOS.md) | 验收场景穷举、特性组合矩阵与质量门禁 |
| [🔒 安全文档](SECURITY.md) | 安全策略、漏洞报告流程 |
| [🛡️ 威胁模型](docs/THREAT.md) | STRIDE 分析、框架防御与业务方责任边界 |
| [❓ FAQ](docs/FAQ.md) | 常见问题解答 |
| [🔧 问题排查](docs/TROUBLESHOOTING.md) | 常见问题与解决方案 |
| [🛠️ 开发规范](docs/DEVELOPMENT.md) | TDD 工作流、代码规范与调试技巧 |
| [🚀 部署指南](docs/DEPLOYMENT.md) | 生产部署注意事项 |
| [🗺️ 路线图](docs/ROADMAP.md) | 版本演进规划 |
| [📦 发布工作流](docs/RELEASING.md) | 版本发布流程与门禁 |
| [🤝 贡献指南](docs/CONTRIBUTING.md) | 如何参与项目开发 |
| [📋 更新日志](docs/CHANGELOG.md) | 每个版本的变更记录 |
| [📦 在线 API 文档](https://docs.rs/garrison) | docs.rs 自动生成的最新文档 |
| [📦 crates.io](https://crates.io/crates/garrison) | 发布页面 |

---

## 💻 示例

全部 65 个可运行示例位于 [`examples/`](examples/) 目录（独立 workspace member，`garrison-examples` crate），每个示例配套 1:1 独立测试，按「登录 / 会话 / Token 基础、注解与 Web 集成、认证协议、安全防护、可观测性与基础设施」等主题分组，完整清单与各示例所需 feature 见 [examples/README.md](examples/README.md)。

```bash
# 运行单个示例
cargo run -p garrison-examples --bin basic_login --features full

# 验证全部示例可编译
cargo build -p garrison-examples --features full
```

---

## 🏗️ 架构

Garrison 采用**双抽象层 + 全局单例**架构：`GarrisonDao` trait 统一屏蔽 `dbnexus`（SQLite / PostgreSQL / MySQL）+ `oxcache`（L1 内存 / L2 redis）存储后端差异，核心模块 always on、可选能力（`protocol-*`、`secure-*`、`firewall-*`、`account-*`、`web-*` 等）按 feature 独立门控，核心数据通路为「业务代码 → `GarrisonUtil` → `GarrisonManager` 单例 → `GarrisonLogicDefault` → `GarrisonDao` / `GarrisonPermissionStrategy` → 存储后端」。

模块分层、trait 关系与请求处理数据流的完整说明见 [🏗️ 架构文档](docs/ARCHITECTURE.md)。

---

## 🧪 测试

### 🎯 测试策略

测试按「单元（`src/` 内联 `#[cfg(test)]`）→ 验收 / 集成（`tests/acceptance/` 按域组织 + db 专用 target + trybuild UI 测试）→ 示例级集成（`examples/tests/` 与示例 bin 一一对应）」三层组织，另有 Criterion 基准、文档测试与特性组合编译矩阵（`ci.yml` test-compile-guard + 每周 `feature-matrix.yml`）。场景穷举、真实服务矩阵（Redis / PostgreSQL / MySQL / Keycloak 26 / HIBP）与特性依赖分析见 [🧪 测试场景矩阵](docs/TEST_SCENARIOS.md)。

### ▶️ 运行命令（与 CI 一致）

```bash
# 单元测试（CI test job 的两种特性面）
cargo test --no-default-features --features "default" --lib --locked
cargo test --features "full" --lib --locked

# 验收 / 集成测试（CI integration-test job；services 含 Redis 与 PostgreSQL）
cargo test --features "full" --tests --no-fail-fast

# 验收矩阵（full + testing 特性面）
cargo test --test acceptance --features "full testing"

# 性能基线（concurrency 域 #[ignore] 的 perf_* 用例）
cargo test --test acceptance --features "full testing" perf_ -- \
    --nocapture --test-threads=1 --ignored

# 文档测试（CI Linux/MSRV 腿）
cargo test --features "full,audit-log" --doc --locked

# 一键 E2E（auth_server_serve 冒烟 + 全量验收 + 性能基线 + 报告聚合）
bash scripts/e2e_run.sh
# 本地全量流水线（compose 真服务自举 + 静态门禁 + 全部测试 + 特性矩阵 + 基准）
bash scripts/e2e_matrix.sh

# Lint 与格式门禁
cargo clippy --no-default-features --features "default" -- -D warnings
cargo clippy --features "full" -- -D warnings
cargo fmt --all -- --check

# 覆盖率门禁：行覆盖率不低于 85%
cargo llvm-cov --features "full" --fail-under-lines 85

# 依赖安全门禁
cargo deny --all-features --locked check

# 基准测试（--bench 限定 criterion 目标，避免连带 lib unittest）
cargo bench --bench garrison_benchmark --features full --locked -- --quick
```

> 构建依赖：`protoc`（sdforge build script 需要，CI 经 taiki-e/install-action 安装）。

### 📊 测试规模

约 5330 个测试（单元约 4800 + 验收 / 集成 / UI 约 406 + 示例级约 116 + 过程宏 8）与 4 个 Criterion 基准场景；覆盖率门禁为行覆盖率不低于 85%（当前约 95.8%）。统计口径与明细见 [🧪 测试场景矩阵 · 测试规模统计](docs/TEST_SCENARIOS.md#-测试规模统计)。

---

## 📊 性能

基准场景与目标定义于 [`benches/garrison_benchmark.rs`](benches/garrison_benchmark.rs)（`login_flow` / `token_verify_stateless` / `permission_check` / `oxcache_backend_switch` 四个 Criterion 场景），以 `cargo bench` 在本机复现；验收层另有 HTTP 性能基线（P99 < 200ms / 1000 RPS），经 `scripts/e2e_run.sh` 采集并聚合报告。性能设计要点（单例无锁化、慢哈希 `spawn_blocking` 下沉、请求内快照复用、缓存 TTL 抖动、全量 feature 门控）与逐项优化建议见 [⚡ 性能指南](docs/PERFORMANCE.md)。

---

## 🔒 安全

### 🛡️ 安全设计

Garrison 围绕身份认证全生命周期做纵深防护：Argon2id / Bcrypt 慢哈希经 `spawn_blocking` 下沉、Token 常量时间比较（`secure-ct-eq`，CWE-208）、API Key 哈希存储与 IP 级限速（CWE-916 / CWE-307）、多租户 IDOR 防护、审计事件 token 统一掩码（CWE-532）、外网登录端点 fail-closed 等。逐项机制的代码级细节见 [🏗️ 架构文档](docs/ARCHITECTURE.md) 与 [📖 用户指南 · 安全与防护](docs/USER_GUIDE.md)，安全配置最佳实践与漏洞处理流程见 [🔒 安全文档](SECURITY.md)。

### ⛓️ 供应链与门禁

CI 与发布流程内置三道供应链门禁：`cargo deny check`（漏洞 / 许可证 / 禁用依赖）、`cargo audit`（RustSec 公告扫描）与 pre-commit gitleaks 私钥扫描；门禁标准与处置细节见 [🔒 安全文档 · 供应链与门禁](SECURITY.md)。

### 🚨 报告安全漏洞

请勿通过公开 issue 报告安全漏洞。请使用 GitHub [Security Advisories](https://github.com/Kirky-X/garrison/security/advisories/new) 私密披露通道或发送邮件至 <Kirky-X@outlook.com>。项目承诺 48 小时内确认、7 天内给出初步评估。完整政策见 [SECURITY.md](SECURITY.md)。

---

## 🗺️ 开发路线图

<table style="width:100%; border-collapse: collapse">
<tr><th style="text-align:center">状态</th><th style="text-align:left">方向</th><th style="text-align:left">条目</th></tr>
<tr><td align="center">✅</td><td>核心引擎</td><td>登录认证 + 权限校验 + 双模会话 + axum/actix/warp 适配</td></tr>
<tr><td align="center">✅</td><td>协议层</td><td>JWT / OAuth2 / SSO / OIDC / SAML 2.0 / API Key / TOTP / Basic / Digest / Sign</td></tr>
<tr><td align="center">✅</td><td>安全与防护</td><td>账号安全引擎 / 安全防护套件 / 防火墙 / 多租户 / 审计日志</td></tr>
<tr><td align="center">✅</td><td>微服务架构</td><td>backend-remote / Auth Server / ABAC / OAuth2 Server / gRPC</td></tr>
<tr><td align="center">✅</td><td>可观测性</td><td>tracing / metrics-prometheus / OTLP / i18n</td></tr>
<tr><td align="center">🚧</td><td>下一版本安全加固</td><td>外网登录端点 fail-closed、密码登录时序侧信道对齐、OAuth2 password grant 限流 fail-closed、JWT 黑名单写失败重试（见 [docs/CHANGELOG.md](docs/CHANGELOG.md) · Unreleased）</td></tr>
<tr><td align="center">📋</td><td>v1.0.0 稳定版</td><td>API 冻结 + 性能基准 + 生产案例</td></tr>
</table>

完整规划见 [docs/ROADMAP.md](./docs/ROADMAP.md)。

---

## 🤝 参与贡献

详细的贡献流程与代码规范请参阅 [🤝 贡献指南](docs/CONTRIBUTING.md)。

### 🛠️ 开发环境

工具链为 Rust 1.85+（`rust-toolchain.toml` 锁定）；提交前运行 `cargo fmt --all -- --check` 与 `cargo clippy --all-targets --all-features -- -D warnings`；提交信息遵循 Conventional Commits（`feat`、`fix`、`docs` 等）。完整环境搭建步骤见 [🤝 贡献指南 · 开发环境搭建](docs/CONTRIBUTING.md#-开发环境搭建)。

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

---

## 📋 更新日志

完整版本历史见 [📋 更新日志](docs/CHANGELOG.md)（遵循 [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) 格式，语义化版本）。

| 版本 | 日期 | 要点 |
|------|------|------|
| 0.9.0-rc.2 | 2026-08-26 | fail-closed 安全加固（check_api_key / check_abac）；自研库 rc.4 升级 |
| 0.9.0-rc.1 | 2026-08-25 | 验收测试体系 + DAO 原子契约收严 + gRPC async 鉴权层 |
| 0.8.1 | 2026-07-25 | 文档一致性修复 + 依赖版本同步 |

---

## 📄 许可证

本项目基于 [Apache-2.0](LICENSE) 许可证开源。为何选择 Apache-2.0 而非 MIT：Apache-2.0 包含专利授权条款，更适合企业级框架使用。

---

## 🙏 致谢

### 🌟 核心依赖

Garrison 站在以下优秀开源项目的肩膀上：

| 依赖 | 用途 |
|------|------|
| [axum](https://github.com/tokio-rs/axum) | tokio 团队出品的 Rust Web 框架 |
| [oxcache](https://github.com/Kirky-X/oxcache) | Rust 多级缓存库（L1 内存 + L2 redis） |
| [dbnexus](https://github.com/Kirky-X/dbnexus) | Rust 数据库抽象层（SQLite / PostgreSQL / MySQL） |
| [inventory](https://github.com/dtolnay/inventory) | David Tolnay 的编译期插件注册库 |
| [confers](https://github.com/Kirky-X/confers) | Rust 配置管理库（零样板代码） |
| [sdforge](https://github.com/Kirky-X/sdforge) | 声明式 Web 框架 |
| [trait-kit](https://github.com/Kirky-X/trait-kit) | trait 工具集 |

### 💝 特别感谢

- [Sa-Token](https://github.com/dromara/sa-token)：Java 生态的认证鉴权框架，为本项目早期领域建模提供参考
- 感谢 Rust 社区与所有 [贡献者](https://github.com/Kirky-X/garrison/graphs/contributors)

---

## 📞 联系与支持

<table style="width:100%; max-width: 600px">
<tr>
<td align="center" width="33%">
<a href="https://github.com/Kirky-X/garrison/issues"><b style="color:#991B1B">Issues</b></a><br>
<span style="color:#64748B">报告问题和 Bug</span>
</td>
<td align="center" width="33%">
<a href="docs/FAQ.md"><b style="color:#1E40AF">FAQ</b></a><br>
<span style="color:#64748B">常见问题解答</span>
</td>
<td align="center" width="33%">
<a href="https://github.com/Kirky-X/garrison"><b style="color:#1E293B">GitHub</b></a><br>
<span style="color:#64748B">查看源代码</span>
</td>
</tr>
</table>

---

## ⭐ Star 历史

[![Star History Chart](https://api.star-history.com/svg?repos=Kirky-X/garrison&type=Date)](https://star-history.com/#Kirky-X/garrison&Date)

如果这个项目对您有帮助，请考虑给它一个 ⭐️！

<b>由 Kirky.X 构建</b>

---

<sub>© 2026 Kirky.X. 保留所有权利。</sub>
