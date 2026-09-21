# 📖 Garrison 用户指南

**Garrison** 是面向 Rust 生态的一站式身份认证鉴权框架：登录认证 → 权限校验 → 会话管理 → 路由拦截开箱即用。业务方实现一个 `GarrisonInterface` 回调、注入一个 `GarrisonDao` 存储后端，即可获得完整的认证鉴权能力；全部可选能力（协议层、防火墙、账号安全等）均以独立 feature 门控，编译产物只包含启用的部分。

> 适用版本：0.9.0-rc.2（MSRV 1.85）。本文只讲「怎么用」；架构设计见 [🏗️ 架构文档](ARCHITECTURE.md)，配置项全表见 [⚙️ 配置指南](CONFIGURATION.md)。

## 📋 目录

- [快速开始](#-快速开始)
  - [安装](#-安装)
  - [最小示例](#-最小示例)
- [核心概念](#-核心概念)
  - [全局单例与静态 API](#-全局单例与静态-api)
  - [双模会话](#-双模会话)
  - [token 上下文（task_local）](#-token-上下文task_local)
  - [双抽象层存储](#️-双抽象层存储)
- [会话管理](#-会话管理)
- [权限与角色](#-权限与角色)
- [Web 框架集成](#-web-框架集成)
- [认证协议](#-认证协议)
- [配置](#️-配置)
- [安全与防护](#️-安全与防护)
- [可观测性与扩展](#-可观测性与扩展)
- [最佳实践](#-最佳实践)
- [延伸阅读](#-延伸阅读)

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

> 预发布版本需显式写完整版本号，`"0.9"` 无法匹配 prerelease。如需启用全部协议层与安全模块：`features = ["full"]`。

| 预设 | 安装方式 | 适用场景 |
|------|----------|----------|
| 开发 | `features = ["development"]` | 内存缓存 + SQLite + axum，快速验证 |
| 生产 | `features = ["production"]` | 生产环境推荐组合 |
| 完整 | `features = ["full"]` | 全部能力 |

### 💡 最小示例

完整业务场景：初始化管理器 → 执行登录 → 校验登录状态 → 校验权限 → 登出。

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

> 本示例已由 [`examples/tests/readme_quickstart.rs`](../examples/tests/readme_quickstart.rs) 持续验证（随 CI 运行），逐字对应，不会与 API 漂移。完整可运行版本见 [`examples/src/bin/basic_login.rs`](../examples/src/bin/basic_login.rs)。

---

## 🧭 核心概念

### 🏢 全局单例与静态 API

`GarrisonManager` 是全局单例，启动时通过 builder 一次性注入 `dao`（存储）、`config`（配置）、`interface`（业务回调）后 `build()`。此后业务代码统一走 `GarrisonUtil` 静态 API（登录、登出、校验等），无需再传递句柄。单例内部持有 `Arc<GarrisonLogicDefault>`（实现 6 个子 trait），经 `arc_swap::ArcSwapOption` 无锁读取。

### 🧩 双模会话

| 会话类型 | 生命周期 | 用途 |
|----------|----------|------|
| Account-Session | 账号级、长生命周期 | 账号级状态（如「账号是否在线」），`max_login_count` 闸门的数据源 |
| Token-Session | 登录级、临时数据 | 每次登录的 token 数据 |

多端登录策略由配置项 `is_share`（多端共享 token）/ `is_concurrent`（多端并发登录）控制。完整的字段说明见 [⚙️ 配置指南](CONFIGURATION.md)。

### 🎯 token 上下文（task_local）

Garrison 不把 token 串进每个函数签名，而是用 task_local 上下文携带：`garrison::stp::with_current_token(token, future)` 在 future 执行期间绑定 token，内部的 `GarrisonUtil::check_login()` 等静态 API 自动读取当前 token。Web 适配层（axum/actix/warp 中间件）已自动完成绑定，业务 handler 内直接调用静态 API 即可。

### 🗄️ 双抽象层存储

- **`dbnexus` 数据库抽象层**：SQLite / PostgreSQL / MySQL（`db-sqlite` / `db-postgres` / `db-mysql` feature），auto-migrate + Repository 层（10 trait）。
- **`oxcache` 缓存抽象层**：L1 内存 + L2 redis（`cache-memory` / `cache-redis` feature）。
- 两者由 `GarrisonDao` trait 统一屏蔽，切换存储后端零业务代码改动。注意 dbnexus 约束：embedded（sqlite）与 server-side（postgres/mysql）驱动不可同时编译。

---

## 👤 会话管理

`GarrisonUtil` 提供的会话操作（完整签名见 [📘 API 参考](API_REFERENCE.md)）：

| API | 说明 |
|-----|------|
| `GarrisonUtil::login(id, &LoginParams)` | 执行登录，返回 token；`LoginParams` 可携带设备、租户等扩展字段 |
| `GarrisonUtil::login_simple(id)` | 默认参数登录 |
| `GarrisonUtil::logout()` | 登出当前 token |
| `GarrisonUtil::logout_by_login_id(id)` | 按登录主体登出 |
| `GarrisonUtil::kickout(id)` / `kickout_by_token(token)` | 踢人下线 |
| `GarrisonUtil::check_login()` | 校验登录状态（未登录返回 `GarrisonError::NotLogin`） |
| `GarrisonUtil::get_login_id()` / `get_login_id_by_token(token)` | 读取当前 / 指定 token 的主体 |
| `GarrisonUtil::revoke_token(token)` | 吊销 token（RFC 7009 语义） |
| `GarrisonUtil::refresh_token(token)` | RefreshToken 轮换（`protocol-jwt`） |
| `GarrisonUtil::invalidate_sessions_after_password_change(...)` | 改密后批量失效会话 |

登录风格（token 样式）由配置决定；`token_styles` 相关示例见 [`examples/src/bin/token_styles.rs`](../examples/src/bin/token_styles.rs)。

---

## 🔑 权限与角色

- **校验**：`GarrisonUtil::check_permission("user:read")` / `check_role("admin")`，失败分别抛 `NotPermission` / `NotRole`；`has_permission` / `has_role` 返回布尔而不抛错。
- **数据来源**：框架不假定权限数据存放在哪里，由业务方实现 `GarrisonInterface::get_permission_list` / `get_role_list` 提供回调（可查数据库、读配置、调外部服务）。多账号体系覆写 `get_permission_list_with_type`，按 `login_type` 隔离不同主体（如 admin / merchant）的权限。
- **自定义策略**：默认策略 `GarrisonPermissionStrategyDefault` 做字符串匹配；需要更复杂的判定时实现 `GarrisonPermissionStrategy` 替换。
- **角色层级**：`RoleHierarchyService` + `RoleHierarchyRecord` 提供角色继承（SQL 后端自适应占位符，`any(db-sqlite, db-postgres, db-mysql)`）。
- **决策溯源**：`core-advanced` 面提供 `AuthRequest` / `Decision` / `DecisionReason`，`authorize()` 返回带原因的决策结果。
- **注解式**：axum 下可用 `#[check_login]` / `#[check_role("admin")]` / `#[check_permission("user:read")]` 属性宏（见下节）。

---

## 🌐 Web 框架集成

三个框架适配独立可共存（`web-axum` / `web-actix` / `web-warp`）：

**axum + 注解宏**（`annotation-macros` feature，10 个属性宏）：

```rust
use garrison::annotation::*;

// 路由 handler 上直接标注
#[check_login]
async fn profile() -> &'static str { "ok" }

#[check_role("admin")]
#[check_permission("user:write")]
async fn admin_write() -> &'static str { "ok" }
```

**actix-web**：`GarrisonRouter` + `GarrisonMiddleware` 请求前进入租户上下文再执行鉴权；`with_tenant_resolver(resolver)` / `with_header_tenant()` 配置租户提取（`tenant-isolation` 场景）。

**统一路由抽象**：`GarrisonRouter` 汇聚路由 → `GarrisonInterceptor` 拦截器 → `GarrisonUtil` 静态 API，三个框架共享同一条链路。

完整可运行示例：[`axum_integration.rs`](../examples/src/bin/axum_integration.rs)（253 行完整 Web 应用）、[`macro_annotations.rs`](../examples/src/bin/macro_annotations.rs)、[`web_actix_example.rs`](../examples/src/bin/web_actix_example.rs)、[`web_warp_example.rs`](../examples/src/bin/web_warp_example.rs)。

---

## 🔐 认证协议

全部协议能力按 feature 门控，启用后 API 从 `protocol` 模块与 `GarrisonUtil` 进入：

| 协议 | Feature | 能力要点 | 示例 |
|------|---------|----------|------|
| JWT | `protocol-jwt` | HS256/HS512 三种模式 + refresh 轮换 | `jwt_login.rs` / `jwt_modes.rs` |
| OAuth2 客户端 | `protocol-oauth2` | 四种 grant、PKCE（OAuth 2.1）、token introspection | `oauth2_flow.rs` / `oauth2_pkce.rs` |
| OAuth2 Server | `oauth2-server` | 完整 Server 4 端点 | `oauth2_server_flow.rs` |
| OIDC | `protocol-oidc` | id_token 签发/验证 + discovery + 三重防重放 | `oidc_handler.rs` |
| Keycloak RP | `keycloak-oidc` | Keycloak OIDC relying party | `keycloak_oidc.rs` |
| SSO | `protocol-sso` / `protocol-sso-server` | ticket 流 / SsoServer 抽象 / Redis pub/sub 跨实例 | `sso_flow.rs` / `sso_server.rs` |
| SAML | `protocol-saml` | SAML 2.0（XML 签名验证） | — |
| API Key | `protocol-apikey` | 命名空间管理、安全存储 | `apikey_management.rs` / `apikey_namespace.rs` |
| 临时凭证 | `protocol-temp` | 临时 token 签发 | `temp_credential.rs` |
| API 签名 | `protocol-sign` | HMAC 签名 + nonce 防重放 | `sign_protocol.rs` |
| TOTP | `secure-totp` | RFC 6238 动态验证码 | `totp_login.rs` |
| Basic / Digest | `protocol-httpbasic` / `protocol-httpdigest` | HTTP 标准认证 | `httpbasic_login.rs` / `httpdigest_login.rs` |

> 注意：`protocol-sso` 隐含 `protocol-jwt`（OIDC id_token 强制验签，fail-closed）；`db-sqlite` 与 `db-postgres`/`db-mysql` 互斥。全部约束见 [🧪 测试场景矩阵 · 硬约束](TEST_SCENARIOS.md#硬约束组合矩阵必须遵守)。

---

## ⚙️ 配置

`GarrisonConfig` 统一管理全部配置，实现 `serde::Serialize / Deserialize`：

- **三级配置源合并**：代码默认值 → 配置文件（TOML，经 confers `FileSource` 加载，含路径遍历防护与 10MB 上限）→ 环境变量（confers `EnvSource`，扁平 key 以 `__` 分隔）。
- **热更新**：`tokio::sync::watch` 通道（`config-hot-reload` 面经 confers 透传）。
- **加密**：`config-encryption` 面支持配置文件加密。

会话策略、Token 策略、异常行为、Cookie 策略、多租户、remember-me 等完整配置项表与 TOML 示例见 [⚙️ 配置指南](CONFIGURATION.md)；生产环境变量清单见 `.env.example`。

---

## 🛡️ 安全与防护

| 能力 | Feature | 说明 |
|------|---------|------|
| 密码哈希 | `account-credential` | Argon2id / Bcrypt，慢哈希经 `spawn_blocking` 移出 async executor；Credential SPI + 密码策略（`account-policy`）+ 认证流 DSL（`account-authflow`） |
| 防火墙 | `firewall` / `firewall-*` | 暴力破解 / 限流 / 异常登录 / GeoIP / DDoS / WAF；启用任一 `firewall-*` 时 builder 自动装配检查钩子 |
| 多租户隔离 | `tenant-isolation` | 逻辑隔离 + IDOR 防护，Header / Subdomain / Claim 三种 resolver |
| 审计日志 | `audit-log` | 审计监听器 + 查询（`AuditConfig` / `AuditEntry` / `AuditQuery`），事件载荷 token 统一掩码 |
| 安全工具集 | `secure-*` | 脱敏（masking）、XSS 防护、常量时间比较（`secure-ct-eq`，CWE-208）、混淆字符（confusable）、HMAC（`secure-sign`） |
| 邮箱验证 | `email-verification` (+`-smtp`) | 验证码 + SMTP 发送 + 小时限速 |
| 短信限速 | `sms-rate-limit` | 小时/日双窗口限速与尝试次数控制 |
| 邀请码注册 | `protocol-invitation` | 邀请码凭证 + DAO 防爆破计数 |

安全配置建议与漏洞报告流程见 [🔒 安全文档](SECURITY.md)。

---

## 📡 可观测性与扩展

- **事件监听**（`listener`，15 个事件变体）：实现 `GarrisonListener` trait 并经 `inventory::submit!` 编译期注册，登录 / 登出 / 踢出 / 替换 / 过期 / 刷新等事件实时回调。示例：[`event_listener.rs`](../examples/src/bin/event_listener.rs)、[`custom_plugin.rs`](../examples/src/bin/custom_plugin.rs)。
- **插件**：`GarrisonPlugin` trait + inventory 注册，可在生命周期钩子注入逻辑。
- **tracing 日志**（`tracing-log`）、**Prometheus 指标**（`metrics-prometheus`）、**OTLP**（`otlp`）：示例 [`observability_setup.rs`](../examples/src/bin/observability_setup.rs)。
- **gRPC 拦截器**（`grpc`）：tonic auth layer。示例 [`grpc_interceptor.rs`](../examples/src/bin/grpc_interceptor.rs)。
- **i18n**（`i18n` / `i18n-icu`）：错误消息按 locale 切换中英文（fluent + FTL 资源，`locales/` 目录）。示例 [`i18n_usage.rs`](../examples/src/bin/i18n_usage.rs)。
- **健康检查**（`server-health-check`）：`DbHealthCheck::with_pool` 执行真实 SQL 往返探测。示例 [`health_check.rs`](../examples/src/bin/health_check.rs)。
- **微服务**：`backend-remote`（HTTP 调用远程 Auth Server + limiteron 熔断）、`auth-server`（独立认证服务器，sdforge 声明式路由 + TLS + 优雅停机）。示例 [`backend_remote.rs`](../examples/src/bin/backend_remote.rs)、[`auth_server.rs`](../examples/src/bin/auth_server.rs)。

---

## ✅ 最佳实践

1. **用 `development` 预设起步，逐步收窄 feature 面**：聚合特性只为快速验证，生产按需启用，缩短编译时间并减小二进制体积。
2. **`GarrisonInterface` 回调做缓存**：权限/角色回调在每次鉴权时触发，数据源侧自备缓存或直接用 Repository 层。
3. **不要在 handler 里手动解析 token**：Web 中间件已完成 task_local 绑定，handler 内直接调用 `GarrisonUtil` 静态 API。
4. **遵循 dbnexus 互斥约束**：SQLite（embedded）与 PostgreSQL/MySQL（server-side）二选一，`--all-features` 不可用。
5. **生产启用防火墙与审计**：`firewall-bruteforce` 等启用即自动装配；`audit-log` 的事件已统一掩码 token，自定义 listener 打日志前不要再输出完整 token。
6. **升级前看 [📋 更新日志](CHANGELOG.md) 的 Breaking 章节**：v0.9.0 有 feature 改名映射与 fail-closed 行为变更（`check_api_key` / `check_abac` 等）。
7. **遇到问题先查 [❓ FAQ](FAQ.md) 与 [🔧 问题排查](TROUBLESHOOTING.md)**。

---

## 📚 延伸阅读

| 文档 | 说明 |
|------|------|
| [📘 API 参考](API_REFERENCE.md) | 公开 API 与模块参考 |
| [🏗️ 架构文档](ARCHITECTURE.md) | 设计原则、模块划分与数据流 |
| [⚙️ 配置指南](CONFIGURATION.md) | 三级配置源、完整配置项与热更新 |
| [🧪 测试场景矩阵](TEST_SCENARIOS.md) | 验收场景穷举与特性组合矩阵 |
| [⚡ 性能指南](PERFORMANCE.md) | 性能目标、基准测试与优化建议 |
| [🚀 部署指南](DEPLOYMENT.md) | 生产部署注意事项 |
| [💻 示例目录](../examples/) | 65 个可运行示例（`cargo run -p garrison-examples --bin <名称> --features full`） |
