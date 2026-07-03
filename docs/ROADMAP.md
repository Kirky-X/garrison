# Bulwark 项目路线图

本文件描述 Bulwark（Rust 认证授权框架，借鉴 Sa-Token v1.45.0 设计哲学）的版本演进规划与设计原则。

> 仓库：<https://github.com/Kirky-X/bulwark>
> License：Apache-2.0
> 作者：Kirky.X
> 变更管理：通过 OpenSpec 工作流进行 proposal → design → tasks → archive
> 架构设计详见 [architecture.md](./ARCHITECTURE.md)；开发规范详见 [development.md](./DEVELOPMENT.md)。

---

## 版本总览

| 版本 | 状态 | 计划完成 | 主要内容 |
|------|------|---------|---------|
| 0.1.0 | ✅ 已完成 | 2026-06-30 | 核心基础设施 |
| 0.2.0 | ✅ 已完成 | 2026-07-01 | 协议与安全层 |
| 0.2.1 | ✅ 已完成 | 2026-07-01 | auto-wire 修复 + 协议边界测试 + examples 工程化 |
| 0.3.0 | ✅ 已完成 | 2026-07-02 | 生态完善与可观测（OTLP / gRPC / i18n / metrics） |
| 0.4.0 | ✅ 已完成 | 2026-07-02 | 0.2.0 协议层遗留 gap 补齐（OIDC / ScopeHandler / SsoServer / AloneCache / ParameterQuery） |
| 1.0.0 | 📋 待规划 | 2027 Q2 | 稳定版 |

---

## 详细版本规划

### v0.1.0 核心基础设施（已完成）

发布日期：2026-06-30

- ✅ 错误类型体系（`BulwarkError`）
- ✅ 配置系统（三级配置源 + `tokio::sync::watch` 热更新）
- ✅ 上下文抽象（`BulwarkContext` + axum adapter + task_local）
- ✅ DAO 抽象（`BulwarkDao` trait + oxcache + dbnexus）
- ✅ 双模会话管理（Account-Session + Token-Session）
- ✅ 核心 API（`BulwarkLogic` + `BulwarkUtil`）
- ✅ 权限校验策略（`BulwarkFirewallStrategy`）
- ✅ 全局管理器（`BulwarkManager` + inventory 编译期注册）
- ✅ axum 集成（extractor + `BulwarkRouter` + Interceptor）

**里程碑意义**：完成"能跑起来"的最小闭环，支持基于 UUID/Random64 Token 的登录、会话、权限校验与 axum 集成。可作为评估框架设计哲学的基线版本。

#### 已知限制（0.1.0）

- oxcache 0.3 `Cache<K,V>::update` 无法保留 per-entry TTL
- dbnexus 0.2 仅支持 SQLite（PostgreSQL/MySQL 待 0.2.0+）
- `BulwarkRouter::route_protected` 仅支持 GET 方法

---

### v0.2.0 协议与安全层（已完成）

发布日期：2026-07-01

#### 0.2.0 特性域状态表

Bulwark 借鉴 Sa-Token 的 13 个特性域设计，0.2.0 的推进状态如下：

| # | 特性域 | 模块 | Feature | 0.1.0 状态 | 0.2.0 状态 |
|---|--------|------|---------|-----------|------------|
| 1 | 登录认证 | `core/auth` | - | ✅ 已完成 | 🚧 完善 |
| 2 | 权限认证 | `core/permission` | - | ✅ 已完成 | 🚧 完善 |
| 3 | Session 会话 | `session` | - | ✅ 已完成 | 🚧 完善 |
| 4 | OAuth2 | `protocol/oauth2` | `protocol-oauth2` | ❌ 未开始 | 🚧 规划中 |
| 5 | 单点登录 (SSO) | `protocol/sso` | `protocol-sso` | ❌ 未开始 | 🚧 规划中 |
| 6 | JWT | `protocol/jwt` | `protocol-jwt` | ❌ 未开始 | 🚧 规划中 |
| 7 | 微服务网关鉴权 | `protocol/sign` | `protocol-sign` | ❌ 未开始 | 🚧 规划中 |
| 8 | API 接口鉴权 | `protocol/apikey` | `protocol-apikey` | ❌ 未开始 | 🚧 规划中 |
| 9 | 临时凭证 | `protocol/temp` | `protocol-temp` | ❌ 未开始 | 🚧 规划中 |
| 10 | TOTP 动态验证码 | `secure/totp` | `secure-totp` | ❌ 未开始 | 🚧 规划中 |
| 11 | Basic 认证 | `secure/httpbasic` | `secure-httpbasic` | ❌ 未开始 | 🚧 规划中 |
| 12 | Digest 认证 | `secure/httpdigest` | `secure-httpdigest` | ❌ 未开始 | 🚧 规划中 |
| 13 | 路由拦截鉴权 | `router` | `web-axum` | ✅ 已完成 | 🚧 完善 |

#### 协议层（protocol-*）

- 🚧 JWT 签发与验证（`protocol-jwt`）
- 🚧 OAuth2 三种模式（`protocol-oauth2`，授权码 / 密码 / 客户端凭证）
- 🚧 SSO 单点登录 ticket（`protocol-sso`）
- 🚧 API 签名 + nonce 防重放（`protocol-sign`）
- 🚧 API Key 认证（`protocol-apikey`）
- 🚧 临时凭证（`protocol-temp`）

#### 安全层（secure-*）

- 🚧 TOTP 动态验证码（`secure-totp`，RFC 6238）
- 🚧 HMAC 签名工具（`secure-sign`）
- 🚧 HTTP Basic 认证（`secure-httpbasic`）
- 🚧 HTTP Digest 认证（`secure-httpdigest`）

#### 核心扩展

- 🚧 `core/auth` / `core/permission` / `core/token` 抽象完善
- 🚧 异常系统 + JSON 模板 + 插件系统 + 监听器
- 🚧 新增配置字段：`jwt_algorithm`、`sign_window_seconds`、`sso_ticket_ttl_seconds`

**里程碑意义**：覆盖 Sa-Token 13 个特性域中的大部分协议与安全子域，Bulwark 从"可用"走向"完整"。

---

### v0.2.1 稳定性优化与文档补充（已完成）

发布日期：2026-07-01

PATCH 版本，聚焦于 0.2.0 的 bug 修复与协议层稳定性优化，不引入新协议或新功能特性。

#### 修复

- ✅ auto-wire gap 修复：`BulwarkManager::init` 现自动注入 PluginManager / ListenerManager / AuthLogic / PermissionChecker 到 `BulwarkLogicDefault`
- ✅ `BulwarkLogicDefault` 新增 4 个 builder 方法（`with_plugin_manager` / `with_listener_manager` / `with_auth_logic` / `with_permission_checker`）
- ✅ `BulwarkLogicFactoryFn` 签名扩展，新增 `BulwarkLogicFactoryContext` 支持 factory 注入 manager

#### 测试补全

- ✅ 协议层边界场景测试（6 个模块 20 个测试）：OAuth2 / SSO / JWT / Sign / APIKey / Temp
- ✅ auto-wire 集成测试（3 个测试）：验证 `BulwarkUtil::login/logout` 自动触发 plugin/listener
- ✅ examples 工程化重组：workspace member + 每 bin 独立测试文件

#### 文档

- ✅ 修复 `context_request` 模块 doc 未闭合 HTML 标签
- ✅ `cargo doc --no-deps --features full --workspace` 零警告

**里程碑意义**：补齐 0.2.0 的 auto-wire gap 与协议层边界测试覆盖，为 0.3.0 多后端演进奠定稳定基线。

---

### v0.3.0 生态完善与可观测（已完成）

发布日期：2026-07-02

聚焦于生态集成与可观测性能力，不引入新协议层。

#### 新增（生态集成）

- ✅ OpenTelemetry OTLP 分布式追踪（`observability-otlp` feature，OTLP gRPC 导出）
- ✅ gRPC 鉴权拦截器（`grpc` feature，`tonic::Interceptor` 实现）
- ✅ 异常消息国际化（`i18n` feature，fluent-rs 中英文切换）
- ✅ Prometheus 指标（`metrics-prometheus` feature）

#### 已知限制（0.3.0）

- PostgreSQL / MySQL 后端仍待 `dbnexus` 0.3+ 提供（推迟至 0.5.0+）
- actix-web / warp 适配仅提供最小骨架，未做完整 extractor 适配

**里程碑意义**：补齐生产级可观测性与生态集成能力，为 0.4.0 协议层 gap 闭环奠定基础。

---

### v0.4.0 协议层遗留 gap 补齐（已完成）

发布日期：2026-07-02

聚焦于 0.2.0 协议层遗留的 8 项 gap，通过 OpenSpec change
`v0-2-0-protocol-layer-gap-closure` 实施。完成 7 项，gap #4 因 spec 错误延后至 0.5.0+。

#### 新增（5 个 feature flag）

| Gap | Feature | 核心类型 | 状态 |
|-----|---------|---------|------|
| #1 OAuth2 RefreshToken | `protocol-oauth2`（扩展现有 feature） | `OAuth2Client::refresh_access_token` | ✅ 完成 |
| #2 OIDC | `protocol-oidc` | `OidcHandler`（sign_id_token / verify_id_token / discovery_metadata） | ✅ 完成 |
| #3 Scope Handler | `oauth2-scope-handler` | `ScopeHandler` trait + `ScopeRegistry` | ✅ 完成 |
| #5 SSO Server | `protocol-sso-server` | `SsoServer` trait + `CenterIdConverter` + `SsoChannel` + `DefaultSsoServer` | ✅ 完成 |
| #6 AloneCache | `alone-cache` | `AloneCache` 装饰器 + `AloneCacheManager` | ✅ 完成 |
| #7 ParameterQuery | `parameter-query` | `ParameterQuery` trait + `ParameterQueryBuilder` | ✅ 完成 |
| #8 master-slave 验证 | — | spec 文档验证（oxcache 0.3 sentinel 模式覆盖） | ✅ 完成 |
| #4 注解系统 | — | `@CheckAccessToken` / `@CheckClientToken` | ⏸️ 延后 0.5.0+ |

#### 代码审查后修复（review pass）

- ✅ M5：`SsoClient::validate_ticket` client_id 不匹配错误类型 `Config` → `InvalidToken`
- ✅ M6：`SsoTicketData` 跨模块去重，`pub(crate)` 导出
- ✅ M7：`ParameterQueryBuilder::check_permission/check_role` 提取 `check_common` helper
- ✅ M4：`OidcHandler` 新增 `require_hmac_algorithm()`，非对称算法返回 `Config` 错误
- ✅ L9：`verify_id_token_tampered_fails` 测试断言强化为 `InvalidToken`
- ✅ M1：SSO `validate_ticket` TOCTOU 竞态添加 doc 警告（待 0.5.0+ 原子 get-and-delete）

#### 测试覆盖率

- 829 lib tests + 集成测试 + example tests 全部通过
- tarpaulin 覆盖率 95.43%（2298/2408 行），超过 95% 目标

#### 已知限制（0.4.0）

- **gap #4 延后**：spec 错误引用 `OAuth2Client::validate_client_token`（方法不存在）。需先设计
  token introspection（RFC 7662）或复用 `OidcHandler::verify_id_token` 的方案
- **SSO TOCTOU 竞态（M1）**：`validate_ticket` 的 get→delete 非原子，并发调用同一 ticket
  理论上可重放。60 秒 TTL 窗口内影响有限，安全敏感场景应通过外层加锁保证。待 0.5.0+ 统一修复

**里程碑意义**：补齐 0.2.0 协议层遗留 gap，OIDC / Scope Handler / SSO Server / AloneCache /
ParameterQuery 五大能力就位，Bulwark 协议层从"能用"走向"完整"。

---

### v1.0.0 稳定版（待规划）

计划完成：2027 Q2

- 📋 API 冻结（semver 稳定承诺）
- 📋 性能基准测试
- 📋 生产案例文档
- 📋 安全审计

**里程碑意义**：发布 1.0 稳定版，给出向后兼容承诺与生产可用性证据，进入长期维护期。

---

## 版本兼容性策略（SemVer）

Bulwark 遵循 [SemVer](https://semver.org/lang/zh-CN/) 语义化版本规范：

| 版本变更 | 允许的变更类型 | 示例 |
|---------|---------------|------|
| **patch**（0.1.0 → 0.1.1） | 仅 bug fix 与文档，**不破坏**任何 API | 修复会话续期 panic |
| **minor**（0.1 → 0.2） | 可新增 feature、新增 API，**不破坏**已有 API | 新增 `protocol-jwt` |
| **major**（0.x → 1.0） | 允许破坏性变更，仅在重大设计缺陷下 | API 冻结前的最后机会 |

### 破坏性变更过渡策略

破坏性变更优先以 deprecation 周期过渡：

1. 先标记 `#[deprecated]` + 文档警告
2. 至少经过一个 minor 版本的过渡期
3. 过渡期结束后在 major 版本中移除

> 在 0.x 阶段（1.0 之前），minor 版本理论上允许破坏性变更，但 Bulwark 承诺仅在不可避免时才这样做，并提前在 CHANGELOG 中标注。

### 向后兼容承诺

- **0.1.0 的核心 API** 在 1.0 之前不会发生破坏性变更（`BulwarkManager` / `BulwarkUtil` / `BulwarkConfig` 等核心接口稳定）。
- **协议/安全层 API** 在 0.2.0 阶段可能调整，建议在生产环境中锁定具体 patch 版本。

---

## 设计原则

Bulwark 在整个版本演进过程中遵循以下四条原则：

### 1. 借鉴而非照搬

学习 Sa-Token 的领域建模（13 特性域划分）、API 设计哲学（静态工具类 + 全局配置）与使用习惯，但用 Rust idiomatic 方式实现：

- 用 `trait` 替代 Java interface
- 用 `async fn` + `tokio` 替代线程池
- 用 `inventory` 替代 SPI 反射
- 用 `Feature` 门控替代 Maven profile

### 2. 抽象优先

所有核心组件均以 **trait + Default** 模式提供，任何组件都可被替换为自定义实现，框架默认实现仅在未被覆盖时生效。

### 3. Feature 门控

按需编译，减小二进制体积。每个特性域对应一个 cargo feature，通过聚合 feature 一键启用常用组合。保证 Bulwark 在 Edge、WASM、嵌入式等资源敏感场景下也能使用。

### 4. 向后兼容

遵循 semver 规范，破坏性变更优先以 deprecation 周期过渡。

---

## 变更管理

所有版本演进通过 **OpenSpec 工作流** 管理：

```text
explore → propose → apply → archive
```

- `explore`：探索阶段，明确需求与可行性
- `propose`：提案阶段，输出 proposal / design / specs / tasks
- `apply`：实施阶段，按 tasks 推进实现
- `archive`：归档阶段，同步 delta spec 到主 spec 库

每个变更在合并前必须经过影响面分析，HIGH / CRITICAL 风险变更需要显式评估后才能推进。

---

> 本路线图为持续滚动更新文档，实际发布时间与内容可能随社区反馈调整。最新进展请关注 [GitHub Releases](https://github.com/Kirky-X/bulwark/releases)。
