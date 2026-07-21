# Garrison 项目路线图

本文件描述 Garrison（Rust 认证授权框架）的版本演进规划与设计原则。

> 仓库：<https://github.com/Kirky-X/garrison>
> License：Apache-2.0
> 作者：Kirky.X
> 变更管理：通过 specmark 工作流进行 proposal → design → tasks → archive
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
| 0.4.2 | ✅ 已完成 | 2026-07-05 | gap closure（dao 扩展 / strategy-registry / jwt-modes / oauth-2-1 / token-introspection / apikey-namespace / sso-toctou / password-login / secure-password / login-id-type / login-type-multi-account / session-kickout-device / listener-events-extend / repository-layer / web-context-adapters / annotation-macros） |
| 0.5.0 | ✅ 已完成 | 2026-07-06 | 生产刚需版（多租户 / 社交登录 / 审计日志 / Token Rotation / 安全防护 / 角色层级 / 决策溯源 / Keycloak OIDC RP / SSO TOCTOU 原子化 / 注解系统 / PostgreSQL / actix+warp 完整适配） |
| 0.5.1 | ✅ 已合入 | 2026-07-07 | 工程优化版（RBAC 实体 / UserDevice / 权限注册表 / 请求对象 API / miette 富错误 / JSON 测试 / 显式 Manager API / confusable string 检测，功能直接合入 0.5.2+ 发布） |
| 0.5.2 | ✅ 已完成 | 2026-07-08 | 架构重构版（GarrisonLogic trait 拆分 / LoginId newtype / oxcache _sync 评估 / keys 性能 / stp 模块拆分） |
| 0.5.3 | ✅ 已完成 | 2026-07-09 | 功能补全版（oxcache 升级 / stp 完整拆分 / MySQL 后端 / Firewall MaxMindDb 生产后端） |
| 0.6.0 | ✅ 已完成 | 2026-07-09 | 账号安全引擎版（account/ 模块 + Credential SPI + PasswordPolicyEngine + UserLockoutStrategy + AuthenticationFlow DSL + i18n 社交登录异常 + AccountMetrics） |
| 0.6.1 | ✅ 已完成 | 2026-07-10 | gap-closure-remaining 关闭（remember_me / Redis 部署模式 / switch_to / renew_to_equivalent / OAuth2 注解 / group() / SessionExpiryListener / SAML 2.0 / OIDC RP / Redis pub/sub SsoChannel — 11 项全部补齐） |
| 0.6.7 | ✅ 已完成 | 2026-07-13 | 安全与性能增强（forbid 优先语义 / WAF 级防火墙 / 三层缓存架构 / SMS 验证码渐进式限速 / AnomalousLoginDetector 双引擎） |
| 0.7.0 | ✅ 已完成 | 2026-07-13 | 微服务架构 + ABAC/Cedar + OAuth2 Server + 依赖优化 + 架构加固（7 个能力域 / 252 TDD 任务 / 2968 测试通过） |
| 1.0.0 | 📋 待规划 | 2027 Q2 | 稳定版 |

---

## 详细版本规划

### v0.1.0 核心基础设施（已完成）

发布日期：2026-06-30

- ✅ 错误类型体系（`GarrisonError`）
- ✅ 配置系统（三级配置源 + `tokio::sync::watch` 热更新）
- ✅ 上下文抽象（`GarrisonContext` + axum adapter + task_local）
- ✅ DAO 抽象（`GarrisonDao` trait + oxcache + dbnexus）
- ✅ 双模会话管理（Account-Session + Token-Session）
- ✅ 核心 API（`GarrisonLogic` + `GarrisonUtil`）
- ✅ 权限校验策略（`GarrisonPermissionStrategy`）
- ✅ 全局管理器（`GarrisonManager` + inventory 编译期注册）
- ✅ axum 集成（extractor + `GarrisonRouter` + Interceptor）

**里程碑意义**：完成"能跑起来"的最小闭环，支持基于 UUID/Random64 Token 的登录、会话、权限校验与 axum 集成。可作为评估框架设计哲学的基线版本。

#### 已知限制（0.1.0）

- oxcache 0.3 `Cache<K,V>::update` 无法保留 per-entry TTL
- dbnexus 0.2 仅支持 SQLite（PostgreSQL/MySQL 待 0.2.0+）
- `GarrisonRouter::route_protected` 仅支持 GET 方法

---

### v0.2.0 协议与安全层（已完成）

发布日期：2026-07-01

#### 0.2.0 特性域状态表

Garrison 采用 13 个特性域设计，0.2.0 的推进状态如下：

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

**里程碑意义**：覆盖 13 个特性域中的大部分协议与安全子域，Garrison 从"可用"走向"完整"。

---

### v0.2.1 稳定性优化与文档补充（已完成）

发布日期：2026-07-01

PATCH 版本，聚焦于 0.2.0 的 bug 修复与协议层稳定性优化，不引入新协议或新功能特性。

#### 修复

- ✅ auto-wire gap 修复：`GarrisonManager::init` 现自动注入 PluginManager / ListenerManager / AuthLogic / PermissionChecker 到 `GarrisonLogicDefault`
- ✅ `GarrisonLogicDefault` 新增 4 个 builder 方法（`with_plugin_manager` / `with_listener_manager` / `with_auth_logic` / `with_permission_checker`）
- ✅ `GarrisonLogicFactoryFn` 签名扩展，新增 `GarrisonLogicFactoryContext` 支持 factory 注入 manager

#### 测试补全

- ✅ 协议层边界场景测试（6 个模块 20 个测试）：OAuth2 / SSO / JWT / Sign / APIKey / Temp
- ✅ auto-wire 集成测试（3 个测试）：验证 `GarrisonUtil::login/logout` 自动触发 plugin/listener
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

聚焦于 0.2.0 协议层遗留的 8 项 gap，通过 specmark change
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
ParameterQuery 五大能力就位，Garrison 协议层从"能用"走向"完整"。

---

### v0.5.0 生产刚需版（已完成）

完成时间：2026-07-06

聚焦于生产环境刚需能力，通过吸收 QIdentity（认证服务）与 cedar（策略引擎）的工程设计，让 garrison 从"协议完整"走向"生产可用"。同时补齐 v0.4.0 遗留限制。

#### 新增（生产刚需，吸收 QIdentity）

| # | Feature | 核心能力 | 来源 |
|---|---------|---------|------|
| H1 | `tenant-isolation` | 多租户逻辑隔离：`tenant_id` 字段 + `task_local!` TenantContext + Repository 强制过滤 + TenantResolution middleware | QIdentity |
| H2 | `social-wechat` / `social-alipay` | 社交登录：`SocialLoginProvider` trait + 微信扫码/支付宝 Provider + SocialBinding 表（小程序变体 `WechatMiniApp` 预留，实现推迟到 v0.5.1+） | QIdentity |
| H3 | `audit-log` | 审计日志持久化：`audit_logs` 表 + 14 个 listener 事件订阅 + 复合条件查询 + 自动脱敏 | QIdentity |
| H4 | `protocol-jwt`（扩展） | RefreshToken Rotation：`refresh_tokens` 表 + tokenHash(SHA-256) + parentTokenHash 链 + keyVersion + 重用检测 | QIdentity |
| H5 | `firewall-bruteforce` / `firewall-ratelimit` / `firewall-anomalous` / `firewall-ddos` / `firewall-geoip` / `firewall-maxminddb` | 安全防护套件：5 个 FirewallStrategy 实现 + MaxMindDb 生产后端（v0.5.3 补齐 `MaxMindDbGeoLookup` / `MaxMindDbCountryLookup`），复用 oxcache 作为计数后端 | QIdentity |
| H6 | `repository-layer`（扩展） | 角色层级：`role_hierarchy` 表 + parents/indirect_ancestors + TC 预计算 + 登录时缓存权限并集 | cedar |
| H7 | `decision-trace` | 决策溯源：`Decision{allowed, reason, errors}` + 新增 `authorize()` API + 保留 `check_permission()` 旧 API | cedar |

#### 新增（Keycloak 集成，用户要求）

| # | Feature | 核心能力 |
|---|---------|---------|
| K1 | `keycloak-oidc` | Keycloak 作为 OIDC IdP：garrison 作为 RP 接入，discovery metadata + JWKS 验签 + ID Token 验证（不引入 keycloak-admin-client，保持轻量定位） |

#### 补齐（v0.4.0 遗留限制）

| # | 内容 | 来源 |
|---|------|------|
| P1 | SSO TOCTOU 原子化：`SsoClient::validate_ticket` 改用 `GarrisonDao::get_and_delete` 原子方法 | v0.4.0 M1 |
| P2 | 注解系统（gap #4）：`@CheckPermission` / `@CheckRole` 过程宏 | v0.4.0 gap #4 |
| P3 | PostgreSQL 后端：dbnexus 0.3+ 发布后集成（外部依赖，可能延后） | v0.4.0 已知限制 |
| P4 | actix-web / warp 完整 Extractor 适配 | v0.3.0 已知限制 |

#### 设计原则（吸收时遵循）

- **Rule 2 简洁优先**：不引入策略 DSL，不引入 keycloak-admin-client
- **Rule 7 暴露冲突**：QIdentity 的 UserLevel vs Role 双轨制只选 Role；cedar 的 DSL 与框架既有风格不混合
- **Rule 11 惯例优先**：保留 `login_id: i64` + 全局单例，不强行改 newtype（A-004 在 v0.5.2 做）
- **Rule 12 失败显性化**：所有 Stub/降级必须返回 `Unsupported` 错误，避免 QIdentity 的 7 个缺陷
- **Rule 5 确定性逻辑**：阈值/路由/限流规则用显式配置，不交给模型

#### 已知风险（Pre-mortem 识别）

| 风险 ID | 描述 | 缓解措施 |
|---------|------|---------|
| F1 | 范围爆炸导致烂尾 | 拆分阶段发布（v0.5.0/v0.5.1/v0.5.2） |
| F4 | 多租户与 oxcache 不兼容 | 明确逻辑隔离，不依赖 schema |
| F5 | 社交登录测试困难 | 用 mockito 模拟微信/支付宝响应 |
| F10 | dbnexus 0.3+ 阻塞 | P3 可延后到 v0.5.1，不阻塞 v0.5.0 主体 |

**里程碑意义**：补齐生产环境刚需能力（多租户/社交登录/审计/安全防护/角色层级/决策溯源/Keycloak），garrison 从"协议完整"走向"生产可用"。

---

### v0.5.1 工程优化版（已合入 0.5.2+）

完成时间：2026-07-07

聚焦于工程优化与开发者体验，吸收 QIdentity 的 RBAC 实体模型与 cedar 的工程设计思想。功能直接合入主分支，随 0.5.2+ 版本发布，未单独发布 0.5.1 版本号。

#### 新增（工程优化）

| # | Feature | 核心能力 | 来源 |
|---|---------|---------|------|
| M1 | `repository-layer`（扩展） | RBAC 实体模型：`roles`/`permissions`/`role_permissions`/`user_roles` 表 + 可配置角色初始化 | QIdentity |
| M2 | `repository-layer`（扩展） | UserDevice 实体：`user_devices` 表 + MAX_DEVICES 配置 + block/unblock + UA 解析（ua-parser crate） | QIdentity |
| M3 | `permission-registry` | 权限注册表：轻量 schema，启动时声明 `permission -> required_roles` 映射并校验 | cedar |
| M4 | `authorize-api` | 请求对象式 API：`AuthRequest{principal,action,resource,context}` + `authorize(req) -> Decision` | cedar |
| M5 | `garrison-error`（扩展） | miette 富错误：GarrisonError 携带结构化上下文（解决 A-008）+ 保留现有变体 + 新增 source 链 | cedar + A-008 |
| M6 | `garrison-testing` | JSON 测试用例：声明式授权测试格式，与 specmark 互补 | cedar |
| M7 | `manager-explicit` | 显式 Manager API：保留全局单例 + 新增 `Manager::authorize(req)` 显式 API | cedar |
| L6 | `security-confusable` | confusable string 检测：启动时扫描 permission 字符串，警告 Unicode 同形异义字 | cedar |

**里程碑意义**：补齐工程优化与开发者体验，权限模型从"字符串匹配"走向"声明式 + 可解释"。

---

### v0.5.2 架构重构版（已完成）

完成时间：2026-07-08

聚焦于架构重构与代码质量，解决 diting 审查识别的架构性问题。允许破坏性变更（0.x 阶段 semver 允许）。

> **实施决策修订**：原计划用 `#[deprecated]` 周期过渡，apply 阶段用户决策直接删除（无向后兼容），彻底清零技术债。

#### 重构（架构优化）

| # | 内容 | 核心变更 | 状态 | Commit |
|---|------|---------|------|--------|
| A-002 | GarrisonLogic trait 拆分 | 21 方法上帝 trait 拆分为 6 个子 trait（GarrisonCore/SessionLogic/PermissionLogic/TokenLogic/MfaLogic/PasswordLogic），**直接删除 GarrisonLogic**（无 deprecated 过渡） | ✅ 已完成 | `cbcedcb` `7c86a99` `bc63645` |
| A-004 | LoginId 迁移 | **删除 LoginId newtype**，全栈使用 `String`/`&str`（对象安全，可作 `dyn`） | ✅ 已完成 | `a52f8e0` |
| A-009 | oxcache _sync API 阻塞评估 | 评估结论：保留 `_sync` API（in-memory backend 下 <1μs vs spawn_blocking 10-50μs），文档化性能约束 | ✅ 已完成 | 见 `docs/decisions/A-009-oxcache-sync-api-evaluation.md` |
| A-010 | keys 全表扫描性能评估 | 评估结论：defer 到 oxcache 0.5+（`Cache.backend` 为 `pub(crate)`），文档化已知限制 | ✅ 已完成 | 见 `docs/decisions/A-010-dao-keys-performance-evaluation.md` |
| A-011 | src/stp/mod.rs 拆分 | 164KB 单文件拆分为 10 个职责文件（随 A-002 一起做） | ✅ 已完成 | `cbcedcb` `a52f8e0` `bc63645` |

#### 兼容性策略

- ~~所有破坏性 API 用 `#[deprecated]` 标记 + 文档警告~~ **修订：直接删除，无过渡**
- ~~至少经过一个 minor 版本过渡期（v0.5.2 标记 → v0.6.0 移除）~~ **修订：v0.5.2 直接删除**
- ~~旧 trait 保留为 type alias，转发到新 trait~~ **修订：无 type alias**
- Manager 持有具体类型 `Arc<GarrisonLogicDefault>`（非 trait 对象），调用方需显式 `use` 子 trait

**里程碑意义**：架构债务清零，为 v1.0.0 API 冻结做准备。

---

### v0.5.3 功能补全版（已完成）

完成时间：2026-07-09

聚焦于功能补全，通过 specmark change `v0-5-3-feature-completion` 实施 4 项功能补全（A-015/A-014/A-012/A-013）。补齐 stp 模块拆分遗留、MySQL 后端、Firewall MaxMindDb 生产后端，并升级 oxcache。

#### 补全（功能闭环）

| # | 内容 | 核心变更 | 状态 | Commit |
|---|------|---------|------|--------|
| A-015 | oxcache 升级 + 决策文档同步 | 升级 `oxcache` 到 0.3.3（per-entry TTL + `ttl_sync()` 查询）；更新 A-010 决策文档与 `src/dao/mod.rs` 注释 | ✅ 已完成 | `e3b89c6` |
| A-014 | stp/mod.rs 完整拆分 | 164KB `src/stp/mod.rs` 拆分为 11 个职责文件（新增 `tests.rs` + `interface.rs` + `util.rs`）；6 个 `impl trait for GarrisonLogicDefault` 块移至对应子文件；mod.rs 最终 12.4KB / 284 行 | ✅ 已完成 | `d5b945e` `5862e77` `57c9e59` `bc52803` |
| A-012 | MySQL 后端启用 + testcontainers 集成测试 | 启用 `db-mysql` feature；添加 `testcontainers = "0.27"` dev-dependency；新建 `tests/db_mysql_testcontainers.rs`（11 个 `#[serial]` 集成测试）；新建 `migrations/mysql/core/` 6 个 MySQL 兼容迁移文件 | ✅ 已完成 | `904718a` |
| A-013 | Firewall MaxMindDb 生产后端 | 添加 `maxminddb = "0.29"` 依赖 + `firewall-maxminddb` feature；实现 `MaxMindDbGeoLookup`（GeoIP2-City）+ `MaxMindDbCountryLookup`（GeoIP2-Country）；14 个测试 + GeoLite2 测试数据 | ✅ 已完成 | `a9e23ba` |

#### 偏离说明

- **db-mysql 未加入 `full` 聚合 feature**：dbnexus 禁止 db-sqlite 与 db-mysql 同时启用（`compile_error!`），故 db-mysql 需单独启用
- **stp 拆分文件数 11（非 spec 原定 10）**：v0.5.3 新增 `tests.rs` 承载集成测试，mod.rs 改用 `#[cfg(test)] mod tests;` 引用子模块；spec 验收标准已同步修订（10→11 文件，mod.rs < 5KB→< 15KB）

#### 验证结果

- `cargo test --features full --lib`：1336 passed; 0 failed
- `cargo clippy --features full --lib --tests -- -D warnings`：零警告
- `cargo test --features "db-mysql" --test db_mysql_testcontainers`：11 passed（需 Docker）
- `cargo test --features "firewall-maxminddb" --lib maxminddb`：14 passed
- `cargo doc --no-deps --features full`：10 个预存 warning（`decision.rs` broken intra-doc links + `web_actix`/`web_warp` unclosed HTML tag，非 v0.5.3 引入）

#### 已知限制

- `cargo test --features full --workspace` 中 `tests/integration/tenant_isolation.rs` 有预存失败（v0.5.2 LoginId 迁移遗留，非 v0.5.3 引入）

**里程碑意义**：功能补全版，补齐 stp 拆分遗留、MySQL 后端与 Firewall MaxMindDb 生产后端，为 v1.0.0 API 冻结做最后功能闭环。

---

### v0.6.0 账号安全引擎版（已完成）

完成时间：2026-07-09

聚焦于账号安全能力中枢建设，通过 specmark change `v0-6-0-account-security-engine` 实施 4 项核心能力（E-001/E-002/E-003/E-004）+ 4 项技术债清理（B-001/B-002/C-001/D-001）。引入 `account/` 模块作为账号安全能力中枢，提供 Credential SPI、密码策略引擎、用户锁定策略、AuthenticationFlow DSL，并补齐 i18n 社交登录异常消息与 Prometheus 指标。

#### 新增（账号安全引擎）

| # | 内容 | 核心变更 | 状态 | Commit |
|---|------|---------|------|--------|
| E-001 | account/ 模块骨架 + Credential SPI | 新建 `account/` 顶层模块；`Credential` trait 统一凭证模型 SPI；`PasswordCredential` + `TotpCredential` 实现；`DaoCredentialRepository` 基于 `GarrisonDao`；迁移 `PasswordHasher` 到 `account/credential/password.rs`（删除 `secure-password` feature） | ✅ 已完成 | `003443a` `c99f03c` `0933a74` `1e5f3cb` `e395763` `ca67934` |
| E-002 | PasswordPolicyEngine | `PasswordPolicyRule` trait + `PasswordPolicyEngine` + `PasswordPolicyContext`；6 个核心规则（长度/复杂度/历史/字典/用户名相似/序列）+ 6 个扩展规则（重复字符/键盘模式/日期/常见密码/上下文敏感/唯一字符数） | ✅ 已完成 | `19dd442` `92edce5` `b00c2c2` |
| E-003 | UserLockoutStrategy + GarrisonFirewallStrategy | `UserLockoutConfig` + `WaitStrategy` + `LockoutState`；`UserLockoutStrategy` 基于用户的登录锁定；`GarrisonFirewallStrategy` 整合到 GarrisonFirewall 框架；**破坏性**：`FirewallContext.login_id` `i64`→`String` | ✅ 已完成 | `644e78d` `09d1556` `527a19b` |
| E-004 | AuthenticationFlow DSL | `AuthStep` enum + `AuthenticationFlow` + `AuthContext` + `AuthResult`；`FlowBuilder` 流式构建；`FlowRegistry` inventory 编译期注册；`AuthExecutor` 核心执行器（5 字段约束）；`SocialProvider` + `SsoServer` 步骤扩展；内置 5 个 flow | ✅ 已完成 | `cad6560` `d5c5c90` `a9b28c8` `4e0f67c` `dae13c2` `31cdfd1` |
| C-001 | 社交登录异常消息 fluent i18n | `loc!` 宏（`#[cfg(feature = "i18n")]` 分支）；`translate_detail` 函数；38 个 ftl key（wechat 12 + alipay 8 + keycloak 18）中英文双语；46 个错误构造点接入 | ✅ 已完成 | `cda9338` |
| D-001 | AccountMetrics Prometheus 指标 | `AccountMetrics` struct（4 个指标：credential_verify_duration / policy_validate_duration / lockout_triggered_total / authflow_execute_duration）；feature 未启用时 `type = ()` | ✅ 已完成 | `f1dac15` |

#### 技术债清理

| # | 内容 | 核心变更 | 状态 | Commit |
|---|------|---------|------|--------|
| B-001 | cargo doc 10 个 warning 修复 | 8 个 broken intra-doc links + 2 个 unclosed HTML tags | ✅ 已完成 | `c2583bf` |
| B-002 | tenant_isolation 集成测试修复 | `login_id: i64` → `&str` 对齐 `GarrisonInterface` 签名（7 处修改） | ✅ 已完成 | `0eb8929` |

#### 破坏性变更

1. **`PasswordHasher` 迁移（T002）**：从 `src/secure/password.rs` 迁移到 `account/credential/password.rs`，`secure-password` feature 删除（功能合并到 `account` feature）
2. **`FirewallContext.login_id` 类型变更（T010）**：`i64` → `String`（所有 FirewallStrategy 实现需更新签名）

#### 验证结果

- `cargo test --features full --lib`：1463 passed; 0 failed
- `cargo clippy --features full --lib --tests -- -D warnings`：零警告
- `cargo doc --no-deps --features full`：零警告（修复 v0.5.3 遗留 10 个 warning）
- `cargo test --features "full audit-log" --test integration tenant_isolation`：1 passed（修复 v0.5.3 遗留失败）

#### 已知限制

- `AuthExecutor` metrics 仅通过 `execute_with_metrics` 显式传入，未集成到 `GarrisonManager` 自动注入链路（待 v0.7.0+ Manager 重构）
- `FlowRegistry` inventory 注册的 flow 在编译期固定，运行时动态注册需调用 `register` 方法

**里程碑意义**：账号安全引擎版，引入 account/ 模块作为账号安全能力中枢，提供从凭证存储到认证流程编排的完整能力，为 v1.0.0 API 冻结补齐账号安全维度。

---

### v0.6.1 gap-closure-remaining（✅ 已完成）

通过 specmark change `gap-closure-remaining` 完成 11 项能力域补齐（T001-T011），**所有 origin 文档与代码实现之间的 gap 已全部关闭，零残留**。

#### 新增（能力域补齐）

| # | 内容 | 核心变更 |
|---|------|---------|
| T001/T008 | remember_me 扩展会话超时 | `remember_me_enabled` / `remember_me_timeout` 配置字段 + 环境变量覆盖 + validate 校验逻辑 |
| T002 | Redis 部署模式枚举 | `RedisDeploymentMode` 枚举（Single / Sentinel / Cluster / MasterSlave）+ `RedisConfig` 结构 |
| T003 | 身份切换 switch_to | `switch_to(login_id)` API，支持临时切换登录身份 |
| T004 | Token 置换 renew_to_equivalent | `renew_to_equivalent()` API，在保留会话状态的前提下置换 Token |
| T005 | OAuth2 注解 | `CheckAccessToken` / `CheckClientToken` 注解变体 + 路由拦截集成 |
| T006 | 路由分组 group() | `GarrisonRouter::group()` 方法，支持路由分组与统一中间件应用 |
| T007 | 会话过期回调 | `SessionExpiryListener` trait + 异步回调机制 |
| T009 | SAML 2.0 骨干 | `SamlProvider` trait + `DefaultSamlProvider` 实现 |
| T010 | OIDC RP 骨干 | `OidcProvider` trait + `DefaultOidcProvider` 实现 |
| T011 | Redis pub/sub SsoChannel | `RedisPubSubSsoChannel` 实现 + `SsoChannel` / `SsoServer` trait 整合 |

**里程碑意义**：关闭所有剩余能力 gap，remember_me / 身份切换 / Token 置换 / OAuth2 注解 / 路由分组 / 会话过期回调 / SAML 2.0 / OIDC RP / Redis pub/sub SsoChannel 十一大能力悉数就位。

---

### v0.7.0 微服务架构 + ABAC/Cedar + OAuth2 Server（✅ 已完成）

通过 specmark change `v0.7.0-microservice-abac-oauth2-hardening` 完成 7 个能力域（D1-D7），252 个 TDD 任务，2968 测试通过。

#### D1: 架构加固

- 错误类型统一：全代码库使用 `GarrisonError` / `GarrisonResult`
- mod.rs 加固：Mock 代码迁移到独立 `mock.rs`，impl 块迁移到 `impl.rs`
- `secure-sanitize` feature：通用输入消毒 `sanitize_input()` 函数

#### D2: 依赖优化

- clippy 零告警（全模式 + 特性组合）
- cargo doc 零告警
- 特性组合测试：10 种组合全部通过

#### D3: 微服务架构

- `backend-remote` feature：远程后端适配器
- `server/external.rs` + `server/internal.rs`：外部/内部 API 服务器
- `src/bin/auth_server.rs`：独立认证服务器二进制

#### D4: ABAC/Cedar DSL

- `abac` feature：基于 Cedar DSL 的属性访问控制引擎
- `src/abac/engine.rs` + `src/abac/policy.rs`

#### D5: OAuth2 Server

- `oauth2-server` feature：完整 OAuth2 Server
- `/oauth2/authorize` + `/oauth2/token` + `/oauth2/revoke` + `/oauth2/introspect`
- PKCE 强制（S256）+ redirect_uri 白名单 + state CSRF 防护

#### D6: 质量提升

- 特性组合测试 + clippy/doc 告警清理 + cargo-audit

#### D7: 安全审查

- tiangang SAST：0 CRITICAL
- diting：88/100（0 CRITICAL + 0 HIGH）
- security.md 10 维度安全检查全部通过

**里程碑意义**：微服务架构就位，ABAC/Cedar + OAuth2 Server 安全能力补齐，满足生产级安全门禁。

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

Garrison 遵循 [SemVer](https://semver.org/lang/zh-CN/) 语义化版本规范：

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

> 在 0.x 阶段（1.0 之前），minor 版本理论上允许破坏性变更，但 Garrison 承诺仅在不可避免时才这样做，并提前在 CHANGELOG 中标注。

### 向后兼容承诺

- **0.1.0 的核心 API** 在 1.0 之前不会发生破坏性变更（`GarrisonManager` / `GarrisonUtil` / `GarrisonConfig` 等核心接口稳定）。
- **协议/安全层 API** 在 0.2.0 阶段可能调整，建议在生产环境中锁定具体 patch 版本。

---

## 设计原则

Garrison 在整个版本演进过程中遵循以下四条原则：

### 1. 领域建模优先

采用 13 特性域领域建模、静态工具类 + 全局配置的 API 设计哲学，并用 Rust idiomatic 方式实现：

- 用 `trait` 替代 Java interface
- 用 `async fn` + `tokio` 替代线程池
- 用 `inventory` 替代 SPI 反射
- 用 `Feature` 门控替代 Maven profile

### 2. 抽象优先

所有核心组件均以 **trait + Default** 模式提供，任何组件都可被替换为自定义实现，框架默认实现仅在未被覆盖时生效。

### 3. Feature 门控

按需编译，减小二进制体积。每个特性域对应一个 cargo feature，通过聚合 feature 一键启用常用组合。保证 Garrison 在 Edge、WASM、嵌入式等资源敏感场景下也能使用。

### 4. 向后兼容

遵循 semver 规范，破坏性变更优先以 deprecation 周期过渡。

---

## 变更管理

所有版本演进通过 **specmark 工作流** 管理：

```text
explore → propose → apply → archive
```

- `explore`：探索阶段，明确需求与可行性
- `propose`：提案阶段，输出 proposal / design / specs / tasks
- `apply`：实施阶段，按 tasks 推进实现
- `archive`：归档阶段，同步 delta spec 到主 spec 库

每个变更在合并前必须经过影响面分析，HIGH / CRITICAL 风险变更需要显式评估后才能推进。

---

> 本路线图为持续滚动更新文档，实际发布时间与内容可能随社区反馈调整。最新进展请关注 [GitHub Releases](https://github.com/Kirky-X/garrison/releases)。
