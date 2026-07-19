# 版本路线图

本页描述 Bulwark（Rust 认证授权框架）的版本演进规划。

> 变更管理通过 specmark 工作流进行：explore → propose → apply → archive。
> 完整路线图详见 [../../docs/ROADMAP.md](../../docs/ROADMAP.md)。

## 版本总览

| 版本 | 状态 | 完成时间 | 主要内容 |
|:---|:---|:---|:---|
| 0.1.0 | ✅ 已完成 | 2026-06-30 | 核心基础设施 |
| 0.2.0 | ✅ 已完成 | 2026-07-01 | 协议与安全层 |
| 0.2.1 | ✅ 已完成 | 2026-07-01 | auto-wire 修复 + 协议边界测试 + examples 工程化 |
| 0.3.0 | ✅ 已完成 | 2026-07-02 | 生态完善与可观测（OTLP / gRPC / i18n / metrics） |
| 0.4.0 | ✅ 已完成 | 2026-07-02 | 0.2.0 协议层遗留 gap 补齐（OIDC / ScopeHandler / SsoServer / AloneCache / ParameterQuery） |
| 0.4.2 | ✅ 已完成 | 2026-07-05 | gap closure（dao 扩展 / strategy-registry / jwt-modes / oauth-2-1 / token-introspection / apikey-namespace 等 18 项） |
| 0.5.0 | ✅ 已完成 | 2026-07-06 | 生产刚需版（多租户 / 社交登录 / 审计日志 / Token Rotation / 安全防护 / 角色层级 / 决策溯源 / Keycloak OIDC RP / PostgreSQL / actix+warp 完整适配） |
| 0.5.1 | ✅ 已合入 | 2026-07-07 | 工程优化版（RBAC 实体 / UserDevice / 权限注册表 / 请求对象 API / miette 富错误 / 显式 Manager API / confusable string 检测，功能直接合入 0.5.2+ 发布） |
| 0.5.2 | ✅ 已完成 | 2026-07-08 | 架构重构版（BulwarkLogic trait 拆分 / LoginId newtype 删除 / oxcache _sync 评估 / keys 性能 / stp 模块拆分） |
| 0.5.3 | ✅ 已完成 | 2026-07-09 | 功能补全版（oxcache 升级 / stp 完整拆分 / MySQL 后端 / Firewall MaxMindDb 生产后端） |
| 0.6.0 | ✅ 已完成 | 2026-07-09 | 账号安全引擎版（account/ 模块 + Credential SPI + PasswordPolicyEngine + UserLockoutStrategy + AuthenticationFlow DSL + i18n 社交登录异常 + AccountMetrics） |
| 0.6.1 | ✅ 已完成 | 2026-07-10 | gap-closure-remaining（remember_me / Redis 部署模式 / switch_to / Token 置换 / OAuth2 注解 / group() / SessionExpiryListener / SAML 2.0 / OIDC RP / Redis pub/sub SsoChannel — 11 项全部补齐） |
| 0.6.7 | ✅ 已完成 | 2026-07-13 | 安全与性能增强（forbid 优先语义 / WAF 级防火墙 / 三层缓存架构 / SMS 验证码渐进式限速 / AnomalousLoginDetector 双引擎） |
| 0.7.0 | ✅ 已完成 | 2026-07-13 | 微服务架构 + ABAC/Cedar + OAuth2 Server + 依赖优化 + 架构加固（7 个能力域 / 252 TDD 任务 / 2968 测试通过） |
| 1.0.0 | 📋 待规划 | 2027 Q2 | 稳定版 |

## v0.1.0 核心基础设施（已完成）

- ✅ 错误类型体系（`BulwarkError`）
- ✅ 配置系统（三级配置源 + `tokio::sync::watch` 热更新）
- ✅ 上下文抽象（`BulwarkContext` + axum adapter + task_local）
- ✅ DAO 抽象（`BulwarkDao` trait + oxcache + dbnexus）
- ✅ 双模会话管理（Account-Session + Token-Session）
- ✅ 核心 API（`BulwarkLogic` + `BulwarkUtil`）
- ✅ 权限校验策略（`BulwarkPermissionStrategy`）
- ✅ 全局管理器（`BulwarkManager` + inventory 编译期注册）
- ✅ axum 集成（extractor + `BulwarkRouter` + Interceptor）

**里程碑**：完成"能跑起来"的最小闭环，基于 UUID/Random64 Token 的登录、会话、权限校验与 axum 集成。

## v0.2.0 协议与安全层（已完成）

- ✅ 协议层：JWT / OAuth2 / SSO / Sign / APIKey / Temp
- ✅ 安全模块：TOTP（RFC 6238）/ HMAC 签名 / HTTP Basic / HTTP Digest
- ✅ 核心扩展：`Token` trait + `AuthLogic` + `PermissionChecker` + `BulwarkPlugin` + `BulwarkListener`
- ✅ 新增配置字段：`jwt_algorithm` / `sign_window_seconds` / `sso_ticket_ttl_seconds`

**里程碑**：覆盖 13 个特性域的大部分协议与安全子域，从"可用"走向"完整"。

## v0.2.1 稳定性优化（已完成）

- ✅ auto-wire gap 修复：`BulwarkManager::init` 自动注入 PluginManager / ListenerManager / AuthLogic / PermissionChecker
- ✅ `BulwarkLogicDefault` 新增 4 个 builder 方法
- ✅ 协议层边界场景测试（6 模块 20 测试）
- ✅ examples 工程化重组（workspace member + 独立测试）

## v0.3.0 生态完善与可观测（已完成）

- ✅ OpenTelemetry OTLP 分布式追踪（`observability-otlp` feature，OTLP gRPC 导出）
- ✅ gRPC 鉴权拦截器（`grpc` feature，`tonic::Interceptor` 实现）
- ✅ 异常消息国际化（`i18n` feature，fluent-rs 中英文切换）
- ✅ Prometheus 指标（`metrics-prometheus` feature）

**已知限制**：PostgreSQL / MySQL 后端仍待 `dbnexus` 0.3+ 提供（推迟至 0.5.0+）；actix-web / warp 适配仅提供最小骨架，未做完整 extractor 适配。

## v0.4.0 / v0.4.2 协议层 gap 补齐（已完成）

聚焦于 0.2.0 协议层遗留 gap 的补齐：

- ✅ OIDC（`protocol-oidc`）：`OidcHandler` 签发 / 验证 / discovery
- ✅ Scope Handler（`oauth2-scope-handler`）：`ScopeHandler` trait + `ScopeRegistry`
- ✅ SSO Server（`protocol-sso-server`）：`SsoServer` trait + `CenterIdConverter` + `SsoChannel`
- ✅ AloneCache（`alone-cache`）：多 Redis 实例隔离
- ✅ ParameterQuery（`parameter-query`）：参数化查询机制
- ✅ 0.4.2 gap closure：dao 扩展 / strategy-registry / jwt-modes / oauth-2-1 / token-introspection / apikey-namespace / sso-toctou / password-login / secure-password / login-id-type / login-type-multi-account / session-kickout-device / listener-events-extend / repository-layer / web-context-adapters / annotation-macros 等 18 项

## v0.5.0 生产刚需版（已完成）

- ✅ 多租户隔离（`tenant-isolation`）：`tenant_id` 字段 + `task_local!` TenantContext + Repository 强制过滤
- ✅ 社交登录（`social-wechat` / `social-alipay`）：`SocialLoginProvider` trait + 微信扫码 / 支付宝 Provider
- ✅ 审计日志（`audit-log`）：`audit_logs` 表 + 14 个 listener 事件订阅 + 复合条件查询 + 自动脱敏
- ✅ Token Rotation（`protocol-jwt` 扩展）：`refresh_tokens` 表 + tokenHash + parentTokenHash 链 + 重用检测
- ✅ 安全防护套件：5 个 FirewallStrategy 实现 + MaxMindDb 生产后端
- ✅ 角色层级：`role_hierarchy` 表 + parents/indirect_ancestors + TC 预计算
- ✅ 决策溯源（`decision-trace`）：`Decision{allowed, reason, errors}` + 新增 `authorize()` API
- ✅ Keycloak OIDC RP（`keycloak-oidc`）：discovery + JWKS 验签 + ID Token 验证
- ✅ PostgreSQL 后端：dbnexus 0.3+ 集成
- ✅ actix-web / warp 完整 Extractor 适配
- ✅ SSO TOCTU 原子化：`validate_ticket` 改用 `BulwarkDao::get_and_delete`
- ✅ 注解系统：`@CheckPermission` / `@CheckRole` 过程宏

**里程碑**：从"协议完整"走向"生产可用"。

## v0.5.1~v0.5.3 工程优化与功能补全（已完成）

- ✅ **0.5.1**：RBAC 实体 / UserDevice / 权限注册表 / 请求对象 API / miette 富错误 / JSON 测试 / 显式 Manager API / confusable string 检测（合入 0.5.2+ 发布）
- ✅ **0.5.2**：`BulwarkLogic` 上帝 trait 拆分为 6 个子 trait（BulwarkCore / SessionLogic / PermissionLogic / TokenLogic / MfaLogic / PasswordLogic），删除 `BulwarkLogic` 与 `LoginId` newtype，stp 模块拆分
- ✅ **0.5.3**：oxcache 升级到 0.3.3 + stp 完整拆分 + MySQL 后端 + Firewall MaxMindDb 生产后端

## v0.6.0 / v0.6.1 账号安全引擎（已完成）

- ✅ **0.6.0**：account/ 模块 + Credential SPI（`Credential` trait + `PasswordCredential` + `TotpCredential`）+ PasswordPolicyEngine（12+ 规则）+ UserLockoutStrategy + AuthenticationFlow DSL（FlowBuilder + FlowRegistry + AuthExecutor）+ i18n 社交登录异常（38 个 ftl key）+ AccountMetrics Prometheus 指标
- ✅ **0.6.1**：gap-closure-remaining 11 项 — remember_me / Redis 部署模式 / switch_to / renew_to_equivalent / OAuth2 注解 / group() / SessionExpiryListener / SAML 2.0 骨干 / OIDC RP 骨干 / Redis pub/sub SsoChannel

## v0.6.7 安全与性能增强（已完成）

- ✅ forbid 优先语义（`safe-defaults`）：`Forbid` 决策不可被 Allow 覆盖
- ✅ WAF 级防火墙（`firewall-waf`）：策略层 WAF Hook 链 + axum middleware 适配器
- ✅ 三层缓存架构（`three-tier-cache`）：L1 oxcache 内存 + L2 DAO 持久化 + L3 interface 回调
- ✅ SMS 验证码渐进式限速（`sms-rate-limit`）：双窗口限速 + 异常发送检测
- ✅ AnomalousLoginDetector 双引擎：burst / geo_jump / device_mutation 定时分析

## v0.7.0 微服务架构 + ABAC/Cedar + OAuth2 Server（已完成）

通过 specmark change `v0.7.0-microservice-abac-oauth2-hardening` 完成 7 个能力域，252 个 TDD 任务，2968 测试通过：

- ✅ **D1 架构加固**：错误类型统一 + mod.rs 加固（Mock 迁移 + impl 块拆分）+ `secure-sanitize` 输入消毒
- ✅ **D2 依赖优化**：clippy / cargo doc 零告警 + 10 种特性组合测试通过
- ✅ **D3 微服务架构**：`backend-remote` 远程后端 + `server/external.rs` + `server/internal.rs` + `src/bin/auth_server.rs` 独立认证服务器
- ✅ **D4 ABAC/Cedar DSL**（`abac` feature）：基于 Cedar 的属性访问控制引擎 + `src/abac/engine.rs` + `src/abac/policy.rs`
- ✅ **D5 OAuth2 Server**（`oauth2-server` feature）：4 端点（authorize / token / revoke / introspect）+ 4 种 grant type + PKCE 强制（S256）+ redirect_uri 白名单 + state CSRF 防护
- ✅ **D6 质量提升**：特性组合测试 + clippy/doc 告警清理 + cargo-audit
- ✅ **D7 安全审查**：tiangang SAST 0 CRITICAL + diting 88/100（0 CRITICAL + 0 HIGH）+ security.md 10 维度安全检查全部通过

**里程碑**：微服务架构就位，ABAC/Cedar + OAuth2 Server 安全能力补齐，满足生产级安全门禁。

## v1.0.0 稳定版（待规划）

- 📋 API 冻结（semver 稳定承诺）
- 📋 性能基准测试
- 📋 生产案例文档
- 📋 安全审计

## 设计原则

- **库优先**：Bulwark 是库而非框架，业务方保持控制权
- **feature 门控**：核心 always on，协议/安全/适配按需启用
- **trait 抽象**：双抽象层 + `BulwarkDao` 屏蔽后端差异
- **编译期注册**：`inventory` 实现 zero-cost 插件与 factory 注册
- **向后兼容**：新增能力通过 feature 开关，未启用时 no-op

> 完整路线图详见 [../../docs/ROADMAP.md](../../docs/ROADMAP.md)。
