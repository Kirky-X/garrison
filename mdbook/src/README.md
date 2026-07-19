<!-- markdownlint-disable MD041 -->
<p align="center">
  <img src="./assets/logo.png" alt="Bulwark Logo" width="160" />
</p>

# Bulwark 简介

Bulwark 是一个面向 Rust 生态的身份认证鉴权框架，目标是提供开箱即用的认证、授权、会话与协议层能力。

- 仓库：<https://github.com/Kirky-X/bulwark>
- License：Apache-2.0
- 当前版本：0.7.0（2026-07-13 发布）
- MSRV：Rust 1.85+（部分依赖如 `inventory 0.3` 要求 edition 2024）

## 框架定位

Bulwark 是一个 **库（crate）**，不直接产出可执行二进制。业务方将其作为依赖集成到 axum / actix-web / warp 服务中，通过 `BulwarkManager::init()` 注入依赖即可获得完整的认证鉴权能力。核心模块（core / stp / config / dao / session 等）总是编译，协议层与安全模块通过 Cargo feature 按需启用。

## 核心特性（13 个功能域）

采用 13 个特性域设计：

1. **登录认证** — 基于 Token 的会话管理
2. **权限认证** — RBAC 权限模型
3. **Session 会话** — 会话生命周期管理
4. **OAuth2** — 第三方授权（Authorization Code / Client Credentials / Password）
5. **单点登录 (SSO)** — ticket 一次性 60s 短时票据
6. **JWT** — HS256 / HS512 签发与验证
7. **微服务网关鉴权** — HMAC-SHA256 签名 + 防重放
8. **API 接口鉴权** — API Key 生成 / 校验 / 吊销 / 轮换
9. **临时凭证** — TempCredential issue / consume / revoke
10. **TOTP 动态验证码** — RFC 6238，±1 时间窗口
11. **Basic 认证** — HTTP Basic Auth
12. **Digest 认证** — HTTP Digest Auth
13. **路由拦截鉴权** — 多框架适配 + 编译期插件注册

## 双抽象层架构

Bulwark 采用 **双抽象层 + 全局单例** 的架构：

- **dbnexus**：数据库抽象层（SQLite / PostgreSQL / MySQL），由 `BulwarkDao` trait 屏蔽后端差异
- **oxcache**：缓存抽象层（L1 内存 + L2 redis），承载 Token-Session 与 Account-Session 双向映射
- **BulwarkManager**：全局单例，持有 `Arc<BulwarkLogicDefault>`（基于 `parking_lot::RwLock`，支持覆盖式 `init`）；自 0.5.2 起 `BulwarkLogic` 上帝 trait 已拆分为 6 个职责子 trait（BulwarkCore / SessionLogic / PermissionLogic / TokenLogic / MfaLogic / PasswordLogic），Manager 持有具体类型而非 trait 对象
- **inventory 编译期注册**：`PermissionRegistration`（权限注册表）/ `StrategyRegistration`（Firewall 策略）等通过 `inventory::submit!` 注册，运行时由 `inventory::iter` 收集

逻辑层分为三层：`BulwarkLogicDefault`（默认实现，组合 6 个子 trait）/ `BulwarkInterface`（业务方实现的回调）/ `BulwarkUtil`（面向使用者的静态 API）。

## 版本演进

Bulwark 自 0.1.0 起逐步演进至当前 0.7.0，主要能力域落地节奏如下：

- **0.2.0**：协议层（JWT / OAuth2 / SSO / Sign / APIKey / Temp）与安全模块（TOTP / HMAC / HTTP Basic / HTTP Digest）
- **0.3.0**：可观测性（Prometheus 指标 + 结构化 JSON 日志 + OpenTelemetry OTLP）、gRPC 鉴权拦截器（`BulwarkGrpcInterceptor` 实现 `tonic::Interceptor`）、异常消息 i18n（fluent-rs 中英文切换）、防火墙安全钩子（`BulwarkFirewallCheckHook` 5 个登录流程检查点）、多框架适配（`web-actix` / `web-warp` feature 与 axum 对齐）
- **0.4.0 / 0.4.2**：协议层 gap 补齐（OIDC / ScopeHandler / SsoServer / AloneCache / ParameterQuery / token-introspection / apikey-namespace 等）
- **0.5.0**：生产刚需版（多租户隔离 / 社交登录 / 审计日志 / Token Rotation / 安全防护套件 / 角色层级 / 决策溯源 / Keycloak OIDC RP / PostgreSQL 后端 / actix+warp 完整适配）
- **0.5.1~0.5.3**：RBAC 实体 / UserDevice / 权限注册表 / 请求对象 API / miette 富错误 / 显式 Manager API / BulwarkLogic trait 拆分 / LoginId newtype 删除 / oxcache 升级 / MySQL 后端 / Firewall MaxMindDb 生产后端
- **0.6.0 / 0.6.1**：账号安全引擎版（account/ 模块 + Credential SPI + PasswordPolicyEngine + UserLockoutStrategy + AuthenticationFlow DSL + i18n 社交登录异常 + AccountMetrics）+ gap-closure-remaining 11 项能力（remember_me / Redis 部署模式 / switch_to / Token 置换 / OAuth2 注解 / group() / SessionExpiryListener / SAML 2.0 / OIDC RP / Redis pub/sub SsoChannel）
- **0.6.7**：安全与性能增强（forbid 优先语义 / WAF 级防火墙 / 三层缓存架构 / SMS 验证码渐进式限速 / AnomalousLoginDetector 双引擎）
- **0.7.0**：微服务架构（`backend-remote` + Auth Server + `auth_server` 二进制）+ ABAC/Cedar DSL 策略引擎 + OAuth2 Server（authorize / token / revoke / introspect + PKCE）+ 依赖优化与架构加固

详细演进历史与里程碑意义见 [版本路线图](./roadmap.md)。

## 下一步

- [入门指南](./getting-started.md)
- [配置参考](./configuration.md)
- [整体架构](./architecture.md)
