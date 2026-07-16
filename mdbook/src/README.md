# Bulwark 简介

Bulwark 是一个面向 Rust 生态的身份认证鉴权框架，目标是提供开箱即用的认证、授权、会话与协议层能力。

- 仓库：<https://github.com/Kirky-X/bulwark>
- License：Apache-2.0
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
- **oxcache**：缓存抽象层（L1 moka + L2 redis），承载 Token-Session 与 Account-Session 双向映射
- **BulwarkManager**：全局单例，持有 `Arc<dyn BulwarkLogic>`（基于 `parking_lot::RwLock`，支持覆盖式 `init`）
- **inventory 编译期注册**：`BulwarkLogicFactory` 通过 `inventory::submit!` 注册，运行时由 `inventory::iter` 选取

逻辑层分为三层：`BulwarkLogic`（顶层抽象）/ `BulwarkInterface`（业务方实现的回调）/ `BulwarkUtil`（面向使用者的静态 API）。

## 0.3.0 新增能力

0.3.0 在 0.2.x 基础上扩展了生态与可观测性：

- **可观测性**：Prometheus 指标 + 结构化 JSON 日志 + OpenTelemetry 分布式追踪（OTLP gRPC 导出）
- **gRPC 鉴权拦截器**：`BulwarkGrpcInterceptor` 实现 `tonic::Interceptor`，从 metadata 提取 Bearer token
- **异常消息 i18n**：基于 fluent-rs 的中英文切换，`set_locale(BulwarkLocale::En)` 即时生效
- **防火墙安全钩子**：`BulwarkFirewallCheckHook` 提供 5 个登录流程检查点，返回 `Err` 阻断登录
- **多框架适配**：新增 actix-web 与 warp 适配（`web-actix` / `web-warp` feature），与 axum 对齐

## 下一步

- [入门指南](./getting-started.md)
- [配置参考](./configuration.md)
- [整体架构](./architecture.md)
