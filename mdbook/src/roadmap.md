# 版本路线图

本页描述 Bulwark（Rust 认证授权框架，借鉴 Sa-Token v1.45.0）的版本演进规划。

> 变更管理通过 OpenSpec 工作流进行：proposal → design → tasks → archive。

## 版本总览

| 版本 | 状态 | 计划完成 | 主要内容 |
|:---|:---|:---|:---|
| 0.1.0 | ✅ 已完成 | 2026-06-30 | 核心基础设施 |
| 0.2.0 | ✅ 已完成 | 2026-07-01 | 协议与安全层 |
| 0.2.1 | ✅ 已完成 | 2026-07-01 | auto-wire 修复 + 协议边界测试 + examples 工程化 |
| 0.3.0 | 📋 待规划 | 2026 Q4 | 生态集成与可观测性 |
| 0.4.0 | 📋 待规划 | 2027 Q1 | PostgreSQL/MySQL + RBAC 层级 + ABAC + 多租户 |
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

**里程碑**：覆盖 Sa-Token 13 个特性域的大部分协议与安全子域，从"可用"走向"完整"。

## v0.2.1 稳定性优化（已完成）

- ✅ auto-wire gap 修复：`BulwarkManager::init` 自动注入 PluginManager / ListenerManager / AuthLogic / PermissionChecker
- ✅ `BulwarkLogicDefault` 新增 4 个 builder 方法
- ✅ 协议层边界场景测试（6 模块 20 测试）
- ✅ examples 工程化重组（workspace member + 独立测试）

## v0.3.0 生态集成与可观测性（待规划）

- 📋 Prometheus 指标 + 结构化 JSON 日志 + OpenTelemetry 分布式追踪
- 📋 gRPC 鉴权拦截器（`tonic::Interceptor`）
- 📋 异常消息 i18n（fluent-rs 中英文切换）
- 📋 防火墙安全钩子（5 个登录流程检查点）
- 📋 actix-web / warp 适配完善

**里程碑**：完成生态集成与生产级可观测性，覆盖企业级部署需求。

## v0.4.0 高级特性（待规划）

- 📋 PostgreSQL / MySQL 后端（待 dbnexus 0.3+）
- 📋 RBAC 层级角色完善
- 📋 ABAC 属性访问控制
- 📋 多租户支持
- 📋 Refresh Token 自动轮换
- 📋 审计日志持久化

**里程碑**：补充高级安全特性，对标 Sa-Token 的高级场景能力。

## v1.0.0 稳定版（待规划）

- 📋 API 稳定性承诺
- 📋 完整文档与示例
- 📋 性能基准与优化
- 📋 安全审计

## 设计原则

- **库优先**：Bulwark 是库而非框架，业务方保持控制权
- **feature 门控**：核心 always on，协议/安全/适配按需启用
- **trait 抽象**：双抽象层 + `BulwarkDao` 屏蔽后端差异
- **编译期注册**：`inventory` 实现 zero-cost 插件与 factory 注册
- **向后兼容**：新增能力通过 feature 开关，未启用时 no-op

> 完整路线图详见 [../../docs/ROADMAP.md](../../docs/ROADMAP.md)。
