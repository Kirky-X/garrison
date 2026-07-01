# Changelog

本文件记录 Bulwark 项目的所有显著变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [0.2.1] - 2026-07-01

### 概述

Bulwark 0.2.1 是 0.2.0 的 PATCH 版本，聚焦于：auto-wire gap 修复、协议层边界场景测试补全、
examples 工程化重组与文档补充。本版本不引入新协议或新功能特性，仅包含 bug 修复与稳定性优化。

### 修复

- **auto-wire gap（TG4+TG5）**：修复 `BulwarkManager::init` 未注入 PluginManager /
  ListenerManager / AuthLogic / PermissionChecker 的 gap。`BulwarkLogicDefault` 新增 4 个可选字段
  与 builder 方法，`login` / `logout` / `kickout` / `login_by_token` / `refresh_token` 现自动触发
  plugin 钩子与 listener 事件。`BulwarkLogicFactoryFn` 签名扩展为接收 `&BulwarkLogicFactoryContext`
  以支持 factory 注入 manager。

### 新增（测试与工程化）

- **协议层边界场景测试（TG6-TG11）**：新增 6 个测试文件共 20 个边界场景测试
  - OAuth2: refresh_token 失效 / scope 边界 / code 重放 / expires_in=0
  - SSO: ticket 格式非法 / centerId 映射缺失 / 并发校验仅一次成功
  - JWT: none 算法注入拒绝 / iat 未来时间容忍 / refresh 过期 / 空 claims
  - Sign: nonce 重放拒绝 / timestamp 漂移超出窗口 / 缺失必填参数
  - APIKey: namespace 隔离 / 过期校验 / 格式非法
  - Temp: 一次性凭证失效 / 过期校验 / scope 越权
- **auto-wire 集成测试（TG5.8）**：新增 3 个集成测试验证 `BulwarkUtil::login/logout` 自动触发
  plugin/listener
- **examples 工程化重组（TG2-TG3）**：examples 从零散 `.rs` 文件重组为 workspace member
  （`bulwark-examples` crate，`publish = false`），每个 bin 配套独立 `tests/<name>.rs` 测试文件

### 变更

- `BulwarkLogicFactoryFn` 类型签名扩展（新增第 4 个参数 `&BulwarkLogicFactoryContext`）
  — 0.x.x 阶段可接受的不兼容变更，自定义 factory 需适配新签名
- `BulwarkLogicDefault` 新增 4 个字段（`plugin_manager` / `listener_manager` / `auth_logic` /
  `permission_checker`），均通过 builder 方法注入，向后兼容（未注入时行为同 0.2.0）

### 文档

- 修复 `examples/src/context_request.rs` 模块 doc 中未闭合 HTML 标签 `Request<Body>`
- `cargo doc --no-deps --features full --workspace` 零警告

### 测试

- 693 tests passing（+30 vs 0.2.0 的 663）
- clippy 零警告（`-D warnings`）
- 90%+ 覆盖率（保持 0.2.0 水平）

## [0.2.0] - 2026-07-01

### 概述

Bulwark 0.2.0 在 0.1.0 核心基础设施上补全了 13 个占位特性域，覆盖 Sa-Token v1.45.0 的全部能力。
本版本新增 17 个 capability，修改 3 个 capability，新增 200+ 单元测试 + 32 个集成测试，
覆盖率 92.56%。所有协议层与安全模块均通过 spec-driven TDD 工作流实现。

### 新增（17 个 capability）

#### 协议层模块（6 个）

- **protocol-jwt**：JWT 签发与验证（HS256/HS512，自定义 claims，过期校验），
  `JwtHandler` 提供 `sign(login_id, timeout)` / `verify(token)` / `refresh(token)`
- **protocol-oauth2**：OAuth2 授权码模式（Authorization Code）、客户端凭证模式（Client Credentials）、
  密码模式（Password），`OAuth2Client` 提供 `exchange_code` / `get_client_credentials_token` /
  `get_password_token` / `get_auth_url`
- **protocol-sso**：SSO 单点登录 ticket 模型（签发、校验、销毁），64 字符随机 ticket，
  60 秒 TTL，一次性使用，`SsoClient` 跨子系统通过共享 `BulwarkDao` 实现 SSO
- **protocol-sign**：API 签名认证（HMAC-SHA256 + nonce + timestamp 防重放）
- **protocol-apikey**：API Key 认证（生成/校验/吊销/轮换）
- **protocol-temp**：临时凭证（短期 token，自动过期，issue/get/revoke/consume）

#### 安全模块（4 个）

- **secure-totp**：TOTP 动态验证码（RFC 6238，30 秒窗口，6 位数字），
  `TotpHandler` 提供 `generate(secret)` / `validate(secret, code)`
- **secure-sign**：安全签名工具（HMAC-SHA256/SHA512，Base64 编码，MD5 工具）
- **secure-httpbasic**：HTTP Basic 认证（RFC 7617，Base64 编解码）
- **secure-httpdigest**：HTTP Digest 认证（RFC 7616，MD5/SHA256）

#### 核心模块（3 个）

- **core-auth**：`AuthLogic` trait + `DefaultAuthLogic`，整合 login/verify/refresh
- **core-permission**：`PermissionChecker` trait + `DefaultPermissionChecker`，支持 RBAC/ABAC
- **core-token**：`Token` trait + `TokenStyleFactory`，支持 uuid/random_64/simple/jwt 风格

#### 辅助模块（4 个）

- **exception-system**：`BulwarkException` 异常类型体系（含 login_type、token_value 等上下文）
- **json-template**：`BulwarkJsonTemplate` / `BulwarkSerializer` trait（JSON 模板与序列化抽象）
- **plugin-system**：`BulwarkPlugin` trait + `BulwarkPluginManager` + inventory 编译期注册，
  生命周期钩子（on_login / on_logout / on_permission_check），插件失败仅 tracing::warn!
- **listener-system**：`BulwarkListener` trait + `BulwarkListenerManager` + 事件广播，
  6 个事件变体（Login / Logout / Kickout / PermissionDenied / RoleDenied / TokenExpired）

### 修改（3 个 capability）

- **core-auth-api**：扩展 `BulwarkLogic` trait，新增 `login_by_token` / `verify_token` / `refresh_token`
  默认方法（向后兼容 0.1.0）；修复 `generate_token` 对 "jwt" style 的支持（委托 `JwtHandler::sign`）
- **session-management**：扩展 `BulwarkSession`，支持 SSO ticket 关联与临时凭证关联
- **permission-role-check**：扩展 `BulwarkFirewallStrategyDefault`，集成 `PermissionChecker`，
  支持角色层级（hierarchy）、插件钩子、权限缓存短路

### 文档与示例

- **crate-level 文档**：新增 0.2.0 模块概览，修正 default feature 描述
- **协议/安全模块文档**：移除占位描述，添加实现引用
- **示例代码**：
  - `examples/jwt_login.rs`：JwtHandler sign/verify/refresh 完整流程
  - `examples/oauth2_flow.rs`：OAuth2Client 构造 + get_auth_url
  - `examples/sso_flow.rs`：SsoClient ticket 签发/校验/销毁（含 InMemoryDao）
  - `examples/totp_login.rs`：TotpHandler generate/validate + Base32 解码

### 集成测试

- **tests/protocol_jwt_integration.rs**（4 tests）：JWT 完整 login/verify/refresh/logout 流程
- **tests/protocol_oauth2_integration.rs**（7 tests）：wiremock mock 授权服务器，
  覆盖 Authorization Code / Client Credentials / Password 三种流程
- **tests/protocol_sso_integration.rs**（9 tests）：跨子系统 ticket 签发 → 校验 → 销毁，
  验证一次性使用、client_id 隔离、destroy 跨子系统生效
- **tests/plugin_listener_integration.rs**（12 tests）：inventory 编译期注册 +
  钩子调用 + 事件广播 + 端到端生命周期协同

### 测试覆盖率

- **lib tests**：565 个
- **集成测试**：43 个（annotation 9 + axum 11 + dbnexus 10 + jwt 4 + oauth2 7 + sso 9 + plugin_listener 12）
  - 注：部分测试在多 feature 组合下重复编译，全量运行时为 633 tests passed
- **doc-tests**：6 passed, 9 ignored
- **覆盖率**：92.56%（1430/1545 行），超过 90% 目标

### 特性域

| 特性域 | 状态 | 说明 |
|--------|------|------|
| 登录认证 | ✅ 完成 | 基于 Token 的会话管理 |
| 权限认证 | ✅ 完成 | RBAC 权限模型 + PermissionChecker |
| Session 会话 | ✅ 完成 | 双模会话 + SSO/temp 关联 |
| 路由拦截鉴权 | ✅ 完成 | axum Web 框架适配 |
| 插件化扩展 | ✅ 完成 | BulwarkPlugin + inventory 注册 |
| OAuth2 | ✅ 完成 | 三种授权模式 |
| 单点登录 (SSO) | ✅ 完成 | ticket 模型 + 跨子系统 |
| JWT | ✅ 完成 | HS256/HS512 + refresh |
| 微服务网关鉴权 | ✅ 完成 | API 签名认证 |
| API 接口鉴权 | ✅ 完成 | API Key 认证 |
| TOTP 动态验证码 | ✅ 完成 | RFC 6238 |
| Basic 认证 | ✅ 完成 | RFC 7617 |
| Digest 认证 | ✅ 完成 | RFC 7616 |

### 已知限制

- **auto-wire gap**：`BulwarkLogicDefault` 当前不持有 `BulwarkPluginManager` / `BulwarkListenerManager`，
  `BulwarkUtil::login` 不会自动触发 `on_login` / `Login` 事件。需用户在业务层手动调用
  plugin/listener manager。此 auto-wire 在延后任务 13.4/13.5 中实现
- **login_by_token 默认实现**：`BulwarkLogicDefault` 未 override `login_by_token`（返回 `NotImplemented`），
  OAuth2/SSO 场景需直接使用协议层 client
- **oxcache 0.3 `Cache<K,V>::update`**：无法保留 per-entry TTL（同 0.1.0）
- **dbnexus 0.2**：仅支持 SQLite（同 0.1.0）

### 最低支持 Rust 版本

- Rust 1.85+（同 0.1.0）

## [0.1.0] - 2026-06-30

### 概述

Bulwark 0.1.0 是首个里程碑版本，实现了身份认证鉴权框架的核心基础设施。
借鉴 Sa-Token v1.45.0 的设计理念，提供基于 Token 的会话管理、RBAC 权限模型、
axum Web 框架集成等核心能力。

### 新增

#### 核心基础设施

- **错误类型体系**：`BulwarkError` 枚举，涵盖 12 个变体
  （NotLogin / NotPermission / NotRole / InvalidToken / ExpiredToken / Dao / Config / Internal / Session / Annotation / Context）
- **配置系统**：`BulwarkConfig` 全局配置，支持代码默认值 / toml 文件 / 环境变量三级配置源，
  通过 `tokio::sync::watch` 实现热更新
- **上下文抽象**：`BulwarkContext` / `BulwarkRequest` / `BulwarkResponse` / `BulwarkStorage` trait，
  解耦 Web 框架依赖；提供 axum 适配器 `AxumRequest` / `AxumResponse` / `AxumStorage` / `AxumContext`

#### 数据访问层

- **DAO 抽象**：`BulwarkDao` trait，提供 get / set / update / delete / expire 五元操作
- **oxcache 0.3 集成**：`BulwarkDaoOxcache` 实现，支持 per-entry TTL，
  通过 `Cache<K,V>::ttl()` 保留原有 TTL（依赖本地 oxcache 仓库）
- **dbnexus 0.2 集成**：`init_dbnexus` 初始化 + `BulwarkMigration` 8 张核心表迁移
  （users / oauth2_accounts / roles / permissions / user_roles / user_permissions / sessions / user_ext）

#### 会话与认证

- **双模会话管理**：`BulwarkSession` 支持 Account-Session（按 login_id 索引）+ Token-Session（按 token 索引）
- **核心认证 API**：`BulwarkLogic` trait 定义 login / logout / check_login / kickout 完整契约，
  `BulwarkLogicDefault` 默认实现
- **task_local 上下文**：`with_current_token` / `current_token` 提供 async 请求级 token 存取
- **权限校验策略**：`BulwarkFirewallStrategy` trait + `BulwarkFirewallStrategyDefault` 默认实现

#### 全局管理器

- **BulwarkManager 单例**：持有 `Arc<dyn BulwarkLogic>` 全局引用，支持显式 `init()` 初始化
  + 覆盖式更新 + `reset_for_test()`（cfg(test)）
- **inventory 编译期注册**：`BulwarkLogicFactoryEntry` 通过 `inventory::submit!` 注册工厂函数，
  支持编译期扩展
- **BulwarkUtil 静态委托**：8 个静态方法（login / logout / kickout / check_login / get_login_id /
  check_permission / check_role）委托到 `BulwarkManager::logic()?`

#### axum Web 框架集成

- **注解系统**：5 个 axum extractor（`CheckLogin` / `CheckRole<R>` / `CheckPermission<P>` /
  `Ignore` / `Mode<M>`），基于 Marker struct + 关联常量模式
- **`IntoResponse` 实现**：`BulwarkError` 自动映射 HTTP 状态码
  （401 Unauthorized / 403 Forbidden / 500 Internal Server Error）
- **BulwarkRouter**：包装 `axum::Router`，提供 `route_protected(path, handler, annotation)` 语法糖
- **BulwarkInterceptor**：`pre_handle` trait + `DefaultBulwarkInterceptor` 默认实现
- **axum middleware**：自动从 header（Authorization: Bearer 或自定义 token_name）/ cookie 提取 token，
  通过 `with_current_token` 设置 task_local

#### 文档与示例

- **crate-level 文档**：包含快速开始 / 特性 / 架构 3 个章节
- **public API 文档**：所有 pub 项均有 `///` 文档注释
- **示例代码**：
  - `examples/basic_login.rs`：完整业务场景（init + login + check + logout，144 行）
  - `examples/axum_integration.rs`：完整 Web 应用（BulwarkRouter + 4 路由 + 服务器启动，244 行）

### 特性域

| 特性域 | 状态 | 说明 |
|--------|------|------|
| 登录认证 | ✅ 完成 | 基于 Token 的会话管理 |
| 权限认证 | ✅ 完成 | RBAC 权限模型 |
| Session 会话 | ✅ 完成 | 双模会话生命周期管理 |
| 路由拦截鉴权 | ✅ 完成 | axum Web 框架适配 |
| 插件化扩展 | 🚧 占位 | 0.2.0+ 实现 |
| OAuth2 | 🚧 占位 | 0.2.0+ 实现 |
| 单点登录 (SSO) | 🚧 占位 | 0.2.0+ 实现 |
| JWT | 🚧 占位 | 0.2.0+ 实现 |
| 微服务网关鉴权 | 🚧 占位 | 0.2.0+ 实现 |
| API 接口鉴权 | 🚧 占位 | 0.2.0+ 实现 |
| TOTP 动态验证码 | 🚧 占位 | 0.2.0+ 实现 |
| Basic 认证 | 🚧 占位 | 0.2.0+ 实现 |
| Digest 认证 | 🚧 占位 | 0.2.0+ 实现 |

### 技术栈

- **缓存抽象层**：oxcache 0.3（L1 moka + L2 redis，支持 per-entry TTL）
- **数据库抽象层**：dbnexus 0.2（SQLite + 自动迁移）
- **Web 框架**：axum 0.7
- **异步运行时**：tokio 1.x
- **序列化**：serde + serde_json + toml

### 特性门控

| 特性 | 默认 | 说明 |
|------|------|------|
| `cache-memory` | ✅ | 内存缓存后端（oxcache） |
| `cache-redis` | ✅ | Redis 缓存后端（oxcache） |
| `db-sqlite` | ✅ | SQLite 数据库后端（dbnexus） |
| `web-axum` | ✅ | axum Web 框架适配 |
| `protocol-jwt` | ❌ | JWT 支持 |
| `protocol-oauth2` | ❌ | OAuth2 支持 |
| `protocol-sso` | ❌ | SSO 支持 |
| `protocol-sign` | ❌ | 签名认证 |
| `protocol-apikey` | ❌ | API Key 认证 |
| `secure-totp` | ❌ | TOTP 动态验证码 |
| `secure-sign` | ❌ | 安全签名 |
| `secure-httpbasic` | ❌ | HTTP Basic 认证 |
| `secure-httpdigest` | ❌ | HTTP Digest 认证 |
| `listener` | ❌ | 事件监听器 |
| `metrics-prometheus` | ❌ | Prometheus 指标 |
| `full` | ❌ | 聚合所有特性 |
| `production` | ❌ | 生产环境推荐特性组合 |
| `development` | ❌ | 开发环境特性组合 |

### 测试覆盖率

- **单元测试**：292 个
- **集成测试**：30 个（annotation_integration 9 + axum_integration 11 + dbnexus 10）
- **doc-tests**：1 passed, 9 ignored
- **覆盖率**：97.81%（669/684 行），未覆盖代码为少量错误分支

### 已知限制

- **oxcache 0.3 `Cache<K,V>::update`**：无法保留 per-entry TTL（`Cache<K,V>` 未暴露 `ttl()`），
  当前使用 `set()` 覆盖（清除 per-entry TTL），待 oxcache 暴露 `ttl()` 后修复
- **dbnexus 0.2**：仅支持 SQLite，PostgreSQL/MySQL 待 0.2.0+ dbnexus 添加
- **BulwarkRouter::route_protected**：仅支持 GET 方法，其他方法待后续版本支持

### 最低支持 Rust 版本

- Rust 1.85+（部分 deps 如 inventory 0.3 要求 edition2024）
