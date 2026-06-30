# Changelog

本文件记录 Bulwark 项目的所有显著变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

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
