# 📘 Garrison API 参考

本参考文档收录 Garrison 的公开 API：全局管理器与静态门面、业务回调 trait、存储层 trait、注解宏、错误类型以及特性门控模块。文档假设启用了相应 feature；未启用时对应 API 不参与编译。在线文档（docs.rs 自动生成）：<https://docs.rs/garrison>。

> 适用版本：0.9.0-rc.1。完整签名以 rustdoc 为准，本文按「模块 → trait/类型 → 方法表」组织，供快速定位。

## 📋 目录

- [概述](#-概述)
- [prelude 预导出](#-prelude-预导出)
- [全局管理器](#-全局管理器)
- [静态门面 GarrisonUtil](#️-静态门面-garrisonutil)
- [token 上下文](#-token-上下文)
- [业务回调 GarrisonInterface](#-业务回调-garrisoninterface)
- [存储层 GarrisonDao](#️-存储层-garrisondao)
- [权限策略](#-权限策略)
- [会话与状态](#-会话与状态)
- [Web 集成与注解宏](#-web-集成与注解宏)
- [插件与监听器](#-插件与监听器)
- [Repository 层](#️-repository-层)
- [错误类型](#-错误类型)
- [模块地图](#️-模块地图)
- [相关文档](#-相关文档)

---

## 🎯 概述

### API 设计原则

| 原则 | 说明 |
|:-----|:-----|
| **静态门面** | 业务代码只与 `GarrisonManager`（初始化一次）和 `GarrisonUtil`（静态方法）打交道 |
| **回调注入** | 框架不假定数据来源，权限 / 角色数据经 `GarrisonInterface` 回调由业务方提供 |
| **trait 可替换** | `GarrisonDao`、`GarrisonPermissionStrategy`、`GarrisonPlugin`、`GarrisonListener` 均可自定义实现替换默认行为 |
| **feature 门控** | 可选能力（协议、防火墙、Web 适配等）按 feature 独立编译；功能矩阵见 [README · 特性标志](../README.md#-特性标志) |

### 导入方式

```rust
use garrison::prelude::*;          // 核心 API 一步到位
use garrison::stp::with_current_token; // token 上下文（prelude 亦含）
```

---

## 📦 prelude 预导出

`garrison::prelude`（`src/prelude.rs`）聚合最常用类型，`use garrison::prelude::*` 即可覆盖 README 最小示例的全部依赖：

| 导出项 | 说明 |
|--------|------|
| `GarrisonConfig` | 配置类型 |
| `GarrisonContext` / `GarrisonRequest` / `GarrisonResponse` / `GarrisonStorage` | 上下文抽象 |
| `AuthRequest` / `Decision` / `DecisionReason` | 授权请求与决策（`core-advanced`） |
| `GarrisonDao` | 存储 trait |
| `GarrisonError` / `GarrisonResult` | 错误类型与 Result 别名 |
| `GarrisonManager` | 全局管理器 |
| `GarrisonPlugin` | 插件 trait |
| `GarrisonInterceptor` / `GarrisonRouter` | 路由与拦截器 |
| `GarrisonSession` | 会话 |
| `GarrisonPermissionStrategy` / `GarrisonPermissionStrategyDefault` | 权限策略 trait 与默认实现 |
| `Annotation` | 注解（`annotation-macros`） |
| `GarrisonDaoOxcache` | oxcache DAO 实现（`cache-*`） |
| `LoginParams` | 登录参数 |
| `with_current_token` / `current_token` | token 上下文 |
| `CreditMeteringListener` 等 | 计量监听（`credit-metering`） |

---

## 🏢 全局管理器

`GarrisonManager`（`src/manager/`）— 全局单例，内部逻辑经 `arc_swap::ArcSwapOption` 无锁读取。

```rust
GarrisonManager::builder()
    .dao(dao)               // Arc<dyn GarrisonDao>
    .config(config)         // Arc<GarrisonConfig>
    .interface(interface)   // Arc<dyn GarrisonInterface>
    .build().await?;        // 初始化全局单例
```

| 项 | 说明 |
|----|------|
| `GarrisonManager::builder()` | 返回 builder；启用任一 `firewall-*` 时自动注入防火墙检查钩子 |
| 初始化时序 | 全局只可 `build()` 一次；并发初始化为 CAS 语义 |
| 后端模式 | `backend-embedded`（默认，进程内认证）/ `backend-remote`（HTTP 调用远程 Auth Server，含熔断） |

---

## 🛠️ 静态门面 GarrisonUtil

`GarrisonUtil`（`src/stp/util/mod.rs`）— 全部为关联函数，读取当前 task_local token 上下文执行。以下为实际公开 API（按主题分组）：

### 登录 / 登出

| 方法 | 说明 |
|------|------|
| `login(id, params: &LoginParams) -> GarrisonResult<String>` | 登录并返回 token |
| `login_simple(id) -> GarrisonResult<String>` | 默认参数登录 |
| `logout() -> GarrisonResult<()>` | 登出当前 token |
| `logout_by_login_id(login_id) -> GarrisonResult<()>` | 按主体登出 |
| `kickout(login_id) -> GarrisonResult<()>` | 踢人下线 |
| `kickout_by_token(token) -> GarrisonResult<()>` | 按 token 踢出 |
| `login_by_token(token) -> GarrisonResult<()>` | 以既有 token 恢复登录态 |
| `invalidate_sessions_after_password_change(...) -> GarrisonResult<()>` | 改密后失效历史会话 |

### 登录态校验

| 方法 | 说明 |
|------|------|
| `check_login() -> GarrisonResult<bool>` | 校验登录状态，未登录抛 `NotLogin` |
| `check_login_sync() -> GarrisonResult<bool>` | 同步版本 |
| `get_login_id() -> GarrisonResult<Option<String>>` | 当前主体 |
| `get_login_id_by_token(token) -> GarrisonResult<Option<String>>` | 按 token 查主体 |

### 权限 / 角色

| 方法 | 说明 |
|------|------|
| `check_permission(permission) -> GarrisonResult<()>` | 校验权限，失败抛 `NotPermission` |
| `check_role(role) -> GarrisonResult<()>` | 校验角色，失败抛 `NotRole` |
| `check_permission_sync(perm)` / `check_role_sync(role)` | 同步版本 |
| `has_permission(permission) -> GarrisonResult<bool>` / `has_role(role)` | 布尔版 |
| `get_permission_list() -> GarrisonResult<Vec<String>>` / `get_role_list()` | 读取当前主体权限 / 角色列表 |

### Token 与协议

| 方法 | 说明 | Feature |
|------|------|---------|
| `verify_token(token) -> GarrisonResult<String>` | 验证 token | — |
| `revoke_token(token) -> GarrisonResult<()>` | 吊销 token（RFC 7009 语义） | — |
| `refresh_token(token) -> GarrisonResult<String>` | RefreshToken 轮换 | `protocol-jwt` |
| `check_access_token()` / `check_client_token()` / `check_temp_token()` | OAuth2 三类 token 校验 | `protocol-oauth2` |
| `check_api_key(namespace) -> GarrisonResult<()>` | API Key 校验（feature 关闭时 fail-closed 返回 `Config` 错误） | `protocol-apikey` |

### 二次认证与封禁

| 方法 | 说明 |
|------|------|
| `check_safe() -> GarrisonResult<()>` | 校验二次认证完成度，未完成抛 `NotSafe { reason }` |
| `check_disable() -> GarrisonResult<()>` | 校验账号封禁状态，被封禁抛 `DisableService { service, until }` |

> 另有 `garrison::stp::util::init_backend(backend)` 初始化后端（`backend-*` 架构面）。

---

## 🎯 token 上下文

`garrison::stp`（`src/stp/context.rs`）— task_local 携带当前 token，Web 中间件已自动绑定：

| 函数 | 说明 |
|------|------|
| `with_current_token(token, fut)` | 在 `fut` 执行期间绑定 token（链式可嵌套） |
| `current_token()` | 读取当前 token（`Option<String>`） |

---

## 🔌 业务回调 GarrisonInterface

`garrison::GarrisonInterface`（`src/stp/interface.rs`）— 业务方实现，提供权限 / 角色数据（对应 Sa-Token 的 `StpInterface`）。

| 方法 | 默认实现 | 说明 |
|------|----------|------|
| `get_permission_list(&self, login_id) -> GarrisonResult<Vec<String>>` | 必须实现 | 指定主体的权限标识列表 |
| `get_role_list(&self, login_id) -> GarrisonResult<Vec<String>>` | 必须实现 | 指定主体的角色标识列表 |
| `get_permission_list_with_type(&self, login_id, login_type)` | 委托 `get_permission_list` | 多账号体系按 `login_type` 隔离（默认策略传入 `with_login_type` 配置的值） |
| `get_role_list_with_type(&self, login_id, login_type)` | 委托 `get_role_list` | 同上（角色维度） |

数据来源由业务方自定（数据库 / 配置 / 外部服务）；`GarrisonPermissionStrategyDefault` 拿到列表后做字符串匹配。

---

## 🗄️ 存储层 GarrisonDao

`garrison::GarrisonDao`（`src/dao/mod.rs`）— 统一 KV 抽象，屏蔽 oxcache / dbnexus 后端差异。核心方法（全部 `async`，返回 `GarrisonResult`）：

### 基础 KV

| 方法 | 说明 |
|------|------|
| `get(key) -> Option<String>` | 读取 |
| `set(key, value, ttl_seconds)` | 写入（带 TTL） |
| `set_permanent(key, value)` | 永久写入（默认实现 `set` ttl=0） |
| `set_if_absent(key, value, ttl_seconds)` | 不存在才写入（原子语义） |
| `update(key, value)` | 更新（保留原 TTL） |
| `expire(key, seconds)` | 重设 TTL |
| `get_timeout(key) -> Option<Duration>` | 读取剩余 TTL（默认实现返回 `NotImplemented`） |
| `get_with_ttl(key) -> Option<(String, Option<Duration>)>` | 值 + 剩余 TTL |
| `delete(key)` | 删除 |
| `keys(pattern) -> Vec<String>` | 按模式列举 |
| `rename(old_key, new_key)` | 重命名 |
| `get_and_delete(key) -> Option<String>` | 原子取出并删除 |
| `incr(key, ttl_seconds) -> u64` / `decr(key) -> u64` | 原子计数 |

### 扩展契约

| 方法 | 说明 | Feature |
|------|------|---------|
| `compare_and_update_if_greater(...)` | 数值比较后更新（限流计数基座） | — |
| `compare_and_swap(...)` | CAS | — |
| `find_social_binding(...)` / `insert_social_binding(...)` | 社交账号绑定 | `social-*` |
| `query_role_hierarchy_edges(...)` / `insert_role_hierarchy_edge(...)` / `delete_role_hierarchy_edge(...)` | 角色层级边存储 | — |
| `eval_lua(...)` | Lua 脚本（redis 面下透传） | `cache-redis` |
| `insert_credit_consumption(...)` / `query_credit_consumption(...)` | 计量消费记录 | `credit-metering` |

### 内置实现

| 类型 | Feature | 说明 |
|------|---------|------|
| `GarrisonDaoOxcache` | `cache-memory` / `cache-redis` | L1 内存（per-entry TTL + 写入抖动）+ L2 redis |
| dbnexus DAO | `db-sqlite` / `db-postgres` / `db-mysql` | SQL 持久化 + Repository 层（见下） |
| 内存 Mock DAO | — | `src/stp/mock.rs`（测试用） |

---

## 🧮 权限策略

`garrison::GarrisonPermissionStrategy`（`src/strategy/`）— 鉴权决策入口，可整体替换：

| 项 | 说明 |
|----|------|
| `GarrisonPermissionStrategyDefault` | 默认实现：经 `GarrisonInterface` 回调取数据后字符串匹配；`with_login_type` 设置多账号 login_type |
| `firewall_hook_injected()` | 诊断方法，返回防火墙钩子是否已被 builder 注入 |
| ABAC | `abac` feature：Cedar DSL 策略引擎（`garrison::abac`），`#[check_abac]` 注解 + `set_abac_missing_feature_policy` 逃生门 |
| 决策溯源 | `core-advanced`：`authorize(AuthRequest) -> Decision`（`Allow` / `Deny` + `DecisionReason`） |

---

## 💼 会话与状态

| 类型 | 说明 |
|------|------|
| `GarrisonSession`（`src/session/`） | 会话操作面；`session::dao()` 在 `firewall-bruteforce` 面下对 crate 内开放 |
| `TokenState`（`src/state/`，prelude 导出） | token 状态机 |
| `UserStatus` | 用户状态枚举 |
| `GarrisonPrincipal` / `TenantContext` / `TENANT`（`src/context/`） | 请求主体与租户上下文（`tenant-isolation`）；`TENANT.scope(tenant, fut)` 进入租户作用域 |
| `ClaimTenantResolver` | 从 claim 解析租户的 resolver |

---

## 🌐 Web 集成与注解宏

### 路由与拦截

| 类型 | 说明 |
|------|------|
| `GarrisonRouter` | 统一路由抽象；actix 面提供 `with_tenant_resolver(resolver)` / `with_header_tenant()` |
| `GarrisonInterceptor` | 请求拦截器，进入 `GarrisonUtil` 静态 API |
| `garrison::web`（`web-axum`） | axum extractor 与中间件 |
| `garrison::web_actix` / `garrison::web_warp` | actix-web / warp 适配 |
| `garrison::grpc`（`grpc`） | tonic auth layer |

### 注解宏（`annotation-macros` feature，过程宏 crate `garrison-macros`）

10 个属性宏（wrapper 生成 axum `Response`），另有 3 个 sdforge `#[forge]` 路由变体：

| 宏 | 对应校验 |
|----|----------|
| `#[check_login]` | 登录态（`NotLogin` → 401） |
| `#[check_role("...")]` / `#[check_permission("...")]` | 角色 / 权限 |
| `#[check_access_token]` / `#[check_client_token]` / `#[check_temp_token]` | OAuth2 token 类型 |
| `#[check_api_key("...")]` | API Key（feature 关闭时 fail-closed） |
| `#[check_disable]` | 封禁状态 |
| `#[check_mfa]` | 二次认证 |
| `#[check_abac(policy = "...")]` | ABAC 策略（`abac`） |
| `#[check_login_forge]` / `#[check_role_forge]` / `#[check_permission_forge]` | sdforge 动态路由变体 |

---

## 🧩 插件与监听器

| trait | 注册方式 | 说明 |
|-------|----------|------|
| `GarrisonPlugin`（`src/plugin/`） | `inventory::submit!` 编译期注册 | 生命周期钩子注入 |
| `GarrisonListener`（`src/listener/`） | `inventory::submit!` 编译期注册 | 15 个事件变体（Login / Logout / Kickout / Replaced / TokenExpired / TokenRefresh / CreditConsumed / CreditAlert 等）；事件载荷 token 已统一掩码 |
| `AuditLogListener` / `AuditConfig` / `AuditEntry` / `AuditQuery`（`listener::audit`，`audit-log`） | — | 审计日志监听与查询 |

---

## 🗃️ Repository 层

`db-*` feature 下经 `src/dao/repository/` 提供类型化仓储（10 trait），lib.rs 顶层 re-export SQLite 实现：

| Re-export | 说明 |
|-----------|------|
| `DbnexusUserRepository` / `DbnexusRoleRepository` / `DbnexusPermissionRepository` | 用户 / 角色 / 权限 |
| `DbnexusUserRoleRepository` / `DbnexusRolePermissionRepository` | 关联表 |
| `DbnexusAuthMethodRepository` / `DbnexusSessionRepository` / `DbnexusLoginLogRepository` / `DbnexusUserExtRepository` | 认证方式 / 会话 / 登录日志 / 扩展字段 |
| `RoleHierarchyService` / `RoleHierarchyRecord` | 角色层级（SQL 占位符按后端自适应） |
| `init_dbnexus_with_pool_config(url, PoolConfig)` | 经 dbnexus `DbPoolBuilder` 透传连接池参数（max/min connections、超时） |

协议层补充 re-export：`RefreshTokenRecord` / `RefreshTokenRotation`（`protocol-jwt`）。

---

## ❗ 错误类型

`garrison::GarrisonError`（`src/error.rs`，`thiserror` 派生）— 统一错误枚举，`GarrisonResult<T> = Result<T, GarrisonError>`。

Display 行为：未启用 `i18n` 时硬编码中文；启用 `i18n` 后按线程本地 locale 切换中英文。

| 变体 | HTTP 语义 | 说明 |
|------|-----------|------|
| `NotLogin(String)` | 401 | 未登录（对应 NotLoginException） |
| `NotPermission(String)` / `NotRole(String)` | 403 | 无权限 / 无角色 |
| `InvalidToken(String)` / `ExpiredToken(String)` / `TokenRevoked(String)` | 401 | token 无效 / 过期 / 已吊销（RFC 7009） |
| `Dao(String)` | 500 | 存储层错误 |
| `Config(String)` | 500 | 配置错误（含 fail-closed 的 feature 缺失，如未启用 `protocol-apikey` 时调用 `check_api_key`） |
| `Internal(String)` | 500 | 内部错误 |
| `Session(String)` | 500 | 会话创建 / 查询 / 过期 / 续期错误 |
| `Annotation(String)` | 500 | 注解校验失败 / 组合冲突 |
| `Context(String)` | 500 | GarrisonContext / Request / Response / Storage 异常 |
| `Exception(Box<GarrisonException>)` | — | 业务异常（Box 装载控制枚举体积，越过 `result_large_err` 阈值） |
| `OAuth2(String)` / `Network(String)` / `InvalidResponse(String)` | 502 | OAuth2 协议 / 网络层 / 上游响应解析失败（三者语义互斥） |
| `InvalidParam(String)` | 400 | 参数无效 |
| `NotImplemented(String)` | 500 | default 实现未覆盖 |
| `FirewallBlocked(String)` | 429 | 防火墙拦截（携带 strategy 名与原因，供 audit-log 订阅） |
| `DisableService { service, until }` | 403 | 账号封禁（`until = None` 为永久；不泄露 user_id / tenant_id） |
| `NotSafe { reason }` | 401 | 未完成二次认证（如 `MFA_TOTP_REQUIRED`） |
| `InvalidStateTransition { from, to }` | 500 | 状态机非法转换 |
| `SmsRateLimitExceeded { window }` / `SmsVerifyMaxAttempts` / `SmsCodeNotFound` / `SmsChannelRecycled` | 429/400 | 短信验证码（`sms-rate-limit`） |
| `EmailRateLimitExceeded { window }` 等 | 429/400 | 邮箱验证（`email-verification` 门控变体） |

---

## 🗺️ 模块地图

`src/lib.rs` 公开模块（无标注为总编译核心；其余按 feature 门控，功能矩阵见 [README · 特性标志](../README.md#-特性标志)）：

| 模块 | 说明 |
|------|------|
| `stp` | 静态门面层（登录 / 校验 / token 上下文 / util） |
| `core` / `manager` / `strategy` / `session` / `dao` | 核心引擎 |
| `annotation` / `router` | 注解与路由 |
| `config` / `context` / `state` / `json` / `exception` / `constants` / `error` / `prelude` | 配置 / 上下文 / 状态 / JSON 模板 / 异常 / 常量 / 错误 / 预导出 |
| `plugin` / `listener` | 插件 / 事件监听 |
| `cache`（`cache-*`） | 缓存后端 |
| `limiteron` | 分布式限流适配（无条件编译，公共基座） |
| `credit`（`credit-metering`） | 计量 |
| `secure`（`secure-*`） | 安全工具集 |
| `account`（`account-*`） | 账号安全引擎 |
| `protocol`（`protocol-*`） | 认证协议层 |
| `abac`（`abac`） | Cedar 属性访问控制 |
| `web` / `web_actix` / `web_warp`（`web-*`） | Web 框架适配 |
| `server`（`auth-server`） | 独立认证服务器 |
| `oauth2_server`（`oauth2-server`） | OAuth2 Server |
| `backend`（`backend-*`） | 后端架构（embedded / remote / kit） |
| `grpc`（`grpc`） | gRPC 拦截器 |
| `observability`（`tracing-log` / `metrics-prometheus` / `otlp`） | 可观测性 |
| `health` | 健康检查 |
| `i18n` | 国际化（基础层无条件编译） |
| `testing`（`testing`） | 测试辅助（验收矩阵配套） |

---

## 📚 相关文档

| 文档 | 说明 |
|------|------|
| [📖 用户指南](USER_GUIDE.md) | 从安装到进阶的完整使用教程 |
| [🏗️ 架构文档](ARCHITECTURE.md) | 设计原则、模块划分与数据流 |
| [⚙️ 配置指南](CONFIGURATION.md) | `GarrisonConfig` 全量配置项 |
| [🧪 测试场景矩阵](TEST_SCENARIOS.md) | 验收场景穷举与特性组合矩阵 |
| [💻 在线 API 文档](https://docs.rs/garrison) | docs.rs 自动生成的最新文档 |
