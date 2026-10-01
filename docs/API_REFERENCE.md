# 📘 Garrison API 参考

本参考文档收录 Garrison 的公开 API：全局管理器与静态门面、业务回调 trait、存储层 trait、注解宏、错误类型以及特性门控模块。文档假设启用了相应 feature；未启用时对应 API 不参与编译。在线文档（docs.rs 自动生成）：<https://docs.rs/garrison>。

> 适用版本：0.9.0-rc.2。完整签名以 rustdoc 为准，本文按「模块 → trait/类型 → 方法表」组织，供快速定位。

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
- [密码哈希器（account-credential）](#-密码哈希器account-credential)
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

**Refresh token 重用检测与宽限窗口**（`RefreshTokenRotation`，`protocol-jwt` + `db-sqlite` feature；SQL 面向 SQLite，服务整体 `db-sqlite` 门控）：旧 token 重放按三级分类处置（`RecentPrev`/`OrphanedBranch` 按配置分派、`StaleLineage` 恒吊销整条 chain），完整处置表见 [THREAT.md](THREAT.md)。相关 `GarrisonConfig` 字段：

| 字段 | 默认 | 说明 |
|------|------|------|
| `recent_reuse_behaviour` | `TheftDetected` | `RecentPrev`/`OrphanedBranch` 重用处置：`TheftDetected` 吊销整条 chain + `TokenRevoked`；`Unauthorised` 仅拒绝本次（401）不吊销。非法值启动期 fail-fast |
| `refresh_grace_period_secs` | `0`（关闭） | 宽限窗口秒数——窗口内已轮换旧 token 再次呈现返回既有新 token（不重旋转，容忍并发双刷；兑现凭据进程内暂存，多实例仅签发实例命中） |
| `refresh_grace_max_uses` | `1` | 窗口内同一旧 token 最大宽限兑现次数，耗尽后的窗口内重放按 `recent_reuse_behaviour` 处置（默认吊销整条 chain）；仅窗口 >0 时生效 |

对应环境变量：`GARRISON_RECENT_REUSE_BEHAVIOUR` / `GARRISON_REFRESH_GRACE_PERIOD_SECS` / `GARRISON_REFRESH_GRACE_MAX_USES`。**生效前提**：上述字段由注入的 `RefreshTokenRotation` 读取——应用经 `TokenHandler::with_refresh_rotation` 注入轮换服务时须同步以 `with_reuse_behaviour` / `with_grace_window` 装配配置值（框架默认不自动装配，未注入时 refresh 走 DAO 退化路径，配置不生效）。

### OAuth2 discovery 与 JWKS 多 kid 轮换（`oauth2-server`）

**Discovery 端点**（`OAuth2State::oidc_discovery_enabled`，默认跟随 `protocol-oidc` feature，可运行时覆写）：`GET /.well-known/openid-configuration`（OIDC Discovery 1.0）与 `GET /.well-known/oauth-authorization-server`（RFC 8414）。issuer 未配置或开关关闭 → 404（fail-closed）。元数据从实际能力派生（非静态模板）：

| 字段 | 派生来源 |
|------|---------|
| `issuer` / `authorization_endpoint` / `token_endpoint` 等端点路径 | `OAuth2State::issuer` + 固定路由 |
| `grant_types_supported` | token 端点既有能力（authorization_code/refresh_token/client_credentials）；`password` 仅在装配方注入 password verifier 并置位 `password_grant_advertised` 后宣告 |
| `scopes_supported` | 注册客户端 scope 并集（运行时查询派生；派生失败 500 显性暴露，空集回退 `openid`） |
| `jwks_uri` / `jwks_algorithms`（id_token 签名算法） | 仅在实际发布 JWKS 时出现（防死链误导客户端） |
| `code_challenge_methods_supported` | PKCE 强制开启 → 仅 `S256` |

响应带 `Cache-Control: public, max-age=300`。

**JWKS 多 kid 轮换**（`oauth2_server::jwks::JwksKeystore`，注入 `OAuth2State::jwks_keystore` 后 JWKS 端点优先从库发布）：钥三态 `Active`（签名）/ `Passive`（退役保留验证，仍发布）/ `Disabled`（移出发布与验证面）。三视图语义：签名取 Active、验证取 Active∪Passive（`kid` 命中 Passive 旧钥验证成功；缺失回退 Active；未知 kid 显性报错）、JWKS 输出取 Active∪Passive。轮换经 DAO `compare_and_swap` 账本提交（防多实例竞态：并发轮换恰一成功，失败方读到胜者后的一致状态）；Passive 超 `jwks_retention_secs`（默认 7200 = 2× access token TTL，见 [CONFIGURATION.md](CONFIGURATION.md)）转 Disabled 并移出 JWKS。JWKS 端点 `Cache-Control: max-age` 按 retention 的一半动态计算。

### authorize 两段式票据与 consent 记忆（`oauth2-server`，R18）

**两段式流程**：`GET /oauth2/authorize` 校验通过（response_type/PKCE S256/redirect 白名单）→ 签发 32 字符随机票据暂存完整请求（TTL 600s）→ `LoginRequired` 重定向登录页（`return_to=/oauth2/authorize/resume?ticket=...`）→ 登录成功后 `GET /oauth2/authorize/resume?ticket=...` 凭会话身份原子消费票据续流签发授权码。票据不绑定主体（续流主体以会话为准）；消费一次性（二次消费/过期/未知统一 `invalid_ticket` 显性拒绝，无状态泄露）。

**prompt 语义**（OIDC Core §3.1.2.1，`AuthorizeRequest.prompt` 字段显式出现时生效）：`none` → 未登录或 consent 不足一律 `interaction_required`（不弹任何交互页）；`login` → 已登录也强制重走登录往返。

**consent 记忆**：键 `oauth2:consent:{tenant}:{user}:{client}` 持久化已授 scope 集合 + 属性快照双粒度哈希（ATTRIBUTE_NAME / ATTRIBUTE_VALUE，SHA-512，`with_attribute_granularity` 可配）。再次授权：请求 scope ⊆ 已授且属性快照未变 → 免征询直接放行；新增 scope → 合并为超集；快照不可解析 → fail-safe 重新征询。`reconcile_consents` 清理已删 client 的孤儿行，幂等；框架 `listen()` 启动时自动执行（fail-open：失败仅告警不阻断启动，下次启动或运维显式调用重试）。

**装配契约**：prompt=none 静默续期以空属性视图比对快照——经征询页批准（非空属性视图）的用户需部署方传入一致属性视图，否则重新触发 `interaction_required`（fail-safe，文档见 `with_consent_url`）。

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
| `rename(old_key, new_key)` | 重命名（缺键返回 `InvalidParam`，原子保留原 TTL） |
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

### 契约测试套件 `dao::testing`

多后端同一把尺子：组断言函数库按能力分层，`dao_conformance_tests!` 宏对每个
`GarrisonDao` 实现（内置或自定义）实例化运行。`cfg(test)` 下随单元测试执行；
`testing` feature 构建面开放给下游复用。

| 组断言函数 | 能力层 | 内容 |
|-----------|--------|------|
| `run_basic(&Arc<dyn GarrisonDao>, prefix)` | `basic` | get/set/update/delete/expire、永久键、get_with_ttl 三态、incr/decr 全语义、CAS-if-greater、rename（缺键 `InvalidParam`） |
| `run_atomic(&Arc<dyn GarrisonDao>, prefix)` | `atomic` | set_if_absent / get_and_delete / compare_and_swap 单线程原子语义 |
| `run_concurrent(&Arc<dyn GarrisonDao>, prefix)` | `concurrent` | multi_thread 真并发：SETNX 恰一赢家、GETDEL 一次性消费、incr/decr 返回值排列恰一、CAS 单调 |
| `run_ttl(&Arc<dyn GarrisonDao>, prefix)` | `ttl` | 过期不复活、update/rename/incr 保留原窗口、`expire(k, 0)` 转永久（墙钟，单次 sleep 3s） |
| `run_keys(&Arc<dyn GarrisonDao>, prefix)` | `keys` | glob `*`/`?` 精确匹配、空 Vec、delete/rename 扫描同步 |

一行接入（自定义后端）：

```rust
garrison::dao_conformance_tests! {
    backend: my_dao,
    make: || async { MyDao::new().await.map(|d| Arc::new(d) as Arc<dyn GarrisonDao>) },
    caps: [basic, atomic, concurrent],   // 未声明的层不生成测试
    // serial: true,                      // 可选：#[serial_test::serial]（仅测试构建）
    // ignore: "requires X",             // 可选：#[ignore = "..."]
}
```

`make` 每测试新建空实例（每测试全新存储，兼容共享存储后端）；全部键名以
`<backend>:` 前缀隔离；构造失败 panic（fail-loud）。

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
| `GarrisonSession`（`src/session/`） | 会话操作面；`session::dao()` 无 feature 门控，对 crate 内 `pub(crate)` 开放（调用方含 `protocol-apikey` / `db-postgres` / `db-mysql` / `cache-redis` / `protocol-jwt`） |
| `TokenState`（`src/state/`，crate 根 re-export） | token 状态机 |
| `UserStatus` | 用户状态枚举（同样经 crate 根 re-export） |
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

### Set-Cookie 单一构建点（context 层，always-on）

`garrison::context::cookie` — 全部 Set-Cookie 写路径（三框架适配器、axum 续签中间件、CSRF 中间件）的唯一产出点，纯函数、无框架依赖：

| 类型 / 函数 | 说明 |
|------|------|
| `CookieScope` | SameSite × HttpOnly 合法组合封闭枚举：`LaxHttpOnly` / `StrictHttpOnly` / `NoneHttpOnly`（HttpOnly 恒定） |
| `CookiePath` | 路径作用域：`Root`（`Path=/`）/ `Of(String)`（预留：短时 token 限定路径，当前无生产写点） |
| `CookieType` | 构建参数（`name` / `scope` / `path` / `domain` / `max_age`）；`CookieType::token(&config)` 承接会话 token cookie，`session(name, &config)` 承接其他会话 cookie；`resolved_name(secure)` 输出读侧解析名 |
| `build_set_cookie_value(&CookieType, value, secure)` | 构建 Set-Cookie 值；校验失败时返回错误，调用方不得产出任何 Set-Cookie |
| `token_cookie_name(&config)` | 会话 token cookie 读侧统一入口（与写侧产出同名） |

不变式（由构建点强制，写点无法绕过）：

1. **HttpOnly 恒定**：三个 `CookieScope` 变体均输出 HttpOnly。
2. **SameSite 白名单 fail-fast**：非 `["Lax", "Strict", "None"]` 返回错误（合法值与启动期配置校验白名单 `COOKIE_SAME_SITE_VALUES` 一一对应，由跨引用测试锁定漂移）。
3. **None→Lax 降级**：`cookie_secure=false`（非 Secure 上下文确定性信号）时 `SameSite=None` 降级为 `Lax`（warn 一次）。
4. **production 前缀**：`production` feature + Secure 上下文时，`Path=/` 且无 Domain → `__Host-<name>`；限定路径或带 Domain → `__Secure-<name>`；http 降级无前缀。读侧必须经 `token_cookie_name` / `CookieType::resolved_name` 同名解析。
5. **注入防护**：name/value 复用 `validate_cookie_name_value`，拒绝 `;`、控制字符等分隔符；path 拒 `;` 与控制字符，domain 仅允许主机名字符（字母数字连字符点）。

### 注解宏（`annotation-macros` feature，过程宏 crate `garrison-macros`）

13 个属性宏（wrapper 生成 axum `Response`）：10 个 axum wrapper 宏 + 3 个 sdforge `#[forge]` 路由变体。

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
| `GarrisonListener`（`src/listener/`） | `inventory::submit!` 编译期注册 | 31 个事件变体（Login / Logout / Kickout / PermissionCheck / RoleCheck / TokenExpired / LoginFailure / PasswordRehashed / TokenRefresh / RevokeToken / SessionTimeout / AccountLocked / FirewallBlock / TokenRotate / TempCredentialConsumed / SocialLogin / TenantSwitch / DeviceBlock / DeviceUnblock / ConfigReload / AnomalousLoginDetected / Replaced / CreditConsumed / CreditAlert / InvitationCreated / InvitationRevoked / InvitationRedeemed / QrLoginCreated / QrLoginScanned / QrLoginConfirmed / QrLoginCancelled）；trait 侧为单一 `async fn on_event` 回调（非逐事件钩子），事件载荷 token 已统一掩码 |
| `AuditLogListener` / `AuditConfig` / `AuditEntry` / `AuditQuery`（`listener::audit`，`audit-log`） | — | 审计日志监听与查询 |

---

## 🗃️ Repository 层

`db-*` feature 下经 `src/dao/repository/` 提供类型化仓储（13 trait），lib.rs 顶层 re-export 其中 9 个 SQLite 实现：

| Re-export | 说明 |
|-----------|------|
| `DbnexusUserRepository` / `DbnexusRoleRepository` / `DbnexusPermissionRepository` | 用户 / 角色 / 权限 |
| `DbnexusUserRoleRepository` / `DbnexusRolePermissionRepository` | 关联表 |
| `DbnexusAuthMethodRepository` / `DbnexusSessionRepository` / `DbnexusLoginLogRepository` / `DbnexusUserExtRepository` | 认证方式 / 会话 / 登录日志 / 扩展字段 |
| `UserIdentifierRepository`（`app_user_identifier`） | 登录标识（phone / email）原子防重注册 |
| `UserDeviceRepository`（`app_user_device`） | 设备注册与 `MAX_DEVICES` 上限 |
| `WebauthnCredentialRepository`（`app_webauthn_credential`） | WebAuthn 凭据绑定与查询 |
| `PasswordHistoryRepository`（`app_password_history`） | 历史密码 hash（`account-policy` 重用拒绝） |
| `RoleHierarchyService` / `RoleHierarchyRecord` | 角色层级（SQL 占位符按后端自适应） |
| `init_dbnexus_with_pool_config(url, PoolConfig)` | 经 dbnexus `DbPoolBuilder` 透传连接池参数（max/min connections、超时） |

协议层补充 re-export：`RefreshTokenRecord` / `RefreshTokenRotation`（`protocol-jwt`）。

---

## 🔑 密码哈希器（`account-credential`）

`account::credential::password` 提供 `PasswordHasher` trait 与内置实现（`config.password_hasher.build_hasher()` 工厂一键构造）：

| API | 说明 |
|-----|------|
| `PasswordHasher::hash(password) / verify(password, hash)` | 同步哈希 / 校验（慢哈希调用点包 `spawn_blocking` 使用） |
| `PasswordHasher::concurrency_gate() -> Option<&Arc<Semaphore>>` | 并发闸门探针（默认 `None`，自定义实现零改动）；返回 `Some` 时由池化封装按 permit 串行化哈希执行 |
| `Argon2Hasher::with_params(m, t, p).with_pool(pool_size)` | Argon2id 哈希器 + 并发令牌池（`pool_size` 0 钳制为 1）；默认无池（向后兼容） |
| `BcryptHasher::with_cost(cost)` | bcrypt 哈希器，**不入池**（单次执行工作区 KB 级，池化无内存防护收益） |
| `PasswordCredential::verify(input)` | 凭证校验：`spawn_blocking` 下沉 + 有池时受 permit 约束；排队不拒绝 |

**并发令牌池行为注记**：permit 在 `spawn_blocking` 前 async 获取并**移入闭包**——permit 存活期 == 哈希执行期，调用方 future 被取消时孤儿 blocking 任务继续持有 permit 直至完成，Argon2 内存驻留上界在任何取消时序下恒等于 `pool_size × m_cost`（不超卖）；等待中的调用异步排队（不拒绝）；信号量 `close()` 后显性返回 `Internal("account-argon2-pool-closed::...")`，不静默成功。池大小经 `password_hasher.argon2_pool_size` 配置（区间 `[1, 256]`，默认 1）。

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
| `OAuth2(String)` | 500 | OAuth2 协议错误（`error_id` 为 `oauth.error`——格式约束不含数字，故模块段用词根 `oauth`） |
| `Network(String)` / `InvalidResponse(String)` | 502 | 网络层 / 上游响应解析失败（语义互斥） |
| `InvalidParam(String)` | 400 | 参数无效 |
| `NotImplemented(String)` | 501 | default 实现未覆盖 |
| `FirewallBlocked(String)` | 403 | 防火墙拦截（携带 strategy 名与原因，供 audit-log 订阅） |
| `DisableService { service, until }` | 403 | 账号封禁（`until = None` 为永久；不泄露 user_id / tenant_id） |
| `NotSafe { reason }` | 400 | 未完成二次认证（如 `MFA_TOTP_REQUIRED`） |
| `InvalidStateTransition { from, to }` | 500 | 状态机非法转换 |
| `SmsRateLimitExceeded { window }` / `SmsVerifyMaxAttempts` / `SmsCodeNotFound` / `SmsChannelRecycled` | 429/400 | 短信验证码（`sms-rate-limit`） |
| `EmailRateLimitExceeded { window }` 等 | 429/400 | 邮箱验证（`email-verification` 门控变体） |
| `RateLimited { retry_after_secs }` | 429 | 网关层限流（携带 `Retry-After` 响应头；`server` 限流中间件与 limiteron 桥接使用） |

### 统一错误响应体（R04）

`GarrisonError` / `GarrisonException` 的 HTTP 错误响应体（三框架 axum / actix-web / warp 形状一致）：

```json
{
  "error_code": "NOT_LOGIN",
  "error_id": "auth.not_login",
  "message": "Not logged in",
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

- `error_code`：**旧码**（`UPPER_SNAKE_CASE`），冻结原值继续输出，不 deprecate。
- `error_id`：**新码**（模块前缀 `<module>.<snake>`），新旧并存；单一事实来源为
  `parts_and_msg_key` 私有函数（逐 arm 显式静态书写，非自动派生）。API 为
  `GarrisonError::prefixed_code()`。
- `request_id`：当前请求的 request id（`X-Request-ID` 中间件注入 task-local）。
  **无 request id 时该字段省略**（omitempty 语义）。
- `Exception` 变体额外含 `code` 字段（`i32` 业务码）。
- `message`：i18n 化通用描述，不含变体 detail（防泄露）。

旧码 → `error_id` 对照表（全量，`Exception` 变体按业务 `code` 三分为 `exception.*`）：

| 旧 error_code | error_id | 旧 error_code | error_id |
|---------------|----------|---------------|----------|
| `NOT_LOGIN` | `auth.not_login` | `NOT_SAFE` | `auth.not_safe` |
| `INVALID_TOKEN` | `auth.invalid_token` | `INVALID_STATE_TRANSITION` | `state.invalid_transition` |
| `TOKEN_REVOKED` | `auth.token_revoked` | `RATE_LIMITED` | `ratelimit.rate_limited` |
| `EXPIRED_TOKEN` | `auth.expired_token` | `SMS_RATE_LIMIT_EXCEEDED` | `sms.rate_limit_exceeded` |
| `NOT_PERMISSION` | `auth.not_permission` | `SMS_VERIFY_MAX_ATTEMPTS` | `sms.verify_max_attempts` |
| `NOT_ROLE` | `auth.not_role` | `SMS_CODE_NOT_FOUND` | `sms.code_not_found` |
| `DAO_ERROR` | `dao.error` | `SMS_CHANNEL_RECYCLED` | `sms.channel_recycled` |
| `CONFIG_ERROR` | `config.error` | `EMAIL_RATE_LIMIT_EXCEEDED` | `email.rate_limit_exceeded` |
| `INTERNAL_ERROR` | `internal.error` | `EMAIL_VERIFY_MAX_ATTEMPTS` | `email.verify_max_attempts` |
| `SESSION_ERROR` | `session.error` | `EMAIL_CODE_NOT_FOUND` | `email.code_not_found` |
| `ANNOTATION_ERROR` | `annotation.error` | `EMAIL_CHANNEL_RECYCLED` | `email.channel_recycled` |
| `CONTEXT_ERROR` | `context.error` | `CREDIT_INSUFFICIENT` | `credit.insufficient` |
| `OAUTH2_ERROR` | `oauth.error` | `NOT_LOGIN`（Exception -1） | `exception.not_login` |
| `NETWORK_ERROR` | `network.error` | `NOT_PERMISSION`（Exception -2） | `exception.not_permission` |
| `INVALID_RESPONSE` | `network.invalid_response` | `EXCEPTION`（其他） | `exception.default` |
| `INVALID_PARAM` | `validation.invalid_param` | | |
| `NOT_IMPLEMENTED` | `internal.not_implemented` | | |
| `FIREWALL_BLOCKED` | `firewall.blocked` | | |
| `DISABLE_SERVICE` | `account.disable_service` | | |

响应头语义（头名为**固定常量，非配置项**，见 ADR-0004）：

| 头 | 语义 | 条件 |
|----|------|------|
| `X-Request-ID` | 回传请求标识（入站合法原样回传；非法/缺失回传生成的 UUID v4） | 挂载 request id 中间件后所有响应 |
| `Retry-After` | delta-seconds 整数秒（下限 1），仅 `RateLimited` 变体 | `retry_after_secs()` 为 `Some` |

入站 `X-Request-ID` 校验（不可信输入）：非空、长度 ≤ 128、全部可见 ASCII
（`0x21..=0x7E`）；CRLF / 非 ASCII / 超长即丢弃重新生成，防 header / 日志注入。

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
| `compliance`（`data-erasure`） | 数据擦除服务与擦除报告 |
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
