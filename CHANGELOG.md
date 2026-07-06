# Changelog

本文件记录 Bulwark 项目的所有显著变更。

格式基于 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [0.5.0] - 2026-07-06

### 概述

Bulwark 0.5.0 是"生产刚需版"，通过 specmark change
`v0-5-0-production-essentials` 实施多租户隔离、社交登录、审计日志、
RefreshToken Rotation、安全防护套件、角色层级、决策溯源、Keycloak OIDC RP、
SSO TOCTOU 原子化、注解系统、PostgreSQL 后端适配等核心生产能力。

### 新增

#### 多租户隔离

- **`tenant-isolation` feature**：`TENANT` task_local + `TenantContext` +
  `prefixed_key` 函数自动为缓存 key 添加 `tenant:{id}:` 前缀，
  确保多租户数据隔离。`TenantResolution` middleware 从 Header/Query/Token
  解析租户 ID。

#### 社交登录

- **`social-wechat` feature**：`WechatProvider` 实现微信扫码登录，
  支持 access_token 端点 + 用户信息查询。
- **`SocialBindingService`**：社交账号绑定/解绑 + find_or_create 语义。

#### 审计日志

- **`audit-log` feature**：`AuditLogListener` 订阅 14 种 `BulwarkEvent`，
  写入 `audit_logs` 表（含 tenant_id/login_id/event_type/mask_fields 脱敏）。
  `AuditQuery` 支持复合条件查询。

#### RefreshToken Rotation

- **`protocol-jwt`（扩展）**：`RefreshTokenRotation` 服务提供
  `rotate()`（轮换）+ `detect_reuse()`（重用检测）+ `revoke_chain()`（链级吊销）。
  `refresh_tokens` 表使用 SHA-256 hash chain（token_hash + parent_token_hash）。

#### 决策溯源

- **`decision-trace` feature**：`PermissionChecker` trait + `authorize()` API
  返回 `Decision { allowed, reason, errors }`，`DecisionReason` 枚举包含
  `ExplicitAllow`/`ExplicitDeny`/`NoMatchingPermission`/`RoleBased` 等原因。

#### Keycloak OIDC RP

- **`keycloak-oidc` feature**：`KeycloakProvider` 实现 OIDC 依赖方，
  支持 `discover()`（discovery endpoint）+ `exchange_code()`（授权码交换）+
  `verify_id_token()`（JWKS 验签 + KeycloakClaims 解析）。

#### 安全防护套件

- **5 个 FirewallStrategy 实现**：`BruteForceStrategy`/`RateLimitStrategy`/
  `AnomalousLoginStrategy`/`DDoSStrategy`/`GeoIPStrategy`，
  复用 oxcache 作为计数后端。

#### 角色层级

- **`role_hierarchy` 表**：`parents`/`indirect_ancestors` + TC 预计算，
  登录时缓存权限并集。

#### 数据库后端

- **`db-postgres` feature**：PostgreSQL 后端适配，`make_statement`/
  `convert_placeholders` 实现 backend-agnostic SQL。

#### 集成测试

- **4 个端到端集成测试**（`tests/integration_v0_5_0.rs`）：
  多租户隔离+审计日志+决策溯源 / Keycloak OIDC RP 完整流程 /
  RefreshToken Rotation + Reuse Detection / RSA 密钥对 smoke 测试。

#### 示例

- **`v0_5_0_demo` 示例**：演示 v0.5.0 核心生产能力（多租户+审计日志+
  决策溯源+Keycloak RP+微信社交登录配置）。

### 验证

- `cargo test --features "full" --workspace` → 全绿
- `cargo clippy --features "full" --workspace -- -D warnings` → 零警告
- `cargo doc --no-deps --features full --workspace` → 完成

## [0.4.2] - 2026-07-05

### 概述

Bulwark 0.4.2 是 0.4.x 系列的 MINOR 版本，通过 specmark change
`v0-4-2-gap-closure-and-features` 实施 origin 文档与代码实现对齐 gap 闭合 + 新功能增强。
共完成 16 个 Phase（capability），覆盖：LoginId newtype、BulwarkDao 扩展、密码哈希、
Repository 层、密码登录、多账户隔离、JWT 三模式、API Key namespace、SSO TOCTOU 修复、
kickout_by_device、事件扩展、Web 适配器、Strategy 注册表、过程宏注解、OAuth 2.1 PKCE、
Token Introspection。

### 新增

#### 核心类型

- **LoginId newtype（Phase 1）**：`src/stp/login_id.rs` 新增 `LoginId` enum
  （`Numeric(i64)` / `String(String)`），实现 `From<i64>`/`From<String>`/`From<&str>`/
  `as_str`/`as_i64`/`Display`/`Serialize`/`Deserialize`。`stp`/`session`/
  `protocol/{jwt,oauth2,sso,apikey}` 公开方法签名改为 `impl Into<LoginId>`，保留 i64
  通过 `From<i64>` 兼容（`login_id_to_i64` 改 `pub(crate)` 复用）

#### DAO 层（Phase 2）

- **BulwarkDao 4 方法扩展**：新增 `set_permanent`（无 TTL）/`get_timeout`（查询剩余 TTL）/
  `keys`（glob pattern 扫描）/`rename`（重命名 key），均提供默认实现保持向后兼容。
  `BulwarkDaoOxcache` 重写 `set_permanent`/`get_timeout`/`rename` 使用 oxcache 原生 API
  保留 TTL（`set_with_ttl_sync(None)` / `ttl_sync()` / `get→ttl_sync→set_with_ttl_sync→delete`）

#### 安全模块

- **PasswordHasher（Phase 3）**：新增 `secure-password` feature + `PasswordHasher` trait +
  `Argon2Hasher` + `BcryptHasher` + `PasswordVerifier`（自动识别 hash 格式：argon2/bcrypt/BCrypt）。
  依赖 argon2 0.5 + bcrypt 0.15 + rand 0.8
- **JWT 三模式（Phase 7）**：`JwtMode` enum（`Stateless`/`Mixin`/`Simple`），
  `BulwarkLogicDefault::with_jwt_mode` builder，`check_login` 按模式分支：
  Stateless 仅 JWT verify / Mixin JWT+session / Simple 仅 session

#### 数据访问

- **Repository 层（Phase 4）**：`db-sqlite` 启用 `src/dao/repository/` 模块，定义 9 个
  Repository trait（UserRepository/RoleRepository/PermissionRepository/UserRoleRepository/
  RolePermissionRepository/AuthMethodRepository/SessionRepository/LoginLogRepository/
  UserExtRepository），所有方法首参 `tenant_id: i64`。9 个 SqliteRepository 基于 dbnexus
  DbPool + sea-orm 实现

#### 认证路径

- **密码登录（Phase 5）**：`BulwarkLogic::login_with_password(login_id, password)` 默认方法，
  整合 `UserRepository::find_by_username` + `PasswordHasher::verify` + `login`。
  `BulwarkLogicDefault::with_password_hasher` builder 注入 `Arc<dyn PasswordHasher>`
- **多账户 login_type（Phase 6）**：`BulwarkInterface` 新增
  `get_permission_list_with_type(login_id, login_type)` + `get_role_list_with_type`，
  旧方法默认委托（login_type="default"）。`with_login_type` builder

#### 协议层

- **API Key namespace（Phase 8）**：`ApiKeyInfo` 新增 `namespace: String` 字段
  （`#[serde(default = "default_namespace")]` 填充 "default"），key 格式升级为
  `bulwark:apikey:<namespace>:<key>`。`generate_with_namespace` 方法 +
  `list_by_namespace`（依赖 `BulwarkDao::keys`）。`verify` 兼容旧格式
- **SSO TOCTOU 修复（Phase 9）**：`BulwarkDao::get_and_delete(key)` 原子方法（默认实现
  get→delete 两步，`BulwarkDaoOxcache` 用 `parking_lot::Mutex` 保护进程内原子）。
  `SsoClient::validate_ticket` / `DefaultSsoServer::validate_ticket` 改用原子消费消除竞态
- **OAuth 2.1 PKCE（Phase 15）**：`OAuth2Client::generate_pkce_challenge`（S256 方法，
  RFC 7636 测试向量验证）+ `get_auth_url_with_pkce(state, code_verifier)` +
  `exchange_code_with_pkce(code, state, code_verifier)`。旧 `get_auth_url`/`exchange_code`
  标记 `#[deprecated]`
- **Token Introspection（Phase 16）**：`OAuth2Client::introspect_token(token)` 方法
  （RFC 7662），`TokenIntrospectionResponse` struct（12 字段：active/scope/client_id/
  username/token_type/exp/iat/nbf/sub/aud/iss/jti）。`with_introspect_url` builder，
  URL 推导（显式 → token_url 替换 `/token`→`/introspect` → 追加 `/introspect`）

#### 会话管理

- **kickout_by_device（Phase 10）**：`BulwarkSession::kickout_by_device(login_id, device)`
  方法，查询 account session → 过滤 device → 批量 logout_by_token

#### 事件与策略

- **BulwarkEvent 14 变体（Phase 11）**：新增 8 个事件（`LoginFailure`/`TokenRefresh`/
  `TokenRevoke`/`SessionTimeout`/`AccountLocked`/`FirewallBlock`/`ApiKeyRotate`/
  `TempCredentialConsumed`），8 个 broadcast 集成点（login_with_password
  失败/refresh_token/revoke_token/check_login session timeout/FirewallCheckHook 锁定/FirewallStrategy
  阻止/ApiKeyHandler::rotate/TempCredentialHandler::consume）。`BulwarkEvent` 派生
  `PartialEq`。`ConfigReload` 变体因 `ConfigLoader` 无 reload 方法未添加，待 v0.5.0+ 实现
- **Strategy Registry（Phase 13）**：`src/strategy/registry.rs` 新增 6 个策略 trait
  （`LoginHandler`/`LogoutHandler`/`PermissionHandler`/`TokenGenerator`/`SessionCreator`/
  `FirewallStrategy`）+ 6 个默认实现（委托 `Arc<dyn BulwarkLogic>`）+ `Strategy` 注册表
  struct（18 个 register/get/remove 方法）。`BulwarkManager` 持有
  `Arc<RwLock<Strategy>>`，`strategy()` getter + `with_strategy` builder

#### Web 适配器

- **ActixContext + WarpContext（Phase 12）**：新增 `web-actix` 启用
  `src/context/actix_adapter.rs`（`ActixContext`/`ActixRequest`/`ActixResponse`/
  `ActixStorage` 4 件套，34 测试，`ActixRequestWrapper` 私有结构体绕过生命周期限制）。
  新增 `web-warp` 启用 `src/context/warp_adapter.rs`（`WarpContext`/`WarpRequest`/
  `WarpResponse`/`WarpStorage` 4 件套，33 测试，持有 owned 数据）。`strip_bearer_prefix`
  大小写不敏感（RFC 7235）

#### 过程宏

- **bulwark-macros crate（Phase 14）**：新建 workspace member `bulwark-macros`，提供
  `#[check_login]`/`#[check_permission]`/`#[check_role]` 三个 `#[proc_macro_attribute]`。
  `annotation-macros` feature 启用（依赖 `web-axum`）。wrapper + inner function 模式：
  原 fn 重命名为 `__bulwark_inner_<name>`，wrapper 使用原名称返回 `axum::response::Response`。
  `check_login` 特殊处理：Ok(false) → 401，Err → forward。AND 语义：多参数生成多次调用。
  13 个集成测试覆盖 login/permission/role scenarios

### 变更

- `Cargo.toml` version 0.4.1 → 0.4.2
- `Cargo.toml` `[workspace].members` 新增 `"bulwark-macros"`
- `Cargo.toml` 新增 4 个 feature：`secure-password` / `annotation-macros` / `web-actix` /
  `web-warp`，均加入 `full` 聚合
- `Cargo.toml` 新增依赖：argon2 0.5 / bcrypt 0.15 / rand 0.8 / bulwark-macros path 依赖；
  `protocol-oauth2` feature 添加 `sha2` + `base64` 依赖（PKCE S256 复用）
- `BulwarkDao` trait 新增 5 个方法（4 个 Phase 2 + get_and_delete Phase 9），均提供默认
  实现保持向后兼容
- `SsoClient::validate_ticket` / `DefaultSsoServer::validate_ticket` 改用两步法
  （get 校验 client_id → get_and_delete 原子消费），client_id 不匹配时不消费 ticket
- `OAuth2Client::get_auth_url` / `exchange_code` 标记 `#[deprecated]`
- `BulwarkEvent` 派生 `PartialEq`
- `ApiKeyInfo` 新增 `namespace: String` 字段（`#[serde(default)]` 向后兼容）

### 修复

- **SSO validate_ticket spec 冲突解决**：原实现"client_id 不匹配也消费 ticket"（防爆破）
  与测试期望"client_id 不匹配不删除 ticket"（允许重试）冲突。改为两步法：先 `get` 校验
  client_id，匹配后 `get_and_delete` 原子消费。同时满足"用户友好"（错误 client_id 不消费）
  和"TOCTOU 修复"（并发仅一个成功）
- **examples apikey_management MockDao keys() 缺失**：Phase 8 namespace isolation 引入
  `BulwarkDao::keys` 后，`examples/src/apikey_management.rs` 的 MockDao 未实现 `keys()`，
  导致 `ApiKeyHandler::verify` 扫描新格式 key 失败。添加 `keys()` 实现 + `glob_match` 函数
  （与 `tests/protocol_apikey_edge_cases.rs` 保持一致）
- **RFC 7636 测试向量修正**：spec 中 code_verifier `dBjftJeZ4CVP-mB92K29uhjUjUy5YGA`
  （31 字符）不满足 43-128 长度要求，改为 RFC 7636 Appendix B 正确值
  `dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`（43 字符）

### 已知限制

- `BulwarkDao::keys` 默认实现返回 `NotImplemented`，`BulwarkDaoOxcache` 当前也返回
  `NotImplemented`（oxcache 0.3 不支持 key scan，待 v0.5.0+ 升级）
- `BulwarkDao::rename` 默认实现为 get→set_permanent→delete 三步，非原子；
  `BulwarkDaoOxcache` 重写为 get→ttl_sync→set_with_ttl_sync→delete 四步保留 TTL，
  但仍非原子（oxcache 0.3 无原子 rename API，待 v0.5.0+）
- `BulwarkEvent::TokenRevoke` 已在 `revoke_token` 调用时集成 broadcast；
  `ConfigReload` 变体未添加（`ConfigLoader` 无 reload 方法，待 v0.5.0+ 实现后添加变体 + 集成 broadcast）
- `LoginId::String` 形式在内部层（i64）尚未完成迁移，公开 API 接受 `impl Into<LoginId>`
  但 `login_id_to_i64` 对 `String` 形式返回 `BulwarkError::Config`（待 v0.5.0+ 完成内部层迁移）
- Strategy Registry 的 `DefaultFirewallStrategy` 为 no-op（`BulwarkLogic` 无
  `check_login_hooks` 方法），`DefaultTokenGenerator::generate_token` 委托 `logic.login`
  （最接近的方法）
- Token Introspection 不缓存结果（每次调用请求授权服务器，待 v0.5.0+ 加缓存）
- PKCE 仅实现 S256 方法（plain 方法已弃用，不实现）

### 文档与示例

- `bulwark-macros/Cargo.toml` + `bulwark-macros/src/lib.rs` 新建（proc-macro crate
  manifest + 3 个 `#[proc_macro_attribute]` 实现）
- `tests/annotation_macros_integration.rs` 新建（13 个集成测试）
- `examples/src/oauth2_flow.rs` 添加 `#[allow(deprecated)]` 兼容旧 PKCE 方法
- 测试统计：lib 1101 个 + 集成测试 80+ 个，全部通过；clippy 零警告；fmt 通过

## [0.4.0] - 2026-07-02

### 概述

Bulwark 0.4.0 聚焦于 0.2.0 协议层遗留 gap 的补齐。通过 openspec change
`v0-2-0-protocol-layer-gap-closure` 实施 8 项 gap 中的 7 项（gap #4 注解系统因 spec
错误 `OAuth2Client::validate_client_token` 不存在而延后至 0.5.0+）。

### 新增

- **OAuth2 RefreshToken GrantType（gap #1）**：`OAuth2Client::refresh_access_token` 方法
  支持 grant_type=refresh_token 流程，可选 scope 参数（用于缩小/扩大授权范围）
- **OAuth2 OIDC 支持（gap #2）**：新增 `protocol-oidc` feature + `OidcHandler` struct
  （sign_id_token / verify_id_token / discovery_metadata），id_token 含标准 OIDC claims
  （iss/sub/aud/exp/iat/nonce/login_id），三重校验（iss/aud/nonce）防重放
- **OAuth2 Scope Handler 注册表（gap #3）**：新增 `oauth2-scope-handler` feature +
  `ScopeHandler` trait + `ScopeRegistry` struct（parking_lot::RwLock + HashMap），
  `OAuth2Client::with_scope_registry` 注入后 3 个 token 方法在 HTTP 请求前委托校验
- **SSO Server 独立抽象（gap #5）**：新增 `protocol-sso-server` feature + `SsoServer`
  trait + `CenterIdConverter` trait + `SsoChannel` trait + `DefaultSsoServer` +
  `IdentityCenterIdConverter` + `NoopSsoChannel`，支持通过共享 BulwarkDao 与 SsoClient
  间接通信
- **AloneCache 多 Redis 实例隔离（gap #6）**：新增 `alone-cache` feature + `AloneCache`
  装饰器（实现 BulwarkDao，入口拼接 key_prefix 后委托 inner dao）+ `AloneCacheManager`
  （RwLock + HashMap 多实例管理）
- **ParameterQuery 参数化查询（gap #7）**：新增 `parameter-query` feature +
  `ParameterQuery` trait + `ParameterQueryBuilder`（链式 with_login_id/with_device/with_token
  - async check_permission/check_role），token 上下文优先于 login_id

### 变更

- `Cargo.toml` 新增 5 个 feature flag：`protocol-oidc` / `oauth2-scope-handler` /
  `protocol-sso-server` / `alone-cache` / `parameter-query`，均加入 `full` 聚合
- `Cargo.toml` 新增 `base64` dev-dependency（OIDC 测试解析 JWT header 段）
- `OAuth2Client` 新增 `scope_registry: Option<Arc<ScopeRegistry>>` 字段（feature-gated）
- `OAuth2Client` 3 个 token 方法新增 `validate_scope` 调用（feature-gated，未注入跳过）
- `src/protocol/oauth2/mod.rs` 模块文档注释更新（"三种"→"四种"，新增 RefreshToken）
- `openspec/specs/dao-oxcache-basic/spec.md` 新增 Known Limitations 章节：oxcache 0.3
  支持 standalone/sentinel/cluster，master-slave 由 sentinel 模式覆盖

### 修复（代码审查后，全维度 review pass）

- **M5（MEDIUM）**：`SsoClient::validate_ticket` 与 `DefaultSsoServer::validate_ticket` 在
  `client_id` 不匹配时错误类型由 `Config` 改为 `InvalidToken`（认证失败语义更准确，
  票据被错误方持有属于认证失败而非配置错误）。同步修复 2 处集成测试断言
  （`tests/protocol_sso_edge_cases.rs` / `tests/protocol_sso_integration.rs`）
- **M6（MEDIUM）**：`SsoTicketData` 跨 `sso::mod.rs` 与 `sso::server.rs` 重复定义，
  改为 `pub(crate)` 导出 + `use super::SsoTicketData` 复用，避免格式漂移
- **M7（MEDIUM）**：`ParameterQueryBuilder::check_permission` / `check_role` ~40 行重复，
  提取 `check_common` helper + `CheckKind` enum，消除重复
- **M4（MEDIUM）**：`OidcHandler::with_algorithm` 接受非对称算法但实现只支持对称密钥，
  新增 `require_hmac_algorithm()` 在 `sign_id_token` / `verify_id_token` 入口校验，
  非对称算法返回 `Config` 错误。新增 2 个回归测试
  （`sign_id_token_rejects_asymmetric_algorithm` /
  `verify_id_token_rejects_asymmetric_algorithm`）
- **L9（LOW）**：`verify_id_token_tampered_fails` 测试断言过弱（仅 `is_err()`），
  强化断言错误类型为 `InvalidToken`
- **M1（MEDIUM，文档警告）**：SSO `validate_ticket` 的 get→delete 非原子存在 TOCTOU 竞态，
  在 `SsoClient` 与 `SsoServer` trait 的 doc 注释中添加显式警告，待 0.5.0+ 设计原子
  get-and-delete 后统一修复

### 文档与示例（代码审查后补全）

- **examples 覆盖 0.4.0 全部新特性**：新增 5 个 example（`oidc_handler` / `scope_handler` /
  `sso_server` / `alone_cache` / `parameter_query`），每个 bin 配套独立 `tests/<name>.rs`
  测试文件；扩展 `oauth2_flow` 增加 `refresh_access_token` 演示段落
- **examples/Cargo.toml**：新增 5 个 feature 转发（`protocol-oidc` / `oauth2-scope-handler` /
  `protocol-sso-server` / `alone-cache` / `parameter-query`）+ 5 个 `[[bin]]` 段，
  `full` 聚合特性同步更新

### 按规则 7 暴露冲突（不修复）

- **M2/M3（MEDIUM）**：`OAuth2Client::exchange_code` 的 `_state` 参数与
  `OAuth2Client::get_password_token` 的 `_scope` 参数未使用。这是有意保留的
  forward-compat API 参数（doc 注释已说明），移除会破坏 0.4.0 公共 API。维持现状

### 已知限制

- **gap #4（OAuth2 @CheckAccessToken/@CheckClientToken 注解）延后至 0.5.0+**：spec 错误
  引用 `OAuth2Client::validate_client_token`（方法不存在于代码库）。需先设计 token
  introspection（RFC 7662）或复用 OidcHandler::verify_id_token 的方案
- **SSO TOCTOU 竞态（M1）**：`validate_ticket` 的 get→delete 非原子，并发调用同一 ticket
  时理论上可重放。60 秒 TTL 窗口内影响有限，安全敏感场景应通过外层加锁或单点校验保证。
  待 0.5.0+ 设计原子 get-and-delete 后统一修复

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
  - 覆盖式更新 + `reset_for_test()`（cfg(test)）
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
