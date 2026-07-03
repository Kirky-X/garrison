# 协议层（JWT / OAuth2 / SSO / Sign / APIKey / Temp / OIDC / ScopeHandler / SsoServer）

协议层通过 feature 门控，提供主流鉴权协议的签发与校验能力。0.4.0 补齐了 0.2.0 遗留的协议层 gap，
新增 OIDC / ScopeHandler / SsoServer 三项协议能力，以及 AloneCache / ParameterQuery 两项扩展能力。

## 模块总览

| 协议 | 模块 | Feature | 核心类型 | 引入版本 |
|:---|:---|:---|:---|:---|
| JWT | `protocol::jwt` | `protocol-jwt` | `JwtHandler`（sign / verify / refresh） | 0.2.0 |
| OAuth2 | `protocol::oauth2` | `protocol-oauth2` | `OAuth2Client`（四种流程，含 RefreshToken） | 0.2.0（0.4.0 扩展） |
| SSO | `protocol::sso` | `protocol-sso` | `SsoClient`（ticket 签发/校验/销毁） | 0.2.0 |
| Sign | `protocol::sign` | `protocol-sign` | `SignHandler`（HMAC-SHA256 签名） | 0.2.0 |
| APIKey | `protocol::apikey` | `protocol-apikey` | `ApiKeyHandler`（生成/校验/吊销/轮换） | 0.2.0 |
| Temp | `protocol::temp` | `protocol-temp` | `TempCredentialHandler`（issue/get/revoke/consume） | 0.2.0 |
| OIDC | `protocol::oauth2::oidc` | `protocol-oidc` | `OidcHandler`（sign_id_token / verify_id_token / discovery） | 0.4.0 |
| ScopeHandler | `protocol::oauth2::scope` | `oauth2-scope-handler` | `ScopeHandler` trait + `ScopeRegistry` | 0.4.0 |
| SsoServer | `protocol::sso::server` | `protocol-sso-server` | `SsoServer` trait + `DefaultSsoServer` + `CenterIdConverter` | 0.4.0 |
| AloneCache | `dao::alone_cache` | `alone-cache` | `AloneCache` 装饰器 + `AloneCacheManager` | 0.4.0 |
| ParameterQuery | `stp::parameter` | `parameter-query` | `ParameterQuery` trait + `ParameterQueryBuilder` | 0.4.0 |

## JWT（HS256 / HS512）

`JwtHandler` 支持 HS256（默认）与 HS512 算法，密钥来自 `config.jwt_secret`：

```rust
use bulwark::protocol::jwt::JwtHandler;
use jsonwebtoken::Algorithm;

// 链式构造（默认 HS256，可通过 with_algorithm 切换 HS512）
let handler = JwtHandler::new("my-secret").with_algorithm(Algorithm::HS512);
let token = handler.sign(1001, 3600)?;           // 签发（login_id + timeout 秒）
let claims = handler.verify(&token)?;            // 校验，返回 BulwarkJwtClaims
let new_token = handler.refresh(&token, 3600)?;  // 刷新（新 timeout）
```

`token_style = "jwt"` 时，`login` 自动使用 `JwtHandler` 生成 token。

## OAuth2

`OAuth2Client` 支持四种流程（依据 spec protocol-oauth2，0.4.0 新增 RefreshToken）：

- **Authorization Code**：标准授权码流程，适用于 Web 应用
- **Client Credentials**：机器到机器，无用户参与
- **Password**：资源所有者密码凭证（legacy，不推荐）
- **RefreshToken**（0.4.0 新增）：通过 `refresh_access_token(refresh_token, scope)` 刷新过期 token，
  可选 `scope` 参数缩小/扩大授权范围

依赖 `reqwest`（rustls + rustls-native-certs，无 OpenSSL）。

### OIDC（0.4.0 新增，gap #2）

`OidcHandler` 提供 OpenID Connect id_token 签发与验证能力，依赖 `protocol-jwt` + `protocol-oauth2`：

```rust
use bulwark::protocol::oauth2::oidc::OidcHandler;
use jsonwebtoken::Algorithm;

// 构造（issuer / audience / secret 三参数，默认 HS256）
let handler = OidcHandler::new(
    "https://auth.example.com",  // issuer
    "my-client-id",              // audience
    "my-secret",                 // HMAC 签名密钥
)
.with_algorithm(Algorithm::HS256);  // 可选，默认即 HS256

// 签发 id_token（login_id + nonce + scope + timeout 秒）
// 含标准 OIDC claims: iss/sub/aud/exp/iat/nonce/login_id
let id_token = handler.sign_id_token(1001, "nonce-xyz", "read", 3600)?;

// 验证 id_token（三重校验: iss + aud + nonce，防重放）
let claims = handler.verify_id_token(&id_token, "nonce-xyz")?;

// discovery endpoint 元数据
let metadata = handler.discovery_metadata();
```

**安全约束**：`OidcHandler` 仅支持 HMAC 对称算法（HS256/HS384/HS512）。
`with_algorithm` 接受非对称算法（如 RS256）会在 `sign_id_token` / `verify_id_token` 入口
返回 `BulwarkError::Config` 错误（M4 修复）。

### ScopeHandler（0.4.0 新增，gap #3）

`ScopeHandler` trait + `ScopeRegistry` 提供 OAuth2 scope 校验注册表：

```rust
use bulwark::protocol::oauth2::scope::{ScopeHandler, ScopeRegistry};
use bulwark::protocol::oauth2::OAuth2Client;
use async_trait::async_trait;
use bulwark::error::BulwarkResult;
use std::sync::Arc;

// 业务方实现 ScopeHandler
struct MyScopeHandler;
#[async_trait]
impl ScopeHandler for MyScopeHandler {
    async fn validate(&self, scope: &str) -> BulwarkResult<()> { /* ... */ Ok(()) }
}

// 注册并注入 OAuth2Client
let mut registry = ScopeRegistry::new();
registry.register("read", Arc::new(MyScopeHandler));
let client = OAuth2Client::new(
    "client-id", "client-secret", "https://example.com/cb",
    "https://auth.example.com/auth", "https://auth.example.com/token",
)?.with_scope_registry(Arc::new(registry));
// 此后 exchange_code / get_client_credentials_token / get_password_token 在 HTTP 请求前委托校验
```

## SSO（ticket 一次性 60s）

`SsoClient` 提供跨系统单点登录的 ticket 机制：

- ticket 一次性使用，TTL 默认 60 秒（`config.sso_ticket_ttl_seconds`）
- 签发 → 校验 → 销毁，校验后立即失效
- `BulwarkSession::link_sso_ticket` 关联 ticket 与会话
- `client_id` 不匹配时返回 `InvalidToken`（M5 修复，原为 `Config`）

> ⚠️ **TOCTOU 竞态限制（M1）**：`validate_ticket` 的 get→delete 非原子，并发调用同一
> ticket 时理论上可重放。60 秒 TTL 窗口内影响有限，安全敏感场景应通过外层加锁或单点
> 校验保证。待 0.5.0+ 设计原子 get-and-delete 后统一修复。

### SsoServer（0.4.0 新增，gap #5）

`SsoServer` trait 提供独立的服务端抽象，解耦 SSO Server 与 Client 职责：

```rust
use bulwark::protocol::sso::server::{DefaultSsoServer, IdentityCenterIdConverter};
use std::sync::Arc;

// DefaultSsoServer::new 只接收 dao，converter 通过 with_converter 注入
let dao: Arc<dyn bulwark::dao::BulwarkDao> = /* ... */;
let server = DefaultSsoServer::new(dao)
    .with_converter(Arc::new(IdentityCenterIdConverter));  // identity 直通映射

// 签发 ticket（client_id 视角）
let ticket = server.issue_ticket(1001, 2001).await?;
// 校验 ticket（返回 client_id 对应的 login_id）
let login_id = server.validate_ticket(&ticket, 2001).await?;
```

核心组件：

- `SsoServer` trait：定义 `issue_ticket` / `validate_ticket` / `destroy_ticket` 契约
- `CenterIdConverter` trait：center_id ↔ login_id 映射（`IdentityCenterIdConverter` 直通实现）
- `SsoChannel` trait：服务端推送通道（`NoopSsoChannel` 空实现）
- `DefaultSsoServer`：默认实现，通过共享 `BulwarkDao` 与 `SsoClient` 间接通信

## Sign（HMAC-SHA256 防重放）

`SignHandler` 用于微服务网关签名鉴权：

- HMAC-SHA256 签名请求参数
- 时间窗口防重放，默认 300 秒（`config.sign_window_seconds`）
- 超出窗口的请求拒绝，防止重放攻击

## APIKey

`ApiKeyHandler` 提供 API Key 全生命周期管理：

| 操作 | 方法 | 说明 |
|:---|:---|:---|
| 生成 | `generate(login_id)` | 为账号生成新 API Key |
| 校验 | `verify(key)` | 校验有效性并返回 login_id |
| 吊销 | `revoke(key)` | 立即失效 |
| 轮换 | `rotate(login_id)` | 生成新 Key 并吊销旧 Key |

## TempCredential（临时凭证）

`TempCredentialHandler` 提供短期临时凭证：

- `issue(login_id, ttl)` 签发临时凭证
- `get(token)` 查询
- `revoke(token)` 主动吊销
- `consume(token)` 一次性消费（使用后失效）
- `BulwarkSession::link_temp_credential` 关联会话

## AloneCache（0.4.0 新增，gap #6）

`AloneCache` 是 `BulwarkDao` 的装饰器，通过 key_prefix 实现多 Redis 实例隔离：

```rust
use bulwark::dao::alone_cache::{AloneCache, AloneCacheManager};

// 包装底层 dao，所有 key 自动拼接 "prefix:" 前缀
let alone = AloneCache::new(inner_dao, "tenant-a");
// alone.get("user:1") 实际查询 inner_dao.get("tenant-a:user:1")

// AloneCacheManager：多实例管理（RwLock + HashMap）
let manager = AloneCacheManager::new();
manager.register("tenant-a", alone_cache_a);
manager.register("tenant-b", alone_cache_b);
if let Some(cache) = manager.get("tenant-a") {
    // cache: Arc<AloneCache>，可作为 BulwarkDao 使用
    let _ = cache.get("user:1").await?;
}
```

## ParameterQuery（0.4.0 新增，gap #7）

`ParameterQuery` trait + `ParameterQueryBuilder` 提供参数化查询机制，支持 token / login_id
两种上下文，token 优先：

```rust
use bulwark::stp::parameter::{ParameterQuery, ParameterQueryBuilder};

// 链式构造
let builder = ParameterQueryBuilder::new()
    .with_login_id(1001);

// async check_permission / check_role
builder.check_permission("user:read").await?;
builder.check_role("admin").await?;

// 也可注入 token 上下文（优先于 login_id）
let builder = ParameterQueryBuilder::new()
    .with_token("some-token-string");
builder.check_permission("user:write").await?;
```

`check_permission` 与 `check_role` 内部通过 `check_common` helper 委托（M7 修复，消除重复）。

## 相关章节

- [安全模块（TOTP/Basic/Digest）](./secure-modules.md)
- [登录认证与会话](./auth-session.md)
- [整体架构](./architecture.md)
