# 协议层（JWT / OAuth2 / SSO / Sign / APIKey / Temp / OIDC / ScopeHandler / SsoServer / Invitation / Social / WebAuthn）

协议层通过 feature 门控，提供主流鉴权协议的签发与校验能力。0.4.0 补齐了 0.2.0 遗留的协议层 gap，
新增 OIDC / ScopeHandler / SsoServer 三项协议能力。

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
| QRLogin | `protocol::qrlogin` | `protocol-qrlogin` | `QrLoginService`（create/scan/confirm/poll 两票分离状态机 + bind_token 双票兑换）+ `QrLoginSessionIssuer` 端口 | Unreleased |
| Invitation | `protocol::invitation` | `protocol-invitation` | `InvitationHandler` + `InvitationSpec`（一次性/N 次、TTL、吊销、防爆破） | — |
| Social | `protocol::social` | 核心无门控；内置 provider 需 `social-wechat` / `social-alipay` | `SocialLoginProvider` trait + `SocialLoginService`（微信/支付宝登录） | 0.5.0 |
| WebAuthn | `protocol::webauthn` | `protocol-webauthn` | `WebauthnService` + `WebauthnCredential`（Passkey 注册/认证仪式） | Unreleased |
<!-- AloneCache 和 ParameterQuery 属于扩展层而非协议层，详见 architecture.md 扩展层章节 -->

## JWT（HS256 / HS384 / HS512 / RS256 / ES256 / EdDSA）

`JwtHandler` 支持 HS256（默认）/HS384/HS512 对称算法（密钥来自 `config.jwt_secret`），并可通过
`with_rsa_private_pem` / `with_ec_pem` / `with_ed_pem` 注入 PEM 私钥启用 RS256/RS384/RS512、
ES256/ES384 与 EdDSA 非对称签名；算法与密钥类型不匹配时 fail-closed 拒绝。config 白名单
（`JWT_ALGORITHMS`）为 HS256/HS384/HS512/RS256/ES256/EdDSA，非对称私钥分别经
`config.jwt_rsa_private_key_pem` / `jwt_ec_private_key_pem` / `jwt_ed_private_key_pem` 配置：

```rust
use garrison::protocol::jwt::JwtHandler;
use jsonwebtoken::Algorithm;

// 链式构造（默认 HS256，可通过 with_algorithm 切换 HS512）
let handler = JwtHandler::new("my-secret-that-is-at-least-32-bytes").with_algorithm(Algorithm::HS512);
// 非对称：JwtHandler::new(secret).with_rsa_private_pem(pem)?.try_with_algorithm(Algorithm::RS256)?
let token = handler.sign("1001", 3600)?;           // 签发（login_id 字符串 + timeout 秒）
let claims = handler.verify(&token)?;            // 校验，返回 GarrisonJwtClaims
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
use garrison::protocol::oauth2::oidc::OidcHandler;
use jsonwebtoken::Algorithm;

// 构造（issuer / audience / secret 三参数，默认 HS256）
let handler = OidcHandler::new(
    "https://auth.example.com",  // issuer
    "my-client-id",              // audience
    "my-secret",                 // HMAC 签名密钥
)?
.with_algorithm(Algorithm::HS256);  // 可选，默认即 HS256

// 签发 id_token（login_id + nonce + scope + timeout 秒）
// 含标准 OIDC claims: iss/sub/aud/exp/iat/nonce/login_id
// login_id 接收 impl Into<String>，需传字符串或 String
let id_token = handler.sign_id_token("1001", "nonce-xyz", "read", 3600)?;

// 验证 id_token（三重校验: iss + aud + nonce，防重放）
let claims = handler.verify_id_token(&id_token, "nonce-xyz")?;

// discovery endpoint 元数据
let metadata = handler.discovery_metadata();
```

**安全约束**：`OidcHandler` 仅支持 HMAC 对称算法（HS256/HS384/HS512）。
`with_algorithm` 接受非对称算法（如 RS256）会在 `sign_id_token` / `verify_id_token` 入口
返回 `GarrisonError::Config` 错误（M4 修复）。

### ScopeHandler（0.4.0 新增，gap #3）

`ScopeHandler` trait + `ScopeRegistry` 提供 OAuth2 scope 校验注册表：

```rust
use garrison::protocol::oauth2::scope::{ScopeHandler, ScopeRegistry};
use garrison::protocol::oauth2::OAuth2Client;
use garrison::error::GarrisonResult;
use std::sync::Arc;

// 业务方实现 ScopeHandler（同步方法，接收 login_id 参数）
struct MyScopeHandler;
impl ScopeHandler for MyScopeHandler {
    fn validate(&self, scope: &str, login_id: i64) -> GarrisonResult<bool> {
        // 返回 Ok(true) 允许，Ok(false) 拒绝，Err 透传错误
        Ok(true)
    }
}

// 注册并注入 OAuth2Client
let registry = ScopeRegistry::new();
registry.register("read", Arc::new(MyScopeHandler));
let client = OAuth2Client::new(
    "client-id", "client-secret", "https://example.com/cb",
    "https://auth.example.com/auth", "https://auth.example.com/token",
)?.with_scope_registry(Arc::new(registry));
// 此后 get_password_token / get_client_credentials_token / refresh_access_token 在 HTTP 请求前委托校验
```

## SSO（ticket 一次性 60s）

`SsoClient` 提供跨系统单点登录的 ticket 机制：

- ticket 一次性使用，TTL 默认 60 秒（`SsoClient::with_ticket_ttl` 可调；`config.sso_ticket_ttl_seconds` 字段当前无消费方、不自动生效，如需随配置调整须自行读取后经 `with_ticket_ttl` 注入）
- 签发 → 校验 → 销毁，校验后立即失效
- `GarrisonSession::link_sso_ticket` 关联 ticket 与会话
- `client_id` 不匹配时返回 `InvalidToken`（M5 修复，原为 `Config`）
- ticket 签名验证（M5 修复）：所有 ticket 包含 HMAC 签名，DAO 被攻破也无法伪造

> ✅ **TOCTOU 竞态已修复**：`SsoClient::validate_ticket` 与 `SsoServer::validate_ticket` 采用相同的两步校验：先验签，随后 `get` 读取票据校验 `client_id`（不消费票据，client_id 不匹配时允许持正确 client_id 的调用方重试），再以 `GarrisonDao::get_and_delete` 原子消费票据。并发调用同一 ticket 时仅一个调用成功。

### SsoServer（0.4.0 新增，gap #5）

`SsoServer` trait 提供独立的服务端抽象，解耦 SSO Server 与 Client 职责：

```rust
use garrison::protocol::sso::server::{DefaultSsoServer, IdentityCenterIdConverter};
use std::sync::Arc;

// DefaultSsoServer::new 接收 dao + HMAC secret（与 SsoClient 必须一致，禁止空字符串）
// converter 通过 with_converter 注入（默认 IdentityCenterIdConverter）
let dao: Arc<dyn garrison::dao::GarrisonDao> = /* ... */;
let server = DefaultSsoServer::new(dao, "sso-hmac-secret")?
    .with_converter(Arc::new(IdentityCenterIdConverter));  // identity 直通映射

// 签发 ticket（login_id 为 &str，client_id 为 i64）
let ticket = server.issue_ticket("1001", 2001).await?;
// 校验 ticket（返回 client_id 对应的 login_id）
let login_id = server.validate_ticket(&ticket, 2001).await?;
```

核心组件：

- `SsoServer` trait：定义 `issue_ticket` / `validate_ticket` / `destroy_ticket` / `push_message` 契约
- `CenterIdConverter` trait：center_id ↔ login_id 映射（`IdentityCenterIdConverter` 直通实现）
- `SsoChannel` trait：服务端推送通道（`NoopSsoChannel` 空实现）
- `DefaultSsoServer`：默认实现，通过共享 `GarrisonDao` 与 `SsoClient` 间接通信

## Sign（HMAC-SHA256 防重放）

`SignHandler` 用于微服务网关签名鉴权：

- HMAC-SHA256 签名请求参数
- 时间窗口防重放，默认 300 秒（`SignHandler::with_timestamp_window` 可调；`config.sign_window_seconds` 字段存在但当前无自动接线，如需随配置生效须自行读取后经 `with_timestamp_window` 注入）
- 超出窗口的请求拒绝，防止重放攻击

## APIKey

`ApiKeyHandler` 提供 API Key 全生命周期管理：

| 操作 | 方法 | 说明 |
|:---|:---|:---|
| 生成 | `generate(login_id, scopes, timeout)` | 为账号生成新 API Key（scopes 作用域列表，timeout 过期秒数），返回 `key_id.key_secret` 双段格式 |
| 校验 | `verify(key)` | 校验有效性并返回 login_id |
| 吊销 | `revoke(key)` | 立即失效 |
| 轮换 | `rotate(old_key)` | 校验旧 Key 后生成新 Key（保留原 login_id/scopes/剩余 TTL）并吊销旧 Key |

## TempCredential（临时凭证）

`TempCredentialHandler` 提供短期临时凭证：

- `issue(prefix, value, ttl_seconds)` 按业务前缀签发临时凭证（value 为任意载荷），返回完整 key（`garrison:temp:<prefix>:<64 位随机 hex>`）
- `get(key)` 查询（不删除）
- `revoke(key)` 主动吊销（幂等）
- `consume(key)` 一次性消费（原子 get_and_delete，使用后失效）
- `GarrisonSession::link_temp_credential` 关联会话

> 以下 AloneCache 和 ParameterQuery 属于 **扩展层**（非协议层），详见 [架构文档](./architecture.md) 扩展层章节。

## AloneCache（0.4.0 新增，gap #6）

`AloneCache` 是 `GarrisonDao` 的装饰器，通过 key_prefix 实现多 Redis 实例隔离：

```rust
use garrison::dao::alone_cache::{AloneCache, AloneCacheManager};

// 包装底层 dao，前缀原样拼接（不自动补 ":"，分隔符需写在前缀里）
let alone = AloneCache::new(inner_dao, "tenant-a:");
// alone.get("user:1") 实际查询 inner_dao.get("tenant-a:user:1")

// AloneCacheManager：多实例管理（RwLock + HashMap）
let manager = AloneCacheManager::new();
manager.register("tenant-a", alone_cache_a);
manager.register("tenant-b", alone_cache_b);
if let Some(cache) = manager.get("tenant-a") {
    // cache: Arc<AloneCache>，可作为 GarrisonDao 使用
    let _ = cache.get("user:1").await?;
}
```

## ParameterQuery（0.4.0 新增，gap #7）

`ParameterQuery` trait + `ParameterQueryBuilder` 提供参数化查询机制，支持 token / login_id
两种上下文，token 优先：

```rust
use garrison::stp::parameter::{ParameterQuery, ParameterQueryBuilder};

// 链式构造（login_id 为 String，与全局 login_id 类型一致）
let builder = ParameterQueryBuilder::new()
    .with_login_id("1001".to_string());

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

## QRLogin 安全语义

扫码登录（QRLogin）的凭证模型与固有风险提示：

- **双票兑换**：`qr_id` 编码在公开可见的二维码票据（`t=` 参数）中；`bind_token`
  作为第二票仅在 create 响应中下发给 Web 端本人。poll 必须出示 `qr_id + bind_token`
  双票方可兑换会话——肩窥/截图二维码者因缺第二票而无法劫持。
- **二维码展示环境需可信**：投影、直播、共享屏幕等场景等同于公开票据（含签名票据
  本身），建议在不可信展示环境提示用户尽快完成或刷新会话（会话 TTL 默认 120s）。
- **login CSRF（固有面）**：任意已登录 App 用户可扫他人屏幕上的二维码并确认，使
  受害者浏览器登录进攻击者账号。App 确认页会下发待登录端脱敏摘要（设备标签 +
  创建时间）供扫码者核对；请引导用户核对后再确认。
- **确认者绑定**：`confirm` 强制确认者身份与扫码者一致（服务端锁定，不信任请求体），
  confirm_token 一次性且 TTL 短（默认 60s）。
