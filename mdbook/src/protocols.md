# 协议层（JWT / OAuth2 / SSO / Sign / APIKey / Temp）

协议层通过 feature 门控，提供主流鉴权协议的签发与校验能力。

## 模块总览

| 协议 | 模块 | Feature | 核心类型 |
|:---|:---|:---|:---|
| JWT | `protocol::jwt` | `protocol-jwt` | `JwtHandler`（sign / verify / refresh） |
| OAuth2 | `protocol::oauth2` | `protocol-oauth2` | `OAuth2Client`（三种流程） |
| SSO | `protocol::sso` | `protocol-sso` | `SsoClient`（ticket 签发/校验/销毁） |
| Sign | `protocol::sign` | `protocol-sign` | `SignHandler`（HMAC-SHA256 签名） |
| APIKey | `protocol::apikey` | `protocol-apikey` | `ApiKeyHandler`（生成/校验/吊销/轮换） |
| Temp | `protocol::temp` | `protocol-temp` | `TempCredentialHandler`（issue/get/revoke/consume） |

## JWT（HS256 / HS512）

`JwtHandler` 支持 HS256（默认）与 HS512 算法，密钥来自 `config.jwt_secret`：

```rust
use bulwark::protocol::jwt::JwtHandler;

let handler = JwtHandler::new("my-secret", "HS256")?;
let token = handler.sign(claims).await?;     // 签发
let claims = handler.verify(&token).await?;  // 校验
let new_token = handler.refresh(&token).await?;  // 刷新
```

`token_style = "jwt"` 时，`login` 自动使用 `JwtHandler` 生成 token。

## OAuth2

`OAuth2Client` 支持三种流程（依据 spec protocol-oauth2）：

- **Authorization Code**：标准授权码流程，适用于 Web 应用
- **Client Credentials**：机器到机器，无用户参与
- **Password**：资源所有者密码凭证（legacy，不推荐）

依赖 `reqwest`（rustls + rustls-native-certs，无 OpenSSL）。

## SSO（ticket 一次性 60s）

`SsoClient` 提供跨系统单点登录的 ticket 机制：

- ticket 一次性使用，TTL 默认 60 秒（`config.sso_ticket_ttl_seconds`）
- 签发 → 校验 → 销毁，校验后立即失效
- `BulwarkSession::link_sso_ticket` 关联 ticket 与会话

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

## 相关章节

- [安全模块（TOTP/Basic/Digest）](./secure-modules.md)
- [登录认证与会话](./auth-session.md)
