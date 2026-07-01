# 安全模块（TOTP / Basic / Digest）

安全模块提供二次认证与 HTTP 认证协议实现，通过 feature 门控。

## 模块总览

| 模块 | Feature | 核心类型 | 依赖 |
|:---|:---|:---|:---|
| TOTP | `secure-totp` | `TotpHandler` | `totp-rs` + `base32` |
| Sign | `secure-sign` | `SignVerifier` trait | `sha2` + `hmac` + `base64` + `md5` |
| HTTP Basic | `secure-httpbasic` | `HttpBasicHandler` | `base64` |
| HTTP Digest | `secure-httpdigest` | `HttpDigestHandler` | `sha2` + `base64` + `md5` |

## TOTP（RFC 6238）

`TotpHandler` 实现时间一次性密码（TOTP），符合 RFC 6238：

```rust
use bulwark::secure::totp::TotpHandler;

let handler = TotpHandler::new(secret_base32)?;
let code = handler.generate_now()?;          // 生成当前 6 位验证码
let ok = handler.verify(&code)?;             // 校验（±1 时间窗口偏差）
```

要点：

- **±1 时间窗口偏差**：允许前后一个 30s 窗口，容忍时钟漂移
- 密钥使用 Base32 编码（依赖 `base32` crate）
- 适用于二步验证（2FA）、MFA 场景
- 与登录流程结合：`check_login` 通过后要求二次 TOTP 校验

## HTTP Basic 认证

`HttpBasicHandler` 实现 RFC 7617 HTTP Basic 认证：

```rust
use bulwark::secure::httpbasic::HttpBasicHandler;

let handler = HttpBasicHandler::new();
let (username, password) = handler.decode("Authorization: Basic dXNlcjpwYXNz")?;
let ok = handler.verify(&username, &password, &verify_fn).await?;
```

- 解析 `Authorization: Basic <base64>` header
- 依赖 `base64` 解码
- 校验逻辑由业务方通过闭包/回调提供

## HTTP Digest 认证

`HttpDigestHandler` 实现 RFC 7616 HTTP Digest 认证：

- 支持 MD5 / SHA-256 摘要（依赖 `sha2` + `md5`）
- 提供 `challenge()` 生成 `WWW-Authenticate` 质询
- `verify()` 校验客户端响应
- 防 replay：nonce + nc 计数

```rust
use bulwark::secure::httpdigest::HttpDigestHandler;

let handler = HttpDigestHandler::new("my-realm");
let challenge = handler.challenge()?;   // 生成质询
let ok = handler.verify(&auth_header, &password_lookup).await?;
```

## SignVerifier trait

`secure-sign` 提供 `SignVerifier` trait，抽象签名校验逻辑，与协议层 `protocol::sign` 配合使用：

- 业务方可实现自定义 `SignVerifier` 接入非 HMAC 签名方案
- 默认实现使用 HMAC-SHA256

## Feature 组合建议

| 场景 | 推荐组合 |
|:---|:---|
| Web 应用 2FA | `secure-totp` |
| 内网 API 网关 | `secure-httpbasic` + `protocol-sign` |
| 兼容遗留系统 | `secure-httpdigest` |
| 全量安全能力 | `secure-totp` + `secure-sign` + `secure-httpbasic` + `secure-httpdigest` |

## 相关章节

- [协议层](./protocols.md)
- [登录认证与会话](./auth-session.md)
