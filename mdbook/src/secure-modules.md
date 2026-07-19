# 安全模块（TOTP / Basic / Digest / Sign）

安全模块提供二次认证、HTTP 认证协议、签名校验等能力，通过 feature 门控。

## 模块总览

| 模块 | Feature | 核心类型 | 依赖 |
|:---|:---|:---|:---|
| TOTP | `secure-totp` | `TotpHandler` | `totp-rs` + `base32` |
| Sign | `secure-sign` | `Signer` / `SignVerifier` trait | `sha2` + `hmac` + `base64` + `md5` |
| HTTP Basic | `secure-httpbasic` | `HttpBasicAuth` | `base64` |
| HTTP Digest | `secure-httpdigest` | `HttpDigestAuth` | `sha2` + `base64` + `md5` |
| Unicode 同形字 | `secure-confusable` | `check_confusable` 函数 | `unicode-security` |
| 敏感数据脱敏 | `secure-masking` | `SensitiveDataMasker` | `serde_json` |
| XSS 防护 | `secure-xss` | `XssProtector` | 零外部依赖 |
| SMS 验证码 | `sms-rate-limit` | `SmsVerificationService` | `sha2` + `base64` |
| 输入消毒 | `secure-sanitize` | `sanitize_input` 函数 | 零外部依赖 |

## TOTP（RFC 6238）

`TotpHandler` 实现时间一次性密码（TOTP），符合 RFC 6238：

```rust
use bulwark::secure::totp::TotpHandler;

let secret = b"12345678901234567890".to_vec();
let handler = TotpHandler::new(secret, 30, 6)?;  // (密钥字节, step, digits)
let code = handler.generate(1700000000);          // 生成当前 6 位验证码（传入 Unix 时间戳）
let ok = handler.validate(&code, 1700000000);     // 校验（±1 时间窗口偏差），返回 bool
```

要点：

- **构造参数**：`new(secret: Vec<u8>, step: u64, digits: u32)` —— 接收原始密钥字节、时间步长、位数
- **`generate(now: i64) -> String`**：传入 Unix 时间戳（秒），返回指定位数的验证码
- **`validate(code: &str, now: i64) -> bool`**：校验验证码，允许 ±1 时间窗口偏差
- **`validate_and_consume(login_id, code, now, dao)`**：在 `validate` 基础上通过 DAO 原子 `incr` 防重放
- **`secret_from_base32(s: &str)`**：将 Base32 编码的密钥解码为原始字节
- 使用 SHA1 算法（RFC 6238 默认，兼容主流 Authenticator App）
- 适用于二步验证（2FA）、MFA 场景

## HTTP Basic 认证

`HttpBasicAuth` 实现 RFC 7617 HTTP Basic 认证（unit struct，所有方法为关联函数）：

```rust
use bulwark::secure::httpbasic::HttpBasicAuth;

// 编码：返回 Base64 字符串（不含 Basic 前缀）
let encoded = HttpBasicAuth::encode("alice", "secret");

// 解码：接收 Base64 字符串，返回 Credential { user, pass }
let cred = HttpBasicAuth::decode(&encoded)?;
assert_eq!(cred.user, "alice");
assert_eq!(cred.pass, "secret");

// 从完整 Authorization header 解析（自动剥离 "Basic " 前缀）
let cred = HttpBasicAuth::parse_authorization_header("Basic YWxpY2U6c2VjcmV0")?;
```

- `encode(user, pass) -> String`：Base64 编码
- `decode(header_value) -> BulwarkResult<Credential>`：解码 Base64 凭证（不含 `Basic` 前缀）
- `parse_authorization_header(header) -> BulwarkResult<Credential>`：从完整 Authorization header 解析（scheme 大小写不敏感）
- 依赖 `base64` 解码
- **无 `new()` / `verify()` 方法**：校验逻辑由业务方自行实现（对比 `Credential.user` / `Credential.pass`）

## HTTP Digest 认证

`HttpDigestAuth` 实现 RFC 7616 HTTP Digest 认证：

- 支持 MD5 / SHA-256 摘要（依赖 `sha2` + `md5`），默认 SHA-256
- `challenge()` 生成 `WWW-Authenticate` 质询
- `validate()` / `validate_with_body()` 校验客户端响应（后者用于 `qop=auth-int`）
- 防 replay：nonce 内嵌时间戳 + 可选 nc 单调性校验（注入 DAO 后启用）

```rust
use bulwark::secure::httpdigest::HttpDigestAuth;

let auth = HttpDigestAuth::new("test@realm", "MD5")?;   // (realm, algorithm_str)
let challenge = auth.challenge();                        // 生成质询（返回 String，非 Result）
assert!(challenge.starts_with("Digest "));
```

- **构造参数**：`new(realm: &str, algorithm_str: &str)` —— 接收 realm 与算法字符串（`"MD5"` / `"SHA-256"`）
- **nonce 格式**：`base64(timestamp:random_uuid)`，`validate` 时校验时间戳防过期
- **`qop=auth` 与 `qop=auth-int`**：后者需通过 `validate_with_body` 传入请求体
- **nc 重放检测**：注入 DAO 后启用，key 格式 `digest:nc:{nonce}`，TTL 与 `nonce_ttl` 一致

## Signer 与 SignVerifier

`secure-sign` 提供 `Signer` struct（unit struct，纯静态方法）与 `SignVerifier` trait：

```rust
use bulwark::secure::sign::Signer;

let sig = Signer::hmac_sha256(b"secret", b"data");    // 64 字符小写十六进制
let ok = Signer::verify_hmac_sha256(b"secret", b"data", &sig);  // 常量时间校验
```

- `Signer::hmac_sha256(secret, data) -> String`：HMAC-SHA256 签名（小写十六进制）
- `Signer::verify_hmac_sha256(secret, data, expected_sig) -> bool`：常量时间校验（防时序侧信道）
- `Signer` 还提供 SHA-512 / Base64 / MD5 等关联函数
- `SignVerifier` trait：抽象签名校验逻辑（`verify_sign` / `create_sign`），供业务方实现非 HMAC 方案

## 其他子模块

| 子模块 | Feature | 说明 |
|:---|:---|:---|
| `confusable` | `secure-confusable` | Unicode 同形异义字检测（homoglyphs），`PermissionRegistry::register` 自动调用 |
| `masking` | `secure-masking` | 敏感数据脱敏（手机号 / 身份证 / 邮箱 / 银行卡），支持 `serde_json::Value` 递归脱敏 |
| `xss` | `secure-xss` | XSS 防护（HTML 转义 / 白名单过滤），零外部依赖 |
| `sms` | `sms-rate-limit` | SMS 验证码三层抽象：`SmsSender` trait / `SmsRateLimiter`（双窗口限速）/ `SmsVerificationService` |
| `sanitize` | `secure-sanitize` | 通用输入消毒（null 字节 / 控制字符 / 长度限制），零外部依赖 |

## Feature 组合建议

| 场景 | 推荐组合 |
|:---|:---|
| Web 应用 2FA | `secure-totp` |
| 内网 API 网关 | `secure-httpbasic` + `secure-sign` |
| 兼容遗留系统 | `secure-httpdigest` |
| 全量安全能力 | `secure-totp` + `secure-sign` + `secure-httpbasic` + `secure-httpdigest` + `secure-sanitize` + `secure-xss` |
| SMS 验证码业务 | `sms-rate-limit` |

## 相关章节

- [协议层](./protocols.md)
- [登录认证与会话](./auth-session.md)
