//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 安全模块，提供 TOTP / 签名 / Basic / Digest 验证。
//!
//! 对应 安全模块（`secure` 包），
//! 提供二步验证、签名校验、HTTP Basic/Digest 认证能力。
//!
//! 该模块在启用任一 `secure-*` 特性时编译（见 `lib.rs` 的 `#[cfg(any(...))]`）。
//! 0.2.0 已实现全部安全子模块。

use crate::error::{GarrisonError, GarrisonResult};

/// TOTP 验证器 trait，定义动态验证码校验抽象。
///
/// 对应 TOTP 能力，
/// 通过 `totp-rs` crate 实现基于时间的一次性密码。
///
/// # ⚠️ 与 `TotpHandler` 的关系（务必阅读）
///
/// **`totp::TotpHandler` 并未实现本 trait**，本 crate 中也不存在任何
/// `impl TotpVerifier for ...`。两者签名不兼容且语义不同：
///
/// | | `TotpVerifier`（本 trait） | `TotpHandler`（具体实现） |
/// |---|---|---|
/// | 生成 | `generate_totp(&self)`（无参，自取时间） | `generate(&self, now: i64)`（显式传时间戳） |
/// | 校验 | `verify_totp(&self, code: &str)` | `validate(&self, code: &str, now: i64)` |
///
/// 本 trait 是面向业务方的**可替换抽象**（调用方注入自己的 TOTP 实现时使用），
/// `TotpHandler` 是框架内置的**具体实现 API**（自带 now 参数便于测试与多时钟源）。
/// 文档中提及 `TotpHandler` 仅指能力对应关系，不代表类型实现关系。
///
/// # 默认实现的安全语义
///
/// `verify_totp` / `generate_totp` 的默认实现**返回
/// `Err(GarrisonError::NotImplemented)`**（fail-closed：未实现时拒绝而非放行，
/// 不会 fail-open）。这是刻意的设计取舍：trait 方法带默认实现使实现方可以
/// 按需选择实现子集，代价是**没有编译期强制**——忘记覆盖 `verify_totp` 的实现
/// 只会在运行期得到 `NotImplemented` 错误。实现方**必须**覆盖 `verify_totp`，
/// 建议调用方在装配期（启动时）主动调用一次探针校验，及早发现遗漏。
pub trait TotpVerifier {
    /// 校验 TOTP 验证码。
    ///
    /// # 参数
    /// - `code`: 用户输入的验证码。
    ///
    /// # 默认实现
    /// 返回 `Err(GarrisonError::NotImplemented)`（fail-closed，见 trait 文档）。
    fn verify_totp(&self, _code: &str) -> GarrisonResult<bool> {
        Err(GarrisonError::NotImplemented(
            "secure-verify-totp-not-implemented::".to_string(),
        ))
    }

    /// 生成当前 TOTP 验证码。
    ///
    /// # 默认实现
    /// 返回 `Err(GarrisonError::NotImplemented)`（fail-closed，见 trait 文档）。
    fn generate_totp(&self) -> GarrisonResult<String> {
        Err(GarrisonError::NotImplemented(
            "secure-generate-totp-not-implemented::".to_string(),
        ))
    }
}

/// 签名验证器 trait，定义请求签名校验抽象。
///
/// 对应 签名校验能力，
/// 通过 `sha2` / `hmac` / `base64` 实现网关签名认证。
///
/// # ⚠️ 与 `Signer` 的关系（务必阅读）
///
/// **`SignVerifier` 与 `sign::Signer` 是两套独立抽象，本 crate 中不存在任何
/// `impl SignVerifier for Signer`。** 两者参数类型不兼容，不能直接互换：
///
/// | | `SignVerifier`（本 trait） | `sign::Signer`（具体实现） |
/// |---|---|---|
/// | 校验 | `verify_sign(&self, data: &str, sign: &str, secret: &str)` | `verify_hmac_sha256(&self, secret: &[u8], data: &[u8], expected_sig: &str)` |
/// | 签名 | `create_sign(&self, data: &str, secret: &str)` | `sign_hmac_sha256(&self, secret: &[u8], data: &[u8])` |
///
/// 本 trait 面向**文本协议**场景（data/secret 均为 `&str`，如 HTTP 网关签名）；
/// `sign::Signer` 面向**字节流**场景（`&[u8]`，如二进制载荷签名）。
/// 若需用 `Signer` 实现 `SignVerifier`，必须自行做 `&str` → `&[u8]` 适配
/// （`as_bytes()`）并确认 secret 的字节编码一致。`secret: &str` 暴露在 trait
/// 签名中，实现方应注意不要将其写入日志或错误消息。
///
/// # 默认实现的安全语义
///
/// `verify_sign` / `create_sign` 的默认实现**返回
/// `Err(GarrisonError::NotImplemented)`**（fail-closed：未实现时拒绝而非放行）。
/// 这是刻意的设计取舍：**没有编译期强制**——忘记覆盖的实现只会在运行期报错。
/// 实现方**必须**覆盖这两个方法，建议调用方在装配期主动探针校验。
#[cfg(feature = "secure-sign")]
pub trait SignVerifier {
    /// 校验请求签名。
    ///
    /// # 参数
    /// - `data`: 原始数据。
    /// - `sign`: 待校验的签名。
    /// - `secret`: 签名密钥。
    ///
    /// # 默认实现
    /// 返回 `Err(GarrisonError::NotImplemented)`（fail-closed，见 trait 文档）。
    fn verify_sign(&self, _data: &str, _sign: &str, _secret: &str) -> GarrisonResult<bool> {
        Err(GarrisonError::NotImplemented(
            "secure-verify-sign-not-implemented::".to_string(),
        ))
    }

    /// 生成请求签名。
    ///
    /// # 参数
    /// - `data`: 待签名数据。
    /// - `secret`: 签名密钥。
    ///
    /// # 默认实现
    /// 返回 `Err(GarrisonError::NotImplemented)`（fail-closed，见 trait 文档）。
    fn create_sign(&self, _data: &str, _secret: &str) -> GarrisonResult<String> {
        Err(GarrisonError::NotImplemented(
            "secure-create-sign-not-implemented::".to_string(),
        ))
    }
}

// ====================================================================
// 安全子模块（特性门控）
// ====================================================================

/// TOTP 子模块，时间一次性密码实现。
#[cfg(feature = "secure-totp")]
pub mod totp;

/// 签名子模块，请求签名校验实现。
#[cfg(feature = "secure-sign")]
pub mod sign;

/// HTTP Basic 认证子模块。
#[cfg(feature = "protocol-httpbasic")]
pub mod httpbasic;

/// HTTP Digest 认证子模块。
#[cfg(feature = "protocol-httpdigest")]
pub mod httpdigest;

/// Unicode 同形异义字检测子模块。
///
/// 提供 [`check_confusable`](confusable::check_confusable) 函数，检测字符串中的 Unicode
/// 同形异义字（homoglyphs）。启用 `secure-confusable` feature 后，
/// `PermissionRegistry::register` 会自动调用检测可疑 permission name。
#[cfg(feature = "secure-confusable")]
pub mod confusable;

/// 敏感数据脱敏子模块。
///
/// 提供 [`SensitiveDataMasker`](masking::SensitiveDataMasker) 对手机号 / 身份证 / 邮箱 /
/// 银行卡等敏感字段进行脱敏，支持对 `serde_json::Value` 递归脱敏。
#[cfg(feature = "secure-masking")]
pub mod masking;

/// XSS 防护子模块。
///
/// 提供 [`XssProtector`](xss::XssProtector) 对 HTML 输入进行转义/白名单过滤，
/// 防止 XSS 攻击。零外部依赖。
#[cfg(feature = "secure-xss")]
pub mod xss;

/// SMS 验证码渐进式限速子模块。
///
/// 提供 [`SmsVerificationService`](sms::SmsVerificationService) 三层抽象：
/// - `SmsSender` trait（业务方实现短信发送）
/// - `SmsRateLimiter`（双窗口限速：小时 + 天）
/// - `SmsVerificationService`（发送/验证/异常发送检测）
#[cfg(feature = "sms-rate-limit")]
pub mod sms;

/// 邮箱验证码子模块。
///
/// 提供 [`EmailVerificationService`](email::EmailVerificationService) 三层抽象：
/// - `EmailSender` trait（业务方实现邮件发送，`email-verification-smtp` feature 提供内置 SMTP 实现）
/// - `EmailRateLimiter`（双窗口限速：小时 + 天，含邮箱规范化）
/// - `EmailVerificationService`（发送/验证/异常发送检测）
#[cfg(feature = "email-verification")]
pub mod email;

/// 通用输入消毒子模块。
///
/// 提供 `sanitize::sanitize_input` 对用户输入进行通用消毒：
/// 移除 null 字节、控制字符，trim 空白，限制长度。零外部依赖。
#[cfg(feature = "secure-sanitize")]
pub mod sanitize;

/// 常量时间比较原语子模块（CWE-208 防御）。
///
/// 提供 `crate::secure::ct_eq::constant_time_eq` 函数，基于 `subtle::ConstantTimeEq`
/// 实现字节级常量时间比较，防止时序侧信道。供 `audit-log` / `oauth2-server` 等需要
/// 常量时间比较的 feature 复用，避免在各模块重复实现（规则 7 先读再写）。
#[cfg(feature = "secure-ct-eq")]
pub mod ct_eq;

#[cfg(test)]
mod tests {
    use super::*;

    /// TotpVerifier trait default verify_totp 返回 NotImplemented 错误（spec: 占位实现）。
    #[test]
    fn totp_verifier_default_verify_returns_not_implemented() {
        struct MockTotpVerifier;
        impl TotpVerifier for MockTotpVerifier {}
        let v = MockTotpVerifier;
        let result = v.verify_totp("123456");
        assert!(matches!(result, Err(GarrisonError::NotImplemented(_))));
    }

    /// TotpVerifier trait default generate_totp 返回 NotImplemented 错误（spec: 占位实现）。
    #[test]
    fn totp_verifier_default_generate_returns_not_implemented() {
        struct MockTotpVerifier;
        impl TotpVerifier for MockTotpVerifier {}
        let v = MockTotpVerifier;
        let result = v.generate_totp();
        assert!(matches!(result, Err(GarrisonError::NotImplemented(_))));
    }

    /// SignVerifier trait default verify_sign 返回 NotImplemented 错误（spec: 占位实现）。
    #[cfg(feature = "secure-sign")]
    #[test]
    fn sign_verifier_default_verify_returns_not_implemented() {
        struct MockSignVerifier;
        impl SignVerifier for MockSignVerifier {}
        let v = MockSignVerifier;
        let result = v.verify_sign("data", "sign", "secret");
        assert!(matches!(result, Err(GarrisonError::NotImplemented(_))));
    }

    /// SignVerifier trait default create_sign 返回 NotImplemented 错误（spec: 占位实现）。
    #[cfg(feature = "secure-sign")]
    #[test]
    fn sign_verifier_default_create_returns_not_implemented() {
        struct MockSignVerifier;
        impl SignVerifier for MockSignVerifier {}
        let v = MockSignVerifier;
        let result = v.create_sign("data", "secret");
        assert!(matches!(result, Err(GarrisonError::NotImplemented(_))));
    }
}
