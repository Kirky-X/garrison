//! 安全模块，提供 TOTP / 签名 / Basic / Digest 验证。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的安全模块（`secure` 包），
//! 提供二步验证、签名校验、HTTP Basic/Digest 认证能力。
//!
//! 该模块在启用任一 `secure-*` 特性时编译（见 `lib.rs` 的 `#[cfg(any(...))]`）。
//! 0.2.0 已实现全部安全子模块。

use crate::error::{BulwarkError, BulwarkResult};

/// TOTP 验证器 trait，定义动态验证码校验抽象。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的 TOTP 能力，
/// 通过 `totp-rs` crate 实现基于时间的一次性密码。
///
/// 具体实现见 `totp::TotpHandler`（启用 `secure-totp` 特性）。
pub trait TotpVerifier {
    /// 校验 TOTP 验证码。
    ///
    /// # 参数
    /// - `code`: 用户输入的验证码。
    fn verify_totp(&self, _code: &str) -> BulwarkResult<bool> {
        Err(BulwarkError::NotImplemented(
            "verify_totp 未实现".to_string(),
        ))
    }

    /// 生成当前 TOTP 验证码。
    fn generate_totp(&self) -> BulwarkResult<String> {
        Err(BulwarkError::NotImplemented(
            "generate_totp 未实现".to_string(),
        ))
    }
}

/// 签名验证器 trait，定义请求签名校验抽象。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的签名校验能力，
/// 通过 `sha2` / `hmac` / `base64` 实现网关签名认证。
#[cfg(feature = "secure-sign")]
pub trait SignVerifier {
    /// 校验请求签名。
    ///
    /// # 参数
    /// - `data`: 原始数据。
    /// - `sign`: 待校验的签名。
    /// - `secret`: 签名密钥。
    fn verify_sign(&self, _data: &str, _sign: &str, _secret: &str) -> BulwarkResult<bool> {
        Err(BulwarkError::NotImplemented(
            "verify_sign 未实现".to_string(),
        ))
    }

    /// 生成请求签名。
    ///
    /// # 参数
    /// - `data`: 待签名数据。
    /// - `secret`: 签名密钥。
    fn create_sign(&self, _data: &str, _secret: &str) -> BulwarkResult<String> {
        Err(BulwarkError::NotImplemented(
            "create_sign 未实现".to_string(),
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
#[cfg(feature = "secure-httpbasic")]
pub mod httpbasic;

/// HTTP Digest 认证子模块。
#[cfg(feature = "secure-httpdigest")]
pub mod httpdigest;

/// 密码哈希子模块（0.4.2 新增，依据 spec secure-password）。
///
/// 提供 `PasswordHasher` trait + `Argon2Hasher` / `BcryptHasher` 实现 + `PasswordVerifier` 自动识别。
#[cfg(feature = "secure-password")]
pub mod password;

/// Unicode 同形异义字检测子模块（0.5.1 新增，依据 design.md D10，L6）。
///
/// 提供 [`check_confusable`](confusable::check_confusable) 函数，检测字符串中的 Unicode
/// 同形异义字（homoglyphs）。启用 `secure-confusable` feature 后，
/// `PermissionRegistry::register` 会自动调用检测可疑 permission name。
#[cfg(feature = "secure-confusable")]
pub mod confusable;

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
        assert!(matches!(result, Err(BulwarkError::NotImplemented(_))));
    }

    /// TotpVerifier trait default generate_totp 返回 NotImplemented 错误（spec: 占位实现）。
    #[test]
    fn totp_verifier_default_generate_returns_not_implemented() {
        struct MockTotpVerifier;
        impl TotpVerifier for MockTotpVerifier {}
        let v = MockTotpVerifier;
        let result = v.generate_totp();
        assert!(matches!(result, Err(BulwarkError::NotImplemented(_))));
    }

    /// SignVerifier trait default verify_sign 返回 NotImplemented 错误（spec: 占位实现）。
    #[cfg(feature = "secure-sign")]
    #[test]
    fn sign_verifier_default_verify_returns_not_implemented() {
        struct MockSignVerifier;
        impl SignVerifier for MockSignVerifier {}
        let v = MockSignVerifier;
        let result = v.verify_sign("data", "sign", "secret");
        assert!(matches!(result, Err(BulwarkError::NotImplemented(_))));
    }

    /// SignVerifier trait default create_sign 返回 NotImplemented 错误（spec: 占位实现）。
    #[cfg(feature = "secure-sign")]
    #[test]
    fn sign_verifier_default_create_returns_not_implemented() {
        struct MockSignVerifier;
        impl SignVerifier for MockSignVerifier {}
        let v = MockSignVerifier;
        let result = v.create_sign("data", "secret");
        assert!(matches!(result, Err(BulwarkError::NotImplemented(_))));
    }
}
