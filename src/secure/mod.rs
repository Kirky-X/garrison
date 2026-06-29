//! 安全模块，提供 TOTP / 签名 / Basic / Digest 验证。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的安全模块（`secure` 包），
//! 提供二步验证、签名校验、HTTP Basic/Digest 认证能力。
//!
//! 此模块仅在启用 `secure-totp` 特性时编译。

use crate::error::BulwarkResult;

/// TOTP 验证器 trait，定义动态验证码校验抽象。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的 TOTP 能力，
/// 通过 `totp-rs` crate 实现基于时间的一次性密码。
pub trait TotpVerifier {
    /// 校验 TOTP 验证码。
    ///
    /// # 参数
    /// - `code`: 用户输入的验证码。
    fn verify_totp(&self, code: &str) -> BulwarkResult<bool> {
        todo!()
    }

    /// 生成当前 TOTP 验证码。
    fn generate_totp(&self) -> BulwarkResult<String> {
        todo!()
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
    fn verify_sign(&self, data: &str, sign: &str, secret: &str) -> BulwarkResult<bool> {
        todo!()
    }

    /// 生成请求签名。
    ///
    /// # 参数
    /// - `data`: 待签名数据。
    /// - `secret`: 签名密钥。
    fn create_sign(&self, data: &str, secret: &str) -> BulwarkResult<String> {
        todo!()
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
