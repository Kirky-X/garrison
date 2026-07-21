//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 签名工具模块，提供 HMAC-SHA256/SHA512、Base64、MD5 签名与编码工具。
//!
//! 对应 `SaSign` 工具类，
//! 提供微服务网关签名认证所需的加密原语。
//!
//! 所有方法均为关联函数（static method），`Signer` struct 不持有任何状态。

/// 签名工具 struct，纯静态方法封装，不持有任何状态。
///
/// 所有方法为关联函数，无需实例化即可调用：
///
/// ```
/// #[cfg(feature = "secure-sign")]
/// # {
/// use garrison::secure::sign::Signer;
/// let sig = Signer::hmac_sha256(b"secret", b"data");
/// assert_eq!(sig.len(), 64);
/// # }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Signer;

/// `Signer` 实现块（HMAC / Base64 / MD5）。
pub mod signer;

#[cfg(test)]
mod tests;
