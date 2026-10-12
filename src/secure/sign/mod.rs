// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 签名工具模块：HMAC-SHA256/SHA512、Base64 编码与签名校验原语。
//!
//! 全部为关联函数（static method），`Signer` 不持有状态，无需实例化。

/// 签名工具（纯静态方法封装，无需实例化）。
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

/// `Signer` 实现块（HMAC / Base64）。
pub mod signer;

#[cfg(test)]
mod tests;
