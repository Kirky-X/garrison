//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! HTTP Digest 认证子模块（RFC 7616）。
//!
//! 对应 Digest 认证能力，
//! 基于 `md5` / `sha2` crate 实现摘要认证。
//!
//! - `DigestAlgorithm::default()` 返回 `Sha256`
//! - nonce 格式为 `base64(timestamp:random_uuid)`，validate 时校验时间戳防过期
//! - 支持 `qop=auth` 与 `qop=auth-int`（后者需通过 `validate_with_body` 传入请求体）
//!
//! # 安全说明
//!
//! MD5 算法已被证明存在碰撞攻击，不建议在新系统中使用。
//! 仅在兼容旧客户端时使用 MD5，新系统应使用 SHA256（现为默认值）。

/// Digest 算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// MD5 算法（兼容旧客户端，安全性较弱）。
    Md5,
    /// SHA256 算法（默认值，安全性较高）。
    Sha256,
}

/// `DigestAlgorithm` 实现块（算法名称、摘要计算、字符串解析）。
pub mod algorithm;

/// HTTP Digest 认证工具，封装 RFC 7616 质询生成与响应校验。
///
/// # 示例
///
/// ```
/// #[cfg(feature = "secure-httpdigest")]
/// # {
/// use bulwark::secure::httpdigest::HttpDigestAuth;
///
/// let auth = HttpDigestAuth::new("test@realm", "MD5").unwrap();
/// let challenge = auth.challenge();
/// assert!(challenge.starts_with("Digest "));
/// # }
/// ```
pub struct HttpDigestAuth {
    /// 认证域。
    realm: String,
    /// 摘要算法。
    algorithm: DigestAlgorithm,
    /// nonce 有效期（秒），质询生成时嵌入时间戳，校验时检查是否过期。
    nonce_ttl: u64,
    /// 可选 DAO，用于 nc 单调性校验（vuln-0008 修复，RFC 7616 §3.4.6）。
    ///
    /// - `None`：跳过 nc 重放检测（向后兼容，仅依赖 nonce TTL 防重放）
    /// - `Some(dao)`：在 `validate_inner` 中调用 `validate_nc`，通过 DAO 跟踪
    ///   每个 nonce 的最后 nc 值，拒绝 nc 回退或重复（fail-open on DAO error）
    ///
    /// # Key 格式
    ///
    /// `digest:nc:{nonce}` — value 为最后接受的 nc 十进制字符串。
    /// TTL 与 `nonce_ttl` 一致，nonce 过期后 nc 记录自动清理。
    dao: Option<std::sync::Arc<dyn crate::dao::BulwarkDao>>,
}

/// `HttpDigestAuth` 实现块（质询生成与响应校验）。
pub mod auth;

#[cfg(test)]
mod tests;
