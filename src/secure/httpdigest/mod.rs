// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! HTTP Digest 认证子模块（RFC 7616），基于 `md5` / `sha2` crate 实现摘要认证。
//!
//! `DigestAlgorithm::default()` 为 `Sha256`；nonce 形如 `base64(timestamp:random_uuid)`，validate 校验时间戳防过期；
//! 支持 `qop=auth` 与 `qop=auth-int`（后者经 `validate_with_body` 传入请求体）。
//!
//! # 安全说明
//!
//! MD5 已被证明存在碰撞攻击，新系统须用 SHA256（现为默认）；`MD5` 变体未做 feature 门控，
//! 但构造时输出 `tracing::warn!` 便于审计每次使用，仅限客户端只支持 MD5 时使用。
//!
//! # 重放防护（务必阅读）
//!
//! nonce 本身仅是 `base64(timestamp:uuid)` + TTL（默认 300s），**不防重放**；完整 nc 单调性防护
//! （RFC 7616 §3.4.6）须经 `with_dao` 注入 DAO 才启用：未注入 DAO 时 nc 校验 fail-open（仅进程级 warn 一次），
//! 攻击者可在 TTL 窗口内重放同一 Authorization header；注入 DAO 后 nc 回退/重复被拒绝（fail-closed，DAO 故障即拒绝认证）；
//! 未注入 `server_key` 时 nonce 无 HMAC 签名、客户端可自铸（仍受 TTL 约束）。
//!
//! 生产环境必须 `with_dao(...)` 并强烈建议 `with_server_key(...)`；API 无编译期强制，遗漏只在运行期产生 warn 日志。

/// Digest 算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    /// MD5 算法（安全性较弱，存在碰撞攻击，仅限客户端只支持 MD5 时使用）。
    Md5,
    /// SHA256 算法（默认值，安全性较高）。
    Sha256,
}

/// `DigestAlgorithm` 实现块。
pub mod algorithm;

/// HTTP Digest 认证工具，封装 RFC 7616 质询生成与响应校验。
///
/// # 示例
///
/// ```
/// #[cfg(feature = "protocol-httpdigest")]
/// # {
/// use garrison::secure::httpdigest::HttpDigestAuth;
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
    /// 可选 DAO，用于 nc 单调性校验（RFC 7616 §3.4.6）；行为细节见 `auth::validate_nc`。
    dao: Option<std::sync::Arc<dyn crate::dao::GarrisonDao>>,
    /// 服务端签名密钥（32 字节），为 nonce 附加 HMAC-SHA256 签名：`is_nonce_valid` 先验 HMAC 再校验时间戳，拒绝自铸 nonce。
    ///
    /// 经 `with_server_key` 以 HKDF 从配置密钥派生（复用 protocol-sign 范式）；未注入时 nonce 为无签名格式、仅靠时间戳 TTL，
    /// 生产环境强烈建议注入。
    server_key: Option<[u8; 32]>,
}

/// `HttpDigestAuth` 实现块。
pub mod auth;

#[cfg(test)]
mod tests;
