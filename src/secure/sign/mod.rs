//! 签名子模块，请求签名校验实现。
//!
//! [借鉴 Sa-Token] 基于 `sha2` / `hmac` / `base64` 实现，
//! 提供微服务网关签名认证能力。

use crate::error::BulwarkResult;

/// 签名算法枚举。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignAlgorithm {
    /// HMAC-SHA256。
    HmacSha256,
    /// HMAC-SHA512。
    HmacSha512,
    /// SHA256 摘要。
    Sha256,
}

/// 签名校验器，持有算法与密钥。
pub struct SignChecker {
    /// 签名算法。
    pub algorithm: SignAlgorithm,

    /// 签名密钥。
    pub secret: String,
}

impl SignChecker {
    /// 创建新的签名校验器。
    ///
    /// # 参数
    /// - `algorithm`: 签名算法。
    /// - `secret`: 签名密钥。
    pub fn new(algorithm: SignAlgorithm, secret: impl Into<String>) -> Self {
        todo!()
    }

    /// 生成签名。
    ///
    /// # 参数
    /// - `data`: 待签名数据。
    pub fn sign(&self, data: &str) -> BulwarkResult<String> {
        todo!()
    }

    /// 校验签名。
    ///
    /// # 参数
    /// - `data`: 原始数据。
    /// - `sign`: 待校验签名。
    pub fn verify(&self, data: &str, sign: &str) -> BulwarkResult<bool> {
        todo!()
    }
}
