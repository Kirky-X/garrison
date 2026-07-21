//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `DigestAlgorithm` 实现块，封装算法名称、摘要计算与字符串解析。

use super::DigestAlgorithm;
use crate::error::{GarrisonError, GarrisonResult};
use std::str::FromStr;

/// 将字节数组编码为小写 hex 字符串。
pub(super) fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

impl DigestAlgorithm {
    /// 返回算法名称字符串。
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Sha256 => "SHA256",
        }
    }

    /// 计算给定数据的摘要（hex 输出）。
    pub(super) fn hash(&self, data: &[u8]) -> String {
        match self {
            Self::Md5 => {
                let digest = md5::compute(data);
                hex_encode(&digest.0)
            },
            Self::Sha256 => {
                use sha2::Digest;
                let mut hasher = sha2::Sha256::new();
                hasher.update(data);
                hex_encode(&hasher.finalize())
            },
        }
    }
}

impl Default for DigestAlgorithm {
    /// 默认算法为 SHA256。
    ///
    /// 新系统应使用 SHA256 以避免 MD5 碰撞攻击。需要在兼容旧客户端时
    /// 通过 `HttpDigestAuth::new(realm, "MD5")` 显式指定。
    fn default() -> Self {
        Self::Sha256
    }
}

impl FromStr for DigestAlgorithm {
    type Err = GarrisonError;

    /// 从字符串解析算法（大小写不敏感）。
    fn from_str(s: &str) -> GarrisonResult<Self> {
        match s.to_ascii_uppercase().as_str() {
            "MD5" => Ok(Self::Md5),
            "SHA256" => Ok(Self::Sha256),
            other => Err(GarrisonError::Internal(format!(
                "不支持的 Digest 算法: {}，仅支持 MD5 / SHA256",
                other
            ))),
        }
    }
}
