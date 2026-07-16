//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `Signer` 实现块，封装 HMAC-SHA256/SHA512、Base64、MD5 签名与编码方法。

use super::Signer;
use crate::error::{BulwarkError, BulwarkResult};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha512};

/// 将字节切片编码为小写十六进制字符串。
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

impl Signer {
    /// 计算 HMAC-SHA256 签名，输出小写十六进制字符串。
    ///
    /// # 参数
    /// - `secret`: 签名密钥（任意长度）。
    /// - `data`: 待签名数据。
    ///
    /// # 返回
    /// 64 字符的小写十六进制字符串。
    pub fn hmac_sha256(secret: &[u8], data: &[u8]) -> String {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(data);
        hex_encode(&mac.finalize().into_bytes())
    }

    /// 计算 HMAC-SHA512 签名，输出小写十六进制字符串。
    ///
    /// # 参数
    /// - `secret`: 签名密钥（任意长度）。
    /// - `data`: 待签名数据。
    ///
    /// # 返回
    /// 128 字符的小写十六进制字符串。
    pub fn hmac_sha512(secret: &[u8], data: &[u8]) -> String {
        type HmacSha512 = Hmac<Sha512>;
        let mut mac = HmacSha512::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(data);
        hex_encode(&mac.finalize().into_bytes())
    }

    /// Base64 标准编码。
    ///
    /// # 参数
    /// - `data`: 待编码字节。
    ///
    /// # 返回
    /// Base64 编码字符串（含 `=` padding）。
    pub fn base64_encode(data: &[u8]) -> String {
        STANDARD.encode(data)
    }

    /// Base64 标准解码。
    ///
    /// # 参数
    /// - `s`: Base64 编码字符串。
    ///
    /// # 返回
    /// - `Ok(Vec<u8>)`: 解码后的字节。
    /// - `Err(BulwarkError::Internal)`: 非法 Base64 字符串。
    pub fn base64_decode(s: &str) -> BulwarkResult<Vec<u8>> {
        STANDARD
            .decode(s)
            .map_err(|e| BulwarkError::Internal(format!("Base64 解码失败: {}", e)))
    }

    /// 计算 MD5 摘要，输出小写十六进制字符串。
    ///
    /// # 废弃说明
    /// MD5 已被证明不安全（存在碰撞攻击），仅用于兼容旧版签名协议。
    /// 新业务请使用 [`hmac_sha256`](Self::hmac_sha256) 或 [`hmac_sha512`](Self::hmac_sha512)。
    #[deprecated(note = "MD5 已不安全，请使用 hmac_sha256 或 hmac_sha512")]
    pub fn md5(data: &[u8]) -> String {
        let digest = md5::compute(data);
        hex_encode(&digest.0)
    }
}
