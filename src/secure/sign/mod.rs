//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 签名工具模块，提供 HMAC-SHA256/SHA512、Base64、MD5 签名与编码工具。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `SaSign` 工具类，
//! 提供微服务网关签名认证所需的加密原语。
//!
//! 所有方法均为关联函数（static method），`Signer` struct 不持有任何状态。

use crate::error::{BulwarkError, BulwarkResult};
use base64::{engine::general_purpose::STANDARD, Engine};
use hmac::{Hmac, KeyInit, Mac};
use sha2::{Sha256, Sha512};

/// 签名工具 struct，纯静态方法封装，不持有任何状态（依据 spec secure-sign）。
///
/// 所有方法为关联函数，无需实例化即可调用：
///
/// ```
/// #[cfg(feature = "secure-sign")]
/// # {
/// use bulwark::secure::sign::Signer;
/// let sig = Signer::hmac_sha256(b"secret", b"data");
/// assert_eq!(sig.len(), 64);
/// # }
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct Signer;

/// 将字节切片编码为小写十六进制字符串。
fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

impl Signer {
    /// 计算 HMAC-SHA256 签名，输出小写十六进制字符串（依据 spec secure-sign）。
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

    /// 计算 HMAC-SHA512 签名，输出小写十六进制字符串（依据 spec secure-sign）。
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

    /// Base64 标准编码（依据 spec secure-sign）。
    ///
    /// # 参数
    /// - `data`: 待编码字节。
    ///
    /// # 返回
    /// Base64 编码字符串（含 `=` padding）。
    pub fn base64_encode(data: &[u8]) -> String {
        STANDARD.encode(data)
    }

    /// Base64 标准解码（依据 spec secure-sign）。
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

    /// 计算 MD5 摘要，输出小写十六进制字符串（依据 spec secure-sign）。
    ///
    /// # 废弃说明
    /// MD5 已被证明不安全（存在碰撞攻击），仅用于兼容 Sa-Token 旧版签名协议。
    /// 新业务请使用 [`hmac_sha256`](Self::hmac_sha256) 或 [`hmac_sha512`](Self::hmac_sha512)。
    #[deprecated(note = "MD5 已不安全，请使用 hmac_sha256 或 hmac_sha512")]
    pub fn md5(data: &[u8]) -> String {
        let digest = md5::compute(data);
        hex_encode(&digest.0)
    }
}

#[cfg(test)]
mod tests {
    #![allow(deprecated)]
    use super::*;

    // ========================================================================
    // HMAC-SHA256 测试（依据 spec secure-sign + RFC 4231 测试向量）
    // ========================================================================

    /// RFC 4231 Test Case 1: key=[0x0b;20], data="Hi There"。
    #[test]
    fn hmac_sha256_rfc4231_test_case_1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let result = Signer::hmac_sha256(&key, data);
        assert_eq!(result.len(), 64);
        assert_eq!(
            result,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    /// RFC 4231 Test Case 2: key="Jefe", data="what do ya want for nothing?"。
    #[test]
    fn hmac_sha256_rfc4231_test_case_2() {
        let result = Signer::hmac_sha256(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(
            result,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    /// 相同输入多次调用返回一致结果。
    #[test]
    fn hmac_sha256_deterministic() {
        let a = Signer::hmac_sha256(b"key", b"data");
        let b = Signer::hmac_sha256(b"key", b"data");
        assert_eq!(a, b);
    }

    /// 不同 secret 产生不同签名。
    #[test]
    fn hmac_sha256_different_secret_different_result() {
        let a = Signer::hmac_sha256(b"secret1", b"data");
        let b = Signer::hmac_sha256(b"secret2", b"data");
        assert_ne!(a, b);
    }

    // ========================================================================
    // HMAC-SHA512 测试（依据 spec secure-sign + RFC 4231 测试向量）
    // ========================================================================

    /// RFC 4231 Test Case 1: key=[0x0b;20], data="Hi There"。
    #[test]
    fn hmac_sha512_rfc4231_test_case_1() {
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let result = Signer::hmac_sha512(&key, data);
        assert_eq!(result.len(), 128);
        assert_eq!(
            result,
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
    }

    // ========================================================================
    // Base64 测试（依据 spec secure-sign）
    // ========================================================================

    /// Base64 编码与解码互逆。
    #[test]
    fn base64_encode_decode_roundtrip() {
        let original = b"Hello, World!";
        let encoded = Signer::base64_encode(original);
        let decoded = Signer::base64_decode(&encoded).unwrap();
        assert_eq!(decoded, original);
    }

    /// Base64 编码已知值。
    #[test]
    fn base64_encode_known_values() {
        assert_eq!(Signer::base64_encode(b"hello"), "aGVsbG8=");
        assert_eq!(Signer::base64_encode(b""), "");
    }

    /// 解码非法 Base64 字符串失败，不 panic。
    #[test]
    fn base64_decode_invalid_input_errors() {
        let result = Signer::base64_decode("!!!not-base64!!!");
        assert!(result.is_err());
    }

    // ========================================================================
    // MD5 测试（依据 spec secure-sign，标记废弃）
    // ========================================================================

    /// MD5 输出 32 字符小写十六进制，与标准值一致。
    #[test]
    fn md5_known_values() {
        assert_eq!(Signer::md5(b"hello"), "5d41402abc4b2a76b9719d911017c592");
        assert_eq!(Signer::md5(b""), "d41d8cd98f00b204e9800998ecf8427e");
    }

    // ========================================================================
    // Signer struct 测试
    // ========================================================================

    /// `Signer` 可构造且 `Default` 可用。
    #[test]
    fn signer_implements_default() {
        let _signer: Signer = Default::default();
    }
}
