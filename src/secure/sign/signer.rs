// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `Signer` 实现块，封装 HMAC-SHA256/SHA512、Base64 签名与编码方法。

use super::Signer;
use crate::error::{GarrisonError, GarrisonResult};
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

    /// 常量时间验证 HMAC-SHA256 签名，防止时序侧信道攻击。
    ///
    /// 重新计算 `data` 的 HMAC-SHA256，与 `expected_sig` 在常量时间内比较，
    /// 不在第一个不匹配字节处提前返回，也不因长度差异提前返回。
    ///
    /// # 安全性
    ///
    /// 比较统一委托公共原语 [`crate::secure::ct_eq::constant_time_eq`]
    /// （ADR-0003 决策 2：消除本地第二实现；`secure-sign` feature 依赖
    /// `secure-ct-eq`）。原语基于 `subtle::ConstantTimeEq`，长度比较不 early
    /// return，字节比较遍历到 `max_len`（短方 0 padding），编译器无法优化为
    /// 短路比较（DEEP-02 修复：移除永远不可达的 `constant_time_eq_manual` 死代码）。
    ///
    /// # 参数
    /// - `secret`: 签名密钥。
    /// - `data`: 原始数据。
    /// - `expected_sig`: 待校验的签名（小写十六进制字符串）。
    ///
    /// # 返回
    /// - `true`: 签名匹配。
    /// - `false`: 签名不匹配或长度不符。
    pub fn verify_hmac_sha256(secret: &[u8], data: &[u8], expected_sig: &str) -> bool {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(data);
        let computed_hex = hex_encode(&mac.finalize().into_bytes());

        crate::secure::ct_eq::constant_time_eq(computed_hex.as_bytes(), expected_sig.as_bytes())
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
    /// - `Err(GarrisonError::Internal)`: 非法 Base64 字符串。
    pub fn base64_decode(s: &str) -> GarrisonResult<Vec<u8>> {
        STANDARD
            .decode(s)
            .map_err(|e| GarrisonError::Internal(format!("secure-base64-decode::{}", e)))
    }
}
