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
    /// 计算 HMAC-SHA256 签名，返回 64 字符小写十六进制字符串。
    pub fn hmac_sha256(secret: &[u8], data: &[u8]) -> String {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(data);
        hex_encode(&mac.finalize().into_bytes())
    }

    /// 常量时间验证 HMAC-SHA256 签名，防时序侧信道。
    ///
    /// 重算 HMAC 后委托 [`crate::secure::ct_eq::constant_time_eq`] 比较（ADR-0003 决策 2：消除本地第二实现）；
    /// 该原语不做 early return、遍历到 `max_len`（短方 0 padding），编译器无法优化为短路比较。
    pub fn verify_hmac_sha256(secret: &[u8], data: &[u8], expected_sig: &str) -> bool {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(data);
        let computed_hex = hex_encode(&mac.finalize().into_bytes());

        crate::secure::ct_eq::constant_time_eq(computed_hex.as_bytes(), expected_sig.as_bytes())
    }

    /// 计算 HMAC-SHA512 签名，返回 128 字符小写十六进制字符串。
    pub fn hmac_sha512(secret: &[u8], data: &[u8]) -> String {
        type HmacSha512 = Hmac<Sha512>;
        let mut mac = HmacSha512::new_from_slice(secret).expect("HMAC accepts any key length");
        mac.update(data);
        hex_encode(&mac.finalize().into_bytes())
    }

    /// Base64 标准编码（含 `=` padding）。
    pub fn base64_encode(data: &[u8]) -> String {
        STANDARD.encode(data)
    }

    /// Base64 标准解码；非法输入返回 `Err(GarrisonError::Internal)`。
    pub fn base64_decode(s: &str) -> GarrisonResult<Vec<u8>> {
        STANDARD
            .decode(s)
            .map_err(|e| GarrisonError::Internal(format!("secure-base64-decode::{}", e)))
    }
}
