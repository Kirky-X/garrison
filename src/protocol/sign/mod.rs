//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! API 签名协议模块，提供请求签名生成与校验 + nonce 防重放。
//!
//! 对应 微服务网关签名认证，
//! 基于 HMAC-SHA256 + Base64 实现请求签名。
//!
//! 仅在启用 `protocol-sign` 特性时编译。
//!
//! ## 签名算法
//!
//! `sign = base64(hmac_sha256(hkdf_key, "{method}\n{path}\n{timestamp}\n{nonce}\n{body_sha256}"))`
//!
//! 其中 `hkdf_key = HKDF-SHA256(app_secret, salt=app_key, info="garrison-sign-v2")`。
//!
//! ## Key 命名空间
//!
//! 所有 sign nonce 存储在 `garrison:sign:nonce:<nonce>` 命名空间下。

/// SignHandler 实现（构造/签名/校验/Drop 零化）。
pub mod handler;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

use crate::dao::GarrisonDao;
use hmac::Hmac;
use sha2::Sha256;
use std::sync::Arc;

/// 默认时间戳窗口（秒）。
const DEFAULT_TIMESTAMP_WINDOW: i64 = 300;

/// app_secret 最小长度（32 字节 = 256 位，满足 HMAC-SHA256 安全要求）。
const MIN_APP_SECRET_LEN: usize = 32;

/// HKDF info 上下文字符串（域分隔，防止同一密钥在不同用途间复用）。
const HKDF_INFO: &[u8] = b"garrison-sign-v2";

/// HMAC-SHA256 类型别名。
type HmacSha256 = Hmac<Sha256>;

/// API 签名处理器。
///
/// 持有 `app_key`、`app_secret` 与 `Arc<dyn GarrisonDao>`（用于 nonce 存储）。
/// 实现 `Send + Sync`，可在多线程环境共享。
///
/// `app_secret` 最小 32 字节，内部用 HKDF-SHA256 派生 HMAC 密钥。
///
/// 性能优化：HKDF 派生密钥在构造时一次性计算并缓存到 `derived_key` 字段，
/// `sign`/`validate` 直接使用缓存密钥，避免每次签名重复 HKDF 计算。
pub struct SignHandler {
    /// 应用标识。
    app_key: String,
    /// 应用密钥（原始，HKDF 输入材料）。
    /// 保留用于 `protocol-zeroize` feature 下的 Drop 零化；非 zeroize 构建中不再被读取。
    #[cfg_attr(not(feature = "protocol-zeroize"), allow(dead_code))]
    app_secret: String,
    /// DAO 抽象层，用于 nonce 存储。
    dao: Arc<dyn GarrisonDao>,
    /// 时间戳窗口（秒）。
    timestamp_window: i64,
    /// HKDF 派生密钥（构造时一次性计算，sign/validate 直接使用）。
    derived_key: [u8; 32],
}
