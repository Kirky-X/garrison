// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! API 签名协议模块（对应 微服务网关签名认证）：HMAC-SHA256 + Base64 请求签名
//! 生成与校验 + nonce 防重放。仅在启用 `protocol-sign` 特性时编译。
//!
//! ## 签名算法
//!
//! `sign = base64(hmac_sha256(hkdf_key, "{method}\n{path}\n{timestamp}\n{nonce}\n{body_sha256}"))`
//!
//! 其中 `hkdf_key = HKDF-SHA256(app_secret, salt=app_key, info="garrison-sign-v2")`。
//!
//! ## Key 命名空间
//!
//! sign nonce 存于 `garrison:sign:nonce:<app_key>:<nonce>`（app_key 前缀隔离多应用）。

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

/// API 签名处理器：持有 `app_key`、`app_secret` 与 `Arc<dyn GarrisonDao>`（nonce
/// 存储）。`app_secret` 最小 32 字节；HKDF 派生密钥在构造时一次性计算并缓存到
/// `derived_key`，`sign`/`validate` 直接复用。
pub struct SignHandler {
    /// 应用标识。
    app_key: String,
    /// 应用密钥明文（HKDF 输入材料；`protocol-zeroize` 下析构时零化，非 zeroize
    /// 构建中不再被读取）。
    ///
    /// # 安全注意（明文存储 + 零化 feature 门控）
    ///
    /// 默认构建 Drop 不零化，内存随普通 `String` 释放、内容不保证被清除（可能
    /// 残留于已释放堆块 / swap / core dump，扩容或所有权转移亦留碎片）；对密钥
    /// 卫生有要求的部署应显式启用 `protocol-zeroize`（见 `handler.rs` 的 `Drop` impl）。
    #[cfg_attr(not(feature = "protocol-zeroize"), allow(dead_code))]
    app_secret: String,
    /// DAO 抽象层，用于 nonce 存储。
    dao: Arc<dyn GarrisonDao>,
    /// 时间戳窗口（秒）。
    timestamp_window: i64,
    /// HKDF 派生密钥（构造时一次性计算，sign/validate 直接使用）。
    ///
    /// # 安全注意（明文存储 + 零化 feature 门控）
    ///
    /// 明文 `[u8; 32]`：仅 `protocol-zeroize` 下 Drop 时被覆写（见 `handler.rs`
    /// 的 `Drop` impl），默认构建释放后内容不保证清除（可能残留于已释放堆块 /
    /// swap / core dump）。
    derived_key: [u8; 32],
}
