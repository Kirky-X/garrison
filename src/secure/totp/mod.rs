// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! TOTP 子模块：基于 `totp-rs` 实现 RFC 6238 时间一次性密码（2FA）。
//!
//! SHA1（RFC 6238 默认，兼容主流 Authenticator App），允许 ±1 时间窗口偏差以容忍时钟漂移。

/// TOTP 处理器，封装 RFC 6238 动态验证码生成与校验。
///
/// # 示例
///
/// ```
/// #[cfg(feature = "secure-totp")]
/// # {
/// use garrison::secure::totp::TotpHandler;
///
/// let secret = b"12345678901234567890".to_vec();
/// let handler = TotpHandler::new(secret, 30, 6).unwrap();
/// let code = handler.generate(1700000000).unwrap();
/// assert_eq!(code.len(), 6);
/// assert!(handler.validate(&code, 1700000000).unwrap());
/// # }
/// ```
pub struct TotpHandler {
    /// 内部 TOTP 实例。
    totp: totp_rs::Totp,
    /// 时间步长（秒）。用于重放防护 TTL 计算（`validate_and_consume`）。
    step: u64,
}

mod handler;
#[cfg(test)]
mod tests;
