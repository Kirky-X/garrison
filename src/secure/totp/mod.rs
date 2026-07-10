//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! TOTP 子模块，时间一次性密码实现（RFC 6238）。
//!
//! [借鉴 Sa-Token] 基于 `totp-rs` crate 实现，
//! 提供二步验证（2FA）能力。
//!
//! 使用 SHA1 算法（RFC 6238 默认，兼容主流 Authenticator App），
//! 允许 ±1 时间窗口偏差以容忍时钟漂移。

use crate::error::{BulwarkError, BulwarkResult};
use totp_rs::{Algorithm, TOTP};

/// TOTP 处理器，封装 RFC 6238 动态验证码生成与校验。
///
/// # 示例
///
/// ```
/// #[cfg(feature = "secure-totp")]
/// # {
/// use bulwark::secure::totp::TotpHandler;
///
/// let secret = b"12345678901234567890".to_vec();
/// let handler = TotpHandler::new(secret, 30, 6).unwrap();
/// let code = handler.generate(1700000000);
/// assert_eq!(code.len(), 6);
/// assert!(handler.validate(&code, 1700000000));
/// # }
/// ```
pub struct TotpHandler {
    /// 内部 TOTP 实例。
    totp: TOTP,
    /// 时间步长（秒）。元数据字段，供调试/日志使用；TOTP 验证由 totp-rs 库内部处理。
    #[allow(dead_code)]
    step: u64,
    /// 验证码位数。元数据字段，供调试/日志使用；TOTP 验证由 totp-rs 库内部处理。
    #[allow(dead_code)]
    digits: u32,
}

impl TotpHandler {
    /// 创建新的 TOTP 处理器。
    ///
    /// 使用 SHA1 算法（RFC 6238 默认），skew=1 允许 ±1 时间窗口偏差。
    ///
    /// # 参数
    /// - `secret`: 原始密钥字节。
    /// - `step`: 时间步长（秒），RFC 6238 默认 30。
    /// - `digits`: 验证码位数，通常 6 或 8。
    ///
    /// # 返回
    /// - `Ok(Self)`: 构造成功。
    /// - `Err(BulwarkError::Internal)`: 密钥长度或位数不合法。
    pub fn new(secret: Vec<u8>, step: u64, digits: u32) -> BulwarkResult<Self> {
        let totp = TOTP::new(
            Algorithm::SHA1,
            digits as usize,
            1, // skew = 1，允许 ±1 时间窗口偏差（RFC 6238 §5.2 推荐）
            step,
            secret,
        )
        .map_err(|e| BulwarkError::Internal(format!("TOTP 初始化失败: {}", e)))?;
        Ok(Self { totp, step, digits })
    }

    /// 生成 TOTP 验证码。
    ///
    /// # 参数
    /// - `now`: 当前 Unix 时间戳（秒）。
    ///
    /// # 返回
    /// 指定位数的数字字符串。
    pub fn generate(&self, now: i64) -> String {
        self.totp.generate(now as u64)
    }

    /// 校验 TOTP 验证码。
    ///
    /// 允许 ±1 个时间窗口的偏差以容忍客户端与时钟漂移。
    ///
    /// # 参数
    /// - `code`: 用户输入的验证码。
    /// - `now`: 当前 Unix 时间戳（秒）。
    ///
    /// # 返回
    /// - `true`: 校验通过。
    /// - `false`: 校验失败。
    pub fn validate(&self, code: &str, now: i64) -> bool {
        self.totp.check(code, now as u64)
    }

    /// 将 Google Authenticator 风格的 Base32 密钥解码为原始字节。
    ///
    /// 使用 RFC 4648 Base32 编码（无 padding），兼容主流 Authenticator App。
    ///
    /// # 参数
    /// - `s`: Base32 编码的密钥字符串。
    ///
    /// # 返回
    /// - `Ok(Vec<u8>)`: 解码成功。
    /// - `Err(BulwarkError::Internal)`: Base32 解码失败。
    pub fn secret_from_base32(s: &str) -> BulwarkResult<Vec<u8>> {
        base32::decode(base32::Alphabet::Rfc4648 { padding: false }, s)
            .ok_or_else(|| BulwarkError::Internal(format!("Base32 解码失败: {}", s)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 测试密钥（20 字节 ASCII）。
    const TEST_SECRET: &[u8] = b"12345678901234567890";

    // ========================================================================
    // 构造测试
    // ========================================================================

    /// 使用默认参数构造 TotpHandler（spec Scenario）。
    #[test]
    fn new_with_default_params() {
        let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6);
        assert!(handler.is_ok());
    }

    /// 自定义时间步长与位数（spec Scenario）。
    #[test]
    fn new_with_custom_params() {
        let handler = TotpHandler::new(TEST_SECRET.to_vec(), 60, 8).unwrap();
        let code = handler.generate(1700000000);
        assert_eq!(code.len(), 8);
    }

    /// 密钥过短应报错。
    #[test]
    fn new_with_short_secret_errors() {
        // totp-rs 要求密钥至少 10 字节
        let result = TotpHandler::new(b"short".to_vec(), 30, 6);
        assert!(result.is_err());
    }

    // ========================================================================
    // generate 测试
    // ========================================================================

    /// 生成 6 位验证码（spec Scenario）。
    #[test]
    fn generate_returns_6_digits() {
        let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
        let code = handler.generate(1700000000);
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }

    /// 相同 secret + 时间戳生成一致验证码（spec Scenario）。
    #[test]
    fn generate_is_deterministic() {
        let h1 = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
        let h2 = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
        assert_eq!(h1.generate(1700000000), h2.generate(1700000000));
    }

    /// 同一 30 秒窗口内验证码稳定（spec Scenario）。
    #[test]
    fn same_time_window_produces_same_code() {
        let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
        let c1 = handler.generate(1700000000);
        let c2 = handler.generate(1700000005); // 同一窗口内
        assert_eq!(c1, c2);
    }

    /// 跨时间窗口验证码变化（spec Scenario）。
    #[test]
    fn different_time_window_produces_different_code() {
        let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
        let c1 = handler.generate(1700000000);
        let c2 = handler.generate(1700000030); // 下一窗口
        assert_ne!(c1, c2);
    }

    // ========================================================================
    // validate 测试
    // ========================================================================

    /// 当前窗口验证码校验通过（spec Scenario）。
    #[test]
    fn validate_current_window_succeeds() {
        let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
        let code = handler.generate(1700000000);
        assert!(handler.validate(&code, 1700000000));
    }

    /// 允许前一个时间窗口的验证码（spec Scenario，±1 窗口容差）。
    #[test]
    fn validate_previous_window_succeeds() {
        let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
        let code = handler.generate(1699999970); // 前一窗口
        assert!(handler.validate(&code, 1700000000));
    }

    /// 允许后一个时间窗口的验证码（spec Scenario，±1 窗口容差）。
    #[test]
    fn validate_next_window_succeeds() {
        let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
        let code = handler.generate(1700000030); // 后一窗口
        assert!(handler.validate(&code, 1700000000));
    }

    /// 超出容差窗口的验证码校验失败（spec Scenario）。
    #[test]
    fn validate_beyond_tolerance_fails() {
        let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
        let code = handler.generate(1699999940); // 前两个窗口
        assert!(!handler.validate(&code, 1700000000));
    }

    /// 错误验证码校验失败。
    #[test]
    fn validate_wrong_code_fails() {
        let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
        assert!(!handler.validate("000000", 1700000000));
    }

    // ========================================================================
    // secret_from_base32 测试
    // ========================================================================

    /// 解码合法 Base32 密钥（spec Scenario）。
    #[test]
    fn secret_from_base32_decodes_valid() {
        // 使用足够长的 Base32 字符串（解码后 >= 16 字节 / 128 位）
        let bytes = TotpHandler::secret_from_base32("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").unwrap();
        assert!(!bytes.is_empty());
        assert!(bytes.len() >= 16); // 满足 totp-rs 的 128 位最低要求
    }

    /// 解码非法 Base32 字符串失败（spec Scenario）。
    #[test]
    fn secret_from_base32_rejects_invalid() {
        assert!(TotpHandler::secret_from_base32("invalid!base32").is_err());
    }

    /// Base32 密钥生成的验证码与原始字节一致（spec Scenario）。
    #[test]
    fn base32_secret_matches_raw_bytes() {
        let b32_str = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
        let bytes = TotpHandler::secret_from_base32(b32_str).unwrap();
        let h1 = TotpHandler::new(bytes.clone(), 30, 6).unwrap();
        let h2 = TotpHandler::new(bytes, 30, 6).unwrap();
        assert_eq!(h1.generate(1700000000), h2.generate(1700000000));
    }
}
