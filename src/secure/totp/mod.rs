//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! TOTP 子模块，时间一次性密码实现（RFC 6238）。
//!
//! [借鉴 Sa-Token] 基于 `totp-rs` crate 实现，
//! 提供二步验证（2FA）能力。
//!
//! 使用 SHA1 算法（RFC 6238 默认，兼容主流 Authenticator App），
//! 允许 ±1 时间窗口偏差以容忍时钟漂移。

use crate::dao::BulwarkDao;
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
    /// 时间步长（秒）。用于重放防护 TTL 计算（`validate_and_consume`）。
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

    /// 校验 TOTP 验证码并防止重放攻击。
    ///
    /// 在 [`validate`](Self::validate) 的基础上增加重放防护：
    /// 验证通过后将 `(login_id, code)` 记录到 DAO，同一验证码在 TTL 内不可重复使用。
    ///
    /// TTL = `step * 3`，覆盖 skew=1 的 3 个时间窗口（前一窗口 + 当前窗口 + 后一窗口），
    /// 确保验证码在整个有效期内不可重放。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识（用户 ID）。
    /// - `code`: 用户输入的验证码。
    /// - `now`: 当前 Unix 时间戳（秒）。
    /// - `dao`: DAO 抽象（用于记录已用验证码）。
    ///
    /// # 返回
    /// - `Ok(true)`: 校验通过且首次使用。
    /// - `Ok(false)`: 校验失败或验证码已使用（重放拒绝）。
    /// - `Err(_)`: DAO 读写失败。
    pub async fn validate_and_consume(
        &self,
        login_id: &str,
        code: &str,
        now: i64,
        dao: &dyn BulwarkDao,
    ) -> BulwarkResult<bool> {
        if !self.totp.check(code, now as u64) {
            return Ok(false);
        }
        let replay_key = format!("totp:used:{}:{}", login_id, code);
        if dao.get(&replay_key).await?.is_some() {
            return Ok(false);
        }
        dao.set(&replay_key, "1", self.step * 3).await?;
        Ok(true)
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

    // ========================================================================
    // validate_and_consume 测试（C-5 重放防护）
    // ========================================================================

    /// 首次校验正确验证码返回 Ok(true)。
    #[tokio::test]
    async fn validate_and_consume_first_use_succeeds() {
        let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
        let dao = crate::dao::tests::MockDao::new();
        let code = handler.generate(1700000000);
        let result = handler
            .validate_and_consume("user-001", &code, 1700000000, &dao)
            .await;
        assert!(result.is_ok(), "validate_and_consume 不应报错");
        assert!(result.unwrap(), "首次使用正确验证码应返回 true");
    }

    /// 同一验证码第二次校验返回 Ok(false)（重放拒绝，C-5 核心修复）。
    #[tokio::test]
    async fn validate_and_consume_rejects_replay() {
        let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
        let dao = crate::dao::tests::MockDao::new();
        let code = handler.generate(1700000000);

        let first = handler
            .validate_and_consume("user-001", &code, 1700000000, &dao)
            .await
            .expect("首次校验不应报错");
        assert!(first, "首次应通过");

        let second = handler
            .validate_and_consume("user-001", &code, 1700000000, &dao)
            .await
            .expect("二次校验不应报错");
        assert!(!second, "同一验证码二次使用应被拒绝（C-5 重放防护）");
    }

    /// 不同 login_id 的同一验证码不互相影响（隔离性）。
    #[tokio::test]
    async fn validate_and_consume_isolates_by_login_id() {
        let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
        let dao = crate::dao::tests::MockDao::new();
        let code = handler.generate(1700000000);

        let user_a = handler
            .validate_and_consume("user-A", &code, 1700000000, &dao)
            .await
            .unwrap();
        assert!(user_a, "user-A 首次应通过");

        let user_b = handler
            .validate_and_consume("user-B", &code, 1700000000, &dao)
            .await
            .unwrap();
        assert!(user_b, "user-B 使用同一验证码应通过（不同 login_id 隔离）");
    }

    /// 错误验证码返回 Ok(false) 且不记录到 DAO（不占用缓存）。
    #[tokio::test]
    async fn validate_and_consume_wrong_code_returns_false_without_recording() {
        let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
        let dao = crate::dao::tests::MockDao::new();

        let result = handler
            .validate_and_consume("user-001", "000000", 1700000000, &dao)
            .await
            .unwrap();
        assert!(!result, "错误验证码应返回 false");

        let replay_key = "totp:used:user-001:000000";
        let stored = dao.get(replay_key).await.unwrap();
        assert!(
            stored.is_none(),
            "错误验证码不应记录到 DAO（避免无效码占用缓存）"
        );
    }

    /// 同一 login_id 使用不同验证码均通过（不同时间窗口的验证码不冲突）。
    #[tokio::test]
    async fn validate_and_consume_different_codes_both_succeed() {
        let handler = TotpHandler::new(TEST_SECRET.to_vec(), 30, 6).unwrap();
        let dao = crate::dao::tests::MockDao::new();
        let code1 = handler.generate(1700000000);
        let code2 = handler.generate(1700000030);

        if code1 == code2 {
            return;
        }

        let first = handler
            .validate_and_consume("user-001", &code1, 1700000000, &dao)
            .await
            .unwrap();
        assert!(first, "code1 应通过");

        let second = handler
            .validate_and_consume("user-001", &code2, 1700000030, &dao)
            .await
            .unwrap();
        assert!(second, "code2（不同窗口）应通过");
    }
}
