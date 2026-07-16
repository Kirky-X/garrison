//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `TotpHandler` 实现。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use dashmap::DashMap;
use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::sync::Mutex as TokioMutex;
use totp_rs::{Algorithm, TOTP};

use super::TotpHandler;

/// Per-login_id TOTP 验证锁，防止 `validate_and_consume` 的 TOCTOU 竞态（FMEA #7，RPN=288）。
///
/// 锁粒度为 login_id，不影响不同用户的并发。使用 `tokio::sync::Mutex`（持有锁跨 await 点）。
/// `TotpHandler` 每次从 `TotpSecretData::to_handler()` 创建新实例，无法在实例上持有锁，
/// 因此使用模块级全局 `DashMap` 存储 per-login_id 锁。
static TOTP_LOCKS: Lazy<DashMap<String, Arc<TokioMutex<()>>>> = Lazy::new(DashMap::new);

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
        Ok(Self { totp, step })
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

        // FMEA #7: per-login_id 锁包裹 get-then-set，防止 TOCTOU 竞态
        //（kueiku RPN=288）。两个并发请求验证同一 login_id 的同一 code 时，
        // 锁确保只有第一个通过，第二个读到 replay_key 后返回 false。
        let lock = TOTP_LOCKS
            .entry(login_id.to_string())
            .or_insert_with(|| Arc::new(TokioMutex::new(())))
            .clone();
        let _guard = lock.lock().await;

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
