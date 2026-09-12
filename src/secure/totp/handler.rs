//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `TotpHandler` 实现。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use totp_rs::{Algorithm, Builder as TotpBuilder};

use super::TotpHandler;

impl TotpHandler {
    /// 校验时间戳合法性：负值对 TOTP 无意义，裸 `as u64` 转换会静默回绕为
    /// 巨大值，产生完全不同时间窗口的验证码。
    fn check_now(now: i64) -> GarrisonResult<u64> {
        u64::try_from(now)
            .map_err(|_| GarrisonError::InvalidParam("secure-totp-negative-now::".to_string()))
    }

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
    /// - `Err(GarrisonError::Internal)`: 密钥长度或位数不合法。
    pub fn new(secret: Vec<u8>, step: u64, digits: u32) -> GarrisonResult<Self> {
        let totp = TotpBuilder::new()
            .with_algorithm(Algorithm::SHA1)
            .with_digits(digits as u8)
            .with_skew(1) // skew = 1，允许 ±1 时间窗口偏差（RFC 6238 §5.2 推荐）
            .with_step_duration(step)
            .with_secret(secret)
            .build()
            .map_err(|e| GarrisonError::Internal(format!("secure-totp-init::{}", e)))?;
        Ok(Self { totp, step })
    }

    /// 生成 TOTP 验证码。
    ///
    /// # 参数
    /// - `now`: 当前 Unix 时间戳（秒），必须 >= 0。
    ///
    /// # 返回
    /// - `Ok(String)`: 指定位数的数字字符串。
    /// - `Err(GarrisonError::InvalidParam)`: `now` 为负值（裸 `as u64` 会静默回绕
    ///   为巨大计数器，产生错误时间窗口的验证码，故显式拒绝）。
    pub fn generate(&self, now: i64) -> GarrisonResult<String> {
        let now = Self::check_now(now)?;
        Ok(self.totp.generate(now).to_string())
    }

    /// 校验 TOTP 验证码。
    ///
    /// 允许 ±1 个时间窗口的偏差以容忍客户端与时钟漂移。
    ///
    /// # 参数
    /// - `code`: 用户输入的验证码。
    /// - `now`: 当前 Unix 时间戳（秒），必须 >= 0。
    ///
    /// # 返回
    /// - `Ok(true)`: 校验通过。
    /// - `Ok(false)`: 校验失败。
    /// - `Err(GarrisonError::InvalidParam)`: `now` 为负值。
    pub fn validate(&self, code: &str, now: i64) -> GarrisonResult<bool> {
        let now = Self::check_now(now)?;
        Ok(self.totp.check(code, now).is_some())
    }

    /// 校验 TOTP 验证码并防止重放攻击。
    ///
    /// 在 [`validate`](Self::validate) 的基础上增加重放防护：
    /// 验证通过后通过 DAO 的原子 `incr` 操作记录 `(login_id, code)`，同一验证码在
    /// TTL 内不可重复使用。
    ///
    /// # E3 修复：消除无界 DashMap
    ///
    /// 原实现使用 `static TOTP_LOCKS: Lazy<DashMap<String, Arc<TokioMutex<()>>>>` 存储
    /// per-login_id 锁，无 TTL 且无容量上限，每个 login_id 创建一个永久条目，
    /// 导致无界内存增长（攻击者可用大量 login_id OOM）。
    ///
    /// 新实现使用 [`GarrisonDao::incr`] 的原子性消除 TOCTOU 竞态：
    /// - `incr` 在后端（`GarrisonDaoOxcache` 用 `parking_lot::Mutex`，`MockDao` 用
    ///   `parking_lot::Mutex`，Redis 后端用 `INCR` 命令）保证进程内原子
    /// - 首次调用返回 1（key 不存在 → 初始化为 "1"），后续调用返回 2+（递增）
    /// - `incr` 返回 1 时视为首次使用，返回 >1 时视为重放
    ///
    /// 此方案完全消除 per-login_id 锁，内存由 DAO 后端（oxcache）自管理：
    /// - replay_key 的 TTL = `step * 3`（覆盖 skew=1 的 3 个时间窗口）
    /// - oxcache 后端的容量与淘汰策略由调用方通过 `GarrisonDaoOxcache::new()` 配置
    /// - 不再需要 `DashMap` / `once_cell` / `Arc<TokioMutex>` 等进程内状态
    ///
    /// # FMEA #7 TOCTOU 防护保留
    ///
    /// 原锁的目的是防止两个并发请求同时通过 `get → set` 序列（TOCTOU）。
    /// `incr` 将 get + set 合并为单次原子操作，从语义上消除 TOCTOU 窗口：
    /// - 两个并发 `incr` 调用，后端保证只有一个返回 1，另一个返回 2
    /// - 无需进程内锁，跨进程（Redis 后端）也保证原子性
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识（用户 ID）。
    /// - `code`: 用户输入的验证码。
    /// - `now`: 当前 Unix 时间戳（秒），必须 >= 0。
    /// - `dao`: DAO 抽象（用于原子记录已用验证码）。
    ///
    /// # 返回
    /// - `Ok(true)`: 校验通过且首次使用（`incr` 返回 1）。
    /// - `Ok(false)`: 校验失败或验证码已使用（重放拒绝，`incr` 返回 >1）。
    /// - `Err(GarrisonError::InvalidParam)`: `now` 为负值。
    /// - `Err(_)`: DAO 读写失败。
    pub async fn validate_and_consume(
        &self,
        login_id: &str,
        code: &str,
        now: i64,
        dao: &dyn GarrisonDao,
    ) -> GarrisonResult<bool> {
        let now = Self::check_now(now)?;
        if self.totp.check(code, now).is_none() {
            return Ok(false);
        }
        let replay_key = format!("totp:used:{}:{}", login_id, code);

        // E3 + FMEA #7：用 DAO 的原子 incr 替代 per-login_id 锁 + get-then-set。
        // incr 在后端用 Mutex/INCR 保证原子性：首次返回 1，重放返回 >1。
        // TTL = step * 3，覆盖 skew=1 的 3 个时间窗口（前 + 当前 + 后）；
        // step * 3 用 checked_mul 防止超大 step 溢出回绕出错误的短 TTL。
        let ttl = self
            .step
            .checked_mul(3)
            .ok_or_else(|| GarrisonError::Internal("secure-totp-ttl-overflow::".to_string()))?;
        let count = dao.incr(&replay_key, ttl).await?;
        Ok(count == 1)
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
    /// - `Err(GarrisonError::Internal)`: Base32 解码失败。
    pub fn secret_from_base32(s: &str) -> GarrisonResult<Vec<u8>> {
        base32::decode(base32::Alphabet::Rfc4648 { padding: false }, s).ok_or_else(|| {
            // 错误信息仅暴露 secret 长度，避免泄露密钥原文（T39）
            GarrisonError::Internal(format!("secure-base32-decode::secret_len={}", s.len()))
        })
    }
}
