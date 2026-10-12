// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

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

    /// 创建 TOTP 处理器：SHA1（RFC 6238 默认），skew=1 允许 ±1 时间窗口偏差。
    pub fn new(secret: Vec<u8>, step: u64, digits: u32) -> GarrisonResult<Self> {
        Self::new_with_hash_algorithm(secret, step, digits, Algorithm::SHA1)
    }

    /// 以指定哈希算法创建（SHA1/SHA256/SHA512）：默认 SHA1 兼容主流 Authenticator App，
    /// SHA256/SHA512 供服务端对齐 RFC 6238 完整算法组；算法须构造期选定（totp-rs 构建后不可变更）。
    /// `secret` 须匹配算法长度（SHA1 20 / SHA256 32 / SHA512 64 字节）。
    pub fn new_with_hash_algorithm(
        secret: Vec<u8>,
        step: u64,
        digits: u32,
        algorithm: Algorithm,
    ) -> GarrisonResult<Self> {
        let totp = TotpBuilder::new()
            .with_algorithm(algorithm)
            .with_digits(digits as u8)
            .with_skew(1) // skew = 1，允许 ±1 时间窗口偏差（RFC 6238 §5.2 推荐）
            .with_step_duration(step)
            .with_secret(secret)
            .build()
            .map_err(|e| GarrisonError::Internal(format!("secure-totp-init::{}", e)))?;
        Ok(Self { totp, step })
    }

    /// 生成 TOTP 验证码；`now` 为负返回 `Err(GarrisonError::InvalidParam)`（裸 `as u64` 会静默回绕产生错误窗口的码）。
    pub fn generate(&self, now: i64) -> GarrisonResult<String> {
        let now = Self::check_now(now)?;
        Ok(self.totp.generate(now).to_string())
    }

    /// 校验 TOTP 验证码，允许 ±1 时间窗口偏差以容忍客户端与时钟漂移；`now` 为负返回 `Err(GarrisonError::InvalidParam)`。
    pub fn validate(&self, code: &str, now: i64) -> GarrisonResult<bool> {
        let now = Self::check_now(now)?;
        Ok(self.totp.check(code, now).is_some())
    }

    /// 校验验证码并防重放（E3 修复：以 DAO `incr` 原子操作取代无界 `TOTP_LOCKS`
    /// DashMap 锁表，内存由 DAO 后端自管理）：通过后用 [`GarrisonDao::incr`] 原子记录 `(login_id, code)`，TTL 内同一验证码不可复用。
    ///
    /// `incr` 由后端（Redis `INCR` / oxcache `Mutex`）保证原子，首次返回 1、重放返回 >1，把 get + set
    /// 合并为单次原子操作，语义上消除 TOCTOU，无需进程内 per-login_id 锁。
    /// replay_key 的 TTL = `step * 3`，覆盖 skew=1 的前/当前/后三个窗口；`checked_mul` 防大 step 溢出成短 TTL。
    /// 返回 `true` 仅当校验通过且首次使用（重放或校验失败返回 `false`），`now` 为负返回 `Err(GarrisonError::InvalidParam)`。
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

        // 原子 incr 替代 per-login_id 锁 + get-then-set：首次返回 1、重放返回 >1；
        // TTL = step * 3 覆盖 skew=1 的三个窗口，checked_mul 防大 step 溢出回绕出短 TTL。
        let ttl = self
            .step
            .checked_mul(3)
            .ok_or_else(|| GarrisonError::Internal("secure-totp-ttl-overflow::".to_string()))?;
        let count = dao.incr(&replay_key, ttl).await?;
        Ok(count == 1)
    }

    /// 解码 Google Authenticator 风格 Base32 密钥（RFC 4648，无 padding）；解码失败返回 `Err(GarrisonError::Internal)`。
    pub fn secret_from_base32(s: &str) -> GarrisonResult<Vec<u8>> {
        base32::decode(base32::Alphabet::Rfc4648 { padding: false }, s).ok_or_else(|| {
            // 错误信息仅暴露 secret 长度，避免泄露密钥原文
            GarrisonError::Internal(format!("secure-base32-decode::secret_len={}", s.len()))
        })
    }
}
