//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! EmailRateLimiter 实现：双窗口（小时/天）渐进式限速。
//!
//! 使用 limiteron `DistributedLimiter` trait 实现原子计数，保留 `dao` 用于
//! `decrement_counter`（limiteron 无 decrement 方法）。

use super::{EmailRateLimiter, GarrisonDao, GarrisonResult};
use crate::error::GarrisonError;
use crate::limiteron::GarrisonDaoDistributedLimiter;
use std::sync::Arc;
use std::time::Duration;

/// 每小时秒数（用于时间桶计算与 TTL）。
const SECONDS_PER_HOUR: u64 = 3600;
/// 每天秒数（用于日窗口 TTL）。
const SECONDS_PER_DAY: u64 = 86400;

/// 限速窗口桶信息（`check_and_increment_inner` 返回，供 `rollback_inner_with` 精确回滚）。
///
/// check 与 rollback **不得**各自用当前时间重算桶键：若跨越小时/午夜边界，
/// rollback 按当前时间重算的 `%Y-%m-%d`/小时桶与递增时不一致，会递减错误的 key，
/// 原计数器滞留（静默失败的回滚）。调用方必须把
/// [`check_and_increment_inner`](EmailRateLimiter::check_and_increment_inner)
/// 返回的窗口信息原样传给 [`rollback_inner_with`](EmailRateLimiter::rollback_inner_with)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmailRateWindows {
    /// 小时桶索引（Unix 秒 / 3600）。
    pub hour_bucket: u64,
    /// 日期键（UTC，`%Y-%m-%d` 格式）。
    pub date: String,
}

/// 规范化邮箱地址（trim + 小写化）。
///
/// 防止 `Foo@x.com` / `foo@x.com` 双发绕过限速。
pub(super) fn normalize_email(email: &str) -> String {
    email.trim().to_lowercase()
}

/// 校验邮箱格式（key 注入防护 + DoS 防护）。
///
/// 约束：非空、无控制字符、含 `@`、不含 `:`（防 key 注入）、长度 <= 254。
pub(super) fn validate_email(email: &str) -> GarrisonResult<()> {
    if email.is_empty() {
        return Err(GarrisonError::InvalidParam(
            "secure-email-empty::".to_string(),
        ));
    }
    if email.contains(':') {
        return Err(GarrisonError::InvalidParam(
            "secure-email-no-colon::".to_string(),
        ));
    }
    if email.chars().any(|c| c.is_control()) {
        return Err(GarrisonError::InvalidParam(
            "secure-email-no-control-char::".to_string(),
        ));
    }
    if email.len() > 254 {
        return Err(GarrisonError::InvalidParam(
            "secure-email-invalid-format::".to_string(),
        ));
    }
    if !email.contains('@') {
        return Err(GarrisonError::InvalidParam(
            "secure-email-invalid-format::".to_string(),
        ));
    }
    Ok(())
}

impl EmailRateLimiter {
    /// 创建限速器实例。
    ///
    /// 内部创建 [`GarrisonDaoDistributedLimiter`] 适配器，将 `dao` 桥接到
    /// limiteron `DistributedLimiter` trait，用于原子 `incr_with_ttl`。
    pub fn new(dao: Arc<dyn GarrisonDao>, hourly_limit: u32, daily_limit: u32) -> Self {
        let limiter = Arc::new(GarrisonDaoDistributedLimiter::new(dao.clone()));
        Self {
            dao,
            limiter,
            hourly_limit,
            daily_limit,
        }
    }

    /// 递减计数器（委托 `dao.decr` 原子操作）。
    pub(super) async fn decrement_counter(dao: &dyn GarrisonDao, key: &str) -> GarrisonResult<()> {
        dao.decr(key).await.map(|_| ())
    }

    /// 检查并递增限速计数器。
    ///
    /// 超限时回滚已递增的计数器，避免拒绝的请求消耗配额。
    pub async fn check_and_increment(&self, email: &str) -> GarrisonResult<()> {
        let normalized = normalize_email(email);
        validate_email(&normalized)?;
        self.check_and_increment_inner(&normalized)
            .await
            .map(|_| ())
    }

    /// 内部实现：接受已规范化的邮箱，避免重复 normalize。
    ///
    /// 返回本次递增命中的窗口桶信息，发送失败路径应将其原样传给
    /// [`rollback_inner_with`](Self::rollback_inner_with)，保证跨小时/午夜边界时
    /// 递减的是递增时的同一个桶。
    pub(super) async fn check_and_increment_inner(
        &self,
        normalized: &str,
    ) -> GarrisonResult<EmailRateWindows> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| GarrisonError::Internal(format!("secure-system-time::{}", e)))?;
        let windows = EmailRateWindows {
            hour_bucket: now.as_secs() / SECONDS_PER_HOUR,
            date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
        };

        // 小时窗口
        let hour_key = format!("email:rate:{}:hour:{}", normalized, windows.hour_bucket);
        let hour_count = self
            .limiter
            .incr_with_ttl(&hour_key, 1, Duration::from_secs(SECONDS_PER_HOUR))
            .await
            .map_err(|e| GarrisonError::Internal(format!("secure-limiter-incr::{}", e)))?;
        if hour_count > self.hourly_limit as u64 {
            if let Err(e) = Self::decrement_counter(&*self.dao, &hour_key).await {
                tracing::warn!(error = %e, key = %hour_key, "rollback hourly window counter failed");
            }
            return Err(GarrisonError::EmailRateLimitExceeded {
                window: "hourly".to_string(),
            });
        }

        // 天窗口
        let day_key = format!("email:rate:{}:day:{}", normalized, windows.date);
        let day_count = self
            .limiter
            .incr_with_ttl(&day_key, 1, Duration::from_secs(SECONDS_PER_DAY))
            .await
            .map_err(|e| GarrisonError::Internal(format!("secure-limiter-incr::{}", e)))?;
        if day_count > self.daily_limit as u64 {
            // 回滚失败仅 warn：不覆盖主错误（限流拒绝），计数器残留至 TTL 过期，
            // 运维通过 warn 告警感知（与 sms 模块统一回滚错误策略）
            if let Err(e) = Self::decrement_counter(&*self.dao, &day_key).await {
                tracing::warn!(error = %e, key = %day_key, "rollback daily window counter failed");
            }
            if let Err(e) = Self::decrement_counter(&*self.dao, &hour_key).await {
                tracing::warn!(error = %e, key = %hour_key, "rollback hourly window counter failed");
            }
            return Err(GarrisonError::EmailRateLimitExceeded {
                window: "daily".to_string(),
            });
        }

        Ok(windows)
    }

    /// 回滚限速计数器（发送失败时调用）。
    ///
    /// 注意：本方法按**当前时间**重算窗口桶，若 check 与 rollback 之间跨越
    /// 小时/午夜边界会递减错误的 key。发送失败路径应改用
    /// [`rollback_inner_with`](Self::rollback_inner_with) 并传入
    /// [`check_and_increment_inner`](Self::check_and_increment_inner) 返回的窗口信息。
    pub async fn rollback(&self, email: &str) -> GarrisonResult<()> {
        let normalized = normalize_email(email);
        validate_email(&normalized)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| GarrisonError::Internal(format!("secure-system-time::{}", e)))?;
        let windows = EmailRateWindows {
            hour_bucket: now.as_secs() / SECONDS_PER_HOUR,
            date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
        };
        self.rollback_windows(&normalized, &windows).await
    }

    /// 内部实现：使用调用方提供的窗口桶信息回滚（优先使用）。
    ///
    /// 聚合执行小时 + 天两次递减（首个失败不中断第二个），返回首个错误。
    pub(super) async fn rollback_inner_with(
        &self,
        normalized: &str,
        windows: &EmailRateWindows,
    ) -> GarrisonResult<()> {
        self.rollback_windows(normalized, windows).await
    }

    /// 回滚实现：聚合两次递减，首个失败不中断第二个，最终返回首个错误。
    async fn rollback_windows(
        &self,
        normalized: &str,
        windows: &EmailRateWindows,
    ) -> GarrisonResult<()> {
        let mut first_err: Option<GarrisonError> = None;

        let hour_key = format!("email:rate:{}:hour:{}", normalized, windows.hour_bucket);
        if let Err(e) = Self::decrement_counter(&*self.dao, &hour_key).await {
            tracing::warn!(error = %e, key = %hour_key, "rollback hourly window counter failed");
            first_err.get_or_insert(e);
        }

        let day_key = format!("email:rate:{}:day:{}", normalized, windows.date);
        if let Err(e) = Self::decrement_counter(&*self.dao, &day_key).await {
            tracing::warn!(error = %e, key = %day_key, "rollback daily window counter failed");
            first_err.get_or_insert(e);
        }

        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }
}
