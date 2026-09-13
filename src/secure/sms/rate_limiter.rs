//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SmsRateLimiter 实现：双窗口（小时/天）渐进式限速。
//!
//! 使用 limiteron `DistributedLimiter` trait 实现原子计数，保留 `dao` 用于
//! `decrement_counter`（limiteron 无 decrement 方法）。

use super::{GarrisonDao, GarrisonResult, SmsRateLimiter};
use crate::error::GarrisonError;
use crate::limiteron::GarrisonDaoDistributedLimiter;
use std::sync::Arc;
use std::time::Duration;

/// 每小时秒数（用于时间桶计算与 TTL）。
const SECONDS_PER_HOUR: u64 = 3600;
/// 每天秒数（用于日窗口 TTL）。
const SECONDS_PER_DAY: u64 = 86400;

/// 限速窗口桶信息（`check_and_increment_with` 返回，供 `rollback_with` 精确回滚）。
///
/// check 与 rollback **不得**各自用当前时间重算桶键：若 DAO 往返跨越小时/天边界，
/// rollback 按当前时间重算会得到不同的桶索引，递减到错误的 key，原计数器膨胀
/// 直至 TTL 自然过期。调用方必须把 [`check_and_increment_with`](SmsRateLimiter::check_and_increment_with)
/// 返回的窗口信息原样传给 [`rollback_with`](SmsRateLimiter::rollback_with)。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsRateWindows {
    /// 小时桶索引（Unix 秒 / 3600）。
    pub hour_bucket: u64,
    /// 日期键（UTC，`%Y-%m-%d` 格式）。
    pub date: String,
}

/// 规范化手机号（trim 前后空白）。
///
/// 防止 `" 13800138000 "` 与 `"13800138000"` 生成不同的限速 key，
/// 静默绕过限速（对齐 email 模块的 `normalize_email` 惯例）。
pub(super) fn normalize_phone(phone: &str) -> String {
    phone.trim().to_string()
}

/// 校验手机号格式（key 注入防护 + DoS 防护）。
///
/// spec 约束：phone 不能含 ':'（防止 key 结构破坏）。
/// 额外校验：非空、无空白字符（前后空白由 [`normalize_phone`] 剥离，内部空白拒绝）、
/// 无控制字符、长度 <= 20（防止超大 key 消耗内存）。
pub(super) fn validate_phone(phone: &str) -> GarrisonResult<()> {
    if phone.is_empty() {
        return Err(GarrisonError::InvalidParam(
            "secure-phone-empty::".to_string(),
        ));
    }
    if phone.contains(':') {
        return Err(GarrisonError::InvalidParam(
            "secure-phone-no-colon".to_string(),
        ));
    }
    if phone.chars().any(|c| c.is_control()) {
        return Err(GarrisonError::InvalidParam(
            "secure-phone-no-control-char".to_string(),
        ));
    }
    if phone.chars().any(|c| c.is_whitespace()) {
        return Err(GarrisonError::InvalidParam(
            "secure-phone-no-whitespace".to_string(),
        ));
    }
    if phone.len() > 20 {
        return Err(GarrisonError::InvalidParam(
            "secure-phone-too-long".to_string(),
        ));
    }
    Ok(())
}

impl SmsRateLimiter {
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
    ///
    /// 委托 [`GarrisonDao::decr`] 在单次 DAO 调用内完成 get → parse → update/delete，
    /// 消除原三步组合的 TOCTOU 竞态（fix-refresh-race-and-test-contracts / T014）。
    ///
    /// 语义（与 `dao.decr` 一致）：
    /// - key 不存在或已过期：返回 Ok(())（dao.decr 返回 0，无副作用）
    /// - cur_val == 0：返回 Ok(())（dao.decr 返回 0，不递减为负）
    /// - cur_val > 0：递减 1；new_val == 0 时删除 key；new_val > 0 时保留原 TTL
    ///
    /// # 错误
    /// - `GarrisonError::Dao`：dao.decr 内部 parse 失败（非数字值）
    /// - 其他 `GarrisonError`：dao.decr 内部 get/update/delete 错误
    pub(super) async fn decrement_counter(dao: &dyn GarrisonDao, key: &str) -> GarrisonResult<()> {
        dao.decr(key).await.map(|_| ())
    }

    /// 计算当前窗口桶信息。
    fn current_windows() -> GarrisonResult<SmsRateWindows> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| GarrisonError::Internal(format!("secure-system-time::{}", e)))?;
        Ok(SmsRateWindows {
            hour_bucket: now.as_secs() / SECONDS_PER_HOUR,
            date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
        })
    }

    /// 检查并递增限速计数器。
    ///
    /// 超限时回滚已递增的计数器，避免拒绝的请求消耗配额。
    ///
    /// # 回滚错误处理策略（统一约定）
    ///
    /// 回滚是 best-effort 修正：失败记录 `tracing::warn`（含 key 与错误）并继续，
    /// 不覆盖本次调用的主错误（限流拒绝）。代价是计数器可能残留膨胀至 TTL
    /// 自然过期（小时窗口最多 1h、天窗口最多 24h），运维通过 warn 告警感知。
    /// [`rollback`](Self::rollback) / [`rollback_with`](Self::rollback_with) 无主错误可保留，
    /// 故聚合后返回首个回滚错误——两条路径均全程 warn，观测语义一致。
    pub async fn check_and_increment(&self, phone: &str) -> GarrisonResult<()> {
        self.check_and_increment_with(phone).await.map(|_| ())
    }

    /// [`check_and_increment`](Self::check_and_increment) 的窗口信息携带版本。
    ///
    /// 返回本次递增命中的窗口桶信息，发送失败时应将其原样传给
    /// [`rollback_with`](Self::rollback_with)，保证跨小时/天边界时递减的是
    /// 递增时的同一个桶。
    pub async fn check_and_increment_with(&self, phone: &str) -> GarrisonResult<SmsRateWindows> {
        let phone = normalize_phone(phone);
        validate_phone(&phone)?;
        let windows = Self::current_windows()?;

        // 小时窗口：1 小时 TTL（limiteron DistributedLimiter.incr_with_ttl 替换 dao.incr）
        let hour_key = format!("sms:rate:{}:hour:{}", phone, windows.hour_bucket);
        let hour_count = self
            .limiter
            .incr_with_ttl(&hour_key, 1, Duration::from_secs(SECONDS_PER_HOUR))
            .await
            .map_err(|e| GarrisonError::Internal(format!("secure-limiter-incr::{}", e)))?;
        if hour_count > self.hourly_limit as u64 {
            // 超限，回滚 incr
            if let Err(e) = Self::decrement_counter(&*self.dao, &hour_key).await {
                tracing::warn!(error = %e, key = %hour_key, "rollback hourly window counter failed");
            }
            return Err(GarrisonError::SmsRateLimitExceeded {
                window: "hourly".to_string(),
            });
        }

        // 天窗口：24 小时 TTL（limiteron DistributedLimiter.incr_with_ttl 替换 dao.incr）
        let day_key = format!("sms:rate:{}:day:{}", phone, windows.date);
        // 天窗口递增失败时必须回滚已递增的小时计数，否则小时配额泄漏
        // （每次失败遗留 +1，直至 TTL 过期）
        let day_count = match self
            .limiter
            .incr_with_ttl(&day_key, 1, Duration::from_secs(SECONDS_PER_DAY))
            .await
        {
            Ok(count) => count,
            Err(e) => {
                if let Err(re) = Self::decrement_counter(&*self.dao, &hour_key).await {
                    tracing::warn!(
                        error = %re,
                        key = %hour_key,
                        "rollback hourly window counter failed after day incr failure"
                    );
                }
                return Err(GarrisonError::Internal(format!(
                    "secure-limiter-incr::{}",
                    e
                )));
            },
        };
        if day_count > self.daily_limit as u64 {
            // 超限，回滚 day 和 hour。
            // 回滚失败仅 warn：不覆盖主错误（daily 限流拒绝），计数器残留至 TTL
            // 过期（最长 1h/24h），运维通过 warn 告警感知（统一回滚错误策略，见方法文档）。
            if let Err(e) = Self::decrement_counter(&*self.dao, &day_key).await {
                tracing::warn!(error = %e, key = %day_key, "rollback daily window counter failed");
            }
            if let Err(e) = Self::decrement_counter(&*self.dao, &hour_key).await {
                tracing::warn!(error = %e, key = %hour_key, "rollback hourly window counter failed");
            }
            return Err(GarrisonError::SmsRateLimitExceeded {
                window: "daily".to_string(),
            });
        }

        Ok(windows)
    }

    /// 回滚限速计数器（发送失败时调用）。
    ///
    /// 注意：本方法按**当前时间**重算窗口桶，若 check 与 rollback 之间跨越
    /// 小时/天边界会递减错误的 key。发送失败路径应改用
    /// [`rollback_with`](Self::rollback_with) 并传入
    /// [`check_and_increment_with`](Self::check_and_increment_with) 返回的窗口信息。
    ///
    /// # 错误
    /// 聚合执行小时 + 天两次递减（首个失败不中断第二个），返回首个错误。
    pub async fn rollback(&self, phone: &str) -> GarrisonResult<()> {
        let phone = normalize_phone(phone);
        validate_phone(&phone)?;
        let windows = Self::current_windows()?;
        self.rollback_inner(&phone, &windows).await
    }

    /// [`rollback`](Self::rollback) 的窗口信息携带版本（优先使用）。
    ///
    /// 使用 check 时返回的窗口桶信息，跨窗口边界也不会递减错误的 key。
    pub async fn rollback_with(&self, phone: &str, windows: &SmsRateWindows) -> GarrisonResult<()> {
        let phone = normalize_phone(phone);
        validate_phone(&phone)?;
        self.rollback_inner(&phone, windows).await
    }

    /// 回滚实现：聚合两次递减，首个失败不中断第二个，最终返回首个错误。
    async fn rollback_inner(&self, phone: &str, windows: &SmsRateWindows) -> GarrisonResult<()> {
        let mut first_err: Option<GarrisonError> = None;

        // 递减小时窗口计数（失败不中断天窗口回滚——rollback 是 best-effort，
        // 只回滚一半比完全不回滚更糟）
        let hour_key = format!("sms:rate:{}:hour:{}", phone, windows.hour_bucket);
        if let Err(e) = Self::decrement_counter(&*self.dao, &hour_key).await {
            tracing::warn!(error = %e, key = %hour_key, "rollback hourly window counter failed");
            first_err.get_or_insert(e);
        }

        // 递减天窗口计数
        let day_key = format!("sms:rate:{}:day:{}", phone, windows.date);
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
