//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SmsRateLimiter 实现：双窗口（小时/天）渐进式限速。
//!
//! 使用 limiteron `DistributedLimiter` trait 实现原子计数，保留 `dao` 用于
//! `decrement_counter`（limiteron 无 decrement 方法）。

use super::{BulwarkDao, BulwarkResult, SmsRateLimiter};
use crate::error::BulwarkError;
use crate::limiteron::BulwarkDaoDistributedLimiter;
use std::sync::Arc;
use std::time::Duration;

/// 校验手机号格式（key 注入防护 + DoS 防护）。
///
/// spec 约束：phone 不能含 ':'（防止 key 结构破坏）。
/// 额外校验：非空、无控制字符、长度 <= 20（防止超大 key 消耗内存）。
pub(super) fn validate_phone(phone: &str) -> BulwarkResult<()> {
    if phone.is_empty() {
        return Err(BulwarkError::InvalidParam(
            "secure-phone-empty::".to_string(),
        ));
    }
    if phone.contains(':') {
        return Err(BulwarkError::InvalidParam(
            "secure-phone-no-colon".to_string(),
        ));
    }
    if phone.chars().any(|c| c.is_control()) {
        return Err(BulwarkError::InvalidParam(
            "secure-phone-no-control-char".to_string(),
        ));
    }
    if phone.len() > 20 {
        return Err(BulwarkError::InvalidParam(
            "secure-phone-too-long".to_string(),
        ));
    }
    Ok(())
}

impl SmsRateLimiter {
    /// 创建限速器实例。
    ///
    /// 内部创建 [`BulwarkDaoDistributedLimiter`] 适配器，将 `dao` 桥接到
    /// limiteron `DistributedLimiter` trait，用于原子 `incr_with_ttl`。
    pub fn new(dao: Arc<dyn BulwarkDao>, hourly_limit: u32, daily_limit: u32) -> Self {
        let limiter = Arc::new(BulwarkDaoDistributedLimiter::new(dao.clone()));
        Self {
            dao,
            limiter,
            hourly_limit,
            daily_limit,
        }
    }

    /// 递减计数器（get → parse → update/delete）。
    ///
    /// 计数器值降为 0 时删除 key，否则更新为新值。
    /// 解析失败返回错误（不静默吞掉）。
    pub(super) async fn decrement_counter(dao: &dyn BulwarkDao, key: &str) -> BulwarkResult<()> {
        if let Some(v) = dao.get(key).await? {
            let count: u64 = v.parse::<u64>().map_err(|e| {
                BulwarkError::Internal(format!("secure-counter-parse::{}::{}", key, e))
            })?;
            if count > 0 {
                let new_val = count - 1;
                if new_val == 0 {
                    dao.delete(key).await?;
                } else {
                    dao.update(key, &new_val.to_string()).await?;
                }
            }
        }
        Ok(())
    }

    /// 检查并递增限速计数器。
    ///
    /// 超限时回滚已递增的计数器，避免拒绝的请求消耗配额。
    pub async fn check_and_increment(&self, phone: &str) -> BulwarkResult<()> {
        validate_phone(phone)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| BulwarkError::Internal(format!("secure-system-time::{}", e)))?;
        let hour_bucket = now.as_secs() / 3600;
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();

        // 小时窗口：1 小时 TTL（limiteron DistributedLimiter.incr_with_ttl 替换 dao.incr）
        let hour_key = format!("sms:rate:{}:hour:{}", phone, hour_bucket);
        let hour_count = self
            .limiter
            .incr_with_ttl(&hour_key, 1, Duration::from_secs(3600))
            .await
            .map_err(|e| BulwarkError::Internal(format!("secure-limiter-incr::{}", e)))?;
        if hour_count > self.hourly_limit as u64 {
            // 超限，回滚 incr
            if let Err(e) = Self::decrement_counter(&*self.dao, &hour_key).await {
                tracing::warn!(error = %e, key = %hour_key, "回滚小时窗口计数器失败");
            }
            return Err(BulwarkError::SmsRateLimitExceeded {
                window: "hourly".to_string(),
            });
        }

        // 天窗口：24 小时 TTL（limiteron DistributedLimiter.incr_with_ttl 替换 dao.incr）
        let day_key = format!("sms:rate:{}:day:{}", phone, date);
        let day_count = self
            .limiter
            .incr_with_ttl(&day_key, 1, Duration::from_secs(86400))
            .await
            .map_err(|e| BulwarkError::Internal(format!("secure-limiter-incr::{}", e)))?;
        if day_count > self.daily_limit as u64 {
            // 超限，回滚 day 和 hour
            if let Err(e) = Self::decrement_counter(&*self.dao, &day_key).await {
                tracing::warn!(error = %e, key = %day_key, "回滚天窗口计数器失败");
            }
            if let Err(e) = Self::decrement_counter(&*self.dao, &hour_key).await {
                tracing::warn!(error = %e, key = %hour_key, "回滚小时窗口计数器失败");
            }
            return Err(BulwarkError::SmsRateLimitExceeded {
                window: "daily".to_string(),
            });
        }

        Ok(())
    }

    /// 回滚限速计数器（发送失败时调用）。
    pub async fn rollback(&self, phone: &str) -> BulwarkResult<()> {
        validate_phone(phone)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| BulwarkError::Internal(format!("secure-system-time::{}", e)))?;
        let hour_bucket = now.as_secs() / 3600;
        let date = chrono::Utc::now().format("%Y-%m-%d").to_string();

        // 递减小时窗口计数
        let hour_key = format!("sms:rate:{}:hour:{}", phone, hour_bucket);
        Self::decrement_counter(&*self.dao, &hour_key).await?;

        // 递减天窗口计数
        let day_key = format!("sms:rate:{}:day:{}", phone, date);
        Self::decrement_counter(&*self.dao, &day_key).await?;

        Ok(())
    }
}
