// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! EmailRateLimiter 薄包装：双窗口（小时/天）渐进式限速。
//!
//! 窗口判定与补偿委托泛型内核 [`DualWindowQuota`]（limiteron `QuotaStorage`
//! 账本），本文件只保留邮箱特有面：normalize/validate、`email:` 账本命名
//! 空间、`EmailRateLimitExceeded` 错误变体与窗口桶快照类型。
//!
//! 键形说明：账本键 `quota:{hour,day}:email:{addr}`（窗口滚动由 TTL 表达），
//! 与旧时间桶键 `email:rate:{addr}:{hour:{bucket},day:{date}}` 不同——旧 key
//! 依赖 TTL 自然过期，无迁移需求（见 CHANGELOG）。

use super::{EmailRateLimiter, GarrisonDao, GarrisonResult};
use crate::error::GarrisonError;
use crate::limiteron::storage::GarrisonDaoQuotaStorage;
use crate::secure::dual_window::{DualWindowError, DualWindowQuota};
use std::sync::Arc;

/// 每小时秒数（用于时间桶快照计算）。
const SECONDS_PER_HOUR: u64 = 3600;

/// Email 账本命名空间（与 sms 账本隔离，键形 `quota:{hour,day}:email:{addr}`）。
const LEDGER_NAMESPACE: &str = "email";

/// 限速窗口桶信息（`check_and_increment_inner` 返回）。
///
/// 账本模型下窗口滚动由存储 TTL 表达、键名不含时间成分，跨小时/午夜边界的
/// 回滚命中同一账本；本快照保留为公开 API 兼容与观测用途，
/// [`rollback_inner_with`](EmailRateLimiter::rollback_inner_with) 不再需要按它重算键。
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

/// 账本身份标识（命名空间 + 规范化邮箱，与 sms 账本隔离）。
fn ledger_identity(email: &str) -> String {
    format!("{LEDGER_NAMESPACE}:{email}")
}

impl EmailRateLimiter {
    /// 创建限速器实例。
    ///
    /// 内部以 [`GarrisonDaoQuotaStorage`] 把 `dao` 桥接为 limiteron
    /// `QuotaStorage` 账本，双窗口判定委托 [`DualWindowQuota`]。
    pub fn new(dao: Arc<dyn GarrisonDao>, hourly_limit: u32, daily_limit: u32) -> Self {
        Self {
            kernel: DualWindowQuota::new(
                GarrisonDaoQuotaStorage::new(dao),
                hourly_limit,
                daily_limit,
            ),
        }
    }

    /// 递减计数器（委托 `dao.decr` 原子操作）。
    ///
    /// 限速窗口补偿已由 `QuotaStorage::refund` 账本原语承载（见
    /// [`DualWindowQuota`]）；本方法保留给非窗口计数器
    /// （`email:unverified:{addr}` 连续未验证计数）使用。
    pub(super) async fn decrement_counter(dao: &dyn GarrisonDao, key: &str) -> GarrisonResult<()> {
        dao.decr(key).await.map(|_| ())
    }

    /// 检查并递增限速计数器。
    ///
    /// 超限时账本自回滚（`QuotaStorage` 适配器内部 `decr` 补偿），
    /// 拒绝的请求不消耗配额。
    pub async fn check_and_increment(&self, email: &str) -> GarrisonResult<()> {
        let normalized = normalize_email(email);
        validate_email(&normalized)?;
        self.check_and_increment_inner(&normalized)
            .await
            .map(|_| ())
    }

    /// 内部实现：接受已规范化的邮箱，避免重复 normalize。
    ///
    /// 返回本次递增的窗口桶快照；账本模型下回滚不依赖它（键无时间成分），
    /// 发送失败路径仍可将其原样传给
    /// [`rollback_inner_with`](Self::rollback_inner_with)（调用方零改动）。
    pub(super) async fn check_and_increment_inner(
        &self,
        normalized: &str,
    ) -> GarrisonResult<EmailRateWindows> {
        let windows = current_windows()?;
        self.kernel
            .consume_and_check(&ledger_identity(normalized))
            .await
            .map_err(|e| match e {
                DualWindowError::Exceeded(w) => GarrisonError::EmailRateLimitExceeded {
                    window: w.as_str().to_string(),
                },
                DualWindowError::Storage(msg) => GarrisonError::Internal(msg),
            })?;
        Ok(windows)
    }

    /// 回滚限速计数器（发送失败时调用）。
    ///
    /// 账本模型下键名不含时间成分，本方法按当前身份退还两个窗口账本；
    /// 跨小时/午夜边界时命中的仍是 check 时的同一账本（已随窗口过期即 no-op）。
    pub async fn rollback(&self, email: &str) -> GarrisonResult<()> {
        let normalized = normalize_email(email);
        validate_email(&normalized)?;
        self.kernel
            .refund_windows(&ledger_identity(&normalized))
            .await
    }

    /// 内部实现：使用调用方提供的窗口桶信息回滚（优先使用）。
    ///
    /// 账本模型下 `windows` 不参与键定位（保留为调用方兼容参数）；
    /// 退还语义与 [`rollback`](Self::rollback) 一致。
    pub(super) async fn rollback_inner_with(
        &self,
        normalized: &str,
        _windows: &EmailRateWindows,
    ) -> GarrisonResult<()> {
        self.kernel
            .refund_windows(&ledger_identity(normalized))
            .await
    }
}

/// 计算当前窗口桶快照（公开 API 兼容与观测用途；账本键不含时间成分）。
fn current_windows() -> GarrisonResult<EmailRateWindows> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| GarrisonError::Internal(format!("secure-system-time::{}", e)))?;
    Ok(EmailRateWindows {
        hour_bucket: now.as_secs() / SECONDS_PER_HOUR,
        date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
    })
}
