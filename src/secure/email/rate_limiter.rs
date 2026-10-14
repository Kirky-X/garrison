// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! EmailRateLimiter 薄包装：双窗口（小时/天）渐进式限速。
//!
//! 窗口判定与补偿委托泛型内核 `DualWindowQuota`（limiteron `QuotaStorage` 账本），
//! 本文件只保留邮箱特有面：normalize/validate、`email:` 账本命名空间、
//! `EmailRateLimitExceeded` 错误变体与窗口桶快照类型。
//!
//! 键形说明：账本键 `quota:{hour,day}:email:{addr}`，窗口滚动由 TTL 表达、键名不含时间成分。

use super::{EmailRateLimiter, GarrisonDao, GarrisonResult};
use crate::error::GarrisonError;
use crate::limiteron::storage::GarrisonDaoQuotaStorage;
use crate::secure::dual_window::{DualWindowError, DualWindowQuota};
use std::sync::Arc;

const SECONDS_PER_HOUR: u64 = 3600;

/// Email 账本命名空间（与 sms 账本隔离，键形 `quota:{hour,day}:email:{addr}`）。
const LEDGER_NAMESPACE: &str = "email";

/// 限速窗口桶信息（`check_and_increment_inner` 返回）。
///
/// 账本模型下窗口滚动由存储 TTL 表达、键名不含时间成分，跨小时/午夜边界的回滚命中
/// 同一账本；本快照保留为公开 API 兼容与观测用途，回滚不依赖它重算键。
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

/// 校验邮箱格式：非空、无控制字符、含 `@`、不含 `:`（防 key 注入）、长度 <= 254（DoS 防护）。
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
    /// 创建限速器实例：内部以 [`GarrisonDaoQuotaStorage`] 把 `dao` 桥接为 limiteron
    /// `QuotaStorage` 账本，双窗口判定委托 `DualWindowQuota`。
    pub fn new(dao: Arc<dyn GarrisonDao>, hourly_limit: u32, daily_limit: u32) -> Self {
        Self {
            kernel: DualWindowQuota::new(
                GarrisonDaoQuotaStorage::new(dao),
                hourly_limit,
                daily_limit,
            ),
        }
    }

    /// 递减非窗口计数器（`email:unverified:{addr}` 连续未验证计数）；窗口补偿已由账本原语承载。
    pub(super) async fn decrement_counter(dao: &dyn GarrisonDao, key: &str) -> GarrisonResult<()> {
        dao.decr(key).await.map(|_| ())
    }

    /// 检查并递增限速计数器；超限时账本自回滚，拒绝的请求不消耗配额。
    pub async fn check_and_increment(&self, email: &str) -> GarrisonResult<()> {
        let normalized = normalize_email(email);
        validate_email(&normalized)?;
        self.check_and_increment_inner(&normalized)
            .await
            .map(|_| ())
    }

    /// 接受已规范化邮箱（避免重复 normalize），返回窗口桶快照（账本模型下回滚不依赖它，仅为调用方兼容）。
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

    /// 发送失败时回滚两个窗口账本；键名不含时间成分，跨小时/午夜边界命中同一账本（已过期即 no-op）。
    pub async fn rollback(&self, email: &str) -> GarrisonResult<()> {
        let normalized = normalize_email(email);
        validate_email(&normalized)?;
        self.kernel
            .refund_windows(&ledger_identity(&normalized))
            .await
    }

    /// 带窗口桶参数的回滚（`windows` 不参与键定位，保留为调用方兼容），语义同 [`rollback`](Self::rollback)。
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
