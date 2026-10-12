// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! SmsRateLimiter 薄包装：双窗口（小时/天）渐进式限速。
//!
//! 窗口判定与补偿委托泛型内核 [`DualWindowQuota`]（limiteron `QuotaStorage`
//! 账本），本文件只保留 SMS 特有面：手机号 normalize/validate、`sms:` 账本
//! 命名空间、`SmsRateLimitExceeded` 错误变体与窗口桶快照类型。
//!
//! 键形说明：账本键 `quota:{hour,day}:sms:{phone}`（窗口滚动由 TTL 表达）；旧时间桶键无迁移需求（依赖 TTL 自然过期）。

use super::{GarrisonDao, GarrisonResult, SmsRateLimiter};
use crate::error::GarrisonError;
use crate::limiteron::storage::GarrisonDaoQuotaStorage;
use crate::secure::dual_window::{DualWindowError, DualWindowQuota};
use std::sync::Arc;

/// 每小时秒数（用于时间桶快照计算）。
const SECONDS_PER_HOUR: u64 = 3600;

/// SMS 账本命名空间（与 email 账本隔离，键形 `quota:{hour,day}:sms:{phone}`）。
const LEDGER_NAMESPACE: &str = "sms";

/// 限速窗口桶信息（`check_and_increment_with` 返回，供 `rollback_with` 传回）；
/// 账本键不含时间成分，回滚不依赖它，仅为公开 API 兼容与观测用途。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmsRateWindows {
    /// 小时桶索引（Unix 秒 / 3600）。
    pub hour_bucket: u64,
    /// 日期键（UTC，`%Y-%m-%d` 格式）。
    pub date: String,
}

/// 规范化手机号（trim）；防 `" 13800138000 "` 与 `"13800138000"` 生成不同限速 key 静默绕过限速（对齐 email 惯例）。
pub(super) fn normalize_phone(phone: &str) -> String {
    phone.trim().to_string()
}

/// 校验手机号：非空、不含 ':'（防 key 结构破坏）、无控制字符与内部空白（前后空白由 [`normalize_phone`] 剥离）、长度 ≤ 20（防超大 key 耗内存）。
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

/// 账本身份标识（命名空间 + 规范化手机号，与 email 账本隔离）。
fn ledger_identity(phone: &str) -> String {
    format!("{LEDGER_NAMESPACE}:{phone}")
}

impl SmsRateLimiter {
    /// 创建限速器实例：以 [`GarrisonDaoQuotaStorage`] 把 `dao` 桥接为 limiteron `QuotaStorage` 账本，双窗口判定委托 [`DualWindowQuota`]。
    pub fn new(dao: Arc<dyn GarrisonDao>, hourly_limit: u32, daily_limit: u32) -> Self {
        Self {
            kernel: DualWindowQuota::new(
                GarrisonDaoQuotaStorage::new(dao),
                hourly_limit,
                daily_limit,
            ),
        }
    }

    /// 递减非窗口计数器（`sms:unverified:{phone}` 连续未验证计数）；窗口补偿已由账本原语承载。
    ///
    /// `dao.decr` 在单次调用内完成 get → parse → update/delete，消除三步组合的 TOCTOU：
    /// key 不存在或 cur_val == 0 时无副作用，cur_val > 0 时递减（归零删 key，否则保留原 TTL）；非数字值报 `GarrisonError::Dao`。
    pub(super) async fn decrement_counter(dao: &dyn GarrisonDao, key: &str) -> GarrisonResult<()> {
        dao.decr(key).await.map(|_| ())
    }

    /// 计算当前窗口桶快照（公开 API 兼容与观测用途；账本键不含时间成分）。
    fn current_windows() -> GarrisonResult<SmsRateWindows> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| GarrisonError::Internal(format!("secure-system-time::{}", e)))?;
        Ok(SmsRateWindows {
            hour_bucket: now.as_secs() / SECONDS_PER_HOUR,
            date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
        })
    }

    /// 检查并递增限速计数器；超限时账本自回滚，拒绝的请求不消耗配额。
    ///
    /// 回滚为 best-effort：失败仅 `tracing::warn` 且不覆盖主错误（限流拒绝），账本可能残留膨胀至 TTL 自然过期；
    /// [`rollback`](Self::rollback) / [`rollback_with`](Self::rollback_with) 无主错误可保留，故聚合后返回首个回滚错误，两条路径观测语义一致。
    pub async fn check_and_increment(&self, phone: &str) -> GarrisonResult<()> {
        self.check_and_increment_with(phone).await.map(|_| ())
    }

    /// 携带窗口信息的版本：返回本次递增的窗口桶快照（回滚不依赖它，键无时间成分，仅为公开 API 兼容）。
    pub async fn check_and_increment_with(&self, phone: &str) -> GarrisonResult<SmsRateWindows> {
        let phone = normalize_phone(phone);
        validate_phone(&phone)?;
        let windows = Self::current_windows()?;

        self.kernel
            .consume_and_check(&ledger_identity(&phone))
            .await
            .map_err(|e| match e {
                DualWindowError::Exceeded(w) => GarrisonError::SmsRateLimitExceeded {
                    window: w.as_str().to_string(),
                },
                DualWindowError::Storage(msg) => GarrisonError::Internal(msg),
            })?;
        Ok(windows)
    }

    /// 发送失败时回滚两个窗口账本；键名不含时间成分，跨小时/天边界命中同一账本（已随窗口过期即 no-op）。
    ///
    /// 聚合小时 + 天两次退还（首个失败不中断第二个），返回首个错误。
    pub async fn rollback(&self, phone: &str) -> GarrisonResult<()> {
        let phone = normalize_phone(phone);
        validate_phone(&phone)?;
        self.kernel.refund_windows(&ledger_identity(&phone)).await
    }

    /// 带窗口参数的回滚（`windows` 不参与键定位，保留为公开 API 兼容），语义同 [`rollback`](Self::rollback)。
    pub async fn rollback_with(
        &self,
        phone: &str,
        _windows: &SmsRateWindows,
    ) -> GarrisonResult<()> {
        let phone = normalize_phone(phone);
        validate_phone(&phone)?;
        self.kernel.refund_windows(&ledger_identity(&phone)).await
    }
}
