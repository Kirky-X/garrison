// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! SmsRateLimiter 薄包装：双窗口（小时/天）渐进式限速。
//!
//! 窗口判定与补偿委托泛型内核 [`DualWindowQuota`]（limiteron `QuotaStorage`
//! 账本），本文件只保留 SMS 特有面：手机号 normalize/validate、`sms:` 账本
//! 命名空间、`SmsRateLimitExceeded` 错误变体与窗口桶快照类型。
//!
//! 键形说明：账本键 `quota:{hour,day}:sms:{phone}`（窗口滚动由 TTL 表达），
//! 与旧时间桶键 `sms:rate:{phone}:{hour:{bucket},day:{date}}` 不同——旧 key
//! 依赖 TTL 自然过期，无迁移需求（见 CHANGELOG）。

use super::{GarrisonDao, GarrisonResult, SmsRateLimiter};
use crate::error::GarrisonError;
use crate::limiteron::storage::GarrisonDaoQuotaStorage;
use crate::secure::dual_window::{DualWindowError, DualWindowQuota};
use std::sync::Arc;

/// 每小时秒数（用于时间桶快照计算）。
const SECONDS_PER_HOUR: u64 = 3600;

/// SMS 账本命名空间（与 email 账本隔离，键形 `quota:{hour,day}:sms:{phone}`）。
const LEDGER_NAMESPACE: &str = "sms";

/// 限速窗口桶信息（`check_and_increment_with` 返回，供 `rollback_with` 传回）。
///
/// 账本模型下窗口滚动由存储 TTL 表达、键名不含时间成分，跨小时/天边界的
/// 回滚命中同一账本；本快照保留为公开 API 兼容与观测用途，
/// [`rollback_with`](SmsRateLimiter::rollback_with) 不再需要按它重算键。
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

/// 账本身份标识（命名空间 + 规范化手机号，与 email 账本隔离）。
fn ledger_identity(phone: &str) -> String {
    format!("{LEDGER_NAMESPACE}:{phone}")
}

impl SmsRateLimiter {
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
    /// 委托 [`GarrisonDao::decr`] 在单次 DAO 调用内完成 get → parse → update/delete，
    /// 消除原三步组合的 TOCTOU 竞态（fix-refresh-race-and-test-contracts /）。
    /// 限速窗口补偿已由 `QuotaStorage::refund` 账本原语承载
    /// （见 [`DualWindowQuota`]）；本方法保留给非窗口计数器
    /// （`sms:unverified:{phone}` 连续未验证计数）使用。
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

    /// 检查并递增限速计数器。
    ///
    /// 超限时账本自回滚（`QuotaStorage` 适配器内部 `decr` 补偿），
    /// 拒绝的请求不消耗配额。
    ///
    /// # 回滚错误处理策略（统一约定）
    ///
    /// 回滚是 best-effort 修正：失败记录 `tracing::warn`（含 key 与错误）并继续，
    /// 不覆盖本次调用的主错误（限流拒绝）。代价是账本可能残留膨胀至 TTL
    /// 自然过期（小时窗口最多 1h、天窗口最多 24h），运维通过 warn 告警感知。
    /// [`rollback`](Self::rollback) / [`rollback_with`](Self::rollback_with) 无主错误可保留，
    /// 故聚合后返回首个回滚错误——两条路径均全程 warn，观测语义一致。
    pub async fn check_and_increment(&self, phone: &str) -> GarrisonResult<()> {
        self.check_and_increment_with(phone).await.map(|_| ())
    }

    /// [`check_and_increment`](Self::check_and_increment) 的窗口信息携带版本。
    ///
    /// 返回本次递增的窗口桶快照；账本模型下回滚不依赖它（键无时间成分），
    /// 发送失败路径仍可将其原样传给
    /// [`rollback_with`](Self::rollback_with)（公开 API 兼容）。
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

    /// 回滚限速计数器（发送失败时调用）。
    ///
    /// 账本模型下键名不含时间成分，本方法按当前身份退还两个窗口账本；
    /// 跨小时/天边界时命中的仍是 check 时的同一账本（已随窗口过期即 no-op）。
    ///
    /// # 错误
    /// 聚合执行小时 + 天两次退还（首个失败不中断第二个），返回首个错误。
    pub async fn rollback(&self, phone: &str) -> GarrisonResult<()> {
        let phone = normalize_phone(phone);
        validate_phone(&phone)?;
        self.kernel.refund_windows(&ledger_identity(&phone)).await
    }

    /// [`rollback`](Self::rollback) 的窗口信息携带版本（优先使用）。
    ///
    /// 账本模型下 `windows` 不参与键定位（保留为公开 API 兼容参数）；
    /// 退还语义与 [`rollback`](Self::rollback) 一致。
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
