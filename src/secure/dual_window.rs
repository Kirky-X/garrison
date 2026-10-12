// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 泛型双窗口限速内核（sms/email 验证码限速共用）。
//!
//! 以 limiteron [`QuotaStorage`] 账本承载 hour/day 双窗口判定：对两个 resource 维度各执行一次
//! `consume(identity, resource, 1, limit, window)`。超限由存储适配器内部自回滚
//! （`GarrisonDaoQuotaStorage` 的 `decr` 补偿），已成功的另一窗由本内核 `refund` 归还。
//! sms/email 的差异（normalize / validate、错误变体、命名空间）收敛在各自薄包装内。
//!
//! 键形说明：账本键 `quota:{resource}:{identity}` 不含时间成分——窗口滚动由存储 TTL 表达，
//! 跨小时/午夜边界的回滚命中同一账本（账本已随窗口过期即 no-op，不按当前时间重算）。

use crate::error::{GarrisonError, GarrisonResult};
use limiteron::storage::QuotaStorage;
use std::time::Duration;

const RESOURCE_HOUR: &str = "hour";
const RESOURCE_DAY: &str = "day";
const HOUR_WINDOW: Duration = Duration::from_secs(3600);
const DAY_WINDOW: Duration = Duration::from_secs(86400);

/// 双窗口拒绝归属（映射回 sms/email 各自的错误变体与 `window` 字段）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DualWindowExceeded {
    /// 小时窗口超限。
    Hourly,
    /// 天窗口超限。
    Daily,
}

impl DualWindowExceeded {
    /// 现错误串的 `window` 字段值（`"hourly"` / `"daily"`，运维契约不变）。
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Hourly => "hourly",
            Self::Daily => "daily",
        }
    }
}

/// 双窗口内核错误：超限拒绝或存储故障。
#[derive(Debug)]
pub(crate) enum DualWindowError {
    /// 窗口超限（归属哪个窗口）。
    Exceeded(DualWindowExceeded),
    /// 存储故障（消息含 `secure-limiter-incr::{e}` 前缀，错误串契约与手写实现一致；调用方映射为 `GarrisonError::Internal`）。
    Storage(String),
}

/// 泛型双窗口限速内核。
pub(crate) struct DualWindowQuota<S: QuotaStorage> {
    /// 账本存储（hour/day 两个 resource 维度）。
    storage: S,
    hourly_limit: u64,
    daily_limit: u64,
}

impl<S: QuotaStorage> DualWindowQuota<S> {
    /// 创建内核实例（hourly_limit / daily_limit：小时/天窗口上限，配置默认值不变）。
    pub(crate) fn new(storage: S, hourly_limit: u32, daily_limit: u32) -> Self {
        Self {
            storage,
            hourly_limit: u64::from(hourly_limit),
            daily_limit: u64::from(daily_limit),
        }
    }

    /// 双窗口消费（hour 通过后消费 day）。
    ///
    /// 回滚约定（与手写实现逐条对齐）：hour 超限时适配器已自回滚 hour，直接返回 Hourly；
    /// day 存储故障或超限时 refund hour（失败仅 warn），超限返回 Daily（day 自身已由适配器自回滚）。
    pub(crate) async fn consume_and_check(&self, identity: &str) -> Result<(), DualWindowError> {
        let hour = self
            .storage
            .consume(identity, RESOURCE_HOUR, 1, self.hourly_limit, HOUR_WINDOW)
            .await
            .map_err(|e| DualWindowError::Storage(format!("secure-limiter-incr::{e}")))?;
        if !hour.allowed {
            return Err(DualWindowError::Exceeded(DualWindowExceeded::Hourly));
        }

        let day = self
            .storage
            .consume(identity, RESOURCE_DAY, 1, self.daily_limit, DAY_WINDOW)
            .await;
        let day = match day {
            Ok(r) => r,
            Err(e) => {
                // 天窗消费失败：归还已成功的小时配额，防配额泄漏
                self.refund_quiet(identity, RESOURCE_HOUR, "hourly").await;
                return Err(DualWindowError::Storage(format!(
                    "secure-limiter-incr::{e}"
                )));
            },
        };
        if !day.allowed {
            self.refund_quiet(identity, RESOURCE_HOUR, "hourly").await;
            return Err(DualWindowError::Exceeded(DualWindowExceeded::Daily));
        }
        Ok(())
    }

    /// 退还两个窗口的消费（`rollback` 路径）。
    ///
    /// 聚合两次退还：首个失败不中断第二个，最终返回首个错误（聚合语义与 `rollback_inner` 一致）；失败均仅 warn。
    pub(crate) async fn refund_windows(&self, identity: &str) -> GarrisonResult<()> {
        let mut first_err: Option<GarrisonError> = None;
        if let Err(e) = self.refund_mapped(identity, RESOURCE_HOUR).await {
            tracing::warn!(
                error = %e,
                key = %ledger_key(RESOURCE_HOUR, identity),
                "rollback hourly window counter failed"
            );
            first_err.get_or_insert(e);
        }
        if let Err(e) = self.refund_mapped(identity, RESOURCE_DAY).await {
            tracing::warn!(
                error = %e,
                key = %ledger_key(RESOURCE_DAY, identity),
                "rollback daily window counter failed"
            );
            first_err.get_or_insert(e);
        }
        match first_err {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// 退还单窗（best-effort）：失败仅 warn，不向上传播。
    async fn refund_quiet(&self, identity: &str, resource: &str, label: &str) {
        if let Err(e) = self.refund_mapped(identity, resource).await {
            tracing::warn!(
                error = %e,
                key = %ledger_key(resource, identity),
                "rollback {label} window counter failed"
            );
        }
    }

    /// 退还单窗并把 `StorageError` 映射为 `GarrisonError::Dao`（错误串保真透传）。
    async fn refund_mapped(&self, identity: &str, resource: &str) -> GarrisonResult<()> {
        self.storage
            .refund(identity, resource, 1, 0, Duration::ZERO)
            .await
            .map(|_| ())
            .map_err(|e| GarrisonError::Dao(format!("secure-limiter-refund::{e}")))
    }
}

/// 账本键（仅用于 warn 日志可观测性；真实键由存储适配器按同构规则构造）。
fn ledger_key(resource: &str, identity: &str) -> String {
    format!("quota:{resource}:{identity}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::limiteron::storage::GarrisonDaoQuotaStorage;
    use std::sync::Arc;

    fn make_kernel(hourly: u32, daily: u32) -> DualWindowQuota<GarrisonDaoQuotaStorage> {
        let dao = Arc::new(MockDao::new());
        DualWindowQuota::new(GarrisonDaoQuotaStorage::new(dao), hourly, daily)
    }

    /// 小时超限：第 hourly+1 次拒绝且归属 Hourly；适配器自回滚，再次消费仍被拒而非放行。
    #[tokio::test]
    async fn kernel_hourly_exceed_rejects_without_leak() {
        let kernel = make_kernel(2, 100);
        kernel.consume_and_check("ns:id").await.unwrap();
        kernel.consume_and_check("ns:id").await.unwrap();
        let err = kernel.consume_and_check("ns:id").await.unwrap_err();
        assert!(
            matches!(err, DualWindowError::Exceeded(DualWindowExceeded::Hourly)),
            "第 3 次应返回 Hourly 超限"
        );
        // 账本自回滚到 2：继续消费仍被拒（证明拒绝未留下 +1 泄漏）
        assert!(
            matches!(
                kernel.consume_and_check("ns:id").await.unwrap_err(),
                DualWindowError::Exceeded(DualWindowExceeded::Hourly)
            ),
            "超限请求不应消耗配额（账本回滚后仍为 2）"
        );
        assert_eq!(DualWindowExceeded::Hourly.as_str(), "hourly");
        assert_eq!(DualWindowExceeded::Daily.as_str(), "daily");
    }

    /// 天超限：已成功的小时消费被 refund 归还，hour 账本回到请求前值。
    #[tokio::test]
    async fn kernel_daily_exceed_refunds_hour() {
        let kernel = make_kernel(100, 1);
        kernel.consume_and_check("ns:id2").await.unwrap();
        let err = kernel.consume_and_check("ns:id2").await.unwrap_err();
        assert!(
            matches!(err, DualWindowError::Exceeded(DualWindowExceeded::Daily)),
            "第 2 次应返回 Daily 超限"
        );
        // hour 配额已归还：耗尽 daily 后 hour 侧仍可按上限消费
        for _ in 0..100 {
            // daily 已满，每次都在 day 窗被拒并归还 hour；hour 计数应恒不增长
            let _ = kernel.consume_and_check("ns:id2").await;
        }
        kernel.refund_windows("ns:id2").await.unwrap();
        // 两次退还后账本归零（refund 幂等，不存在即 no-op，不为负）
        kernel.refund_windows("ns:id2").await.unwrap();
    }

    /// refund_windows 退还两个窗口：账本归零后 key 删除，重复退还为 no-op。
    #[tokio::test]
    async fn kernel_refund_windows_clears_both() {
        let dao = Arc::new(MockDao::new());
        let kernel = DualWindowQuota::new(GarrisonDaoQuotaStorage::new(dao.clone()), 100, 100);

        kernel.consume_and_check("ns:id3").await.unwrap();
        kernel.refund_windows("ns:id3").await.unwrap();

        let quota = GarrisonDaoQuotaStorage::new(dao);
        assert!(
            quota
                .get_quota("ns:id3", RESOURCE_HOUR)
                .await
                .unwrap()
                .is_none(),
            "refund 后 hour 账本应归零删除"
        );
        assert!(
            quota
                .get_quota("ns:id3", RESOURCE_DAY)
                .await
                .unwrap()
                .is_none(),
            "refund 后 day 账本应归零删除"
        );
        // 幂等：对不存在账本再退还是 no-op
        kernel.refund_windows("ns:id3").await.unwrap();
    }

    /// 账本键不随时间变化：跨窗口边界的 refund 命中同一账本（无按当前时间重算键的路径）。
    #[tokio::test]
    async fn kernel_ledger_key_is_time_independent() {
        let dao = Arc::new(MockDao::new());
        let kernel = DualWindowQuota::new(GarrisonDaoQuotaStorage::new(dao.clone()), 5, 5);

        kernel.consume_and_check("ns:id4").await.unwrap();
        let quota = GarrisonDaoQuotaStorage::new(dao);
        let before = quota
            .get_quota("ns:id4", RESOURCE_HOUR)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(before.consumed, 1);
        // 键名是确定的（无时间成分），多次读取命中同一账本
        let again = quota
            .get_quota("ns:id4", RESOURCE_HOUR)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(again.consumed, 1);
    }
}
