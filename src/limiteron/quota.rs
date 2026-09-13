//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `QuotaStorage` 适配器，用 `GarrisonDao::incr` 实现配额消费。
//!
//! `consume` 采用「预检 → 扣减 → 确认」三步：
//! 1. 预检：当前已消费 + cost 超限时直接拒绝，**不扣减配额**（修复旧的
//!    「先 incr 后判断、拒绝不回滚」导致的配额永久损耗）；
//! 2. 扣减：循环 `dao.incr` cost 次（cost=1 时单次，进程内原子）；
//! 3. 确认：扣减后若并发交错导致超限，回滚本次扣减（decr）并拒绝。
//!
//! # meta 滞后语义
//!
//! meta（consumed 快照 + 窗口边界）在扣减成功**之后**写入：并发 `get_quota`
//! 在扣减与 meta 写入之间可能读到滞后的 consumed 快照。限额判断与回滚均以
//! count key（实时值）为准，meta 滞后不影响限流正确性；`get_quota` 返回的
//! consumed 仅为近似快照。

use crate::dao::GarrisonDao;
use crate::error::GarrisonError;
use async_trait::async_trait;
use chrono::Utc;
use limiteron::error::{ConsumeResult, StorageError};
use limiteron::storage::{QuotaInfo, QuotaStorage};
use std::sync::Arc;
use std::time::Duration;

use super::errors::map_to_storage_err;

/// 配额 key 前缀。
const QUOTA_KEY_PREFIX: &str = "limiteron:quota";
/// 配额计数 key：`limiteron:quota:{user_id}:{resource}:count`，存储 u64 计数值。
fn quota_count_key(user_id: &str, resource: &str) -> String {
    format!("{}:{}:{}:count", QUOTA_KEY_PREFIX, user_id, resource)
}
/// 配额元数据 key：`limiteron:quota:{user_id}:{resource}:meta`，存储 `consumed|limit|window_start|window_end`。
fn quota_meta_key(user_id: &str, resource: &str) -> String {
    format!("{}:{}:{}:meta", QUOTA_KEY_PREFIX, user_id, resource)
}

/// `QuotaStorage` 适配器，用 `GarrisonDao::incr` 实现配额消费。
///
/// `consume` 采用「预检 → 扣减 → 确认」三步（见模块文档）。
///
/// # 非原子性声明
///
/// `GarrisonDao` 无通用 `INCRBY` / Lua 接口：预检（get）与扣减（incr）不是
/// 单个原子操作，cost > 1 时扣减本身也是循环单步 incr。并发交错窗口由确认
/// 阶段的回滚兜底（拒绝路径不消耗配额），但中间态计数可能短暂超过 limit。
pub struct GarrisonDaoQuotaStorage {
    pub(super) dao: Arc<dyn GarrisonDao>,
}

impl GarrisonDaoQuotaStorage {
    /// 创建适配器实例。
    ///
    /// # 参数
    /// - `dao`: 内部 DAO 实现。
    pub fn new(dao: Arc<dyn GarrisonDao>) -> Self {
        Self { dao }
    }

    /// 构造拒绝结果（不扣减配额）：remaining / usage_percent 基于当前已消费量计算。
    fn denied_result(limit: u64, consumed: u64) -> ConsumeResult {
        let remaining = limit.saturating_sub(consumed);
        let usage_percent = if limit == 0 {
            100.0
        } else {
            (consumed as f64 / limit as f64) * 100.0
        };
        ConsumeResult {
            allowed: false,
            remaining,
            alert_triggered: usage_percent >= 80.0,
            usage_percent,
        }
    }

    /// 构造允许结果：remaining / usage_percent 基于扣减后的已消费量计算。
    fn allowed_result(limit: u64, consumed: u64) -> ConsumeResult {
        let remaining = limit.saturating_sub(consumed);
        let usage_percent = if limit == 0 {
            100.0
        } else {
            (consumed as f64 / limit as f64) * 100.0
        };
        ConsumeResult {
            allowed: true,
            remaining,
            alert_triggered: usage_percent >= 80.0,
            usage_percent,
        }
    }
}

#[async_trait]
impl QuotaStorage for GarrisonDaoQuotaStorage {
    async fn get_quota(
        &self,
        user_id: &str,
        resource: &str,
    ) -> Result<Option<QuotaInfo>, StorageError> {
        let meta_key = quota_meta_key(user_id, resource);
        let count_key = quota_count_key(user_id, resource);

        let meta = self.dao.get(&meta_key).await.map_err(map_to_storage_err)?;
        let count = self.dao.get(&count_key).await.map_err(map_to_storage_err)?;

        match (meta, count) {
            (Some(meta_str), Some(count_str)) => {
                // M-3: parse 失败显性化 — 脏数据返回 Err（fail-fast）
                let consumed: u64 = count_str.parse().map_err(|e| {
                    map_to_storage_err(GarrisonError::Dao(format!(
                        "limiteron-quota-count-parse-failed::{}::{}::{}",
                        count_key, count_str, e
                    )))
                })?;
                let parts: Vec<&str> = meta_str.split('|').collect();
                if parts.len() != 4 {
                    return Err(map_to_storage_err(GarrisonError::Dao(format!(
                        "limiteron-quota-meta-format-error::{}::{}::{}",
                        meta_key,
                        meta_str,
                        parts.len()
                    ))));
                }
                let limit: u64 = parts[1].parse().map_err(|e| {
                    map_to_storage_err(GarrisonError::Dao(format!(
                        "limiteron-quota-limit-parse-failed::{}::{}::{}",
                        meta_key, parts[1], e
                    )))
                })?;
                let window_start_ts: i64 = parts[2].parse().map_err(|e| {
                    map_to_storage_err(GarrisonError::Dao(format!(
                        "limiteron-quota-window-start-parse-failed::{}::{}::{}",
                        meta_key, parts[2], e
                    )))
                })?;
                let window_end_ts: i64 = parts[3].parse().map_err(|e| {
                    map_to_storage_err(GarrisonError::Dao(format!(
                        "limiteron-quota-window-end-parse-failed::{}::{}::{}",
                        meta_key, parts[3], e
                    )))
                })?;
                let window_start = chrono::DateTime::from_timestamp(window_start_ts, 0)
                    .ok_or_else(|| {
                        map_to_storage_err(GarrisonError::Dao(format!(
                            "limiteron-quota-window-start-datetime-failed::{}",
                            window_start_ts
                        )))
                    })?;
                let window_end =
                    chrono::DateTime::from_timestamp(window_end_ts, 0).ok_or_else(|| {
                        map_to_storage_err(GarrisonError::Dao(format!(
                            "limiteron-quota-window-end-datetime-failed::{}",
                            window_end_ts
                        )))
                    })?;
                Ok(Some(QuotaInfo {
                    consumed,
                    limit,
                    window_start,
                    window_end,
                }))
            },
            _ => Ok(None),
        }
    }

    async fn consume(
        &self,
        user_id: &str,
        resource: &str,
        cost: u64,
        limit: u64,
        window: Duration,
    ) -> Result<ConsumeResult, StorageError> {
        let count_key = quota_count_key(user_id, resource);
        let meta_key = quota_meta_key(user_id, resource);
        let ttl = window.as_secs();

        // ---- 预检：已消费 + cost 超限时直接拒绝，不扣减配额 ----
        //（修复旧实现「先 incr cost 次后判 allowed、拒绝不回滚」导致的
        //  配额被拒绝请求永久消耗的问题）
        let current: u64 = match self.dao.get(&count_key).await.map_err(map_to_storage_err)? {
            Some(v) => v.parse().map_err(|e| {
                map_to_storage_err(GarrisonError::Dao(format!(
                    "limiteron-quota-count-parse-failed::{}::{}::{}",
                    count_key, v, e
                )))
            })?,
            None => 0,
        };
        // cost 校验：cost = 0 的消费为纯 no-op——不扣减、不写 meta（旧实现会
        // 残留一条 count 缺失的 orphan meta 键），直接返回允许。
        if cost == 0 {
            return Ok(Self::allowed_result(limit, current));
        }
        if current.saturating_add(cost) > limit {
            return Ok(Self::denied_result(limit, current));
        }

        // ---- 扣减：循环 incr cost 次（cost=1 时单次，进程内原子）----
        // cost>1 时非原子（并发可交错），由下方确认阶段兜底
        let mut new_count = current;
        for _ in 0..cost {
            new_count = self
                .dao
                .incr(&count_key, ttl)
                .await
                .map_err(map_to_storage_err)?;
        }

        // ---- 确认：并发交错导致超限时回滚本次扣减并拒绝 ----
        if new_count > limit {
            tracing::warn!(
                user_id,
                resource,
                cost,
                new_count,
                limit,
                "limiteron-quota: 并发交错导致超限扣减，回滚本次消费"
            );
            for _ in 0..cost {
                if let Err(e) = self.dao.decr(&count_key).await {
                    tracing::warn!(
                        user_id,
                        resource,
                        error = %e,
                        "limiteron-quota: 回滚 decr 失败（best-effort）"
                    );
                }
            }
            return Ok(Self::denied_result(limit, new_count.saturating_sub(cost)));
        }

        // 初始化/更新元数据（首次消费时设置窗口）
        //（meta 在扣减成功后写入，滞后窗口见模块文档「meta 滞后语义」）
        let now = Utc::now();
        let window_end = now
            + chrono::Duration::from_std(window)
                .unwrap_or_else(|_| chrono::Duration::seconds(window.as_secs() as i64));
        let meta_val = format!(
            "{}|{}|{}|{}",
            new_count,
            limit,
            now.timestamp(),
            window_end.timestamp()
        );
        // 用 set 覆盖元数据（保留 TTL 与窗口一致）
        self.dao
            .set(&meta_key, &meta_val, ttl)
            .await
            .map_err(map_to_storage_err)?;

        Ok(Self::allowed_result(limit, new_count))
    }

    async fn reset(
        &self,
        user_id: &str,
        resource: &str,
        _limit: u64,
        _window: Duration,
    ) -> Result<(), StorageError> {
        let count_key = quota_count_key(user_id, resource);
        let meta_key = quota_meta_key(user_id, resource);
        self.dao
            .delete(&count_key)
            .await
            .map_err(map_to_storage_err)?;
        self.dao.delete(&meta_key).await.map_err(map_to_storage_err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::InMemoryDao;

    fn make_dao() -> Arc<dyn GarrisonDao> {
        Arc::new(InMemoryDao::new())
    }

    // --- GarrisonDaoQuotaStorage 测试 ---

    #[tokio::test]
    async fn quota_consume_within_limit() {
        let quota = GarrisonDaoQuotaStorage::new(make_dao());
        let result = quota
            .consume("user1", "sms", 1, 5, Duration::from_secs(3600))
            .await
            .unwrap();
        assert!(result.allowed);
        assert_eq!(result.remaining, 4);
    }

    #[tokio::test]
    async fn quota_consume_exceeds_limit() {
        let quota = GarrisonDaoQuotaStorage::new(make_dao());
        // 消费 5 次，第 6 次超限
        for _ in 0..5 {
            let r = quota
                .consume("user2", "sms", 1, 5, Duration::from_secs(3600))
                .await
                .unwrap();
            assert!(r.allowed);
        }
        let result = quota
            .consume("user2", "sms", 1, 5, Duration::from_secs(3600))
            .await
            .unwrap();
        assert!(!result.allowed);
        assert_eq!(result.remaining, 0);
    }

    #[tokio::test]
    async fn quota_reset_clears_counters() {
        let quota = GarrisonDaoQuotaStorage::new(make_dao());
        quota
            .consume("user3", "sms", 3, 10, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(quota.get_quota("user3", "sms").await.unwrap().is_some());

        quota
            .reset("user3", "sms", 10, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(quota.get_quota("user3", "sms").await.unwrap().is_none());
    }

    // --- M-3: unwrap_or(0) 静默吞错修复测试 ---

    /// M-3: QuotaStorage::get_quota 遇到脏 count 数据时返回错误（fail-fast）。
    #[tokio::test]
    async fn m3_quota_get_quota_dirty_count_returns_err() {
        let quota = GarrisonDaoQuotaStorage::new(make_dao());
        // 直接注入脏数据：count 是非数字字符串
        quota
            .dao
            .set("limiteron:quota:user1:res:count", "not-a-number", 0)
            .await
            .unwrap();
        quota
            .dao
            .set("limiteron:quota:user1:res:meta", "1|5|1000|2000", 0)
            .await
            .unwrap();
        let result = quota.get_quota("user1", "res").await;
        assert!(
            result.is_err(),
            "脏 count 数据应返回错误，实际: {:?}",
            result
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("limiteron 配额计数解析失败"),
            "错误消息应包含翻译后的配额计数解析失败提示，实际: {}",
            err_msg
        );
    }

    /// M-3: QuotaStorage::get_quota 遇到脏 meta 数据时返回错误（fail-fast）。
    #[tokio::test]
    async fn m3_quota_get_quota_dirty_meta_returns_err() {
        let quota = GarrisonDaoQuotaStorage::new(make_dao());
        quota
            .dao
            .set("limiteron:quota:user2:res:count", "1", 0)
            .await
            .unwrap();
        // meta 中 limit 字段是非数字
        quota
            .dao
            .set(
                "limiteron:quota:user2:res:meta",
                "1|not-number|1000|2000",
                0,
            )
            .await
            .unwrap();
        let result = quota.get_quota("user2", "res").await;
        assert!(
            result.is_err(),
            "脏 meta 数据应返回错误，实际: {:?}",
            result
        );
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("limiteron 配额上限解析失败"),
            "错误消息应包含翻译后的配额上限解析失败提示，实际: {}",
            err_msg
        );
    }

    // --- 补充覆盖：quota 辅助函数与边界路径 ---

    /// quota_count_key 与 quota_meta_key 生成正确的 key 格式。
    #[test]
    fn quota_key_format_correct() {
        assert_eq!(
            quota_count_key("user1", "sms"),
            "limiteron:quota:user1:sms:count"
        );
        assert_eq!(
            quota_meta_key("user1", "sms"),
            "limiteron:quota:user1:sms:meta"
        );
        assert_eq!(quota_count_key("", ""), "limiteron:quota:::count");
    }

    /// get_quota 在 consume 后返回正确的 QuotaInfo（round-trip）。
    #[tokio::test]
    async fn quota_get_quota_after_consume_returns_valid_info() {
        let quota = GarrisonDaoQuotaStorage::new(make_dao());
        quota
            .consume("user_rt", "res", 1, 10, Duration::from_secs(3600))
            .await
            .unwrap();
        let info = quota.get_quota("user_rt", "res").await.unwrap();
        assert!(info.is_some(), "consume 后 get_quota 应返回 Some");
        let info = info.unwrap();
        assert_eq!(info.consumed, 1);
        assert_eq!(info.limit, 10);
    }

    /// consume cost > 1 时正确递增计数。
    #[tokio::test]
    async fn quota_consume_cost_greater_than_one() {
        let quota = GarrisonDaoQuotaStorage::new(make_dao());
        let result = quota
            .consume("user_cost", "res", 5, 10, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(result.allowed, "5 <= 10 应允许");
        assert_eq!(result.remaining, 5, "remaining = 10 - 5 = 5");
        assert!(
            result.usage_percent >= 50.0,
            "usage_percent 应 >= 50%，实际: {}",
            result.usage_percent
        );
    }

    /// consume 在 limit=0 时 usage_percent 为 100%。
    #[tokio::test]
    async fn quota_consume_limit_zero_usage_100_percent() {
        let quota = GarrisonDaoQuotaStorage::new(make_dao());
        let result = quota
            .consume("user_zero", "res", 1, 0, Duration::from_secs(60))
            .await
            .unwrap();
        // limit=0, count=1 > 0 → 不允许
        assert!(!result.allowed, "count 1 > limit 0 应拒绝");
        assert_eq!(result.remaining, 0);
        assert_eq!(
            result.usage_percent, 100.0,
            "limit=0 时 usage_percent 应为 100%"
        );
    }

    /// consume 在使用率达到 80% 时触发 alert_triggered。
    #[tokio::test]
    async fn quota_consume_alert_triggered_at_80_percent() {
        let quota = GarrisonDaoQuotaStorage::new(make_dao());
        // 消费 8 次（limit=10），usage=80%，应触发 alert
        let result = quota
            .consume("user_alert", "res", 8, 10, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(
            result.alert_triggered,
            "usage 80% 应触发 alert，实际 usage_percent: {}",
            result.usage_percent
        );
        assert!(result.usage_percent >= 80.0);
    }

    /// consume 在使用率低于 80% 时不触发 alert。
    #[tokio::test]
    async fn quota_consume_no_alert_below_80_percent() {
        let quota = GarrisonDaoQuotaStorage::new(make_dao());
        let result = quota
            .consume("user_noalert", "res", 7, 10, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(
            !result.alert_triggered,
            "usage 70% 不应触发 alert，实际 usage_percent: {}",
            result.usage_percent
        );
    }

    /// get_quota meta 格式错误（段数不对）返回错误。
    #[tokio::test]
    async fn quota_get_quota_meta_wrong_parts_returns_err() {
        let quota = GarrisonDaoQuotaStorage::new(make_dao());
        // 注入 count 正确但 meta 段数不对的数据
        quota
            .dao
            .set("limiteron:quota:user_w:res:count", "1", 0)
            .await
            .unwrap();
        // meta 只有 2 段（应为 4 段）
        quota
            .dao
            .set("limiteron:quota:user_w:res:meta", "1|5", 0)
            .await
            .unwrap();
        let result = quota.get_quota("user_w", "res").await;
        assert!(result.is_err(), "meta 段数不对应返回错误");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("limiteron 配额元数据格式错误"),
            "错误消息应包含翻译后的配额元数据格式错误提示，实际: {}",
            err_msg
        );
    }

    /// get_quota window_start_ts 无效时返回错误。
    #[tokio::test]
    async fn quota_get_quota_invalid_window_start_ts_returns_err() {
        let quota = GarrisonDaoQuotaStorage::new(make_dao());
        quota
            .dao
            .set("limiteron:quota:user_ts:res:count", "1", 0)
            .await
            .unwrap();
        // window_start_ts 不是数字
        quota
            .dao
            .set("limiteron:quota:user_ts:res:meta", "1|5|not_number|2000", 0)
            .await
            .unwrap();
        let result = quota.get_quota("user_ts", "res").await;
        assert!(result.is_err(), "无效 window_start_ts 应返回错误");
    }

    /// get_quota 仅 count 存在但 meta 缺失时返回 None。
    #[tokio::test]
    async fn quota_get_quota_count_without_meta_returns_none() {
        let quota = GarrisonDaoQuotaStorage::new(make_dao());
        // 只有 count 没有 meta
        quota
            .dao
            .set("limiteron:quota:user_nm:res:count", "5", 0)
            .await
            .unwrap();
        let result = quota.get_quota("user_nm", "res").await.unwrap();
        assert!(result.is_none(), "count 有但 meta 缺失时应返回 None");
    }

    /// 被拒绝的消费不扣减配额（预检拒绝）：拒绝后计数不变，剩余额度留给小请求。
    #[tokio::test]
    async fn quota_consume_denied_does_not_consume_quota() {
        let quota = GarrisonDaoQuotaStorage::new(make_dao());
        // 消费 3（allowed，count=3）
        let r1 = quota
            .consume("user_rb", "res", 3, 5, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(r1.allowed);

        // cost=5：3+5 > 5 → 预检拒绝，不扣减
        let denied = quota
            .consume("user_rb", "res", 5, 5, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(!denied.allowed, "3+5 > 5 应拒绝");
        assert_eq!(denied.remaining, 2, "拒绝路径 remaining 基于已消费 3 计算");
        assert!(
            (denied.usage_percent - 60.0).abs() < f64::EPSILON,
            "拒绝路径 usage 应为 60%，实际: {}",
            denied.usage_percent
        );

        // 计数未被拒绝请求推高
        let info = quota.get_quota("user_rb", "res").await.unwrap().unwrap();
        assert_eq!(info.consumed, 3, "被拒绝的请求不应消耗配额");

        // 小请求仍可用剩余额度
        let ok = quota
            .consume("user_rb", "res", 2, 5, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(ok.allowed, "拒绝后剩余 2 额度应可供小请求使用");
        assert_eq!(ok.remaining, 0);
    }

    /// cost=0 的消费：不递增计数（count key 不产生），视为允许。
    #[tokio::test]
    async fn quota_consume_zero_cost_noop() {
        let quota = GarrisonDaoQuotaStorage::new(make_dao());
        let result = quota
            .consume("user_zc", "res", 0, 5, Duration::from_secs(60))
            .await
            .unwrap();
        assert!(result.allowed, "cost=0 应允许");
        assert_eq!(result.remaining, 5, "cost=0 不消耗额度");
        // count key 未创建（get_quota 因 count 缺失返回 None）
        let info = quota.get_quota("user_zc", "res").await.unwrap();
        assert!(info.is_none(), "cost=0 不应创建 count key");
    }
}
