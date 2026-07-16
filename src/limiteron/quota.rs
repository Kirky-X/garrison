//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `QuotaStorage` 适配器，用 `BulwarkDao::incr` 实现配额消费。
//!
//! `consume` 通过循环 `dao.incr` 实现：cost=1 时单次 incr（进程内原子），
//! cost>1 时多次 incr（非原子，中间可能被其他请求插入）。

use crate::dao::BulwarkDao;
use crate::error::BulwarkError;
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

/// `QuotaStorage` 适配器，用 `BulwarkDao::incr` 实现配额消费。
///
/// `consume` 通过循环 `dao.incr` 实现：cost=1 时单次 incr（进程内原子），
/// cost>1 时多次 incr（非原子，中间可能被其他请求插入）。
pub struct BulwarkDaoQuotaStorage {
    pub(super) dao: Arc<dyn BulwarkDao>,
}

impl BulwarkDaoQuotaStorage {
    /// 创建适配器实例。
    ///
    /// # 参数
    /// - `dao`: 内部 DAO 实现。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self { dao }
    }
}

#[async_trait]
impl QuotaStorage for BulwarkDaoQuotaStorage {
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
                    map_to_storage_err(BulwarkError::Dao(format!(
                        "get_quota parse 失败 (count, key={}, val={}): {}",
                        count_key, count_str, e
                    )))
                })?;
                let parts: Vec<&str> = meta_str.split('|').collect();
                if parts.len() != 4 {
                    return Err(map_to_storage_err(BulwarkError::Dao(format!(
                        "get_quota meta 格式错误 (key={}, val={}): 期望 4 段, 实际 {} 段",
                        meta_key,
                        meta_str,
                        parts.len()
                    ))));
                }
                let limit: u64 = parts[1].parse().map_err(|e| {
                    map_to_storage_err(BulwarkError::Dao(format!(
                        "get_quota parse 失败 (limit, key={}, val={}): {}",
                        meta_key, parts[1], e
                    )))
                })?;
                let window_start_ts: i64 = parts[2].parse().map_err(|e| {
                    map_to_storage_err(BulwarkError::Dao(format!(
                        "get_quota parse 失败 (window_start_ts, key={}, val={}): {}",
                        meta_key, parts[2], e
                    )))
                })?;
                let window_end_ts: i64 = parts[3].parse().map_err(|e| {
                    map_to_storage_err(BulwarkError::Dao(format!(
                        "get_quota parse 失败 (window_end_ts, key={}, val={}): {}",
                        meta_key, parts[3], e
                    )))
                })?;
                let window_start = chrono::DateTime::from_timestamp(window_start_ts, 0)
                    .ok_or_else(|| {
                        map_to_storage_err(BulwarkError::Dao(format!(
                            "get_quota DateTime 转换失败 (window_start_ts={})",
                            window_start_ts
                        )))
                    })?;
                let window_end =
                    chrono::DateTime::from_timestamp(window_end_ts, 0).ok_or_else(|| {
                        map_to_storage_err(BulwarkError::Dao(format!(
                            "get_quota DateTime 转换失败 (window_end_ts={})",
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

        // 循环 incr cost 次（cost=1 时单次，进程内原子）
        let mut new_count = 0u64;
        for _ in 0..cost {
            new_count = self
                .dao
                .incr(&count_key, ttl)
                .await
                .map_err(map_to_storage_err)?;
        }

        // 初始化/更新元数据（首次消费时设置窗口）
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

        let allowed = new_count <= limit;
        let remaining = limit.saturating_sub(new_count);
        let usage_percent = if limit == 0 {
            100.0
        } else {
            (new_count as f64 / limit as f64) * 100.0
        };

        Ok(ConsumeResult {
            allowed,
            remaining,
            alert_triggered: usage_percent >= 80.0,
            usage_percent,
        })
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
    use crate::dao::tests::MockDao;

    fn make_dao() -> Arc<dyn BulwarkDao> {
        Arc::new(MockDao::new())
    }

    // --- BulwarkDaoQuotaStorage 测试 ---

    #[tokio::test]
    async fn quota_consume_within_limit() {
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
        let result = quota
            .consume("user1", "sms", 1, 5, Duration::from_secs(3600))
            .await
            .unwrap();
        assert!(result.allowed);
        assert_eq!(result.remaining, 4);
    }

    #[tokio::test]
    async fn quota_consume_exceeds_limit() {
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
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
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
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
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
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
            err_msg.contains("parse 失败"),
            "错误消息应包含 'parse 失败'，实际: {}",
            err_msg
        );
    }

    /// M-3: QuotaStorage::get_quota 遇到脏 meta 数据时返回错误（fail-fast）。
    #[tokio::test]
    async fn m3_quota_get_quota_dirty_meta_returns_err() {
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
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
            err_msg.contains("parse 失败"),
            "错误消息应包含 'parse 失败'，实际: {}",
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
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
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
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
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
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
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
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
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
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
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
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
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
            err_msg.contains("格式错误"),
            "错误消息应包含 '格式错误'，实际: {}",
            err_msg
        );
    }

    /// get_quota window_start_ts 无效时返回错误。
    #[tokio::test]
    async fn quota_get_quota_invalid_window_start_ts_returns_err() {
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
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
        let quota = BulwarkDaoQuotaStorage::new(make_dao());
        // 只有 count 没有 meta
        quota
            .dao
            .set("limiteron:quota:user_nm:res:count", "5", 0)
            .await
            .unwrap();
        let result = quota.get_quota("user_nm", "res").await.unwrap();
        assert!(result.is_none(), "count 有但 meta 缺失时应返回 None");
    }
}
