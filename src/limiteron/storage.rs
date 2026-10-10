// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `Storage` / `QuotaStorage` 适配器，将 `GarrisonDao` 桥接到 limiteron trait。
//!
//! `Storage::set` 的 `ttl: None` 映射为 `dao.set(key, value, 0)`（永久驻留）。
//!
//! `GarrisonDaoQuotaStorage` 为账本模型：`consume` 经 [`GarrisonDao::incr`]
//! 原子递增后判定，超限以 [`GarrisonDao::decr`] 逐次补偿回滚；`refund` 以
//! `decr` 循环归还，归还量天然钳制不超过已消耗量（账本不为负），key 不存在/
//! 已过期时 `decr` 语义即 no-op。窗口 TTL 随 `incr` 首创建落盘，无请求时
//! key 自然过期（与旧时间桶键形的过渡语义见 CHANGELOG）。

use crate::dao::GarrisonDao;
use async_trait::async_trait;
use chrono::Utc;
use limiteron::error::{ConsumeResult, StorageError};
use limiteron::storage::{QuotaInfo, QuotaStorage, Storage};
use std::sync::Arc;
use std::time::Duration;

use super::errors::map_to_storage_err;

/// `Storage` 适配器，将 `GarrisonDao` 桥接到 limiteron `Storage` trait。
///
/// `set` 的 `ttl: None` 映射为 `dao.set(key, value, 0)`（永久驻留）。
pub struct GarrisonDaoStorage {
    /// 内部 DAO。
    dao: Arc<dyn GarrisonDao>,
}

impl GarrisonDaoStorage {
    /// 创建适配器实例。
    ///
    /// # 参数
    /// - `dao`: 内部 DAO 实现。
    pub fn new(dao: Arc<dyn GarrisonDao>) -> Self {
        Self { dao }
    }
}

#[async_trait]
impl Storage for GarrisonDaoStorage {
    async fn get(&self, key: &str) -> Result<Option<String>, StorageError> {
        self.dao.get(key).await.map_err(map_to_storage_err)
    }

    async fn set(&self, key: &str, value: &str, ttl: Option<u64>) -> Result<(), StorageError> {
        let ttl_secs = ttl.unwrap_or(0);
        self.dao
            .set(key, value, ttl_secs)
            .await
            .map_err(map_to_storage_err)
    }

    async fn delete(&self, key: &str) -> Result<(), StorageError> {
        self.dao.delete(key).await.map_err(map_to_storage_err)
    }
}

/// `QuotaStorage` 适配器，将 `GarrisonDao` 桥接到 limiteron `QuotaStorage` trait。
///
/// 账本模型：计数器键 `quota:{resource}:{user_id}` 经 `incr`/`decr` 原子
/// 增减；`consume` 超限后以 `decr` 逐次补偿（与 limiteron 各后端
/// 「超限自回滚」同构），`refund` 归还量钳制不超过已消耗量（不为负）。
/// 窗口界限与上限记于 sidecar 元数据键（首消费时落盘、`reset` 时清除），
/// 供 `get_quota` 如实回答；元数据缺失时降级为「已用量 + 界限取当前时刻」。
pub struct GarrisonDaoQuotaStorage {
    /// 内部 DAO。
    dao: Arc<dyn GarrisonDao>,
}

impl GarrisonDaoQuotaStorage {
    /// 创建适配器实例。
    ///
    /// # 参数
    /// - `dao`: 内部 DAO 实现。
    pub fn new(dao: Arc<dyn GarrisonDao>) -> Self {
        Self { dao }
    }

    /// 账本计数键：`quota:{resource}:{user_id}`。
    fn ledger_key(user_id: &str, resource: &str) -> String {
        format!("quota:{resource}:{user_id}")
    }

    /// 窗口元数据 sidecar 键：`quota-meta:{resource}:{user_id}`，
    /// 值形如 `{limit}:{window_start_unix}:{window_end_unix}`。
    fn meta_key(user_id: &str, resource: &str) -> String {
        format!("quota-meta:{resource}:{user_id}")
    }

    /// 窗口 TTL 秒数（下限 1s：`incr` 的 0 语义为永久驻留，会泄漏窗口）。
    fn window_ttl(window: Duration) -> u64 {
        window.as_secs().max(1)
    }
}

#[async_trait]
impl QuotaStorage for GarrisonDaoQuotaStorage {
    async fn get_quota(
        &self,
        user_id: &str,
        resource: &str,
    ) -> Result<Option<QuotaInfo>, StorageError> {
        let Some(value) = self
            .dao
            .get(&Self::ledger_key(user_id, resource))
            .await
            .map_err(map_to_storage_err)?
        else {
            return Ok(None);
        };
        let Ok(consumed) = value.parse::<u64>() else {
            // 计数键损坏（非数字）：视为无记录，交由后续 consume 重写
            return Ok(None);
        };
        let now = Utc::now();
        let meta = self
            .dao
            .get(&Self::meta_key(user_id, resource))
            .await
            .map_err(map_to_storage_err)?
            .and_then(|m| {
                let mut parts = m.splitn(3, ':');
                let limit = parts.next()?.parse().ok()?;
                let start = parts
                    .next()?
                    .parse::<i64>()
                    .ok()
                    .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))?;
                let end = parts
                    .next()?
                    .parse::<i64>()
                    .ok()
                    .and_then(|ts| chrono::DateTime::from_timestamp(ts, 0))?;
                Some((limit, start, end))
            });
        Ok(Some(match meta {
            Some((limit, window_start, window_end)) => QuotaInfo {
                consumed,
                limit,
                window_start,
                window_end,
            },
            None => QuotaInfo {
                consumed,
                limit: 0,
                window_start: now,
                window_end: now,
            },
        }))
    }

    async fn consume(
        &self,
        user_id: &str,
        resource: &str,
        cost: u64,
        limit: u64,
        window: Duration,
    ) -> Result<ConsumeResult, StorageError> {
        let key = Self::ledger_key(user_id, resource);
        let ttl = Self::window_ttl(window);
        let cur = self.dao.incr(&key, ttl).await.map_err(map_to_storage_err)?;
        if cur == cost {
            // 本窗口首次消费：落盘窗口元数据（limit + 起止界限），TTL 与账本一致
            let start = Utc::now().timestamp();
            let end = start + window.as_secs() as i64;
            self.dao
                .set(
                    &Self::meta_key(user_id, resource),
                    &format!("{limit}:{start}:{end}"),
                    ttl,
                )
                .await
                .map_err(map_to_storage_err)?;
        }
        if cur <= limit {
            Ok(ConsumeResult::allowed(cur, limit))
        } else {
            // 超限自回滚：每次 decr 1（不存在/值为 0 时 decr 返回 0，不为负）。
            // 补偿失败仅 warn 不传播：拒绝判定本身已成立，回滚失败只让账本残留
            // 至窗口 TTL 自然过期（与手写实现的统一回滚错误策略一致），
            // 不得把「限流拒绝」升级成存储错误。
            for _ in 0..cost {
                if let Err(e) = self.dao.decr(&key).await {
                    tracing::warn!(error = %e, key = %key, "quota consume over-limit rollback failed");
                }
            }
            Ok(ConsumeResult::rejected(cur - cost, limit))
        }
    }

    async fn reset(
        &self,
        user_id: &str,
        resource: &str,
        _limit: u64,
        _window: Duration,
    ) -> Result<(), StorageError> {
        self.dao
            .delete(&Self::ledger_key(user_id, resource))
            .await
            .map_err(map_to_storage_err)?;
        self.dao
            .delete(&Self::meta_key(user_id, resource))
            .await
            .map_err(map_to_storage_err)?;
        Ok(())
    }

    async fn refund(
        &self,
        user_id: &str,
        resource: &str,
        amount: u64,
        _limit: u64,
        _window: Duration,
    ) -> Result<u64, StorageError> {
        let key = Self::ledger_key(user_id, resource);
        let mut current = self
            .dao
            .get(&key)
            .await
            .map_err(map_to_storage_err)?
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        for _ in 0..amount {
            // decr 钳制：不存在/已过期/值为 0 均返回 0 且不建 key，最终不为负
            current = self.dao.decr(&key).await.map_err(map_to_storage_err)?;
        }
        Ok(current)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;

    fn make_dao() -> Arc<dyn GarrisonDao> {
        Arc::new(MockDao::new())
    }

    // --- GarrisonDaoStorage 测试 ---

    #[tokio::test]
    async fn storage_get_set_delete() {
        let storage = GarrisonDaoStorage::new(make_dao());

        assert!(storage.get("key1").await.unwrap().is_none());

        storage.set("key1", "value1", Some(60)).await.unwrap();
        assert_eq!(
            storage.get("key1").await.unwrap(),
            Some("value1".to_string())
        );

        storage.delete("key1").await.unwrap();
        assert!(storage.get("key1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn storage_set_ttl_none_is_permanent() {
        let storage = GarrisonDaoStorage::new(make_dao());
        storage.set("perm", "val", None).await.unwrap();
        assert_eq!(storage.get("perm").await.unwrap(), Some("val".to_string()));
    }

    // --- GarrisonDaoQuotaStorage 测试 ---

    /// consume 到限后拒绝（remaining=0）；refund 1 后可再次消费，再消费一次又被拒。
    #[tokio::test]
    async fn quota_consume_to_limit_rejects_then_refund_reopens() {
        let storage = GarrisonDaoQuotaStorage::new(make_dao());
        let window = Duration::from_secs(3600);

        for i in 1..=3 {
            let r = storage.consume("u1", "hour", 1, 3, window).await.unwrap();
            assert!(r.allowed, "第 {i} 次 consume 应放行");
            assert_eq!(r.remaining, 3 - i);
        }
        let blocked = storage.consume("u1", "hour", 1, 3, window).await.unwrap();
        assert!(!blocked.allowed, "超过 limit 后应拒绝");
        assert_eq!(blocked.remaining, 0, "拒绝时 remaining 应为 0");

        let after = storage.refund("u1", "hour", 1, 3, window).await.unwrap();
        assert_eq!(after, 2, "退还 1 后已用量应为 2");
        let again = storage.consume("u1", "hour", 1, 3, window).await.unwrap();
        assert!(again.allowed, "refund 后应可再次消费");
        let blocked2 = storage.consume("u1", "hour", 1, 3, window).await.unwrap();
        assert!(!blocked2.allowed, "再次到限后应继续拒绝");
    }

    /// refund 对不存在记录为 no-op（返回 0，不创建 key）。
    #[tokio::test]
    async fn quota_refund_nonexistent_is_noop() {
        let storage = GarrisonDaoQuotaStorage::new(make_dao());
        let window = Duration::from_secs(3600);

        assert_eq!(
            storage.refund("ghost", "hour", 2, 3, window).await.unwrap(),
            0,
            "不存在记录 refund 应为 no-op（返回 0）"
        );
        assert!(
            storage.get_quota("ghost", "hour").await.unwrap().is_none(),
            "no-op refund 不得创建账本 key"
        );
    }

    /// refund 归还量钳制不超过已消耗量：消费 1 次后退还 5，账本不为负（decr 到 0 删 key）。
    #[tokio::test]
    async fn quota_refund_clamped_at_zero() {
        let storage = GarrisonDaoQuotaStorage::new(make_dao());
        let window = Duration::from_secs(3600);

        storage.consume("u2", "day", 1, 5, window).await.unwrap();
        let after = storage.refund("u2", "day", 5, 5, window).await.unwrap();
        assert_eq!(after, 0, "归还量钳制不超过已消耗量（账本不为负）");
        assert!(
            storage.get_quota("u2", "day").await.unwrap().is_none(),
            "账本归零后 key 应被删除"
        );
    }

    /// 两任务并发 consume 同一账本（limit=1）：恰一个越过。
    #[tokio::test(flavor = "multi_thread")]
    async fn quota_concurrent_consume_limit_one_exactly_one_passes() {
        let storage = std::sync::Arc::new(GarrisonDaoQuotaStorage::new(make_dao()));
        let window = Duration::from_secs(3600);

        let mut handles = Vec::new();
        for _ in 0..8 {
            let s = std::sync::Arc::clone(&storage);
            handles.push(tokio::spawn(async move {
                s.consume("race", "hour", 1, 1, window)
                    .await
                    .unwrap()
                    .allowed
            }));
        }
        let mut passed = 0;
        for h in handles {
            if h.await.unwrap() {
                passed += 1;
            }
        }
        assert_eq!(passed, 1, "limit=1 时并发消费应恰一个越过，实际 {passed}");

        let info = storage.get_quota("race", "hour").await.unwrap().unwrap();
        assert_eq!(info.consumed, 1, "并发补偿后账本应恰为 1");
        assert_eq!(info.limit, 1, "元数据应记录 limit");
    }

    /// consume/refund 交错并发：账本恒不为负、终态守恒（consume 成功数 - refund 数）。
    #[tokio::test(flavor = "multi_thread")]
    async fn quota_concurrent_consume_refund_never_negative() {
        let storage = std::sync::Arc::new(GarrisonDaoQuotaStorage::new(make_dao()));
        let window = Duration::from_secs(3600);
        let limit = 10;

        let mut handles = Vec::new();
        for i in 0..24 {
            let s = std::sync::Arc::clone(&storage);
            handles.push(tokio::spawn(async move {
                if i % 2 == 0 {
                    // 半数任务消费后立即退还（净效果 0，制造交错）
                    let r = s.consume("mix", "hour", 1, limit, window).await.unwrap();
                    if r.allowed {
                        s.refund("mix", "hour", 1, limit, window).await.unwrap();
                    }
                    r.allowed
                } else {
                    s.consume("mix", "hour", 1, limit, window)
                        .await
                        .unwrap()
                        .allowed
                }
            }));
        }
        let mut net = 0i64;
        for h in handles {
            if h.await.unwrap() {
                net += 1;
            }
        }
        let info = storage
            .get_quota("mix", "hour")
            .await
            .unwrap()
            .expect("至少一次成功消费后账本应存在");
        assert!(
            info.consumed <= limit as u64,
            "账本不得超过 limit，实际 {}",
            info.consumed
        );
        assert!(
            net >= 0,
            "成功消费计数不应为负（decr 钳制保证账本不为负），实际 {net}"
        );
    }
}
