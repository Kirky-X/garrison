//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Credit KV 热数据存储层。
//!
//! `CreditMeterStorage` 通过 `GarrisonDao` KV 接口管理当前周期的 credit 计数与元数据。
//! 热数据路径：消费、查询、重置均走 KV 缓存，保证性能。

use crate::credit::cycle::CreditCycle;
use crate::credit::error::{CreditError, CreditResult};
use crate::dao::GarrisonDao;
use std::sync::Arc;

/// 配额 key 前缀。
const CREDIT_KEY_PREFIX: &str = "credit";

/// 配额计数 key：`credit:{tenant_id}:consumed`。
fn credit_consumed_key(tenant_id: i64) -> String {
    format!("{}:{}:consumed", CREDIT_KEY_PREFIX, tenant_id)
}

/// 配额元数据 key：`credit:{tenant_id}:meta`。
///
/// 格式：`consumed|limit|window_start|window_end|cycle_type|cycle_param`
fn credit_meta_key(tenant_id: i64) -> String {
    format!("{}:{}:meta", CREDIT_KEY_PREFIX, tenant_id)
}

/// 滚动窗口起始 key：`credit:{tenant_id}:window_start`（仅 Rolling 模式）。
fn credit_window_start_key(tenant_id: i64) -> String {
    format!("{}:{}:window_start", CREDIT_KEY_PREFIX, tenant_id)
}

/// Credit 周期元数据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreditMeta {
    /// 当前周期已消费总量。
    pub consumed: u64,
    /// 当前周期 credit 配额。
    pub limit: u64,
    /// 当前周期起始（Unix 时间戳）。
    pub window_start: i64,
    /// 当前周期结束（Unix 时间戳）。
    pub window_end: i64,
    /// 周期模式。
    pub cycle: CreditCycle,
}

/// KV 热数据存储层。
///
/// 持有 `Arc<dyn GarrisonDao>`，提供 credit 计数的读写操作。
pub struct CreditMeterStorage {
    dao: Arc<dyn GarrisonDao>,
}

impl CreditMeterStorage {
    /// 创建存储实例。
    pub fn new(dao: Arc<dyn GarrisonDao>) -> Self {
        Self { dao }
    }

    /// 获取当前周期已消费 credit 计数。
    ///
    /// 返回 `None` 表示尚无消费记录。
    pub async fn get_consumed(&self, tenant_id: i64) -> CreditResult<Option<u64>> {
        let key = credit_consumed_key(tenant_id);
        let val = self
            .dao
            .get(&key)
            .await
            .map_err(|e| CreditError::Dao(format!("credit-get-consumed::{}", e)))?;
        match val {
            Some(s) => {
                let count: u64 = s.parse().map_err(|e| {
                    CreditError::Dao(format!(
                        "credit-consumed-parse-failed::{}::{}::{}",
                        key, s, e
                    ))
                })?;
                Ok(Some(count))
            },
            None => Ok(None),
        }
    }

    /// 递增已消费 credit 计数。
    ///
    /// 循环 `dao.incr` credits 次（cost=1 时单次，进程内原子；cost>1 时非原子，
    /// 与 `QuotaStorage::consume` 一致）。返回递增后的新计数。
    pub async fn incr_consumed(&self, tenant_id: i64, credits: u64, ttl: u64) -> CreditResult<u64> {
        let key = credit_consumed_key(tenant_id);
        let mut new_count = 0u64;
        for _ in 0..credits {
            new_count = self
                .dao
                .incr(&key, ttl)
                .await
                .map_err(|e| CreditError::Dao(format!("credit-incr-failed::{}", e)))?;
        }
        Ok(new_count)
    }

    /// 获取当前周期元数据。
    ///
    /// 返回 `None` 表示 meta key 不存在（尚未消费或已重置）。
    /// 脏数据（parse 失败）返回 `Err`（fail-fast，与 limiteron quota M-3 修复一致）。
    pub async fn get_meta(&self, tenant_id: i64) -> CreditResult<Option<CreditMeta>> {
        let key = credit_meta_key(tenant_id);
        let val = self
            .dao
            .get(&key)
            .await
            .map_err(|e| CreditError::Dao(format!("credit-get-meta::{}", e)))?;
        match val {
            Some(s) => {
                let parts: Vec<&str> = s.split('|').collect();
                if parts.len() != 6 {
                    return Err(CreditError::Dao(format!(
                        "credit-meta-format-error::{}::{}::expected 6 parts, got {}",
                        key,
                        s,
                        parts.len()
                    )));
                }
                let consumed: u64 = parts[0].parse().map_err(|e| {
                    CreditError::Dao(format!(
                        "credit-meta-consumed-parse-failed::{}::{}::{}",
                        key, parts[0], e
                    ))
                })?;
                let limit: u64 = parts[1].parse().map_err(|e| {
                    CreditError::Dao(format!(
                        "credit-meta-limit-parse-failed::{}::{}::{}",
                        key, parts[1], e
                    ))
                })?;
                let window_start: i64 = parts[2].parse().map_err(|e| {
                    CreditError::Dao(format!(
                        "credit-meta-window-start-parse-failed::{}::{}::{}",
                        key, parts[2], e
                    ))
                })?;
                let window_end: i64 = parts[3].parse().map_err(|e| {
                    CreditError::Dao(format!(
                        "credit-meta-window-end-parse-failed::{}::{}::{}",
                        key, parts[3], e
                    ))
                })?;
                let cycle_type = parts[4];
                let cycle_param: u32 = parts[5].parse().map_err(|e| {
                    CreditError::Dao(format!(
                        "credit-meta-cycle-param-parse-failed::{}::{}::{}",
                        key, parts[5], e
                    ))
                })?;
                let cycle = CreditCycle::from_tag(cycle_type, cycle_param).ok_or_else(|| {
                    CreditError::Dao(format!(
                        "credit-meta-unknown-cycle-type::{}::{}",
                        key, cycle_type
                    ))
                })?;
                Ok(Some(CreditMeta {
                    consumed,
                    limit,
                    window_start,
                    window_end,
                    cycle,
                }))
            },
            None => Ok(None),
        }
    }

    /// 写入当前周期元数据。
    pub async fn set_meta(&self, tenant_id: i64, meta: &CreditMeta, ttl: u64) -> CreditResult<()> {
        let key = credit_meta_key(tenant_id);
        let val = format!(
            "{}|{}|{}|{}|{}|{}",
            meta.consumed,
            meta.limit,
            meta.window_start,
            meta.window_end,
            meta.cycle.type_tag(),
            meta.cycle.param()
        );
        self.dao
            .set(&key, &val, ttl)
            .await
            .map_err(|e| CreditError::Dao(format!("credit-set-meta-failed::{}", e)))
    }

    /// 重置 credit 计数（删除 consumed + meta + window_start 三个 key）。
    pub async fn reset(&self, tenant_id: i64) -> CreditResult<()> {
        let consumed_key = credit_consumed_key(tenant_id);
        let meta_key = credit_meta_key(tenant_id);
        let ws_key = credit_window_start_key(tenant_id);
        self.dao
            .delete(&consumed_key)
            .await
            .map_err(|e| CreditError::Dao(format!("credit-reset-consumed::{}", e)))?;
        self.dao
            .delete(&meta_key)
            .await
            .map_err(|e| CreditError::Dao(format!("credit-reset-meta::{}", e)))?;
        self.dao
            .delete(&ws_key)
            .await
            .map_err(|e| CreditError::Dao(format!("credit-reset-window-start::{}", e)))?;
        Ok(())
    }

    /// 获取滚动窗口起始时间戳（仅 Rolling 模式使用）。
    pub async fn get_window_start(&self, tenant_id: i64) -> CreditResult<Option<i64>> {
        let key = credit_window_start_key(tenant_id);
        let val = self
            .dao
            .get(&key)
            .await
            .map_err(|e| CreditError::Dao(format!("credit-get-window-start::{}", e)))?;
        match val {
            Some(s) => {
                let ts: i64 = s.parse().map_err(|e| {
                    CreditError::Dao(format!(
                        "credit-window-start-parse-failed::{}::{}::{}",
                        key, s, e
                    ))
                })?;
                Ok(Some(ts))
            },
            None => Ok(None),
        }
    }

    /// 设置滚动窗口起始时间戳。
    pub async fn set_window_start(&self, tenant_id: i64, ts: i64, ttl: u64) -> CreditResult<()> {
        let key = credit_window_start_key(tenant_id);
        self.dao
            .set(&key, &ts.to_string(), ttl)
            .await
            .map_err(|e| CreditError::Dao(format!("credit-set-window-start::{}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;

    fn make_dao() -> Arc<dyn GarrisonDao> {
        Arc::new(MockDao::new())
    }

    /// incr_consumed 返回递增后的新计数。
    #[tokio::test]
    async fn test_incr_consumed_returns_new_count() {
        let storage = CreditMeterStorage::new(make_dao());
        let count = storage.incr_consumed(42, 3, 3600).await.unwrap();
        assert_eq!(count, 3);
        let count2 = storage.incr_consumed(42, 2, 3600).await.unwrap();
        assert_eq!(count2, 5);
    }

    /// get_meta 正确解析合法 meta 数据。
    #[tokio::test]
    async fn test_get_meta_parse_success() {
        let storage = CreditMeterStorage::new(make_dao());
        // 写入合法 meta
        let meta = CreditMeta {
            consumed: 100,
            limit: 1000,
            window_start: 1_700_000_000,
            window_end: 1_702_592_000,
            cycle: CreditCycle::Fixed { day_of_month: 1 },
        };
        storage.set_meta(42, &meta, 86400).await.unwrap();
        let loaded = storage.get_meta(42).await.unwrap().unwrap();
        assert_eq!(loaded.consumed, 100);
        assert_eq!(loaded.limit, 1000);
        assert_eq!(loaded.cycle, CreditCycle::Fixed { day_of_month: 1 });
    }

    /// get_meta 脏数据返回 Err（fail-fast）。
    #[tokio::test]
    async fn test_get_meta_dirty_data_returns_err() {
        let storage = CreditMeterStorage::new(make_dao());
        // 写入段数不对的 meta（3 段而非 6 段）
        storage
            .dao
            .set("credit:42:meta", "100|1000|bad", 0)
            .await
            .unwrap();
        let result = storage.get_meta(42).await;
        assert!(result.is_err(), "脏 meta 应返回 Err");
    }

    /// reset 清除所有 key。
    #[tokio::test]
    async fn test_reset_clears_all_keys() {
        let storage = CreditMeterStorage::new(make_dao());
        storage.incr_consumed(42, 5, 3600).await.unwrap();
        let meta = CreditMeta {
            consumed: 5,
            limit: 100,
            window_start: 1_700_000_000,
            window_end: 1_702_592_000,
            cycle: CreditCycle::Fixed { day_of_month: 1 },
        };
        storage.set_meta(42, &meta, 3600).await.unwrap();
        storage.reset(42).await.unwrap();
        assert!(storage.get_consumed(42).await.unwrap().is_none());
        assert!(storage.get_meta(42).await.unwrap().is_none());
    }

    /// get_consumed 在 key 不存在时返回 None。
    #[tokio::test]
    async fn test_get_consumed_missing_returns_none() {
        let storage = CreditMeterStorage::new(make_dao());
        assert!(storage.get_consumed(999).await.unwrap().is_none());
    }
}
