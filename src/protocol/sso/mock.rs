//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! SSO 协议层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `MockDao`（基于 `tokio::sync::Mutex<HashMap>` 模拟 DAO），
//! 供 `protocol::sso::tests` 票据签发/校验测试复用。
//!
//! TTL 语义（对齐产品 `dao::InMemoryDao`）：
//! - `set(key, value, ttl_seconds)`：`ttl_seconds == 0` 表示永不过期，
//! 否则记录过期时间点；
//! - `get` 读取时惰性判断过期，过期键即删即返 `None`；
//! - `expire(key, seconds)`：改写过期时间点，键不存在返回 `Err(Dao)`（与产品一致）。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// 单条 mock 条目：值 + 可选过期时间点（`None` = 永不过期）。
struct MockEntry {
    value: String,
    expires_at: Option<Instant>,
}

impl MockEntry {
    /// 是否已过期（`expires_at` 为 `None` 时永不过期）。
    fn is_expired(&self, now: Instant) -> bool {
        matches!(self.expires_at, Some(t) if t <= now)
    }
}

/// 测试用 Mock DAO，支持 TTL 模拟。
pub struct MockDao {
    data: Mutex<HashMap<String, MockEntry>>,
}

impl MockDao {
    /// 创建空的 mock DAO 实例（无任何键值）。
    pub fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl GarrisonDao for MockDao {
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        let mut data = self.data.lock().await;
        // 惰性过期：读取时判断，过期即删即返 None
        match data.get(key) {
            Some(entry) if entry.is_expired(Instant::now()) => {
                data.remove(key);
                Ok(None)
            },
            Some(entry) => Ok(Some(entry.value.clone())),
            None => Ok(None),
        }
    }

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
        let expires_at = if ttl_seconds == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(ttl_seconds))
        };
        let mut data = self.data.lock().await;
        data.insert(
            key.to_string(),
            MockEntry {
                value: value.to_string(),
                expires_at,
            },
        );
        Ok(())
    }

    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        let mut data = self.data.lock().await;
        match data.get_mut(key) {
            Some(entry) => {
                entry.value = value.to_string();
                Ok(())
            },
            None => Err(GarrisonError::Dao("sso-mock-key-not-found".to_string())),
        }
    }

    async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
        let mut data = self.data.lock().await;
        match data.get_mut(key) {
            Some(entry) => {
                entry.expires_at = if seconds == 0 {
                    None
                } else {
                    Some(Instant::now() + Duration::from_secs(seconds))
                };
                Ok(())
            },
            // 对齐产品 InMemoryDao：对不存在的键 expire 返回 Err
            None => Err(GarrisonError::Dao(format!("sso-mock-key-missing::{}", key))),
        }
    }

    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        let mut data = self.data.lock().await;
        data.remove(key);
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>> {
        let mut data = self.data.lock().await;
        // 过期键视为不存在：删除并返回 None
        match data.get(key) {
            Some(entry) if entry.is_expired(Instant::now()) => {
                data.remove(key);
                Ok(None)
            },
            Some(_) => {
                let entry = data.remove(key).expect("entry 已确认存在");
                Ok(Some(entry.value))
            },
            None => Ok(None),
        }
    }

    // 其余 5 个原子方法经子集宏展开（逻辑单点维护于
    // dao::atomic_fallback::impls），本 mock 自定义的单锁原子 get_and_delete
    //（一次性语义）保留不被覆盖。
    crate::atomic_test_fallback_no_get_and_delete!();
}

#[cfg(test)]
mod mock_dao_coverage_tests {
    use super::*;

    #[tokio::test]
    async fn mock_dao_atomic_and_default_methods_coverage() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 60).await.unwrap();
        let _ = dao.set_if_absent("a1", "v1", 60).await;
        let _ = dao.get_and_delete("a1").await;
        let _ = dao.incr("ctr", 60).await;
        let _ = dao.decr("ctr").await;
        let _ = dao.rename("k1", "k2").await;
        let _ = dao.compare_and_swap("k2", Some("v1"), "v2", 60).await;
        let _ = dao.set_permanent("p1", "val").await;
        let _ = dao.get_timeout("k1").await;
        let _ = dao.get_with_ttl("k1").await;
        let _ = dao.keys("*").await;
        let _ = dao.find_social_binding(0, "w", "o").await;
        let _ = dao.insert_social_binding(0, "u", "w", "o", None, 0).await;
        let _ = dao.compare_and_update_if_greater("k1", 10, 60).await;
        let _ = dao.eval_lua("r", vec![], vec![]).await;
        #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
        {
            let _ = dao.insert_credit_consumption(0, "r", 1, 1, 1, 0).await;
            let _ = dao.query_credit_consumption(0, 0, 0).await;
            let _ = dao.query_role_hierarchy_edges(0).await;
            let _ = dao.insert_role_hierarchy_edge(0, "c", "p").await;
            let _ = dao.delete_role_hierarchy_edge(0, "c", "p").await;
        }
    }

    /// TTL 语义：set 带 ttl 的键过期后 get 返回 None（真实过期，而非永不过期）。
    #[tokio::test]
    async fn mock_dao_ttl_expires_key() {
        let dao = MockDao::new();
        dao.set("ttl-key", "v", 1).await.unwrap();
        // 过期前可读
        assert_eq!(dao.get("ttl-key").await.unwrap().as_deref(), Some("v"));
        // 等待过期（TTL=1s）
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(
            dao.get("ttl-key").await.unwrap(),
            None,
            "超过 TTL 后 get 应返回 None"
        );
    }

    /// ttl_seconds=0 表示永不过期。
    #[tokio::test]
    async fn mock_dao_ttl_zero_means_permanent() {
        let dao = MockDao::new();
        dao.set("perm-key", "v", 0).await.unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            dao.get("perm-key").await.unwrap().as_deref(),
            Some("v"),
            "ttl=0 应永不过期"
        );
    }

    /// expire 实际缩短过期时间；对不存在的键返回 Err（对齐产品语义）。
    #[tokio::test]
    async fn mock_dao_expire_invalidates_key() {
        let dao = MockDao::new();
        dao.set("exp-key", "v", 0).await.unwrap();
        dao.expire("exp-key", 1).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(
            dao.get("exp-key").await.unwrap(),
            None,
            "expire 后超过时长 get 应返回 None"
        );
        // 不存在的键 expire 返回 Err
        let missing = dao.expire("no-such-key", 10).await;
        assert!(
            matches!(missing, Err(GarrisonError::Dao(_))),
            "对不存在键 expire 应返回 Err，实际: {:?}",
            missing
        );
    }
}
