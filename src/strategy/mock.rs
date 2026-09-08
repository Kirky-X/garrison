//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 策略层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `MockCacheDao`（基于 `HashMap` 模拟权限缓存 DAO），
//! 供 `strategy::tests` 权限缓存测试复用。

use crate::dao::GarrisonDao;
use crate::error::GarrisonResult;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;

/// 简单的 MockDao，用于权限缓存测试。
pub struct MockCacheDao {
    store: Mutex<HashMap<String, String>>,
}

impl MockCacheDao {
    /// 创建空的 mock DAO 实例（无任何键值）。
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl GarrisonDao for MockCacheDao {
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        Ok(self.store.lock().get(key).cloned())
    }
    async fn set(&self, key: &str, value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
        self.store.lock().insert(key.to_string(), value.to_string());
        Ok(())
    }
    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        self.store.lock().insert(key.to_string(), value.to_string());
        Ok(())
    }
    async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
        Ok(())
    }
    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        self.store.lock().remove(key);
        Ok(())
    }
    async fn keys(&self, pattern: &str) -> GarrisonResult<Vec<String>> {
        let mut result = Vec::new();
        // 支持尾部 `*` 通配前缀匹配（覆盖权限缓存失效场景）
        let prefix = pattern.strip_suffix('*').unwrap_or(pattern);
        for k in self.store.lock().keys() {
            if k.starts_with(prefix) {
                result.push(k.clone());
            }
        }
        Ok(result)
    }
    crate::atomic_test_fallback!();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn update_overwrites_existing_key() {
        let dao = MockCacheDao::new();
        dao.set("k1", "v1", 60).await.unwrap();
        dao.update("k1", "v2").await.unwrap();
        assert_eq!(dao.get("k1").await.unwrap(), Some("v2".to_string()));
    }

    #[tokio::test]
    async fn expire_is_noop_ok() {
        let dao = MockCacheDao::new();
        assert!(dao.expire("k1", 120).await.is_ok());
    }

    #[tokio::test]
    async fn delete_removes_key() {
        let dao = MockCacheDao::new();
        dao.set("k1", "v1", 60).await.unwrap();
        dao.delete("k1").await.unwrap();
        assert_eq!(dao.get("k1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn mock_cache_dao_atomic_and_default_methods_coverage() {
        use crate::dao::GarrisonDao;
        let dao = MockCacheDao::new();
        dao.set("k1", "v1", 60).await.unwrap();
        // atomic_test_fallback! 方法
        let _ = dao.set_if_absent("a1", "v1", 60).await;
        let _ = dao.get_and_delete("a1").await;
        let _ = dao.incr("ctr", 60).await;
        let _ = dao.decr("ctr").await;
        let _ = dao.rename("k1", "k2").await;
        let _ = dao.compare_and_swap("k2", Some("v1"), "v2", 60).await;
        // trait 默认方法
        let _ = dao.set_permanent("p1", "val").await;
        let _ = dao.get_timeout("k1").await;
        let _ = dao.keys("*").await;
        let _ = dao.find_social_binding(0, "wechat", "oid").await;
        let _ = dao
            .insert_social_binding(0, "u1", "wechat", "oid", None, 0)
            .await;
        let _ = dao.compare_and_update_if_greater("k1", 10, 60).await;
        let _ = dao.eval_lua("return 1", vec![], vec![]).await;
        #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
        {
            let _ = dao.insert_credit_consumption(0, "r", 1, 100, 100, 0).await;
            let _ = dao.query_credit_consumption(0, 0, 0).await;
            let _ = dao.query_role_hierarchy_edges(0).await;
            let _ = dao.insert_role_hierarchy_edge(0, "c", "p").await;
            let _ = dao.delete_role_hierarchy_edge(0, "c", "p").await;
        }
    }
}
