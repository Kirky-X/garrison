//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 策略层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `MockCacheDao`（基于 `HashMap` 模拟权限缓存 DAO），
//! 供 `strategy::tests` 权限缓存测试复用。

use crate::dao::BulwarkDao;
use crate::error::BulwarkResult;
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
impl BulwarkDao for MockCacheDao {
    async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
        Ok(self.store.lock().get(key).cloned())
    }
    async fn set(&self, key: &str, value: &str, _ttl_seconds: u64) -> BulwarkResult<()> {
        self.store.lock().insert(key.to_string(), value.to_string());
        Ok(())
    }
    async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
        self.store.lock().insert(key.to_string(), value.to_string());
        Ok(())
    }
    async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
        Ok(())
    }
    async fn delete(&self, key: &str) -> BulwarkResult<()> {
        self.store.lock().remove(key);
        Ok(())
    }
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
}
