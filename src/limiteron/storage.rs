//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `Storage` 适配器，将 `BulwarkDao` 桥接到 limiteron `Storage` trait。
//!
//! `set` 的 `ttl: None` 映射为 `dao.set(key, value, 0)`（永久驻留）。

use crate::dao::BulwarkDao;
use async_trait::async_trait;
use limiteron::error::StorageError;
use limiteron::storage::Storage;
use std::sync::Arc;

use super::errors::map_to_storage_err;

/// `Storage` 适配器，将 `BulwarkDao` 桥接到 limiteron `Storage` trait。
///
/// `set` 的 `ttl: None` 映射为 `dao.set(key, value, 0)`（永久驻留）。
pub struct BulwarkDaoStorage {
    /// 内部 DAO。
    dao: Arc<dyn BulwarkDao>,
}

impl BulwarkDaoStorage {
    /// 创建适配器实例。
    ///
    /// # 参数
    /// - `dao`: 内部 DAO 实现。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self { dao }
    }
}

#[async_trait]
impl Storage for BulwarkDaoStorage {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;

    fn make_dao() -> Arc<dyn BulwarkDao> {
        Arc::new(MockDao::new())
    }

    // --- BulwarkDaoStorage 测试 ---

    #[tokio::test]
    async fn storage_get_set_delete() {
        let storage = BulwarkDaoStorage::new(make_dao());

        // 初始 get 返回 None
        assert!(storage.get("key1").await.unwrap().is_none());

        // set + get
        storage.set("key1", "value1", Some(60)).await.unwrap();
        assert_eq!(
            storage.get("key1").await.unwrap(),
            Some("value1".to_string())
        );

        // delete + get
        storage.delete("key1").await.unwrap();
        assert!(storage.get("key1").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn storage_set_ttl_none_is_permanent() {
        let storage = BulwarkDaoStorage::new(make_dao());
        storage.set("perm", "val", None).await.unwrap();
        assert_eq!(storage.get("perm").await.unwrap(), Some("val".to_string()));
    }
}
