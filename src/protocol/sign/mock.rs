//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! API 签名协议层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `MockDao`（基于 `tokio::sync::Mutex<HashMap>` 模拟 DAO），
//! 供 `protocol::sign::tests` 签名生成/校验测试复用。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::Mutex;

/// 测试用 Mock DAO。
pub struct MockDao {
    data: Mutex<HashMap<String, String>>,
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
impl BulwarkDao for MockDao {
    async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
        let data = self.data.lock().await;
        Ok(data.get(key).cloned())
    }

    async fn set(&self, key: &str, value: &str, _ttl_seconds: u64) -> BulwarkResult<()> {
        let mut data = self.data.lock().await;
        data.insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
        let mut data = self.data.lock().await;
        if data.contains_key(key) {
            data.insert(key.to_string(), value.to_string());
            Ok(())
        } else {
            Err(BulwarkError::Dao("dao-key-not-found".to_string()))
        }
    }

    async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
        Ok(())
    }

    async fn delete(&self, key: &str) -> BulwarkResult<()> {
        let mut data = self.data.lock().await;
        data.remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn update_existing_key_overwrites_value() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 60).await.unwrap();
        dao.update("k1", "v2").await.unwrap();
        assert_eq!(dao.get("k1").await.unwrap(), Some("v2".to_string()));
    }

    #[tokio::test]
    async fn update_missing_key_returns_dao_error() {
        let dao = MockDao::new();
        let result = dao.update("missing", "v").await;
        assert!(matches!(result, Err(BulwarkError::Dao(_))));
    }

    #[tokio::test]
    async fn expire_is_noop_ok() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 60).await.unwrap();
        assert!(dao.expire("k1", 120).await.is_ok());
    }

    #[tokio::test]
    async fn delete_removes_key() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 60).await.unwrap();
        dao.delete("k1").await.unwrap();
        assert_eq!(dao.get("k1").await.unwrap(), None);
    }
}
