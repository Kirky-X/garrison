//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SSO 协议层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `MockDao`（基于 `tokio::sync::Mutex<HashMap>` 模拟 DAO），
//! 供 `protocol::sso::tests` 票据签发/校验测试复用。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use std::collections::HashMap;
use tokio::sync::Mutex;

/// 测试用 Mock DAO，支持 TTL 模拟。
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
impl GarrisonDao for MockDao {
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        let data = self.data.lock().await;
        Ok(data.get(key).cloned())
    }

    async fn set(&self, key: &str, value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
        let mut data = self.data.lock().await;
        data.insert(key.to_string(), value.to_string());
        Ok(())
    }

    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        let mut data = self.data.lock().await;
        if data.contains_key(key) {
            data.insert(key.to_string(), value.to_string());
            Ok(())
        } else {
            Err(GarrisonError::Dao("sso-mock-key-not-found".to_string()))
        }
    }

    async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
        Ok(())
    }

    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        let mut data = self.data.lock().await;
        data.remove(key);
        Ok(())
    }

    async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>> {
        let mut data = self.data.lock().await;
        Ok(data.remove(key))
    }
}
