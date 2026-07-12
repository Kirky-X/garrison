//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! API Key 协议层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `MockDao`（基于 `tokio::sync::Mutex<HashMap>` 模拟 DAO），
//! 供 `protocol::apikey::tests` API Key 生成/校验测试复用。
//!
//! `keys` 方法复用 `crate::dao::tests::glob_match`（通过 T007 兼容层保持可用）。

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
            Err(BulwarkError::Dao("key 不存在".to_string()))
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

    /// keys 复用 dao::tests::glob_match（避免重复实现 glob 逻辑）。
    async fn keys(&self, pattern: &str) -> BulwarkResult<Vec<String>> {
        let data = self.data.lock().await;
        let mut result = Vec::new();
        for key in data.keys() {
            if crate::dao::tests::glob_match(pattern, key) {
                result.push(key.clone());
            }
        }
        Ok(result)
    }
}
