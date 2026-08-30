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

    // T012：以下 5 个原子方法为编译期契约必需。本 mock 的原子性由
    // `tokio::sync::Mutex` 单锁保证的 `get_and_delete` 提供核心语义，
    // 其余方法按 trait 原组合语义实现（测试环境，TOCTOU 可接受）。
    // `set_permanent` 走 trait 默认（委托 `set`，本 mock 无 TTL）。

    async fn set_if_absent(
        &self,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        if self.get(key).await?.is_some() {
            return Ok(false);
        }
        self.set(key, value, ttl_seconds).await?;
        Ok(true)
    }

    async fn rename(&self, old_key: &str, new_key: &str) -> GarrisonResult<()> {
        let value = self
            .get(old_key)
            .await?
            .ok_or_else(|| GarrisonError::InvalidParam(format!("dao-key-missing::{}", old_key)))?;
        self.set_permanent(new_key, &value).await?;
        self.delete(old_key).await
    }

    async fn incr(&self, key: &str, ttl_seconds: u64) -> GarrisonResult<u64> {
        match self.get(key).await? {
            Some(v) => {
                let cur_val: u64 = v.parse().map_err(|_| {
                    GarrisonError::Dao(format!("dao-incr-parse-u64::{}::{}", key, v))
                })?;
                let new_val = cur_val + 1;
                self.update(key, &new_val.to_string()).await?;
                Ok(new_val)
            },
            None => {
                self.set(key, "1", ttl_seconds).await?;
                Ok(1)
            },
        }
    }

    async fn decr(&self, key: &str) -> GarrisonResult<u64> {
        match self.get(key).await? {
            Some(v) => {
                let cur_val: u64 = v.parse().map_err(|_| {
                    GarrisonError::Dao(format!("dao-decr-parse-u64::{}::{}", key, v))
                })?;
                if cur_val == 0 {
                    return Ok(0);
                }
                let new_val = cur_val - 1;
                if new_val == 0 {
                    self.delete(key).await?;
                } else {
                    self.update(key, &new_val.to_string()).await?;
                }
                Ok(new_val)
            },
            None => Ok(0),
        }
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        let current = self.get(key).await?;
        if current.as_deref() == expected {
            if ttl_seconds == 0 {
                self.set_permanent(key, new_value).await?;
            } else {
                self.set(key, new_value, ttl_seconds).await?;
            }
            Ok(true)
        } else {
            Ok(false)
        }
    }
}
