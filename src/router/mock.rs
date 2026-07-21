//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 路由层测试 mock 实现。
//!
//! 本模块仅在 `cfg(all(test, feature = "web-axum"))` 下编译（通过 `mod.rs` 中的
//! `#[cfg(all(test, feature = "web-axum"))] mod mock;` 声明），
//! 提供 `MockDao`（基于 `parking_lot::Mutex<HashMap>` + `Instant` 模拟 TTL）
//! 与 `MockInterface`（模拟 `GarrisonInterface` 权限/角色回调），
//! 供 `router::tests` 集成测试复用。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use crate::stp::GarrisonInterface;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ------------------------------------------------------------------------
// MockDao（HashMap + Instant 模拟 TTL）
// ------------------------------------------------------------------------

/// 测试用 mock DAO，模拟 TTL 行为。
pub struct MockDao {
    store: Mutex<HashMap<String, (String, Option<Instant>)>>,
}

impl MockDao {
    /// 创建空的 mock DAO 实例（无任何键值）。
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl GarrisonDao for MockDao {
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        let mut store = self.store.lock();
        match store.get(key) {
            Some((value, expire_at)) => {
                if let Some(deadline) = expire_at {
                    if Instant::now() >= *deadline {
                        store.remove(key);
                        return Ok(None);
                    }
                }
                Ok(Some(value.clone()))
            },
            None => Ok(None),
        }
    }

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
        let expire_at = if ttl_seconds == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(ttl_seconds))
        };
        self.store
            .lock()
            .insert(key.to_string(), (value.to_string(), expire_at));
        Ok(())
    }

    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        let mut store = self.store.lock();
        match store.get_mut(key) {
            Some((existing, _)) => {
                *existing = value.to_string();
                Ok(())
            },
            None => Err(GarrisonError::Dao(format!("router-key-not-found::{}", key))),
        }
    }

    async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
        let mut store = self.store.lock();
        match store.get_mut(key) {
            Some((_, expire_at)) => {
                *expire_at = if seconds == 0 {
                    None
                } else {
                    Some(Instant::now() + Duration::from_secs(seconds))
                };
                Ok(())
            },
            None => Err(GarrisonError::Dao(format!("router-key-not-found::{}", key))),
        }
    }

    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        self.store.lock().remove(key);
        Ok(())
    }
}

// ------------------------------------------------------------------------
// MockInterface（权限/角色数据回调）
// ------------------------------------------------------------------------

/// 测试用 mock GarrisonInterface，模拟权限/角色数据。
pub struct MockInterface {
    permissions: HashMap<String, Vec<String>>,
    roles: HashMap<String, Vec<String>>,
}

impl MockInterface {
    /// 创建空的 mock 实例（无任何权限/角色）。
    pub fn new() -> Self {
        Self {
            permissions: HashMap::new(),
            roles: HashMap::new(),
        }
    }

    /// 链式注入指定 login_id 的权限列表。
    pub fn with_permission(mut self, login_id: &str, perms: &[&str]) -> Self {
        self.permissions.insert(
            login_id.to_string(),
            perms.iter().map(|s| s.to_string()).collect(),
        );
        self
    }

    /// 链式注入指定 login_id 的角色列表。
    pub fn with_role(mut self, login_id: &str, roles: &[&str]) -> Self {
        self.roles.insert(
            login_id.to_string(),
            roles.iter().map(|s| s.to_string()).collect(),
        );
        self
    }
}

#[async_trait]
impl GarrisonInterface for MockInterface {
    async fn get_permission_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
    }

    async fn get_role_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(self.roles.get(login_id).cloned().unwrap_or_default())
    }
}
