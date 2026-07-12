//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Stp 层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `MockDao` / `MockFirewall` / `MockInterface` / `MockInterfaceWithPerms` /
//! `MockUserRepository` / `MockInterfaceWithLoginType` 等 mock，
//! 供 `stp::tests` 集成测试复用。

use super::BulwarkInterface;
use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use crate::strategy::BulwarkPermissionStrategy;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

#[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
use crate::dao::repository::{NewUser, UpdateUser, UserRepository, UserRow};

// ------------------------------------------------------------------------
// MockDao：复用 dao/session 测试的 HashMap + Instant 模拟 TTL
// ------------------------------------------------------------------------

pub struct MockDao {
    store: Mutex<HashMap<String, (String, Option<Instant>)>>,
}

impl MockDao {
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl BulwarkDao for MockDao {
    async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
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

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
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

    async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
        let mut store = self.store.lock();
        match store.get_mut(key) {
            Some((existing, _)) => {
                *existing = value.to_string();
                Ok(())
            },
            None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
        }
    }

    async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
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
            None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
        }
    }

    async fn delete(&self, key: &str) -> BulwarkResult<()> {
        self.store.lock().remove(key);
        Ok(())
    }

    async fn get_timeout(&self, key: &str) -> BulwarkResult<Option<Duration>> {
        let store = self.store.lock();
        match store.get(key) {
            Some((_, Some(deadline))) => {
                let now = Instant::now();
                if *deadline <= now {
                    Ok(None)
                } else {
                    Ok(Some(*deadline - now))
                }
            },
            _ => Ok(None),
        }
    }
}

// ------------------------------------------------------------------------
// MockFirewall：模拟 BulwarkPermissionStrategy，控制权限/角色校验返回值
// ------------------------------------------------------------------------

/// 测试用 BulwarkPermissionStrategy mock，可控制 check_permission/check_role 返回值。
pub struct MockFirewall {
    pub has_permission: bool,
    pub has_role: bool,
}

#[async_trait]
impl BulwarkPermissionStrategy for MockFirewall {
    async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
    async fn check_permission(&self, _login_id: &str, _permission: &str) -> BulwarkResult<bool> {
        Ok(self.has_permission)
    }
    async fn check_role(&self, _login_id: &str, _role: &str) -> BulwarkResult<bool> {
        Ok(self.has_role)
    }
    async fn check_role_any(&self, _login_id: &str, _roles: &[&str]) -> BulwarkResult<bool> {
        Ok(self.has_role)
    }
    async fn check_role_all(&self, _login_id: &str, _roles: &[&str]) -> BulwarkResult<bool> {
        Ok(self.has_role)
    }
}

// ------------------------------------------------------------------------
// MockInterface：用于 BulwarkUtil 全局管理器测试
// ------------------------------------------------------------------------

pub struct MockInterface;

#[async_trait]
impl BulwarkInterface for MockInterface {
    async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
}

/// 带预设权限/角色列表的 MockInterface（用于 has_permission/has_role 返回 true 的测试）。
pub struct MockInterfaceWithPerms {
    pub permissions: Vec<String>,
    pub roles: Vec<String>,
}

#[async_trait]
impl BulwarkInterface for MockInterfaceWithPerms {
    async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(self.permissions.clone())
    }
    async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(self.roles.clone())
    }
}

// ------------------------------------------------------------------------
// MockUserRepository：测试用 UserRepository mock（cfg-gated）
// ------------------------------------------------------------------------

/// 测试用 UserRepository mock，用 HashMap 存储 UserRow，按 username 索引。
#[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
pub struct MockUserRepository {
    users: Mutex<HashMap<String, UserRow>>,
}

#[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
impl MockUserRepository {
    pub fn new() -> Self {
        Self {
            users: Mutex::new(HashMap::new()),
        }
    }
    pub fn insert(&self, user: UserRow) {
        self.users.lock().insert(user.username.clone(), user);
    }
}

#[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
#[async_trait]
impl UserRepository for MockUserRepository {
    async fn find_by_id(&self, _tenant_id: i64, id: &str) -> BulwarkResult<Option<UserRow>> {
        Ok(self.users.lock().values().find(|u| u.id == id).cloned())
    }
    async fn find_by_username(
        &self,
        _tenant_id: i64,
        username: &str,
    ) -> BulwarkResult<Option<UserRow>> {
        Ok(self.users.lock().get(username).cloned())
    }
    async fn create(&self, _tenant_id: i64, _user: NewUser) -> BulwarkResult<String> {
        Err(BulwarkError::Internal(
            "MockUserRepository::create not implemented".to_string(),
        ))
    }
    async fn update(&self, _tenant_id: i64, _id: &str, _user: UpdateUser) -> BulwarkResult<()> {
        Ok(())
    }
    async fn delete(&self, _tenant_id: i64, _id: &str) -> BulwarkResult<()> {
        Ok(())
    }
    async fn list(
        &self,
        _tenant_id: i64,
        _offset: i64,
        _limit: i64,
    ) -> BulwarkResult<Vec<UserRow>> {
        Ok(vec![])
    }
}

// ------------------------------------------------------------------------
// MockInterfaceWithLoginType：支持 login_type 隔离的 BulwarkInterface mock
// ------------------------------------------------------------------------

/// 测试用 BulwarkInterface mock，支持 login_type 隔离（override 新方法）。
pub struct MockInterfaceWithLoginType {
    pub perms: HashMap<String, Vec<String>>,
    pub roles: HashMap<String, Vec<String>>,
}

#[async_trait]
impl BulwarkInterface for MockInterfaceWithLoginType {
    async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(self.perms.get("default").cloned().unwrap_or_default())
    }
    async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(self.roles.get("default").cloned().unwrap_or_default())
    }
    // override 新方法以支持多账号隔离
    async fn get_permission_list_with_type(
        &self,
        _login_id: &str,
        login_type: &str,
    ) -> BulwarkResult<Vec<String>> {
        Ok(self.perms.get(login_type).cloned().unwrap_or_default())
    }
    async fn get_role_list_with_type(
        &self,
        _login_id: &str,
        login_type: &str,
    ) -> BulwarkResult<Vec<String>> {
        Ok(self.roles.get(login_type).cloned().unwrap_or_default())
    }
}
