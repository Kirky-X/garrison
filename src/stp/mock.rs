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
            None => Err(BulwarkError::Dao(format!("dao-key-not-found::{}", key))),
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
            None => Err(BulwarkError::Dao(format!("dao-key-not-found::{}", key))),
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

// ============================================================================
// mock 实现自身的单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ------------------------------------------------------------------------
    // MockDao 测试
    // ------------------------------------------------------------------------

    /// set 后 get 返回相同值。
    #[tokio::test]
    async fn mock_dao_set_then_get_returns_value() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 0).await.unwrap();
        let v = dao.get("k1").await.unwrap();
        assert_eq!(v.as_deref(), Some("v1"));
    }

    /// get 不存在的 key 返回 None。
    #[tokio::test]
    async fn mock_dao_get_missing_returns_none() {
        let dao = MockDao::new();
        let v = dao.get("no-such-key").await.unwrap();
        assert!(v.is_none(), "不存在的 key 应返回 None");
    }

    /// update 已存在的 key 后 get 返回新值。
    #[tokio::test]
    async fn mock_dao_update_existing_key() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 0).await.unwrap();
        dao.update("k1", "v2").await.unwrap();
        assert_eq!(dao.get("k1").await.unwrap().as_deref(), Some("v2"));
    }

    /// update 不存在的 key 返回 Dao 错误。
    #[tokio::test]
    async fn mock_dao_update_missing_key_returns_error() {
        let dao = MockDao::new();
        let result = dao.update("missing", "v").await;
        assert!(
            matches!(result, Err(BulwarkError::Dao(ref msg)) if msg.contains("missing")),
            "update 不存在的 key 应返回 Dao 错误包含 key 名，实际: {:?}",
            result
        );
    }

    /// expire 不存在的 key 返回 Dao 错误。
    #[tokio::test]
    async fn mock_dao_expire_missing_key_returns_error() {
        let dao = MockDao::new();
        let result = dao.expire("missing", 60).await;
        assert!(
            matches!(result, Err(BulwarkError::Dao(_))),
            "expire 不存在的 key 应返回 Dao 错误，实际: {:?}",
            result
        );
    }

    /// expire 设置 0 秒后 TTL 变为 None（永久）。
    #[tokio::test]
    async fn mock_dao_expire_zero_seconds_clears_ttl() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 60).await.unwrap();
        dao.expire("k1", 0).await.unwrap();
        assert_eq!(dao.get("k1").await.unwrap().as_deref(), Some("v1"));
        // get_timeout 应返回 None（无 deadline）
        let t = dao.get_timeout("k1").await.unwrap();
        assert!(
            t.is_none(),
            "expire 0 后应无 deadline，get_timeout 返回 None"
        );
    }

    /// delete 后 key 不再可读。
    #[tokio::test]
    async fn mock_dao_delete_removes_key() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 0).await.unwrap();
        dao.delete("k1").await.unwrap();
        assert!(dao.get("k1").await.unwrap().is_none());
    }

    /// delete 不存在的 key 仍返回 Ok（幂等）。
    #[tokio::test]
    async fn mock_dao_delete_missing_key_is_idempotent() {
        let dao = MockDao::new();
        assert!(dao.delete("missing").await.is_ok());
    }

    /// get_timeout 不存在的 key 返回 None。
    #[tokio::test]
    async fn mock_dao_get_timeout_missing_returns_none() {
        let dao = MockDao::new();
        let t = dao.get_timeout("missing").await.unwrap();
        assert!(t.is_none());
    }

    /// get_timeout 永久 key（无 TTL）返回 None。
    #[tokio::test]
    async fn mock_dao_get_timeout_permanent_key_returns_none() {
        let dao = MockDao::new();
        dao.set("perm", "v", 0).await.unwrap();
        assert!(dao.get_timeout("perm").await.unwrap().is_none());
    }

    /// set 带 TTL 后 get_timeout 返回 Some(Duration)。
    #[tokio::test]
    async fn mock_dao_get_timeout_returns_some_for_ttl_key() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 3600).await.unwrap();
        let t = dao.get_timeout("k1").await.unwrap();
        assert!(t.is_some(), "带 TTL 的 key get_timeout 应返回 Some");
        let d = t.unwrap();
        // 容差检查：剩余时间应小于等于 3600 秒
        assert!(d.as_secs() <= 3600, "剩余时间应 <= 3600s，实际: {:?}", d);
    }

    /// set 带 1 秒 TTL 后等待过期，get 返回 None（覆盖 lines 46-49 过期清理路径）。
    #[tokio::test]
    async fn mock_dao_get_expired_key_returns_none() {
        let dao = MockDao::new();
        dao.set("expiring", "v", 1).await.unwrap();
        // 确认立即读取有值
        assert_eq!(dao.get("expiring").await.unwrap().as_deref(), Some("v"));
        // 等待过期
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        // 过期后应返回 None 并清理
        assert!(
            dao.get("expiring").await.unwrap().is_none(),
            "过期 key 应返回 None"
        );
    }

    /// get_timeout 在 deadline 已过期时返回 None（覆盖 lines 105-106）。
    #[tokio::test]
    async fn mock_dao_get_timeout_expired_returns_none() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 1).await.unwrap();
        // 等待过期
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        // deadline <= now 时应返回 None
        let t = dao.get_timeout("k1").await.unwrap();
        assert!(
            t.is_none(),
            "deadline <= now 时 get_timeout 应返回 None，实际: {:?}",
            t
        );
    }

    /// set 带 TTL 后 expire 重新设置更长 TTL，key 仍可读。
    #[tokio::test]
    async fn mock_dao_expire_extends_ttl() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 1).await.unwrap();
        // 续期到 3600 秒
        dao.expire("k1", 3600).await.unwrap();
        // 等待原 TTL 过期
        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;
        // 续期后应仍可读
        assert_eq!(
            dao.get("k1").await.unwrap().as_deref(),
            Some("v1"),
            "expire 续期后 key 应仍可读"
        );
    }

    // ------------------------------------------------------------------------
    // MockFirewall 测试
    // ------------------------------------------------------------------------

    /// MockFirewall 的 check_permission/check_role 返回构造时设置的 bool 值。
    #[tokio::test]
    async fn mock_firewall_returns_configured_booleans() {
        let fw = MockFirewall {
            has_permission: true,
            has_role: false,
        };
        assert!(fw.check_permission("u1", "p1").await.unwrap());
        assert!(!fw.check_role("u1", "r1").await.unwrap());
    }

    /// MockFirewall 的 check_role_any 返回 has_role（与 role 列表无关）。
    #[tokio::test]
    async fn mock_firewall_check_role_any_returns_has_role() {
        let fw = MockFirewall {
            has_permission: false,
            has_role: true,
        };
        assert!(fw.check_role_any("u1", &["a", "b"]).await.unwrap());
    }

    /// MockFirewall 的 check_role_all 返回 has_role（与 role 列表无关）。
    #[tokio::test]
    async fn mock_firewall_check_role_all_returns_has_role() {
        let fw = MockFirewall {
            has_permission: false,
            has_role: false,
        };
        assert!(!fw.check_role_all("u1", &["a", "b"]).await.unwrap());
    }

    /// MockFirewall 的 get_permission_list / get_role_list 返回空 Vec。
    #[tokio::test]
    async fn mock_firewall_get_lists_return_empty() {
        let fw = MockFirewall {
            has_permission: true,
            has_role: true,
        };
        assert_eq!(
            fw.get_permission_list("u1").await.unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(fw.get_role_list("u1").await.unwrap(), Vec::<String>::new());
    }

    // ------------------------------------------------------------------------
    // MockInterface / MockInterfaceWithPerms 测试
    // ------------------------------------------------------------------------

    /// MockInterface 默认返回空权限/角色列表。
    #[tokio::test]
    async fn mock_interface_returns_empty_lists() {
        let iface = MockInterface;
        assert_eq!(
            iface.get_permission_list("u1").await.unwrap(),
            Vec::<String>::new()
        );
        assert_eq!(
            iface.get_role_list("u1").await.unwrap(),
            Vec::<String>::new()
        );
    }

    /// MockInterfaceWithPerms 返回构造时设置的权限/角色列表。
    #[tokio::test]
    async fn mock_interface_with_perms_returns_configured_lists() {
        let iface = MockInterfaceWithPerms {
            permissions: vec!["user:read".to_string(), "user:write".to_string()],
            roles: vec!["admin".to_string()],
        };
        assert_eq!(
            iface.get_permission_list("u1").await.unwrap(),
            vec!["user:read".to_string(), "user:write".to_string()]
        );
        assert_eq!(
            iface.get_role_list("u1").await.unwrap(),
            vec!["admin".to_string()]
        );
    }

    // ------------------------------------------------------------------------
    // MockInterfaceWithLoginType 测试
    // ------------------------------------------------------------------------

    /// get_permission_list_with_type 按 login_type 隔离返回权限列表。
    #[tokio::test]
    async fn mock_interface_with_login_type_returns_perms_by_type() {
        let mut perms = HashMap::new();
        perms.insert(
            "admin".to_string(),
            vec!["admin:read".to_string(), "admin:write".to_string()],
        );
        perms.insert("user".to_string(), vec!["user:read".to_string()]);
        let iface = MockInterfaceWithLoginType {
            perms,
            roles: HashMap::new(),
        };
        // admin login_type
        assert_eq!(
            iface
                .get_permission_list_with_type("u1", "admin")
                .await
                .unwrap(),
            vec!["admin:read".to_string(), "admin:write".to_string()]
        );
        // user login_type
        assert_eq!(
            iface
                .get_permission_list_with_type("u1", "user")
                .await
                .unwrap(),
            vec!["user:read".to_string()]
        );
        // 未知 login_type 返回空 Vec
        assert_eq!(
            iface
                .get_permission_list_with_type("u1", "unknown")
                .await
                .unwrap(),
            Vec::<String>::new()
        );
    }

    /// get_role_list_with_type 按 login_type 隔离返回角色列表。
    #[tokio::test]
    async fn mock_interface_with_login_type_returns_roles_by_type() {
        let mut roles = HashMap::new();
        roles.insert("admin".to_string(), vec!["super-admin".to_string()]);
        let iface = MockInterfaceWithLoginType {
            perms: HashMap::new(),
            roles,
        };
        assert_eq!(
            iface.get_role_list_with_type("u1", "admin").await.unwrap(),
            vec!["super-admin".to_string()]
        );
        // 未知 login_type 返回空 Vec
        assert_eq!(
            iface.get_role_list_with_type("u1", "user").await.unwrap(),
            Vec::<String>::new()
        );
    }

    /// get_permission_list（不带 type）默认查询 "default" login_type。
    #[tokio::test]
    async fn mock_interface_with_login_type_default_uses_default_key() {
        let mut perms = HashMap::new();
        perms.insert("default".to_string(), vec!["default:perm".to_string()]);
        let iface = MockInterfaceWithLoginType {
            perms,
            roles: HashMap::new(),
        };
        assert_eq!(
            iface.get_permission_list("u1").await.unwrap(),
            vec!["default:perm".to_string()]
        );
    }

    // ------------------------------------------------------------------------
    // MockUserRepository 测试（cfg-gated: account-credential + db-sqlite）
    // ------------------------------------------------------------------------

    #[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
    mod user_repo_tests {
        use super::*;

        fn make_row(id: &str, username: &str) -> UserRow {
            UserRow {
                id: id.to_string(),
                username: username.to_string(),
                password_hash: "hash".to_string(),
                status: "active".to_string(),
                tenant_id: 0,
                created_at: "2026-07-04T00:00:00Z".to_string(),
                updated_at: "2026-07-04T00:00:00Z".to_string(),
                last_login_at: None,
            }
        }

        /// insert 后 find_by_username 返回 Some。
        #[tokio::test]
        async fn mock_user_repo_find_by_username_returns_some() {
            let repo = MockUserRepository::new();
            repo.insert(make_row("u-1", "alice"));
            let r = repo.find_by_username(0, "alice").await.unwrap();
            assert!(r.is_some(), "插入后 find_by_username 应返回 Some");
            assert_eq!(r.unwrap().id, "u-1");
        }

        /// find_by_username 不存在的用户返回 None。
        #[tokio::test]
        async fn mock_user_repo_find_by_username_missing_returns_none() {
            let repo = MockUserRepository::new();
            let r = repo.find_by_username(0, "nobody").await.unwrap();
            assert!(r.is_none(), "未插入用户 find_by_username 应返回 None");
        }

        /// find_by_id 按 id 字段查找（与 username 无关）。
        #[tokio::test]
        async fn mock_user_repo_find_by_id_returns_some() {
            let repo = MockUserRepository::new();
            repo.insert(make_row("u-42", "alice"));
            let r = repo.find_by_id(0, "u-42").await.unwrap();
            assert!(r.is_some(), "插入后 find_by_id 应返回 Some");
            assert_eq!(r.unwrap().username, "alice");
        }

        /// find_by_id 不存在返回 None。
        #[tokio::test]
        async fn mock_user_repo_find_by_id_missing_returns_none() {
            let repo = MockUserRepository::new();
            let r = repo.find_by_id(0, "missing").await.unwrap();
            assert!(r.is_none());
        }

        /// create 始终返回 Err(Internal)（mock 未实现 create）。
        #[tokio::test]
        async fn mock_user_repo_create_returns_internal_error() {
            let repo = MockUserRepository::new();
            let new_user = NewUser {
                username: "new".to_string(),
                password_hash: "hash".to_string(),
                status: "active".to_string(),
            };
            let result = repo.create(0, new_user).await;
            assert!(
                matches!(result, Err(BulwarkError::Internal(ref msg)) if msg.contains("create not implemented")),
                "create 应返回 Internal 错误包含 'create not implemented'，实际: {:?}",
                result
            );
        }

        /// update 始终返回 Ok（no-op）。
        #[tokio::test]
        async fn mock_user_repo_update_returns_ok() {
            let repo = MockUserRepository::new();
            let update = UpdateUser {
                username: None,
                password_hash: Some("new-hash".to_string()),
                status: Some("inactive".to_string()),
                last_login_at: None,
            };
            repo.update(0, "any-id", update).await.unwrap();
        }

        /// delete 始终返回 Ok（no-op）。
        #[tokio::test]
        async fn mock_user_repo_delete_returns_ok() {
            let repo = MockUserRepository::new();
            repo.delete(0, "any-id").await.unwrap();
        }

        /// list 始终返回空 Vec。
        #[tokio::test]
        async fn mock_user_repo_list_returns_empty() {
            let repo = MockUserRepository::new();
            let v = repo.list(0, 0, 10).await.unwrap();
            assert!(v.is_empty(), "list 应返回空 Vec，实际长度: {}", v.len());
        }
    }
}
