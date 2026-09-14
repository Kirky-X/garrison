//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! web_warp 模块测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `MockDao`（HashMap + Instant 模拟 TTL）与 `MockInterface`（权限/角色数据回调），
//! 供 `web_warp::tests` Filter 集成测试复用。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use crate::stp::GarrisonInterface;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ------------------------------------------------------------------------
// Mock 实现：基于 HashMap + Instant 模拟 TTL，严格按 spec 语义
// ------------------------------------------------------------------------

/// 测试用 mock DAO，支持 TTL 模拟。
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
            None => Err(GarrisonError::Dao(format!("web-key-not-found::{}", key))),
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
            None => Err(GarrisonError::Dao(format!("web-key-not-found::{}", key))),
        }
    }

    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        self.store.lock().remove(key);
        Ok(())
    }
    crate::atomic_test_fallback!();
}

// ------------------------------------------------------------------------
// MockInterface（权限/角色数据回调）
// ------------------------------------------------------------------------

/// 测试用 mock interface，提供权限/角色数据回调。
pub struct MockInterface {
    permissions: HashMap<String, Vec<String>>,
    roles: HashMap<String, Vec<String>>,
}

impl MockInterface {
    /// 创建空的 mock interface 实例（无任何权限/角色数据）。
    pub fn new() -> Self {
        Self {
            permissions: HashMap::new(),
            roles: HashMap::new(),
        }
    }

    /// 设置指定 login_id 的权限列表。
    pub fn with_permission(mut self, login_id: &str, perms: &[&str]) -> Self {
        self.permissions.insert(
            login_id.to_string(),
            perms.iter().map(|s| s.to_string()).collect(),
        );
        self
    }

    /// 设置指定 login_id 的角色列表。
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

#[cfg(test)]
mod mock_dao_coverage_tests {
    use super::*;

    /// MockDao 组合回退方法覆盖测试。
    ///
    /// ocr #7586：不再对结果一律 `let _ =`——确定性路径补断言，
    /// 回归（如 rename 丢值 / incr 不计数）将使测试失败。
    #[tokio::test]
    async fn mock_dao_atomic_and_default_methods_coverage() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 60).await.unwrap();

        // set_if_absent：key 不存在 → Ok(true) 并写入
        let inserted = dao.set_if_absent("a1", "v1", 60).await.unwrap();
        assert!(inserted, "set_if_absent 对不存在的 key 应返回 true");

        // get_and_delete：取回并删除
        let removed = dao.get_and_delete("a1").await.unwrap();
        assert_eq!(
            removed.as_deref(),
            Some("v1"),
            "get_and_delete 应取回刚写入的值"
        );
        let gone = dao.get("a1").await.unwrap();
        assert!(gone.is_none(), "get_and_delete 后 key 应不存在");

        // incr：从 1 开始计数
        let n = dao.incr("ctr", 60).await.unwrap();
        assert_eq!(n, 1, "incr 对不存在的 key 应返回 1");

        // decr：1 → 0（并删除 key）
        let n = dao.decr("ctr").await.unwrap();
        assert_eq!(n, 0, "decr 1 应得到 0");
        let gone = dao.get("ctr").await.unwrap();
        assert!(gone.is_none(), "decr 到 0 后 key 应被删除");

        // rename：值迁移到新 key
        dao.rename("k1", "k2").await.unwrap();
        let migrated = dao.get("k2").await.unwrap();
        assert_eq!(
            migrated.as_deref(),
            Some("v1"),
            "rename 后新 key 应携带原值"
        );
        let gone = dao.get("k1").await.unwrap();
        assert!(gone.is_none(), "rename 后旧 key 应不存在");

        // compare_and_swap：expected 匹配 → 写入成功
        let swapped = dao
            .compare_and_swap("k2", Some("v1"), "v2", 60)
            .await
            .unwrap();
        assert!(swapped, "expected 匹配时 CAS 应成功");
        let updated = dao.get("k2").await.unwrap();
        assert_eq!(updated.as_deref(), Some("v2"));

        // set_permanent + get
        dao.set_permanent("p1", "val").await.unwrap();
        let v = dao.get("p1").await.unwrap();
        assert_eq!(v.as_deref(), Some("val"));

        // 其余辅助方法：冒烟调用（返回值语义依赖 trait 默认实现，仅保证不 panic）
        let _ = dao.get_with_ttl("k1").await;
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
