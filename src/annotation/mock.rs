//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! 注解层测试 mock 实现。
//!
//! 本模块仅在 `cfg(all(test, feature = "web-axum"))` 下编译（通过 `mod.rs` 中的
//! `#[cfg(all(test, feature = "web-axum"))] mod mock;` 声明），
//! 提供 `MockDao`（基于 `parking_lot::Mutex<HashMap>` + `Instant` 模拟 TTL）
//! 与 `MockInterface`（模拟 `GarrisonInterface` 权限/角色回调），
//! 供 `annotation::tests` axum extractor 集成测试复用。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use crate::stp::GarrisonInterface;
use async_trait::async_trait;
use parking_lot::Mutex;
use std::collections::HashMap;
use std::time::{Duration, Instant};

// ------------------------------------------------------------------------
// MockDao（复用 manager 测试的 HashMap + Instant 模拟 TTL）
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
            None => Err(GarrisonError::Dao(format!("dao-key-not-found::{}", key))),
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
            None => Err(GarrisonError::Dao(format!("dao-key-not-found::{}", key))),
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

#[cfg(test)]
mod mock_dao_coverage_tests {
    use super::*;

    /// ocr #408：fallback / 默认方法调用的结果不再 `let _` 丢弃——
    /// 组合回退路径逐一断言返回值；MockDao 未重写的默认方法断言
    /// fail-closed 的 `NotImplemented` 语义。
    #[tokio::test]
    async fn mock_dao_atomic_and_default_methods_coverage() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 60).await.unwrap();

        // ---- atomic_test_fallback! 方法（组合回退语义）----
        // key 不存在 → 写入成功
        assert!(dao.set_if_absent("a1", "v1", 60).await.unwrap());
        // 读取并删除 → 取回刚写入的值
        assert_eq!(
            dao.get_and_delete("a1").await.unwrap().as_deref(),
            Some("v1")
        );
        // 计数器：缺失 key 首次 incr → 1，再 decr → 归 0（key 删除）
        assert_eq!(dao.incr("ctr", 60).await.unwrap(), 1);
        assert_eq!(dao.decr("ctr").await.unwrap(), 0);
        // rename：k1 存在 → Ok(())，值迁移到 k2
        dao.rename("k1", "k2").await.unwrap();
        assert_eq!(dao.get("k2").await.unwrap().as_deref(), Some("v1"));
        // CAS：k2 当前值匹配 expected → 成功交换
        assert!(dao
            .compare_and_swap("k2", Some("v1"), "v2", 60)
            .await
            .unwrap());
        assert_eq!(dao.get("k2").await.unwrap().as_deref(), Some("v2"));

        // ---- trait 默认方法 ----
        dao.set_permanent("p1", "val").await.unwrap();
        assert_eq!(dao.get("p1").await.unwrap().as_deref(), Some("val"));
        // k1 已 rename 到 k2 → Ok(None)
        assert!(dao.get_with_ttl("k1").await.unwrap().is_none());
        // MockDao 未重写 get_timeout → fail-closed NotImplemented
        assert!(matches!(
            dao.get_timeout("k1").await,
            Err(GarrisonError::NotImplemented(_))
        ));
        // KV 抽象不支持 glob 扫描 / SQL 类默认方法 → NotImplemented
        assert!(matches!(
            dao.keys("*").await,
            Err(GarrisonError::NotImplemented(_))
        ));
        assert!(matches!(
            dao.find_social_binding(0, "wechat", "oid").await,
            Err(GarrisonError::NotImplemented(_))
        ));
        assert!(matches!(
            dao.insert_social_binding(0, "u1", "wechat", "oid", None, 0)
                .await,
            Err(GarrisonError::NotImplemented(_))
        ));
        assert!(matches!(
            dao.compare_and_update_if_greater("k1", 10, 60).await,
            Err(GarrisonError::NotImplemented(_))
        ));
        assert!(matches!(
            dao.eval_lua("return 1", vec![], vec![]).await,
            Err(GarrisonError::NotImplemented(_))
        ));
        #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
        {
            assert!(matches!(
                dao.insert_credit_consumption(0, "r", 1, 100, 100, 0).await,
                Err(GarrisonError::NotImplemented(_))
            ));
            assert!(matches!(
                dao.query_credit_consumption(0, 0, 0).await,
                Err(GarrisonError::NotImplemented(_))
            ));
            assert!(matches!(
                dao.query_role_hierarchy_edges(0).await,
                Err(GarrisonError::NotImplemented(_))
            ));
            assert!(matches!(
                dao.insert_role_hierarchy_edge(0, "c", "p").await,
                Err(GarrisonError::NotImplemented(_))
            ));
            assert!(matches!(
                dao.delete_role_hierarchy_edge(0, "c", "p").await,
                Err(GarrisonError::NotImplemented(_))
            ));
        }
    }
}
