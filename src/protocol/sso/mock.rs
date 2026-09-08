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

    // T012/架构审查 A3：其余 5 个原子方法经子集宏展开（逻辑单点维护于
    // dao::atomic_fallback::impls），本 mock 自定义的单锁原子 get_and_delete
    //（vuln-0005 语义）保留不被覆盖。
    crate::atomic_test_fallback_no_get_and_delete!();
}

#[cfg(test)]
mod mock_dao_coverage_tests {
    use super::*;

    #[tokio::test]
    async fn mock_dao_atomic_and_default_methods_coverage() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 60).await.unwrap();
        let _ = dao.set_if_absent("a1", "v1", 60).await;
        let _ = dao.get_and_delete("a1").await;
        let _ = dao.incr("ctr", 60).await;
        let _ = dao.decr("ctr").await;
        let _ = dao.rename("k1", "k2").await;
        let _ = dao.compare_and_swap("k2", Some("v1"), "v2", 60).await;
        let _ = dao.set_permanent("p1", "val").await;
        let _ = dao.get_timeout("k1").await;
        let _ = dao.get_with_ttl("k1").await;
        let _ = dao.keys("*").await;
        let _ = dao.find_social_binding(0, "w", "o").await;
        let _ = dao.insert_social_binding(0, "u", "w", "o", None, 0).await;
        let _ = dao.compare_and_update_if_greater("k1", 10, 60).await;
        let _ = dao.eval_lua("r", vec![], vec![]).await;
        #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
        {
            let _ = dao.insert_credit_consumption(0, "r", 1, 1, 1, 0).await;
            let _ = dao.query_credit_consumption(0, 0, 0).await;
            let _ = dao.query_role_hierarchy_edges(0).await;
            let _ = dao.insert_role_hierarchy_edge(0, "c", "p").await;
            let _ = dao.delete_role_hierarchy_edge(0, "c", "p").await;
        }
    }
}
