//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! API 签名协议层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `MockDao`（基于 `tokio::sync::Mutex<HashMap>` 模拟 DAO），
//! 供 `protocol::sign::tests` 签名生成/校验测试复用。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// 测试用 Mock DAO。
///
/// TTL 语义（可验证，不再是 no-op）：
/// - `set` 的 `ttl_seconds > 0` 记录过期时刻，`ttl_seconds == 0` 表示永不过期；
/// - `expire` 为**已存在**的 key 设置新的过期时刻（与 Redis EXPIRE 对齐，
///   `seconds == 0` 即立即过期），key 不存在时静默忽略；
/// - `get` 命中已过期 key 时惰性清除并返回 `None`。
///
/// 使 TTL 过期行为（如 sign nonce 跨窗口重放）可经此 mock 真实验证，
/// 而不是依赖 TTL 的测试全部"假通过"。
pub struct MockDao {
    data: Mutex<HashMap<String, String>>,
    /// key → 过期时刻；未记录表示永不过期。
    expiries: Mutex<HashMap<String, Instant>>,
}

impl MockDao {
    /// 创建空的 mock DAO 实例（无任何键值）。
    pub fn new() -> Self {
        Self {
            data: Mutex::new(HashMap::new()),
            expiries: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl GarrisonDao for MockDao {
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        // 锁序恒为 data → expiries，避免与 set/delete 交叉死锁
        let mut data = self.data.lock().await;
        let mut expiries = self.expiries.lock().await;
        // TTL 惰性过期：命中已过期 key 时清除并视为不存在
        if let Some(deadline) = expiries.get(key) {
            if Instant::now() >= *deadline {
                expiries.remove(key);
                data.remove(key);
                return Ok(None);
            }
        }
        Ok(data.get(key).cloned())
    }

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
        let mut data = self.data.lock().await;
        let mut expiries = self.expiries.lock().await;
        data.insert(key.to_string(), value.to_string());
        if ttl_seconds > 0 {
            expiries.insert(
                key.to_string(),
                Instant::now() + Duration::from_secs(ttl_seconds),
            );
        } else {
            expiries.remove(key);
        }
        Ok(())
    }

    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        let mut data = self.data.lock().await;
        if data.contains_key(key) {
            data.insert(key.to_string(), value.to_string());
            Ok(())
        } else {
            Err(GarrisonError::Dao(format!("dao-key-not-found::{}", key)))
        }
    }

    async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
        let data = self.data.lock().await;
        let mut expiries = self.expiries.lock().await;
        // 与 Redis EXPIRE 对齐：仅对存在的 key 生效；seconds == 0 即立即过期
        if data.contains_key(key) {
            expiries.insert(
                key.to_string(),
                Instant::now() + Duration::from_secs(seconds),
            );
        }
        Ok(())
    }

    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        let mut data = self.data.lock().await;
        let mut expiries = self.expiries.lock().await;
        data.remove(key);
        expiries.remove(key);
        Ok(())
    }
    crate::atomic_test_fallback!();
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
        assert!(matches!(result, Err(GarrisonError::Dao(_))));
    }

    #[tokio::test]
    async fn expire_sets_deadline_key_stays_readable_before_expiry() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 0).await.unwrap();
        dao.expire("k1", 120).await.unwrap();
        // 未到期仍可读
        assert_eq!(dao.get("k1").await.unwrap(), Some("v1".to_string()));
    }

    /// expire(0) 立即过期：get 惰性清除并返回 None。
    #[tokio::test]
    async fn expire_zero_expires_key_immediately() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 0).await.unwrap();
        dao.expire("k1", 0).await.unwrap();
        assert_eq!(dao.get("k1").await.unwrap(), None);
    }

    /// expire 对不存在的 key 静默忽略（Redis EXPIRE 语义，不报错）。
    #[tokio::test]
    async fn expire_missing_key_is_ignored() {
        let dao = MockDao::new();
        assert!(dao.expire("missing", 60).await.is_ok());
    }

    /// set 携带的 TTL 到期后 get 返回 None（真实时间流逝，惰性清除）。
    #[tokio::test]
    async fn set_with_ttl_expires_after_deadline() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 1).await.unwrap();
        assert_eq!(dao.get("k1").await.unwrap(), Some("v1".to_string()));
        tokio::time::sleep(Duration::from_millis(1100)).await;
        assert_eq!(dao.get("k1").await.unwrap(), None);
    }

    #[tokio::test]
    async fn delete_removes_key() {
        let dao = MockDao::new();
        dao.set("k1", "v1", 60).await.unwrap();
        dao.delete("k1").await.unwrap();
        assert_eq!(dao.get("k1").await.unwrap(), None);
    }

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
