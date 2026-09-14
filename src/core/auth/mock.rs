//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! 认证逻辑层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `MockDao`（基于 `tokio::sync::Mutex<HashMap>` + `Instant` 模拟 TTL），
//! 供 `core::auth::tests` 登录/登出/会话测试复用。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// 测试用 mock DAO，模拟 oxcache 的 TTL 行为。
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
        let mut store = self.store.lock().await;
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
            .await
            .insert(key.to_string(), (value.to_string(), expire_at));
        Ok(())
    }

    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        let mut store = self.store.lock().await;
        match store.get_mut(key) {
            Some((existing, _)) => {
                *existing = value.to_string();
                Ok(())
            },
            None => Err(GarrisonError::Dao(format!("dao-key-not-found::{}", key))),
        }
    }

    async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
        let mut store = self.store.lock().await;
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
        self.store.lock().await.remove(key);
        Ok(())
    }

    /// 查询 key 的剩余 TTL（供 renew_to_equivalent 测试使用）。
    ///
    /// - `Some(remaining)`: 键存在且设置了 TTL（expire_at - now）
    /// - `None`: 键不存在，或永久键（expire_at = None）
    async fn get_timeout(&self, key: &str) -> GarrisonResult<Option<Duration>> {
        let store = self.store.lock().await;
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

    /// 原子获取 value + TTL（性能优化重写）。
    ///
    /// 单次 lookup + 锁获取，避免 `get` + `get_timeout` 两次锁获取。
    /// 用于 `renew_to_equivalent` 热路径性能优化。
    ///
    /// 过期语义与 [`Self::get`] 一致：
    /// - 单次 `Instant::now()` 同时用于过期判断与 TTL 计算（消除两次取时之间
    /// deadline 到期导致的「条目残留 + TTL 为 None」TOCTOU 窗口）
    /// - `deadline <= now` 时惰性删除并返回 `Ok(None)`（原实现在边界处返回
    /// `Some((value, None))` 且不删键，与 `get` 行为不一致）
    async fn get_with_ttl(&self, key: &str) -> GarrisonResult<Option<(String, Option<Duration>)>> {
        let mut store = self.store.lock().await;
        match store.get(key) {
            Some((value, expire_at)) => {
                // 单次取时：过期判断与 TTL 计算使用同一 Instant
                let now = Instant::now();
                match expire_at {
                    Some(deadline) if *deadline <= now => {
                        // 惰性删除，与 get 行为一致
                        store.remove(key);
                        Ok(None)
                    },
                    Some(deadline) => Ok(Some((value.clone(), Some(*deadline - now)))),
                    None => Ok(Some((value.clone(), None))),
                }
            },
            None => Ok(None),
        }
    }
    crate::atomic_test_fallback!();
}

#[cfg(test)]
mod mock_dao_coverage_tests {
    use super::*;

    /// 原子回退方法 + trait 默认方法的覆盖测试。
    ///
    /// 对每个方法的返回值断言（组合回退语义 / NotImplemented 契约），
    /// 而非仅验证编译与不 panic。
    ///
    /// trait 默认实现（keys / find_social_binding / eval_lua / DB 域方法等）
    /// 返回 `NotImplemented`，用 `matches!` 锁定契约，不静默丢弃错误。
    #[tokio::test]
    async fn mock_dao_atomic_and_default_methods_coverage() {
        let dao = MockDao::new();

        // --- 原子回退方法：组合语义断言 ---
        dao.set("k1", "v1", 60).await.unwrap();

        // set_if_absent：不存在时插入成功，已存在时返回 false
        assert!(
            dao.set_if_absent("a1", "v1", 60).await.unwrap(),
            "key 不存在时 set_if_absent 应返回 true"
        );
        assert!(
            !dao.set_if_absent("a1", "v2", 60).await.unwrap(),
            "key 已存在时 set_if_absent 应返回 false"
        );

        // get_and_delete：返回原值并删除；再取为 None
        assert_eq!(
            dao.get_and_delete("a1").await.unwrap().as_deref(),
            Some("v1"),
            "get_and_delete 应返回原值"
        );
        assert_eq!(
            dao.get("a1").await.unwrap(),
            None,
            "get_and_delete 后键应被删除"
        );

        // incr / decr：计数器组合语义（incr 从 1 起，decr 到 0 时删键）
        assert_eq!(dao.incr("ctr", 60).await.unwrap(), 1, "首次 incr 应为 1");
        assert_eq!(dao.incr("ctr", 60).await.unwrap(), 2, "二次 incr 应为 2");
        assert_eq!(dao.decr("ctr").await.unwrap(), 1, "decr 应递减到 1");

        // rename：old 键迁移到 new 键
        dao.rename("k1", "k2").await.unwrap();
        assert_eq!(dao.get("k1").await.unwrap(), None, "rename 后旧键应删除");
        assert_eq!(
            dao.get("k2").await.unwrap().as_deref(),
            Some("v1"),
            "rename 后新键应携带原值"
        );

        // compare_and_swap：expected 匹配时写入并返回 true，不匹配返回 false
        assert!(
            dao.compare_and_swap("k2", Some("v1"), "v2", 60)
                .await
                .unwrap(),
            "expected 匹配时 compare_and_swap 应成功"
        );
        assert!(
            !dao.compare_and_swap("k2", Some("v1"), "v3", 60)
                .await
                .unwrap(),
            "expected 不匹配时 compare_and_swap 应返回 false"
        );

        // set_permanent：永久键可读且 get_timeout 为 None（无 TTL）
        dao.set_permanent("p1", "val").await.unwrap();
        assert_eq!(dao.get("p1").await.unwrap().as_deref(), Some("val"));
        assert_eq!(
            dao.get_timeout("p1").await.unwrap(),
            None,
            "永久键 get_timeout 应为 None"
        );

        // get_with_ttl：存在且设置了 TTL 的键返回 Some((value, Some(remaining)))
        let (v, ttl) = dao
            .get_with_ttl("k2")
            .await
            .unwrap()
            .expect("已设 TTL 的键 get_with_ttl 应返回 Some");
        assert_eq!(v, "v2");
        assert!(ttl.is_some(), "设置了 TTL 的键应返回 Some(remaining)");

        // --- trait 默认实现：NotImplemented 契约锁定 ---
        assert!(
            matches!(dao.keys("*").await, Err(GarrisonError::NotImplemented(_))),
            "keys 默认实现应返回 NotImplemented"
        );
        assert!(
            matches!(
                dao.find_social_binding(0, "w", "o").await,
                Err(GarrisonError::NotImplemented(_))
            ),
            "find_social_binding 默认实现应返回 NotImplemented"
        );
        assert!(
            matches!(
                dao.insert_social_binding(0, "u", "w", "o", None, 0).await,
                Err(GarrisonError::NotImplemented(_))
            ),
            "insert_social_binding 默认实现应返回 NotImplemented"
        );
        assert!(
            matches!(
                dao.compare_and_update_if_greater("k1", 10, 60).await,
                Err(GarrisonError::NotImplemented(_))
            ),
            "compare_and_update_if_greater 默认实现应返回 NotImplemented"
        );
        assert!(
            matches!(
                dao.eval_lua("r", vec![], vec![]).await,
                Err(GarrisonError::NotImplemented(_))
            ),
            "eval_lua 默认实现应返回 NotImplemented"
        );
        #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
        {
            assert!(
                matches!(
                    dao.insert_credit_consumption(0, "r", 1, 1, 1, 0).await,
                    Err(GarrisonError::NotImplemented(_))
                ),
                "insert_credit_consumption 默认实现应返回 NotImplemented"
            );
            assert!(
                matches!(
                    dao.query_credit_consumption(0, 0, 0).await,
                    Err(GarrisonError::NotImplemented(_))
                ),
                "query_credit_consumption 默认实现应返回 NotImplemented"
            );
            assert!(
                matches!(
                    dao.query_role_hierarchy_edges(0).await,
                    Err(GarrisonError::NotImplemented(_))
                ),
                "query_role_hierarchy_edges 默认实现应返回 NotImplemented"
            );
            assert!(
                matches!(
                    dao.insert_role_hierarchy_edge(0, "c", "p").await,
                    Err(GarrisonError::NotImplemented(_))
                ),
                "insert_role_hierarchy_edge 默认实现应返回 NotImplemented"
            );
            assert!(
                matches!(
                    dao.delete_role_hierarchy_edge(0, "c", "p").await,
                    Err(GarrisonError::NotImplemented(_))
                ),
                "delete_role_hierarchy_edge 默认实现应返回 NotImplemented"
            );
        }
    }
}
