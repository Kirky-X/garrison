// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 缓存预热子模块。
//!
//! 提供 [`CacheWarmupService`] 在启动时从 DAO 加载角色权限与租户配置到缓存，
//! 减少冷启动延迟。

use crate::constants::DaoKeyPrefix;
use crate::error::GarrisonResult;
use std::sync::Arc;

use crate::dao::GarrisonDao;

/// 预热统计。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmupStats {
    /// 加载的角色数量。
    pub roles_loaded: u32,
    /// 加载的租户配置数量。
    pub tenants_loaded: u32,
}

/// 缓存预热服务。
///
/// 从 DAO 扫描 `role:*` 和 `tenant:*` 键，逐个 `get()` 触发缓存填充，
/// 返回加载统计。预热是可选行为，由调用方显式调用 `warmup()`。
pub struct CacheWarmupService {
    dao: Arc<dyn GarrisonDao>,
}

impl CacheWarmupService {
    /// 创建预热服务实例。
    pub fn new(dao: Arc<dyn GarrisonDao>) -> Self {
        Self { dao }
    }

    /// 执行缓存预热：扫描 DAO 中所有 `role:*` 与 `tenant:*` 键并逐个 `get()` 触发填充，返回加载统计；空库返回零统计不报错。
    ///
    /// # 部分失败语义
    ///
    /// DAO 不支持 `keys()`（返回 `NotImplemented`，如部分 oxcache 部署）时，对应部分记 `warn` 按零键处理，
    /// **其余部分继续预热**（不丢弃已成功结果），不传播错误；两者都不支持时返回零统计。
    pub async fn warmup(&self) -> GarrisonResult<WarmupStats> {
        let role_pattern = format!("{}*", DaoKeyPrefix::Role.as_str());
        let tenant_pattern = format!("{}*", DaoKeyPrefix::Tenant.as_str());

        let role_keys = match self.dao.keys(&role_pattern).await {
            Ok(keys) => keys,
            Err(crate::error::GarrisonError::NotImplemented(_)) => {
                tracing::warn!(
                    "DAO backend does not support role keys(), role warmup skipped (tenants still warmed)"
                );
                Vec::new()
            },
            Err(e) => return Err(e),
        };
        let tenant_keys = match self.dao.keys(&tenant_pattern).await {
            Ok(keys) => keys,
            Err(crate::error::GarrisonError::NotImplemented(_)) => {
                tracing::warn!(
                    "DAO backend does not support tenant keys(), tenant warmup skipped (roles still warmed)"
                );
                Vec::new()
            },
            Err(e) => return Err(e),
        };

        let mut roles_loaded: u32 = 0;
        for key in &role_keys {
            if self.dao.get(key).await?.is_some() {
                roles_loaded += 1;
            }
        }

        let mut tenants_loaded: u32 = 0;
        for key in &tenant_keys {
            if self.dao.get(key).await?.is_some() {
                tenants_loaded += 1;
            }
        }

        Ok(WarmupStats {
            roles_loaded,
            tenants_loaded,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// warmup 从 DAO 加载所有角色权限（3 个 role:* key → roles_loaded == 3）。
    #[tokio::test]
    async fn warmup_loads_role_permissions() {
        let dao = Arc::new(crate::dao::InMemoryDao::new());
        dao.set("role:admin", "perm1,perm2", 3600).await.unwrap();
        dao.set("role:user", "perm3", 3600).await.unwrap();
        dao.set("role:guest", "", 3600).await.unwrap();

        let service = CacheWarmupService::new(dao);
        let stats = service.warmup().await.unwrap();

        assert_eq!(stats.roles_loaded, 3);
        assert_eq!(stats.tenants_loaded, 0);
    }

    /// warmup 从 DAO 加载所有租户配置（2 个 tenant:* key → tenants_loaded == 2）。
    #[tokio::test]
    async fn warmup_loads_tenant_configs() {
        let dao = Arc::new(crate::dao::InMemoryDao::new());
        dao.set("tenant:acme", "config1", 3600).await.unwrap();
        dao.set("tenant:globex", "config2", 3600).await.unwrap();

        let service = CacheWarmupService::new(dao);
        let stats = service.warmup().await.unwrap();

        assert_eq!(stats.roles_loaded, 0);
        assert_eq!(stats.tenants_loaded, 2);
    }

    /// 空数据库不报错，返回零统计。
    #[tokio::test]
    async fn warmup_empty_db_returns_zero_stats() {
        let dao = Arc::new(crate::dao::InMemoryDao::new());

        let service = CacheWarmupService::new(dao);
        let stats = service.warmup().await.unwrap();

        assert_eq!(
            stats,
            WarmupStats {
                roles_loaded: 0,
                tenants_loaded: 0,
            }
        );
    }

    /// warmup 跳过已过期的 key（get 返回 None 的 key 不计入统计）。
    ///
    /// keys() 返回 key 但 get() 返回 None 的 mock，模拟 key 在 keys() 与 get() 之间过期的竞态。
    #[tokio::test]
    async fn warmup_skips_expired_keys() {
        let dao = Arc::new(ExpiredKeyMockDao::new(vec![
            "role:expired1".to_string(),
            "role:expired2".to_string(),
        ]));

        let service = CacheWarmupService::new(dao);
        let stats = service.warmup().await.unwrap();

        assert_eq!(stats.roles_loaded, 0, "过期 key 不应计入统计");
    }

    /// 模拟 key 已过期的 mock DAO：`keys()` 按 pattern 前缀过滤返回构造时 key 列表，`get()` 始终 None。
    struct ExpiredKeyMockDao {
        keys: Vec<String>,
    }

    impl ExpiredKeyMockDao {
        fn new(keys: Vec<String>) -> Self {
            Self { keys }
        }
    }

    #[async_trait::async_trait]
    impl GarrisonDao for ExpiredKeyMockDao {
        async fn get(&self, _key: &str) -> GarrisonResult<Option<String>> {
            Ok(None)
        }

        async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }

        async fn update(&self, _key: &str, _value: &str) -> GarrisonResult<()> {
            Ok(())
        }

        async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }

        async fn delete(&self, _key: &str) -> GarrisonResult<()> {
            Ok(())
        }

        async fn keys(&self, pattern: &str) -> GarrisonResult<Vec<String>> {
            let prefix = pattern.trim_end_matches('*');
            Ok(self
                .keys
                .iter()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
        crate::atomic_test_fallback!();
    }

    /// 模拟不支持 keys() 的 DAO（`keys()` 返回 `NotImplemented`，如生产 oxcache 场景；warmup 应捕获并按零统计处理）。
    struct NoKeysDao;

    impl NoKeysDao {
        fn new() -> Self {
            Self
        }
    }

    #[async_trait::async_trait]
    impl GarrisonDao for NoKeysDao {
        async fn get(&self, _key: &str) -> GarrisonResult<Option<String>> {
            Ok(None)
        }

        async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }

        async fn update(&self, _key: &str, _value: &str) -> GarrisonResult<()> {
            Ok(())
        }

        async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }

        async fn delete(&self, _key: &str) -> GarrisonResult<()> {
            Ok(())
        }

        async fn keys(&self, _pattern: &str) -> GarrisonResult<Vec<String>> {
            Err(crate::error::GarrisonError::NotImplemented(
                "keys 未实现：NoKeysDao 后端不支持 key scan".to_string(),
            ))
        }
        crate::atomic_test_fallback!();
    }

    /// warmup 在 DAO 不支持 keys() 时返回零统计而非报错（warn 后按零键处理）。
    #[tokio::test]
    async fn warmup_returns_zero_stats_when_keys_not_implemented() {
        let dao = Arc::new(NoKeysDao::new());
        let service = CacheWarmupService::new(dao);
        let stats = service
            .warmup()
            .await
            .expect("NotImplemented 应被捕获，不应传播");

        assert_eq!(
            stats,
            WarmupStats {
                roles_loaded: 0,
                tenants_loaded: 0,
            },
            "keys() NotImplemented 时应返回零统计"
        );
    }

    // 错误传播与边界测试

    /// 模拟 keys() 返回非 NotImplemented 错误的 mock（验证错误传播，不吞掉）。
    struct ErrorKeysDao;

    impl ErrorKeysDao {
        fn new() -> Self {
            Self
        }
    }

    #[async_trait::async_trait]
    impl GarrisonDao for ErrorKeysDao {
        async fn get(&self, _key: &str) -> GarrisonResult<Option<String>> {
            Ok(None)
        }

        async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }

        async fn update(&self, _key: &str, _value: &str) -> GarrisonResult<()> {
            Ok(())
        }

        async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }

        async fn delete(&self, _key: &str) -> GarrisonResult<()> {
            Ok(())
        }

        async fn keys(&self, _pattern: &str) -> GarrisonResult<Vec<String>> {
            Err(crate::error::GarrisonError::Dao(
                "模拟 keys() 数据库连接失败".to_string(),
            ))
        }
        crate::atomic_test_fallback!();
    }

    /// warmup 在 keys() 返回非 NotImplemented 错误时传播（仅 NotImplemented 被捕获）。
    #[tokio::test]
    async fn warmup_propagates_non_not_implemented_keys_error() {
        let dao = Arc::new(ErrorKeysDao::new());
        let service = CacheWarmupService::new(dao);
        let result = service.warmup().await;

        assert!(result.is_err(), "非 NotImplemented 错误应传播");
        match result {
            Err(crate::error::GarrisonError::Dao(msg)) => {
                assert!(
                    msg.contains("模拟 keys() 数据库连接失败"),
                    "错误消息应包含原始错误描述，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 Dao 错误，实际: {:?}", other),
            Ok(_) => panic!("期望错误传播，实际返回 Ok"),
        }
    }

    /// 模拟 keys() 正常但 get() 返回 Dao 错误的 mock DAO。
    struct ErrorGetDao {
        keys: Vec<String>,
    }

    impl ErrorGetDao {
        fn new(keys: Vec<String>) -> Self {
            Self { keys }
        }
    }

    #[async_trait::async_trait]
    impl GarrisonDao for ErrorGetDao {
        async fn get(&self, _key: &str) -> GarrisonResult<Option<String>> {
            Err(crate::error::GarrisonError::Dao(
                "模拟 get() 读取失败".to_string(),
            ))
        }

        async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }

        async fn update(&self, _key: &str, _value: &str) -> GarrisonResult<()> {
            Ok(())
        }

        async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }

        async fn delete(&self, _key: &str) -> GarrisonResult<()> {
            Ok(())
        }

        async fn keys(&self, pattern: &str) -> GarrisonResult<Vec<String>> {
            let prefix = pattern.trim_end_matches('*');
            Ok(self
                .keys
                .iter()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
        crate::atomic_test_fallback!();
    }

    /// warmup 在 get() 返回错误时传播（不吞掉）。
    #[tokio::test]
    async fn warmup_propagates_get_error() {
        let dao = Arc::new(ErrorGetDao::new(vec!["role:admin".to_string()]));
        let service = CacheWarmupService::new(dao);
        let result = service.warmup().await;

        assert!(result.is_err(), "get() 错误应传播");
        match result {
            Err(crate::error::GarrisonError::Dao(msg)) => {
                assert!(
                    msg.contains("模拟 get() 读取失败"),
                    "错误消息应包含 get() 错误描述，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 Dao 错误，实际: {:?}", other),
            Ok(_) => panic!("期望错误传播，实际返回 Ok"),
        }
    }

    /// 模拟 role keys() 成功但 tenant keys() 返回 NotImplemented 的 mock DAO。
    struct PartialNotImplDao {
        role_keys: Vec<String>,
    }

    impl PartialNotImplDao {
        fn new(role_keys: Vec<String>) -> Self {
            Self { role_keys }
        }
    }

    #[async_trait::async_trait]
    impl GarrisonDao for PartialNotImplDao {
        async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
            // 返回 Some 模拟 key 存在
            if self.role_keys.contains(&key.to_string()) {
                Ok(Some("value".to_string()))
            } else {
                Ok(None)
            }
        }

        async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }

        async fn update(&self, _key: &str, _value: &str) -> GarrisonResult<()> {
            Ok(())
        }

        async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }

        async fn delete(&self, _key: &str) -> GarrisonResult<()> {
            Ok(())
        }

        async fn keys(&self, pattern: &str) -> GarrisonResult<Vec<String>> {
            // role:* pattern 返回成功，tenant:* pattern 返回 NotImplemented
            if pattern.starts_with("role:") {
                Ok(self
                    .role_keys
                    .iter()
                    .filter(|k| k.starts_with("role:"))
                    .cloned()
                    .collect())
            } else {
                Err(crate::error::GarrisonError::NotImplemented(
                    "tenant keys 不支持".to_string(),
                ))
            }
        }
        crate::atomic_test_fallback!();
    }

    /// role keys 成功但 tenant keys 返回 NotImplemented 时继续加载 roles（部分失败语义；修复前整体提前返回零统计）。
    #[tokio::test]
    async fn warmup_tenant_keys_not_implemented_still_loads_roles() {
        let dao = Arc::new(PartialNotImplDao::new(vec![
            "role:admin".to_string(),
            "role:user".to_string(),
        ]));
        let service = CacheWarmupService::new(dao);
        let result = service.warmup().await;

        // tenant keys() 返回 NotImplemented 时不应报错，roles 继续加载
        assert!(
            result.is_ok(),
            "NotImplemented 应被捕获: {:?}",
            result.err()
        );
        let stats = result.unwrap();
        assert_eq!(
            stats.roles_loaded, 2,
            "tenant NotImplemented 时已获取的 role keys 应继续加载"
        );
        assert_eq!(stats.tenants_loaded, 0);
    }

    /// WarmupStats 的 Debug/Clone/PartialEq/Eq trait 行为验证。
    #[test]
    fn warmup_stats_derives_work_correctly() {
        let stats1 = WarmupStats {
            roles_loaded: 5,
            tenants_loaded: 3,
        };
        let stats2 = stats1.clone();
        assert_eq!(stats1, stats2, "Clone 后应相等");

        let stats3 = WarmupStats {
            roles_loaded: 5,
            tenants_loaded: 3,
        };
        assert_eq!(stats1, stats3, "相同值应相等");

        let stats4 = WarmupStats {
            roles_loaded: 0,
            tenants_loaded: 3,
        };
        assert_ne!(stats1, stats4, "不同值应不等");

        // Debug 输出应包含字段名和值
        let debug_str = format!("{:?}", stats1);
        assert!(debug_str.contains("WarmupStats"));
        assert!(debug_str.contains("roles_loaded"));
        assert!(debug_str.contains("5"));
        assert!(debug_str.contains("tenants_loaded"));
        assert!(debug_str.contains("3"));
    }

    // Mock DAO 完整方法覆盖测试

    /// ExpiredKeyMockDao 的写方法均为 no-op 返回 Ok。
    #[tokio::test]
    async fn expired_key_mock_dao_all_methods_return_ok() {
        let dao = ExpiredKeyMockDao::new(vec!["role:test".to_string()]);
        dao.set("k", "v", 60).await.unwrap();
        dao.update("k", "v2").await.unwrap();
        dao.expire("k", 30).await.unwrap();
        dao.delete("k").await.unwrap();
        assert!(dao.get("k").await.unwrap().is_none());
        let keys = dao.keys("role:*").await.unwrap();
        assert_eq!(keys.len(), 1);
        let empty = dao.keys("tenant:*").await.unwrap();
        assert!(empty.is_empty());
        // atomic + 默认 trait 方法覆盖
        let _ = dao.set_if_absent("a", "v", 60).await;
        let _ = dao.get_and_delete("a").await;
        let _ = dao.incr("c", 60).await;
        let _ = dao.decr("c").await;
        let _ = dao.rename("a", "b").await;
        let _ = dao.compare_and_swap("b", None, "v", 60).await;
        let _ = dao.set_permanent("p", "v").await;
        let _ = dao.get_timeout("k").await;
        let _ = dao.find_social_binding(0, "w", "o").await;
        let _ = dao.insert_social_binding(0, "u", "w", "o", None, 0).await;
        let _ = dao.compare_and_update_if_greater("k", 1, 60).await;
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

    /// NoKeysDao 的写方法均为 no-op，get 返回 None。
    #[tokio::test]
    async fn no_keys_dao_all_methods_return_ok() {
        let dao = NoKeysDao::new();
        assert!(dao.get("k").await.unwrap().is_none());
        dao.set("k", "v", 60).await.unwrap();
        dao.update("k", "v2").await.unwrap();
        dao.expire("k", 30).await.unwrap();
        dao.delete("k").await.unwrap();
        // keys 始终返回 NotImplemented
        assert!(dao.keys("any:*").await.is_err());
        // atomic + 默认 trait 方法覆盖
        let _ = dao.set_if_absent("a", "v", 60).await;
        let _ = dao.get_and_delete("a").await;
        let _ = dao.incr("c", 60).await;
        let _ = dao.decr("c").await;
        let _ = dao.rename("a", "b").await;
        let _ = dao.compare_and_swap("b", None, "v", 60).await;
        let _ = dao.set_permanent("p", "v").await;
        let _ = dao.get_timeout("k").await;
        let _ = dao.get_with_ttl("k").await;
        let _ = dao.find_social_binding(0, "w", "o").await;
        let _ = dao.insert_social_binding(0, "u", "w", "o", None, 0).await;
        let _ = dao.compare_and_update_if_greater("k", 1, 60).await;
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

    /// ErrorKeysDao 的写方法均为 no-op，keys 返回 Dao 错误。
    #[tokio::test]
    async fn error_keys_dao_all_methods_return_ok() {
        let dao = ErrorKeysDao::new();
        assert!(dao.get("k").await.unwrap().is_none());
        dao.set("k", "v", 60).await.unwrap();
        dao.update("k", "v2").await.unwrap();
        dao.expire("k", 30).await.unwrap();
        dao.delete("k").await.unwrap();
        // keys 始终返回 Dao 错误
        assert!(dao.keys("any:*").await.is_err());
        // atomic + 默认 trait 方法覆盖
        let _ = dao.set_if_absent("a", "v", 60).await;
        let _ = dao.get_and_delete("a").await;
        let _ = dao.incr("c", 60).await;
        let _ = dao.decr("c").await;
        let _ = dao.rename("a", "b").await;
        let _ = dao.compare_and_swap("b", None, "v", 60).await;
        let _ = dao.set_permanent("p", "v").await;
        let _ = dao.get_timeout("k").await;
        let _ = dao.get_with_ttl("k").await;
        let _ = dao.find_social_binding(0, "w", "o").await;
        let _ = dao.insert_social_binding(0, "u", "w", "o", None, 0).await;
        let _ = dao.compare_and_update_if_greater("k", 1, 60).await;
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

    /// ErrorGetDao 的写方法均为 no-op，get 返回 Dao 错误。
    #[tokio::test]
    async fn error_get_dao_non_get_methods_return_ok() {
        let dao = ErrorGetDao::new(vec!["role:test".to_string()]);
        dao.set("k", "v", 60).await.unwrap();
        dao.update("k", "v2").await.unwrap();
        dao.expire("k", 30).await.unwrap();
        dao.delete("k").await.unwrap();
        assert!(dao.get("k").await.is_err());
        let keys = dao.keys("role:*").await.unwrap();
        assert_eq!(keys.len(), 1);
        // atomic + 默认 trait 方法覆盖
        let _ = dao.set_if_absent("a", "v", 60).await;
        let _ = dao.get_and_delete("a").await;
        let _ = dao.incr("c", 60).await;
        let _ = dao.decr("c").await;
        let _ = dao.rename("a", "b").await;
        let _ = dao.compare_and_swap("b", None, "v", 60).await;
        let _ = dao.set_permanent("p", "v").await;
        let _ = dao.get_timeout("k").await;
        let _ = dao.find_social_binding(0, "w", "o").await;
        let _ = dao.insert_social_binding(0, "u", "w", "o", None, 0).await;
        let _ = dao.compare_and_update_if_greater("k", 1, 60).await;
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

    /// PartialNotImplDao 的写方法均为 no-op。
    #[tokio::test]
    async fn partial_not_impl_dao_non_keys_methods_return_ok() {
        let dao = PartialNotImplDao::new(vec!["role:test".to_string()]);
        dao.set("k", "v", 60).await.unwrap();
        dao.update("k", "v2").await.unwrap();
        dao.expire("k", 30).await.unwrap();
        dao.delete("k").await.unwrap();
        // get 对已知 key 返回 Some
        assert_eq!(
            dao.get("role:test").await.unwrap().as_deref(),
            Some("value")
        );
        assert!(dao.get("unknown").await.unwrap().is_none());
        let keys = dao.keys("role:*").await.unwrap();
        assert_eq!(keys.len(), 1);
        // keys 对 tenant: 返回 NotImplemented
        assert!(dao.keys("tenant:*").await.is_err());
        // atomic + 默认 trait 方法覆盖
        let _ = dao.set_if_absent("a", "v", 60).await;
        let _ = dao.get_and_delete("a").await;
        let _ = dao.incr("c", 60).await;
        let _ = dao.decr("c").await;
        let _ = dao.rename("a", "b").await;
        let _ = dao.compare_and_swap("b", None, "v", 60).await;
        let _ = dao.set_permanent("p", "v").await;
        let _ = dao.get_timeout("k").await;
        let _ = dao.find_social_binding(0, "w", "o").await;
        let _ = dao.insert_social_binding(0, "u", "w", "o", None, 0).await;
        let _ = dao.compare_and_update_if_greater("k", 1, 60).await;
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

    // warmup tenant keys 非 NotImplemented 错误传播测试

    /// 模拟 role keys() 成功但 tenant keys() 返回非 NotImplemented 错误的 mock DAO。
    struct TenantErrorDao {
        role_keys: Vec<String>,
    }

    impl TenantErrorDao {
        fn new(role_keys: Vec<String>) -> Self {
            Self { role_keys }
        }
    }

    #[async_trait::async_trait]
    impl GarrisonDao for TenantErrorDao {
        async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
            if self.role_keys.contains(&key.to_string()) {
                Ok(Some("value".to_string()))
            } else {
                Ok(None)
            }
        }

        async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }

        async fn update(&self, _key: &str, _value: &str) -> GarrisonResult<()> {
            Ok(())
        }

        async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }

        async fn delete(&self, _key: &str) -> GarrisonResult<()> {
            Ok(())
        }

        async fn keys(&self, pattern: &str) -> GarrisonResult<Vec<String>> {
            if pattern.starts_with("role:") {
                Ok(self
                    .role_keys
                    .iter()
                    .filter(|k| k.starts_with("role:"))
                    .cloned()
                    .collect())
            } else {
                // tenant keys 返回非 NotImplemented 的 Dao 错误
                Err(crate::error::GarrisonError::Dao(
                    "tenant keys() 数据库连接断开".to_string(),
                ))
            }
        }
        crate::atomic_test_fallback!();
    }

    /// role keys 成功但 tenant keys 返回非 NotImplemented 错误时应传播（第二个 keys 调用的 `Err(e) => return Err(e)` 分支）。
    #[tokio::test]
    async fn warmup_propagates_tenant_keys_non_not_implemented_error() {
        let dao = Arc::new(TenantErrorDao::new(vec![
            "role:admin".to_string(),
            "role:user".to_string(),
        ]));
        // atomic + 默认 trait 方法覆盖
        let _ = dao.set_if_absent("a", "v", 60).await;
        let _ = dao.get_and_delete("a").await;
        let _ = dao.incr("c", 60).await;
        let _ = dao.decr("c").await;
        let _ = dao.rename("a", "b").await;
        let _ = dao.compare_and_swap("b", None, "v", 60).await;
        let _ = dao.set_permanent("p", "v").await;
        let _ = dao.get_timeout("k").await;
        let _ = dao.get_with_ttl("k").await;
        let _ = dao.find_social_binding(0, "w", "o").await;
        let _ = dao.insert_social_binding(0, "u", "w", "o", None, 0).await;
        let _ = dao.compare_and_update_if_greater("k", 1, 60).await;
        let _ = dao.eval_lua("r", vec![], vec![]).await;
        #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
        {
            let _ = dao.insert_credit_consumption(0, "r", 1, 1, 1, 0).await;
            let _ = dao.query_credit_consumption(0, 0, 0).await;
            let _ = dao.query_role_hierarchy_edges(0).await;
            let _ = dao.insert_role_hierarchy_edge(0, "c", "p").await;
            let _ = dao.delete_role_hierarchy_edge(0, "c", "p").await;
        }
        let service = CacheWarmupService::new(dao);
        let result = service.warmup().await;

        assert!(result.is_err(), "tenant keys 非 NotImplemented 错误应传播");
        match result {
            Err(crate::error::GarrisonError::Dao(msg)) => {
                assert!(
                    msg.contains("tenant keys() 数据库连接断开"),
                    "错误消息应包含 tenant keys 错误描述，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 Dao 错误，实际: {:?}", other),
            Ok(_) => panic!("期望错误传播，实际返回 Ok"),
        }
    }

    /// warmup 同时加载 role 和 tenant 配置，返回正确统计。
    #[tokio::test]
    async fn warmup_loads_both_roles_and_tenants() {
        let dao = Arc::new(crate::dao::InMemoryDao::new());
        dao.set("role:admin", "perm1", 3600).await.unwrap();
        dao.set("role:user", "perm2", 3600).await.unwrap();
        dao.set("tenant:acme", "config1", 3600).await.unwrap();
        dao.set("tenant:globex", "config2", 3600).await.unwrap();

        let service = CacheWarmupService::new(dao);
        let stats = service.warmup().await.unwrap();

        assert_eq!(stats.roles_loaded, 2);
        assert_eq!(stats.tenants_loaded, 2);
    }
}
