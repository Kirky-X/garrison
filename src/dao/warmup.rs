//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 缓存预热子模块。
//!
//! 提供 [`CacheWarmupService`] 在启动时从 DAO 加载角色权限与租户配置到缓存，
//! 减少冷启动延迟。

use crate::constants::DaoKeyPrefix;
use crate::error::BulwarkResult;
use std::sync::Arc;

use crate::dao::BulwarkDao;

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
    dao: Arc<dyn BulwarkDao>,
}

impl CacheWarmupService {
    /// 创建预热服务实例。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self { dao }
    }

    /// 执行缓存预热。
    ///
    /// 扫描 DAO 中所有 `role:*` 和 `tenant:*` 键，逐个 `get()` 触发缓存填充，
    /// 返回加载统计。空数据库返回零统计，不报错。
    ///
    /// 当 DAO 后端不支持 `keys()`（返回 `NotImplemented`，如生产环境
    /// `BulwarkDaoOxcache`）时，记录 `warn` 日志并返回零统计，不传播错误。
    pub async fn warmup(&self) -> BulwarkResult<WarmupStats> {
        let role_pattern = format!("{}*", DaoKeyPrefix::Role.as_str());
        let tenant_pattern = format!("{}*", DaoKeyPrefix::Tenant.as_str());

        let role_keys = match self.dao.keys(&role_pattern).await {
            Ok(keys) => keys,
            Err(crate::error::BulwarkError::NotImplemented(_)) => {
                tracing::warn!("DAO 后端不支持 keys()，缓存预热跳过");
                return Ok(WarmupStats {
                    roles_loaded: 0,
                    tenants_loaded: 0,
                });
            },
            Err(e) => return Err(e),
        };
        let tenant_keys = match self.dao.keys(&tenant_pattern).await {
            Ok(keys) => keys,
            Err(crate::error::BulwarkError::NotImplemented(_)) => {
                tracing::warn!("DAO 后端不支持 keys()，缓存预热跳过");
                return Ok(WarmupStats {
                    roles_loaded: 0,
                    tenants_loaded: 0,
                });
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

    /// R-warmup-001: warmup 从 DAO 加载所有角色的权限列表。
    ///
    /// 插入 3 个 role:* key，warmup 后 roles_loaded == 3。
    #[tokio::test]
    async fn warmup_loads_role_permissions() {
        let dao = Arc::new(crate::dao::tests::MockDao::new());
        dao.set("role:admin", "perm1,perm2", 3600).await.unwrap();
        dao.set("role:user", "perm3", 3600).await.unwrap();
        dao.set("role:guest", "", 3600).await.unwrap();

        let service = CacheWarmupService::new(dao);
        let stats = service.warmup().await.unwrap();

        assert_eq!(stats.roles_loaded, 3);
        assert_eq!(stats.tenants_loaded, 0);
    }

    /// R-warmup-002: warmup 从 DAO 加载所有租户配置。
    ///
    /// 插入 2 个 tenant:* key，warmup 后 tenants_loaded == 2。
    #[tokio::test]
    async fn warmup_loads_tenant_configs() {
        let dao = Arc::new(crate::dao::tests::MockDao::new());
        dao.set("tenant:acme", "config1", 3600).await.unwrap();
        dao.set("tenant:globex", "config2", 3600).await.unwrap();

        let service = CacheWarmupService::new(dao);
        let stats = service.warmup().await.unwrap();

        assert_eq!(stats.roles_loaded, 0);
        assert_eq!(stats.tenants_loaded, 2);
    }

    /// R-warmup-003: 空数据库不报错，返回零统计。
    #[tokio::test]
    async fn warmup_empty_db_returns_zero_stats() {
        let dao = Arc::new(crate::dao::tests::MockDao::new());

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
    /// 使用自定义 mock，keys() 返回 key 但 get() 返回 None，
    /// 模拟 key 在 keys() 与 get() 之间过期的竞态。
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

    /// 模拟 key 已过期的 mock DAO。
    ///
    /// `keys()` 返回构造时传入的 key 列表（按 pattern 前缀过滤），
    /// `get()` 始终返回 None，模拟 key 在 keys() 扫描后、get() 读取前过期。
    struct ExpiredKeyMockDao {
        keys: Vec<String>,
    }

    impl ExpiredKeyMockDao {
        fn new(keys: Vec<String>) -> Self {
            Self { keys }
        }
    }

    #[async_trait::async_trait]
    impl BulwarkDao for ExpiredKeyMockDao {
        async fn get(&self, _key: &str) -> BulwarkResult<Option<String>> {
            Ok(None)
        }

        async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> BulwarkResult<()> {
            Ok(())
        }

        async fn update(&self, _key: &str, _value: &str) -> BulwarkResult<()> {
            Ok(())
        }

        async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
            Ok(())
        }

        async fn delete(&self, _key: &str) -> BulwarkResult<()> {
            Ok(())
        }

        async fn keys(&self, pattern: &str) -> BulwarkResult<Vec<String>> {
            let prefix = pattern.trim_end_matches('*');
            Ok(self
                .keys
                .iter()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    /// 模拟不支持 keys() 的 DAO（如生产环境 BulwarkDaoOxcache）。
    ///
    /// `keys()` 返回 `NotImplemented`，模拟 oxcache 后端无法扫描 key 的场景。
    /// warmup 应捕获此错误并返回零统计，而非传播错误。
    struct NoKeysDao;

    impl NoKeysDao {
        fn new() -> Self {
            Self
        }
    }

    #[async_trait::async_trait]
    impl BulwarkDao for NoKeysDao {
        async fn get(&self, _key: &str) -> BulwarkResult<Option<String>> {
            Ok(None)
        }

        async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> BulwarkResult<()> {
            Ok(())
        }

        async fn update(&self, _key: &str, _value: &str) -> BulwarkResult<()> {
            Ok(())
        }

        async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
            Ok(())
        }

        async fn delete(&self, _key: &str) -> BulwarkResult<()> {
            Ok(())
        }

        async fn keys(&self, _pattern: &str) -> BulwarkResult<Vec<String>> {
            Err(crate::error::BulwarkError::NotImplemented(
                "keys 未实现：NoKeysDao 后端不支持 key scan".to_string(),
            ))
        }
    }

    /// warmup 在 DAO 不支持 keys() 时应返回零统计而非报错。
    ///
    /// 模拟生产环境 BulwarkDaoOxcache（keys 返回 NotImplemented），
    /// warmup 应 warn 并返回 Ok(WarmupStats { 0, 0 })。
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

    // ========================================================================
    // 错误传播与边界测试
    // ========================================================================

    /// 模拟 keys() 返回非 NotImplemented 错误的 mock DAO。
    ///
    /// 用于测试 warmup 在 keys() 返回 Dao 错误时正确传播错误（不吞掉）。
    struct ErrorKeysDao;

    impl ErrorKeysDao {
        fn new() -> Self {
            Self
        }
    }

    #[async_trait::async_trait]
    impl BulwarkDao for ErrorKeysDao {
        async fn get(&self, _key: &str) -> BulwarkResult<Option<String>> {
            Ok(None)
        }

        async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> BulwarkResult<()> {
            Ok(())
        }

        async fn update(&self, _key: &str, _value: &str) -> BulwarkResult<()> {
            Ok(())
        }

        async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
            Ok(())
        }

        async fn delete(&self, _key: &str) -> BulwarkResult<()> {
            Ok(())
        }

        async fn keys(&self, _pattern: &str) -> BulwarkResult<Vec<String>> {
            Err(crate::error::BulwarkError::Dao(
                "模拟 keys() 数据库连接失败".to_string(),
            ))
        }
    }

    /// warmup 在 keys() 返回非 NotImplemented 错误时应传播错误。
    ///
    /// 验证只有 NotImplemented 被捕获，其他 DAO 错误必须传播给调用方。
    #[tokio::test]
    async fn warmup_propagates_non_not_implemented_keys_error() {
        let dao = Arc::new(ErrorKeysDao::new());
        let service = CacheWarmupService::new(dao);
        let result = service.warmup().await;

        assert!(result.is_err(), "非 NotImplemented 错误应传播");
        match result {
            Err(crate::error::BulwarkError::Dao(msg)) => {
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

    /// 模拟 get() 返回错误的 mock DAO。
    ///
    /// keys() 正常返回 key 列表，但 get() 返回 Dao 错误，
    /// 用于测试 warmup 在遍历 key 时 get() 失败的错误传播。
    struct ErrorGetDao {
        keys: Vec<String>,
    }

    impl ErrorGetDao {
        fn new(keys: Vec<String>) -> Self {
            Self { keys }
        }
    }

    #[async_trait::async_trait]
    impl BulwarkDao for ErrorGetDao {
        async fn get(&self, _key: &str) -> BulwarkResult<Option<String>> {
            Err(crate::error::BulwarkError::Dao(
                "模拟 get() 读取失败".to_string(),
            ))
        }

        async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> BulwarkResult<()> {
            Ok(())
        }

        async fn update(&self, _key: &str, _value: &str) -> BulwarkResult<()> {
            Ok(())
        }

        async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
            Ok(())
        }

        async fn delete(&self, _key: &str) -> BulwarkResult<()> {
            Ok(())
        }

        async fn keys(&self, pattern: &str) -> BulwarkResult<Vec<String>> {
            let prefix = pattern.trim_end_matches('*');
            Ok(self
                .keys
                .iter()
                .filter(|k| k.starts_with(prefix))
                .cloned()
                .collect())
        }
    }

    /// warmup 在 get() 返回错误时应传播错误。
    ///
    /// keys() 成功返回 role key，但 get() 返回 Dao 错误，
    /// warmup 应传播该错误而非吞掉。
    #[tokio::test]
    async fn warmup_propagates_get_error() {
        let dao = Arc::new(ErrorGetDao::new(vec!["role:admin".to_string()]));
        let service = CacheWarmupService::new(dao);
        let result = service.warmup().await;

        assert!(result.is_err(), "get() 错误应传播");
        match result {
            Err(crate::error::BulwarkError::Dao(msg)) => {
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
    ///
    /// 用于测试 warmup 中 tenant keys() 的 NotImplemented 分支（role keys 成功后）。
    struct PartialNotImplDao {
        role_keys: Vec<String>,
    }

    impl PartialNotImplDao {
        fn new(role_keys: Vec<String>) -> Self {
            Self { role_keys }
        }
    }

    #[async_trait::async_trait]
    impl BulwarkDao for PartialNotImplDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            // 返回 Some 模拟 key 存在
            if self.role_keys.contains(&key.to_string()) {
                Ok(Some("value".to_string()))
            } else {
                Ok(None)
            }
        }

        async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> BulwarkResult<()> {
            Ok(())
        }

        async fn update(&self, _key: &str, _value: &str) -> BulwarkResult<()> {
            Ok(())
        }

        async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
            Ok(())
        }

        async fn delete(&self, _key: &str) -> BulwarkResult<()> {
            Ok(())
        }

        async fn keys(&self, pattern: &str) -> BulwarkResult<Vec<String>> {
            // role:* pattern 返回成功，tenant:* pattern 返回 NotImplemented
            if pattern.starts_with("role:") {
                Ok(self
                    .role_keys
                    .iter()
                    .filter(|k| k.starts_with("role:"))
                    .cloned()
                    .collect())
            } else {
                Err(crate::error::BulwarkError::NotImplemented(
                    "tenant keys 不支持".to_string(),
                ))
            }
        }
    }

    /// warmup 在 role keys 成功但 tenant keys 返回 NotImplemented 时应返回零统计。
    ///
    /// 验证 tenant keys() 的 NotImplemented 分支被正确捕获（role keys 成功后的第二个 keys 调用）。
    #[tokio::test]
    async fn warmup_tenant_keys_not_implemented_returns_zero() {
        let dao = Arc::new(PartialNotImplDao::new(vec![
            "role:admin".to_string(),
            "role:user".to_string(),
        ]));
        let service = CacheWarmupService::new(dao);
        let result = service.warmup().await;

        // tenant keys() 返回 NotImplemented 时，整个 warmup 返回零统计
        assert!(
            result.is_ok(),
            "NotImplemented 应被捕获: {:?}",
            result.err()
        );
        let stats = result.unwrap();
        assert_eq!(
            stats.roles_loaded, 0,
            "tenant NotImplemented 时 roles 也应为 0"
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

    // ========================================================================
    // Mock DAO 完整方法覆盖测试
    // ========================================================================

    /// ExpiredKeyMockDao 的 set/update/expire/delete 方法均返回 Ok(())。
    #[tokio::test]
    async fn expired_key_mock_dao_all_methods_return_ok() {
        let dao = ExpiredKeyMockDao::new(vec!["role:test".to_string()]);
        dao.set("k", "v", 60).await.unwrap();
        dao.update("k", "v2").await.unwrap();
        dao.expire("k", 30).await.unwrap();
        dao.delete("k").await.unwrap();
        // get 始终返回 None
        assert!(dao.get("k").await.unwrap().is_none());
        // keys 按 pattern 过滤
        let keys = dao.keys("role:*").await.unwrap();
        assert_eq!(keys.len(), 1);
        let empty = dao.keys("tenant:*").await.unwrap();
        assert!(empty.is_empty());
    }

    /// NoKeysDao 的 get/set/update/expire/delete 方法均返回 Ok(()), get 返回 None。
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
    }

    /// ErrorKeysDao 的 get/set/update/expire/delete 方法均返回 Ok(()), keys 返回 Dao 错误。
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
    }

    /// ErrorGetDao 的 set/update/expire/delete 方法返回 Ok(()), get 返回 Dao 错误。
    #[tokio::test]
    async fn error_get_dao_non_get_methods_return_ok() {
        let dao = ErrorGetDao::new(vec!["role:test".to_string()]);
        dao.set("k", "v", 60).await.unwrap();
        dao.update("k", "v2").await.unwrap();
        dao.expire("k", 30).await.unwrap();
        dao.delete("k").await.unwrap();
        // get 返回错误
        assert!(dao.get("k").await.is_err());
        // keys 按 pattern 过滤
        let keys = dao.keys("role:*").await.unwrap();
        assert_eq!(keys.len(), 1);
    }

    /// PartialNotImplDao 的 set/update/expire/delete 方法返回 Ok(())。
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
        // get 对未知 key 返回 None
        assert!(dao.get("unknown").await.unwrap().is_none());
        // keys 对 role: 返回成功
        let keys = dao.keys("role:*").await.unwrap();
        assert_eq!(keys.len(), 1);
        // keys 对 tenant: 返回 NotImplemented
        assert!(dao.keys("tenant:*").await.is_err());
    }

    // ========================================================================
    // warmup tenant keys 非 NotImplemented 错误传播测试（覆盖 line 69）
    // ========================================================================

    /// 模拟 role keys() 成功但 tenant keys() 返回非 NotImplemented 错误的 mock DAO。
    ///
    /// 用于测试 warmup 中 tenant keys() 的非 NotImplemented 错误传播（line 69）。
    struct TenantErrorDao {
        role_keys: Vec<String>,
    }

    impl TenantErrorDao {
        fn new(role_keys: Vec<String>) -> Self {
            Self { role_keys }
        }
    }

    #[async_trait::async_trait]
    impl BulwarkDao for TenantErrorDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            if self.role_keys.contains(&key.to_string()) {
                Ok(Some("value".to_string()))
            } else {
                Ok(None)
            }
        }

        async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> BulwarkResult<()> {
            Ok(())
        }

        async fn update(&self, _key: &str, _value: &str) -> BulwarkResult<()> {
            Ok(())
        }

        async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
            Ok(())
        }

        async fn delete(&self, _key: &str) -> BulwarkResult<()> {
            Ok(())
        }

        async fn keys(&self, pattern: &str) -> BulwarkResult<Vec<String>> {
            if pattern.starts_with("role:") {
                Ok(self
                    .role_keys
                    .iter()
                    .filter(|k| k.starts_with("role:"))
                    .cloned()
                    .collect())
            } else {
                // tenant keys 返回非 NotImplemented 的 Dao 错误
                Err(crate::error::BulwarkError::Dao(
                    "tenant keys() 数据库连接断开".to_string(),
                ))
            }
        }
    }

    /// warmup 在 role keys 成功但 tenant keys 返回非 NotImplemented 错误时应传播错误。
    ///
    /// 覆盖 warmup.rs line 69: `Err(e) => return Err(e)` 分支
    /// （role keys 成功后的第二个 keys 调用返回非 NotImplemented 错误）。
    #[tokio::test]
    async fn warmup_propagates_tenant_keys_non_not_implemented_error() {
        let dao = Arc::new(TenantErrorDao::new(vec![
            "role:admin".to_string(),
            "role:user".to_string(),
        ]));
        let service = CacheWarmupService::new(dao);
        let result = service.warmup().await;

        assert!(result.is_err(), "tenant keys 非 NotImplemented 错误应传播");
        match result {
            Err(crate::error::BulwarkError::Dao(msg)) => {
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
        let dao = Arc::new(crate::dao::tests::MockDao::new());
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
