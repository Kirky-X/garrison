//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
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
    pub async fn warmup(&self) -> BulwarkResult<WarmupStats> {
        let role_pattern = format!("{}*", DaoKeyPrefix::Role.as_str());
        let tenant_pattern = format!("{}*", DaoKeyPrefix::Tenant.as_str());

        let role_keys = self.dao.keys(&role_pattern).await?;
        let tenant_keys = self.dao.keys(&tenant_pattern).await?;

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
}
