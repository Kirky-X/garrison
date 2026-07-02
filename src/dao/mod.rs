//! DAO 模块，定义持久化数据访问抽象层。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `SaTokenDao`，
//! 通过 oxcache / dbnexus 提供多后端（缓存 / 关系型数据库）支持。

use crate::error::BulwarkResult;
use async_trait::async_trait;

/// DAO 抽象层 trait，定义 Token 与会话的持久化操作。
///
/// [借鉴 Sa-Token] 对应 `SaTokenDao`，提供 get / set / update / delete / expire 五元操作。
///
/// - `set` 必须指定 TTL（Token/Session 不应永久驻留，与 Sa-Token 语义一致）
/// - `update` 更新值时保留原有 TTL（不重置过期时间）
/// - `expire` 重置键的过期时间
#[async_trait]
pub trait BulwarkDao: Send + Sync {
    /// 获取指定键的值。
    ///
    /// # 参数
    /// - `key`: 存储键。
    ///
    /// # 返回
    /// - `Some(value)`: 键存在且未过期。
    /// - `None`: 键不存在或已过期。
    async fn get(&self, key: &str) -> BulwarkResult<Option<String>>;

    /// 设置键值对，附带 TTL。
    ///
    /// # 参数
    /// - `key`: 存储键。
    /// - `value`: 存储值。
    /// - `ttl_seconds`: 过期秒数（0 表示永久驻留；可被 `expire` 重置）。
    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()>;

    /// 更新键的值，保留原有 TTL（不重置过期时间）。
    ///
    /// # 参数
    /// - `key`: 存储键（必须已存在）。
    /// - `value`: 新值。
    ///
    /// # 错误
    /// - 若键不存在，返回 `BulwarkError::Dao`。
    async fn update(&self, key: &str, value: &str) -> BulwarkResult<()>;

    /// 设置（或重置）键的过期时间。
    ///
    /// # 参数
    /// - `key`: 存储键。
    /// - `seconds`: 过期秒数（0 表示永久驻留）。
    ///
    /// # 错误
    /// - 若键不存在，返回 `BulwarkError::Dao`。
    async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()>;

    /// 删除指定键。
    ///
    /// # 参数
    /// - `key`: 存储键。
    async fn delete(&self, key: &str) -> BulwarkResult<()>;
}

// ============================================================================
// oxcache 实现（feature = "cache-memory" 或 "cache-redis"）
// ============================================================================

#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
mod oxcache_impl {
    use super::BulwarkDao;
    use crate::error::{BulwarkError, BulwarkResult};
    use async_trait::async_trait;
    use oxcache::Cache;
    use std::time::Duration;

    /// oxcache 0.3 默认实现，包装 `oxcache::Cache<String, String>`。
    ///
    /// - L1（moka）+ L2（redis）由 oxcache 0.3 自动管理（0.3 起 moka 后端支持 per-entry TTL）。
    /// - Bulwark 自身不实现任何缓存逻辑，全部委托给 oxcache。
    /// - 启用 `sync_mode(true)` 后使用 `_sync` API（依据 codebase-hardening Task 2），
    ///   要求调用方在 multi_thread tokio runtime 中执行。
    ///
    /// # TTL 保留
    /// - `update` 通过 `cache.ttl_sync()` 读取剩余 TTL，用 `set_with_ttl_sync` 保留原 TTL（不重置过期时间）
    /// - `expire` 通过 `cache.expire_sync()` 原子更新 TTL（不触碰 value）
    /// - 依赖本地 oxcache 仓库（crates.io 0.3.0 未暴露 `Cache<K,V>::ttl_sync()`，本地仓库已暴露）
    pub struct BulwarkDaoOxcache {
        cache: Cache<String, String>,
    }

    impl BulwarkDaoOxcache {
        /// 创建默认的 oxcache DAO 实例。
        ///
        /// 启用 `sync_mode(true)` 以支持 `_sync` API（依据 codebase-hardening Task 2.1）。
        ///
        /// # 返回
        /// 已初始化的 `BulwarkDaoOxcache` 实例（内部 `oxcache::Cache` 已就绪，sync_mode 启用）。
        ///
        /// # 错误
        /// - `BulwarkError::Dao`：oxcache 初始化失败（消息含 "oxcache 初始化失败"）。
        pub async fn new() -> BulwarkResult<Self> {
            let cache = Cache::builder()
                .sync_mode(true)
                .build()
                .await
                .map_err(|e| BulwarkError::Dao(format!("oxcache 初始化失败: {}", e)))?;
            Ok(Self { cache })
        }
    }

    #[async_trait]
    impl BulwarkDao for BulwarkDaoOxcache {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            self.cache
                .get_sync(&key.to_string())
                .map_err(|e| BulwarkError::Dao(format!("oxcache get_sync 失败: {}", e)))
        }

        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
            let ttl = if ttl_seconds == 0 {
                None
            } else {
                Some(Duration::from_secs(ttl_seconds))
            };
            self.cache
                .set_with_ttl_sync(&key.to_string(), &value.to_string(), ttl)
                .map_err(|e| BulwarkError::Dao(format!("oxcache set_with_ttl_sync 失败: {}", e)))
        }

        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            // 通过 cache.ttl_sync() 读取剩余 TTL，用 set_with_ttl_sync 保留原 TTL（不重置过期时间）。
            // ttl_sync() 返回 None 表示永久驻留（set_with_ttl_sync 接受 None 表示无 TTL）。
            // 但 None 也可能表示键不存在，需要先检查键存在性。
            if !self
                .cache
                .exists_sync(&key.to_string())
                .map_err(|e| BulwarkError::Dao(format!("oxcache exists_sync 失败: {}", e)))?
            {
                return Err(BulwarkError::Dao(format!("键不存在: {}", key)));
            }
            let remaining_ttl = self
                .cache
                .ttl_sync(&key.to_string())
                .map_err(|e| BulwarkError::Dao(format!("oxcache ttl_sync 失败: {}", e)))?;
            self.cache
                .set_with_ttl_sync(&key.to_string(), &value.to_string(), remaining_ttl)
                .map_err(|e| {
                    BulwarkError::Dao(format!("oxcache update (set_with_ttl_sync) 失败: {}", e))
                })
        }

        async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
            // oxcache 0.3 的 Cache<K,V> 暴露了 expire_sync(key, ttl) 方法（原子更新 TTL，不触碰 value）。
            // expire_sync 返回 bool：true=更新成功，false=键不存在。
            // 注意：seconds=0 表示永久驻留，需要用 get_sync + set_with_ttl_sync(None) 实现
            // （cache.expire_sync(key, Duration::from_secs(0)) 会让键立即过期，不符合 spec 的 0=永久语义）。
            if seconds == 0 {
                let value = self
                    .cache
                    .get_sync(&key.to_string())
                    .map_err(|e| BulwarkError::Dao(format!("oxcache get_sync 失败: {}", e)))?
                    .ok_or_else(|| BulwarkError::Dao(format!("键不存在: {}", key)))?;
                self.cache
                    .set_with_ttl_sync(&key.to_string(), &value, None)
                    .map_err(|e| {
                        BulwarkError::Dao(format!("oxcache expire (set_with_ttl_sync) 失败: {}", e))
                    })
            } else {
                let updated = self
                    .cache
                    .expire_sync(&key.to_string(), Duration::from_secs(seconds))
                    .map_err(|e| BulwarkError::Dao(format!("oxcache expire_sync 失败: {}", e)))?;
                if !updated {
                    return Err(BulwarkError::Dao(format!("键不存在: {}", key)));
                }
                Ok(())
            }
        }

        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            self.cache
                .delete_sync(&key.to_string())
                .map_err(|e| BulwarkError::Dao(format!("oxcache delete_sync 失败: {}", e)))
        }
    }
}

#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
pub use oxcache_impl::BulwarkDaoOxcache;

// ============================================================================
// dbnexus 实现（feature = "db-sqlite")
// ============================================================================

#[cfg(feature = "db-sqlite")]
mod dbnexus_impl;

#[cfg(feature = "db-sqlite")]
pub use dbnexus_impl::{init_dbnexus, BulwarkMigration};

// ============================================================================
// AloneCache 装饰器（feature = "alone-cache"）
// ============================================================================

#[cfg(feature = "alone-cache")]
pub mod alone_cache;

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
/// DAO trait 契约测试与跨模块共享的 mock 实现（仅 `cfg(test)` 下编译）。
pub mod tests {
    use super::*;
    use crate::error::BulwarkError;
    use parking_lot::Mutex;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    // ------------------------------------------------------------------------
    // Mock 实现：基于 HashMap + Instant 模拟 TTL，严格按 spec 语义
    // ------------------------------------------------------------------------

    /// 测试用 mock DAO，用于验证 trait 契约本身（与具体后端无关）。
    ///
    /// 语义：
    /// - `set(ttl=0)`: 永久驻留（expire_at = None）
    /// - `set(ttl=N)`: N 秒后过期（expire_at = Some(now + N)）
    /// - `update`: 保留原 expire_at，仅更新 value
    /// - `expire`: 重置 expire_at
    ///
    /// `pub` 供跨模块测试（如 `strategy::hooks`）复用，仅在 `cfg(test)` 下编译。
    pub struct MockDao {
        store: Mutex<HashMap<String, (String, Option<Instant>)>>,
    }

    impl Default for MockDao {
        fn default() -> Self {
            Self::new()
        }
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
    }

    // ------------------------------------------------------------------------
    // 契约测试：验证 BulwarkDao trait 行为契约（使用 MockDao）
    // 对应 dao-oxcache-basic spec 的 4 个 scenario
    // ------------------------------------------------------------------------

    /// Scenario: set 与 get 配对。
    /// WHEN 调用 set("key1", "value1", 3600) 后 get("key1")
    /// THEN 返回 Some("value1")
    #[tokio::test]
    async fn mock_set_get_pair() {
        let dao = MockDao::new();
        dao.set("key1", "value1", 3600).await.unwrap();
        let got = dao.get("key1").await.unwrap();
        assert_eq!(got, Some("value1".to_string()));
    }

    /// Scenario: 过期自动删除。
    /// WHEN set("key1", "value1", 1) 并等待 2 秒
    /// THEN get("key1") 返回 None
    #[tokio::test]
    async fn mock_expire_auto_delete() {
        let dao = MockDao::new();
        dao.set("key1", "value1", 1).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        let got = dao.get("key1").await.unwrap();
        assert!(got.is_none(), "过期后 get 应返回 None");
    }

    /// Scenario: delete 删除键。
    /// WHEN set("key1", "value1", 3600) 后 delete("key1")
    /// THEN get("key1") 返回 None
    #[tokio::test]
    async fn mock_delete_removes_key() {
        let dao = MockDao::new();
        dao.set("key1", "value1", 3600).await.unwrap();
        dao.delete("key1").await.unwrap();
        let got = dao.get("key1").await.unwrap();
        assert!(got.is_none(), "delete 后 get 应返回 None");
    }

    /// Scenario: update 更新值（保留 TTL）。
    /// WHEN set("key1", "value1", 3600) 后 update("key1", "value2")
    /// THEN get("key1") 返回 Some("value2")
    /// AND  TTL 保持 3600（不重置）
    #[tokio::test]
    async fn mock_update_preserves_ttl() {
        let dao = MockDao::new();
        // 用短 TTL 验证 update 不重置 TTL
        dao.set("key1", "value1", 2).await.unwrap();
        // 立即 update（在 TTL 内）
        dao.update("key1", "value2").await.unwrap();
        // 验证值已更新
        let got = dao.get("key1").await.unwrap();
        assert_eq!(got, Some("value2".to_string()));
        // 等待原 TTL 过期（2 秒 + 1 秒余量）
        tokio::time::sleep(Duration::from_secs(3)).await;
        // update 保留了原 TTL，应已过期
        let got = dao.get("key1").await.unwrap();
        assert!(
            got.is_none(),
            "update 不应重置 TTL，原 TTL 过期后应返回 None"
        );
    }

    /// 验证 update 不存在的键返回错误（Fail Loud 原则）。
    #[tokio::test]
    async fn mock_update_missing_key_errors() {
        let dao = MockDao::new();
        let result = dao.update("missing", "value").await;
        assert!(
            matches!(result, Err(BulwarkError::Dao(_))),
            "update 不存在的键应返回 Dao 错误"
        );
    }

    /// 验证 expire 重置过期时间。
    #[tokio::test]
    async fn mock_expire_resets_ttl() {
        let dao = MockDao::new();
        dao.set("key1", "value1", 1).await.unwrap();
        // 在过期前重置 TTL
        dao.expire("key1", 3600).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        // 原 TTL 已过，但 expire 重置后应仍存在
        let got = dao.get("key1").await.unwrap();
        assert_eq!(got, Some("value1".to_string()));
    }

    /// 验证 expire 不存在的键返回错误。
    #[tokio::test]
    async fn mock_expire_missing_key_errors() {
        let dao = MockDao::new();
        let result = dao.expire("missing", 3600).await;
        assert!(
            matches!(result, Err(BulwarkError::Dao(_))),
            "expire 不存在的键应返回 Dao 错误"
        );
    }

    /// 验证 set(ttl=0) 表示永久驻留。
    #[tokio::test]
    async fn mock_set_zero_ttl_means_permanent() {
        let dao = MockDao::new();
        dao.set("perm", "value", 0).await.unwrap();
        // 即使等待也不会过期（mock 用 Instant，sleep 仅作示意）
        tokio::time::sleep(Duration::from_millis(10)).await;
        let got = dao.get("perm").await.unwrap();
        assert_eq!(got, Some("value".to_string()));
    }

    /// 验证 get 不存在的键返回 None（不报错）。
    #[tokio::test]
    async fn mock_get_missing_returns_none() {
        let dao = MockDao::new();
        let got = dao.get("never_set").await.unwrap();
        assert!(got.is_none());
    }

    /// 验证 MockDao::default() 等价于 new()。
    ///
    /// 覆盖 MockDao 的 Default trait 实现。
    #[tokio::test]
    async fn mock_dao_default_equals_new() {
        let dao = MockDao::default();
        dao.set("default_key", "default_value", 60).await.unwrap();
        let got = dao.get("default_key").await.unwrap();
        assert_eq!(got, Some("default_value".to_string()));
    }

    /// 验证 expire(key, 0) 将键设为永久驻留。
    ///
    /// 覆盖 MockDao::expire 的 `seconds == 0` 分支（expire_at = None）。
    #[tokio::test]
    async fn mock_expire_zero_seconds_means_permanent() {
        let dao = MockDao::new();
        dao.set("k", "v", 1).await.unwrap();
        // expire(0) 改为永久驻留
        dao.expire("k", 0).await.unwrap();
        // 等待原 TTL 过期
        tokio::time::sleep(Duration::from_secs(2)).await;
        let got = dao.get("k").await.unwrap();
        assert_eq!(got, Some("v".to_string()), "expire(0) 应改为永久驻留");
    }

    // ------------------------------------------------------------------------
    // oxcache 集成测试（feature = "cache-memory" 或 "cache-redis"）
    // ------------------------------------------------------------------------

    #[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
    mod oxcache_tests {
        use super::*;

        /// Scenario: set 与 get 配对。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_set_get_pair() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_key1", "value1", 3600).await.unwrap();
            let got = dao.get("oc_key1").await.unwrap();
            assert_eq!(got, Some("value1".to_string()));
        }

        /// Scenario: 过期自动删除。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_expire_auto_delete() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_key2", "value1", 1).await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            let got = dao.get("oc_key2").await.unwrap();
            assert!(got.is_none(), "过期后 get 应返回 None");
        }

        /// Scenario: delete 删除键。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_delete_removes_key() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_key3", "value1", 3600).await.unwrap();
            dao.delete("oc_key3").await.unwrap();
            let got = dao.get("oc_key3").await.unwrap();
            assert!(got.is_none(), "delete 后 get 应返回 None");
        }

        /// 验证 oxcache update 更新值（仅验证值，TTL 保留见 ignore 测试）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_update_changes_value() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_key4", "value1", 3600).await.unwrap();
            dao.update("oc_key4", "value2").await.unwrap();
            let got = dao.get("oc_key4").await.unwrap();
            assert_eq!(got, Some("value2".to_string()));
        }

        /// 验证 update 不存在的键返回错误。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_update_missing_key_errors() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            let result = dao.update("oc_missing", "value").await;
            assert!(
                matches!(result, Err(BulwarkError::Dao(_))),
                "update 不存在的键应返回 Dao 错误"
            );
        }

        /// 验证 expire 重置过期时间。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_expire_resets_ttl() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_key5", "value1", 1).await.unwrap();
            dao.expire("oc_key5", 3600).await.unwrap();
            tokio::time::sleep(Duration::from_secs(2)).await;
            let got = dao.get("oc_key5").await.unwrap();
            assert_eq!(got, Some("value1".to_string()));
        }

        /// 验证 BulwarkDaoOxcache::new() 直接构造（init_oxcache_dao 包装已移除）。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_new_direct_construction() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_init", "init_value", 60).await.unwrap();
            let got = dao.get("oc_init").await.unwrap();
            assert_eq!(got, Some("init_value".to_string()));
        }

        /// Scenario: update 更新值（保留 TTL）。
        ///
        /// oxcache 0.3 的 Cache<K,V> 暴露了 ttl() 方法，update 用 ttl() + set_with_ttl 保留原 TTL。
        ///
        /// 参见：dao-oxcache-basic spec Requirement "BulwarkDao 抽象 trait" Scenario "update 更新值（保留 TTL）"
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_update_preserves_ttl() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            dao.set("oc_ttl", "value1", 2).await.unwrap();
            dao.update("oc_ttl", "value2").await.unwrap();
            // update 保留了原 TTL（2 秒），sleep 后应过期
            tokio::time::sleep(Duration::from_secs(3)).await;
            let got = dao.get("oc_ttl").await.unwrap();
            assert!(
                got.is_none(),
                "update 不应重置 TTL，原 TTL 过期后应返回 None"
            );
        }

        /// 验证 expire(key, 0) 将键设为永久驻留（不删除）。
        ///
        /// 覆盖 BulwarkDaoOxcache::expire 的 `seconds == 0` 分支：
        /// 通过 get + set_with_ttl(None) 实现 0=永久语义。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_expire_zero_seconds_makes_permanent() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            // 设置短 TTL，键会在 1 秒后过期
            dao.set("oc_perm", "value1", 1).await.unwrap();
            // expire(0) 将键改为永久驻留
            dao.expire("oc_perm", 0).await.unwrap();
            // 等待原 TTL 过期
            tokio::time::sleep(Duration::from_secs(2)).await;
            // 键应仍存在（已改为永久驻留）
            let got = dao.get("oc_perm").await.unwrap();
            assert_eq!(
                got,
                Some("value1".to_string()),
                "expire(0) 应将键改为永久驻留，不应过期"
            );
        }

        /// 验证 expire(0) 对不存在的键返回 Dao 错误。
        ///
        /// 覆盖 BulwarkDaoOxcache::expire 的 `seconds == 0` 分支中
        /// `ok_or_else(|| BulwarkError::Dao(...))` 错误路径。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_expire_zero_seconds_missing_key_errors() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            let result = dao.expire("oc_missing_perm", 0).await;
            assert!(
                matches!(result, Err(BulwarkError::Dao(_))),
                "expire(0) 不存在的键应返回 Dao 错误"
            );
        }

        /// 验证 expire 对不存在的键返回 Dao 错误（seconds > 0 分支）。
        ///
        /// 覆盖 BulwarkDaoOxcache::expire 的 `else` 分支中
        /// `if !updated { return Err(...) }` 错误路径。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_expire_missing_key_errors() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            let result = dao.expire("oc_missing_expire", 3600).await;
            assert!(
                matches!(result, Err(BulwarkError::Dao(ref msg)) if msg.contains("键不存在")),
                "expire 不存在的键应返回含 '键不存在' 的 Dao 错误，实际: {:?}",
                result
            );
        }

        /// 验证 set(ttl=0) 写入永久驻留的键（依据 codebase-hardening Task 3.7）。
        ///
        /// 覆盖 BulwarkDaoOxcache::set 的 `ttl_seconds == 0` 分支（ttl=None）：
        /// 键应永久驻留，不会因短时间等待而过期。
        #[tokio::test(flavor = "multi_thread")]
        async fn oxcache_set_with_zero_ttl() {
            let dao = BulwarkDaoOxcache::new().await.unwrap();
            // set(ttl=0) 表示永久驻留
            dao.set("oc_zero_ttl", "permanent_value", 0).await.unwrap();
            // 等待 2 秒，验证键未过期
            tokio::time::sleep(Duration::from_secs(2)).await;
            let got = dao.get("oc_zero_ttl").await.unwrap();
            assert_eq!(
                got,
                Some("permanent_value".to_string()),
                "set(ttl=0) 应写入永久驻留的键，2 秒后仍应存在"
            );
        }
    }
}
