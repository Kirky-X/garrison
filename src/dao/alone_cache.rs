//! AloneCache 模块：多 Redis 实例隔离装饰器。
//!
//! 通过 `AloneCache` 装饰 `BulwarkDao`，为所有 key 自动添加 prefix，
//! 实现权限缓存与业务缓存的物理隔离（同一 Redis 实例中不同 prefix 互不干扰）。
//!
//! `AloneCacheManager` 管理多个 `AloneCache` 实例，每个实例可注入不同的
//! `BulwarkDao`（支持多 Redis 实例路由）。
//!
//! 依据 spec alone-cache（0.4.0 gap #6）。

use crate::dao::BulwarkDao;
use crate::error::BulwarkResult;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// AloneCache 装饰器，为所有 key 自动添加 prefix。
///
/// 实现 `BulwarkDao` trait 时，每方法入口先 `format!("{}{}", key_prefix, key)`
/// 拼接 prefix 后委托内部 dao，确保权限缓存与业务缓存的 key 空间物理隔离。
///
/// # 示例
/// ```ignore
/// use bulwark::dao::alone_cache::AloneCache;
/// use std::sync::Arc;
/// // AloneCache::new(dao, "perm:") 后 set("user:1001", ...) 内部 dao 收到 set("perm:user:1001", ...)
/// ```
pub struct AloneCache {
    /// 内部委托的 dao 实例。
    inner: Arc<dyn BulwarkDao>,
    /// 自动拼接的 key 前缀（如 "perm:" / "biz:"）。
    key_prefix: String,
}

impl AloneCache {
    /// 创建 AloneCache 装饰器。
    ///
    /// # 参数
    /// - `dao`: 内部委托的 `BulwarkDao` 实例（通常是 oxcache / dbnexus 后端）。
    /// - `key_prefix`: 自动拼接的 key 前缀（如 "perm:" / "biz:"）。
    pub fn new(dao: Arc<dyn BulwarkDao>, key_prefix: &str) -> Self {
        Self {
            inner: dao,
            key_prefix: key_prefix.to_string(),
        }
    }

    /// 拼接 prefix 后的完整 key。
    fn prefixed_key(&self, key: &str) -> String {
        format!("{}{}", self.key_prefix, key)
    }
}

#[async_trait]
impl BulwarkDao for AloneCache {
    async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
        self.inner.get(&self.prefixed_key(key)).await
    }

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
        self.inner
            .set(&self.prefixed_key(key), value, ttl_seconds)
            .await
    }

    async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
        self.inner.update(&self.prefixed_key(key), value).await
    }

    async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
        self.inner.expire(&self.prefixed_key(key), seconds).await
    }

    async fn delete(&self, key: &str) -> BulwarkResult<()> {
        self.inner.delete(&self.prefixed_key(key)).await
    }
}

/// AloneCacheManager 管理多个 AloneCache 实例，支持多 Redis 实例路由。
///
/// 通过 `register` 注册命名缓存，`get` 按 name 获取共享 `Arc<AloneCache>`。
/// 内部用 `parking_lot::RwLock` 保护 HashMap，支持并发读写。
pub struct AloneCacheManager {
    caches: RwLock<HashMap<String, Arc<AloneCache>>>,
}

impl AloneCacheManager {
    /// 创建空的 AloneCacheManager。
    pub fn new() -> Self {
        Self {
            caches: RwLock::new(HashMap::new()),
        }
    }

    /// 注册命名缓存。
    ///
    /// 若 name 已存在则覆盖。
    ///
    /// # 参数
    /// - `name`: 缓存实例名（如 "permission" / "business"）。
    /// - `cache`: `AloneCache` 实例（所有权转移，内部包装为 `Arc`）。
    pub fn register(&self, name: &str, cache: AloneCache) {
        self.caches
            .write()
            .insert(name.to_string(), Arc::new(cache));
    }

    /// 按 name 获取已注册的缓存实例。
    ///
    /// # 返回
    /// - `Some(Arc<AloneCache>)`: name 已注册。
    /// - `None`: name 未注册。
    pub fn get(&self, name: &str) -> Option<Arc<AloneCache>> {
        self.caches.read().get(name).cloned()
    }

    /// 注销命名缓存。
    ///
    /// # 返回
    /// - `Some(Arc<AloneCache>)`: name 已注册，返回被移除的实例。
    /// - `None`: name 未注册。
    pub fn unregister(&self, name: &str) -> Option<Arc<AloneCache>> {
        self.caches.write().remove(name)
    }
}

impl Default for AloneCacheManager {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// 单元测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;

    /// Scenario: AloneCache::new(dao, "perm:") 后 set("user:1001", ...) 内部 dao 收到 set("perm:user:1001", ...)。
    ///
    /// 覆盖 spec alone-cache Requirement "AloneCache 装饰器抽象" Scenario "AloneCache 自动添加 prefix"。
    #[tokio::test]
    async fn alone_cache_set_adds_prefix() {
        let mock = Arc::new(MockDao::new());
        let cache = AloneCache::new(mock.clone(), "perm:");
        cache.set("user:1001", "value", 3600).await.unwrap();
        // 内部 mock 应在 "perm:user:1001" 上收到值
        let got = mock.get("perm:user:1001").await.unwrap();
        assert_eq!(got, Some("value".to_string()));
        // 原始无 prefix 的 key 不应存在
        let not_got = mock.get("user:1001").await.unwrap();
        assert!(not_got.is_none(), "无 prefix 的 key 不应存在");
    }

    /// Scenario: AloneCache::new(dao, "perm:") 后 get("user:1001") 内部 dao 收到 get("perm:user:1001")。
    ///
    /// 覆盖 spec alone-cache Requirement "AloneCache 装饰器抽象" Scenario "AloneCache get/delete 同样添加 prefix"。
    #[tokio::test]
    async fn alone_cache_get_adds_prefix() {
        let mock = Arc::new(MockDao::new());
        // 直接在 mock 上设置带 prefix 的 key
        mock.set("perm:user:1001", "value", 3600).await.unwrap();
        let cache = AloneCache::new(mock.clone(), "perm:");
        // 通过 cache.get("user:1001") 应能取到（证明 get 加了 prefix）
        let got = cache.get("user:1001").await.unwrap();
        assert_eq!(got, Some("value".to_string()));
        // 再次经 cache 访问带 prefix 的 key 会拼成 "perm:perm:user:1001"，应返回 None
        let not_got = cache.get("perm:user:1001").await.unwrap();
        assert!(not_got.is_none(), "双重 prefix 的 key 不应存在");
    }

    /// Scenario: AloneCache delete 同样加 prefix。
    ///
    /// 覆盖 spec alone-cache Requirement "AloneCache 装饰器抽象" Scenario "AloneCache get/delete 同样添加 prefix"。
    #[tokio::test]
    async fn alone_cache_delete_adds_prefix() {
        let mock = Arc::new(MockDao::new());
        mock.set("perm:k", "v", 3600).await.unwrap();
        let cache = AloneCache::new(mock.clone(), "perm:");
        cache.delete("k").await.unwrap();
        // 内部 mock 的 "perm:k" 应被删除
        let got = mock.get("perm:k").await.unwrap();
        assert!(got.is_none(), "delete 应删除带 prefix 的 key");
    }

    /// Scenario: AloneCache update 同样加 prefix。
    #[tokio::test]
    async fn alone_cache_update_adds_prefix() {
        let mock = Arc::new(MockDao::new());
        mock.set("perm:k", "v1", 3600).await.unwrap();
        let cache = AloneCache::new(mock.clone(), "perm:");
        cache.update("k", "v2").await.unwrap();
        // 内部 mock 的 "perm:k" 值应已更新
        let got = mock.get("perm:k").await.unwrap();
        assert_eq!(got, Some("v2".to_string()));
    }

    /// Scenario: AloneCache expire 同样加 prefix。
    #[tokio::test]
    async fn alone_cache_expire_adds_prefix() {
        let mock = Arc::new(MockDao::new());
        // 设置短 TTL（1 秒）
        mock.set("perm:k", "v", 1).await.unwrap();
        let cache = AloneCache::new(mock.clone(), "perm:");
        // 通过 cache.expire("k", 3600) 重置 TTL
        // （若未加 prefix，mock 上 "k" 不存在，会返回 Err）
        cache.expire("k", 3600).await.unwrap();
        // 等待原 TTL 过期
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        // expire 重置后应仍存在
        let got = cache.get("k").await.unwrap();
        assert_eq!(
            got,
            Some("v".to_string()),
            "expire 应重置带 prefix 的 key 的 TTL"
        );
    }

    /// Scenario: AloneCache 透明委托返回值与 MockDao 直接调用一致。
    ///
    /// 覆盖 spec alone-cache Requirement "AloneCache 与既有 BulwarkDao 行为一致" Scenario "AloneCache 透明委托"。
    #[tokio::test]
    async fn alone_cache_transparent_delegation() {
        let mock = Arc::new(MockDao::new());
        let cache = AloneCache::new(mock.clone(), "prefix:");

        // set 返回 Ok（与直接调用 mock.set 一致）
        let r1 = cache.set("k", "v", 100).await;
        let r2 = mock.set("prefix:k", "v2", 100).await;
        assert!(r1.is_ok());
        assert!(r2.is_ok());

        // get 返回值与直接调用 mock 一致
        let via_cache = cache.get("k").await.unwrap();
        let via_mock = mock.get("prefix:k").await.unwrap();
        assert_eq!(via_cache, via_mock);

        // expire 不存在的键返回 Err（一致）
        let r4 = cache.expire("missing", 100).await;
        let r5 = mock.expire("prefix:missing", 100).await;
        assert!(r4.is_err(), "cache.expire 不存在的键应返回 Err");
        assert!(r5.is_err(), "mock.expire 不存在的键应返回 Err");
    }

    /// Scenario: AloneCacheManager::register + get 多实例。
    ///
    /// 覆盖 spec alone-cache Requirement "AloneCacheManager 多实例管理" Scenario "创建多个 AloneCache 实例"。
    #[tokio::test]
    async fn alone_cache_manager_register_and_get() {
        let manager = AloneCacheManager::new();
        manager.register(
            "permission",
            AloneCache::new(Arc::new(MockDao::new()), "perm:"),
        );
        manager.register(
            "business",
            AloneCache::new(Arc::new(MockDao::new()), "biz:"),
        );

        let perm = manager.get("permission");
        let biz = manager.get("business");
        assert!(perm.is_some(), "permission 实例应存在");
        assert!(biz.is_some(), "business 实例应存在");
    }

    /// Scenario: 未注册的缓存名返回 None。
    ///
    /// 覆盖 spec alone-cache Requirement "AloneCacheManager 多实例管理" Scenario "未注册的缓存名"。
    #[tokio::test]
    async fn alone_cache_manager_unregistered_returns_none() {
        let manager = AloneCacheManager::new();
        let got = manager.get("unregistered");
        assert!(got.is_none(), "未注册的 name 应返回 None");
    }

    /// Scenario: 多实例注入不同 dao（多 Redis 实例路由）。
    ///
    /// 覆盖 spec alone-cache Requirement "AloneCacheManager 多实例管理" Scenario "创建多个 AloneCache 实例"。
    #[tokio::test]
    async fn alone_cache_manager_multiple_different_dao() {
        let redis1 = Arc::new(MockDao::new());
        let redis2 = Arc::new(MockDao::new());

        let manager = AloneCacheManager::new();
        manager.register("permission", AloneCache::new(redis1.clone(), "perm:"));
        manager.register("business", AloneCache::new(redis2.clone(), "biz:"));

        let perm_cache = manager.get("permission").unwrap();
        let biz_cache = manager.get("business").unwrap();

        perm_cache.set("user:1", "p", 3600).await.unwrap();
        biz_cache.set("user:1", "b", 3600).await.unwrap();

        // 验证写入不同的内部 dao
        let p = redis1.get("perm:user:1").await.unwrap();
        let b = redis2.get("biz:user:1").await.unwrap();
        assert_eq!(p, Some("p".to_string()));
        assert_eq!(b, Some("b".to_string()));

        // 交叉验证：redis1 没有 biz:，redis2 没有 perm:
        assert!(
            redis1.get("biz:user:1").await.unwrap().is_none(),
            "redis1 不应包含 biz: 命名空间"
        );
        assert!(
            redis2.get("perm:user:1").await.unwrap().is_none(),
            "redis2 不应包含 perm: 命名空间"
        );
    }

    /// Scenario: unregister 后 get 返回 None。
    #[tokio::test]
    async fn alone_cache_manager_unregister() {
        let manager = AloneCacheManager::new();
        manager.register("temp", AloneCache::new(Arc::new(MockDao::new()), "t:"));
        assert!(manager.get("temp").is_some());
        let removed = manager.unregister("temp");
        assert!(removed.is_some(), "unregister 应返回被移除的实例");
        assert!(
            manager.get("temp").is_none(),
            "unregister 后 get 应返回 None"
        );
    }

    /// Scenario: 空 prefix 时 key 不变（边界）。
    #[tokio::test]
    async fn alone_cache_empty_prefix_passthrough() {
        let mock = Arc::new(MockDao::new());
        let cache = AloneCache::new(mock.clone(), "");
        cache.set("k", "v", 3600).await.unwrap();
        // 空 prefix 时内部 dao 收到的 key 应为原始 key
        let got = mock.get("k").await.unwrap();
        assert_eq!(got, Some("v".to_string()));
    }

    /// Scenario: delete 不存在的键返回 Ok（idempotent，与 MockDao 行为一致）。
    #[tokio::test]
    async fn alone_cache_delete_nonexistent_is_ok() {
        let mock = Arc::new(MockDao::new());
        let cache = AloneCache::new(mock, "perm:");
        // MockDao::delete 对不存在的键返回 Ok（idempotent）
        let result = cache.delete("never_exists").await;
        assert!(
            result.is_ok(),
            "delete 不存在的键应返回 Ok（与 MockDao 一致）"
        );
    }
}
