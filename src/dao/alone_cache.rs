// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! AloneCache 模块：多 Redis 实例隔离装饰器——为所有 key 自动加 prefix（权限缓存与业务缓存物理隔离）；
//! `AloneCacheManager` 管理多个实例，支持多 Redis 实例路由。

use crate::dao::GarrisonDao;
use crate::error::GarrisonResult;
use async_trait::async_trait;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

/// AloneCache 装饰器：每方法入口先拼 `key_prefix` 再委托内部 dao，确保 key 空间物理隔离。
///
/// # 示例
/// ```ignore
/// use garrison::dao::alone_cache::AloneCache;
/// use std::sync::Arc;
/// // AloneCache::new(dao, "perm:") 后 set("user:1001", ...) 内部 dao 收到 set("perm:user:1001", ...)
/// ```
pub struct AloneCache {
    /// 内部委托的 dao 实例。
    inner: Arc<dyn GarrisonDao>,
    /// 自动拼接的 key 前缀（如 "perm:" / "biz:"）。
    key_prefix: String,
}

impl AloneCache {
    /// 创建装饰器：`dao` 为内部委托实例，`key_prefix` 自动拼接前缀（如 "perm:" / "biz:"）。
    pub fn new(dao: Arc<dyn GarrisonDao>, key_prefix: &str) -> Self {
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
impl GarrisonDao for AloneCache {
    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        self.inner.get(&self.prefixed_key(key)).await
    }

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
        self.inner
            .set(&self.prefixed_key(key), value, ttl_seconds)
            .await
    }

    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        self.inner.update(&self.prefixed_key(key), value).await
    }

    async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
        self.inner.expire(&self.prefixed_key(key), seconds).await
    }

    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        self.inner.delete(&self.prefixed_key(key)).await
    }

    async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>> {
        self.inner.get_and_delete(&self.prefixed_key(key)).await
    }

    /// 透明委托内部 dao：默认实现的 `NotImplemented`（fail-closed）若不透传，
    /// 经 AloneCache 部署的 TTL 查询（expire 续期、会话剩余窗口）会全部失效。
    async fn get_timeout(&self, key: &str) -> GarrisonResult<Option<std::time::Duration>> {
        self.inner.get_timeout(&self.prefixed_key(key)).await
    }

    /// 透明委托内部 dao（与 `get_timeout` 对称）；内部 dao 单次 lookup 的实现应保持复用。
    async fn get_with_ttl(
        &self,
        key: &str,
    ) -> GarrisonResult<Option<(String, Option<std::time::Duration>)>> {
        self.inner.get_with_ttl(&self.prefixed_key(key)).await
    }

    /// 委托内部 dao（原子 SETNX 语义，必需方法）。
    async fn set_if_absent(
        &self,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        self.inner
            .set_if_absent(&self.prefixed_key(key), value, ttl_seconds)
            .await
    }

    /// 委托内部 dao（原子重命名 + TTL 保留，必需方法）。
    async fn rename(&self, old_key: &str, new_key: &str) -> GarrisonResult<()> {
        self.inner
            .rename(&self.prefixed_key(old_key), &self.prefixed_key(new_key))
            .await
    }

    /// 委托内部 dao（原子计数，必需方法）。
    async fn incr(&self, key: &str, ttl_seconds: u64) -> GarrisonResult<u64> {
        self.inner.incr(&self.prefixed_key(key), ttl_seconds).await
    }

    /// 委托内部 dao：默认实现 `NotImplemented`（fail-closed），必须显式 forward 以复用内部原子 CAS。
    async fn compare_and_update_if_greater(
        &self,
        key: &str,
        new_value: u64,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        self.inner
            .compare_and_update_if_greater(&self.prefixed_key(key), new_value, ttl_seconds)
            .await
    }

    /// 委托内部 dao（与 `compare_and_update_if_greater` 对称）：走默认组合（get → parse → update/delete）
    /// 会让经 AloneCache 部署的 SMS 限速等场景仍有 TOCTOU flaky。
    async fn decr(&self, key: &str) -> GarrisonResult<u64> {
        self.inner.decr(&self.prefixed_key(key)).await
    }

    /// 委托内部 dao，保证装饰器透明委托语义并复用内部原子 CAS。
    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        self.inner
            .compare_and_swap(&self.prefixed_key(key), expected, new_value, ttl_seconds)
            .await
    }
}

/// 管理多个 AloneCache：`register` 注册命名缓存、`get` 按 name 取共享 `Arc<AloneCache>`（RwLock 保护，支持并发读写）。
pub struct AloneCacheManager {
    caches: RwLock<HashMap<String, Arc<AloneCache>>>,
}

impl AloneCacheManager {
    /// 创建空的缓存管理器。
    pub fn new() -> Self {
        Self {
            caches: RwLock::new(HashMap::new()),
        }
    }

    /// 注册命名缓存（同名覆盖）。
    pub fn register(&self, name: &str, cache: AloneCache) {
        self.caches
            .write()
            .insert(name.to_string(), Arc::new(cache));
    }

    /// 按 name 获取已注册缓存（未注册返回 None）。
    pub fn get(&self, name: &str) -> Option<Arc<AloneCache>> {
        self.caches.read().get(name).cloned()
    }

    /// 注销命名缓存并返回被移除实例（未注册返回 None）。
    pub fn unregister(&self, name: &str) -> Option<Arc<AloneCache>> {
        self.caches.write().remove(name)
    }
}

impl Default for AloneCacheManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;

    /// set 经装饰器后内部 dao 收到加 prefix 的 key（无 prefix 的原 key 不存在）。
    #[tokio::test]
    async fn alone_cache_set_adds_prefix() {
        let mock = Arc::new(MockDao::new());
        let cache = AloneCache::new(mock.clone(), "perm:");
        cache.set("user:1001", "value", 3600).await.unwrap();
        let got = mock.get("perm:user:1001").await.unwrap();
        assert_eq!(got, Some("value".to_string()));
        let not_got = mock.get("user:1001").await.unwrap();
        assert!(not_got.is_none(), "无 prefix 的 key 不应存在");
    }

    /// get 经装饰器拼 prefix 后命中内部 dao 的 key；访问已带 prefix 的 key 会双重拼接返回 None。
    #[tokio::test]
    async fn alone_cache_get_adds_prefix() {
        let mock = Arc::new(MockDao::new());
        mock.set("perm:user:1001", "value", 3600).await.unwrap();
        let cache = AloneCache::new(mock.clone(), "perm:");
        let got = cache.get("user:1001").await.unwrap();
        assert_eq!(got, Some("value".to_string()));
        let not_got = cache.get("perm:user:1001").await.unwrap();
        assert!(not_got.is_none(), "双重 prefix 的 key 不应存在");
    }

    /// delete 经装饰器加 prefix。
    #[tokio::test]
    async fn alone_cache_delete_adds_prefix() {
        let mock = Arc::new(MockDao::new());
        mock.set("perm:k", "v", 3600).await.unwrap();
        let cache = AloneCache::new(mock.clone(), "perm:");
        cache.delete("k").await.unwrap();
        let got = mock.get("perm:k").await.unwrap();
        assert!(got.is_none(), "delete 应删除带 prefix 的 key");
    }

    /// update 经装饰器加 prefix。
    #[tokio::test]
    async fn alone_cache_update_adds_prefix() {
        let mock = Arc::new(MockDao::new());
        mock.set("perm:k", "v1", 3600).await.unwrap();
        let cache = AloneCache::new(mock.clone(), "perm:");
        cache.update("k", "v2").await.unwrap();
        let got = mock.get("perm:k").await.unwrap();
        assert_eq!(got, Some("v2".to_string()));
    }

    /// expire 经装饰器加 prefix（若未加 prefix 会因 key 不存在返回 Err）。
    #[tokio::test]
    async fn alone_cache_expire_adds_prefix() {
        let mock = Arc::new(MockDao::new());
        mock.set("perm:k", "v", 1).await.unwrap();
        let cache = AloneCache::new(mock.clone(), "perm:");
        cache.expire("k", 3600).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        let got = cache.get("k").await.unwrap();
        assert_eq!(
            got,
            Some("v".to_string()),
            "expire 应重置带 prefix 的 key 的 TTL"
        );
    }

    /// 透明委托：set / get / expire（含错误路径）结果与直接调用内部 dao 一致。
    #[tokio::test]
    async fn alone_cache_transparent_delegation() {
        let mock = Arc::new(MockDao::new());
        let cache = AloneCache::new(mock.clone(), "prefix:");

        let r1 = cache.set("k", "v", 100).await;
        let r2 = mock.set("prefix:k", "v2", 100).await;
        assert!(r1.is_ok());
        assert!(r2.is_ok());

        let via_cache = cache.get("k").await.unwrap();
        let via_mock = mock.get("prefix:k").await.unwrap();
        assert_eq!(via_cache, via_mock);

        let r4 = cache.expire("missing", 100).await;
        let r5 = mock.expire("prefix:missing", 100).await;
        assert!(r4.is_err(), "cache.expire 不存在的键应返回 Err");
        assert!(r5.is_err(), "mock.expire 不存在的键应返回 Err");
    }

    /// register + get 多实例。
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

    /// 未注册的缓存名返回 None。
    #[tokio::test]
    async fn alone_cache_manager_unregistered_returns_none() {
        let manager = AloneCacheManager::new();
        let got = manager.get("unregistered");
        assert!(got.is_none(), "未注册的 name 应返回 None");
    }

    /// 多实例注入不同 dao（多 Redis 实例路由）：命名空间互不可见。
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

        let p = redis1.get("perm:user:1").await.unwrap();
        let b = redis2.get("biz:user:1").await.unwrap();
        assert_eq!(p, Some("p".to_string()));
        assert_eq!(b, Some("b".to_string()));

        assert!(
            redis1.get("biz:user:1").await.unwrap().is_none(),
            "redis1 不应包含 biz: 命名空间"
        );
        assert!(
            redis2.get("perm:user:1").await.unwrap().is_none(),
            "redis2 不应包含 perm: 命名空间"
        );
    }

    /// unregister 后 get 返回 None。
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

    /// 空 prefix 时 key 不变（边界）。
    #[tokio::test]
    async fn alone_cache_empty_prefix_passthrough() {
        let mock = Arc::new(MockDao::new());
        let cache = AloneCache::new(mock.clone(), "");
        cache.set("k", "v", 3600).await.unwrap();
        let got = mock.get("k").await.unwrap();
        assert_eq!(got, Some("v".to_string()));
    }

    /// delete 不存在的键返回 Ok（幂等，与 MockDao 一致）。
    #[tokio::test]
    async fn alone_cache_delete_nonexistent_is_ok() {
        let mock = Arc::new(MockDao::new());
        let cache = AloneCache::new(mock, "perm:");
        let result = cache.delete("never_exists").await;
        assert!(
            result.is_ok(),
            "delete 不存在的键应返回 Ok（与 MockDao 一致）"
        );
    }

    /// `AloneCache::decr` 透明委托内部 dao：prefix 拼接、返回值、TTL 保留均与 inner dao 一致。
    ///（修复：此前走默认 get → parse → update/delete 组合，经 AloneCache 部署的 SMS 限速场景仍有 TOCTOU flaky。）
    #[tokio::test]
    async fn alone_cache_decr_delegates_to_inner_with_prefix() {
        let mock = Arc::new(MockDao::new());
        let cache = AloneCache::new(mock.clone(), "perm:");

        mock.set("perm:counter", "3", 3600).await.unwrap();

        let r1 = cache.decr("counter").await.unwrap();
        assert_eq!(r1, 2, "第一次 decr 应返回 2");
        let v1 = mock.get("perm:counter").await.unwrap();
        assert_eq!(v1.as_deref(), Some("2"), "decr 后内部 dao 应为 '2'");

        let r2 = cache.decr("counter").await.unwrap();
        assert_eq!(r2, 1, "第二次 decr 应返回 1");

        let r3 = cache.decr("counter").await.unwrap();
        assert_eq!(r3, 0, "第三次 decr 应返回 0");
        let v3 = mock.get("perm:counter").await.unwrap();
        assert!(v3.is_none(), "decr 到 0 时 key 应被删除");

        let r4 = cache.decr("counter").await.unwrap();
        assert_eq!(r4, 0, "key 不存在时 decr 应返回 0");
        let v4 = mock.get("perm:counter").await.unwrap();
        assert!(v4.is_none(), "key 不存在时 decr 不应创建 key");
    }

    /// decr 不存在的 key 返回 0（透明委托边界）。
    #[tokio::test]
    async fn alone_cache_decr_missing_key_returns_zero() {
        let mock = Arc::new(MockDao::new());
        let cache = AloneCache::new(mock.clone(), "perm:");

        let r = cache.decr("never").await.unwrap();
        assert_eq!(r, 0, "不存在的 key decr 应返回 0");

        let v = mock.get("perm:never").await.unwrap();
        assert!(v.is_none(), "inner dao 上 'perm:never' 不应存在");
    }

    /// `AloneCache::decr` 并发原子性：10 个 task 并发 decr（初始 5），恰好 4 个非 0（4,3,2,1）+ 6 个 0，key 最终删除。
    ///（修复前走默认组合，多 task 读到同一过时值产生「跨越式递减」；修复后逐 task 串行进入 MockDao 临界区。）
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn alone_cache_decr_concurrent_atomic() {
        let mock = Arc::new(MockDao::new());
        let cache = Arc::new(AloneCache::new(mock.clone(), "perm:"));

        mock.set("perm:counter", "5", 3600).await.unwrap();

        let mut handles = Vec::with_capacity(10);
        for _ in 0..10 {
            let c = cache.clone();
            handles.push(tokio::spawn(
                async move { c.decr("counter").await.unwrap() },
            ));
        }

        let mut results = Vec::with_capacity(10);
        for h in handles {
            results.push(h.await.expect("task join failed"));
        }

        // 4 个非 0（4, 3, 2, 1）+ 6 个 0（第 5 次 key 删除 + 后 5 次）
        let nonzero_count = results.iter().filter(|&&v| v > 0).count();
        let zero_count = results.iter().filter(|&&v| v == 0).count();
        assert_eq!(
            nonzero_count, 4,
            "应恰好 4 个非 0 返回值（4, 3, 2, 1），实际: {:?}",
            results
        );
        assert_eq!(
            zero_count, 6,
            "应恰好 6 个 0 返回值（第 5 次 decr + key 删除后 5 次），实际: {:?}",
            results
        );

        // 非 0 值集合恰好为 {4, 3, 2, 1}（无重复、无遗漏、无跨越式递减）
        let mut nonzero_vals: Vec<u64> = results.iter().copied().filter(|&v| v > 0).collect();
        nonzero_vals.sort_unstable();
        assert_eq!(
            nonzero_vals,
            vec![1, 2, 3, 4],
            "非 0 返回值应恰好为 {{1, 2, 3, 4}}，实际: {:?}",
            nonzero_vals
        );

        let v = mock.get("perm:counter").await.unwrap();
        assert!(v.is_none(), "并发 decr 后 key 应被删除");
    }
}
