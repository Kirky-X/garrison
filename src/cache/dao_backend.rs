// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! DAO 缓存后端（oxcache `CacheBackend` 适配器）：三层缓存的 L2 持久层入链件。
//!
//! 由 oxcache `ChainCache` 组链时作为低分持久后端（`BackendScore` 低分 +
//! `is_persistent=true`），委托 [`GarrisonDao`] 读写：
//!
//! - **值形态**：链上 `Vec<u8>` ↔ DAO 字符串（UTF-8 字节透明）；调用方
//!   （[`UserCacheService`](crate::cache::three_tier::UserCacheService) 门面）
//!   负责 serde_json 序列化，本适配器不做编解码假设。
//! - **TTL 策略钉定**：`set` **忽略**链传入的 TTL，按
//!   [`Self::l2_ttl_with_jitter`]（基础 300s + 10% 抖动）落盘——L1=30s /
//!   L2=300s+抖动的分层时序由本适配器单一承载，链式写入不引入第二处 TTL 策略。
//! - **TTL 回读**：DAO 不暴露剩余 TTL，`ttl()` 恒返回 `None`；链的
//!   original-ttl 保鲜逻辑得到 `None` 时按新 TTL 走，与本适配器的钉定策略
//!   自洽（set 恒按自身策略落盘）。
//! - **容量枚举**：DAO 无高效全量计数（`keys` 扫描代价不可接受），`len()`
//!   返回 0——链的 `len`/`is_empty`/`capacity` 均取**首链**（L1 内存后端），
//!   不会落到本后端；直接调用方应视为「不提供计数」。
//! - **清除**：`clear()` 按构造时给定的缓存键前缀枚举删除（DAO 无全量清除
//!   原语，按前缀扫描是可枚举的唯一诚实实现）。

use crate::constants::DaoKeyPrefix;
use crate::dao::GarrisonDao;
use async_trait::async_trait;
use oxcache::backend::{BackendKind, BackendScore, CacheConnector, CacheReader, CacheWriter};
use std::sync::Arc;
use std::time::Duration;

/// L2 基础 TTL（秒）——与 `UserCacheService` 的 `l2_ttl_secs` 默认值一致。
const L2_BASE_TTL_SECS: u64 = 300;

/// 链分数：低分（0-100）——持久层排在 L1 内存后端之后。
const L2_BACKEND_SCORE: u8 = 20;

/// DAO 缓存后端（oxcache `CacheBackend` 实现）。
#[derive(Clone)]
pub struct GarrisonDaoCacheBackend {
    /// 内部 DAO。
    dao: Arc<dyn GarrisonDao>,
    /// `clear()` 的枚举范围：三层缓存键前缀（perm/role/user cache）。
    clear_prefixes: Vec<String>,
}

impl GarrisonDaoCacheBackend {
    /// 创建适配器实例（`clear_prefixes` 为 `clear()` 的键前缀枚举范围，
    /// 如三层缓存的 `perm:cache:` / `role:cache:` / `user:cache:`）。
    pub fn new(dao: Arc<dyn GarrisonDao>, clear_prefixes: Vec<String>) -> Self {
        Self {
            dao,
            clear_prefixes,
        }
    }

    /// 三层缓存默认前缀（`clear()` 枚举范围）。
    pub fn cache_clear_prefixes() -> Vec<String> {
        vec![
            DaoKeyPrefix::PermissionCache.build_key(""),
            DaoKeyPrefix::RoleCache.build_key(""),
            DaoKeyPrefix::UserCache.build_key(""),
        ]
    }

    /// L2 TTL 抖动：映射到 `[90%, 110%]` 区间。
    ///
    /// 哈希种子含进程随机分量（`DefaultHasher` 每进程随机种子）与线程 id，
    /// 不同 key 获得不同抖动；同一进程同一 key 上结果确定（可测）。
    pub fn l2_ttl_with_jitter(&self, base_secs: u64) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut hasher = DefaultHasher::new();
        base_secs.hash(&mut hasher);
        std::thread::current().id().hash(&mut hasher);
        let hash = hasher.finish();
        let jitter_factor = 0.9 + (hash % 2001) as f64 / 10000.0;
        (base_secs as f64 * jitter_factor).round() as u64
    }
}

fn map_err(e: crate::error::GarrisonError) -> oxcache::error::OxCacheError {
    oxcache::error::OxCacheError::BackendError(format!("garrison-dao-cache::{}", e))
}

#[async_trait]
impl CacheReader for GarrisonDaoCacheBackend {
    async fn get(&self, key: &str) -> oxcache::error::OxCacheResult<Option<Vec<u8>>> {
        Ok(self
            .dao
            .get(key)
            .await
            .map_err(map_err)?
            .map(|s| s.into_bytes()))
    }

    async fn exists(&self, key: &str) -> oxcache::error::OxCacheResult<bool> {
        Ok(self.dao.get(key).await.map_err(map_err)?.is_some())
    }

    async fn ttl(&self, _key: &str) -> oxcache::error::OxCacheResult<Option<Duration>> {
        // DAO 不暴露剩余 TTL（见模块文档：与 set 的钉定策略自洽）
        Ok(None)
    }

    async fn len(&self) -> oxcache::error::OxCacheResult<u64> {
        // 不提供计数（见模块文档）；链的 len/is_empty/capacity 取首链（L1）
        Ok(0)
    }

    async fn capacity(&self) -> oxcache::error::OxCacheResult<u64> {
        // L2 持久层无容量上限（TTL 自然过期为唯一回收机制）
        Ok(0)
    }

    async fn stats(
        &self,
    ) -> oxcache::error::OxCacheResult<std::collections::HashMap<String, String>> {
        // DAO 后端不维护计数器；stats 为空映射（诊断走 L1 内存后端）
        Ok(std::collections::HashMap::new())
    }
}

#[async_trait]
impl CacheWriter for GarrisonDaoCacheBackend {
    async fn set(
        &self,
        key: Arc<str>,
        value: Arc<Vec<u8>>,
        _ttl: Option<Duration>,
    ) -> oxcache::error::OxCacheResult<()> {
        // TTL 策略钉定：忽略链传入 TTL，按 L2 基础 TTL + 抖动落盘
        let ttl = self.l2_ttl_with_jitter(L2_BASE_TTL_SECS);
        let text = String::from_utf8(value.as_ref().clone()).map_err(|e| {
            oxcache::error::OxCacheError::Serialization(format!(
                "garrison-dao-cache-value-not-utf8::{}",
                e
            ))
        })?;
        self.dao.set(&key, &text, ttl).await.map_err(map_err)
    }

    async fn delete(&self, key: &str) -> oxcache::error::OxCacheResult<()> {
        self.dao.delete(key).await.map_err(map_err)
    }

    async fn clear(&self) -> oxcache::error::OxCacheResult<()> {
        // 按前缀枚举删除（DAO 无全量清除原语）；keys 不可用时显性失败
        for prefix in &self.clear_prefixes {
            let keys = self
                .dao
                .keys(&format!("{}*", prefix))
                .await
                .map_err(map_err)?;
            for key in keys {
                self.dao.delete(&key).await.map_err(map_err)?;
            }
        }
        Ok(())
    }

    async fn expire(&self, key: &str, ttl: Duration) -> oxcache::error::OxCacheResult<bool> {
        let existed = self.dao.get(key).await.map_err(map_err)?.is_some();
        if existed {
            self.dao.expire(key, ttl.as_secs()).await.map_err(map_err)?;
        }
        Ok(existed)
    }
}

#[async_trait]
impl CacheConnector for GarrisonDaoCacheBackend {
    async fn health_check(&self) -> oxcache::error::OxCacheResult<()> {
        Ok(())
    }

    async fn shutdown(&self) {}

    fn backend_kind(&self) -> BackendKind {
        BackendKind::Unknown
    }
}

impl BackendScore for GarrisonDaoCacheBackend {
    fn score(&self) -> u8 {
        L2_BACKEND_SCORE
    }

    fn is_persistent(&self) -> bool {
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use std::time::Duration;

    fn make_backend() -> GarrisonDaoCacheBackend {
        GarrisonDaoCacheBackend::new(
            Arc::new(MockDao::new()),
            GarrisonDaoCacheBackend::cache_clear_prefixes(),
        )
    }

    /// get/set/delete 往返 garrison MockDao（字节透明）。
    #[tokio::test]
    async fn backend_get_set_delete_roundtrip() {
        let backend = make_backend();
        let key: Arc<str> = Arc::from("perm:cache:u1");
        let value: Arc<Vec<u8>> = Arc::new(br#"["read"]"#.to_vec());

        assert!(backend.get("perm:cache:u1").await.unwrap().is_none());
        assert!(!backend.exists("perm:cache:u1").await.unwrap());

        backend
            .set(key.clone(), value.clone(), Some(Duration::from_secs(1)))
            .await
            .unwrap();
        assert_eq!(
            backend.get("perm:cache:u1").await.unwrap(),
            Some(br#"["read"]"#.to_vec()),
            "get 应原样返回写入的字节"
        );
        assert!(backend.exists("perm:cache:u1").await.unwrap());

        backend.delete("perm:cache:u1").await.unwrap();
        assert!(backend.get("perm:cache:u1").await.unwrap().is_none());
    }

    /// set 钉定 L2 TTL：链传入 1s TTL 被忽略，2s 后条目仍在（钉定 ~300s 生效）。
    #[tokio::test]
    async fn backend_set_pins_l2_ttl_ignoring_chain_ttl() {
        let backend = make_backend();
        backend
            .set(
                Arc::from("perm:cache:ttl-pin"),
                Arc::new(b"v".to_vec()),
                Some(Duration::from_secs(1)),
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(2100)).await;
        assert!(
            backend.get("perm:cache:ttl-pin").await.unwrap().is_some(),
            "链传入 TTL 应被忽略（L2 钉定 ~300s）"
        );
    }

    /// ttl() 恒 None（DAO 不暴露剩余 TTL）；len() 为 0（不提供计数）。
    #[tokio::test]
    async fn backend_ttl_none_and_len_zero() {
        let backend = make_backend();
        backend
            .set(Arc::from("k"), Arc::new(b"v".to_vec()), None)
            .await
            .unwrap();
        assert_eq!(backend.ttl("k").await.unwrap(), None);
        assert_eq!(backend.len().await.unwrap(), 0);
    }

    /// clear() 按前缀枚举删除，不影响范围外 key。
    #[tokio::test]
    async fn backend_clear_by_prefix_scope() {
        let backend = make_backend();
        for key in ["perm:cache:a", "role:cache:a", "user:cache:a", "other:keep"] {
            backend
                .set(Arc::from(key), Arc::new(b"v".to_vec()), None)
                .await
                .unwrap();
        }
        backend.clear().await.unwrap();
        assert!(backend.get("perm:cache:a").await.unwrap().is_none());
        assert!(backend.get("role:cache:a").await.unwrap().is_none());
        assert!(backend.get("user:cache:a").await.unwrap().is_none());
        assert!(
            backend.get("other:keep").await.unwrap().is_some(),
            "clear 不得删除前缀范围外的 key"
        );
    }

    /// 分数与持久性：低分 + 持久（链序中排在 L1 内存后端之后）。
    #[test]
    fn backend_score_and_persistence() {
        let backend = make_backend();
        assert!(backend.score() < 50, "L2 持久层应为低分");
        assert!(backend.is_persistent(), "DAO 后端为持久层");
        assert_eq!(backend.backend_kind(), BackendKind::Unknown);
    }

    /// 非 UTF-8 值拒绝（DAO 只存字符串，显性失败不静默替换）。
    #[tokio::test]
    async fn backend_rejects_non_utf8_value() {
        let backend = make_backend();
        let result = backend
            .set(Arc::from("k"), Arc::new(vec![0xff, 0xfe]), None)
            .await;
        assert!(
            matches!(result, Err(oxcache::error::OxCacheError::Serialization(_))),
            "非 UTF-8 值应返回 Serialization 错误，实际: {:?}",
            result
        );
    }

    // 链级行为（ChainCache：L1 测试内存后端 + L2 DAO 后端）

    use oxcache::cache::{ChainCache, ChainLink};
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// 测试专用 L1 内存后端（高分、非持久）——链级行为测试的 L1 替身
    /// （oxcache 的内存后端均 feature 门控，测试面自持最小实现钉链契约）。
    #[derive(Clone)]
    struct TestMemoryBackend {
        data: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl TestMemoryBackend {
        fn new() -> Self {
            Self {
                data: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    #[async_trait]
    impl CacheReader for TestMemoryBackend {
        async fn get(&self, key: &str) -> oxcache::error::OxCacheResult<Option<Vec<u8>>> {
            Ok(self.data.lock().unwrap().get(key).cloned())
        }
        async fn exists(&self, key: &str) -> oxcache::error::OxCacheResult<bool> {
            Ok(self.data.lock().unwrap().contains_key(key))
        }
        async fn ttl(&self, _key: &str) -> oxcache::error::OxCacheResult<Option<Duration>> {
            Ok(None)
        }
        async fn len(&self) -> oxcache::error::OxCacheResult<u64> {
            Ok(self.data.lock().unwrap().len() as u64)
        }
        async fn capacity(&self) -> oxcache::error::OxCacheResult<u64> {
            Ok(0)
        }
        async fn stats(&self) -> oxcache::error::OxCacheResult<HashMap<String, String>> {
            Ok(HashMap::new())
        }
    }

    #[async_trait]
    impl CacheWriter for TestMemoryBackend {
        async fn set(
            &self,
            key: Arc<str>,
            value: Arc<Vec<u8>>,
            _ttl: Option<Duration>,
        ) -> oxcache::error::OxCacheResult<()> {
            self.data
                .lock()
                .unwrap()
                .insert(key.to_string(), value.as_ref().clone());
            Ok(())
        }
        async fn delete(&self, key: &str) -> oxcache::error::OxCacheResult<()> {
            self.data.lock().unwrap().remove(key);
            Ok(())
        }
        async fn clear(&self) -> oxcache::error::OxCacheResult<()> {
            self.data.lock().unwrap().clear();
            Ok(())
        }
        async fn expire(&self, _key: &str, _ttl: Duration) -> oxcache::error::OxCacheResult<bool> {
            Ok(true)
        }
    }

    #[async_trait]
    impl CacheConnector for TestMemoryBackend {
        async fn health_check(&self) -> oxcache::error::OxCacheResult<()> {
            Ok(())
        }
        async fn shutdown(&self) {}
        fn backend_kind(&self) -> BackendKind {
            BackendKind::DashMap
        }
    }

    impl BackendScore for TestMemoryBackend {
        fn score(&self) -> u8 {
            90
        }
        fn is_persistent(&self) -> bool {
            false
        }
    }

    /// 组链：L1 测试内存后端（高分）+ L2 DAO 后端（低分持久），开回填。
    fn make_chain(l1: TestMemoryBackend, l2: GarrisonDaoCacheBackend) -> ChainCache {
        ChainCache::builder()
            .backend(l1)
            .backend(l2)
            .enable_backfill()
            .build()
    }

    /// L1 miss 降级读 L2：仅 L2 有值时链读返回该值。
    #[tokio::test]
    async fn chain_high_miss_falls_to_low() {
        let l1 = TestMemoryBackend::new();
        let l2 = make_backend();
        let chain = make_chain(l1.clone(), l2.clone());

        l2.set(Arc::from("k1"), Arc::new(b"v1".to_vec()), None)
            .await
            .unwrap();
        assert_eq!(
            chain.get("k1").await.unwrap(),
            Some(b"v1".to_vec()),
            "L1 miss 应降级读 L2"
        );
    }

    /// L2 命中自动回填 L1：链读后 L1 持有该值（删 L2 仍可命中 L1）。
    #[tokio::test]
    async fn chain_low_hit_backfills_high() {
        let l1 = TestMemoryBackend::new();
        let l2 = make_backend();
        let chain = make_chain(l1.clone(), l2.clone());

        l2.set(Arc::from("k2"), Arc::new(b"v2".to_vec()), None)
            .await
            .unwrap();
        assert!(chain.get("k2").await.unwrap().is_some(), "链读应命中 L2");

        assert_eq!(
            l1.get("k2").await.unwrap(),
            Some(b"v2".to_vec()),
            "L2 命中应自动回填 L1"
        );
        l2.delete("k2").await.unwrap();
        assert_eq!(
            chain.get("k2").await.unwrap(),
            Some(b"v2".to_vec()),
            "回填后删 L2，链读仍命中 L1"
        );
    }

    /// 链写穿透全部后端 + 链删清除双端。
    #[tokio::test]
    async fn chain_set_writes_all_and_delete_clears_both() {
        let l1 = TestMemoryBackend::new();
        let l2 = make_backend();
        let chain = make_chain(l1.clone(), l2.clone());

        chain.set("k3", b"v3".to_vec(), None).await.unwrap();
        assert!(l1.get("k3").await.unwrap().is_some(), "链写应穿透 L1");
        assert!(l2.get("k3").await.unwrap().is_some(), "链写应穿透 L2");

        chain.delete("k3").await.unwrap();
        assert!(l1.get("k3").await.unwrap().is_none(), "链删应清除 L1");
        assert!(l2.get("k3").await.unwrap().is_none(), "链删应清除 L2");
        assert!(chain.get("k3").await.unwrap().is_none(), "删除后链读 miss");
    }

    /// L2 后端以低分排在链尾（BackendScore 契约）。
    #[test]
    fn chain_link_orders_low_score_last() {
        let l1 = ChainLink::from_backend(TestMemoryBackend::new());
        let l2 = ChainLink::from_backend(make_backend());
        assert!(
            l1.score() > l2.score(),
            "L1 内存后端分数应高于 L2 DAO 后端（{} > {}）",
            l1.score(),
            l2.score()
        );
        assert!(l2.is_persistent() && !l1.is_persistent());
    }
}
