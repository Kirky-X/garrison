//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! AloneCache 多 Redis 实例隔离示例（依据 spec alone-cache，0.4.0 新增）。
//!
//! 演示 `AloneCache` 装饰器 + `AloneCacheManager`：
//! 1. 创建 `InMemoryDao`（参考 sso_flow.rs 的实现模式）
//! 2. 包装为 `AloneCache::new(dao, "tenant-a:")` 装饰器
//! 3. 演示 set/get 时自动拼接 key_prefix
//! 4. 创建 `AloneCacheManager`，注册多个 tenant（tenant-a / tenant-b）
//! 5. 验证不同 tenant 的 key 隔离（相同 key 在不同 tenant 下互不干扰）
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin alone_cache --features alone-cache
//! ```

use async_trait::async_trait;
use bulwark::dao::alone_cache::{AloneCache, AloneCacheManager};
use bulwark::dao::BulwarkDao;
use bulwark::error::{BulwarkError, BulwarkResult};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// 最小化内存 DAO 实现（仅供示例，生产环境用 oxcache / dbnexus）。
///
/// `store` 内部为 `HashMap<String, (String, Option<Instant>)>`，
/// 通过 `Instant` 模拟 TTL 过期语义。
pub struct InMemoryDao {
    store: Mutex<HashMap<String, (String, Option<Instant>)>>,
}

impl InMemoryDao {
    /// 创建 InMemoryDao 实例。
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

impl Default for InMemoryDao {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl BulwarkDao for InMemoryDao {
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

/// 运行 AloneCache 示例。
///
/// 演示 AloneCache 装饰器的 key prefix 拼接 + AloneCacheManager 多 tenant 隔离。
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Bulwark AloneCache 多 Redis 实例隔离示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 创建 InMemoryDao 并包装为 AloneCache 装饰器
    // ----------------------------------------------------------------
    let dao: Arc<dyn BulwarkDao> = Arc::new(InMemoryDao::new());
    let cache = AloneCache::new(dao.clone(), "tenant-a:");

    println!("[配置] AloneCache::new(dao, \"tenant-a:\")");
    println!("    所有 key 自动拼接前缀 \"tenant-a:\"\n");

    // ----------------------------------------------------------------
    // 2. 演示 set/get 时自动拼接 key_prefix
    // ----------------------------------------------------------------
    cache.set("user:1001", "alice", 3600).await?;
    println!("[写入] cache.set(\"user:1001\", \"alice\")");

    // 通过 cache.get 读取（内部自动拼接 "tenant-a:user:1001"）
    let value = cache.get("user:1001").await?;
    println!("[读取] cache.get(\"user:1001\") → {:?}", value);
    assert_eq!(value.as_deref(), Some("alice"));

    // 验证内部 dao 实际存储的 key 是带前缀的
    let raw = dao.get("tenant-a:user:1001").await?;
    println!(
        "[验证] dao.get(\"tenant-a:user:1001\") → {:?}（内部 key 带前缀）",
        raw
    );
    assert_eq!(raw.as_deref(), Some("alice"));

    // 验证无前缀的 key 不存在（AloneCache 的 key 空间隔离）
    let missing = dao.get("user:1001").await?;
    println!(
        "[验证] dao.get(\"user:1001\") → {:?}（无前缀 key 不存在）",
        missing
    );
    assert!(missing.is_none());

    // ----------------------------------------------------------------
    // 3. 创建 AloneCacheManager，注册多个 tenant
    // ----------------------------------------------------------------
    println!("\n[Manager] AloneCacheManager 多 tenant 隔离:");

    let manager = AloneCacheManager::new();
    // tenant-a 使用独立的 dao（与上面区分）
    let dao_a: Arc<dyn BulwarkDao> = Arc::new(InMemoryDao::new());
    let dao_b: Arc<dyn BulwarkDao> = Arc::new(InMemoryDao::new());

    manager.register("tenant-a", AloneCache::new(dao_a.clone(), "tenant-a:"));
    manager.register("tenant-b", AloneCache::new(dao_b.clone(), "tenant-b:"));
    println!("    注册 tenant-a（prefix=\"tenant-a:\"）");
    println!("    注册 tenant-b（prefix=\"tenant-b:\"）\n");

    let cache_a = manager.get("tenant-a").expect("tenant-a 应已注册");
    let cache_b = manager.get("tenant-b").expect("tenant-b 应已注册");

    // ----------------------------------------------------------------
    // 4. 验证不同 tenant 的 key 隔离
    // ----------------------------------------------------------------
    println!("[隔离] 相同 key 在不同 tenant 下互不干扰:");

    // 两个 tenant 写入相同 key，不同值
    cache_a.set("config:timeout", "30", 3600).await?;
    cache_b.set("config:timeout", "60", 3600).await?;
    println!("    tenant-a.set(\"config:timeout\", \"30\")");
    println!("    tenant-b.set(\"config:timeout\", \"60\")");

    // 读取各自 tenant 的值
    let val_a = cache_a.get("config:timeout").await?;
    let val_b = cache_b.get("config:timeout").await?;
    println!("    tenant-a.get(\"config:timeout\") → {:?}", val_a);
    println!("    tenant-b.get(\"config:timeout\") → {:?}", val_b);
    assert_eq!(val_a.as_deref(), Some("30"));
    assert_eq!(val_b.as_deref(), Some("60"));
    assert_ne!(val_a, val_b, "不同 tenant 的相同 key 值应不同");

    // 交叉验证：dao_a 只有 "tenant-a:config:timeout"，dao_b 只有 "tenant-b:config:timeout"
    let cross_a = dao_a.get("tenant-b:config:timeout").await?;
    let cross_b = dao_b.get("tenant-a:config:timeout").await?;
    assert!(cross_a.is_none(), "dao_a 不应包含 tenant-b 的 key");
    assert!(cross_b.is_none(), "dao_b 不应包含 tenant-a 的 key");
    println!("    交叉验证：dao_a 无 tenant-b 的 key，dao_b 无 tenant-a 的 key ✓");

    // ----------------------------------------------------------------
    // 5. unregister 后 get 返回 None
    // ----------------------------------------------------------------
    println!("\n[注销] unregister 后 get 返回 None:");
    let removed = manager.unregister("tenant-a");
    assert!(removed.is_some(), "unregister 应返回被移除的实例");
    assert!(
        manager.get("tenant-a").is_none(),
        "unregister 后 get 应返回 None"
    );
    println!("    unregister(\"tenant-a\") → Some（已移除）");
    println!("    get(\"tenant-a\") → None ✓");

    println!("\n=== 示例完成 ===");
    Ok(())
}
