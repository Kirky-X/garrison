//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! cache_redis 示例（cache-redis feature）。
//!
//! 演示 Redis L2 后端配置：
//! 1. `BulwarkDaoOxcache::new()` 默认 L1(moka) DAO（无需 Redis 连接）
//! 2. `oxcache::backend::RedisBackend::builder()` Redis L2 后端配置
//! 3. `oxcache::Cache::builder().backend_arc(...)` 组合 L1+L2 多级缓存
//! 4. `BulwarkDao` trait 操作（get/set/update/expire/delete）
//!
//! 运行方式（需要 Redis 实例运行）：
//! ```sh
//! OXCACHE_ALLOW_INSECURE_REDIS=I_UNDERSTAND_THE_RISKS \
//! cargo run -p bulwark-examples --bin cache_redis --features cache-redis
//! ```
//!
//! 注：Redis 连接需要 TLS（`rediss://`），开发环境可设置环境变量
//! `OXCACHE_ALLOW_INSECURE_REDIS=I_UNDERSTAND_THE_RISKS` 允许非 TLS 连接。

use bulwark::dao::{BulwarkDao, BulwarkDaoOxcache};
use std::sync::Arc;

/// 默认 Redis 连接字符串（开发环境）。
const DEFAULT_REDIS_URL: &str = "redis://127.0.0.1:6379";

/// 创建默认的 L1(moka) DAO 实例（无需 Redis 连接）。
///
/// `BulwarkDaoOxcache::new()` 内部使用 `oxcache::Cache::builder().sync_mode(true).build()`，
/// 仅启用 L1 moka 内存缓存，适合开发/测试环境。
pub async fn create_l1_dao() -> BulwarkDaoOxcache {
    BulwarkDaoOxcache::new()
        .await
        .expect("BulwarkDaoOxcache L1 初始化失败")
}

/// 构造 Redis L2 后端配置（不实际连接）。
///
/// 返回 `RedisBackendBuilder`，调用方可在 `build().await` 时实际连接。
/// 生产环境应使用 `rediss://` 前缀（TLS 加密）。
pub fn build_redis_l2_config() -> oxcache::backend::RedisBackendBuilder {
    oxcache::backend::RedisBackend::builder().connection_string(DEFAULT_REDIS_URL)
}

/// 创建组合 L1(moka) + L2(redis) 的多级缓存（需要 Redis 实例运行）。
///
/// 注：`sync_mode(true)` + `backend_arc()` 不兼容（oxcache 0.3 限制），
/// 此函数使用 async API（无 sync_mode）。
pub async fn create_tiered_cache(
) -> Result<oxcache::Cache<String, String>, Box<dyn std::error::Error>> {
    let redis_backend = build_redis_l2_config().build().await?;
    let cache: oxcache::Cache<String, String> = oxcache::Cache::builder()
        .backend_arc(Arc::new(redis_backend))
        .build()
        .await?;
    Ok(cache)
}

/// 演示 BulwarkDao 操作（通过 L1 moka DAO，无需 Redis）。
///
/// 展示完整的 CRUD + TTL 流程：
/// 1. set + get
/// 2. update（保留 TTL）
/// 3. expire（更新 TTL）
/// 4. delete
pub async fn demo_dao_operations(
    dao: &BulwarkDaoOxcache,
) -> Result<(), Box<dyn std::error::Error>> {
    // set + get
    dao.set("user:1001", "alice", 3600).await?;
    let value = dao.get("user:1001").await?;
    assert_eq!(value.as_deref(), Some("alice"));

    // update（保留 TTL）
    dao.update("user:1001", "bob").await?;
    let updated = dao.get("user:1001").await?;
    assert_eq!(updated.as_deref(), Some("bob"));

    // expire（更新 TTL 为 60 秒）
    dao.expire("user:1001", 60).await?;

    // delete
    dao.delete("user:1001").await?;
    let deleted = dao.get("user:1001").await?;
    assert!(deleted.is_none());

    Ok(())
}

/// 运行 cache_redis 示例。
///
/// 演示 Redis L2 后端配置 + L1 moka DAO 操作：
/// 1. 创建 L1 moka DAO 并演示 CRUD
/// 2. 展示 Redis L2 后端配置（不实际连接）
/// 3. 说明 L1+L2 多级缓存组合方式
pub async fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Bulwark cache-redis Redis L2 后端示例 ===\n");

    // ----------------------------------------------------------------
    // 1. L1 moka DAO（无需 Redis）
    // ----------------------------------------------------------------
    println!("[L1] BulwarkDaoOxcache::new()（L1 moka，无需 Redis）:");
    let dao = create_l1_dao().await;
    println!("    创建 L1 moka DAO 实例成功");
    println!();

    println!("[CRUD] 演示 BulwarkDao 操作:");
    demo_dao_operations(&dao).await?;
    println!("    set(\"user:1001\", \"alice\", 3600)     → Ok");
    println!("    get(\"user:1001\")                    → Some(\"alice\")");
    println!("    update(\"user:1001\", \"bob\")          → Ok（保留 TTL）");
    println!("    get(\"user:1001\")                    → Some(\"bob\")");
    println!("    expire(\"user:1001\", 60)             → Ok（更新 TTL）");
    println!("    delete(\"user:1001\")                 → Ok");
    println!("    get(\"user:1001\")                    → None（已删除）");
    println!();

    // ----------------------------------------------------------------
    // 2. Redis L2 后端配置
    // ----------------------------------------------------------------
    println!("[L2] RedisBackend 配置:");
    let _builder = build_redis_l2_config();
    println!("    RedisBackend::builder()");
    println!("        .connection_string(\"{}\")", DEFAULT_REDIS_URL);
    println!("        .build().await  → 连接 Redis（需实例运行）");
    println!();

    println!("    注：Redis 连接需要 TLS（rediss://），开发环境可设置:");
    println!("        OXCACHE_ALLOW_INSECURE_REDIS=I_UNDERSTAND_THE_RISKS");
    println!();

    // ----------------------------------------------------------------
    // 3. L1+L2 多级缓存组合
    // ----------------------------------------------------------------
    println!("[Tiered] L1(moka) + L2(redis) 多级缓存组合:");
    println!("    // 1. 创建 Redis L2 后端");
    println!("    let redis = RedisBackend::builder()");
    println!("        .connection_string(\"rediss://localhost:6379\")");
    println!("        .build().await?;");
    println!();
    println!("    // 2. 组合为多级 Cache（async API，不支持 sync_mode）");
    println!("    let cache: Cache<String, String> = Cache::builder()");
    println!("        .backend_arc(Arc::new(redis))");
    println!("        .build().await?;");
    println!();
    println!("    限制：sync_mode(true) + backend_arc() 不兼容（oxcache 0.3）");
    println!("    BulwarkDaoOxcache 使用 sync_mode，因此仅支持 L1 moka。");
    println!("    如需 L2 Redis，需直接使用 oxcache async API。");
    println!();

    // ----------------------------------------------------------------
    // 4. 尝试实际连接 Redis（可选，失败不报错）
    // ----------------------------------------------------------------
    println!("[连接] 尝试连接 Redis（可选）:");
    match create_tiered_cache().await {
        Ok(_cache) => {
            println!("    Redis 连接成功，L1+L2 多级缓存已创建");
        },
        Err(e) => {
            println!("    Redis 连接失败（预期行为，需 Redis 实例运行）:");
            println!("    错误: {}", e);
            println!("    这不影响 L1 moka DAO 的正常使用");
        },
    }
    println!();

    println!("=== 示例完成 ===");
    Ok(())
}
