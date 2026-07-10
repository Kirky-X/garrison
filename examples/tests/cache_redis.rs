//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! cache_redis 示例测试（cache-redis feature）。
//!
//! 验证 BulwarkDaoOxcache L1 moka DAO 操作 + Redis L2 配置：
//! - `BulwarkDaoOxcache::new()` 创建 L1 DAO
//! - get/set/update/expire/delete CRUD 操作
//! - `RedisBackend::builder()` 配置构造
//!
//! 注：实际 Redis 连接测试标记为 `#[ignore]`（需要 Redis 实例运行）。
//! L1 moka DAO 测试可独立运行（无需 Redis）。

#![cfg(feature = "cache-redis")]

use bulwark::dao::BulwarkDao;
use serial_test::serial;

/// 测试 BulwarkDaoOxcache::new() 创建 L1 moka DAO（无需 Redis）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_create_l1_dao() {
    let dao = bulwark_examples::infrastructure::cache_redis::create_l1_dao().await;
    // 不 panic 即通过
    drop(dao);
}

/// 测试 set + get 基本操作。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_dao_set_get() {
    let dao = bulwark_examples::infrastructure::cache_redis::create_l1_dao().await;
    dao.set("test:key1", "value1", 3600).await.unwrap();
    let value = dao.get("test:key1").await.unwrap();
    assert_eq!(value.as_deref(), Some("value1"));
    dao.delete("test:key1").await.unwrap();
}

/// 测试 update 更新值。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_dao_update() {
    let dao = bulwark_examples::infrastructure::cache_redis::create_l1_dao().await;
    dao.set("test:update", "old", 3600).await.unwrap();
    dao.update("test:update", "new").await.unwrap();
    let value = dao.get("test:update").await.unwrap();
    assert_eq!(value.as_deref(), Some("new"));
    dao.delete("test:update").await.unwrap();
}

/// 测试 update 不存在的键返回错误。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_dao_update_missing_key_errors() {
    let dao = bulwark_examples::infrastructure::cache_redis::create_l1_dao().await;
    let result = dao.update("nonexistent:key", "value").await;
    assert!(result.is_err(), "更新不存在的键应返回错误");
}

/// 测试 expire 更新 TTL。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_dao_expire() {
    let dao = bulwark_examples::infrastructure::cache_redis::create_l1_dao().await;
    dao.set("test:expire", "value", 3600).await.unwrap();
    dao.expire("test:expire", 60).await.unwrap();
    // 验证键仍存在（expire 不删除值）
    let value = dao.get("test:expire").await.unwrap();
    assert_eq!(value.as_deref(), Some("value"));
    dao.delete("test:expire").await.unwrap();
}

/// 测试 expire 不存在的键返回错误。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_dao_expire_missing_key_errors() {
    let dao = bulwark_examples::infrastructure::cache_redis::create_l1_dao().await;
    let result = dao.expire("nonexistent:key", 60).await;
    assert!(result.is_err(), "expire 不存在的键应返回错误");
}

/// 测试 delete 删除键。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_dao_delete() {
    let dao = bulwark_examples::infrastructure::cache_redis::create_l1_dao().await;
    dao.set("test:delete", "value", 3600).await.unwrap();
    dao.delete("test:delete").await.unwrap();
    let value = dao.get("test:delete").await.unwrap();
    assert!(value.is_none(), "删除后 get 应返回 None");
}

/// 测试 delete 不存在的键不报错（幂等）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_dao_delete_missing_key_idempotent() {
    let dao = bulwark_examples::infrastructure::cache_redis::create_l1_dao().await;
    // delete 不存在的键应返回 Ok（幂等）
    let result = dao.delete("nonexistent:delete").await;
    assert!(result.is_ok(), "delete 不存在的键应幂等返回 Ok");
}

/// 测试 get 不存在的键返回 None。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_dao_get_missing_key_returns_none() {
    let dao = bulwark_examples::infrastructure::cache_redis::create_l1_dao().await;
    let value = dao.get("nonexistent:get").await.unwrap();
    assert!(value.is_none(), "get 不存在的键应返回 None");
}

/// 测试 demo_dao_operations 完整流程。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_demo_dao_operations() {
    let dao = bulwark_examples::infrastructure::cache_redis::create_l1_dao().await;
    bulwark_examples::infrastructure::cache_redis::demo_dao_operations(&dao)
        .await
        .expect("demo_dao_operations 应成功完成");
}

/// 测试 RedisBackend builder 配置构造（不实际连接）。
#[test]
fn test_build_redis_l2_config() {
    let builder = bulwark_examples::infrastructure::cache_redis::build_redis_l2_config();
    // builder 构造成功即可（不调用 build 避免实际连接）
    drop(builder);
}

/// 测试实际 Redis 连接 + L1+L2 多级缓存（需要 Redis 实例运行）。
///
/// 运行方式：
/// ```sh
/// OXCACHE_ALLOW_INSECURE_REDIS=I_UNDERSTAND_THE_RISKS \
/// cargo test -p bulwark-examples --test cache_redis --features cache-redis -- --ignored
/// ```
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[ignore = "需要 Redis 实例运行，设置 OXCACHE_ALLOW_INSECURE_REDIS=I_UNDERSTAND_THE_RISKS"]
async fn test_create_tiered_cache_with_redis() {
    let cache = bulwark_examples::infrastructure::cache_redis::create_tiered_cache()
        .await
        .expect("Redis 连接失败，请确保 Redis 实例运行");
    // 验证 cache 可用（Cache 类型提供 inherent async 方法 set/get/delete）
    cache
        .set(&"tiered:test".to_string(), &"value".to_string())
        .await
        .expect("set 失败");
    let value = cache
        .get(&"tiered:test".to_string())
        .await
        .expect("get 失败");
    assert_eq!(value.as_deref(), Some("value"));
    cache
        .delete(&"tiered:test".to_string())
        .await
        .expect("delete 失败");
}
