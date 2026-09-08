//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 健康检查示例集成测试。

#![cfg(all(
    feature = "cache-memory",
    feature = "db-sqlite",
    // 示例针对内存缓存后端（doc：`--features "cache-memory db-sqlite"`）；
    // cache-redis 启用时 CacheHealthCheck 探测真实 Redis 服务，无服务时正确地
    // 返回 Unhealthy——该场景属环境门控，不在此示例断言范围内。
    not(feature = "cache-redis")
))]

#[tokio::test]
async fn health_check_runs_successfully() {
    garrison_examples::infrastructure::health_check::run()
        .await
        .expect("health_check 示例应成功执行");
}
