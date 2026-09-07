//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! v0_5_0_demo 示例测试（tenant-isolation + audit-log + core-advanced + keycloak-oidc + social-wechat + db-sqlite + cache-memory feature）。
//!
//! 验证 run() 完整执行（内存 SQLite + oxcache 内存 DAO，无需外部依赖）。

#![cfg(all(
    feature = "tenant-isolation",
    feature = "audit-log",
    feature = "core-advanced",
    feature = "keycloak-oidc",
    feature = "social-wechat",
    feature = "db-sqlite",
    feature = "cache-memory"
))]

use garrison_examples::demo::v0_5_0_demo;

#[tokio::test(flavor = "multi_thread")]
async fn test_run_completes() {
    v0_5_0_demo::run().await.unwrap();
}
