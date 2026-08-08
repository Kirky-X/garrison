//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 健康检查示例集成测试。

#![cfg(all(feature = "cache-memory", feature = "db-sqlite"))]

#[tokio::test]
async fn health_check_runs_successfully() {
    garrison_examples::infrastructure::health_check::run()
        .await
        .expect("health_check 示例应成功执行");
}
