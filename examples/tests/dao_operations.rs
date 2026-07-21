//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! dao_operations 示例测试（cache-memory feature）。
//!
//! 验证 run() 完整执行（内部已包含 set/get/update/expire/delete/TTL 断言）。

#![cfg(feature = "cache-memory")]

use garrison_examples::infrastructure::dao_operations;

#[tokio::test(flavor = "multi_thread")]
async fn test_run_completes() {
    dao_operations::run().await.unwrap();
}
