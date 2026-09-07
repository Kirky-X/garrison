//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! credit_metering 示例测试（credit-metering + cache-memory feature）。
//!
//! 验证 run() 完整执行（内部演示消费/查询/告警/重置全流程）。

#![cfg(all(feature = "credit-metering", feature = "cache-memory"))]

use garrison_examples::infrastructure::credit_metering;

#[tokio::test(flavor = "multi_thread")]
async fn test_run_completes() {
    credit_metering::run().await.unwrap();
}
