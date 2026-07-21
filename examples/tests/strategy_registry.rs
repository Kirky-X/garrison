//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! strategy_registry 示例测试（cache-memory feature）。
//!
//! 验证 run() 完整执行：6 策略 register/get/remove + 自定义实现演示。

#![cfg(feature = "cache-memory")]

use garrison_examples::authorization::strategy_registry;

#[tokio::test(flavor = "multi_thread")]
async fn test_run_completes() {
    strategy_registry::run().await.unwrap();
}
