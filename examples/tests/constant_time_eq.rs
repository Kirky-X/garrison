//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! constant_time_eq 示例测试（secure-ct-eq feature）。
//!
//! 验证 run() 完整执行（内部已包含相等/不等/长度不等/空切片断言）。

#![cfg(feature = "secure-ct-eq")]

use garrison_examples::security::constant_time_eq;

#[tokio::test(flavor = "multi_thread")]
async fn test_run_completes() {
    constant_time_eq::run().await.unwrap();
}
