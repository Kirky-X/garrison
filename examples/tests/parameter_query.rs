//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! parameter_query 示例测试（parameter-query feature）。
//!
//! 验证 run() 完整执行（内部已包含 with_login_id / with_token / 无上下文断言）。
//!
//! 使用 `#[serial_test::serial]` 串行化，因为 `run()` 修改全局 `BulwarkManager` 单例
//! （调用 `reset_for_test` + `init`），并行执行会触发 race condition。

#![cfg(feature = "parameter-query")]

use bulwark_examples::infrastructure::parameter_query;

#[tokio::test]
#[serial_test::serial]
async fn test_run_completes() {
    parameter_query::run().await.unwrap();
}
