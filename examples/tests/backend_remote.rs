//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! backend_remote 示例测试。
//!
//! 验证 run() 完整执行（内部对 Network 错误做了预期处理，不会 panic）。

#![cfg(feature = "backend-remote")]

use bulwark_examples::infrastructure::backend_remote;

#[tokio::test]
async fn test_run_completes() {
    backend_remote::run().await.unwrap();
}
