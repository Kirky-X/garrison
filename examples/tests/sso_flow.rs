//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! sso_flow 示例测试（protocol-sso feature）。
//!
//! 验证 run() 完整执行（内部已包含 ticket issue/exchange/consume 断言）。

#![cfg(feature = "protocol-sso")]

use garrison_examples::oauth2::sso_flow;

#[tokio::test]
async fn test_run_completes() {
    sso_flow::run().await.unwrap();
}
