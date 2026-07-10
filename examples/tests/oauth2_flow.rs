//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! oauth2_flow 示例测试（protocol-oauth2 feature）。
//!
//! 验证 run() 完整执行（内部已包含授权 URL 与 token 交换断言）。

#![cfg(feature = "protocol-oauth2")]

use bulwark_examples::oauth2::oauth2_flow;

#[tokio::test]
async fn test_run_completes() {
    oauth2_flow::run().await.unwrap();
}
