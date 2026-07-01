//! oauth2_flow 示例测试（protocol-oauth2 feature）。
//!
//! 验证 run() 完整执行（内部已包含授权 URL 与 token 交换断言）。

#![cfg(feature = "protocol-oauth2")]

use bulwark_examples::oauth2_flow;

#[tokio::test]
async fn test_run_completes() {
    oauth2_flow::run().await.unwrap();
}
