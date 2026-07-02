//! sso_server 示例测试（protocol-sso-server feature）。
//!
//! 验证 run() 完整执行（内部已包含 issue/validate/converter/channel 断言）。

#![cfg(feature = "protocol-sso-server")]

use bulwark_examples::sso_server;

#[tokio::test]
async fn test_run_completes() {
    sso_server::run().await.unwrap();
}
