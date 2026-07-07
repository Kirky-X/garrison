//! sign_protocol 示例测试（protocol-sign feature）。
//!
//! 验证 run() 完整执行（内部已包含签名校验与 nonce replay 拒绝断言）。

#![cfg(feature = "protocol-sign")]

use bulwark_examples::sign::sign_protocol;

#[tokio::test]
async fn test_run_completes() {
    sign_protocol::run().await.unwrap();
}
