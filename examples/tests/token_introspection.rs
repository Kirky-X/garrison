//! token_introspection 示例测试（protocol-oauth2 feature）。
//!
//! 验证 run() 完整执行：RFC 7662 introspection + URL 推导 + 反序列化示例。

#![cfg(feature = "protocol-oauth2")]

use bulwark_examples::token_introspection;

#[tokio::test]
async fn test_run_completes() {
    token_introspection::run().await.unwrap();
}
