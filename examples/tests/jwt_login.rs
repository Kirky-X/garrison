//! jwt_login 示例测试（protocol-jwt feature）。
//!
//! 验证 run() 完整执行（内部已包含 sign/verify/refresh 断言）。

#![cfg(feature = "protocol-jwt")]

use bulwark_examples::authentication::jwt_login;

#[tokio::test]
async fn test_run_completes() {
    jwt_login::run().await.unwrap();
}
