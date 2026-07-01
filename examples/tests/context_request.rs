//! context_request 示例测试（web-axum feature）。
//!
//! 验证 run() 完整执行（内部已包含 token 提取、Cookie 设置、Bearer 大小写断言）。
//!
//! 注意：context_request 不使用 BulwarkManager 全局单例，无需 #[serial]。

#![cfg(feature = "web-axum")]

use bulwark_examples::context_request;

#[tokio::test]
async fn test_run_completes() {
    context_request::run().await.unwrap();
}
