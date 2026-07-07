//! alone_cache 示例测试（alone-cache feature）。
//!
//! 验证 run() 完整执行（内部已包含 prefix 拼接 + tenant 隔离断言）。

#![cfg(feature = "alone-cache")]

use bulwark_examples::infrastructure::alone_cache;

#[tokio::test]
async fn test_run_completes() {
    alone_cache::run().await.unwrap();
}
