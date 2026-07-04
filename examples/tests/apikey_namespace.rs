//! apikey_namespace 示例测试（protocol-apikey + cache-memory feature）。
//!
//! 验证 run() 完整执行：多租户 namespace + 跨 namespace 隔离。

#![cfg(all(feature = "protocol-apikey", feature = "cache-memory"))]

use bulwark_examples::apikey_namespace;

#[tokio::test(flavor = "multi_thread")]
async fn test_run_completes() {
    apikey_namespace::run().await.unwrap();
}
