//! jwt_modes 示例测试（protocol-jwt + cache-memory feature）。
//!
//! 验证 run() 完整执行：JwtMode 三模式（Mixin/Stateless/Simple）+ JwtHandler 独立校验。

#![cfg(all(feature = "protocol-jwt", feature = "cache-memory"))]

use bulwark_examples::jwt_modes;

#[tokio::test(flavor = "multi_thread")]
async fn test_run_completes() {
    jwt_modes::run().await.unwrap();
}
