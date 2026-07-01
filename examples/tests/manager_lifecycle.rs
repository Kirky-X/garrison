//! manager_lifecycle 示例测试（cache-memory + web-axum feature）。
//!
//! 验证 run() 完整执行（内部已包含 login/check_login/kickout/logout 断言）。
//!
//! 注意：manager_lifecycle 调用 `BulwarkManager::init` 注入全局单例，
//! 多测试并行会竞争全局状态，必须用 #[serial] 串行执行。

#![cfg(all(feature = "cache-memory", feature = "web-axum"))]

use bulwark_examples::manager_lifecycle;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_run_completes() {
    manager_lifecycle::run().await.unwrap();
}
