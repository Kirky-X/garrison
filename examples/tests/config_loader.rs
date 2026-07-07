//! config_loader 示例测试。
//!
//! 验证 run() 完整执行（内部已包含配置加载断言）。
//!
//! 注意：config_loader 使用 `std::env::set_var`，多测试并行会污染进程级环境变量，
//! 必须用 #[serial] 保证串行执行。

use bulwark_examples::infrastructure::config_loader;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn test_run_completes() {
    config_loader::run().await.unwrap();
}
