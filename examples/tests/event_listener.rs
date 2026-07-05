//! event_listener 示例测试（listener feature）。
//!
//! 验证 run() 完整执行（内部已包含 listener 注册与计数器断言）。
//!
//! 注意：event_listener 使用 `inventory::submit!` 注册 listener，
//! 静态计数器为全局状态，但本测试只验证 run() 完成，不直接读取计数器。

#![cfg(feature = "listener")]

use bulwark_examples::event_listener;

#[tokio::test]
async fn test_run_completes() {
    event_listener::run().await.unwrap();
}
