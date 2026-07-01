//! custom_plugin 示例测试。
//!
//! 验证 run() 完整执行（内部已包含 plugin 注册与计数器断言）。
//!
//! 注意：custom_plugin 使用 `inventory::submit!` 在模块加载时注册 plugin，
//! 静态计数器为全局状态，多测试并行可能竞争 —— 但本测试只验证 run() 完成，
//! 不直接读取计数器，因此无需 #[serial]。

use bulwark_examples::custom_plugin;

#[test]
fn test_run_completes() {
    custom_plugin::run().unwrap();
}
