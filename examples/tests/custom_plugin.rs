// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! custom_plugin 示例测试：验证 run() 完整执行（内部已包含 plugin 注册与计数器断言）；用
//! `inventory::submit!` 在模块加载时注册 plugin，静态计数器为全局状态，但本测试只验证 run() 完成、
//! 不直接读取计数器，并行竞争无影响，无需 #[serial]。

use garrison_examples::extension::custom_plugin;

#[test]
fn test_run_completes() {
    custom_plugin::run().unwrap();
}
