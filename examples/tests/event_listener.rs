// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! event_listener 示例测试（listener feature）：验证 run() 完整执行（内部已包含 listener 注册与
//! 计数器断言）；用 `inventory::submit!` 注册 listener，静态计数器为全局状态，但本测试只验证
//! run() 完成、不直接读取计数器，并行竞争无影响。

#![cfg(feature = "listener")]

use garrison_examples::extension::event_listener;

#[tokio::test]
async fn test_run_completes() {
    event_listener::run().await.unwrap();
}
