// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! config_loader 示例测试：验证 run() 完整执行（内部已包含配置加载断言）；示例用
//! `std::env::set_var`，多测试并行污染进程级环境变量，必须 #[serial] 串行执行。

use garrison_examples::infrastructure::config_loader;
use serial_test::serial;

#[tokio::test]
#[serial]
async fn test_run_completes() {
    config_loader::run().await.unwrap();
}
