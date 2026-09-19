// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! permission_check 示例测试。
//!
//! 验证 run() 完整执行（内部已包含权限/角色校验断言）。

use garrison_examples::authorization::permission_check;

#[tokio::test]
async fn test_run_completes() {
    permission_check::run().await.unwrap();
}
