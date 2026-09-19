// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! token_styles 示例测试。
//!
//! 验证 run() 完整执行（内部已包含 token 风格切换断言）。

use garrison_examples::authorization::token_styles;

#[test]
fn test_run_completes() {
    token_styles::run().unwrap();
}
