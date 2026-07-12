//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! token_styles 示例测试。
//!
//! 验证 run() 完整执行（内部已包含 token 风格切换断言）。

use bulwark_examples::authorization::token_styles;

#[test]
fn test_run_completes() {
    token_styles::run().unwrap();
}
