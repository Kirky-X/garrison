//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! auth_logic_impl 示例测试。
//!
//! 验证 run() 完整执行（内部已包含 login/logout 断言）。

use garrison_examples::extension::auth_logic_impl;

#[tokio::test]
async fn test_run_completes() {
    auth_logic_impl::run().await.unwrap();
}
