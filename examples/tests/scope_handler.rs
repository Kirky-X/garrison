//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! scope_handler 示例测试（oauth2-scope-handler feature）。
//!
//! 验证 run() 完整执行（内部已包含 registry 校验 + OAuth2Client 集成断言）。

#![cfg(feature = "oauth2-scope-handler")]

use garrison_examples::oauth2::scope_handler;

#[tokio::test]
async fn test_run_completes() {
    scope_handler::run().await.unwrap();
}
