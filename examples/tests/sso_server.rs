//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! sso_server 示例测试（protocol-sso-server feature）。
//!
//! 验证 run() 完整执行（内部已包含 issue/validate/converter/channel 断言）。

#![cfg(feature = "protocol-sso-server")]

use bulwark_examples::oauth2::sso_server;

#[tokio::test]
async fn test_run_completes() {
    sso_server::run().await.unwrap();
}
