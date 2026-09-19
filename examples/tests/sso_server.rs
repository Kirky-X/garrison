// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! sso_server 示例测试（protocol-sso-server feature）。
//!
//! 验证 run() 完整执行（内部已包含 issue/validate/converter/channel 断言）。

#![cfg(feature = "protocol-sso-server")]

use garrison_examples::oauth2::sso_server;

#[tokio::test]
async fn test_run_completes() {
    sso_server::run().await.unwrap();
}
