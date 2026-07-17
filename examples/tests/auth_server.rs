//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! auth_server 示例测试。
//!
//! 验证服务器配置完成（不调用 listen，仅验证 setup 不报错）。

#![cfg(feature = "auth-server")]

use bulwark_examples::infrastructure::auth_server;

#[tokio::test]
async fn test_run_completes() {
    auth_server::run().await.unwrap();
}
