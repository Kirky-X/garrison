//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! apikey_management 示例测试（protocol-apikey feature）。
//!
//! 验证 run() 完整执行（内部已包含 generate/verify/revoke/rotate 断言）。

#![cfg(feature = "protocol-apikey")]

use garrison_examples::apikey::apikey_management;

#[tokio::test]
async fn test_run_completes() {
    apikey_management::run().await.unwrap();
}
