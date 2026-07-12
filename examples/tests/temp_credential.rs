//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! temp_credential 示例测试（protocol-temp feature）。
//!
//! 验证 run() 完整执行（内部已包含 issue/get/consume/revoke 断言）。

#![cfg(feature = "protocol-temp")]

use bulwark_examples::sign::temp_credential;

#[tokio::test]
async fn test_run_completes() {
    temp_credential::run().await.unwrap();
}
