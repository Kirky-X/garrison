//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! email_verification 示例测试（email-verification feature）。
//!
//! 验证 run() 完整执行（内部已包含 send_code/verify_code/限速/规范化断言）。

#![cfg(feature = "email-verification")]

use garrison_examples::security::email_verification;

#[tokio::test]
async fn test_run_completes() {
    email_verification::run().await.unwrap();
}
