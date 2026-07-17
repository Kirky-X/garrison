//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! secure_module 示例测试。
//!
//! 验证 run() 完整执行（内部已包含脱敏/XSS/消毒/同形异义字断言）。

#![cfg(any(
    feature = "secure-masking",
    feature = "secure-xss",
    feature = "secure-sanitize",
    feature = "secure-confusable"
))]

use bulwark_examples::security::secure_module;

#[tokio::test]
async fn test_run_completes() {
    secure_module::run().await.unwrap();
}
