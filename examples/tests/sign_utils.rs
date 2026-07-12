//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! sign_utils 示例测试（secure-sign feature）。
//!
//! 验证 run() 完整执行（内部已包含 HMAC-SHA256/SHA512 + Base64 断言）。

#![cfg(feature = "secure-sign")]

use bulwark_examples::sign::sign_utils;

#[test]
fn test_run_completes() {
    sign_utils::run().unwrap();
}
