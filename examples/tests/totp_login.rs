//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! totp_login 示例测试（secure-totp feature）。
//!
//! 验证 run() 完整执行（内部已包含 TOTP generate/validate 断言）。

#![cfg(feature = "secure-totp")]

use bulwark_examples::authentication::totp_login;

#[test]
fn test_run_completes() {
    totp_login::run().unwrap();
}
