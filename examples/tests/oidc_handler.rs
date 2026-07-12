//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! oidc_handler 示例测试（protocol-oidc feature）。
//!
//! 验证 run() 完整执行（内部已包含 sign/verify/discovery/nonce 校验断言）。

#![cfg(feature = "protocol-oidc")]

use bulwark_examples::oauth2::oidc_handler;

#[test]
fn test_run_completes() {
    oidc_handler::run().unwrap();
}
