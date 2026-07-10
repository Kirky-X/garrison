//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! httpdigest_login 示例测试（secure-httpdigest feature）。
//!
//! 验证 run() 完整执行（内部已包含 HA2/Response 摘要断言）。

#![cfg(feature = "secure-httpdigest")]

use bulwark_examples::authentication::httpdigest_login;

#[test]
fn test_run_completes() {
    httpdigest_login::run().unwrap();
}
