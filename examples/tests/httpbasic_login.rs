//! httpbasic_login 示例测试（secure-httpbasic feature）。
//!
//! 验证 run() 完整执行（内部已包含 encode/decode 断言）。

#![cfg(feature = "secure-httpbasic")]

use bulwark_examples::httpbasic_login;

#[test]
fn test_run_completes() {
    httpbasic_login::run().unwrap();
}
