//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! sign_protocol 示例测试（protocol-sign feature）。
//!
//! 验证 run() 完整执行（内部已包含签名校验与 nonce replay 拒绝断言）。

#![cfg(feature = "protocol-sign")]

use garrison_examples::sign::sign_protocol;

#[tokio::test]
async fn test_run_completes() {
    sign_protocol::run().await.unwrap();
}
