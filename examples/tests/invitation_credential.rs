//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! invitation_credential 示例测试（protocol-invitation feature）。
//!
//! 验证 run() 完整执行（内部已包含 issue/verify/consume/revoke 断言）。

#![cfg(feature = "protocol-invitation")]

use garrison_examples::sign::invitation_credential;

#[tokio::test]
async fn test_run_completes() {
    invitation_credential::run().await.unwrap();
}
