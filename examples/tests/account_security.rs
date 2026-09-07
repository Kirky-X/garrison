//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! account_security 示例测试（account-policy + account-lockout + account-authflow + cache-memory feature）。
//!
//! 验证 run() 完整执行（内部已包含密码策略/账号锁定/认证流程断言）。

#![cfg(all(
    feature = "account-policy",
    feature = "account-lockout",
    feature = "account-authflow",
    feature = "cache-memory"
))]

use garrison_examples::extension::account_security;

#[tokio::test(flavor = "multi_thread")]
async fn test_run_completes() {
    account_security::run().await.unwrap();
}
