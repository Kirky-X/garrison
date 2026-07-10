//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! password_login 示例测试（account-credential + db-sqlite + cache-memory feature）。
//!
//! 验证 run() 完整执行：Argon2 密码哈希 + DbnexusUserRepository + login_with_password 端到端。

#![cfg(all(
    feature = "account-credential",
    feature = "db-sqlite",
    feature = "cache-memory"
))]

use bulwark_examples::authentication::password_login;

#[tokio::test(flavor = "multi_thread")]
async fn test_run_completes() {
    password_login::run().await.unwrap();
}
