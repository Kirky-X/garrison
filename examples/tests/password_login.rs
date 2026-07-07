//! password_login 示例测试（secure-password + db-sqlite + cache-memory feature）。
//!
//! 验证 run() 完整执行：Argon2 密码哈希 + DbnexusUserRepository + login_with_password 端到端。

#![cfg(all(
    feature = "secure-password",
    feature = "db-sqlite",
    feature = "cache-memory"
))]

use bulwark_examples::authentication::password_login;

#[tokio::test(flavor = "multi_thread")]
async fn test_run_completes() {
    password_login::run().await.unwrap();
}
