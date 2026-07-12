//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! basic_login 示例测试（cache-memory + web-axum feature）。
//!
//! 验证 run() 完整执行（内部已包含 login/check_login/logout/登出后失败断言）。
//!
//! 注意：basic_login 调用 `BulwarkManager::init` 注入全局单例，
//! 多测试并行会竞争全局状态，必须用 #[serial] 串行执行。

#![cfg(all(feature = "cache-memory", feature = "web-axum"))]

use bulwark_examples::authentication::basic_login;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_run_completes() {
    basic_login::run().await.unwrap();
}
