//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! session_management 示例测试（cache-memory feature）。
//!
//! 验证 run() 完整执行（内部已包含 session 注入与校验断言）。
//!
//! 注意：session_management 调用 `BulwarkManager::init` 注入全局单例，
//! 多测试并行会竞争全局状态，必须用 #[serial] 串行执行。

#![cfg(feature = "cache-memory")]

use bulwark_examples::extension::session_management;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_run_completes() {
    session_management::run().await.unwrap();
}
