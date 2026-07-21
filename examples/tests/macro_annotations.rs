//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! macro_annotations 示例测试（annotation-macros + cache-memory + web-axum feature）。
//!
//! 验证 run() 完整执行：#[check_login]/#[check_permission]/#[check_role] 宏标注的 handler
//! 在已登录/已授权/未登录/无权限场景下的状态码与 body 行为。

#![cfg(all(
    feature = "annotation-macros",
    feature = "cache-memory",
    feature = "web-axum"
))]

use garrison_examples::extension::macro_annotations;

#[tokio::test(flavor = "multi_thread")]
async fn test_run_completes() {
    macro_annotations::run().await.unwrap();
}
