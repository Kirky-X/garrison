//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! auth_server_serve 示例测试（auth-server + backend-embedded feature）。
//!
//! 验证 serve() 的前置步骤 setup_garrison_manager() 可用。
//!
//! 不直接调用 serve() —— serve() 会绑定双端口并永远阻塞监听，
//! 不适合在自动化测试中调用（同 axum_integration 只测 setup() 不测 run()）。
//!
//! 注意：setup_garrison_manager() 注入全局单例，必须用 #[serial] 串行执行。

#![cfg(all(feature = "auth-server", feature = "backend-embedded"))]

use garrison_examples::infrastructure::auth_server;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_setup_garrison_manager_initializes() {
    let _backend = auth_server::setup_garrison_manager().await.unwrap();
}
