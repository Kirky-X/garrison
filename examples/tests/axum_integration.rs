// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! axum_integration 示例测试（cache-memory + web-axum feature）：验证 setup() 完整执行——创建 oxcache
//! DAO/配置/Interface、`GarrisonManager::builder()` 注入全局单例、`GarrisonUtil::login(1001)` 生成
//! token、`GarrisonRouter::new` 注册 4 个受保护路由，不启动 HTTP 服务器避免测试阻塞；setup 注入全局
//! 单例，并行竞争全局状态，必须 #[serial]；不测试 run()（会绑定 127.0.0.1:3000 并永远阻塞，不适合自动化测试）。

#![cfg(all(feature = "cache-memory", feature = "web-axum"))]

use garrison_examples::web::axum_integration;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_setup_returns_app_and_token() {
    let (app, token) = axum_integration::setup().await.unwrap();
    assert!(!token.is_empty(), "login(1001) 应返回非空 token");
    let _ = app;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_setup_idempotent_reinit() {
    // 多次调用 setup() 都应成功（每次覆盖全局 GarrisonManager 单例）
    let (_app1, token1) = axum_integration::setup().await.unwrap();
    let (_app2, token2) = axum_integration::setup().await.unwrap();
    assert!(!token1.is_empty());
    assert!(!token2.is_empty());
    assert_ne!(token1, token2, "两次 login 应生成不同 token");
}
