//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! axum_integration 示例测试（cache-memory + web-axum feature）。
//!
//! 验证 setup() 完整执行（不启动 HTTP 服务器，避免测试阻塞）。
//!
//! setup() 完成以下工作：
//! 1. 创建 oxcache DAO + 配置 + Interface
//! 2. GarrisonManager::init 注入全局单例
//! 3. GarrisonUtil::login(1001) 生成测试 token
//! 4. GarrisonRouter::new 注册 4 个受保护路由
//!
//! 注意：setup() 调用 `GarrisonManager::init` 注入全局单例，
//! 多测试并行会竞争全局状态，必须用 #[serial] 串行执行。
//!
//! 不测试 run() —— run() 会绑定 127.0.0.1:3000 启动 HTTP 服务器并永远阻塞，
//! 不适合在自动化测试中调用。

#![cfg(all(feature = "cache-memory", feature = "web-axum"))]

use garrison_examples::web::axum_integration;
use serial_test::serial;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_setup_returns_app_and_token() {
    let (app, token) = axum_integration::setup().await.unwrap();
    assert!(!token.is_empty(), "login(1001) 应返回非空 token");
    // app 是已注册 4 个路由的 Router，构建成功即说明 route_protected 链式调用正常
    let _ = app;
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_setup_idempotent_reinit() {
    // 多次调用 setup() 应都能成功（每次都覆盖全局 GarrisonManager 单例）
    let (_app1, token1) = axum_integration::setup().await.unwrap();
    let (_app2, token2) = axum_integration::setup().await.unwrap();
    assert!(!token1.is_empty());
    assert!(!token2.is_empty());
    // 两次 login 生成不同 token（UUID 风格）
    assert_ne!(token1, token2, "两次 login 应生成不同 token");
}
