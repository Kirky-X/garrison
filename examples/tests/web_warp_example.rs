//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! web_warp_example 示例测试（web-warp feature）。
//!
//! 验证 BulwarkRouter + into_filter 守卫行为 + check_login 函数式 Filter：
//! - 公开路径无需 token → 200
//! - 受保护路径无 token → 401（BulwarkRejection）
//! - 受保护路径有 token → 200
//! - CheckRole 路径有匹配角色 → 200
//! - CheckPermission 路径有匹配权限 → 200
//! - 直接测试 `check_login` Filter 函数
//!
//! 使用 `#[serial_test::serial]` 串行化，因为 `setup()` 修改全局 `BulwarkManager` 单例。

#![cfg(feature = "web-warp")]

use bulwark_examples::web::web_warp_example;
use serial_test::serial;
use warp::http::StatusCode;
use warp::Filter;

#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_guard_protection() {
    let (config, token) = web_warp_example::setup().await;
    let routes = web_warp_example::build_routes(config).recover(web_warp_example::handle_rejection);

    // 公开路径 - 无需 token → 200
    let resp = warp::test::request().path("/public").reply(&routes).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // 受保护路径 - 无 token → 401
    let resp = warp::test::request()
        .path("/api/protected")
        .reply(&routes)
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // 受保护路径 - 有 token → 200
    let resp = warp::test::request()
        .header("Authorization", format!("Bearer {}", token))
        .path("/api/protected")
        .reply(&routes)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // CheckRole 路径 - 有 token 且持有 admin 角色 → 200
    let resp = warp::test::request()
        .header("Authorization", format!("Bearer {}", token))
        .path("/api/admin")
        .reply(&routes)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // CheckPermission 路径 - 有 token 且持有 data:read 权限 → 200
    let resp = warp::test::request()
        .header("Authorization", format!("Bearer {}", token))
        .path("/api/data")
        .reply(&routes)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// 直接测试 `check_login` 函数式 Filter：无 token → rejection。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_check_login_filter_rejects_without_token() {
    use bulwark::web_warp::check_login;

    let (config, _token) = web_warp_example::setup().await;

    let route = warp::path("api")
        .and(warp::path("protected"))
        .and(warp::path::end())
        .and(check_login(config))
        .map(|()| "authenticated")
        .recover(web_warp_example::handle_rejection);

    let resp = warp::test::request()
        .path("/api/protected")
        .reply(&route)
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// 直接测试 `check_login` 函数式 Filter：有 token → 200。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_check_login_filter_accepts_with_token() {
    use bulwark::web_warp::check_login;

    let (config, token) = web_warp_example::setup().await;

    let route = warp::path("api")
        .and(warp::path("protected"))
        .and(warp::path::end())
        .and(check_login(config))
        .map(|()| "authenticated");

    let resp = warp::test::request()
        .header("Authorization", format!("Bearer {}", token))
        .path("/api/protected")
        .reply(&route)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// 直接测试 `check_role` 函数式 Filter：有匹配角色 → 200。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_check_role_filter_accepts_with_role() {
    use bulwark::web_warp::check_role;

    let (config, token) = web_warp_example::setup().await;

    let route = warp::path("api")
        .and(warp::path("admin"))
        .and(warp::path::end())
        .and(check_role(config, "admin".to_string()))
        .map(|()| "admin ok");

    let resp = warp::test::request()
        .header("Authorization", format!("Bearer {}", token))
        .path("/api/admin")
        .reply(&route)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// 直接测试 `check_permission` 函数式 Filter：有匹配权限 → 200。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_check_permission_filter_accepts_with_permission() {
    use bulwark::web_warp::check_permission;

    let (config, token) = web_warp_example::setup().await;

    let route = warp::path("api")
        .and(warp::path("data"))
        .and(warp::path::end())
        .and(check_permission(config, "data:read".to_string()))
        .map(|()| "data ok");

    let resp = warp::test::request()
        .header("Authorization", format!("Bearer {}", token))
        .path("/api/data")
        .reply(&route)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// 测试 `handle_rejection`：将 BulwarkRejection 转换为 JSON 错误响应。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_handle_rejection_returns_json() {
    let (config, _token) = web_warp_example::setup().await;
    let routes = web_warp_example::build_routes(config).recover(web_warp_example::handle_rejection);

    let resp = warp::test::request()
        .path("/api/protected")
        .reply(&routes)
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // 验证返回 JSON 错误体
    let body = String::from_utf8_lossy(resp.body());
    assert!(body.contains("error"), "响应体应包含 error 字段: {}", body);
}
