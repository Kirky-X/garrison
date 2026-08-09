//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Web 安全中间件完整流程示例：CORS + CSRF 组合防护。
//!
//! 演示 Garrison Web 安全中间件的业务链路：
//! 1. CORS 跨域资源共享（Origin 校验 + 预检请求）
//! 2. CSRF 跨站请求伪造防护（Double-Submit Cookie 模式）
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin web_security --features "web-cors web-csrf web-axum"
//! ```

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use garrison::error::GarrisonResult;
use garrison::web::cors::CorsConfig;
use garrison::web::csrf::CsrfConfig;
use std::sync::Arc;
use tower::ServiceExt;

/// 运行 Web 安全中间件完整流程。
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison Web 安全中间件完整流程 ===\n");

    // ================================================================
    // 场景一：CORS 跨域资源共享
    // ================================================================
    demo_cors().await?;

    // ================================================================
    // 场景二：CSRF 跨站请求伪造防护
    // ================================================================
    demo_csrf().await?;

    println!("\n=== Web 安全中间件流程演示完成 ===");
    println!("已展示功能：");
    println!("  • CORS 跨域（Origin 校验 + 预检请求 + 凭证携带）");
    println!("  • CSRF 防护（Double-Submit Cookie + 同源校验）");

    Ok(())
}

/// 创建测试用 axum Router。
fn test_router() -> Router {
    Router::new()
        .route("/api/data", get(|| async { "ok" }))
        .route("/api/submit", post(|| async { "submitted" }))
}

/// 场景一：CORS 跨域资源共享。
///
/// 业务流程：
/// 1. 允许来源的跨域请求正确设置 CORS 头
/// 2. 不允许来源的请求被拒绝
/// 3. OPTIONS 预检请求返回允许的方法和头部
async fn demo_cors() -> GarrisonResult<()> {
    println!("--- 场景二：CORS 跨域资源共享 ---");

    let cors_config = Arc::new(CorsConfig {
        allowed_origins: vec!["https://app.example.com".to_string()],
        allowed_methods: vec!["GET".into(), "POST".into()],
        allowed_headers: vec!["Authorization".into(), "Content-Type".into()],
        allow_credentials: true,
        max_age_secs: 3600,
        ..Default::default()
    });

    let app = test_router().layer(axum::middleware::from_fn_with_state(
        cors_config,
        garrison::web::cors::garrison_cors_middleware,
    ));

    // 1. 允许来源的跨域请求
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/data")
                .header("origin", "https://app.example.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let cors_origin = resp
        .headers()
        .get("access-control-allow-origin")
        .map(|v| v.to_str().unwrap_or(""))
        .unwrap_or("");
    println!(
        "[1] Origin: https://app.example.com → CORS 头: {}",
        cors_origin
    );
    assert!(cors_origin.contains("app.example.com"), "应回显允许来源");

    // 2. 不允许来源的请求
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/data")
                .header("origin", "https://evil.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let cors_origin = resp
        .headers()
        .get("access-control-allow-origin")
        .map(|v| v.to_str().unwrap_or(""))
        .unwrap_or("");
    println!("[2] Origin: https://evil.com → 不在允许列表（无 CORS 头或拒绝）");
    assert!(
        !cors_origin.contains("evil.com"),
        "不允许的来源不应出现在 CORS 头中"
    );

    // 3. OPTIONS 预检请求
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/api/data")
                .header("origin", "https://app.example.com")
                .header("access-control-request-method", "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let allow_methods = resp
        .headers()
        .get("access-control-allow-methods")
        .map(|v| v.to_str().unwrap_or(""))
        .unwrap_or("");
    println!(
        "[3] OPTIONS 预检 → Allow-Methods: {}",
        if allow_methods.is_empty() {
            "(not set)"
        } else {
            allow_methods
        }
    );

    println!();
    Ok(())
}

/// 场景二：CSRF 防护（Double-Submit Cookie 模式）。
///
/// 业务流程：
/// 1. GET 请求自动设置 CSRF Cookie
/// 2. POST 请求需携带匹配的 CSRF Header + Cookie
/// 3. 缺少 CSRF token 的 POST 被拒绝
async fn demo_csrf() -> GarrisonResult<()> {
    println!("--- 场景二：CSRF 跨站请求伪造防护 ---");

    let csrf_config = Arc::new(CsrfConfig {
        enabled: true,
        cookie_name: "garrison_csrf_token".into(),
        header_name: "x-csrf-token".into(),
        protected_methods: vec!["POST".into(), "PUT".into(), "DELETE".into()],
        excluded_paths: vec!["/api/webhook".into()],
        cookie_secure: false, // 示例用，生产环境应为 true
        cookie_domain: None,
    });

    let app = Router::new()
        .route("/api/data", get(|| async { "ok" }))
        .route("/api/submit", post(|| async { "submitted" }))
        .route("/api/webhook", post(|| async { "webhook ok" }))
        .layer(axum::middleware::from_fn_with_state(
            csrf_config,
            garrison::web::csrf::garrison_csrf_middleware,
        ));

    // 1. GET 请求放行 + 设置 CSRF Cookie
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/data")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let has_csrf_cookie = resp
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap_or(""))
        .unwrap_or("")
        .contains("garrison_csrf_token");
    println!("[1] GET /api/data → 200 OK");
    println!(
        "    Set-Cookie CSRF: {}",
        if has_csrf_cookie {
            "✓ 已设置"
        } else {
            "(已有 cookie 或未首次设置)"
        }
    );

    // 2. POST 无 CSRF token → 被拒绝
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/submit")
                .header("origin", "https://evil.com")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    println!("[2] POST /api/submit（无 CSRF token）→ 403 Forbidden");

    // 3. 排除路径不受 CSRF 保护
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/webhook")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    println!("[3] POST /api/webhook（排除路径）→ 200 OK（跳过 CSRF 校验）");

    println!();
    Ok(())
}
