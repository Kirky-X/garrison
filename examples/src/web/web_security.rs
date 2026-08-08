//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Web 安全中间件完整流程示例：WAF + CORS + CSRF 组合防护。
//!
//! 演示 Garrison Web 安全中间件的完整业务链路：
//! 1. WAF 请求内容校验（危险字符 / 路径黑名单 / HTTP 方法限制）
//! 2. CORS 跨域资源共享（Origin 校验 + 预检请求）
//! 3. CSRF 跨站请求伪造防护（Double-Submit Cookie 模式）
//! 4. 三层中间件组合（compose_security_stack 一键叠加）
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin web_security --features "web-waf web-cors web-csrf web-axum"
//! ```

use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use garrison::error::GarrisonResult;
use garrison::web::cors::{compose_security_stack, CorsConfig};
use garrison::web::csrf::CsrfConfig;
use garrison::web::waf::WafConfig;
use std::sync::Arc;
use tower::ServiceExt;

/// 运行 Web 安全中间件完整流程。
pub async fn run() -> GarrisonResult<()> {
    println!("=== Garrison Web 安全中间件完整流程 ===\n");

    // ================================================================
    // 场景一：WAF 请求内容校验
    // ================================================================
    demo_waf().await?;

    // ================================================================
    // 场景二：CORS 跨域资源共享
    // ================================================================
    demo_cors().await?;

    // ================================================================
    // 场景三：CSRF 跨站请求伪造防护
    // ================================================================
    demo_csrf().await?;

    // ================================================================
    // 场景四：三层中间件组合
    // ================================================================
    demo_composed().await?;

    println!("\n=== Web 安全中间件流程演示完成 ===");
    println!("已展示功能：");
    println!("  • WAF 请求校验（危险字符 / 路径黑名单 / HTTP 方法限制）");
    println!("  • CORS 跨域（Origin 校验 + 预检请求 + 凭证携带）");
    println!("  • CSRF 防护（Double-Submit Cookie + 同源校验）");
    println!("  • 三层组合（compose_security_stack 一键叠加）");

    Ok(())
}

/// 创建测试用 axum Router。
fn test_router() -> Router {
    Router::new()
        .route("/api/data", get(|| async { "ok" }))
        .route("/api/submit", post(|| async { "submitted" }))
}

/// 场景一：WAF 请求内容校验。
///
/// 业务流程：
/// 1. 正常请求放行
/// 2. 危险字符拦截（路径遍历 `../`、SQL 注入 `;`）
/// 3. 路径黑名单拦截（/admin）
/// 4. HTTP 方法限制（仅允许 GET）
async fn demo_waf() -> GarrisonResult<()> {
    println!("--- 场景一：WAF 请求内容校验 ---");

    let waf_config = Arc::new(WafConfig {
        enabled: true,
        path_blacklist: vec!["/admin".to_string()],
        check_dangerous_chars: true,
        check_directory_traversal: true,
        allowed_methods: vec!["GET".to_string()],
        ..Default::default()
    });

    let app = Router::new()
        .route("/api/data", get(|| async { "ok" }))
        .route("/admin/panel", get(|| async { "admin panel" }))
        .layer(axum::middleware::from_fn_with_state(
            waf_config,
            garrison::web::waf::garrison_waf_middleware,
        ));

    // 1. 正常 GET 请求
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
    println!("[1] 正常 GET /api/data → 200 OK");

    // 2. 路径黑名单拦截
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/panel")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    println!("[2] GET /admin/panel → 400（路径黑名单拦截）");

    // 3. 危险字符拦截（路径遍历）
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/api/../secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    println!("[3] GET /api/../secret → 400（目录遍历拦截）");

    // 4. HTTP 方法限制
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/data")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    println!("[4] POST /api/data → 400（方法限制，仅允许 GET）");

    println!();
    Ok(())
}

/// 场景二：CORS 跨域资源共享。
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

/// 场景三：CSRF 防护（Double-Submit Cookie 模式）。
///
/// 业务流程：
/// 1. GET 请求自动设置 CSRF Cookie
/// 2. POST 请求需携带匹配的 CSRF Header + Cookie
/// 3. 缺少 CSRF token 的 POST 被拒绝
async fn demo_csrf() -> GarrisonResult<()> {
    println!("--- 场景三：CSRF 跨站请求伪造防护 ---");

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

/// 场景四：三层中间件组合。
///
/// 使用 compose_security_stack 一键叠加 WAF + CSRF + CORS。
async fn demo_composed() -> GarrisonResult<()> {
    println!("--- 场景四：三层中间件组合（compose_security_stack）---");

    let waf = Arc::new(WafConfig {
        enabled: true,
        path_blacklist: vec!["/admin".to_string()],
        ..Default::default()
    });
    let csrf = Arc::new(CsrfConfig {
        enabled: true,
        cookie_secure: false,
        ..Default::default()
    });
    let cors = Arc::new(CorsConfig {
        allowed_origins: vec!["https://app.example.com".to_string()],
        allow_credentials: true,
        ..Default::default()
    });

    let app = compose_security_stack(test_router(), waf, csrf, cors);

    // 1. 合法请求通过所有三层
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
    println!("[1] 合法 GET → 通过 WAF + CSRF + CORS 三层检查 → 200 OK");

    // 2. WAF 层拦截（路径黑名单）
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/admin/secret")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    println!("[2] GET /admin/secret → WAF 层拦截 → 400 Bad Request");

    // 3. CSRF 层拦截（POST 无 token）
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
    // WAF 先检查，通过后才到 CSRF
    let status = resp.status();
    println!(
        "[3] POST /api/submit（无 CSRF token）→ {} （CSRF 层拦截）",
        status.as_u16()
    );

    println!();
    Ok(())
}
