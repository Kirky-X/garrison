//! 上下文与请求示例：演示 BulwarkContext + AxumAdapter 的请求/响应操作。
//!
//! 流程：
//! 1. 构造 axum `Request<Body>`
//! 2. 创建 AxumContext 并获取 BulwarkRequest
//! 3. 从 header 提取 token（Bearer + 自定义 header）
//! 4. 从 cookie 提取 token
//! 5. 设置响应状态码与 header
//! 6. 设置安全 Cookie
//! 7. 设置自定义 Cookie（dev 模式关闭 Secure）
//! 8. 消费 context 生成 axum Response
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin context_request --features web-axum
//! ```

use axum::body::Body;
use axum::http::Request;
use bulwark::config::BulwarkConfig;
use bulwark::context::{AxumContext, AxumRequest, BulwarkContext, BulwarkRequest, BulwarkResponse};
use bulwark::error::BulwarkResult;

/// 运行上下文与请求示例。
///
/// 演示 AxumContext 的 request 解析、token 提取（header / cookie）、
/// 响应状态码 / header / Cookie 设置，以及 Bearer 大小写不敏感特性。
pub async fn run() -> BulwarkResult<()> {
    println!("=== Bulwark 上下文与请求示例 ===\n");

    // ----------------------------------------------------------------
    // 1. 构造 axum Request（带 Authorization: Bearer）
    // ----------------------------------------------------------------
    let req = Request::builder()
        .method("GET")
        .uri("/api/users/1001?tab=profile")
        .header("Authorization", "Bearer my_bearer_token_123")
        .header("Cookie", "session_id=xyz789")
        .body(Body::empty())
        .unwrap();
    println!("[1] 构造 Request: GET /api/users/1001?tab=profile");

    let ctx = AxumContext::new(&req);
    let axum_req = ctx.request()?;
    println!("    path() = {}", axum_req.path()?);
    println!("    method() = {}", axum_req.method()?);
    println!();

    // ----------------------------------------------------------------
    // 2. 从 header 提取 token（Bearer）
    // ----------------------------------------------------------------
    let config = BulwarkConfig::default_config();
    let token = axum_req.get_token(&config)?;
    println!("[2] 从 header 提取 token:");
    println!("    Authorization: Bearer my_bearer_token_123");
    println!("    get_token() → {:?}", token);
    assert_eq!(token.as_deref(), Some("my_bearer_token_123"));
    println!();

    // ----------------------------------------------------------------
    // 3. 从自定义 header 提取 token（回退路径）
    // ----------------------------------------------------------------
    let req2 = Request::builder()
        .method("POST")
        .uri("/api/data")
        .header("bulwark_token", "custom_header_token_456")
        .body(Body::empty())
        .unwrap();
    let ctx2 = AxumContext::new(&req2);
    let req2_ref = ctx2.request()?;
    let token2 = req2_ref.get_token(&config)?;
    println!("[3] 从自定义 header 提取 token:");
    println!("    bulwark_token: custom_header_token_456");
    println!("    get_token() → {:?}", token2);
    assert_eq!(token2.as_deref(), Some("custom_header_token_456"));
    println!();

    // ----------------------------------------------------------------
    // 4. 从 cookie 提取 token
    // ----------------------------------------------------------------
    let req3 = Request::builder()
        .method("GET")
        .uri("/")
        .header("Cookie", "bulwark_token=cookie_token_789")
        .body(Body::empty())
        .unwrap();
    let ctx3 = AxumContext::new(&req3);
    let req3_ref = ctx3.request()?;
    let token3 = req3_ref.get_token(&config)?;
    println!("[4] 从 cookie 提取 token:");
    println!("    Cookie: bulwark_token=cookie_token_789");
    println!("    get_token() → {:?}", token3);
    assert_eq!(token3.as_deref(), Some("cookie_token_789"));
    println!();

    // ----------------------------------------------------------------
    // 5. 设置响应状态码与 header
    // ----------------------------------------------------------------
    let mut ctx4 = AxumContext::new(&req);
    {
        let resp = ctx4.raw_response_mut();
        resp.set_status(200)?;
        resp.set_header("X-Trace-Id", "trace-abc-123")?;
    }
    println!("[5] 设置响应状态码与 header:");
    println!("    set_status(200)");
    println!("    set_header(\"X-Trace-Id\", \"trace-abc-123\")");
    let response = ctx4.into_response();
    println!("    Response status = {}", response.status());
    let trace_id = response
        .headers()
        .get("X-Trace-Id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    println!("    Response header = {:?}", trace_id);
    assert_eq!(trace_id, "trace-abc-123");
    println!();

    // ----------------------------------------------------------------
    // 6. 设置安全 Cookie（默认 Secure; SameSite=Lax）
    // ----------------------------------------------------------------
    let mut ctx5 = AxumContext::new(&req);
    {
        let resp = ctx5.raw_response_mut();
        resp.set_cookie("auth_token", "tok_value")?;
    }
    let response = ctx5.into_response();
    let set_cookie = response
        .headers()
        .get("Set-Cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    println!("[6] 设置安全 Cookie（默认）:");
    println!("    set_cookie(\"auth_token\", \"tok_value\")");
    println!("    Set-Cookie: {}", set_cookie);
    assert!(set_cookie.contains("HttpOnly"), "应包含 HttpOnly");
    assert!(set_cookie.contains("Secure"), "应包含 Secure");
    assert!(set_cookie.contains("SameSite=Lax"), "应包含 SameSite=Lax");
    println!("    ✓ 包含 HttpOnly; Secure; SameSite=Lax");
    println!();

    // ----------------------------------------------------------------
    // 7. 设置自定义 Cookie（dev 模式关闭 Secure）
    // ----------------------------------------------------------------
    let mut dev_config = BulwarkConfig::default_config();
    dev_config.cookie_secure = false;
    dev_config.cookie_same_site = "Strict".to_string();

    let mut ctx6 = AxumContext::new(&req);
    {
        let resp = ctx6.raw_response_mut();
        resp.set_cookie_with_config("dev_token", "dev_value", &dev_config)?;
    }
    let response = ctx6.into_response();
    let dev_cookie = response
        .headers()
        .get("Set-Cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    println!("[7] 设置自定义 Cookie（dev 模式）:");
    println!("    set_cookie_with_config(\"dev_token\", \"dev_value\", dev_config)");
    println!("    Set-Cookie: {}", dev_cookie);
    assert!(!dev_cookie.contains("Secure"), "dev 模式不应包含 Secure");
    assert!(
        dev_cookie.contains("SameSite=Strict"),
        "应包含 SameSite=Strict"
    );
    println!("    ✓ dev 模式：无 Secure; SameSite=Strict");
    println!();

    // ----------------------------------------------------------------
    // 8. Bearer 大小写不敏感
    // ----------------------------------------------------------------
    println!("[8] Bearer 大小写不敏感（RFC 7235）:");
    for prefix in &["Bearer", "bearer", "BEARER"] {
        let req_c = Request::builder()
            .method("GET")
            .uri("/")
            .header("Authorization", format!("{} tok_{}", prefix, prefix))
            .body(Body::empty())
            .unwrap();
        let axum_req = AxumRequest::new(&req_c);
        let token = axum_req.get_token(&config)?;
        println!("    {} → {:?}", prefix, token);
        assert_eq!(
            token.as_deref(),
            Some(format!("tok_{}", prefix).as_str()),
            "Bearer 前缀大小写不敏感应能提取 token"
        );
    }

    println!("\n=== 示例执行完成 ===");
    Ok(())
}
