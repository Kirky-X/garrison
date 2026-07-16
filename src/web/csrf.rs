//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! CSRF 跨站请求伪造防护中间件模块。
//!
//! 采用 Double-Submit Cookie 模式：安全方法（GET/HEAD/OPTIONS）懒生成 CSRF token 并写入 Cookie，
//! 受保护方法（POST/PUT/PATCH/DELETE）校验 Header 与 Cookie 中的 token 是否一致。
//!
//! # 行为
//!
//! - **安全方法**（不在 `protected_methods` 中的方法）：
//!   - 若请求中不存在 CSRF cookie，生成新 token 并在响应中设置 `Set-Cookie`。
//!   - 若已存在 CSRF cookie，直接放行。
//!   - 始终放行到 handler。
//! - **受保护方法**（在 `protected_methods` 中的方法）：
//!   - `enabled == false`：直接放行。
//!   - 路径命中 `excluded_paths`：直接放行。
//!   - Origin/Referer 同源校验失败返回 403。
//!   - 从 Cookie 和 Header 提取 token，任一缺失返回 403。
//!   - `validate_csrf_token` 校验失败返回 403。
//!   - 校验通过放行。
//!
//! # 配置
//!
//! 通过 [`CsrfConfig`](crate::web::csrf::CsrfConfig) 控制，集成到 [`crate::config::BulwarkConfig`]。

use crate::error::BulwarkResult;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue};
use serde::{Deserialize, Serialize};

/// CSRF 防护配置。
///
/// 控制 CSRF 防护的启用、Cookie/Header 名称、排除路径与受保护方法。
///
/// # 默认值
///
/// - `enabled`: `true`（默认启用，secure-by-default）
/// - `cookie_name`: `"bulwark_csrf_token"`
/// - `header_name`: `"X-CSRF-Token"`
/// - `excluded_paths`: 空列表
/// - `protected_methods`: `["POST", "PUT", "PATCH", "DELETE"]`
///
/// # 配置示例
///
/// ```toml
/// [csrf_config]
/// enabled = true
/// excluded_paths = ["/api/webhook"]
/// cookie_name = "my_csrf"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CsrfConfig {
    /// 是否启用 CSRF 防护。
    pub enabled: bool,
    /// CSRF Cookie 名称。
    pub cookie_name: String,
    /// CSRF Header 名称（客户端通过此 Header 提交 token）。
    pub header_name: String,
    /// 排除校验的路径列表（精确匹配）。
    pub excluded_paths: Vec<String>,
    /// 受保护方法列表（大小写不敏感）。
    pub protected_methods: Vec<String>,
    /// 是否在 Cookie 中设置 Secure 标志（默认 `true`，与 BulwarkConfig 一致）。
    pub cookie_secure: bool,
}

impl Default for CsrfConfig {
    fn default() -> Self {
        Self {
            // secure-by-default，默认启用 CSRF 防护
            enabled: true,
            cookie_name: "bulwark_csrf_token".to_string(),
            header_name: "X-CSRF-Token".to_string(),
            excluded_paths: Vec::new(),
            protected_methods: vec![
                "POST".to_string(),
                "PUT".to_string(),
                "PATCH".to_string(),
                "DELETE".to_string(),
            ],
            cookie_secure: true,
        }
    }
}

// ============================================================================
// T011: generate_csrf_token + validate_csrf_token
// ============================================================================

/// 生成 CSRF token。
///
/// 使用 `rand::rngs::OsRng` 生成 32 个随机字节，编码为 URL-safe Base64（无填充）。
/// 结果长度约为 43 个字符。
///
/// # 返回
///
/// Base64 编码的 token 字符串。
pub fn generate_csrf_token() -> BulwarkResult<String> {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use rand::rngs::OsRng;
    use rand::RngCore;

    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// 校验 CSRF token（常量时间比较）。
///
/// 对 `header_token` 与 `cookie_token` 执行常量时间比较，防止时序攻击。
///
/// # 常量时间策略
///
/// - 长度不一致时不提前返回，仍遍历较短长度执行 XOR 累积。
/// - 长度差异单独追踪，最终同时判断字节差异与长度差异。
///
/// # 返回
///
/// 任一 token 为空时返回 `false`（空 token 视为非法输入）；
/// 否则长度一致且所有字节匹配时返回 `true`，否则返回 `false`。
pub fn validate_csrf_token(header_token: &str, cookie_token: &str) -> bool {
    // 统一使用 subtle::ConstantTimeEq 做常量时间比较，
    // 并移除 is_empty early return（避免长度泄露）。
    use std::ops::Not;
    use subtle::ConstantTimeEq;

    let h = header_token.as_bytes();
    let c = cookie_token.as_bytes();

    let h_len = h.len() as u64;
    let c_len = c.len() as u64;

    // 长度比较用常量时间（u64::ct_eq），不 early return
    let len_eq = h_len.ct_eq(&c_len);

    // 空 token 视为非法输入：常量时间检查双方都非空（不 early return）
    let non_empty = h_len.ct_eq(&0).not() & c_len.ct_eq(&0).not();

    // 字节比较：遍历到 max_len，短的一方用 0 padding
    let max_len = h.len().max(c.len());
    let mut byte_eq = subtle::Choice::from(1);
    for i in 0..max_len {
        let x = h.get(i).copied().unwrap_or(0);
        let y = c.get(i).copied().unwrap_or(0);
        byte_eq &= x.ct_eq(&y);
    }

    (non_empty & len_eq & byte_eq).unwrap_u8() == 1
}

// ============================================================================
// T013: bulwark_csrf_middleware
// ============================================================================

/// 从请求 headers 中提取指定名称的 Cookie 值。
fn extract_cookie_value(headers: &HeaderMap, cookie_name: &str) -> Option<String> {
    let cookie_header = headers.get(axum::http::header::COOKIE)?.to_str().ok()?;
    for pair in cookie_header.split(';') {
        let pair = pair.trim();
        if let Some((name, value)) = pair.split_once('=') {
            if name.trim() == cookie_name {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// 构建 Set-Cookie 值字符串。
///
/// 当 `cookie_secure` 为 `true` 时追加 `; Secure` 标志。
fn build_set_cookie(cookie_name: &str, token: &str, cookie_secure: bool) -> String {
    let secure_flag = if cookie_secure { "; Secure" } else { "" };
    format!(
        "{}={}; HttpOnly; SameSite=Lax; Path=/{}",
        cookie_name, token, secure_flag
    )
}

/// 从绝对 URI（Origin/Referer header 值）中提取 `host[:port]`。
///
/// 输入应为 `scheme://host[:port]/path` 形式。返回 `host[:port]` 字符串；
/// 解析失败或无 host 时返回 `None`。
fn extract_origin_host(uri_str: &str) -> Option<String> {
    let uri: axum::http::Uri = uri_str.parse().ok()?;
    let host = uri.host()?;
    match uri.port_u16() {
        Some(port) => Some(format!("{}:{}", host, port)),
        None => Some(host.to_string()),
    }
}

/// 校验请求的 Origin/Referer 是否与 Host header 同源。
///
/// 优先检查 `Origin` header；若不存在则回退到 `Referer` header。
/// 两者都不存在时返回 `false`（受保护方法要求同源校验，secure-by-default）。
///
/// # 比较策略
///
/// - 提取 Host header 值作为期望源（`host[:port]`）。
/// - 从 Origin/Referer 解析出 `host[:port]`，与 Host header 严格比较。
/// - Host header 缺失时返回 `false`（无法确定期望源）。
///
/// # 返回
///
/// - Origin 或 Referer 存在且 host 与 Host header 一致：`true`
/// - 都不存在、host 不一致或 Host header 缺失：`false`
fn validate_same_origin(headers: &HeaderMap) -> bool {
    let host = match headers
        .get(axum::http::header::HOST)
        .and_then(|v| v.to_str().ok())
    {
        Some(h) => h,
        None => return false,
    };

    // 优先检查 Origin header
    if let Some(origin) = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
    {
        return extract_origin_host(origin)
            .map(|oh| oh == host)
            .unwrap_or(false);
    }

    // Origin 不存在，回退到 Referer header
    if let Some(referer) = headers
        .get(axum::http::header::REFERER)
        .and_then(|v| v.to_str().ok())
    {
        return extract_origin_host(referer)
            .map(|rh| rh == host)
            .unwrap_or(false);
    }

    // Origin 和 Referer 都不存在：受保护方法拒绝
    false
}

/// CSRF 防护中间件。
///
/// 基于 [`CsrfConfig`] 对请求执行 CSRF 校验。
///
/// # 使用
///
/// ```ignore
/// use bulwark::web::csrf::{bulwark_csrf_middleware, CsrfConfig};
/// use std::sync::Arc;
/// use axum::Router;
///
/// let config = CsrfConfig { enabled: true, ..Default::default() };
/// let app = Router::new()
///     .route("/api", axum::routing::get(|| async { "ok" }))
///     .layer(axum::middleware::from_fn_with_state(
///         Arc::new(config),
///         bulwark_csrf_middleware,
///     ));
/// ```
pub async fn bulwark_csrf_middleware(
    State(config): State<std::sync::Arc<CsrfConfig>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let method = req.method().as_str().to_string();
    let is_protected = config
        .protected_methods
        .iter()
        .any(|m| m.eq_ignore_ascii_case(&method));

    if is_protected {
        // 受保护方法：校验 CSRF token
        if !config.enabled {
            return next.run(req).await;
        }
        let path = req.uri().path().to_string();
        if config.excluded_paths.iter().any(|p| p == &path) {
            return next.run(req).await;
        }
        // Origin/Referer 同源校验（defense-in-depth）
        if !validate_same_origin(req.headers()) {
            return (StatusCode::FORBIDDEN, "CSRF origin validation failed").into_response();
        }
        let cookie_token = extract_cookie_value(req.headers(), &config.cookie_name);
        let header_token = req
            .headers()
            .get(config.header_name.as_str())
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        match (cookie_token, header_token) {
            (Some(ct), Some(ht)) => {
                if validate_csrf_token(&ht, &ct) {
                    next.run(req).await
                } else {
                    (StatusCode::FORBIDDEN, "CSRF token validation failed").into_response()
                }
            },
            _ => (StatusCode::FORBIDDEN, "CSRF token missing").into_response(),
        }
    } else {
        // 安全方法：懒生成 CSRF token
        let has_cookie = extract_cookie_value(req.headers(), &config.cookie_name).is_some();
        let mut resp = next.run(req).await;
        if !has_cookie {
            if let Ok(token) = generate_csrf_token() {
                let set_cookie =
                    build_set_cookie(&config.cookie_name, &token, config.cookie_secure);
                if let Ok(value) = HeaderValue::from_str(&set_cookie) {
                    resp.headers_mut()
                        .append(axum::http::header::SET_COOKIE, value);
                }
            }
        }
        resp
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use std::sync::Arc;
    use tower::ServiceExt;

    // ----------------------------------------------------------------
    // 辅助函数
    // ----------------------------------------------------------------

    fn make_app(config: CsrfConfig) -> Router {
        Router::new()
            .route(
                "/api/test",
                get(|| async { "ok" })
                    .post(|| async { "ok" })
                    .put(|| async { "ok" })
                    .delete(|| async { "ok" })
                    .options(|| async { "ok" }),
            )
            .layer(axum::middleware::from_fn_with_state(
                Arc::new(config),
                bulwark_csrf_middleware,
            ))
    }

    fn make_request(method: &str, path: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap()
    }

    fn make_request_with_csrf(
        method: &str,
        path: &str,
        cookie_token: &str,
        header_token: &str,
    ) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("host", "example.com")
            .header("origin", "https://example.com")
            .header("cookie", format!("bulwark_csrf_token={}", cookie_token))
            .header("X-CSRF-Token", header_token)
            .body(Body::empty())
            .unwrap()
    }

    fn make_request_with_cookie(method: &str, path: &str, cookie: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("cookie", cookie)
            .body(Body::empty())
            .unwrap()
    }

    /// 判断字符串是否仅包含 URL-safe base64 字符（无填充）。
    fn is_url_safe_base64_no_pad(s: &str) -> bool {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    }

    // ========================================================================
    // T011: generate_csrf_token + validate_csrf_token 单元测试（8 个）
    // ========================================================================

    #[test]
    fn token_length_is_43_chars() {
        let token = generate_csrf_token().unwrap();
        assert_eq!(
            token.len(),
            43,
            "32 字节 base64 URL-safe no-pad 应为 43 字符"
        );
    }

    #[test]
    fn token_format_is_url_safe_base64() {
        let token = generate_csrf_token().unwrap();
        assert!(
            is_url_safe_base64_no_pad(&token),
            "token 应仅包含 URL-safe base64 字符（A-Za-z0-9-_），无填充"
        );
    }

    #[test]
    fn two_tokens_are_different() {
        let t1 = generate_csrf_token().unwrap();
        let t2 = generate_csrf_token().unwrap();
        assert_ne!(t1, t2, "两次生成的 token 不应相同");
    }

    #[test]
    fn validate_same_tokens_returns_true() {
        let token = generate_csrf_token().unwrap();
        assert!(validate_csrf_token(&token, &token));
    }

    #[test]
    fn validate_different_tokens_returns_false() {
        let t1 = generate_csrf_token().unwrap();
        let t2 = generate_csrf_token().unwrap();
        assert!(!validate_csrf_token(&t1, &t2));
    }

    #[test]
    fn validate_different_lengths_returns_false() {
        assert!(!validate_csrf_token("abc", "abcdef"));
    }

    #[test]
    fn validate_empty_tokens_returns_false() {
        assert!(!validate_csrf_token("", ""));
    }

    #[test]
    fn validate_one_empty_token_returns_false() {
        assert!(!validate_csrf_token("abc", ""));
        assert!(!validate_csrf_token("", "abc"));
    }

    // ========================================================================
    // T012: CsrfConfig 单元测试（5 个）
    // ========================================================================

    #[test]
    fn csrf_config_default_values() {
        let config = CsrfConfig::default();
        assert!(config.enabled, "VULN-0006: 默认应启用 CSRF 防护");
        assert_eq!(config.cookie_name, "bulwark_csrf_token");
        assert_eq!(config.header_name, "X-CSRF-Token");
        assert!(config.excluded_paths.is_empty());
        assert_eq!(
            config.protected_methods,
            vec!["POST", "PUT", "PATCH", "DELETE"]
        );
        assert!(config.cookie_secure, "cookie_secure 默认应为 true");
    }

    #[test]
    fn csrf_config_custom_values() {
        let config = CsrfConfig {
            enabled: true,
            cookie_name: "my_csrf".to_string(),
            header_name: "X-MY-CSRF".to_string(),
            excluded_paths: vec!["/webhook".to_string()],
            protected_methods: vec!["POST".to_string()],
            cookie_secure: false,
        };
        assert!(config.enabled);
        assert_eq!(config.cookie_name, "my_csrf");
        assert_eq!(config.header_name, "X-MY-CSRF");
        assert_eq!(config.excluded_paths, vec!["/webhook"]);
        assert_eq!(config.protected_methods, vec!["POST"]);
        assert!(!config.cookie_secure);
    }

    #[test]
    fn csrf_config_enabled_field() {
        let mut config = CsrfConfig::default();
        assert!(config.enabled, "VULN-0006: 默认应启用");
        config.enabled = false;
        assert!(!config.enabled);
    }

    #[test]
    fn csrf_config_cookie_name_customization() {
        let config = CsrfConfig {
            cookie_name: "custom_csrf_token".to_string(),
            ..Default::default()
        };
        assert_eq!(config.cookie_name, "custom_csrf_token");
    }

    #[test]
    fn csrf_config_protected_methods_customization() {
        let config = CsrfConfig {
            protected_methods: vec!["POST".to_string(), "PUT".to_string()],
            ..Default::default()
        };
        assert_eq!(config.protected_methods, vec!["POST", "PUT"]);
    }

    // ----------------------------------------------------------------
    // CsrfConfig 默认启用测试
    // ----------------------------------------------------------------

    /// CsrfConfig::default() 应默认启用 CSRF 防护（secure-by-default）。
    #[test]
    fn csrf_config_default_enabled_is_true() {
        let config = CsrfConfig::default();
        assert!(
            config.enabled,
            "VULN-0006: CsrfConfig::default().enabled 必须为 true（secure-by-default）"
        );
    }

    // ========================================================================
    // T013: bulwark_csrf_middleware 集成测试（12 个）
    // ========================================================================

    #[tokio::test]
    async fn get_without_cookie_sets_csrf_cookie() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app.oneshot(make_request("GET", "/api/test")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let set_cookie = resp.headers().get("set-cookie").expect("应设置 Set-Cookie");
        let cookie_str = set_cookie.to_str().unwrap();
        assert!(
            cookie_str.starts_with("bulwark_csrf_token="),
            "Set-Cookie 应以 cookie_name 开头"
        );
        assert!(cookie_str.contains("HttpOnly"));
        assert!(cookie_str.contains("SameSite=Lax"));
        assert!(cookie_str.contains("Path=/"));
        assert!(
            cookie_str.contains("Secure"),
            "默认 cookie_secure=true 应包含 Secure 标志"
        );
    }

    #[tokio::test]
    async fn get_with_existing_cookie_does_not_set_new_cookie() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request_with_cookie(
                "GET",
                "/api/test",
                "bulwark_csrf_token=existing_token_value",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(
            resp.headers().get("set-cookie").is_none(),
            "已有 CSRF cookie 时不应设置新 cookie"
        );
    }

    #[tokio::test]
    async fn post_without_token_returns_403() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request("POST", "/api/test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_with_mismatched_tokens_returns_403() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request_with_csrf(
                "POST",
                "/api/test",
                "cookie_token_value",
                "different_header_token",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn post_with_matching_tokens_passes_through() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let token = generate_csrf_token().unwrap();
        let resp = app
            .oneshot(make_request_with_csrf("POST", "/api/test", &token, &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn get_always_passes_through() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app.oneshot(make_request("GET", "/api/test")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn head_passes_through() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request("HEAD", "/api/test"))
            .await
            .unwrap();
        // HEAD 请求由 axum 自动处理（get handler 兼容 HEAD），返回 200
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn options_passes_through() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request("OPTIONS", "/api/test"))
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn excluded_paths_skip_validation() {
        let config = CsrfConfig {
            enabled: true,
            excluded_paths: vec!["/api/test".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        // POST 无 token，但路径在 excluded_paths 中，应放行
        let resp = app
            .oneshot(make_request("POST", "/api/test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn put_with_matching_tokens_passes() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let token = generate_csrf_token().unwrap();
        let resp = app
            .oneshot(make_request_with_csrf("PUT", "/api/test", &token, &token))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn delete_with_matching_tokens_passes() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let token = generate_csrf_token().unwrap();
        let resp = app
            .oneshot(make_request_with_csrf(
                "DELETE",
                "/api/test",
                &token,
                &token,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn disabled_config_passes_all() {
        let config = CsrfConfig {
            enabled: false,
            ..Default::default()
        };
        let app = make_app(config);
        // POST 无 token，但 enabled=false，应放行
        let resp = app
            .clone()
            .oneshot(make_request("POST", "/api/test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // GET 也应放行
        let resp = app.oneshot(make_request("GET", "/api/test")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // ----------------------------------------------------------------
    // Origin/Referer 同源校验测试
    // ----------------------------------------------------------------

    /// 受保护方法的跨源请求（Origin 不匹配 Host）应被拒绝。
    #[tokio::test]
    async fn csrf_middleware_rejects_cross_origin_request() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let token = generate_csrf_token().unwrap();
        // Origin = evil.com，Host = example.com → 跨源
        let req = Request::builder()
            .method("POST")
            .uri("/api/test")
            .header("host", "example.com")
            .header("origin", "https://evil.com")
            .header("cookie", format!("bulwark_csrf_token={}", token))
            .header("X-CSRF-Token", &token)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::FORBIDDEN,
            "VULN-0006: 跨源请求应被 CSRF 中间件拒绝"
        );
    }

    /// 受保护方法的同源请求（Origin 匹配 Host）应通过。
    #[tokio::test]
    async fn csrf_middleware_allows_same_origin_request() {
        let config = CsrfConfig {
            enabled: true,
            ..Default::default()
        };
        let app = make_app(config);
        let token = generate_csrf_token().unwrap();
        // Origin = example.com，Host = example.com → 同源
        let req = Request::builder()
            .method("POST")
            .uri("/api/test")
            .header("host", "example.com")
            .header("origin", "https://example.com")
            .header("cookie", format!("bulwark_csrf_token={}", token))
            .header("X-CSRF-Token", &token)
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "VULN-0006: 同源请求应通过 CSRF 中间件"
        );
    }
}
