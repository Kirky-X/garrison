//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! WAF middleware 适配器（firewall-waf）。
//!
//! 将 [`WafHookChain`](crate::strategy::firewall::waf::WafHookChain) 包装为 axum middleware，
//! 对每个请求执行 Hook 链校验，任一 Hook 返回 Deny 则返回 403 Forbidden。
//!
//! # 与 web-waf 的区分
//!
//! - `web-waf`（web 层）：`bulwark_waf_middleware`，返回 400 Bad Request
//! - `firewall-waf`（strategy 层）：`waf_middleware`，返回 403 Forbidden
//!
//! # 使用
//!
//! ```ignore
//! use bulwark::strategy::firewall::waf::WafHookChain;
//! use bulwark::web::axum::waf::waf_middleware;
//! use std::sync::Arc;
//! use axum::Router;
//!
//! let mut chain = WafHookChain::new();
//! // chain.register(...);
//! let app = Router::new()
//!     .route("/api", axum::routing::get(|| async { "ok" }))
//!     .layer(axum::middleware::from_fn_with_state(
//!         Arc::new(chain),
//!         waf_middleware,
//!     ));
//! ```

use crate::error::BulwarkError;
use crate::strategy::firewall::waf::{WafContext, WafHookChain};
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use std::sync::Arc;

/// 解析 query string 为 (key, value) 列表。
fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter_map(|kv| {
            if kv.is_empty() {
                return None;
            }
            let mut parts = kv.splitn(2, '=');
            let key = parts.next()?.to_string();
            let value = parts.next().unwrap_or("").to_string();
            Some((key, value))
        })
        .collect()
}

/// 从 `FirewallBlocked` 编码字符串中解析 hook 和 reason。
///
/// 编码格式：`"[hook] reason"`（由 `WafHookChain::check` 生成）。
fn parse_firewall_blocked(s: &str) -> (&str, &str) {
    if s.starts_with('[') {
        if let Some(close) = s.find(']') {
            let hook = &s[1..close];
            let reason = s[close + 1..].trim_start();
            return (hook, reason);
        }
    }
    ("unknown", s)
}

/// WAF 级防火墙 axum middleware。
///
/// 将 [`WafHookChain`] 包装为 axum middleware，对每个请求执行 Hook 链校验。
/// 任一 Hook 返回 `Deny` 则短路返回 403 Forbidden，响应体为 JSON：
///
/// ```json
/// {
///     "error": "firewall_blocked",
///     "hook": "black_path",
///     "reason": "路径 /admin 命中黑名单"
/// }
/// ```
pub async fn waf_middleware(
    State(chain): State<Arc<WafHookChain>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // 提取请求信息（owned，供 WafContext 借用）
    let path = req.uri().path().to_string();
    let method = req.method().as_str().to_string();
    let host = req
        .headers()
        .get("host")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            )
        })
        .collect();
    let params: Vec<(String, String)> = req.uri().query().map(parse_query).unwrap_or_default();

    let ctx = WafContext {
        path: &path,
        method: &method,
        host: host.as_deref(),
        headers: &headers,
        params: &params,
    };

    match chain.check(&ctx).await {
        Ok(()) => next.run(req).await,
        Err(BulwarkError::FirewallBlocked(s)) => {
            let (hook, reason) = parse_firewall_blocked(&s);
            let body = serde_json::json!({
                "error": "firewall_blocked",
                "hook": hook,
                "reason": reason,
            });
            (StatusCode::FORBIDDEN, axum::Json(body)).into_response()
        },
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            axum::Json(serde_json::json!({
                "error": "internal_error",
                "message": e.to_string(),
            })),
        )
            .into_response(),
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::firewall::waf_hooks::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn make_app(chain: WafHookChain) -> Router {
        Router::new()
            .route("/api/test", get(|| async { "ok" }))
            .route("/admin/test", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                Arc::new(chain),
                waf_middleware,
            ))
    }

    fn make_request(method: &str, path: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap()
    }

    /// 验证合法请求放行。
    #[tokio::test]
    async fn middleware_allows_clean_request() {
        let mut chain = WafHookChain::new();
        chain.register(Box::new(BlackPathHook::new(vec!["/admin".to_string()])));
        let app = make_app(chain);
        let resp = app.oneshot(make_request("GET", "/api/test")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// 验证恶意请求被拦截返回 403。
    #[tokio::test]
    async fn middleware_blocks_malicious_request() {
        let mut chain = WafHookChain::new();
        chain.register(Box::new(BlackPathHook::new(vec!["/admin".to_string()])));
        let app = make_app(chain);
        let resp = app
            .oneshot(make_request("GET", "/admin/test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// 验证多 Hook 链式执行。
    #[tokio::test]
    async fn middleware_multiple_hooks_chain() {
        let mut chain = WafHookChain::new();
        chain.register(Box::new(DangerCharacterHook::new()));
        chain.register(Box::new(BlackPathHook::new(vec!["/admin".to_string()])));
        let app = make_app(chain);
        // 危险字符拦截 //
        let resp = app
            .clone()
            .oneshot(make_request("GET", "/api//test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // 黑名单拦截 /admin
        let resp = app
            .clone()
            .oneshot(make_request("GET", "/admin/test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        // 合法请求放行
        let resp = app.oneshot(make_request("GET", "/api/test")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// 验证错误响应为 JSON 格式含 error/hook/reason 字段。
    #[tokio::test]
    async fn middleware_error_response_format() {
        let mut chain = WafHookChain::new();
        chain.register(Box::new(BlackPathHook::new(vec!["/admin".to_string()])));
        let app = make_app(chain);
        let resp = app
            .oneshot(make_request("GET", "/admin/test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(body["error"], "firewall_blocked");
        assert_eq!(body["hook"], "black_path");
        assert!(
            body["reason"].as_str().unwrap().contains("/admin"),
            "reason 应包含路径，实际: {}",
            body["reason"]
        );
    }
}
