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
use crate::strategy::firewall::{WafContext, WafHookChain};
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
    use crate::strategy::firewall::{BlackPathHook, DangerCharacterHook};
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

    // ========================================================================
    // parse_query 单元测试
    // ========================================================================

    /// parse_query 解析标准 query string。
    #[test]
    fn parse_query_standard() {
        let result = parse_query("key1=value1&key2=value2");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], ("key1".to_string(), "value1".to_string()));
        assert_eq!(result[1], ("key2".to_string(), "value2".to_string()));
    }

    /// parse_query 解析无值的参数（key 无 =）。
    #[test]
    fn parse_query_key_without_value() {
        let result = parse_query("flag&key=val");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], ("flag".to_string(), "".to_string()));
        assert_eq!(result[1], ("key".to_string(), "val".to_string()));
    }

    /// parse_query 解析空字符串返回空 Vec。
    #[test]
    fn parse_query_empty_string() {
        let result = parse_query("");
        assert!(result.is_empty());
    }

    /// parse_query 跳过空段（连续 & 符号）。
    #[test]
    fn parse_query_skips_empty_segments() {
        let result = parse_query("key=val&&&key2=val2");
        assert_eq!(result.len(), 2);
        assert_eq!(result[0], ("key".to_string(), "val".to_string()));
        assert_eq!(result[1], ("key2".to_string(), "val2".to_string()));
    }

    /// parse_query 解析单个 key=value。
    #[test]
    fn parse_query_single_pair() {
        let result = parse_query("name=alice");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], ("name".to_string(), "alice".to_string()));
    }

    /// parse_query 解析 key= （值为空）。
    #[test]
    fn parse_query_empty_value() {
        let result = parse_query("empty=");
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], ("empty".to_string(), "".to_string()));
    }

    // ========================================================================
    // parse_firewall_blocked 单元测试
    // ========================================================================

    /// parse_firewall_blocked 解析标准格式 "[hook] reason"。
    #[test]
    fn parse_firewall_blocked_standard_format() {
        let (hook, reason) = parse_firewall_blocked("[black_path] 路径 /admin 命中黑名单");
        assert_eq!(hook, "black_path");
        assert_eq!(reason, "路径 /admin 命中黑名单");
    }

    /// parse_firewall_blocked 解析无前导空格的 reason。
    #[test]
    fn parse_firewall_blocked_no_leading_space() {
        let (hook, reason) = parse_firewall_blocked("[sql_inject]检测到SQL注入");
        assert_eq!(hook, "sql_inject");
        assert_eq!(reason, "检测到SQL注入");
    }

    /// parse_firewall_blocked 无 [hook] 前缀时返回 ("unknown", 原文)。
    #[test]
    fn parse_firewall_blocked_no_bracket_returns_unknown() {
        let (hook, reason) = parse_firewall_blocked("普通错误消息");
        assert_eq!(hook, "unknown");
        assert_eq!(reason, "普通错误消息");
    }

    /// parse_firewall_blocked 有 [ 但无 ] 时返回 ("unknown", 原文)。
    #[test]
    fn parse_firewall_blocked_open_bracket_no_close() {
        let (hook, reason) = parse_firewall_blocked("[incomplete hook message");
        assert_eq!(hook, "unknown");
        assert_eq!(reason, "[incomplete hook message");
    }

    /// parse_firewall_blocked 空中括号 "[]" 返回 ("", "")。
    #[test]
    fn parse_firewall_blocked_empty_brackets() {
        let (hook, reason) = parse_firewall_blocked("[]");
        assert_eq!(hook, "");
        assert_eq!(reason, "");
    }

    /// parse_firewall_blocked 空字符串返回 ("unknown", "")。
    #[test]
    fn parse_firewall_blocked_empty_string() {
        let (hook, reason) = parse_firewall_blocked("");
        assert_eq!(hook, "unknown");
        assert_eq!(reason, "");
    }

    /// parse_firewall_blocked 只有 [hook] 无 reason。
    #[test]
    fn parse_firewall_blocked_hook_only_no_reason() {
        let (hook, reason) = parse_firewall_blocked("[rate_limit]");
        assert_eq!(hook, "rate_limit");
        assert_eq!(reason, "");
    }

    // ========================================================================
    // middleware 查询参数与 host header 测试
    // ========================================================================

    /// 验证带查询参数的请求能正确传递给 WAF Hook。
    #[tokio::test]
    async fn middleware_passes_query_params() {
        let mut chain = WafHookChain::new();
        // DangerCharacterHook 检查危险字符，通过查询参数触发
        chain.register(Box::new(DangerCharacterHook::new()));
        let app = make_app(chain);
        // 合法查询参数应放行
        let resp = app
            .clone()
            .oneshot(make_request("GET", "/api/test?name=alice&page=1"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// 验证 middleware 正确处理 host header。
    #[tokio::test]
    async fn middleware_handles_host_header() {
        let mut chain = WafHookChain::new();
        chain.register(Box::new(BlackPathHook::new(vec!["/admin".to_string()])));
        let app = make_app(chain);

        let req = Request::builder()
            .method("GET")
            .uri("/api/test")
            .header("host", "example.com")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// 验证空查询参数不导致 panic。
    #[tokio::test]
    async fn middleware_handles_empty_query() {
        let mut chain = WafHookChain::new();
        chain.register(Box::new(BlackPathHook::new(vec!["/admin".to_string()])));
        let app = make_app(chain);
        // 带空查询参数的请求
        let resp = app
            .oneshot(make_request("GET", "/api/test?"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
