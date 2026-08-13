//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! HTTP 安全响应头中间件。
//!
//! 为所有响应添加标准安全头，防止 MIME 嗅探、点击劫持、缓存泄露等攻击：
//!
//! | Header | Value | 防护 |
//! |--------|-------|------|
//! | `X-Content-Type-Options` | `nosniff` | MIME 类型嗅探 |
//! | `X-Frame-Options` | `DENY` | 点击劫持 |
//! | `Cache-Control` | `no-store` | 敏感响应缓存 |
//! | `Pragma` | `no-cache` | HTTP/1.0 兼容缓存控制 |
//! | `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | SSL 降级（仅 `tls` feature） |
//!
//! # Feature 门控
//!
//! 仅在 `web-security-headers` feature 启用时编译。

use axum::http::header::HeaderName;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;

/// `X-Content-Type-Options: nosniff` — 阻止浏览器 MIME 类型嗅探。
const X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");
const NOSNIFF: HeaderValue = HeaderValue::from_static("nosniff");

/// `X-Frame-Options: DENY` — 阻止页面被嵌入 iframe（防点击劫持）。
const X_FRAME_OPTIONS: HeaderName = HeaderName::from_static("x-frame-options");
const DENY: HeaderValue = HeaderValue::from_static("DENY");

/// `Cache-Control: no-store` — 禁止缓存敏感认证响应。
const CACHE_CONTROL: HeaderName = HeaderName::from_static("cache-control");
const NO_STORE: HeaderValue = HeaderValue::from_static("no-store");

/// `Pragma: no-cache` — HTTP/1.0 兼容缓存控制。
const PRAGMA: HeaderName = HeaderName::from_static("pragma");
const NO_CACHE: HeaderValue = HeaderValue::from_static("no-cache");

/// `Strict-Transport-Security` — HSTS 头名称（仅 `tls` feature 启用时使用）。
#[cfg(feature = "tls")]
const STRICT_TRANSPORT_SECURITY: HeaderName = HeaderName::from_static("strict-transport-security");

/// HSTS 值：1 年 + includeSubDomains（仅 `tls` feature 启用时使用）。
#[cfg(feature = "tls")]
const HSTS_MAX_AGE: HeaderValue = HeaderValue::from_static("max-age=31536000; includeSubDomains");

/// 安全响应头中间件 — 为所有响应注入标准安全头。
///
/// 挂载到 axum Router 后，所有经过此中间件的响应都会自动添加：
/// - `X-Content-Type-Options: nosniff`
/// - `X-Frame-Options: DENY`
/// - `Cache-Control: no-store`
/// - `Pragma: no-cache`
/// - （`tls` feature 启用时）`Strict-Transport-Security: max-age=31536000; includeSubDomains`
///
/// # 示例
///
/// ```ignore
/// use axum::middleware;
/// use garrison::web::security_headers::security_headers_middleware;
///
/// let app = Router::new()
///     .route("/api", get(handler))
///     .layer(middleware::from_fn(security_headers_middleware));
/// ```
pub async fn security_headers_middleware(req: axum::extract::Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();

    headers.insert(X_CONTENT_TYPE_OPTIONS, NOSNIFF);
    headers.insert(X_FRAME_OPTIONS, DENY);
    headers.insert(CACHE_CONTROL, NO_STORE);
    headers.insert(PRAGMA, NO_CACHE);

    // HSTS 仅在 TLS 终止模式下设置（明文传输 HSTS 无意义且可能被降级攻击）
    #[cfg(feature = "tls")]
    headers.insert(STRICT_TRANSPORT_SECURITY, HSTS_MAX_AGE);

    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    /// 创建包含安全头中间件的测试 Router。
    fn app_with_security_headers() -> Router {
        Router::new()
            .route("/ping", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn(security_headers_middleware))
    }

    /// 验证所有基础安全头存在于响应中且值正确。
    #[tokio::test]
    async fn security_headers_present_in_response() {
        let app = app_with_security_headers();
        let resp = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let headers = resp.headers();

        assert_eq!(
            headers.get("x-content-type-options").unwrap(),
            "nosniff",
            "X-Content-Type-Options 应为 nosniff"
        );
        assert_eq!(
            headers.get("x-frame-options").unwrap(),
            "DENY",
            "X-Frame-Options 应为 DENY"
        );
        assert_eq!(
            headers.get("cache-control").unwrap(),
            "no-store",
            "Cache-Control 应为 no-store"
        );
        assert_eq!(
            headers.get("pragma").unwrap(),
            "no-cache",
            "Pragma 应为 no-cache"
        );
    }

    /// 非 TLS 构建时响应不应包含 HSTS 头。
    ///
    /// 注意：此测试在 `tls` feature 启用时行为相反（HSTS 应存在）。
    /// 通过 `cfg(not(feature = "tls"))` 确保仅在非 TLS 构建时验证 HSTS 缺失。
    #[cfg(not(feature = "tls"))]
    #[tokio::test]
    async fn no_hsts_without_tls_feature() {
        let app = app_with_security_headers();
        let resp = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert!(
            resp.headers().get("strict-transport-security").is_none(),
            "tls feature 未启用时不应设置 HSTS 头"
        );
    }

    /// TLS 构建时响应应包含 HSTS 头。
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn hsts_present_with_tls_feature() {
        let app = app_with_security_headers();
        let resp = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();

        assert_eq!(
            resp.headers().get("strict-transport-security").unwrap(),
            "max-age=31536000; includeSubDomains",
            "tls feature 启用时应设置 HSTS 头"
        );
    }

    /// 错误响应（如 404）也应包含安全头。
    #[tokio::test]
    async fn security_headers_on_error_responses() {
        let app = app_with_security_headers();
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            resp.headers().get("x-content-type-options").unwrap(),
            "nosniff",
            "错误响应也应包含安全头"
        );
        assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
    }
}
