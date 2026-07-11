//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! CORS 跨域资源共享中间件模块。
//!
//! 提供 [`CorsConfig`](crate::web::cors::CorsConfig) 配置与 [`bulwark_cors_middleware`](crate::web::cors::bulwark_cors_middleware) axum 中间件，
//! 支持 CORS 预检（OPTIONS）与实际请求的响应头注入。
//!
//! # 行为
//!
//! - **OPTIONS 预检请求**：Origin 匹配时返回 204 No Content 并注入 CORS 预检响应头；
//!   Origin 不匹配时透传（不注入 CORS 头）。
//! - **实际请求**（非 OPTIONS）：Origin 匹配时注入 CORS 响应头后继续到下一 handler；
//!   Origin 不匹配时透传。
//! - **无 Origin header**：视为非 CORS 请求，直接透传。
//!
//! # 配置
//!
//! 通过 [`CorsConfig`](crate::web::cors::CorsConfig) 控制允许的源、方法、headers 等，集成到 [`crate::config::BulwarkConfig`]。

use crate::error::{BulwarkError, BulwarkResult};
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};

/// CORS 中间件配置。
///
/// 控制允许的跨域来源、方法、headers 等参数。
///
/// # 默认值
///
/// - `allowed_origins`：空列表（不允许任何跨域请求）
/// - `allowed_methods`：`["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]`
/// - `allowed_headers`：`["Authorization", "Content-Type"]`
/// - `exposed_headers`：空列表
/// - `allow_credentials`：`false`
/// - `max_age_secs`：`86400`（24 小时）
///
/// # 配置示例
///
/// ```toml
/// [cors_config]
/// allowed_origins = ["https://example.com"]
/// allowed_methods = ["GET", "POST"]
/// allow_credentials = true
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CorsConfig {
    /// 允许的跨域来源列表（精确匹配，`"*"` 表示通配允许所有来源）。
    pub allowed_origins: Vec<String>,
    /// 允许的 HTTP 方法列表。
    pub allowed_methods: Vec<String>,
    /// 允许的请求 header 列表。
    pub allowed_headers: Vec<String>,
    /// 允许浏览器读取的响应 header 列表（空时不注入 Expose-Headers）。
    pub exposed_headers: Vec<String>,
    /// 是否允许携带凭证（Cookie / Authorization）。
    pub allow_credentials: bool,
    /// 预检结果缓存秒数。
    pub max_age_secs: u64,
}

impl Default for CorsConfig {
    fn default() -> Self {
        Self {
            allowed_origins: Vec::new(),
            allowed_methods: vec![
                "GET".to_string(),
                "POST".to_string(),
                "PUT".to_string(),
                "DELETE".to_string(),
                "HEAD".to_string(),
                "OPTIONS".to_string(),
            ],
            allowed_headers: vec!["Authorization".to_string(), "Content-Type".to_string()],
            exposed_headers: Vec::new(),
            allow_credentials: false,
            max_age_secs: 86400,
        }
    }
}

impl CorsConfig {
    /// 校验 CORS 配置合法性。
    ///
    /// # 校验规则
    ///
    /// - 若 `allow_credentials == true` 且 `allowed_origins` 包含 `"*"`，返回 `Err`：
    ///   CORS 规范禁止 credentials 与通配符 origin 同时使用。
    ///
    /// # 错误
    ///
    /// - `BulwarkError::Config`：credentials 与通配符 origin 冲突。
    pub fn validate(&self) -> BulwarkResult<()> {
        if self.allow_credentials && self.allowed_origins.iter().any(|o| o == "*") {
            return Err(BulwarkError::Config(
                "CORS 配置冲突：allow_credentials=true 时不允许 allowed_origins 包含通配符 \"*\""
                    .to_string(),
            ));
        }
        Ok(())
    }
}

/// 判断给定的 origin 是否在允许列表中。
///
/// # 匹配规则
///
/// 1. `allowed` 为空：返回 `false`（不允许任何来源）
/// 2. `allowed` 包含 `"*"`：返回 `true`（通配允许所有来源）
/// 3. 否则：精确匹配（大小写敏感）
pub fn origin_matches(origin: &str, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return false;
    }
    if allowed.iter().any(|o| o == "*") {
        return true;
    }
    allowed.iter().any(|o| o == origin)
}

/// 计算响应中的 `Access-Control-Allow-Origin` 值。
///
/// - 通配符（allowed 包含 `"*"`）：返回 `"*"`
/// - 否则：返回 origin 本身
fn allow_origin_value<'a>(origin: &'a str, allowed: &'a [String]) -> &'a str {
    if allowed.iter().any(|o| o == "*") {
        "*"
    } else {
        origin
    }
}

/// 将字符串列表拼接为逗号分隔的单个 HeaderValue。
fn join_headers(items: &[String]) -> HeaderValue {
    // SAFETY: CORS header 值均为 ASCII token，HeaderName/HeaderValue::from_str 不会失败。
    let joined = items.join(", ");
    HeaderValue::from_str(&joined).unwrap_or(HeaderValue::from_static(""))
}

/// CORS 中间件。
///
/// 处理 CORS 预检请求（OPTIONS）与实际请求的响应头注入。
///
/// # 行为
///
/// ## OPTIONS 预检请求
///
/// 1. 提取 `Origin` header，若无则透传（非 CORS 请求）
/// 2. Origin 不匹配 `config.allowed_origins` 时透传（不注入 CORS 头）
/// 3. Origin 匹配时注入预检响应头并返回 204 No Content：
///    - `Access-Control-Allow-Origin`
///    - `Access-Control-Allow-Methods`
///    - `Access-Control-Allow-Headers`
///    - `Access-Control-Allow-Credentials`（仅当 `allow_credentials == true`）
///    - `Access-Control-Max-Age`
///
/// ## 实际请求（非 OPTIONS）
///
/// 1. 提取 `Origin` header，若无则透传
/// 2. Origin 匹配时注入响应头后继续到下一 handler：
///    - `Access-Control-Allow-Origin`
///    - `Access-Control-Expose-Headers`（仅当 `exposed_headers` 非空）
///    - `Access-Control-Allow-Credentials`（仅当 `allow_credentials == true`）
/// 3. Origin 不匹配时透传
///
/// # 使用
///
/// ```ignore
/// use bulwark::web::cors::{bulwark_cors_middleware, CorsConfig};
/// use std::sync::Arc;
/// use axum::Router;
///
/// let config = CorsConfig {
///     allowed_origins: vec!["https://example.com".to_string()],
///     ..Default::default()
/// };
/// let app = Router::new()
///     .route("/api", axum::routing::get(|| async { "ok" }))
///     .layer(axum::middleware::from_fn_with_state(
///         Arc::new(config),
///         bulwark_cors_middleware,
///     ));
/// ```
pub async fn bulwark_cors_middleware(
    State(config): State<std::sync::Arc<CorsConfig>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    let origin = match req.headers().get(axum::http::header::ORIGIN) {
        Some(v) => v.to_str().unwrap_or("").to_string(),
        None => return next.run(req).await,
    };

    if origin.is_empty() {
        return next.run(req).await;
    }

    if !origin_matches(&origin, &config.allowed_origins) {
        return next.run(req).await;
    }

    let allow_origin = allow_origin_value(&origin, &config.allowed_origins);

    // OPTIONS 预检请求：短路返回 204
    if req.method() == axum::http::Method::OPTIONS {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_str(allow_origin).unwrap_or(HeaderValue::from_static("*")),
        );
        headers.insert(
            HeaderName::from_static("access-control-allow-methods"),
            join_headers(&config.allowed_methods),
        );
        headers.insert(
            HeaderName::from_static("access-control-allow-headers"),
            join_headers(&config.allowed_headers),
        );
        if config.allow_credentials {
            headers.insert(
                HeaderName::from_static("access-control-allow-credentials"),
                HeaderValue::from_static("true"),
            );
        }
        headers.insert(
            HeaderName::from_static("access-control-max-age"),
            HeaderValue::from_str(&config.max_age_secs.to_string())
                .unwrap_or(HeaderValue::from_static("86400")),
        );
        return (StatusCode::NO_CONTENT, headers).into_response();
    }

    // 实际请求：注入响应头后继续
    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    headers.insert(
        axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_str(allow_origin).unwrap_or(HeaderValue::from_static("*")),
    );
    if !config.exposed_headers.is_empty() {
        headers.insert(
            HeaderName::from_static("access-control-expose-headers"),
            join_headers(&config.exposed_headers),
        );
    }
    if config.allow_credentials {
        headers.insert(
            HeaderName::from_static("access-control-allow-credentials"),
            HeaderValue::from_static("true"),
        );
    }
    resp
}

// ============================================================================
// 测试
// ============================================================================

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

    fn make_app(config: CorsConfig) -> Router {
        Router::new()
            .route("/api/test", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                Arc::new(config),
                bulwark_cors_middleware,
            ))
    }

    fn make_request(method: &str, path: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap()
    }

    fn make_request_with_origin(method: &str, path: &str, origin: &str) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(path)
            .header("origin", origin)
            .body(Body::empty())
            .unwrap()
    }

    // ========================================================================
    // T007: origin_matches 单元测试（10 个）
    // ========================================================================

    #[test]
    fn origin_matches_exact_match() {
        let allowed = vec!["https://example.com".to_string()];
        assert!(origin_matches("https://example.com", &allowed));
    }

    #[test]
    fn origin_matches_wildcard() {
        let allowed = vec!["*".to_string()];
        assert!(origin_matches("https://anything.com", &allowed));
        assert!(origin_matches("http://localhost:3000", &allowed));
    }

    #[test]
    fn origin_matches_multiple_origins() {
        let allowed = vec![
            "https://a.com".to_string(),
            "https://b.com".to_string(),
            "https://c.com".to_string(),
        ];
        assert!(origin_matches("https://a.com", &allowed));
        assert!(origin_matches("https://b.com", &allowed));
        assert!(origin_matches("https://c.com", &allowed));
    }

    #[test]
    fn origin_matches_no_match() {
        let allowed = vec!["https://example.com".to_string()];
        assert!(!origin_matches("https://evil.com", &allowed));
    }

    #[test]
    fn origin_matches_empty_list() {
        let allowed: Vec<String> = vec![];
        assert!(!origin_matches("https://example.com", &allowed));
    }

    #[test]
    fn origin_matches_with_port() {
        let allowed = vec!["http://localhost:3000".to_string()];
        assert!(origin_matches("http://localhost:3000", &allowed));
        assert!(!origin_matches("http://localhost:8080", &allowed));
    }

    #[test]
    fn origin_matches_with_protocol() {
        let allowed = vec!["https://example.com".to_string()];
        assert!(origin_matches("https://example.com", &allowed));
        assert!(!origin_matches("http://example.com", &allowed));
    }

    #[test]
    fn origin_matches_case_sensitive() {
        let allowed = vec!["https://Example.COM".to_string()];
        assert!(origin_matches("https://Example.COM", &allowed));
        assert!(!origin_matches("https://example.com", &allowed));
    }

    #[test]
    fn origin_matches_wildcard_with_credentials_scenario() {
        // 通配符场景：即使 allow_credentials=true，origin_matches 仍返回 true
        // credentials 冲突由 validate() 检查，不在匹配逻辑中处理
        let allowed = vec!["*".to_string()];
        assert!(origin_matches("https://example.com", &allowed));
    }

    #[test]
    fn origin_matches_mixed_exact_and_wildcard() {
        let allowed = vec!["https://example.com".to_string(), "*".to_string()];
        // 通配符存在，任何 origin 都应匹配
        assert!(origin_matches("https://anything.com", &allowed));
        assert!(origin_matches("https://example.com", &allowed));
    }

    // ========================================================================
    // T008: 预检请求（OPTIONS）集成测试（8 个）
    // ========================================================================

    #[tokio::test]
    async fn preflight_matching_origin_returns_204() {
        let config = CorsConfig {
            allowed_origins: vec!["https://example.com".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request_with_origin(
                "OPTIONS",
                "/api/test",
                "https://example.com",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "https://example.com"
        );
    }

    #[tokio::test]
    async fn preflight_non_matching_origin_no_cors_headers() {
        let config = CorsConfig {
            allowed_origins: vec!["https://example.com".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        // 非匹配 origin 透传，OPTIONS 请求未匹配路由 → 404，但不应有 CORS 头
        let resp = app
            .oneshot(make_request_with_origin(
                "OPTIONS",
                "/api/test",
                "https://evil.com",
            ))
            .await
            .unwrap();
        assert!(resp.headers().get("access-control-allow-origin").is_none());
    }

    #[tokio::test]
    async fn preflight_with_credentials_injects_header() {
        let config = CorsConfig {
            allowed_origins: vec!["https://example.com".to_string()],
            allow_credentials: true,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request_with_origin(
                "OPTIONS",
                "/api/test",
                "https://example.com",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers()
                .get("access-control-allow-credentials")
                .unwrap(),
            "true"
        );
    }

    #[tokio::test]
    async fn preflight_no_origin_header_passes_through() {
        let config = CorsConfig {
            allowed_origins: vec!["https://example.com".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        // 无 Origin header 透传，OPTIONS 未匹配路由 → 404
        let resp = app
            .oneshot(make_request("OPTIONS", "/api/test"))
            .await
            .unwrap();
        assert!(resp.headers().get("access-control-allow-origin").is_none());
    }

    #[tokio::test]
    async fn preflight_wildcard_origin_returns_star() {
        let config = CorsConfig {
            allowed_origins: vec!["*".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request_with_origin(
                "OPTIONS",
                "/api/test",
                "https://anything.com",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "*"
        );
    }

    #[tokio::test]
    async fn preflight_verifies_allow_methods() {
        let config = CorsConfig {
            allowed_origins: vec!["https://example.com".to_string()],
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request_with_origin(
                "OPTIONS",
                "/api/test",
                "https://example.com",
            ))
            .await
            .unwrap();
        let methods = resp
            .headers()
            .get("access-control-allow-methods")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(methods.contains("GET"));
        assert!(methods.contains("POST"));
    }

    #[tokio::test]
    async fn preflight_verifies_allow_headers() {
        let config = CorsConfig {
            allowed_origins: vec!["https://example.com".to_string()],
            allowed_headers: vec!["Authorization".to_string(), "X-Custom".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request_with_origin(
                "OPTIONS",
                "/api/test",
                "https://example.com",
            ))
            .await
            .unwrap();
        let headers = resp
            .headers()
            .get("access-control-allow-headers")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(headers.contains("Authorization"));
        assert!(headers.contains("X-Custom"));
    }

    #[tokio::test]
    async fn preflight_verifies_max_age() {
        let config = CorsConfig {
            allowed_origins: vec!["https://example.com".to_string()],
            max_age_secs: 3600,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request_with_origin(
                "OPTIONS",
                "/api/test",
                "https://example.com",
            ))
            .await
            .unwrap();
        let max_age = resp
            .headers()
            .get("access-control-max-age")
            .unwrap()
            .to_str()
            .unwrap();
        assert_eq!(max_age, "3600");
    }

    // ========================================================================
    // T009: 实际请求（非 OPTIONS）集成测试（6 个）
    // ========================================================================

    #[tokio::test]
    async fn actual_request_matching_origin_injects_headers() {
        let config = CorsConfig {
            allowed_origins: vec!["https://example.com".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request_with_origin(
                "GET",
                "/api/test",
                "https://example.com",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "https://example.com"
        );
    }

    #[tokio::test]
    async fn actual_request_non_matching_origin_no_headers() {
        let config = CorsConfig {
            allowed_origins: vec!["https://example.com".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request_with_origin(
                "GET",
                "/api/test",
                "https://evil.com",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("access-control-allow-origin").is_none());
    }

    #[tokio::test]
    async fn actual_request_exposed_headers_injection() {
        let config = CorsConfig {
            allowed_origins: vec!["https://example.com".to_string()],
            exposed_headers: vec!["X-Total-Count".to_string(), "X-Page".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request_with_origin(
                "GET",
                "/api/test",
                "https://example.com",
            ))
            .await
            .unwrap();
        let exposed = resp
            .headers()
            .get("access-control-expose-headers")
            .unwrap()
            .to_str()
            .unwrap();
        assert!(exposed.contains("X-Total-Count"));
        assert!(exposed.contains("X-Page"));
    }

    #[tokio::test]
    async fn actual_request_credentials_true() {
        let config = CorsConfig {
            allowed_origins: vec!["https://example.com".to_string()],
            allow_credentials: true,
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request_with_origin(
                "GET",
                "/api/test",
                "https://example.com",
            ))
            .await
            .unwrap();
        assert_eq!(
            resp.headers()
                .get("access-control-allow-credentials")
                .unwrap(),
            "true"
        );
    }

    #[tokio::test]
    async fn actual_request_no_origin_passes_through() {
        let config = CorsConfig {
            allowed_origins: vec!["https://example.com".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app.oneshot(make_request("GET", "/api/test")).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert!(resp.headers().get("access-control-allow-origin").is_none());
    }

    #[tokio::test]
    async fn actual_request_wildcard_origin() {
        let config = CorsConfig {
            allowed_origins: vec!["*".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        let resp = app
            .oneshot(make_request_with_origin(
                "GET",
                "/api/test",
                "https://anything.com",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers().get("access-control-allow-origin").unwrap(),
            "*"
        );
    }

    // ========================================================================
    // T010: CorsConfig::validate() 单元测试（5 个）
    // ========================================================================

    #[test]
    fn validate_valid_config_passes() {
        let config = CorsConfig {
            allowed_origins: vec!["https://example.com".to_string()],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_credentials_with_wildcard_fails() {
        let config = CorsConfig {
            allowed_origins: vec!["*".to_string()],
            allow_credentials: true,
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_credentials_with_exact_origin_passes() {
        let config = CorsConfig {
            allowed_origins: vec!["https://example.com".to_string()],
            allow_credentials: true,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_empty_origins_passes() {
        let config = CorsConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_after_setting_fields() {
        let mut config = CorsConfig::default();
        // 初始 valid
        assert!(config.validate().is_ok());
        // 设置通配符 + credentials 后应失败
        config.allowed_origins = vec!["*".to_string()];
        config.allow_credentials = true;
        assert!(config.validate().is_err());
        // 改回精确 origin 后应通过
        config.allowed_origins = vec!["https://safe.com".to_string()];
        assert!(config.validate().is_ok());
    }
}
