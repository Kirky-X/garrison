// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! CORS 跨域资源共享中间件（axum）：OPTIONS 预检一律短路 204，仅 Origin 匹配时注入 CORS 头；
//! 实际请求仅 Origin 匹配时注入响应头（必带 `Vary: Origin` 供缓存区分），配置见 [`CorsConfig`](crate::web::cors::CorsConfig)。

use crate::error::{GarrisonError, GarrisonResult};
use axum::extract::State;
use axum::http::{HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};

/// CORS 中间件配置：默认收紧（`allowed_origins` 为空时不放行任何跨域，`allow_credentials` 默认 false）。
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
    /// 校验配置：credentials 与通配符 origin 不可同时使用（CORS 规范），冲突返回 `GarrisonError::Config`。
    pub fn validate(&self) -> GarrisonResult<()> {
        if self.allow_credentials && self.allowed_origins.iter().any(|o| o == "*") {
            return Err(GarrisonError::Config(
                "cors-credentials-wildcard::".to_string(),
            ));
        }
        Ok(())
    }
}

/// origin 是否命中允许列表：空列表不匹配，含 `"*"` 通配，否则大小写敏感精确匹配。
pub fn origin_matches(origin: &str, allowed: &[String]) -> bool {
    if allowed.is_empty() {
        return false;
    }
    if allowed.iter().any(|o| o == "*") {
        return true;
    }
    allowed.iter().any(|o| o == origin)
}

/// 计算 `Access-Control-Allow-Origin` 值：配置含 `"*"` 时返回 `"*"`，否则回显 origin。
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

/// CORS 中间件：OPTIONS 一律短路 204——Origin 匹配时注入 Allow-Origin/Methods/Headers/Max-Age
/// （`allow_credentials` 时加 Allow-Credentials），否则 204 无 CORS 头；实际请求仅 Origin 匹配时注入
/// Allow-Origin/Expose-Headers/Credentials 并继续，否则透传。
///
/// # 使用
///
/// ```ignore
/// use garrison::web::cors::{garrison_cors_middleware, CorsConfig};
/// use std::sync::Arc;
/// use axum::Router;
///
/// let config = CorsConfig {
/// allowed_origins: vec!["https://example.com".to_string()],
/// ..Default::default()
/// };
/// let app = Router::new()
/// .route("/api", axum::routing::get(|| async { "ok" }))
/// .layer(axum::middleware::from_fn_with_state(
/// Arc::new(config),
/// garrison_cors_middleware,
/// ));
/// ```
pub async fn garrison_cors_middleware(
    State(config): State<std::sync::Arc<CorsConfig>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    // OPTIONS 预检请求：无论 Origin 是否匹配均短路返回 204
    if req.method() == axum::http::Method::OPTIONS {
        let origin = req
            .headers()
            .get(axum::http::header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // 仅 Origin 非空且匹配时注入 CORS 头；无 Origin / 空 / 不匹配 → 204 无 CORS 头
        if !origin.is_empty() && origin_matches(origin, &config.allowed_origins) {
            let allow_origin = allow_origin_value(origin, &config.allowed_origins);
            let mut headers = axum::http::HeaderMap::new();
            // Vary: Origin —— 响应随 Origin 变化，缓存层必须按 Origin 区分（RFC 6454 §7.6）
            headers.insert(
                HeaderName::from_static("vary"),
                HeaderValue::from_static("Origin"),
            );
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
        return StatusCode::NO_CONTENT.into_response();
    }

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

    let mut resp = next.run(req).await;
    let headers = resp.headers_mut();
    // Vary: Origin —— 响应随 Origin 变化，缓存必须按 Origin 区分，否则 A 源缓存可能误发给 B 源（RFC 6454 §7.6）
    headers.insert(
        HeaderName::from_static("vary"),
        HeaderValue::from_static("Origin"),
    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use std::sync::Arc;
    use tower::ServiceExt;

    // 辅助函数

    fn make_app(config: CorsConfig) -> Router {
        Router::new()
            .route("/api/test", get(|| async { "ok" }))
            .layer(axum::middleware::from_fn_with_state(
                Arc::new(config),
                garrison_cors_middleware,
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

    // origin_matches 单元测试

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
        // 通配符下 origin_matches 仍返回 true；credentials 冲突由 validate() 单独处理
        let allowed = vec!["*".to_string()];
        assert!(origin_matches("https://example.com", &allowed));
    }

    #[test]
    fn origin_matches_mixed_exact_and_wildcard() {
        let allowed = vec!["https://example.com".to_string(), "*".to_string()];
        assert!(origin_matches("https://anything.com", &allowed));
        assert!(origin_matches("https://example.com", &allowed));
    }

    // OPTIONS 预检集成测试

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
    async fn preflight_non_matching_origin_returns_204_no_cors_headers() {
        let config = CorsConfig {
            allowed_origins: vec!["https://example.com".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        // 非匹配 origin → 204 无 CORS 头（短路，不透传到 handler）
        let resp = app
            .oneshot(make_request_with_origin(
                "OPTIONS",
                "/api/test",
                "https://evil.com",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
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
    async fn preflight_no_origin_header_returns_204() {
        let config = CorsConfig {
            allowed_origins: vec!["https://example.com".to_string()],
            ..Default::default()
        };
        let app = make_app(config);
        // 无 Origin header → 204 无 CORS 头（短路，不透传到 handler）
        let resp = app
            .oneshot(make_request("OPTIONS", "/api/test"))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
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

    // 实际请求（非 OPTIONS）集成测试

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

    // Vary: Origin

    /// 实际请求（注入 ACAO）必须带 Vary: Origin，防止缓存跨 Origin 串用。
    #[tokio::test]
    async fn actual_request_includes_vary_origin() {
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
        assert_eq!(resp.headers().get("vary").unwrap(), "Origin");
    }

    /// 预检请求（注入 CORS 头）必须带 Vary: Origin。
    #[tokio::test]
    async fn preflight_includes_vary_origin() {
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
        assert_eq!(resp.headers().get("vary").unwrap(), "Origin");
    }

    // CorsConfig::validate() 单元测试

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
