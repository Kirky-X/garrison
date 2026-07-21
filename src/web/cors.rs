//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! CORS 跨域资源共享中间件模块。
//!
//! 提供 [`CorsConfig`](crate::web::cors::CorsConfig) 配置与 [`garrison_cors_middleware`](crate::web::cors::garrison_cors_middleware) axum 中间件，
//! 支持 CORS 预检（OPTIONS）与实际请求的响应头注入。
//!
//! # 行为
//!
//! - **OPTIONS 预检请求**：无论 Origin 是否匹配均短路返回 204 No Content；
//!   Origin 匹配时注入 CORS 预检响应头，Origin 不匹配/缺失/空时返回 204 无 CORS 头。
//! - **实际请求**（非 OPTIONS）：Origin 匹配时注入 CORS 响应头后继续到下一 handler；
//!   Origin 不匹配时透传。
//! - **无 Origin header**：视为非 CORS 请求，直接透传。
//!
//! # 配置
//!
//! 通过 [`CorsConfig`](crate::web::cors::CorsConfig) 控制允许的源、方法、headers 等，集成到 [`crate::config::GarrisonConfig`]。

use crate::error::{GarrisonError, GarrisonResult};
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
    /// - `GarrisonError::Config`：credentials 与通配符 origin 冲突。
    pub fn validate(&self) -> GarrisonResult<()> {
        if self.allow_credentials && self.allowed_origins.iter().any(|o| o == "*") {
            return Err(GarrisonError::Config(
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
/// 1. 无论 Origin 是否匹配均短路返回 204 No Content。
/// 2. Origin 匹配时注入预检响应头：
///    - `Access-Control-Allow-Origin`
///    - `Access-Control-Allow-Methods`
///    - `Access-Control-Allow-Headers`
///    - `Access-Control-Allow-Credentials`（仅当 `allow_credentials == true`）
///    - `Access-Control-Max-Age`
/// 3. Origin 缺失/空/不匹配时返回 204 无 CORS 头。
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
/// use garrison::web::cors::{garrison_cors_middleware, CorsConfig};
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
///         garrison_cors_middleware,
///     ));
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

    // 非 OPTIONS 实际请求
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
// C4: compose_security_stack — 安全中间件组合函数
// ============================================================================

/// 组合安全中间件栈（C4 修复 CORS preflight 绕过问题）。
///
/// 按正确顺序叠加 WAF、CSRF、CORS 中间件到给定 Router，确保请求处理方向为：
///
/// ```text
/// 请求 → WAF → CSRF → CORS → handler
/// ```
///
/// # 为什么需要这个函数
///
/// **CORS preflight 绕过问题**：若 CORS 中间件在 WAF/CSRF 之前叠加，
/// OPTIONS 请求会被 CORS 中间件短路返回 204 No Content，**跳过 WAF/CSRF 校验**。
/// 攻击者可利用恶意 OPTIONS 请求（如 `/api/../etc/passwd`）绕过 WAF 目录遍历防护，
/// 或绕过 CSRF Origin 校验。
///
/// 本函数确保 CORS 在**最内层**（最后执行），preflight 短路时 WAF/CSRF 已执行完毕。
///
/// # axum layer 叠加语义
///
/// axum 中 `router.layer(L)` 将 `L` 添加为**最外层**（请求最先经过）。
/// 想要请求顺序 `WAF → CSRF → CORS → handler`，需按 `CORS → CSRF → WAF` 顺序叠加。
///
/// # 参数
///
/// - `router`: 已定义路由的 axum Router
/// - `waf_config`: WAF 配置（`Arc<WafConfig>`）
/// - `csrf_config`: CSRF 配置（`Arc<CsrfConfig>`）
/// - `cors_config`: CORS 配置（`Arc<CorsConfig>`）
///
/// # 返回
///
/// 叠加好三层安全中间件的 Router。
///
/// # 使用
///
/// ```ignore
/// use garrison::web::cors::compose_security_stack;
/// use garrison::web::waf::WafConfig;
/// use garrison::web::csrf::CsrfConfig;
/// use garrison::web::cors::CorsConfig;
/// use std::sync::Arc;
/// use axum::Router;
///
/// let router = Router::new()
///     .route("/api", axum::routing::get(|| async { "ok" }));
/// let app = compose_security_stack(
///     router,
///     Arc::new(WafConfig::default()),
///     Arc::new(CsrfConfig::default()),
///     Arc::new(CorsConfig::default()),
/// );
/// ```
#[cfg(all(feature = "web-waf", feature = "web-csrf", feature = "web-cors"))]
pub fn compose_security_stack(
    router: axum::Router,
    waf_config: std::sync::Arc<crate::web::waf::WafConfig>,
    csrf_config: std::sync::Arc<crate::web::csrf::CsrfConfig>,
    cors_config: std::sync::Arc<CorsConfig>,
) -> axum::Router {
    // axum layer 顺序：后添加的在外层（先执行）
    // 想要请求顺序 WAF → CSRF → CORS → handler
    // 叠加顺序：CORS（最内）→ CSRF（中间）→ WAF（最外）
    router
        .layer(axum::middleware::from_fn_with_state(
            cors_config,
            garrison_cors_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            csrf_config,
            crate::web::csrf::garrison_csrf_middleware,
        ))
        .layer(axum::middleware::from_fn_with_state(
            waf_config,
            crate::web::waf::garrison_waf_middleware,
        ))
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

    // ========================================================================
    // C4: compose_security_stack 测试（8 个）
    // 验证中间件顺序 WAF → CSRF → CORS，防止 CORS preflight 绕过
    // ========================================================================

    #[cfg(all(feature = "web-waf", feature = "web-csrf"))]
    mod c4_compose_stack {
        use super::*;
        use crate::web::csrf::CsrfConfig;
        use crate::web::waf::WafConfig;
        use axum::body::Body;
        use axum::http::{Request, StatusCode};
        use axum::routing::get;
        use axum::Router;
        use std::sync::Arc;
        use tower::ServiceExt;

        fn make_composed_app(waf: WafConfig, csrf: CsrfConfig, cors: CorsConfig) -> Router {
            let router =
                Router::new().route("/api/test", get(|| async { "ok" }).post(|| async { "ok" }));
            compose_security_stack(router, Arc::new(waf), Arc::new(csrf), Arc::new(cors))
        }

        fn make_request_with_origin(method: &str, path: &str, origin: &str) -> Request<Body> {
            Request::builder()
                .method(method)
                .uri(path)
                .header("origin", origin)
                .header("host", "example.com")
                .body(Body::empty())
                .unwrap()
        }

        /// C4: compose_security_stack 函数存在且可调用。
        #[tokio::test]
        async fn compose_stack_function_exists() {
            let app = make_composed_app(
                WafConfig::default(),
                CsrfConfig::default(),
                CorsConfig {
                    allowed_origins: vec!["https://example.com".to_string()],
                    ..Default::default()
                },
            );
            // 正常 GET 请求应通过所有三层中间件
            let resp = app
                .oneshot(make_request_with_origin(
                    "GET",
                    "/api/test",
                    "https://example.com",
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        /// C4 核心：OPTIONS 请求带恶意 path 应被 WAF 拦截（返回 400 而非 204）。
        /// 若 CORS 在 WAF 之前，OPTIONS 会被 CORS 短路返回 204，绕过 WAF。
        #[tokio::test]
        async fn options_with_malicious_path_blocked_by_waf() {
            let app = make_composed_app(
                WafConfig::default(),
                CsrfConfig::default(),
                CorsConfig {
                    allowed_origins: vec!["https://example.com".to_string()],
                    ..Default::default()
                },
            );
            // OPTIONS 请求带目录遍历 path
            let resp = app
                .oneshot(make_request_with_origin(
                    "OPTIONS",
                    "/api/../etc/passwd",
                    "https://example.com",
                ))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "C4: OPTIONS preflight 不应绕过 WAF，恶意 path 应返回 400"
            );
        }

        /// C4: OPTIONS 请求带危险字符应被 WAF 拦截。
        #[tokio::test]
        async fn options_with_dangerous_chars_blocked_by_waf() {
            let app = make_composed_app(
                WafConfig::default(),
                CsrfConfig::default(),
                CorsConfig {
                    allowed_origins: vec!["https://example.com".to_string()],
                    ..Default::default()
                },
            );
            // OPTIONS 请求带双斜杠
            let resp = app
                .oneshot(make_request_with_origin(
                    "OPTIONS",
                    "/api//test",
                    "https://example.com",
                ))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::BAD_REQUEST,
                "C4: OPTIONS preflight 不应绕过 WAF，危险字符应返回 400"
            );
        }

        /// C4: 正常 OPTIONS 请求（匹配 Origin + 干净 path）应返回 204。
        #[tokio::test]
        async fn normal_options_returns_204_with_cors_headers() {
            let app = make_composed_app(
                WafConfig::default(),
                CsrfConfig::default(),
                CorsConfig {
                    allowed_origins: vec!["https://example.com".to_string()],
                    ..Default::default()
                },
            );
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

        /// C4: OPTIONS 请求不匹配 Origin 应返回 204 无 CORS 头（WAF 已通过）。
        #[tokio::test]
        async fn options_non_matching_origin_returns_204_no_cors() {
            let app = make_composed_app(
                WafConfig::default(),
                CsrfConfig::default(),
                CorsConfig {
                    allowed_origins: vec!["https://example.com".to_string()],
                    ..Default::default()
                },
            );
            let resp = app
                .oneshot(make_request_with_origin(
                    "OPTIONS",
                    "/api/test",
                    "https://evil.com",
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::NO_CONTENT);
            // 不匹配 Origin → 无 CORS 头
            assert!(resp.headers().get("access-control-allow-origin").is_none());
        }

        /// C4: GET 请求带恶意 path 也应被 WAF 拦截（非 OPTIONS 场景）。
        #[tokio::test]
        async fn get_with_malicious_path_blocked_by_waf() {
            let app = make_composed_app(
                WafConfig::default(),
                CsrfConfig::default(),
                CorsConfig {
                    allowed_origins: vec!["https://example.com".to_string()],
                    ..Default::default()
                },
            );
            let resp = app
                .oneshot(make_request_with_origin(
                    "GET",
                    "/api/../etc/passwd",
                    "https://example.com",
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        }

        /// C4: POST 请求跨源应被 CSRF 拦截（403）。
        #[tokio::test]
        async fn post_cross_origin_blocked_by_csrf() {
            let app = make_composed_app(
                WafConfig::default(),
                CsrfConfig::default(),
                CorsConfig {
                    allowed_origins: vec!["https://example.com".to_string()],
                    ..Default::default()
                },
            );
            // POST 跨源（Origin=evil.com, Host=example.com）→ CSRF 拦截
            let resp = app
                .oneshot(make_request_with_origin(
                    "POST",
                    "/api/test",
                    "https://evil.com",
                ))
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::FORBIDDEN,
                "C4: POST 跨源应被 CSRF 拦截返回 403"
            );
        }

        /// C4: POST 同源 + 匹配 CSRF token 应通过所有中间件。
        #[tokio::test]
        async fn post_same_origin_with_token_passes_all() {
            use crate::web::csrf::generate_csrf_token;
            let app = make_composed_app(
                WafConfig::default(),
                CsrfConfig::default(),
                CorsConfig {
                    allowed_origins: vec!["https://example.com".to_string()],
                    ..Default::default()
                },
            );
            let token = generate_csrf_token().unwrap();
            let req = Request::builder()
                .method("POST")
                .uri("/api/test")
                .header("host", "example.com")
                .header("origin", "https://example.com")
                .header("cookie", format!("garrison_csrf_token={}", token))
                .header("X-CSRF-Token", &token)
                .body(Body::empty())
                .unwrap();
            let resp = app.oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }
}
