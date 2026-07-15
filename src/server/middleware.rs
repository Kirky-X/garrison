//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Auth Server 中间件栈。
//!
//! 提供三个中间件：
//! - `rate_limit_middleware`：基于 IP 的令牌桶限速，超限返回 429
//! - `api_key_auth_middleware`：验证 X-API-Key 头，不匹配返回 401
//! - `audit_log_middleware`：tracing::info! 记录请求方法+路径+状态码
//!
//! # 设计
//!
//! - **简化原则**（Rule 2）：限速用 in-memory HashMap，不依赖 Redis
//! - **parking_lot::Mutex**：比 std::sync::Mutex 更高效，无需 await 持锁
//! - **from_fn_with_state**：通过 axum middleware state 共享配置

use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use parking_lot::Mutex;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::backend::AuthBackend;
use crate::context::BulwarkPrincipal;

/// 令牌桶 — 简化限速算法。
///
/// 每次请求前 refill（按时间比例补充令牌），再尝试消耗 1 个令牌。
/// 令牌不足时拒绝请求。
#[derive(Debug, Clone)]
struct TokenBucket {
    /// 当前令牌数。
    tokens: f64,
    /// 上次 refill 时间。
    last_refill: Instant,
}

impl TokenBucket {
    /// 创建满桶。
    fn new(capacity: f64) -> Self {
        Self {
            tokens: capacity,
            last_refill: Instant::now(),
        }
    }

    /// 按时间比例补充令牌，上限为 capacity。
    fn refill(&mut self, capacity: f64, refill_per_sec: f64) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * refill_per_sec).min(capacity);
        self.last_refill = now;
    }

    /// 尝试消耗 1 个令牌，返回是否成功。
    fn try_consume(&mut self) -> bool {
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// 限速中间件状态。
///
/// 持有 IP → TokenBucket 的映射和限速配置。
/// 通过 `Arc<RateLimitState>` 共享给 middleware。
#[derive(Debug)]
pub struct RateLimitState {
    buckets: Mutex<HashMap<String, TokenBucket>>,
    /// 每个 IP 的令牌桶容量（也是每秒补充速率）。
    capacity: f64,
}

impl RateLimitState {
    /// 创建限速状态。
    ///
    /// # 参数
    /// - `capacity`：每个 IP 每秒允许的请求数
    pub fn new(capacity: u32) -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
            capacity: capacity as f64,
        }
    }
}

/// 从请求中提取客户端 IP。
///
/// 优先使用 X-Forwarded-For 头（代理场景），
/// 无则使用 "unknown"（兼容 oneshot 测试，无法获取真实连接 IP）。
fn extract_client_ip(req: &Request) -> String {
    req.headers()
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(',').next())
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// 限速中间件 — 基于 IP 的令牌桶。
///
/// 超限返回 429 Too Many Requests，响应体为 JSON：
/// ```json
/// { "error": "rate_limited", "message": "请求过于频繁" }
/// ```
pub async fn rate_limit_middleware(
    axum::extract::State(state): axum::extract::State<Arc<RateLimitState>>,
    req: Request,
    next: Next,
) -> Response {
    let ip = extract_client_ip(&req);
    let allowed = {
        let mut buckets = state.buckets.lock();
        let bucket = buckets.entry(ip.clone()).or_insert_with(|| {
            // 每秒补充 capacity 个令牌，桶容量为 capacity
            TokenBucket::new(state.capacity)
        });
        bucket.refill(state.capacity, state.capacity);
        bucket.try_consume()
    };

    if !allowed {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "error": "rate_limited",
                "message": "请求过于频繁"
            })),
        )
            .into_response();
    }

    next.run(req).await
}

/// API Key 认证中间件状态。
///
/// 持有预期的 API Key 值，与请求 X-API-Key 头比对。
#[derive(Debug, Clone)]
pub struct ApiKeyState {
    /// 预期的 API Key。
    pub api_key: String,
}

/// 常量时间字节比较，防止 timing attack（H-1）。
///
/// 用 XOR 累积比较所有字节，不在第一个不匹配字节处短路返回，
/// 避免攻击者通过测量响应时间逐字节推断 API Key 内容。
///
/// 长度不同时直接返回 false（长度不是秘密，API Key 长度由配置决定）。
fn constant_time_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.as_bytes().iter().zip(b.as_bytes().iter()) {
        result |= x ^ y;
    }
    result == 0
}

/// API Key 认证中间件 — 验证 X-API-Key 头。
///
/// 不匹配或缺失返回 401 Unauthorized，响应体为 JSON：
/// ```json
/// { "error": "unauthorized", "message": "无效的 API Key" }
/// ```
pub async fn api_key_auth_middleware(
    axum::extract::State(state): axum::extract::State<Arc<ApiKeyState>>,
    req: Request,
    next: Next,
) -> Response {
    // M-SAST-1/M-5: fail-closed —— 空 api_key 时拒绝所有请求（防御默认值泄露）
    if state.api_key.is_empty() {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "unauthorized",
                "message": "无效的 API Key"
            })),
        )
            .into_response();
    }

    // H-1: 常量时间比较，防止 timing attack 逐字节推断 API Key
    let valid = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|k| constant_time_eq(k, &state.api_key))
        .unwrap_or(false);

    if !valid {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({
                "error": "unauthorized",
                "message": "无效的 API Key"
            })),
        )
            .into_response();
    }

    next.run(req).await
}

/// 审计日志中间件 — tracing::info! 记录请求方法+路径+状态码。
///
/// 在请求处理后记录响应状态码，便于审计追踪。
pub async fn audit_log_middleware(req: Request, next: Next) -> Response {
    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let response = next.run(req).await;
    let status = response.status();

    tracing::info!(
        method = %method,
        path = %path,
        status = status.as_u16(),
        "auth_server_request"
    );

    response
}

// ============================================================================
// path-filter 中间件（C-1：双端口架构路由分离）
// ============================================================================
//
// sdforge::http::build() 收集所有 15 个 #[forge] 路由到单一 Router，
// 不支持按 name/path/group/tag 过滤。为在双端口架构中分离外网/内网路由，
// 用 path-filter 中间件在请求入口处按路径过滤：
//
// - 外网端口：仅允许 /api/v1/auth/{login,logout,refresh}，其余 404
// - 内网端口：拒绝上述 3 个外网路径，其余放行（由 api_key_auth 保护）

/// 外网路径白名单（仅允许 3 个外网端点）。
const EXTERNAL_ALLOWED_PATHS: &[&str] = &[
    "/api/v1/auth/login",
    "/api/v1/auth/logout",
    "/api/v1/auth/refresh",
];

/// 判断路径是否为外网允许路径。
///
/// 基础 3 路径始终检查；`oauth2-server` feature 启用时额外放行 3 个 OAuth2 外网端点。
pub fn is_external_allowed(path: &str) -> bool {
    if EXTERNAL_ALLOWED_PATHS.contains(&path) {
        return true;
    }
    if cfg!(feature = "oauth2-server") {
        return matches!(
            path,
            "/oauth2/authorize" | "/oauth2/token" | "/oauth2/revoke"
        );
    }
    false
}

/// 外网 path-filter 中间件：仅允许外网路径，其余返回 404。
///
/// 用于外网端口，防止外部用户访问内网端点（check-*/get-*/kickout 等）。
pub async fn external_path_filter(req: Request, next: Next) -> Response {
    if is_external_allowed(req.uri().path()) {
        next.run(req).await
    } else {
        StatusCode::NOT_FOUND.into_response()
    }
}

/// 内网 path-filter 中间件：拒绝外网路径，其余放行。
///
/// 用于内网端口，防止内网调用方访问用户端端点（login/logout/refresh）。
pub async fn internal_path_filter(req: Request, next: Next) -> Response {
    if is_external_allowed(req.uri().path()) {
        StatusCode::NOT_FOUND.into_response()
    } else {
        next.run(req).await
    }
}

/// Principal 注入中间件 — 从 Authorization header 提取 Bearer token，
/// 验证后注入 `BulwarkPrincipal` extension。
///
/// 用于 OAuth2 外网路由，使 `/oauth2/authorize` 能检测用户登录状态：
/// - 有效 token → 注入 `Extension(BulwarkPrincipal { login_id })`，authorize 走授权码签发路径
/// - 无 token / token 无效 → 不注入（principal 为 None），authorize 重定向到登录页
///
/// 本中间件**不阻断请求**，仅做 best-effort 注入。
pub async fn principal_inject_middleware(mut req: Request, next: Next) -> Response {
    if let Some(backend) = req.extensions().get::<Arc<dyn AuthBackend>>().cloned() {
        if let Some(token) = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
        {
            if let Ok(session) = backend.get_session(token).await {
                req.extensions_mut().insert(BulwarkPrincipal {
                    login_id: session.login_id,
                });
            }
        }
    }
    next.run(req).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::{get, post};
    use axum::Extension;
    use axum::Router;
    use tower::ServiceExt;

    /// 创建一个简单的 ok 路由用于测试 middleware。
    fn ok_router() -> Router {
        Router::new().route("/ping", get(|| async { "ok" }))
    }

    #[tokio::test]
    async fn test_rate_limit_allows_under_limit() {
        let state = Arc::new(RateLimitState::new(5));
        let app = ok_router().layer(axum::middleware::from_fn_with_state(
            state,
            rate_limit_middleware,
        ));

        // 发送 5 个请求，都应成功
        for _ in 0..5 {
            let resp = app
                .clone()
                .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
    }

    #[tokio::test]
    async fn test_rate_limit_blocks_over_limit() {
        let state = Arc::new(RateLimitState::new(2));
        let app = ok_router().layer(axum::middleware::from_fn_with_state(
            state,
            rate_limit_middleware,
        ));

        // 前 2 个请求成功
        for _ in 0..2 {
            let resp = app
                .clone()
                .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        // 第 3 个请求被限速
        let resp = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_api_key_auth_missing_header() {
        let state = Arc::new(ApiKeyState {
            api_key: "secret-key".to_string(),
        });
        let app = ok_router().layer(axum::middleware::from_fn_with_state(
            state,
            api_key_auth_middleware,
        ));

        let resp = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_api_key_auth_wrong_key() {
        let state = Arc::new(ApiKeyState {
            api_key: "secret-key".to_string(),
        });
        let app = ok_router().layer(axum::middleware::from_fn_with_state(
            state,
            api_key_auth_middleware,
        ));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ping")
                    .header("x-api-key", "wrong-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_api_key_auth_correct_key() {
        let state = Arc::new(ApiKeyState {
            api_key: "secret-key".to_string(),
        });
        let app = ok_router().layer(axum::middleware::from_fn_with_state(
            state,
            api_key_auth_middleware,
        ));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ping")
                    .header("x-api-key", "secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_audit_log_middleware_passes_through() {
        let app = ok_router().layer(axum::middleware::from_fn(audit_log_middleware));

        let resp = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// M-SAST-1/M-5: 空 API Key 时所有请求被拒绝（fail-closed）。
    #[tokio::test]
    async fn test_api_key_auth_empty_key_rejects_all() {
        let state = Arc::new(ApiKeyState {
            api_key: String::new(), // 空字符串
        });
        let app = ok_router().layer(axum::middleware::from_fn_with_state(
            state,
            api_key_auth_middleware,
        ));
        // 即使带 X-API-Key 头也应被拒绝
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ping")
                    .header("x-api-key", "any-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// H-1: 常量时间比较函数正确性验证。
    #[test]
    fn test_constant_time_eq() {
        assert!(constant_time_eq("abc", "abc"));
        assert!(!constant_time_eq("abc", "abd"));
        assert!(!constant_time_eq("abc", "ab"));
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(constant_time_eq("", ""));
        assert!(!constant_time_eq("", "a"));
        // 确保所有字节都被比较（非短路）
        assert!(!constant_time_eq("abcdefgh", "abcdefgx"));
    }

    // ========================================================================
    // C-1: path-filter 中间件测试
    // ========================================================================

    /// 内网路径列表（12 个）。
    const INTERNAL_PATHS: &[&str] = &[
        "/api/v1/auth/check-login",
        "/api/v1/auth/check-permission",
        "/api/v1/auth/check-role",
        "/api/v1/auth/check-safe",
        "/api/v1/auth/check-disable",
        "/api/v1/auth/check-api-key",
        "/api/v1/auth/get-token-info",
        "/api/v1/auth/get-session",
        "/api/v1/auth/kickout",
        "/api/v1/auth/switch-to",
        "/api/v1/auth/renew-to-equivalent",
        "/api/v1/auth/health",
    ];

    /// 构建包含所有 15 个 auth 路由的测试 Router（用于 path-filter 测试）。
    fn make_all_routes_router() -> Router {
        Router::new()
            .route("/api/v1/auth/login", post(|| async { "ok" }))
            .route("/api/v1/auth/logout", post(|| async { "ok" }))
            .route("/api/v1/auth/refresh", post(|| async { "ok" }))
            .route("/api/v1/auth/check-login", post(|| async { "ok" }))
            .route("/api/v1/auth/check-permission", post(|| async { "ok" }))
            .route("/api/v1/auth/check-role", post(|| async { "ok" }))
            .route("/api/v1/auth/check-safe", post(|| async { "ok" }))
            .route("/api/v1/auth/check-disable", post(|| async { "ok" }))
            .route("/api/v1/auth/check-api-key", post(|| async { "ok" }))
            .route("/api/v1/auth/get-token-info", post(|| async { "ok" }))
            .route("/api/v1/auth/get-session", post(|| async { "ok" }))
            .route("/api/v1/auth/kickout", post(|| async { "ok" }))
            .route("/api/v1/auth/switch-to", post(|| async { "ok" }))
            .route("/api/v1/auth/renew-to-equivalent", post(|| async { "ok" }))
            .route("/api/v1/auth/health", get(|| async { "ok" }))
    }

    /// C-1: 外网 path-filter 放行所有外网路径。
    #[tokio::test]
    async fn test_external_path_filter_allows_external_paths() {
        for &path in EXTERNAL_ALLOWED_PATHS {
            let app =
                make_all_routes_router().layer(axum::middleware::from_fn(external_path_filter));
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "外网 path-filter 应放行 {}",
                path
            );
        }
    }

    /// C-1: 外网 path-filter 拒绝所有内网路径（返回 404）。
    #[tokio::test]
    async fn test_external_path_filter_blocks_internal_paths() {
        for &path in INTERNAL_PATHS {
            let method = if path == "/api/v1/auth/health" {
                "GET"
            } else {
                "POST"
            };
            let app =
                make_all_routes_router().layer(axum::middleware::from_fn(external_path_filter));
            let resp = app
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "外网 path-filter 应拒绝 {}",
                path
            );
        }
    }

    /// C-1: 内网 path-filter 拒绝所有外网路径（返回 404）。
    #[tokio::test]
    async fn test_internal_path_filter_blocks_external_paths() {
        for &path in EXTERNAL_ALLOWED_PATHS {
            let app =
                make_all_routes_router().layer(axum::middleware::from_fn(internal_path_filter));
            let resp = app
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::NOT_FOUND,
                "内网 path-filter 应拒绝 {}",
                path
            );
        }
    }

    /// C-1: 内网 path-filter 放行所有内网路径。
    #[tokio::test]
    async fn test_internal_path_filter_allows_internal_paths() {
        for &path in INTERNAL_PATHS {
            let method = if path == "/api/v1/auth/health" {
                "GET"
            } else {
                "POST"
            };
            let app =
                make_all_routes_router().layer(axum::middleware::from_fn(internal_path_filter));
            let resp = app
                .oneshot(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "内网 path-filter 应放行 {}",
                path
            );
        }
    }

    // ========================================================================
    // principal_inject_middleware 测试
    // ========================================================================

    /// 测试用 Mock AuthBackend —— `get_session` 对 "valid-token" 返回 login_id="1001"。
    struct MockAuthBackend;

    #[async_trait::async_trait]
    impl AuthBackend for MockAuthBackend {
        async fn login(
            &self,
            _login_id: &str,
            _params: &crate::backend::types::LoginParams,
        ) -> crate::error::BulwarkResult<String> {
            Ok("valid-token".to_string())
        }
        async fn logout(&self, _token: &str) -> crate::error::BulwarkResult<()> {
            Ok(())
        }
        async fn check_login(&self, token: &str) -> crate::error::BulwarkResult<bool> {
            Ok(token == "valid-token")
        }
        async fn check_permission(
            &self,
            _token: &str,
            _permission: &str,
        ) -> crate::error::BulwarkResult<()> {
            Ok(())
        }
        async fn check_role(&self, _token: &str, _role: &str) -> crate::error::BulwarkResult<()> {
            Ok(())
        }
        async fn check_safe(&self, _token: &str) -> crate::error::BulwarkResult<bool> {
            Ok(false)
        }
        async fn check_disable(&self, _token: &str) -> crate::error::BulwarkResult<bool> {
            Ok(false)
        }
        async fn check_api_key(
            &self,
            _api_key: &str,
            _namespace: &str,
        ) -> crate::error::BulwarkResult<()> {
            Ok(())
        }
        async fn get_token_info(
            &self,
            token: &str,
        ) -> crate::error::BulwarkResult<crate::backend::types::TokenInfo> {
            Ok(crate::backend::types::TokenInfo {
                token: token.to_string(),
                created_at: 1000,
                last_active_at: 2000,
            })
        }
        async fn get_session(
            &self,
            token: &str,
        ) -> crate::error::BulwarkResult<crate::backend::types::SessionData> {
            if token == "valid-token" {
                Ok(crate::backend::types::SessionData {
                    token: token.to_string(),
                    login_id: "1001".to_string(),
                    created_at: 1000,
                    last_active_at: 2000,
                    attrs: std::collections::HashMap::new(),
                    device: None,
                    ip: None,
                    user_agent: None,
                    safe_services: std::collections::HashMap::new(),
                    #[cfg(feature = "dynamic-active-timeout")]
                    dynamic_active_timeout: None,
                    #[cfg(feature = "anonymous-session")]
                    is_anon: false,
                })
            } else {
                Err(crate::error::BulwarkError::InvalidToken(
                    "token 无效".to_string(),
                ))
            }
        }
        async fn kickout(&self, _login_id: &str) -> crate::error::BulwarkResult<()> {
            Ok(())
        }
        async fn switch_to(
            &self,
            _token: &str,
            _target_login_id: &str,
        ) -> crate::error::BulwarkResult<()> {
            Ok(())
        }
        async fn renew_to_equivalent(&self, _token: &str) -> crate::error::BulwarkResult<String> {
            Ok("new-token".to_string())
        }
    }

    /// 无 Authorization header 时请求正常通过（不注入 principal）。
    #[tokio::test]
    async fn test_principal_inject_no_auth_header_passes_through() {
        let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
        let app = ok_router()
            .layer(axum::middleware::from_fn(principal_inject_middleware))
            .layer(Extension(backend));

        let resp = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// 无效 token 时请求正常通过（不注入 principal，不阻断）。
    #[tokio::test]
    async fn test_principal_inject_invalid_token_passes_through() {
        let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
        let app = ok_router()
            .layer(axum::middleware::from_fn(principal_inject_middleware))
            .layer(Extension(backend));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ping")
                    .header("authorization", "Bearer invalid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// 有效 token 时 principal 被正确注入到 request extensions。
    #[tokio::test]
    async fn test_principal_inject_valid_token_injects_principal() {
        let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
        let app = Router::new()
            .route(
                "/principal",
                get(
                    |principal: axum::extract::Extension<BulwarkPrincipal>| async move {
                        principal.0.login_id
                    },
                ),
            )
            .layer(axum::middleware::from_fn(principal_inject_middleware))
            .layer(Extension(backend));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/principal")
                    .header("authorization", "Bearer valid-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "1001",
            "有效 token 应注入 login_id=1001"
        );
    }

    /// 无 backend extension 时请求正常通过（不注入 principal，不 panic）。
    #[tokio::test]
    async fn test_principal_inject_no_backend_passes_through() {
        let app = ok_router().layer(axum::middleware::from_fn(principal_inject_middleware));

        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ping")
                    .header("authorization", "Bearer some-token")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
