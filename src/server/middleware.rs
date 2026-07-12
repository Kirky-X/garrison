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
    let valid = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .map(|k| k == state.api_key)
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

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::routing::get;
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
}
