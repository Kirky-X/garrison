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

use axum::extract::ConnectInfo;
use axum::extract::Request;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use limiteron::limiters::{Limiter, TokenBucketLimiter};
use parking_lot::Mutex;
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use crate::backend::AuthBackend;
use crate::context::GarrisonPrincipal;

/// per-IP 限速桶条目 — 持有 limiteron 令牌桶 + 最后访问时间（用于 LRU 淘汰）。
///
/// `TokenBucketLimiter` 内部用 `AtomicU64` 管理令牌数与补充时间（线程安全），
/// 不暴露 `last_refill`，故在此额外追踪 `last_access` 实现 LRU 淘汰。
struct BucketEntry {
    limiter: Arc<TokenBucketLimiter>,
    last_access: Instant,
}

/// 限速中间件状态。
///
/// 持有 IP → BucketEntry 的映射和限速配置。
/// 通过 `Arc<RateLimitState>` 共享给 middleware。
///
/// # 安全性
///
/// - `max_entries` 上限防 DoS 内存耗尽，超限时 LRU 淘汰最久未访问的 bucket。
/// - `trusted_proxies` 限定 X-Forwarded-For 信任边界，非可信来源的 XFF 被忽略。
pub struct RateLimitState {
    buckets: Mutex<HashMap<String, BucketEntry>>,
    /// 每个 IP 的令牌桶容量（u64，匹配 limiteron TokenBucketLimiter）。
    capacity: u64,
    /// 每个 IP 的令牌补充速率（令牌/秒）。
    refill_rate: u64,
    /// HashMap 最大条目数（防 DoS 内存耗尽）。
    max_entries: usize,
    /// 可信代理 IP 列表（仅信任来自这些 IP 的 X-Forwarded-For）。
    trusted_proxies: Vec<IpAddr>,
}

/// 默认最大 bucket 数。
const DEFAULT_MAX_ENTRIES: usize = 100_000;

impl RateLimitState {
    /// 创建限速状态（向后兼容，默认 max_entries=100_000，无可信代理）。
    ///
    /// # 参数
    /// - `capacity`：每个 IP 每秒允许的请求数（既是桶容量也是补充速率）
    pub fn new(capacity: u32) -> Self {
        Self::with_options(capacity, DEFAULT_MAX_ENTRIES, Vec::new())
    }

    /// 创建限速状态（完整配置）。
    ///
    /// # 参数
    /// - `capacity`：每个 IP 每秒允许的请求数（既是桶容量也是补充速率）
    /// - `max_entries`：HashMap 最大条目数
    /// - `trusted_proxies`：可信代理 IP 列表
    pub fn with_options(capacity: u32, max_entries: usize, trusted_proxies: Vec<IpAddr>) -> Self {
        let capacity = capacity as u64;
        Self {
            buckets: Mutex::new(HashMap::new()),
            // 桶容量 = 补充速率 = capacity（与原手写实现一致）
            capacity,
            refill_rate: capacity,
            // 至少保留 1 个条目，避免 max_entries=0 导致所有请求被驱逐
            max_entries: max_entries.max(1),
            trusted_proxies,
        }
    }

    /// 当前 bucket 数量（测试/运维用）。
    pub fn bucket_count(&self) -> usize {
        self.buckets.lock().len()
    }
}

/// 从请求中提取客户端 IP。
///
/// # 信任模型
///
/// - 若连接 IP 在 `trusted_proxies` 中：采用 X-Forwarded-For 最左值（原始客户端）。
/// - 若连接 IP 不在 `trusted_proxies` 中：使用连接 IP 本身，忽略 XFF（防伪造）。
/// - 若无 `ConnectInfo`（如 oneshot 测试）：返回 "unknown"（fail-closed，不信任 XFF）。
fn extract_client_ip(req: &Request, trusted_proxies: &[IpAddr]) -> String {
    let connect_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    match connect_ip {
        Some(ip) if trusted_proxies.contains(&ip) => req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.split(',').next())
            .map(|s| s.trim().to_string())
            .unwrap_or_else(|| ip.to_string()),
        Some(ip) => ip.to_string(),
        None => "unknown".to_string(),
    }
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
    let ip = extract_client_ip(&req, &state.trusted_proxies);
    // 短暂持锁：取出 bucket Arc 并更新 last_access，然后在锁外调用 async allow
    // （limiteron allow 内部用原子 CAS，不阻塞，但避免跨 await 持有 parking_lot 锁）
    let bucket = {
        let mut buckets = state.buckets.lock();
        // 新 IP 插入前若已达 max_entries，淘汰最久未访问的 bucket（LRU）
        if !buckets.contains_key(&ip) && buckets.len() >= state.max_entries {
            if let Some(oldest_key) = buckets
                .iter()
                .min_by_key(|(_, e)| e.last_access)
                .map(|(k, _)| k.clone())
            {
                buckets.remove(&oldest_key);
            }
        }
        let entry = buckets.entry(ip.clone()).or_insert_with(|| BucketEntry {
            // 每秒补充 refill_rate 个令牌，桶容量为 capacity
            limiter: Arc::new(TokenBucketLimiter::new(state.capacity, state.refill_rate)),
            last_access: Instant::now(),
        });
        entry.last_access = Instant::now();
        entry.limiter.clone()
    };

    // 在锁外调用 allow(1)（limiteron 内部原子操作，无需持锁）
    let allowed = match bucket.allow(1).await {
        Ok(allowed) => allowed,
        Err(e) => {
            // LimiteronError 仅在 cost 非法时出现（cost=0 或超限），cost=1 不应触发，
            // 但仍按 fail-closed 处理为限速拒绝并记录日志（规则12：失败显性化）
            tracing::warn!(error = %e, "rate limiter error");
            false
        },
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

/// 常量时间字节比较，防止 timing attack。
///
/// 用 `subtle::ConstantTimeEq` 做常量时间比较，既不在第一个不匹配字节处短路返回，
/// 也不在长度不同时提前返回，避免攻击者通过测量响应时间逐字节推断 API Key 内容，
/// 或通过长度差异的时间差推断 API Key 长度。
///
/// # 安全性
///
/// - 长度比较用 `u64::ct_eq`（常量时间），不 early return
/// - 字节比较遍历到 `max(a.len, b.len)`，短的一方用 0 padding
/// - 无论长度是否相等，都做同样多的工作（max_len 次比较）
fn constant_time_eq(a: &str, b: &str) -> bool {
    use subtle::ConstantTimeEq;

    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    // 长度比较用常量时间，不 early return
    let len_eq = (a_bytes.len() as u64).ct_eq(&(b_bytes.len() as u64));

    // 字节比较：遍历到 max_len，短的一方用 0 padding
    let max_len = a_bytes.len().max(b_bytes.len());
    let mut byte_eq = subtle::Choice::from(1);
    for i in 0..max_len {
        let x = a_bytes.get(i).copied().unwrap_or(0);
        let y = b_bytes.get(i).copied().unwrap_or(0);
        byte_eq &= x.ct_eq(&y);
    }

    (len_eq & byte_eq).unwrap_u8() == 1
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
    // fail-closed —— 空 api_key 时拒绝所有请求（防御默认值泄露）
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

    // 常量时间比较，防止 timing attack 逐字节推断 API Key
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
/// 验证后注入 `GarrisonPrincipal` extension。
///
/// 用于 OAuth2 外网路由，使 `/oauth2/authorize` 能检测用户登录状态：
/// - 有效 token → 注入 `Extension(GarrisonPrincipal { login_id })`，authorize 走授权码签发路径
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
                req.extensions_mut().insert(GarrisonPrincipal {
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
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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

    // ========================================================================
    // Rate limiter 内存上限 + LRU 淘汰测试
    // ========================================================================

    /// 超过 max_entries 时淘汰旧 bucket，bucket 数量不超过上限。
    #[tokio::test]
    async fn rate_limit_bucket_cleanup_when_exceeds_max_entries() {
        // capacity=5 req/s，max_entries=2（仅保留 2 个 bucket）
        let state = Arc::new(RateLimitState::with_options(5, 2, Vec::new()));
        let app = ok_router().layer(axum::middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ));

        // 3 个不同 connecting IP，第 3 个会触发淘汰（max_entries=2）
        for addr in ["10.0.0.1:8080", "10.0.0.2:8080", "10.0.0.3:8080"] {
            let req = Request::builder()
                .uri("/ping")
                .extension(ConnectInfo::<SocketAddr>(addr.parse().unwrap()))
                .body(Body::empty())
                .unwrap();
            let _resp = app.clone().oneshot(req).await.unwrap();
        }

        assert!(
            state.bucket_count() <= 2,
            "bucket 数量 {} 超过 max_entries=2",
            state.bucket_count()
        );
    }

    // ========================================================================
    // 多 IP 限速隔离测试
    // ========================================================================

    /// 不同 IP 的限速桶相互隔离 — 一个 IP 耗尽配额不影响另一个 IP。
    #[tokio::test]
    async fn rate_limit_multi_ip_isolation() {
        // capacity=2 per IP
        let state = Arc::new(RateLimitState::new(2));
        let app = ok_router().layer(axum::middleware::from_fn_with_state(
            state,
            rate_limit_middleware,
        ));

        // IP 1: 2 requests OK, 3rd 429
        for _ in 0..2 {
            let req = Request::builder()
                .uri("/ping")
                .extension(ConnectInfo::<SocketAddr>("10.0.0.1:8080".parse().unwrap()))
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let req = Request::builder()
            .uri("/ping")
            .extension(ConnectInfo::<SocketAddr>("10.0.0.1:8080".parse().unwrap()))
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "IP 10.0.0.1 第 3 个请求应被限速"
        );

        // IP 2: 仍有完整配额（2 个请求都 OK）
        for _ in 0..2 {
            let req = Request::builder()
                .uri("/ping")
                .extension(ConnectInfo::<SocketAddr>("10.0.0.2:8080".parse().unwrap()))
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "IP 10.0.0.2 应有独立配额，不受 10.0.0.1 影响"
            );
        }
    }

    // ========================================================================
    // X-Forwarded-For 信任边界测试
    // ========================================================================

    /// 非可信代理 IP 的 XFF 被忽略，使用连接 IP。
    #[test]
    fn extract_client_ip_ignores_untrusted_proxy_xff() {
        let trusted = [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        // 连接来自 203.0.113.1（非可信代理）
        let req = Request::builder()
            .uri("/ping")
            .header("x-forwarded-for", "1.2.3.4")
            .extension(ConnectInfo::<SocketAddr>(
                "203.0.113.1:1234".parse().unwrap(),
            ))
            .body(Body::empty())
            .unwrap();
        // XFF 被忽略，使用连接 IP
        assert_eq!(extract_client_ip(&req, &trusted), "203.0.113.1");
    }

    /// 可信代理 IP 的 XFF 被采用。
    #[test]
    fn extract_client_ip_uses_xff_from_trusted_proxy() {
        let trusted = [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        // 连接来自 10.0.0.1（可信代理）
        let req = Request::builder()
            .uri("/ping")
            .header("x-forwarded-for", "1.2.3.4")
            .extension(ConnectInfo::<SocketAddr>("10.0.0.1:8080".parse().unwrap()))
            .body(Body::empty())
            .unwrap();
        // XFF 被信任，取最左值 = "1.2.3.4"
        assert_eq!(extract_client_ip(&req, &trusted), "1.2.3.4");
    }

    /// 无 ConnectInfo 时返回 "unknown"（fail-closed，不信任 XFF）。
    #[test]
    fn extract_client_ip_no_connect_info_returns_unknown() {
        let trusted = [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        let req = Request::builder()
            .uri("/ping")
            .header("x-forwarded-for", "1.2.3.4")
            .body(Body::empty())
            .unwrap();
        // 无 ConnectInfo → "unknown"（不信任 XFF）
        assert_eq!(extract_client_ip(&req, &trusted), "unknown");
    }

    /// 可信代理但无 XFF 头时使用连接 IP。
    #[test]
    fn extract_client_ip_trusted_proxy_no_xff_uses_connect_ip() {
        let trusted = [IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        let req = Request::builder()
            .uri("/ping")
            .extension(ConnectInfo::<SocketAddr>("10.0.0.1:8080".parse().unwrap()))
            .body(Body::empty())
            .unwrap();
        // 可信代理但无 XFF → 使用连接 IP
        assert_eq!(extract_client_ip(&req, &trusted), "10.0.0.1");
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

    /// 空 API Key 时所有请求被拒绝（fail-closed）。
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

    /// 常量时间比较函数正确性验证。
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
    // constant_time_eq 长度泄露修复测试
    // ========================================================================

    /// 不同长度返回 false（多种长度组合）。
    #[test]
    fn constant_time_eq_different_lengths_returns_false() {
        // 短 vs 长
        assert!(!constant_time_eq("a", "ab"));
        assert!(!constant_time_eq("ab", "a"));
        // 空 vs 非空
        assert!(!constant_time_eq("", "x"));
        assert!(!constant_time_eq("x", ""));
        // 长度差 1 / 多
        assert!(!constant_time_eq("abc", "abcd"));
        assert!(!constant_time_eq("abcd", "abc"));
        assert!(!constant_time_eq("hello", "hello world"));
        // 长输入
        assert!(!constant_time_eq("0123456789abcdef", "0123456789abcdef0"));
    }

    /// 相同值返回 true（多种内容）。
    #[test]
    fn constant_time_eq_same_value_returns_true() {
        assert!(constant_time_eq("", ""));
        assert!(constant_time_eq("a", "a"));
        assert!(constant_time_eq("abc", "abc"));
        assert!(constant_time_eq("hello", "hello"));
        // 长 key（模拟真实 API key 长度）
        assert!(constant_time_eq(
            "sk-garrison-0123456789abcdef0123456789abcdef",
            "sk-garrison-0123456789abcdef0123456789abcdef"
        ));
        // 含特殊字符
        assert!(constant_time_eq("p@ssw0rd!#$%", "p@ssw0rd!#$%"));
    }

    /// 相同长度不同值返回 false（确保不短路）。
    #[test]
    fn constant_time_eq_different_value_returns_false() {
        // 首字节不同
        assert!(!constant_time_eq("abc", "xbc"));
        // 末字节不同
        assert!(!constant_time_eq("abc", "abx"));
        // 中间字节不同
        assert!(!constant_time_eq("abc", "axc"));
        // 单字节
        assert!(!constant_time_eq("a", "b"));
        // 长 key 全部不同
        assert!(!constant_time_eq(
            "sk-garrison-aaaaaaaaaaaaaaaaaaaaaaaa",
            "sk-garrison-bbbbbbbbbbbbbbbbbbbbbbbb"
        ));
        // 长 key 仅末字节不同（验证非常量时间提前返回）
        assert!(!constant_time_eq(
            "sk-garrison-0123456789abcdef0123456789abcdef",
            "sk-garrison-0123456789abcdef0123456789abcdeg"
        ));
    }

    /// 空字符串返回 true。
    #[test]
    fn constant_time_eq_empty_strings_returns_true() {
        assert!(constant_time_eq("", ""));
        // 双重确认：空 vs 非空仍为 false
        assert!(!constant_time_eq("", " "));
        assert!(!constant_time_eq(" ", ""));
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
        ) -> crate::error::GarrisonResult<String> {
            Ok("valid-token".to_string())
        }
        async fn logout(&self, _token: &str) -> crate::error::GarrisonResult<()> {
            Ok(())
        }
        async fn check_login(&self, token: &str) -> crate::error::GarrisonResult<bool> {
            Ok(token == "valid-token")
        }
        async fn check_permission(
            &self,
            _token: &str,
            _permission: &str,
        ) -> crate::error::GarrisonResult<()> {
            Ok(())
        }
        async fn check_role(&self, _token: &str, _role: &str) -> crate::error::GarrisonResult<()> {
            Ok(())
        }
        async fn check_safe(&self, _token: &str) -> crate::error::GarrisonResult<bool> {
            Ok(false)
        }
        async fn check_disable(&self, _token: &str) -> crate::error::GarrisonResult<bool> {
            Ok(false)
        }
        async fn check_api_key(
            &self,
            _api_key: &str,
            _namespace: &str,
        ) -> crate::error::GarrisonResult<()> {
            Ok(())
        }
        async fn get_token_info(
            &self,
            token: &str,
        ) -> crate::error::GarrisonResult<crate::backend::types::TokenInfo> {
            Ok(crate::backend::types::TokenInfo {
                token: token.to_string(),
                created_at: 1000,
                last_active_at: 2000,
            })
        }
        async fn get_session(
            &self,
            token: &str,
        ) -> crate::error::GarrisonResult<crate::backend::types::SessionData> {
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
                Err(crate::error::GarrisonError::InvalidToken(
                    "token 无效".to_string(),
                ))
            }
        }
        async fn kickout(&self, _login_id: &str) -> crate::error::GarrisonResult<()> {
            Ok(())
        }
        async fn switch_to(
            &self,
            _token: &str,
            _target_login_id: &str,
        ) -> crate::error::GarrisonResult<()> {
            Ok(())
        }
        async fn renew_to_equivalent(&self, _token: &str) -> crate::error::GarrisonResult<String> {
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
                    |principal: axum::extract::Extension<GarrisonPrincipal>| async move {
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
