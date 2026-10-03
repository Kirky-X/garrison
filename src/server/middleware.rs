// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Auth Server 中间件栈。
//!
//! 提供：
//! - `rate_limit_middleware`：基于 IP 的令牌桶限速，超限返回 429
//! - `inject_client_ip`：从请求提取真实客户端 IP，存入 `Extension<ClientIp>`
//! - `inject_login_client_ip`：login 端点自动填充 `params.ip`；读体超限/失败返回 413
//! - `sanitize_json_rejection_middleware`：统一改写 axum Json rejection
//!   （400/415/422/413）为统一 JSON 错误体，不回显内部类型名/字段名/字节偏移
//! - `api_key_auth_middleware`：验证 X-API-Key 头，不匹配返回 401；
//!   重复多值头 fail-closed 拒绝；按源 IP 失败锁定（GAR-25/28）
//! - `audit_log_middleware`：tracing::info! 记录请求方法+路径+状态码
//!
//! # 设计
//!
//! - **简化原则**：限速用 in-memory HashMap，不依赖 Redis
//! - **parking_lot::Mutex**：比 std::sync::Mutex 更高效，无需 await 持锁
//! - **from_fn_with_state**：通过 axum middleware state 共享配置

use crate::i18n::translate_detail;
use axum::extract::ConnectInfo;
use axum::extract::Request;
use axum::http::header::CONTENT_TYPE;
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::Json;
use dashmap::DashMap;
use limiteron::limiters::{Limiter, TokenBucketLimiter};
use serde_json::json;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use crate::backend::AuthBackend;
use crate::context::GarrisonPrincipal;
use crate::error::GarrisonError;
use crate::server::api_key_lockout::ApiKeyLockout;

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
    buckets: DashMap<String, BucketEntry>,
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
    /// 创建限速状态（默认配置：max_entries=100_000，无可信代理）。
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
            // 初始容量取 max_entries 的 1/64 与 64 的较大值，避免冷启动时频繁 rehash
            buckets: DashMap::with_capacity((max_entries / 64).max(64)),
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
        self.buckets.len()
    }
}

/// 从 `X-Forwarded-For` 解析真实客户端 IP（rightmost-untrusted 策略）。
///
/// 从右向左跳过 `trusted_proxies` 中的代理，返回第一个不可信跳。
/// 客户端可预伪造 XFF 最左值（代理以追加模式写入时），仅最右侧
/// 不可信跳由可信代理写入、不可伪造；全部跳均可信（纯内网互调）
/// 时回退最左值。存在不可解析跳时返回 `None`（调用方回退连接 IP），
/// 防止常量键（如 "unknown"）聚合全部异常客户端。
pub fn parse_forwarded_for_rightmost(xff: &str, trusted_proxies: &[IpAddr]) -> Option<String> {
    let hops: Vec<&str> = xff
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if hops.is_empty() {
        return None;
    }
    for hop in hops.iter().rev() {
        match hop.parse::<IpAddr>() {
            Ok(ip) if trusted_proxies.contains(&ip) => continue,
            // 非 IP 字面量跳（如异常代理写入的 "unknown"）不可采纳：采纳会使
            // 所有此类客户端聚成同一限流键（可被利用做集体限流/封禁）——返回
            // None 由调用方回退连接 IP（fail-closed 到 socket 地址）
            Ok(_) => return Some((*hop).to_string()),
            Err(_) => return None,
        }
    }
    Some(hops[0].to_string())
}

/// 从请求中提取客户端 IP。
///
/// # 信任模型
///
/// - 若连接 IP 在 `trusted_proxies` 中：采用 XFF rightmost-untrusted
///   （从右向左第一个非可信代理跳，防客户端预伪造最左值）。
/// - 若连接 IP 不在 `trusted_proxies` 中：使用连接 IP 本身，忽略 XFF（防伪造）。
/// - 若无 `ConnectInfo`（如 oneshot 测试）：返回 "unknown"（fail-closed，不信任 XFF）。
pub fn extract_client_ip(req: &Request, trusted_proxies: &[IpAddr]) -> String {
    let connect_ip = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip());

    match connect_ip {
        Some(ip) if trusted_proxies.contains(&ip) => req
            .headers()
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| parse_forwarded_for_rightmost(s, trusted_proxies))
            .unwrap_or_else(|| ip.to_string()),
        Some(ip) => ip.to_string(),
        None => "unknown".to_string(),
    }
}

/// 限速中间件 — 基于 IP 的令牌桶。
///
/// 超限返回 429 Too Many Requests，响应体为统一错误体：
/// ```json
/// { "error_code": "RATE_LIMITED", "error_id": "ratelimit.rate_limited", "message": "..." }
/// ```
/// 并携带 `Retry-After`（delta-seconds 整数秒，下限 1）与 `X-Request-ID` 头
/// （后者需 request id 中间件在外层挂载）。
pub async fn rate_limit_middleware(
    axum::extract::State(state): axum::extract::State<Arc<RateLimitState>>,
    req: Request,
    next: Next,
) -> Response {
    let ip = extract_client_ip(&req, &state.trusted_proxies);
    // 短暂持锁：取出 bucket Arc 并更新 last_access，然后在锁外调用 async allow
    // （limiteron allow 内部用原子 CAS，不阻塞，但避免跨 await 持有 parking_lot 锁）
    // DashMap 分片锁：不同 IP 的读写操作可并行，避免全局 Mutex 瓶颈
    //
    // TOCTOU 修复：先原子 insert（entry() 持分片写锁），再在锁外做
    // 超限检查与 LRU 淘汰。并发插入不同新 IP 时可能短暂超过 max_entries，
    // 但每个新插入都会触发一次淘汰检查，保证最终收敛到 max_entries 以内；
    // 淘汰扫描仅在真正超限时发生（低于上限的新 IP 插入不再全表扫描）。
    let is_new_ip = !state.buckets.contains_key(&ip);
    let bucket = {
        let mut entry = state
            .buckets
            .entry(ip.clone())
            .or_insert_with(|| BucketEntry {
                limiter: Arc::new(TokenBucketLimiter::new(state.capacity, state.refill_rate)),
                last_access: Instant::now(),
            });
        entry.last_access = Instant::now();
        entry.limiter.clone()
    };

    // 新插入后超限：淘汰最久未访问的 bucket（LRU）。
    // 在 entry 写锁释放后执行（DashMap iter 会锁各分片，跨 await/持锁迭代会死锁）。
    if is_new_ip && state.buckets.len() > state.max_entries {
        if let Some(oldest_key) = state
            .buckets
            .iter()
            .min_by_key(|e| e.value().last_access)
            .map(|e| e.key().clone())
        {
            // 防御：不淘汰刚插入的 bucket（其 last_access 刚更新，理论上不会被选中）
            if oldest_key != ip {
                state.buckets.remove(&oldest_key);
            }
        }
    }

    // 在锁外调用 allow(1)（limiteron 内部原子操作，无需持锁）
    let allowed = match bucket.allow(1).await {
        Ok(allowed) => allowed,
        Err(e) => {
            // LimiteronError 仅在 cost 非法时出现（cost=0 或超限），cost=1 不应触发，
            // 但仍按 fail-closed 处理为限速拒绝并记录日志（失败显性化）
            tracing::warn!(error = %e, "rate limiter error");
            false
        },
    };

    if !allowed {
        // 统一错误模型（R04）：429 走 GarrisonError::RateLimited，
        // Retry-After 取 limiteron 快照的 reset_secs（delta-seconds 整数秒，
        // 下限 1 由 retry_after_secs() 强制）；响应体为统一错误体
        // （error_code=RATE_LIMITED / error_id / request_id）。
        // Retry-After 为 advisory 头：allow 判定与本次二次快照之间存在
        // refill 窗口，头值允许陈旧（提示性质，非精确承诺）。
        let reset_secs = bucket
            .remaining()
            .await
            .map(|snapshot| snapshot.reset_secs)
            .unwrap_or(0);
        return GarrisonError::RateLimited {
            retry_after_secs: reset_secs,
        }
        .into_response();
    }

    next.run(req).await
}

/// API Key 认证中间件状态。
///
/// 持有预期的 API Key 值与认证失败锁定状态，与请求 X-API-Key 头比对。
#[derive(Debug, Clone)]
pub struct ApiKeyState {
    /// 预期的 API Key。
    pub api_key: String,
    /// 认证失败锁定（按源 IP 记账，GAR-25）。
    pub lockout: Arc<ApiKeyLockout>,
}

impl ApiKeyState {
    /// 以默认锁定配置（阈值 10 / 窗口 300s，与 AuthServerConfig::default 一致）构造状态。
    pub fn new(api_key: impl Into<String>) -> Self {
        let config = super::AuthServerConfig::default();
        Self::with_lockout(
            api_key,
            config.api_key_lockout_threshold,
            config.api_key_lockout_window_secs,
        )
    }

    /// 完整构造（锁定阈值/窗口由调用方给定；threshold=0 禁用锁定）。
    pub fn with_lockout(api_key: impl Into<String>, threshold: u32, window_secs: u64) -> Self {
        Self {
            api_key: api_key.into(),
            lockout: Arc::new(ApiKeyLockout::new(threshold, window_secs)),
        }
    }
}

/// 常量时间比较循环的固定工作量（字节）。
///
/// 合法 API Key 长度远小于此值；双方不足处以 0 填充对齐到固定长度，
/// 保证比较循环执行次数与输入长度无关（不泄露 API Key 长度）。
const CT_EQ_FIXED_WORKLOAD: usize = 256;

/// API Key 常量时间比较（固定工作量），防止 timing attack。
///
/// 字节比较统一委托公共原语 [`crate::secure::ct_eq::constant_time_eq`]
/// （ADR-0003 决策 2：消除本地第二实现）；为保留「比较工作量与输入长度无关、
/// 不泄露 API Key 长度」的强化语义，双方先按 `CT_EQ_FIXED_WORKLOAD` 定长
/// 0 填充，再走公共原语（原语在定长缓冲上循环，次数与实际输入长度无关）。
///
/// # 安全性
///
/// - 字节比较执行**固定工作量**（`CT_EQ_FIXED_WORKLOAD` 次迭代，与输入长度无关），
///   既不在第一个不匹配字节处短路返回，也不按输入长度决定循环次数，
///   避免攻击者通过测量响应时间逐字节推断 API Key 内容或长度
/// - 任一输入超过固定工作量上限时返回 false：仅泄露"长度 > 256"这一粗粒度信息，
///   不再泄露精确长度（合法 API Key 不会达到该长度）
fn api_key_ct_eq(a: &str, b: &str) -> bool {
    let a_bytes = a.as_bytes();
    let b_bytes = b.as_bytes();

    // 超过固定工作量上限的输入不可能匹配真实 key，判不相等
    //（非短路 & 聚合；仅暴露 "> 上限" 这一 coarse 事实）
    let len_ok = (a_bytes.len() <= CT_EQ_FIXED_WORKLOAD) & (b_bytes.len() <= CT_EQ_FIXED_WORKLOAD);

    // 双方按定长 0 填充（超长截断，超长输入由 len_ok 判 false 兜底），
    // 公共原语在定长缓冲上循环 CT_EQ_FIXED_WORKLOAD 次，与输入长度无关
    let mut a_padded = [0u8; CT_EQ_FIXED_WORKLOAD];
    let mut b_padded = [0u8; CT_EQ_FIXED_WORKLOAD];
    let a_len = a_bytes.len().min(CT_EQ_FIXED_WORKLOAD);
    let b_len = b_bytes.len().min(CT_EQ_FIXED_WORKLOAD);
    a_padded[..a_len].copy_from_slice(&a_bytes[..a_len]);
    b_padded[..b_len].copy_from_slice(&b_bytes[..b_len]);

    len_ok & crate::secure::ct_eq::constant_time_eq(&a_padded, &b_padded)
}

/// API Key 认证中间件 — 验证 X-API-Key 头。
///
/// # 拒绝语义（全部 fail-closed）
///
/// - 空 `api_key` 配置：拒绝所有请求（防御默认值泄露），不参与锁定记账
/// - 重复 `X-API-Key` 头（多值）：401（GAR-28——首值/末值语义因网关而异，
///   多值头本身就是异常请求，直接拒绝消除判定分裂）
/// - 锁定中（同源 IP 连续失败达阈值且在窗口内）：429 + `Retry-After`
/// - 缺失/不匹配：401 并记一次失败；达到锁定阈值时本请求即返回 429
///
/// 不匹配或缺失返回 401 Unauthorized，响应体为 JSON：
/// ```json
/// { "error": "unauthorized", "message": "Invalid API Key" }
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
                "message": translate_detail("server-invalid-api-key", &[])
            })),
        )
            .into_response();
    }

    // 锁定记账键：源连接 IP（无 ConnectInfo 时聚合为 "unknown"；
    // 内网端口面向服务间调用，不做 XFF 解析，避免可信头伪造绕过记账）
    let source = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // 锁定中：窗口期内一律 429，无论本次 key 是否合法
    if let Some(retry_after) = state.lockout.check_locked(&source) {
        tracing::warn!(source = %source, retry_after, "api key auth locked: brute-force lockout window active");
        return GarrisonError::RateLimited {
            retry_after_secs: retry_after,
        }
        .into_response();
    }

    // GAR-28: 重复 X-API-Key 头 fail-closed 拒绝（首值/末值语义分歧下的判定分裂面）
    let mut header_values = req.headers().get_all("x-api-key").iter();
    let first = header_values.next();
    if header_values.next().is_some() {
        let outcome = state.lockout.record_failure(&source);
        tracing::warn!(source = %source, failures = outcome.count, "duplicate X-API-Key header rejected");
        return auth_failure_response(&state, &source, outcome);
    }

    // 常量时间比较，防止 timing attack 逐字节推断 API Key
    let valid = first
        .and_then(|v| v.to_str().ok())
        .map(|k| api_key_ct_eq(k, &state.api_key))
        .unwrap_or(false);

    if !valid {
        let outcome = state.lockout.record_failure(&source);
        tracing::warn!(source = %source, failures = outcome.count, "api key auth failed");
        return auth_failure_response(&state, &source, outcome);
    }

    // 成功认证清零失败记录
    state.lockout.record_success(&source);

    next.run(req).await
}

/// 认证失败响应：达到锁定阈值即 429（本请求即生效，不等下一次），
/// 否则统一 401 JSON 错误体。
fn auth_failure_response(
    state: &ApiKeyState,
    source: &str,
    outcome: crate::server::api_key_lockout::FailureOutcome,
) -> Response {
    if outcome.locked {
        tracing::warn!(source = %source, threshold = state.lockout.threshold(), "api key auth locked out");
        return GarrisonError::RateLimited {
            retry_after_secs: outcome.retry_after_secs,
        }
        .into_response();
    }
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({
            "error": "unauthorized",
            "message": translate_detail("server-invalid-api-key", &[])
        })),
    )
        .into_response()
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
// sdforge::http::build() 收集所有 #[forge] 路由到单一 Router（15 个基础端点，
// metrics-prometheus 启用时 +1 = 16），
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

/// 外网登录端点开关状态（C-1，供 `external_login_gate` 的 middleware state）。
///
/// `false`（默认）时 `POST /api/v1/auth/login` 返回 404——框架的 login 端点
/// 不校验任何凭证（Sa-Token 模型：业务层先验密码、框架只签发会话），
/// 无条件对外暴露将允许任意主体获取任意用户的有效会话。
#[derive(Debug, Clone, Copy)]
pub struct ExternalLoginGate(pub bool);

/// 外网登录端点 gate 中间件（C-1 fail-closed）。
///
/// 挂载在外网 router、`external_path_filter` 内层：path-filter 放行 login 后
/// 由本中间件按 `ExternalLoginGate` 决定放行或 404。禁用状态下不打每请求日志
/// （避免探测刷日志），启用与否由 `listen()` 启动日志声明。
pub async fn external_login_gate(
    axum::extract::State(gate): axum::extract::State<ExternalLoginGate>,
    req: Request,
    next: Next,
) -> Response {
    if !gate.0 && req.uri().path() == "/api/v1/auth/login" {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(req).await
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

// ============================================================================
// 客户端 IP 注入中间件（fix-security-gaps: IP 自动提取）
// ============================================================================

/// 客户端 IP 包装结构体。
///
/// `inject_client_ip` middleware 从 HTTP 请求提取真实客户端 IP 后
/// 存入 `Extension<ClientIp>`，下游 handler 通过 `req.extensions().get::<ClientIp>()`
/// 读取。login handler 在 `LoginParams.ip.is_none()` 时自动填充。
#[derive(Debug, Clone)]
pub struct ClientIp(pub String);

/// 可信代理 IP 列表包装结构体。
///
/// 通过 `Extension<TrustedProxies>` 注入到 router，供 `inject_client_ip`
/// middleware 读取。复用 `AuthServerConfig.rate_limit_trusted_proxies` 配置。
#[derive(Debug, Clone)]
pub struct TrustedProxies(pub Vec<IpAddr>);

/// 客户端 IP 自动注入中间件。
///
/// 从 `ConnectInfo<SocketAddr>` + `X-Forwarded-For`（仅信任 `TrustedProxies` 中的代理）
/// 提取真实客户端 IP，存入 `Extension<ClientIp>`。
///
/// # 挂载位置
///
/// 仅挂载到外网 router（`external_router()`），内网路由不需要。
/// 应在 `rate_limit_middleware` 之后、`external_path_filter` 之前。
pub async fn inject_client_ip(mut req: Request, next: Next) -> Response {
    let trusted_proxies = req
        .extensions()
        .get::<TrustedProxies>()
        .map(|tp| tp.0.as_slice())
        .unwrap_or_default();

    let ip = extract_client_ip(&req, trusted_proxies);
    // 同步写入 task_local，供 SessionHijackDetector 在 check_login 路径读取
    #[cfg(feature = "session-hijack-detection")]
    {
        let _ = CLIENT_IP.try_with(|cell| {
            *cell.borrow_mut() = Some(ip.clone());
        });
    }
    req.extensions_mut().insert(ClientIp(ip));
    next.run(req).await
}

// ============================================================================
// task_local 客户端上下文（供 SessionHijackDetector 读取）
// ============================================================================

// 当前请求客户端 IP（task_local，`session-hijack-detection` feature 启用时可用）。
#[cfg(feature = "session-hijack-detection")]
tokio::task_local! {
    /// 当前请求客户端 IP（task_local，`pub(crate)` 供测试设置上下文）。
    pub(crate) static CLIENT_IP: std::cell::RefCell<Option<String>>;
    /// 当前请求 User-Agent（task_local，`pub(crate)` 供测试设置上下文）。
    pub(crate) static CLIENT_USER_AGENT: std::cell::RefCell<Option<String>>;
}

/// 获取当前请求的客户端 IP（从 task_local 读取）。
///
/// 仅在 `session-hijack-detection` feature 启用时可用。
/// 非 HTTP 请求路径（如直接 API 调用）返回 `None`。
#[cfg(feature = "session-hijack-detection")]
pub fn current_client_ip() -> Option<String> {
    CLIENT_IP
        .try_with(|cell| cell.borrow().clone())
        .unwrap_or(None)
}

/// 获取当前请求的 User-Agent（从 task_local 读取）。
///
/// 仅在 `session-hijack-detection` feature 启用时可用。
/// 非 HTTP 请求路径（如直接 API 调用）返回 `None`。
#[cfg(feature = "session-hijack-detection")]
pub fn current_user_agent() -> Option<String> {
    CLIENT_USER_AGENT
        .try_with(|cell| cell.borrow().clone())
        .unwrap_or(None)
}

/// User-Agent 自动注入中间件。
///
/// 从请求 `User-Agent` header 提取值并存入 task_local `CLIENT_USER_AGENT`，
/// 供 `SessionHijackDetector` 在 `check_login` 路径读取。
///
/// # 挂载位置
///
/// 仅挂载到外网 router（`external_router()`），在 `inject_client_ip` 之后。
/// 仅在 `session-hijack-detection` feature 启用时有实际效果。
pub async fn inject_user_agent(req: Request, next: Next) -> Response {
    #[cfg(feature = "session-hijack-detection")]
    {
        let ua = req
            .headers()
            .get(axum::http::header::USER_AGENT)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        CLIENT_USER_AGENT
            .try_with(|cell| {
                *cell.borrow_mut() = ua;
            })
            .ok();
    }
    next.run(req).await
}

/// 登录端点 IP 自动填充中间件。
///
/// 仅挂载到 `POST /api/v1/auth/login` 端点。读取 `Extension<ClientIp>`，
/// 当请求体 JSON 中 `params.ip` 为 null 或缺失时，自动填充客户端 IP。
///
/// # 行为说明
///
/// 调用方显式传入 `params.ip` 时不覆盖（显式值优先于自动填充）。
/// 非 login 路径不应挂载此中间件（避免不必要的 body 解析开销）。
pub async fn inject_login_client_ip(req: Request, next: Next) -> Response {
    // 仅处理 login 端点，其余路径直接放行（避免不必要的 body 解析）
    if req.uri().path() != "/api/v1/auth/login" {
        return next.run(req).await;
    }

    // GAR-29：读体与限幅判定无条件执行（不依赖 ClientIp 可用性）——否则
    // Extension 缺失/unknown 时超限 body 会穿透到 axum DefaultBodyLimit，
    // 以裸 text 413 响应绕开统一 JSON 错误体。
    let client_ip = req
        .extensions()
        .get::<ClientIp>()
        .map(|c| c.0.clone())
        .filter(|ip| ip != "unknown");

    let (parts, body) = req.into_parts();
    let bytes = match axum::body::to_bytes(body, 256 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            // 读体失败（限幅超限 LengthLimitError 或 IO 错误）直接
            // 返回 413 统一 JSON 错误体——不转发空 body（空 body 会到达
            // Json extractor 产生误导性的 400 EOF），也不静默断连。
            tracing::warn!(error = %e, "inject_login_client_ip: body read failed (oversize or IO)");
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                [(
                    CONTENT_TYPE,
                    axum::http::HeaderValue::from_static("application/json"),
                )],
                PAYLOAD_TOO_LARGE_BODY,
            )
                .into_response();
        },
    };

    // 畸形 JSON body 不再静默替换为 null——
    // 直接返回 400 Bad Request（fail-fast），避免下游 handler 收到被破坏的请求体。
    let mut json: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "inject_login_client_ip: malformed JSON body");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({
                    "error": "bad_request",
                    "message": "request body must be valid JSON"
                })),
            )
                .into_response();
        },
    };

    // 显式传入的 params.ip 优先于自动填充；仅存在已知客户端 IP 时注入
    let should_inject = client_ip.is_some()
        && json
            .get("params")
            .and_then(|p| p.get("ip"))
            .is_none_or(|v| v.is_null());

    let new_body = if should_inject {
        if let Some(params) = json.get_mut("params").and_then(|p| p.as_object_mut()) {
            let ip = client_ip.expect("should_inject 蕴含 client_ip 存在");
            params.insert("ip".to_string(), serde_json::Value::String(ip));
        }
        axum::body::Body::from(serde_json::to_vec(&json).unwrap_or_else(|_| bytes.to_vec()))
    } else {
        // 未注入时原样转发原始字节（不做序列化往返）
        axum::body::Body::from(bytes)
    };
    let req = Request::from_parts(parts, new_body);

    next.run(req).await
}

// ============================================================================
// Json extractor rejection 清洗（GAR-27：422 类型名泄露）
// ============================================================================

/// Json extractor rejection 的统一错误体（不含任何类型/字段/偏移细节）。
const REJECTION_BODY: &str =
    r#"{"error":"bad_request","message":"request body failed validation"}"#;

/// 请求体超限（413）的统一错误体——login 读体限幅（`inject_login_client_ip`）
/// 与 sanitize 中间件（axum `DefaultBodyLimit` 裸 413 rejection）共用同一常量，
/// 避免第二实现漂移。
const PAYLOAD_TOO_LARGE_BODY: &str =
    r#"{"error":"payload_too_large","message":"request body exceeds size limit"}"#;

/// Json extractor rejection 清洗中间件 — 统一改写 axum 默认 rejection 响应。
///
/// axum 0.8 的 `Json` extractor rejection（`JsonDataError` 422 / `JsonSyntaxError`
/// 400 / `MissingJsonContentType` 415）以 `text/plain` 回显序列化诊断信息：
/// 内部 Rust 类型名（"expected struct LoginRequest"）、字段名与攻击者输入的
/// 字节偏移，可用于指纹识别与字段枚举。`DefaultBodyLimit` 的 body 超限
/// rejection（`LengthLimitError`）同为 413 + text/plain 非空诊断体。本中间件
/// 识别「4xx + text/plain + 非空 body」的 rejection 响应，将 body 改写为统一
/// JSON 错误体，状态码保持原值（413 用 [`PAYLOAD_TOO_LARGE_BODY`]，与 login
/// 读体限幅同体；其余用 [`REJECTION_BODY`]）。
///
/// # 误伤排除
///
/// - 业务与中间件自身的 JSON 错误体（`application/json`）不匹配，原样通过
/// - path-filter 等裸 `StatusCode` 响应为空 body，不匹配（且 404 不在集合内）
/// - OAuth2/qrlogin merge 路由自带中间件栈，handler 自产 JSON 错误，不受影响
pub async fn sanitize_json_rejection_middleware(req: Request, next: Next) -> Response {
    let response = next.run(req).await;

    let is_rejection_status = matches!(
        response.status(),
        StatusCode::BAD_REQUEST
            | StatusCode::UNSUPPORTED_MEDIA_TYPE
            | StatusCode::UNPROCESSABLE_ENTITY
            | StatusCode::PAYLOAD_TOO_LARGE
    );
    if !is_rejection_status {
        return response;
    }
    let is_text_plain = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("text/plain"));
    if !is_text_plain {
        return response;
    }

    let status = response.status();
    let sanitized_body = if status == StatusCode::PAYLOAD_TOO_LARGE {
        PAYLOAD_TOO_LARGE_BODY
    } else {
        REJECTION_BODY
    };
    let (_, body) = response.into_parts();
    // rejection 诊断体均为短文本；64KB 上限仅为防御异常大 body
    match axum::body::to_bytes(body, 64 * 1024).await {
        // 重建响应（丢弃旧 headers，避免残留与新 body 不一致的 content-length）
        Ok(bytes) if !bytes.is_empty() => {
            let mut sanitized = axum::http::Response::new(axum::body::Body::from(sanitized_body));
            *sanitized.status_mut() = status;
            sanitized.headers_mut().insert(
                CONTENT_TYPE,
                axum::http::HeaderValue::from_static("application/json"),
            );
            sanitized
        },
        // 空 body 的裸状态码响应（非 rejection）原样放行
        Ok(_) => {
            let mut empty = axum::http::Response::new(axum::body::Body::empty());
            *empty.status_mut() = status;
            empty
        },
        // body 读取失败：错误显性化，返回统一错误体（拒绝语义不变）
        Err(e) => {
            tracing::warn!(error = %e, status = status.as_u16(), "sanitize_json_rejection: body read failed");
            (status, axum::body::Body::from(sanitized_body)).into_response()
        },
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

        for _ in 0..2 {
            let resp = app
                .clone()
                .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }

        let resp = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        // 统一错误体（R04）：error_code / error_id 字段
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error_code"], "RATE_LIMITED");
        assert_eq!(json["error_id"], "ratelimit.rate_limited");
    }

    /// 429 响应携带 Retry-After 头，值为合法 delta-seconds（>= 1）。
    ///
    /// 精确值 = limiteron 快照 reset_secs（受令牌补充时间影响，不作精确断言；
    /// 下限 1 的强制逻辑由 error.rs 的 `retry_after_secs` 纯函数测试覆盖）。
    #[tokio::test]
    async fn rate_limit_429_retry_after_matches_reset_secs() {
        let state = Arc::new(RateLimitState::new(2));
        let app = ok_router().layer(axum::middleware::from_fn_with_state(
            state,
            rate_limit_middleware,
        ));

        for _ in 0..2 {
            let resp = app
                .clone()
                .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK);
        }
        let resp = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let value = resp
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(0);
        assert!(
            value >= 1,
            "Retry-After 应为 delta-seconds 且 >= 1，实际: {value}"
        );
    }

    /// reset_secs=0 时 Retry-After 取下限 1（capacity=0 配置强制触发）。
    #[tokio::test]
    async fn rate_limit_429_retry_after_floor_is_one() {
        let state = Arc::new(RateLimitState::new(0));
        let app = ok_router().layer(axum::middleware::from_fn_with_state(
            state,
            rate_limit_middleware,
        ));
        let resp = app
            .oneshot(Request::builder().uri("/ping").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        let value = resp
            .headers()
            .get("Retry-After")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(value, "1", "reset_secs=0 应取下限 1");
    }

    /// request id 中间件外层挂载时，429 响应体携带 request_id（与请求头一致）。
    #[tokio::test]
    async fn rate_limit_429_body_carries_request_id() {
        let state = Arc::new(RateLimitState::new(0));
        let app = ok_router()
            .layer(axum::middleware::from_fn_with_state(
                state,
                rate_limit_middleware,
            ))
            .layer(axum::middleware::from_fn(
                crate::web::request_id::request_id_middleware,
            ));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ping")
                    .header("X-Request-ID", "gw-429-corr")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get("X-Request-ID")
                .and_then(|v| v.to_str().ok()),
            Some("gw-429-corr")
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["request_id"], "gw-429-corr");
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
        // 单跳 XFF：rightmost-untrusted 即该跳本身（非可信），取 "1.2.3.4"
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
        let state = Arc::new(ApiKeyState::new("secret-key"));
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
        let state = Arc::new(ApiKeyState::new("secret-key"));
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
        let state = Arc::new(ApiKeyState::new("secret-key"));
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
        let state = Arc::new(ApiKeyState::new(String::new()));
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

    /// 常量时间比较函数正确性验证（ADR-0003：字节比较统一委托公共原语，
    /// 本函数保留固定工作量定长填充策略，防 API Key 长度泄露）。
    #[test]
    fn test_api_key_ct_eq() {
        assert!(api_key_ct_eq("abc", "abc"));
        assert!(!api_key_ct_eq("abc", "abx"));
        assert!(!api_key_ct_eq("abc", "ab"));
        assert!(!api_key_ct_eq("abc", "abcd"));
        assert!(api_key_ct_eq("", ""));
        assert!(!api_key_ct_eq("", "a"));
        // 确保所有字节都被比较（非短路）
        assert!(!api_key_ct_eq("abcdefgh", "abcdefgx"));
    }

    // ========================================================================
    // api_key_ct_eq 长度泄露修复测试
    // ========================================================================

    /// 不同长度返回 false（多种长度组合）。
    #[test]
    fn api_key_ct_eq_different_lengths_returns_false() {
        assert!(!api_key_ct_eq("a", "ab"));
        assert!(!api_key_ct_eq("ab", "a"));
        assert!(!api_key_ct_eq("", "x"));
        assert!(!api_key_ct_eq("x", ""));
        assert!(!api_key_ct_eq("abc", "abcd"));
        assert!(!api_key_ct_eq("abcd", "abc"));
        assert!(!api_key_ct_eq("hello", "hello world"));
        assert!(!api_key_ct_eq("0123456789abcdef", "0123456789abcdef0"));
    }

    /// 相同值返回 true（多种内容）。
    #[test]
    fn api_key_ct_eq_same_value_returns_true() {
        assert!(api_key_ct_eq("", ""));
        assert!(api_key_ct_eq("a", "a"));
        assert!(api_key_ct_eq("abc", "abc"));
        assert!(api_key_ct_eq("hello", "hello"));
        // 长 key（模拟真实 API key 长度）
        assert!(api_key_ct_eq(
            "sk-garrison-0123456789abcdef0123456789abcdef",
            "sk-garrison-0123456789abcdef0123456789abcdef"
        ));
        assert!(api_key_ct_eq("p@ssw0rd!#$%", "p@ssw0rd!#$%"));
    }

    /// 相同长度不同值返回 false（确保不短路）。
    #[test]
    fn api_key_ct_eq_different_value_returns_false() {
        assert!(!api_key_ct_eq("abc", "xbc"));
        assert!(!api_key_ct_eq("abc", "abx"));
        assert!(!api_key_ct_eq("abc", "axc"));
        assert!(!api_key_ct_eq("a", "b"));
        assert!(!api_key_ct_eq(
            "sk-garrison-aaaaaaaaaaaaaaaaaaaaaaaa",
            "sk-garrison-bbbbbbbbbbbbbbbbbbbbbbbb"
        ));
        // 长 key 仅末字节不同（验证非常量时间提前返回）
        assert!(!api_key_ct_eq(
            "sk-garrison-0123456789abcdef0123456789abcdef",
            "sk-garrison-0123456789abcdef0123456789abcdeg"
        ));
    }

    /// 空字符串返回 true。
    #[test]
    fn api_key_ct_eq_empty_strings_returns_true() {
        assert!(api_key_ct_eq("", ""));
        // 双重确认：空 vs 非空仍为 false
        assert!(!api_key_ct_eq("", " "));
        assert!(!api_key_ct_eq(" ", ""));
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

    /// 构建包含所有 15 个基础 auth 路由的测试 Router（3 外网 + 12 内网，不含 metrics 端点）。
    /// 用于 path-filter 中间件测试。
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

    /// C-1: gate 禁用（默认）时外网 login 返回 404，其余外网路径不受影响。
    #[tokio::test]
    async fn test_external_login_gate_disabled_blocks_login() {
        let app = make_all_routes_router().layer(axum::middleware::from_fn_with_state(
            ExternalLoginGate(false),
            external_login_gate,
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "默认应拒绝外网 login");
    }

    /// C-1: gate 启用时外网 login 正常到达 handler。
    #[tokio::test]
    async fn test_external_login_gate_enabled_allows_login() {
        let app = make_all_routes_router().layer(axum::middleware::from_fn_with_state(
            ExternalLoginGate(true),
            external_login_gate,
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "显式启用后 login 应放行");
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
                    #[cfg(feature = "session-extra")]
                    dynamic_active_timeout: None,
                    #[cfg(feature = "session-extra")]
                    is_anon: false,
                    effective_timeout: None,
                    amr_ledger: Vec::new(),
                    auth_time: None,
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

    // ========================================================================
    // inject_client_ip middleware 测试
    // ========================================================================

    /// 直连（非可信代理）：使用 ConnectInfo 中的连接 IP。
    #[tokio::test]
    async fn test_inject_client_ip_direct_connection() {
        let app = Router::new()
            .route(
                "/ip",
                get(|req: super::Request| async move {
                    req.extensions()
                        .get::<ClientIp>()
                        .map(|c| c.0.clone())
                        .unwrap_or_default()
                }),
            )
            .layer(axum::middleware::from_fn(inject_client_ip))
            .layer(Extension(TrustedProxies(vec![])));

        let req = Request::builder()
            .uri("/ip")
            .extension(ConnectInfo::<SocketAddr>(
                "203.0.113.1:12345".parse().unwrap(),
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "203.0.113.1");
    }

    /// 经可信代理（XFF 有效）：取 rightmost-untrusted（最右不可信跳）。
    #[tokio::test]
    async fn test_inject_client_ip_trusted_proxy_with_xff() {
        let trusted = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        let app = Router::new()
            .route(
                "/ip",
                get(|req: super::Request| async move {
                    req.extensions()
                        .get::<ClientIp>()
                        .map(|c| c.0.clone())
                        .unwrap_or_default()
                }),
            )
            .layer(axum::middleware::from_fn(inject_client_ip))
            .layer(Extension(TrustedProxies(trusted)));

        let req = Request::builder()
            .uri("/ip")
            .header("x-forwarded-for", "198.51.100.5, 10.0.0.1")
            .extension(ConnectInfo::<SocketAddr>("10.0.0.1:8080".parse().unwrap()))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "198.51.100.5",
            "可信代理场景应取 rightmost-untrusted 跳"
        );
    }

    /// 客户端预伪造最左 XFF：rightmost-untrusted 应忽略伪造值，取可信代理
    /// 追加的真实客户端跳（旧「取最左值」实现会返回 1.2.3.4，即攻击者可控）。
    #[tokio::test]
    async fn test_inject_client_ip_forged_leftmost_xff_ignored() {
        let trusted = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        let app = Router::new()
            .route(
                "/ip",
                get(|req: super::Request| async move {
                    req.extensions()
                        .get::<ClientIp>()
                        .map(|c| c.0.clone())
                        .unwrap_or_default()
                }),
            )
            .layer(axum::middleware::from_fn(inject_client_ip))
            .layer(Extension(TrustedProxies(trusted)));

        let req = Request::builder()
            .uri("/ip")
            .header("x-forwarded-for", "1.2.3.4, 198.51.100.5, 10.0.0.1")
            .extension(ConnectInfo::<SocketAddr>("10.0.0.1:8080".parse().unwrap()))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "198.51.100.5",
            "预伪造的最左值必须被忽略，取最右不可信跳"
        );
    }

    /// parse_forwarded_for_rightmost 纯函数：全可信跳回退最左值。
    #[test]
    fn test_parse_forwarded_for_rightmost_all_trusted_returns_leftmost() {
        let trusted = vec![
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ];
        assert_eq!(
            super::parse_forwarded_for_rightmost("10.0.0.2, 10.0.0.1", &trusted),
            Some("10.0.0.2".to_string())
        );
    }

    /// parse_forwarded_for_rightmost 纯函数：空串返回 None。
    #[test]
    fn test_parse_forwarded_for_rightmost_empty_returns_none() {
        assert_eq!(super::parse_forwarded_for_rightmost("", &[]), None);
        assert_eq!(super::parse_forwarded_for_rightmost(" , ", &[]), None);
    }

    /// 非可信代理伪造 XFF：忽略 XFF，使用连接 IP。
    #[tokio::test]
    async fn test_inject_client_ip_untrusted_proxy_ignores_xff() {
        let trusted = vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))];
        let app = Router::new()
            .route(
                "/ip",
                get(|req: super::Request| async move {
                    req.extensions()
                        .get::<ClientIp>()
                        .map(|c| c.0.clone())
                        .unwrap_or_default()
                }),
            )
            .layer(axum::middleware::from_fn(inject_client_ip))
            .layer(Extension(TrustedProxies(trusted)));

        let req = Request::builder()
            .uri("/ip")
            .header("x-forwarded-for", "198.51.100.5")
            .extension(ConnectInfo::<SocketAddr>(
                "203.0.113.50:9999".parse().unwrap(),
            ))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(
            std::str::from_utf8(&body).unwrap(),
            "203.0.113.50",
            "非可信代理的 XFF 应被忽略"
        );
    }

    /// 无 ConnectInfo（如 oneshot 测试）：返回 "unknown"。
    #[tokio::test]
    async fn test_inject_client_ip_no_connect_info() {
        let app = Router::new()
            .route(
                "/ip",
                get(|req: super::Request| async move {
                    req.extensions()
                        .get::<ClientIp>()
                        .map(|c| c.0.clone())
                        .unwrap_or_default()
                }),
            )
            .layer(axum::middleware::from_fn(inject_client_ip))
            .layer(Extension(TrustedProxies(vec![])));

        let req = Request::builder().uri("/ip").body(Body::empty()).unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "unknown");
    }

    // ========================================================================
    // inject_login_client_ip middleware 测试
    // ========================================================================

    /// login 端点 + params.ip 为 null：自动填充 ClientIp。
    #[tokio::test]
    async fn test_inject_login_client_ip_fills_null_ip() {
        let app = Router::new()
            .route(
                "/api/v1/auth/login",
                post(|body: axum::Json<serde_json::Value>| async move { axum::Json(body.0) }),
            )
            .layer(axum::middleware::from_fn(inject_login_client_ip))
            .layer(Extension(ClientIp("203.0.113.1".to_string())));

        let req = Request::builder()
            .uri("/api/v1/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "login_id": "user1",
                    "params": { "ip": null, "ua": "test" }
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["params"]["ip"].as_str().unwrap(),
            "203.0.113.1",
            "null ip 应被自动填充"
        );
    }

    /// login 端点 + params 无 ip 字段：自动填充。
    #[tokio::test]
    async fn test_inject_login_client_ip_fills_missing_ip() {
        let app = Router::new()
            .route(
                "/api/v1/auth/login",
                post(|body: axum::Json<serde_json::Value>| async move { axum::Json(body.0) }),
            )
            .layer(axum::middleware::from_fn(inject_login_client_ip))
            .layer(Extension(ClientIp("10.0.0.5".to_string())));

        let req = Request::builder()
            .uri("/api/v1/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "login_id": "user1",
                    "params": { "ua": "test" }
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["params"]["ip"].as_str().unwrap(),
            "10.0.0.5",
            "缺失 ip 字段应被自动填充"
        );
    }

    /// login 端点 + params.ip 已有值：不覆盖。
    #[tokio::test]
    async fn test_inject_login_client_ip_does_not_override_existing() {
        let app = Router::new()
            .route(
                "/api/v1/auth/login",
                post(|body: axum::Json<serde_json::Value>| async move { axum::Json(body.0) }),
            )
            .layer(axum::middleware::from_fn(inject_login_client_ip))
            .layer(Extension(ClientIp("203.0.113.1".to_string())));

        let req = Request::builder()
            .uri("/api/v1/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "login_id": "user1",
                    "params": { "ip": "192.168.1.100" }
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["params"]["ip"].as_str().unwrap(),
            "192.168.1.100",
            "已有 ip 值不应被覆盖"
        );
    }

    /// 非 login 端点：直接放行，不修改 body。
    #[tokio::test]
    async fn test_inject_login_client_ip_skips_non_login_path() {
        let app = Router::new()
            .route(
                "/api/v1/auth/logout",
                post(|body: axum::Json<serde_json::Value>| async move { axum::Json(body.0) }),
            )
            .layer(axum::middleware::from_fn(inject_login_client_ip))
            .layer(Extension(ClientIp("203.0.113.1".to_string())));

        let req = Request::builder()
            .uri("/api/v1/auth/logout")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({ "token": "abc" })).unwrap(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("params").is_none(), "非 login 路径不应注入 params");
    }

    /// ClientIp 为 "unknown" 时不注入。
    #[tokio::test]
    async fn test_inject_login_client_ip_unknown_skipped() {
        let app = Router::new()
            .route(
                "/api/v1/auth/login",
                post(|body: axum::Json<serde_json::Value>| async move { axum::Json(body.0) }),
            )
            .layer(axum::middleware::from_fn(inject_login_client_ip))
            .layer(Extension(ClientIp("unknown".to_string())));

        let req = Request::builder()
            .uri("/api/v1/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_string(&serde_json::json!({
                    "login_id": "user1",
                    "params": { "ua": "test" }
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json["params"].get("ip").is_none(), "unknown IP 不应被注入");
    }

    // ========================================================================
    // GAR-29: 限幅超限返回 413
    // ========================================================================

    /// login 端点读体超限（>256KB）返回 413 统一 JSON 错误体，
    /// 不再转发空 body（旧行为会以误导性 400 EOF 到达 handler）。
    #[tokio::test]
    async fn inject_login_client_ip_oversize_body_returns_413() {
        let app = Router::new()
            .route(
                "/api/v1/auth/login",
                post(|body: axum::Json<serde_json::Value>| async move { axum::Json(body.0) }),
            )
            .layer(axum::middleware::from_fn(inject_login_client_ip))
            .layer(Extension(ClientIp("203.0.113.1".to_string())));

        let oversize = vec![b'x'; 256 * 1024 + 1];
        let req = Request::builder()
            .uri("/api/v1/auth/login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(oversize))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "超限 body 应返回 413 而非空 body 透传"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "payload_too_large");
    }

    // ========================================================================
    // GAR-27: Json extractor rejection 清洗
    // ========================================================================

    /// 422 rejection 测试目标类型（触发类型不匹配诊断，回显结构体名）。
    #[derive(serde::Deserialize)]
    #[allow(dead_code)]
    struct SanitizeProbeBody {
        token: String,
    }

    /// 类型错误（422 text/plain，含内部类型名/字段名/字节偏移）被改写为
    /// 统一 JSON 错误体，状态码保持 4xx，无任何类型/字段细节。
    #[tokio::test]
    async fn sanitize_json_rejection_hides_type_details_on_422() {
        let app = Router::new()
            .route(
                "/api/v1/auth/check-login",
                post(|_: axum::Json<SanitizeProbeBody>| async { "ok" }),
            )
            .layer(axum::middleware::from_fn(
                sanitize_json_rejection_middleware,
            ));

        let req = Request::builder()
            .uri("/api/v1/auth/check-login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"token":{"a":1}}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNPROCESSABLE_ENTITY,
            "状态码保持 422（4xx 语义不变，仅清洗 body）"
        );
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/json",
            "清洗后应为 JSON 错误体"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert_eq!(
            text, r#"{"error":"bad_request","message":"request body failed validation"}"#,
            "统一错误体，无任何类型/字段/偏移细节"
        );
        for leaked in ["SanitizeProbeBody", "expected", "line", "column", "token"] {
            assert!(
                !text.contains(leaked),
                "响应不得泄露 {leaked}，实际: {text}"
            );
        }
    }

    /// 语法错误（400）与缺失 content-type（415）同样统一为 JSON 错误体。
    #[tokio::test]
    async fn sanitize_json_rejection_unifies_400_and_415() {
        let app = Router::new()
            .route(
                "/api/v1/auth/check-login",
                post(|_: axum::Json<SanitizeProbeBody>| async { "ok" }),
            )
            .layer(axum::middleware::from_fn(
                sanitize_json_rejection_middleware,
            ));

        // 语法错误 → 400 + 统一 JSON
        let req = Request::builder()
            .uri("/api/v1/auth/check-login")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from("{bad json"))
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert!(!text.contains("EOF"), "不得回显诊断细节: {text}");
        assert!(serde_json::from_slice::<serde_json::Value>(&body).is_ok());

        // 缺失 content-type → 415 + 统一 JSON
        let req = Request::builder()
            .uri("/api/v1/auth/check-login")
            .method("POST")
            .body(Body::from(r#"{"token":"x"}"#))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(serde_json::from_slice::<serde_json::Value>(&body).is_ok());
    }

    /// 非 login 端点超限 body（>256KB）命中 `DefaultBodyLimit` 的 413 text/plain
    /// rejection（axum `LengthLimitError`，非空诊断体），被 sanitize 中间件归一为
    /// 统一 JSON 错误体——与 login 读体限幅（`inject_login_client_ip`）同体，
    /// 不回显 axum 内部诊断。
    #[tokio::test]
    async fn sanitize_json_rejection_unifies_413_oversize_body() {
        let app = Router::new()
            .route(
                "/api/v1/auth/refresh",
                post(|_: axum::Json<SanitizeProbeBody>| async { "ok" }),
            )
            .layer(axum::extract::DefaultBodyLimit::max(256 * 1024))
            .layer(axum::middleware::from_fn(
                sanitize_json_rejection_middleware,
            ));

        let oversize = vec![b'x'; 256 * 1024 + 1];
        let req = Request::builder()
            .uri("/api/v1/auth/refresh")
            .method("POST")
            .header("content-type", "application/json")
            .body(Body::from(oversize))
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "超限 body 应保持 413 语义"
        );
        assert_eq!(
            resp.headers().get(CONTENT_TYPE).unwrap(),
            "application/json",
            "裸 text/plain 413 应归一为 JSON 错误体"
        );
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = std::str::from_utf8(&body).unwrap();
        assert_eq!(
            text, PAYLOAD_TOO_LARGE_BODY,
            "413 错误体应与 login 路径统一"
        );
        assert!(
            !text.contains("buffer"),
            "不得回显 axum 内部诊断，实际: {text}"
        );
    }

    /// 业务 JSON 错误体（application/json）与裸 404（空 body）原样通过，不误伤。
    #[tokio::test]
    async fn sanitize_json_rejection_passes_json_and_404_through() {
        let app = Router::new()
            .route(
                "/biz",
                post(|| async {
                    (
                        StatusCode::BAD_REQUEST,
                        axum::Json(serde_json::json!({"error": "custom"})),
                    )
                }),
            )
            .layer(axum::middleware::from_fn(
                sanitize_json_rejection_middleware,
            ));

        // JSON 400（业务错误体）不被改写
        let req = Request::builder()
            .uri("/biz")
            .method("POST")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "custom", "业务 JSON 错误体不应被清洗");

        // 404（空 body，裸 StatusCode）不被改写
        let req = Request::builder()
            .uri("/no-such-route")
            .method("POST")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    // ========================================================================
    // GAR-28: 重复 X-API-Key 头 fail-closed
    // ========================================================================

    /// 重复 X-API-Key 头（错误值在前）→ 401，即使后续存在合法值。
    #[tokio::test]
    async fn api_key_auth_rejects_duplicate_header_wrong_first() {
        let state = Arc::new(ApiKeyState::with_lockout("secret-key", 0, 300));
        let app = ok_router().layer(axum::middleware::from_fn_with_state(
            state,
            api_key_auth_middleware,
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ping")
                    .header("x-api-key", "wrong-key")
                    .header("x-api-key", "secret-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "重复头应 fail-closed 拒绝，不按首值/末值任一语义放行"
        );
    }

    /// 重复 X-API-Key 头（合法值在前）同样 401——消除与「取末值」网关的判定分裂。
    #[tokio::test]
    async fn api_key_auth_rejects_duplicate_header_valid_first() {
        let state = Arc::new(ApiKeyState::with_lockout("secret-key", 0, 300));
        let app = ok_router().layer(axum::middleware::from_fn_with_state(
            state,
            api_key_auth_middleware,
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .uri("/ping")
                    .header("x-api-key", "secret-key")
                    .header("x-api-key", "wrong-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ========================================================================
    // GAR-25: API Key 认证失败锁定
    // ========================================================================

    /// 连续失败达阈值后，合法 key 也被 429 + Retry-After 锁定。
    #[tokio::test]
    async fn api_key_lockout_blocks_correct_key_after_threshold() {
        let state = Arc::new(ApiKeyState::with_lockout("secret-key", 2, 300));
        let app = ok_router().layer(axum::middleware::from_fn_with_state(
            state,
            api_key_auth_middleware,
        ));
        let wrong = |app: &Router| {
            let req = Request::builder()
                .uri("/ping")
                .header("x-api-key", "wrong")
                .body(Body::empty())
                .unwrap();
            app.clone().oneshot(req)
        };

        let resp = wrong(&app).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "第 1 次失败仍 401");
        let resp = wrong(&app).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "达阈值请求本身即返回 429"
        );
        assert!(
            resp.headers().get("Retry-After").is_some(),
            "429 应携带 Retry-After 头"
        );

        // 锁定窗口内：正确 key 也 429
        let req = Request::builder()
            .uri("/ping")
            .header("x-api-key", "secret-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "锁定窗口内正确 key 也应 429"
        );
    }

    /// 成功认证清零失败记录：失败→成功→失败 不触发锁定。
    #[tokio::test]
    async fn api_key_lockout_resets_on_success() {
        let state = Arc::new(ApiKeyState::with_lockout("secret-key", 2, 300));
        let app = ok_router().layer(axum::middleware::from_fn_with_state(
            state,
            api_key_auth_middleware,
        ));
        let send = |key: &'static str, app: &Router| {
            let req = Request::builder()
                .uri("/ping")
                .header("x-api-key", key)
                .body(Body::empty())
                .unwrap();
            app.clone().oneshot(req)
        };

        assert_eq!(
            send("wrong", &app).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send("secret-key", &app).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            send("wrong", &app).await.unwrap().status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            send("secret-key", &app).await.unwrap().status(),
            StatusCode::OK,
            "成功清零后第二次失败（count=1）不应锁定"
        );
    }

    /// 窗口过期后锁定解除，锁定内/外的响应语义正确。
    #[tokio::test]
    async fn api_key_lockout_window_expiry_unlocks() {
        let state = Arc::new(ApiKeyState::with_lockout("secret-key", 1, 1));
        let app = ok_router().layer(axum::middleware::from_fn_with_state(
            state,
            api_key_auth_middleware,
        ));

        let req = Request::builder()
            .uri("/ping")
            .header("x-api-key", "wrong")
            .body(Body::empty())
            .unwrap();
        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "阈值 1：首次失败即锁定"
        );

        tokio::time::sleep(std::time::Duration::from_millis(1100)).await;

        let req = Request::builder()
            .uri("/ping")
            .header("x-api-key", "secret-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "窗口过期后锁定应解除，正确 key 恢复 200"
        );
    }

    /// threshold=0 显式禁用锁定：多次失败后合法 key 仍 200。
    #[tokio::test]
    async fn api_key_lockout_disabled_when_threshold_zero() {
        let state = Arc::new(ApiKeyState::with_lockout("secret-key", 0, 300));
        let app = ok_router().layer(axum::middleware::from_fn_with_state(
            state,
            api_key_auth_middleware,
        ));
        for _ in 0..20 {
            let req = Request::builder()
                .uri("/ping")
                .header("x-api-key", "wrong")
                .body(Body::empty())
                .unwrap();
            let resp = app.clone().oneshot(req).await.unwrap();
            assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "禁用态应恒 401");
        }
        let req = Request::builder()
            .uri("/ping")
            .header("x-api-key", "secret-key")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "禁用态下合法 key 应 200");
    }
}
