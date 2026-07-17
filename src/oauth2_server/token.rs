//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! /oauth2/token 端点 — 支持 4 种 grant type + PKCE 强制。
//!
//! 处理 RFC 6749 §4 token 签发请求：
//! - `authorization_code`：授权码交换 access_token + refresh_token（强制 PKCE）
//! - `refresh_token`：刷新令牌
//! - `client_credentials`：服务间认证 token（无 user_id，无 refresh_token）
//! - `password`：用户名密码验证 + token（需注入 PasswordVerifier）

use crate::constants::{DaoKeyPrefix, TokenType};
use crate::dao::{BulwarkDao, MockDao};
use crate::error::{BulwarkError, BulwarkResult};
use crate::limiteron::BulwarkDaoDistributedLimiter;
// 导入 DistributedLimiter trait 以使用 get_count / incr_with_ttl 方法
use crate::oauth2_server::authorize::AuthorizeHandler;
use crate::oauth2_server::client::{GrantType, OAuth2Client, OAuth2ClientStore};
#[cfg(feature = "db-sqlite")]
use crate::protocol::jwt::refresh::RefreshTokenRotation;
use async_trait::async_trait;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use limiteron::limiters::DistributedLimiter;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration as StdDuration;

/// access_token 有效期（1 小时，RFC 6749 建议）。
const ACCESS_TOKEN_TTL_SECONDS: u64 = 3600;
/// refresh_token 有效期（30 天）。
const REFRESH_TOKEN_TTL_SECONDS: u64 = 30 * 24 * 3600;

/// /oauth2/token 请求参数。
#[derive(Debug, Clone, Deserialize)]
pub struct TokenRequest {
    /// grant_type（authorization_code / refresh_token / client_credentials / password）。
    pub grant_type: String,
    /// 客户端 ID。
    pub client_id: String,
    /// 客户端密钥。
    pub client_secret: String,
    /// 授权码（authorization_code grant type 必填）。
    pub code: Option<String>,
    /// 重定向 URI（authorization_code grant type 必填，需与 authorize 一致）。
    pub redirect_uri: Option<String>,
    /// PKCE code_verifier（authorization_code grant type 必填）。
    pub code_verifier: Option<String>,
    /// 刷新令牌（refresh_token grant type 必填）。
    pub refresh_token: Option<String>,
    /// 请求的 scope（空格分隔，可选）。
    pub scope: Option<String>,
    /// 用户名（password grant type 必填）。
    pub username: Option<String>,
    /// 密码（password grant type 必填）。
    pub password: Option<String>,
}

/// /oauth2/token 响应。
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct TokenResponse {
    /// 访问令牌。
    pub access_token: String,
    /// 令牌类型（固定 "Bearer"）。
    pub token_type: String,
    /// 过期时间（秒）。
    pub expires_in: u64,
    /// 刷新令牌（client_credentials 不返回）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// 实际授予的 scope。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
}

/// token 记录（存储在 DAO 中）。
///
/// v0.7.1 扩展 `issued_at` / `jti` / `username` 字段以支持 RFC 7662 token 内省完整字段。
/// 新字段使用 `#[serde(default)]` 保证旧 token 反序列化兼容。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenRecord {
    /// token 字符串。
    pub token: String,
    /// 关联的客户端 ID。
    pub client_id: String,
    /// 关联的用户 ID（client_credentials 为 None）。
    pub user_id: Option<i64>,
    /// 授权的 scope 列表。
    pub scopes: Vec<String>,
    /// token 类型（"access" 或 "refresh"）。
    pub token_type: String,
    /// 过期时间（UTC）。
    pub expires_at: DateTime<Utc>,
    /// 签发时间（UTC，RFC 7662 §2.3 `iat` 字段）。
    #[serde(default = "default_issued_at")]
    pub issued_at: DateTime<Utc>,
    /// token 唯一标识（RFC 7519 §4.1.7 `jti`，RFC 7662 内省返回）。
    #[serde(default)]
    pub jti: Option<String>,
    /// 用户名（password grant type 时有值，RFC 7662 §2.3 `username` 字段）。
    #[serde(default)]
    pub username: Option<String>,
}

/// `issued_at` 的 serde 默认值：Unix epoch（旧 token 无此字段时回退）。
fn default_issued_at() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(0, 0).unwrap_or_else(Utc::now)
}

/// 解析 HTTP Basic Authentication 头（RFC 6749 §2.3.1）。
///
/// # 参数
/// - `header`: `Authorization` 头值，期望格式 `"Basic <base64(client_id:client_secret)>"`。
///
/// # 返回
/// - `Some((client_id, client_secret))`: 解析成功。
/// - `None`: 头不是 Basic Auth、base64 解码失败、UTF-8 解码失败、或不含 `:` 分隔符。
///
/// # 安全
///
/// - 不限制 `client_id` / `client_secret` 中的字符（RFC 6749 §2.3.1 允许 percent-encoded）。
/// - 空客户端 ID（`":secret"`）返回 `Some(("", "secret"))`，由调用方决定是否拒绝。
/// - 空密钥（`"cid:"`）返回 `Some(("cid", ""))`，由 `verify_secret` 拒绝。
pub(crate) fn parse_basic_auth(header: &str) -> Option<(String, String)> {
    let encoded = header.strip_prefix("Basic ")?;
    // RFC 7617: HTTP Basic Auth 使用 STANDARD base64（含 +/= 和 padding）。
    // RFC 6749 §2.3.1: client_id 和 client_secret 在编码前需 percent-encoding，
    // 但大多数客户端直接 base64 编码。这里接受 STANDARD base64 输入。
    let decoded = STANDARD.decode(encoded.trim()).ok()?;
    let decoded_str = String::from_utf8(decoded).ok()?;
    let (client_id, client_secret) = decoded_str.split_once(':')?;
    Some((client_id.to_string(), client_secret.to_string()))
}

/// password grant type 验证器 trait.
///
/// 业务方实现此 trait 注入到 `TokenHandler`，用于 password grant type 的用户名密码验证。
/// 未注入时 password grant type 返回 `unauthorized_grant_type` 错误。
#[async_trait]
pub trait PasswordVerifier: Send + Sync {
    /// 验证用户名密码，返回用户 ID。
    ///
    /// # 返回
    /// - `Ok(Some(user_id))`：验证成功
    /// - `Ok(None)`：用户名或密码错误
    /// - `Err`：内部错误
    async fn verify(&self, username: &str, password: &str) -> BulwarkResult<Option<i64>>;
}

/// Password grant 失败计数器 — 防 brute-force。
///
/// 按 username 维度跟踪窗口内失败次数，超阈值后锁定至窗口过期。
/// 验证成功后重置计数。
///
/// # 设计
///
/// - **per-username 维度**：与 `crate::server::middleware::RateLimitState`（per-IP）不同 ——
///   防御多 IP 撞库同一账户的暴力破解
/// - **滑动窗口**：`window_seconds` 内累计失败次数达 `max_attempts` 即锁定至窗口过期
/// - **limiteron 委托**：通过 `BulwarkDaoDistributedLimiter` + `MockDao` 实现原子计数 + TTL，
///   不再手写 `Mutex<HashMap>` + 滑动窗口算法（limiteron 适配器统一抽象）
/// - **进程内原子**：`MockDao::incr` 用 `parking_lot::Mutex` 保护，单进程内原子
/// - **TTL 自动重置**：窗口过期由 `MockDao` 的 TTL 语义保证（首次 `incr` 后过期会重新初始化），
///   无需手动时间窗口判断
///
/// # 与 RateLimitState 的区别
///
/// `RateLimitState` 是 HTTP 中间件级别的 per-IP 令牌桶，限制每秒请求数；
/// 本结构是 OAuth2 handler 级别的 per-username 失败计数器，限制窗口内失败次数。
/// 两者互补：IP 限速防御分布式扫描，账户锁定防御定向撞库。
///
/// # Key 格式
///
/// `rate_limit:pw:{username}` — 通过 `MockDao::keys("rate_limit:pw:*")` 可扫描全部 entry。
pub struct PasswordRateLimiter {
    /// 限流器（基于 `BulwarkDaoDistributedLimiter`，内部用 `MockDao` 进程内原子）
    limiter: BulwarkDaoDistributedLimiter,
    /// 保留 `MockDao` 引用以支持 `entry_count()` 测试辅助方法
    dao: Arc<MockDao>,
    /// 窗口内允许的最大失败次数（达此值后锁定至窗口过期）
    max_attempts: u32,
    /// 滑动窗口时长（秒）
    window_seconds: u64,
}

impl PasswordRateLimiter {
    /// 创建失败计数器。
    ///
    /// 内部创建 `MockDao` + `BulwarkDaoDistributedLimiter`，进程内原子计数。
    ///
    /// # 参数
    /// - `max_attempts`：窗口内允许的最大失败次数（达此值后锁定至窗口过期）
    /// - `window_seconds`：滑动窗口时长（秒），窗口过期后计数自动重置
    pub fn new(max_attempts: u32, window_seconds: u64) -> Self {
        let dao = Arc::new(MockDao::new());
        let limiter = BulwarkDaoDistributedLimiter::new(dao.clone());
        Self {
            limiter,
            dao,
            // 至少 1，避免 max_attempts=0 导致所有请求被锁
            max_attempts: max_attempts.max(1),
            window_seconds,
        }
    }

    /// 检查 username 是否允许尝试（未锁定）。
    ///
    /// 返回 `true` 表示允许尝试，`false` 表示已被锁定（窗口内失败次数达上限）。
    /// 窗口过期时由 `MockDao` 的 TTL 语义自动重置（首次 `incr` 后过期会重新初始化）。
    ///
    /// # Fail-Open 策略
    ///
    /// 当 `limiteron::get_count` 出错（如 DAO 通信失败 / 计数器值损坏）时返回 `true`，
    /// 与原 `Mutex` 实现不失败的语义一致。错误经 `tracing::warn` 记录后吞掉，
    /// 避免单次 DAO 故障导致用户被错误锁定。
    pub async fn check(&self, username: &str) -> bool {
        let key = format!("rate_limit:pw:{}", username);
        match self.limiter.get_count(&key).await {
            Ok(count) => count < self.max_attempts as u64,
            Err(e) => {
                tracing::warn!("PasswordRateLimiter::check get_count failed: {}", e);
                true
            },
        }
    }

    /// 记录一次失败。
    ///
    /// 通过 `limiteron::incr_with_ttl` 原子递增计数器。
    /// - 首次失败：设置 count=1 + TTL=`window_seconds`（窗口起始时间）
    /// - 后续失败：仅递增 count，不重置 TTL（保持窗口起点）
    /// - 窗口过期：由 `MockDao` 的 TTL 语义自动重置（首次 `incr` 重新初始化）
    pub async fn record_failure(&self, username: &str) {
        let key = format!("rate_limit:pw:{}", username);
        let ttl = StdDuration::from_secs(self.window_seconds);
        if let Err(e) = self.limiter.incr_with_ttl(&key, 1, ttl).await {
            tracing::warn!(
                "PasswordRateLimiter::record_failure incr_with_ttl failed: {}",
                e
            );
        }
    }

    /// 验证成功后重置 username 的计数。
    pub async fn reset(&self, username: &str) {
        let key = format!("rate_limit:pw:{}", username);
        if let Err(e) = self.limiter.reset(&key).await {
            tracing::warn!("PasswordRateLimiter::reset failed: {}", e);
        }
    }

    /// 当前未过期 entry 数量（测试/运维用）。
    ///
    /// 通过 `MockDao::keys("rate_limit:pw:*")` 扫描，返回未过期的 entry 数。
    /// 已过期的 key 不会计入（与 `MockDao::keys` 语义一致）。
    pub async fn entry_count(&self) -> usize {
        self.dao
            .keys("rate_limit:pw:*")
            .await
            .map(|v| v.len())
            .unwrap_or(0)
    }
}

/// /token 端点速率限制器 — 防暴力枚举 `client_secret` / 密码。
///
/// 两层独立限速：
/// - **per-client_id**：限制每个 client 的 `/token` 请求速率（默认 10 req/s），
///   防御针对单一 client 的暴力枚举 `client_secret`
/// - **per-username**：限制 password grant 中每个 username 的请求速率（默认 5 req/min），
///   与 `PasswordRateLimiter`（失败计数器）互补 —— 后者限制失败次数，本结构限制请求次数
///
/// # 设计
///
/// - **limiteron 委托**：通过 `BulwarkDaoDistributedLimiter` + `MockDao` 实现原子计数 + TTL，
///   `atomic_check_and_incr` 在 Redis 后端走 Lua 脚本原子 check-and-increment，
///   `MockDao` 后端退化为 `incr` + 阈值判断（单进程原子）
/// - **Fail-Open**：DAO 错误时返回 `true`（放行），避免单次故障导致全部 client 被锁
/// - **独立于 PasswordRateLimiter**：后者是失败计数器（账户锁定），
///   本结构是请求速率限制（QPS 限制），两者互补
///
/// # 与 PasswordRateLimiter 的区别
///
/// | 维度 | PasswordRateLimiter | TokenRateLimiter |
/// |------|---------------------|------------------|
/// | 限速对象 | username | client_id + username |
/// | 计数事件 | 验证失败 | 每次请求 |
/// | 重置条件 | 验证成功 | 窗口过期 |
/// | 防御场景 | 撞库（同账户多 IP） | 暴力枚举 / QPS 滥用 |
///
/// # Key 格式
///
/// - `rate_limit:token:client:{client_id}` — per-client_id 计数
/// - `rate_limit:token:user:{username}` — per-username 计数
pub struct TokenRateLimiter {
    /// 限流器（基于 `BulwarkDaoDistributedLimiter`，内部用 `MockDao` 进程内原子）
    limiter: BulwarkDaoDistributedLimiter,
    /// per-client_id 窗口内最大请求数
    client_max: u64,
    /// per-client_id 窗口时长（秒）
    client_window_secs: u64,
    /// per-username 窗口内最大请求数
    username_max: u64,
    /// per-username 窗口时长（秒）
    username_window_secs: u64,
}

impl TokenRateLimiter {
    /// 创建默认配置的速率限制器（10 req/s per-client_id + 5 req/min per-username）。
    ///
    /// 默认值依据：
    /// - client_id 10 req/s：覆盖正常客户端的 token 刷新 + 短时重试需求
    /// - username 5 req/min：限制单账户密码暴力尝试，与 `PasswordRateLimiter` 失败计数器互补
    pub fn new() -> Self {
        Self::with_limits(10, 1, 5, 60)
    }

    /// 自定义限速参数（测试 / 运维调优用）。
    ///
    /// 所有参数会被 clamp 到至少 1，避免 `max=0` 导致所有请求被拒。
    pub fn with_limits(
        client_max: u64,
        client_window_secs: u64,
        username_max: u64,
        username_window_secs: u64,
    ) -> Self {
        let dao = Arc::new(MockDao::new());
        let limiter = BulwarkDaoDistributedLimiter::new(dao);
        Self {
            limiter,
            // 至少 1，避免 max=0 导致所有请求被拒
            client_max: client_max.max(1),
            client_window_secs: client_window_secs.max(1),
            username_max: username_max.max(1),
            username_window_secs: username_window_secs.max(1),
        }
    }

    /// 检查 client_id 是否允许请求（未超 per-client_id 速率）。
    ///
    /// 调用即计数（`atomic_check_and_incr` 原子 check-and-increment）：
    /// - 返回 `true`：本次请求计入窗口，允许继续
    /// - 返回 `false`：已达窗口上限，拒绝
    ///
    /// # Fail-Open
    ///
    /// DAO 错误时返回 `true`（放行），与 `PasswordRateLimiter::check` 语义一致 ——
    /// 避免单次 DAO 故障导致全部 client 被锁，可用性优先于限速准确性。
    pub async fn check_client(&self, client_id: &str) -> bool {
        let key = format!("rate_limit:token:client:{}", client_id);
        let ttl = StdDuration::from_secs(self.client_window_secs);
        match self
            .limiter
            .atomic_check_and_incr(&key, self.client_max, ttl)
            .await
        {
            Ok(allowed) => allowed,
            Err(e) => {
                tracing::warn!("TokenRateLimiter::check_client failed: {}", e);
                true
            },
        }
    }

    /// 检查 username 是否允许请求（未超 per-username 速率）。
    ///
    /// 调用即计数（`atomic_check_and_incr` 原子 check-and-increment）。
    /// 仅 password grant type 调用，限制单账户的密码尝试 QPS。
    ///
    /// # Fail-Open
    ///
    /// DAO 错误时返回 `true`（放行）。
    pub async fn check_username(&self, username: &str) -> bool {
        let key = format!("rate_limit:token:user:{}", username);
        let ttl = StdDuration::from_secs(self.username_window_secs);
        match self
            .limiter
            .atomic_check_and_incr(&key, self.username_max, ttl)
            .await
        {
            Ok(allowed) => allowed,
            Err(e) => {
                tracing::warn!("TokenRateLimiter::check_username failed: {}", e);
                true
            },
        }
    }
}

impl Default for TokenRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

/// /oauth2/token handler，处理 4 种 grant type。
///
/// # Refresh Token 统一（v0.7.1）
///
/// 启用 `db-sqlite` feature 并通过 `with_refresh_rotation` 注入
/// `RefreshTokenRotation` 后，refresh_token 走统一轮换路径：
/// - `issue_tokens` 委托 `RefreshTokenRotation::issue`（hash chain + INSERT）
/// - `handle_refresh_token` 委托 `RefreshTokenRotation::rotate`（reuse detection + 链式撤销）
///
/// 未注入时退化为 DAO 键值存储（`DaoKeyPrefix::OAuth2RefreshToken`），
/// 无 reuse detection，文档明确标注安全风险。
pub struct TokenHandler {
    store: Arc<dyn OAuth2ClientStore>,
    dao: Arc<dyn BulwarkDao>,
    authorize_handler: Arc<AuthorizeHandler>,
    password_verifier: Option<Arc<dyn PasswordVerifier>>,
    /// Password grant 失败计数器（防 brute-force）。
    /// 为 None 时不启用账户锁定（向后兼容，但不推荐生产使用）。
    password_rate_limiter: Option<Arc<PasswordRateLimiter>>,
    /// /token 端点速率限制器（per-client_id + per-username QPS 限制）。
    /// 为 None 时不启用请求速率限制（向后兼容，但不推荐生产使用）。
    token_rate_limiter: Option<Arc<TokenRateLimiter>>,
    /// 统一的 refresh token 轮换服务（db-sqlite feature 启用时可用）。
    /// 为 None 时退化为 DAO 键值存储（无 reuse detection）。
    #[cfg(feature = "db-sqlite")]
    refresh_rotation: Option<Arc<RefreshTokenRotation>>,
}

impl TokenHandler {
    /// 创建 handler。
    pub fn new(
        store: Arc<dyn OAuth2ClientStore>,
        dao: Arc<dyn BulwarkDao>,
        authorize_handler: Arc<AuthorizeHandler>,
    ) -> Self {
        Self {
            store,
            dao,
            authorize_handler,
            password_verifier: None,
            password_rate_limiter: None,
            token_rate_limiter: None,
            #[cfg(feature = "db-sqlite")]
            refresh_rotation: None,
        }
    }

    /// 注入 password grant type 验证器。
    pub fn with_password_verifier(mut self, verifier: Arc<dyn PasswordVerifier>) -> Self {
        self.password_verifier = Some(verifier);
        self
    }

    /// 注入 PasswordRateLimiter 启用 password grant 失败计数 + 账户锁定。
    ///
    /// 未注入时 password grant 无账户级速率限制（向后兼容，但不推荐生产使用）。
    pub fn with_password_rate_limiter(mut self, limiter: Arc<PasswordRateLimiter>) -> Self {
        self.password_rate_limiter = Some(limiter);
        self
    }

    /// 注入 `TokenRateLimiter` 启用 `/token` 端点速率限制（v0.7.1 B5）。
    ///
    /// 注入后：
    /// - `handle_with_authorization` 在 client 认证前按 `client_id` 限速（默认 10 req/s）
    /// - `handle_password` 在账户锁定检查前按 `username` 限速（默认 5 req/min）
    ///
    /// 未注入时 `/token` 端点无 QPS 限制（向后兼容，但不推荐生产使用 ——
    /// 暴力枚举 `client_secret` / 密码无速率约束）。
    pub fn with_token_rate_limiter(mut self, limiter: Arc<TokenRateLimiter>) -> Self {
        self.token_rate_limiter = Some(limiter);
        self
    }

    /// 注入 RefreshTokenRotation 启用统一轮换 + reuse detection（v0.7.1）。
    ///
    /// 仅在 `db-sqlite` feature 启用时可用。注入后：
    /// - `issue_tokens` 在 `with_refresh=true` 时委托 `rotation.issue()`
    /// - `handle_refresh_token` 委托 `rotation.rotate()` 获得轮换 + hash chain
    ///
    /// 未注入时退化为 DAO 路径（`DaoKeyPrefix::OAuth2RefreshToken`，无 reuse detection）。
    #[cfg(feature = "db-sqlite")]
    pub fn with_refresh_rotation(mut self, rotation: Arc<RefreshTokenRotation>) -> Self {
        self.refresh_rotation = Some(rotation);
        self
    }

    /// 处理 token 请求。
    pub async fn handle(&self, req: &TokenRequest) -> BulwarkResult<TokenResponse> {
        self.handle_with_authorization(req, None).await
    }

    /// 处理 token 请求，支持 HTTP Basic Auth 客户端认证（RFC 6749 §2.3.1）。
    ///
    /// # 参数
    /// - `req`: token 请求参数。
    /// - `authorization`: 可选的 `Authorization` 头值。若为 `Some("Basic ...")`，
    ///   优先从头中解码 `client_id:client_secret`，否则回退到 `req.client_id` /
    ///   `req.client_secret`（body 参数）。
    ///
    /// # RFC 6749 §2.3.1
    ///
    /// 客户端可通过 HTTP Basic Auth 传递凭证，避免凭证出现在 URL 或 body 中。
    /// 此方法遵循 RFC：优先使用 Basic Auth 头，body 参数作为回退。
    pub async fn handle_with_authorization(
        &self,
        req: &TokenRequest,
        authorization: Option<&str>,
    ) -> BulwarkResult<TokenResponse> {
        // 0. per-client_id 速率限制（在 client 认证前，防暴力枚举 client_secret）
        //
        // 从 Basic Auth 头或 body 提取 client_id 用于限速 —— 即使凭证错误也计入，
        // 防御攻击者用错误凭证暴力枚举 client_secret（与 PasswordRateLimiter 在
        // 密码验证前 check 的设计一致）。
        if let Some(limiter) = &self.token_rate_limiter {
            let client_id = authorization
                .and_then(parse_basic_auth)
                .map(|(id, _)| id)
                .unwrap_or_else(|| req.client_id.clone());
            if !client_id.is_empty() && !limiter.check_client(&client_id).await {
                return Err(BulwarkError::OAuth2(
                    "rate_limited: 客户端请求过于频繁，请稍后再试".into(),
                ));
            }
        }

        // 1. 验证客户端凭证（优先 Basic Auth）
        let client = self
            .authenticate_client_with_authorization(
                authorization,
                &req.client_id,
                &req.client_secret,
            )
            .await?;

        // 2. 根据 grant_type 分发（使用 GrantType 枚举，避免硬编码字符串）
        let grant_type: GrantType = req.grant_type.parse()?;
        match grant_type {
            GrantType::AuthorizationCode => self.handle_authorization_code(&client, req).await,
            GrantType::RefreshToken => self.handle_refresh_token(&client, req).await,
            GrantType::ClientCredentials => self.handle_client_credentials(&client, req).await,
            GrantType::Password => self.handle_password(&client, req).await,
        }
    }

    /// 验证客户端凭证，支持 HTTP Basic Auth。
    ///
    /// 优先解析 `Authorization: Basic` 头；若未提供或解析失败，回退到 body 参数。
    /// 两种来源均未提供 client_id 时返回 `invalid_client`。
    async fn authenticate_client_with_authorization(
        &self,
        authorization: Option<&str>,
        body_client_id: &str,
        body_client_secret: &str,
    ) -> BulwarkResult<OAuth2Client> {
        // 优先解析 Authorization: Basic 头（RFC 6749 §2.3.1）
        let (client_id, client_secret) = match authorization.and_then(parse_basic_auth) {
            Some((id, secret)) => (id, secret),
            None => (body_client_id.to_string(), body_client_secret.to_string()),
        };

        if client_id.is_empty() {
            return Err(BulwarkError::OAuth2(
                "invalid_client: client_id 缺失（既未在 Authorization 头也未在 body 中提供）"
                    .into(),
            ));
        }

        let client =
            self.store.get(&client_id).await?.ok_or_else(|| {
                BulwarkError::OAuth2(format!("invalid_client: {client_id} 不存在"))
            })?;
        if !client.verify_secret(&client_secret)? {
            return Err(BulwarkError::OAuth2(
                "invalid_client: client_secret 不匹配".into(),
            ));
        }
        Ok(client)
    }

    /// authorization_code grant type：授权码交换 token。
    async fn handle_authorization_code(
        &self,
        client: &OAuth2Client,
        req: &TokenRequest,
    ) -> BulwarkResult<TokenResponse> {
        if !client.allows_grant_type(&GrantType::AuthorizationCode) {
            return Err(BulwarkError::OAuth2(
                "unauthorized_client: 客户端未授权 authorization_code grant type".into(),
            ));
        }

        let code = req
            .code
            .as_ref()
            .ok_or_else(|| BulwarkError::OAuth2("invalid_request: code 参数缺失".into()))?;
        let code_verifier = req.code_verifier.as_ref().ok_or_else(|| {
            BulwarkError::OAuth2("invalid_request: code_verifier 参数缺失（PKCE 强制）".into())
        })?;
        let redirect_uri = req
            .redirect_uri
            .as_ref()
            .ok_or_else(|| BulwarkError::OAuth2("invalid_request: redirect_uri 参数缺失".into()))?;

        // 消费授权码（一次性）
        let auth_code = self
            .authorize_handler
            .consume_code(code)
            .await?
            .ok_or_else(|| BulwarkError::OAuth2("invalid_grant: 授权码无效或已过期".into()))?;

        // 校验 client_id 一致性
        if auth_code.client_id != client.client_id {
            return Err(BulwarkError::OAuth2(
                "invalid_grant: 授权码与 client_id 不匹配".into(),
            ));
        }

        // 校验 redirect_uri 一致性
        if auth_code.redirect_uri != *redirect_uri {
            return Err(BulwarkError::OAuth2(
                "invalid_grant: redirect_uri 与授权时不一致".into(),
            ));
        }

        // PKCE 验证
        if !crate::oauth2_server::authorize::verify_pkce(code_verifier, &auth_code.code_challenge)?
        {
            return Err(BulwarkError::OAuth2(
                "invalid_grant: PKCE code_verifier 校验失败".into(),
            ));
        }

        // 签发 token
        let scopes = auth_code.scopes.clone();
        // 校验授权码中的 scope 是否在客户端 allowed_scopes 内（纵深防御）
        client.validate_scopes(&scopes)?;
        let user_id = auth_code.user_id;
        self.issue_tokens(
            &client.client_id,
            Some(user_id),
            &scopes,
            true, // 返回 refresh_token
            None, // authorization_code grant type 不携带 username
        )
        .await
    }

    /// refresh_token grant type：刷新令牌。
    ///
    /// # Refresh Token 统一（v0.7.1）
    ///
    /// 启用 `db-sqlite` 且注入 `RefreshTokenRotation` 时，走统一轮换路径：
    /// - 调用 `rotation.rotate()` 获得 hash chain + reuse detection + 链式撤销
    /// - 返回新 refresh_token（轮换，旧 token revoked=1）
    ///
    /// 未注入时退化为 DAO 路径（轮换 + 删除旧 token）：
    /// - 查找 `DaoKeyPrefix::OAuth2RefreshToken` 记录
    /// - 校验 client_id 一致性
    /// - 删除旧 refresh_token（防止重放）
    /// - 签发新 access_token + 新 refresh_token（with_refresh=true 轮换）
    /// - 旧 token 删除后再次使用 → `invalid_grant`（隐式 reuse detection）
    async fn handle_refresh_token(
        &self,
        client: &OAuth2Client,
        req: &TokenRequest,
    ) -> BulwarkResult<TokenResponse> {
        if !client.allows_grant_type(&GrantType::RefreshToken) {
            return Err(BulwarkError::OAuth2(
                "unauthorized_client: 客户端未授权 refresh_token grant type".into(),
            ));
        }

        let refresh_token = req.refresh_token.as_ref().ok_or_else(|| {
            BulwarkError::OAuth2("invalid_request: refresh_token 参数缺失".into())
        })?;

        // v0.7.1 统一路径：RefreshTokenRotation.rotate（reuse detection + hash chain）
        #[cfg(feature = "db-sqlite")]
        {
            if let Some(rotation) = &self.refresh_rotation {
                // rotate 直接处理 reuse detection + 链式撤销：
                // - reuse → TokenRevoked（透传）
                // - not found → InvalidToken（映射为 OAuth2 invalid_grant）
                let (new_access, new_refresh) = match rotation.rotate(refresh_token).await {
                    Ok(t) => t,
                    Err(BulwarkError::InvalidToken(_)) => {
                        return Err(BulwarkError::OAuth2(
                            "invalid_grant: refresh_token 无效或已过期".into(),
                        ));
                    },
                    Err(e) => return Err(e),
                };
                // validate 新 token 获取 scopes + client_id 供响应
                let record = rotation.validate(&new_refresh).await?.ok_or_else(|| {
                    BulwarkError::Internal("rotate 后新 refresh_token validate 失败".into())
                })?;
                // 校验 client_id 一致性
                let record_client_id = record.client_id.as_deref().unwrap_or("");
                if record_client_id != client.client_id {
                    return Err(BulwarkError::OAuth2(
                        "invalid_grant: refresh_token 与 client_id 不匹配".into(),
                    ));
                }
                let scopes: Vec<String> = record
                    .scopes
                    .as_ref()
                    .map(|s| s.split_whitespace().map(|x| x.to_string()).collect())
                    .unwrap_or_default();
                let scope_str = if scopes.is_empty() {
                    None
                } else {
                    Some(scopes.join(" "))
                };
                return Ok(TokenResponse {
                    access_token: new_access,
                    token_type: TokenType::Bearer.to_string(),
                    expires_in: ACCESS_TOKEN_TTL_SECONDS,
                    refresh_token: Some(new_refresh),
                    scope: scope_str,
                });
            }
        }

        // DAO fallback 路径 — refresh_token 轮换 + 删除旧 token
        //
        // 删除旧 refresh_token + 签发新 refresh_token（轮换）
        // 旧 token 删除后，再次使用会因 dao.get 返回 None 而返回 invalid_grant
        // （隐式 reuse detection：旧 token 无法重用）
        #[allow(deprecated)]
        let key = DaoKeyPrefix::OAuth2RefreshToken.build_key(refresh_token);
        let json = self.dao.get(&key).await?.ok_or_else(|| {
            BulwarkError::OAuth2("invalid_grant: refresh_token 无效或已过期".into())
        })?;
        let record: TokenRecord = serde_json::from_str(&json)
            .map_err(|e| BulwarkError::Internal(format!("TokenRecord 反序列化失败: {e}")))?;

        // 校验 client_id 一致性
        if record.client_id != client.client_id {
            return Err(BulwarkError::OAuth2(
                "invalid_grant: refresh_token 与 client_id 不匹配".into(),
            ));
        }

        // 删除旧 refresh_token（轮换核心步骤）
        // 删除后旧 token 无法再次使用，防止旧 token 泄露后被重放
        self.dao.delete(&key).await?;

        // 签发新 access_token + 新 refresh_token（with_refresh=true 轮换）
        let user_id = record.user_id;
        let scopes = record.scopes.clone();
        let username = record.username.clone();
        self.issue_tokens(
            &client.client_id,
            user_id,
            &scopes,
            true, // 轮换 — 签发新 refresh_token
            username.as_deref(),
        )
        .await
    }

    /// client_credentials grant type：服务间认证 token。
    async fn handle_client_credentials(
        &self,
        client: &OAuth2Client,
        req: &TokenRequest,
    ) -> BulwarkResult<TokenResponse> {
        if !client.allows_grant_type(&GrantType::ClientCredentials) {
            return Err(BulwarkError::OAuth2(
                "unauthorized_client: 客户端未授权 client_credentials grant type".into(),
            ));
        }

        let scopes: Vec<String> = req
            .scope
            .as_ref()
            .map(|s| s.split_whitespace().map(|x| x.to_string()).collect())
            .unwrap_or_default();

        // 校验请求的 scope 是否在客户端 allowed_scopes 内
        client.validate_scopes(&scopes)?;

        // 无 user_id，无 refresh_token
        self.issue_tokens(&client.client_id, None, &scopes, false, None)
            .await
    }

    /// password grant type：用户名密码验证 + token。
    async fn handle_password(
        &self,
        client: &OAuth2Client,
        req: &TokenRequest,
    ) -> BulwarkResult<TokenResponse> {
        if !client.allows_grant_type(&GrantType::Password) {
            return Err(BulwarkError::OAuth2(
                "unauthorized_client: 客户端未授权 password grant type".into(),
            ));
        }

        let verifier = self.password_verifier.as_ref().ok_or_else(|| {
            BulwarkError::OAuth2(
                "unauthorized_grant_type: password grant type 未配置 PasswordVerifier".into(),
            )
        })?;

        let username = req
            .username
            .as_ref()
            .ok_or_else(|| BulwarkError::OAuth2("invalid_request: username 参数缺失".into()))?;
        let password = req
            .password
            .as_ref()
            .ok_or_else(|| BulwarkError::OAuth2("invalid_request: password 参数缺失".into()))?;

        // per-username QPS 速率限制（在账户锁定检查前，防暴力撞库）
        //
        // 与 PasswordRateLimiter（失败计数器）互补 —— 后者限制窗口内失败次数，
        // 本结构限制窗口内请求 QPS，两者叠加形成纵深防御。
        if let Some(limiter) = &self.token_rate_limiter {
            if !limiter.check_username(username).await {
                return Err(BulwarkError::OAuth2(
                    "rate_limited: 用户请求过于频繁，请稍后再试".into(),
                ));
            }
        }

        // 验证密码前检查账户锁定状态（防 brute-force）
        if let Some(limiter) = &self.password_rate_limiter {
            if !limiter.check(username).await {
                return Err(BulwarkError::OAuth2(
                    "rate_limited: 账户已被临时锁定，请稍后再试".into(),
                ));
            }
        }

        let user_id = match verifier.verify(username, password).await? {
            Some(uid) => uid,
            None => {
                // 验证失败后增加失败计数
                if let Some(limiter) = &self.password_rate_limiter {
                    limiter.record_failure(username).await;
                }
                return Err(BulwarkError::OAuth2(
                    "invalid_grant: 用户名或密码错误".into(),
                ));
            },
        };

        // 验证成功后重置失败计数
        if let Some(limiter) = &self.password_rate_limiter {
            limiter.reset(username).await;
        }

        let scopes: Vec<String> = req
            .scope
            .as_ref()
            .map(|s| s.split_whitespace().map(|x| x.to_string()).collect())
            .unwrap_or_default();

        // 校验请求的 scope 是否在客户端 allowed_scopes 内
        client.validate_scopes(&scopes)?;

        self.issue_tokens(
            &client.client_id,
            Some(user_id),
            &scopes,
            true,
            Some(username.as_str()),
        )
        .await
    }

    /// 签发 token 并存储。
    ///
    /// `username` 仅 password grant type 有值（RFC 7662 §2.3 内省返回）。
    ///
    /// # Refresh Token 统一（v0.7.1）
    ///
    /// `with_refresh=true` 时：
    /// - 启用 `db-sqlite` 且注入 `RefreshTokenRotation` → 委托 `rotation.issue()`
    /// - 否则 → DAO 路径（`DaoKeyPrefix::OAuth2RefreshToken`，无 reuse detection）
    async fn issue_tokens(
        &self,
        client_id: &str,
        user_id: Option<i64>,
        scopes: &[String],
        with_refresh: bool,
        username: Option<&str>,
    ) -> BulwarkResult<TokenResponse> {
        let access_token = generate_token();
        let now = Utc::now();
        let at_expires_at = now + Duration::seconds(ACCESS_TOKEN_TTL_SECONDS as i64);
        // RFC 7519 §4.1.7 jti：保证同一秒内签发的 token 唯一
        let at_jti = uuid::Uuid::new_v4().to_string();

        let at_record = TokenRecord {
            token: access_token.clone(),
            client_id: client_id.to_string(),
            user_id,
            scopes: scopes.to_vec(),
            token_type: TokenType::Access.to_string(),
            expires_at: at_expires_at,
            issued_at: now,
            jti: Some(at_jti),
            username: username.map(|s| s.to_string()),
        };

        let at_key = DaoKeyPrefix::OAuth2AccessToken.build_key(&access_token);
        let at_json = serde_json::to_string(&at_record)
            .map_err(|e| BulwarkError::Internal(format!("TokenRecord 序列化失败: {e}")))?;
        self.dao
            .set(&at_key, &at_json, ACCESS_TOKEN_TTL_SECONDS)
            .await?;

        let refresh_token = if with_refresh {
            // v0.7.1 统一路径：RefreshTokenRotation.issue（hash chain + INSERT）
            #[cfg(feature = "db-sqlite")]
            {
                if let Some(rotation) = &self.refresh_rotation {
                    let login_id = user_id.unwrap_or(0);
                    let rt = rotation
                        .issue(
                            client_id,
                            user_id,
                            scopes,
                            username,
                            login_id,
                            0, // tenant_id: 默认租户
                            REFRESH_TOKEN_TTL_SECONDS as i64,
                        )
                        .await?;
                    Some(rt)
                } else {
                    // Fallback: DAO 存储（无 reuse detection）
                    self.issue_refresh_via_dao(client_id, user_id, scopes, username, now)
                        .await?
                }
            }
            #[cfg(not(feature = "db-sqlite"))]
            {
                self.issue_refresh_via_dao(client_id, user_id, scopes, username, now)
                    .await?
            }
        } else {
            None
        };

        let scope_str = if scopes.is_empty() {
            None
        } else {
            Some(scopes.join(" "))
        };

        Ok(TokenResponse {
            access_token,
            token_type: TokenType::Bearer.to_string(),
            expires_in: ACCESS_TOKEN_TTL_SECONDS,
            refresh_token,
            scope: scope_str,
        })
    }

    /// DAO fallback 路径签发 refresh_token（无 reuse detection）。
    ///
    /// 当 `RefreshTokenRotation` 未注入或 `db-sqlite` feature 未启用时使用。
    /// refresh_token 存储在 DAO 中（`DaoKeyPrefix::OAuth2RefreshToken`），
    /// 无 hash chain、无 reuse detection、无链式撤销。
    async fn issue_refresh_via_dao(
        &self,
        client_id: &str,
        user_id: Option<i64>,
        scopes: &[String],
        username: Option<&str>,
        now: DateTime<Utc>,
    ) -> BulwarkResult<Option<String>> {
        let rt = generate_token();
        let rt_expires_at = now + Duration::seconds(REFRESH_TOKEN_TTL_SECONDS as i64);
        let rt_jti = uuid::Uuid::new_v4().to_string();
        let rt_record = TokenRecord {
            token: rt.clone(),
            client_id: client_id.to_string(),
            user_id,
            scopes: scopes.to_vec(),
            token_type: TokenType::Refresh.to_string(),
            expires_at: rt_expires_at,
            issued_at: now,
            jti: Some(rt_jti),
            username: username.map(|s| s.to_string()),
        };
        #[allow(deprecated)]
        let rt_key = DaoKeyPrefix::OAuth2RefreshToken.build_key(&rt);
        let rt_json = serde_json::to_string(&rt_record)
            .map_err(|e| BulwarkError::Internal(format!("TokenRecord 序列化失败: {e}")))?;
        self.dao
            .set(&rt_key, &rt_json, REFRESH_TOKEN_TTL_SECONDS)
            .await?;
        Ok(Some(rt))
    }

    /// 查找 access_token 记录（供 introspect 端点使用）。
    pub async fn get_access_token_record(&self, token: &str) -> BulwarkResult<Option<TokenRecord>> {
        let key = DaoKeyPrefix::OAuth2AccessToken.build_key(token);
        let json = self.dao.get(&key).await?;
        match json {
            Some(json) => {
                let record: TokenRecord = serde_json::from_str(&json).map_err(|e| {
                    BulwarkError::Internal(format!("TokenRecord 反序列化失败: {e}"))
                })?;
                Ok(Some(record))
            },
            None => Ok(None),
        }
    }

    /// 撤销 token（供 revoke 端点使用）。
    pub async fn revoke_token(&self, token: &str) -> BulwarkResult<()> {
        // 尝试删除 access_token
        let at_key = DaoKeyPrefix::OAuth2AccessToken.build_key(token);
        self.dao.delete(&at_key).await?;
        // 尝试删除 refresh_token（同一 token 值不会同时是两种类型）
        #[allow(deprecated)]
        let rt_key = DaoKeyPrefix::OAuth2RefreshToken.build_key(token);
        self.dao.delete(&rt_key).await?;
        Ok(())
    }
}

/// 生成 token（32 字节随机数 → BASE64URL 编码）。
fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::MockDao;
    use crate::oauth2_server::authorize::AuthorizeHandler;
    use crate::oauth2_server::client::DaoOAuth2ClientStore;

    /// 测试用 PasswordVerifier。
    struct TestPasswordVerifier;
    #[async_trait]
    impl PasswordVerifier for TestPasswordVerifier {
        async fn verify(&self, username: &str, password: &str) -> BulwarkResult<Option<i64>> {
            if username == "alice" && password == "wonderland" {
                Ok(Some(5001))
            } else {
                Ok(None)
            }
        }
    }

    /// 创建测试用 handler（含 password verifier）。
    fn make_handler() -> (TokenHandler, Arc<MockDao>) {
        let dao = Arc::new(MockDao::new());
        let store = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
        let authorize_handler = Arc::new(AuthorizeHandler::new(
            store.clone(),
            dao.clone(),
            "https://auth.example.com/login".into(),
        ));
        let handler = TokenHandler::new(store, dao.clone(), authorize_handler)
            .with_password_verifier(Arc::new(TestPasswordVerifier));
        (handler, dao)
    }

    /// 创建测试用客户端（支持所有 grant type）。
    fn make_full_client(id: &str) -> OAuth2Client {
        OAuth2Client::new(
            id,
            "secret-123",
            vec!["https://app.example.com/cb".into()],
            vec![
                GrantType::AuthorizationCode,
                GrantType::RefreshToken,
                GrantType::ClientCredentials,
                GrantType::Password,
            ],
            vec!["read".into(), "write".into()],
        )
        .unwrap()
    }

    /// 通过 authorize 端点获取授权码。
    async fn get_auth_code(handler: &TokenHandler, client_id: &str, verifier: &str) -> String {
        let challenge = crate::oauth2_server::authorize::generate_code_challenge(verifier);
        let req = crate::oauth2_server::authorize::AuthorizeRequest {
            response_type: "code".into(),
            client_id: client_id.into(),
            redirect_uri: "https://app.example.com/cb".into(),
            scope: Some("read".into()),
            state: Some("xyz".into()),
            code_challenge: challenge,
            code_challenge_method: "S256".into(),
        };
        let resp = handler
            .authorize_handler
            .authorize(&req, Some(1001))
            .await
            .unwrap();
        match resp {
            crate::oauth2_server::authorize::AuthorizeResponse::Redirect { location } => location
                .split("code=")
                .nth(1)
                .unwrap()
                .split('&')
                .next()
                .unwrap()
                .to_string(),
            _ => panic!("期望 Redirect"),
        }
    }

    // === 客户端认证测试 ===

    #[tokio::test]
    async fn handle_invalid_client_id() {
        let (handler, _) = make_handler();
        let req = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "no-such".into(),
            client_secret: "secret".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };
        let err = handler.handle(&req).await.unwrap_err();
        assert!(err.to_string().contains("invalid_client"));
    }

    #[tokio::test]
    async fn handle_invalid_client_secret() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("c-secret"))
            .await
            .unwrap();
        let req = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "c-secret".into(),
            client_secret: "wrong".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };
        let err = handler.handle(&req).await.unwrap_err();
        assert!(err.to_string().contains("invalid_client"));
    }

    // === HTTP Basic Auth 测试 ===

    /// parse_basic_auth 正确解析标准 Basic Auth 头。
    #[test]
    fn parse_basic_auth_decodes_valid_header() {
        // "cid:secret" → base64 → "Y2lkOnNlY3JldA=="
        let header = "Basic Y2lkOnNlY3JldA==";
        let result = parse_basic_auth(header);
        assert_eq!(result, Some(("cid".to_string(), "secret".to_string())));
    }

    /// parse_basic_auth 对非 Basic 头返回 None。
    #[test]
    fn parse_basic_auth_rejects_non_basic() {
        assert!(parse_basic_auth("Bearer token123").is_none());
        assert!(parse_basic_auth("").is_none());
    }

    /// parse_basic_auth 对无效 base64 返回 None。
    #[test]
    fn parse_basic_auth_rejects_invalid_base64() {
        assert!(parse_basic_auth("Basic !!!not-base64!!!").is_none());
    }

    /// parse_basic_auth 对不含 `:` 的解码结果返回 None。
    #[test]
    fn parse_basic_auth_rejects_no_colon() {
        // "noseparator" → base64 → "bm9zZXBhcmF0b3I="
        assert!(parse_basic_auth("Basic bm9zZXBhcmF0b3I=").is_none());
    }

    /// parse_basic_auth 正确处理空 client_id（":secret"）。
    #[test]
    fn parse_basic_auth_handles_empty_client_id() {
        // ":secret" → base64 → "OnNlY3JldA=="
        let result = parse_basic_auth("Basic OnNlY3JldA==");
        assert_eq!(result, Some(("".to_string(), "secret".to_string())));
    }

    /// handle_with_authorization 使用 Basic Auth 头认证客户端。
    ///
    /// 场景：client_id/client_secret 通过 Authorization 头传递，body 中为空。
    /// 期望：认证成功，token 签发成功。
    #[tokio::test]
    async fn handle_with_authorization_uses_basic_auth() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("basic-auth-cid"))
            .await
            .unwrap();

        // "basic-auth-cid:secret-123" → base64
        let credentials = STANDARD.encode("basic-auth-cid:secret-123");
        let auth_header = format!("Basic {}", credentials);

        let req = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "".into(), // body 中为空，依赖 Basic Auth
            client_secret: "".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };

        let resp = handler
            .handle_with_authorization(&req, Some(&auth_header))
            .await
            .expect("Basic Auth 认证应成功");
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 3600);
    }

    /// Basic Auth 头优先于 body 参数。
    ///
    /// 场景：Authorization 头含正确凭证，body 中含错误凭证。
    /// 期望：使用 Basic Auth 头的凭证认证成功（RFC 6749 §2.3.1 优先级）。
    #[tokio::test]
    async fn handle_with_authorization_basic_auth_overrides_body() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("override-cid"))
            .await
            .unwrap();

        // Basic Auth 头：正确凭证
        let credentials = STANDARD.encode("override-cid:secret-123");
        let auth_header = format!("Basic {}", credentials);

        let req = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "override-cid".into(),
            client_secret: "WRONG-SECRET".into(), // body 中错误
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };

        let resp = handler
            .handle_with_authorization(&req, Some(&auth_header))
            .await
            .expect("Basic Auth 应优先，body 错误凭证被忽略");
        assert_eq!(resp.token_type, "Bearer");
    }

    /// 无 Basic Auth 头时回退到 body 参数（向后兼容）。
    #[tokio::test]
    async fn handle_with_authorization_falls_back_to_body() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("fallback-cid"))
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "fallback-cid".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };

        // 不传 Authorization 头
        let resp = handler
            .handle_with_authorization(&req, None)
            .await
            .expect("body 参数认证应成功");
        assert_eq!(resp.token_type, "Bearer");
    }

    /// Basic Auth 头凭证错误时返回 invalid_client。
    #[tokio::test]
    async fn handle_with_authorization_basic_auth_wrong_secret() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("wrong-secret-cid"))
            .await
            .unwrap();

        // 错误密钥
        let credentials = STANDARD.encode("wrong-secret-cid:WRONG");
        let auth_header = format!("Basic {}", credentials);

        let req = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "".into(),
            client_secret: "".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };

        let err = handler
            .handle_with_authorization(&req, Some(&auth_header))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid_client"));
    }

    /// 既无 Basic Auth 头又无 body client_id 时返回 invalid_client。
    #[tokio::test]
    async fn handle_with_authorization_no_credentials_returns_error() {
        let (handler, _) = make_handler();

        let req = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "".into(),
            client_secret: "".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };

        let err = handler
            .handle_with_authorization(&req, None)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("invalid_client"),
            "无凭证应返回 invalid_client，实际: {}",
            err
        );
    }

    // === unsupported_grant_type 测试 ===

    #[tokio::test]
    async fn handle_unsupported_grant_type() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("c-gt"))
            .await
            .unwrap();
        let req = TokenRequest {
            grant_type: "implicit".into(),
            client_id: "c-gt".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };
        let err = handler.handle(&req).await.unwrap_err();
        assert!(err.to_string().contains("unsupported_grant_type"));
    }

    // === authorization_code grant type 测试 ===

    #[tokio::test]
    async fn handle_authorization_code_success() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("ac-001"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code = get_auth_code(&handler, "ac-001", verifier).await;

        let req = TokenRequest {
            grant_type: "authorization_code".into(),
            client_id: "ac-001".into(),
            client_secret: "secret-123".into(),
            code: Some(code),
            redirect_uri: Some("https://app.example.com/cb".into()),
            code_verifier: Some(verifier.into()),
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };
        let resp = handler.handle(&req).await.expect("签发 token");
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 3600);
        assert!(!resp.access_token.is_empty());
        assert!(resp.refresh_token.is_some());
    }

    #[tokio::test]
    async fn handle_authorization_code_pkce_mismatch() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("ac-002"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code = get_auth_code(&handler, "ac-002", verifier).await;

        let req = TokenRequest {
            grant_type: "authorization_code".into(),
            client_id: "ac-002".into(),
            client_secret: "secret-123".into(),
            code: Some(code),
            redirect_uri: Some("https://app.example.com/cb".into()),
            code_verifier: Some("wrong-verifier-wrong-verifier-wrong-verifier-wrong".into()),
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };
        let err = handler.handle(&req).await.unwrap_err();
        assert!(err.to_string().contains("PKCE"));
    }

    #[tokio::test]
    async fn handle_authorization_code_already_used() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("ac-003"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code = get_auth_code(&handler, "ac-003", verifier).await;

        let req = TokenRequest {
            grant_type: "authorization_code".into(),
            client_id: "ac-003".into(),
            client_secret: "secret-123".into(),
            code: Some(code.clone()),
            redirect_uri: Some("https://app.example.com/cb".into()),
            code_verifier: Some(verifier.into()),
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };
        // 第一次：成功
        handler.handle(&req).await.expect("首次签发");
        // 第二次：授权码已被消费
        let err = handler.handle(&req).await.unwrap_err();
        assert!(err.to_string().contains("invalid_grant"));
    }

    // === refresh_token grant type 测试 ===

    #[tokio::test]
    async fn handle_refresh_token_success() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("rt-001"))
            .await
            .unwrap();

        // 先通过 authorization_code 获取 refresh_token
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code = get_auth_code(&handler, "rt-001", verifier).await;
        let req = TokenRequest {
            grant_type: "authorization_code".into(),
            client_id: "rt-001".into(),
            client_secret: "secret-123".into(),
            code: Some(code),
            redirect_uri: Some("https://app.example.com/cb".into()),
            code_verifier: Some(verifier.into()),
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };
        let first_resp = handler.handle(&req).await.unwrap();
        let refresh_token = first_resp.refresh_token.clone().unwrap();

        // 使用 refresh_token 刷新
        let refresh_req = TokenRequest {
            grant_type: "refresh_token".into(),
            client_id: "rt-001".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: Some(refresh_token),
            scope: None,
            username: None,
            password: None,
        };
        let resp = handler.handle(&refresh_req).await.expect("刷新 token");
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 3600);
        // refresh_token 轮换 — 应返回新 refresh_token
        assert!(
            resp.refresh_token.is_some(),
            "VULN-0009: 刷新应轮换返回新 refresh_token"
        );
        assert_ne!(
            resp.refresh_token.as_ref().unwrap(),
            first_resp.refresh_token.as_ref().unwrap(),
            "VULN-0009: 新 refresh_token 应与旧的不同（轮换）"
        );
    }

    #[tokio::test]
    async fn handle_refresh_token_invalid() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("rt-002"))
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "refresh_token".into(),
            client_id: "rt-002".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: Some("invalid-token".into()),
            scope: None,
            username: None,
            password: None,
        };
        let err = handler.handle(&req).await.unwrap_err();
        assert!(err.to_string().contains("invalid_grant"));
    }

    /// refresh_token 轮换后，旧 token 被删除，重用返回 invalid_grant。
    ///
    /// 流程：
    /// 1. authorization_code 获取 refresh_token（old_token）
    /// 2. 用 old_token 刷新 → 返回新 refresh_token（new_token），old_token 被删除
    /// 3. 再次用 old_token 刷新 → invalid_grant（旧 token 已删除）
    #[tokio::test]
    async fn handle_refresh_token_rotation_deletes_old_token() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("rt-rot-001"))
            .await
            .unwrap();

        // 1. 获取初始 refresh_token
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code = get_auth_code(&handler, "rt-rot-001", verifier).await;
        let issue_req = TokenRequest {
            grant_type: "authorization_code".into(),
            client_id: "rt-rot-001".into(),
            client_secret: "secret-123".into(),
            code: Some(code),
            redirect_uri: Some("https://app.example.com/cb".into()),
            code_verifier: Some(verifier.into()),
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };
        let issue_resp = handler.handle(&issue_req).await.unwrap();
        let old_token = issue_resp.refresh_token.unwrap();

        // 2. 用 old_token 刷新（轮换）
        let refresh_req = TokenRequest {
            grant_type: "refresh_token".into(),
            client_id: "rt-rot-001".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: Some(old_token.clone()),
            scope: None,
            username: None,
            password: None,
        };
        let refresh_resp = handler
            .handle(&refresh_req)
            .await
            .expect("第一次刷新应成功");
        let new_token = refresh_resp.refresh_token.unwrap();
        assert_ne!(&new_token, &old_token, "新 refresh_token 应与旧的不同");

        // 3. 再次用 old_token 刷新 → invalid_grant（旧 token 已删除）
        let err = handler.handle(&refresh_req).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid_grant"),
            "VULN-0009: 重用已删除的旧 refresh_token 应返回 invalid_grant，实际: {}",
            err
        );
    }

    // === client_credentials grant type 测试 ===

    #[tokio::test]
    async fn handle_client_credentials_success() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("cc-001"))
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "cc-001".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: Some("read".into()),
            username: None,
            password: None,
        };
        let resp = handler.handle(&req).await.expect("签发 token");
        assert_eq!(resp.token_type, "Bearer");
        assert_eq!(resp.expires_in, 3600);
        assert!(
            resp.refresh_token.is_none(),
            "client_credentials 不应返回 refresh_token"
        );
        assert_eq!(resp.scope.as_deref(), Some("read"));
    }

    #[tokio::test]
    async fn handle_client_credentials_grant_not_allowed() {
        let (handler, _) = make_handler();
        // 创建仅支持 authorization_code 的客户端
        let client = OAuth2Client::new(
            "cc-only-auth",
            "secret-123",
            vec!["https://app.example.com/cb".into()],
            vec![GrantType::AuthorizationCode],
            vec![],
        )
        .unwrap();
        handler.store.create(client).await.unwrap();

        let req = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "cc-only-auth".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };
        let err = handler.handle(&req).await.unwrap_err();
        assert!(err.to_string().contains("unauthorized_client"));
    }

    // === password grant type 测试 ===

    #[tokio::test]
    async fn handle_password_success() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("pw-001"))
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "password".into(),
            client_id: "pw-001".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: Some("read".into()),
            username: Some("alice".into()),
            password: Some("wonderland".into()),
        };
        let resp = handler.handle(&req).await.expect("签发 token");
        assert_eq!(resp.token_type, "Bearer");
        assert!(resp.refresh_token.is_some());
        assert_eq!(resp.scope.as_deref(), Some("read"));
    }

    #[tokio::test]
    async fn handle_password_wrong_credentials() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("pw-002"))
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "password".into(),
            client_id: "pw-002".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: Some("alice".into()),
            password: Some("wrong-password".into()),
        };
        let err = handler.handle(&req).await.unwrap_err();
        assert!(err.to_string().contains("invalid_grant"));
    }

    // === password grant rate limiting 测试 ===

    /// 连续失败超过阈值后，再尝试应返回 rate_limited 错误（账户锁定）。
    ///
    /// max_attempts=3，window=300s：
    /// - 前 3 次失败：返回 invalid_grant（凭据错误，未超阈值）
    /// - 第 4 次尝试：返回 rate_limited（账户锁定，不调用 verifier）
    #[tokio::test]
    async fn handle_password_rate_limited_after_max_attempts() {
        let limiter = Arc::new(PasswordRateLimiter::new(3, 300));
        let (handler, _) = make_handler();
        let handler = handler.with_password_rate_limiter(limiter);
        handler
            .store
            .create(make_full_client("pw-rl-001"))
            .await
            .unwrap();

        let wrong_req = TokenRequest {
            grant_type: "password".into(),
            client_id: "pw-rl-001".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: Some("alice".into()),
            password: Some("wrong".into()),
        };

        // 前 3 次失败：返回 invalid_grant（凭据错误，未超阈值 max_attempts=3）
        for i in 0..3 {
            let err = handler.handle(&wrong_req).await.unwrap_err();
            assert!(
                err.to_string().contains("invalid_grant"),
                "第 {} 次失败应为 invalid_grant，实际: {}",
                i + 1,
                err
            );
        }

        // 第 4 次尝试：rate_limited（账户锁定）
        let err = handler.handle(&wrong_req).await.unwrap_err();
        assert!(
            err.to_string().contains("rate_limited"),
            "第 4 次尝试应为 rate_limited，实际: {}",
            err
        );
    }

    /// 成功登录后重置失败计数，可重新尝试至再次超阈值。
    ///
    /// max_attempts=3，window=300s：
    /// 1. 2 次失败（未超阈值）
    /// 2. 1 次成功 → 计数重置
    /// 3. 3 次失败（重新累计，未超阈值）
    /// 4. 第 4 次尝试 → rate_limited（重置后再次达上限）
    #[tokio::test]
    async fn handle_password_rate_limit_resets_on_success() {
        let limiter = Arc::new(PasswordRateLimiter::new(3, 300));
        let (handler, _) = make_handler();
        let handler = handler.with_password_rate_limiter(limiter);
        handler
            .store
            .create(make_full_client("pw-rl-002"))
            .await
            .unwrap();

        let wrong_req = TokenRequest {
            grant_type: "password".into(),
            client_id: "pw-rl-002".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: Some("alice".into()),
            password: Some("wrong".into()),
        };

        let right_req = TokenRequest {
            grant_type: "password".into(),
            client_id: "pw-rl-002".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: Some("alice".into()),
            password: Some("wonderland".into()),
        };

        // 1. 2 次失败（未超阈值 3）
        for _ in 0..2 {
            let _ = handler.handle(&wrong_req).await.unwrap_err();
        }

        // 2. 1 次成功：重置计数
        let resp = handler.handle(&right_req).await.expect("成功登录");
        assert_eq!(resp.token_type, "Bearer");

        // 3. 重置后再 3 次失败：仍应返回 invalid_grant（计数已重置，未超阈值）
        for i in 0..3 {
            let err = handler.handle(&wrong_req).await.unwrap_err();
            assert!(
                err.to_string().contains("invalid_grant"),
                "重置后第 {} 次失败应为 invalid_grant，实际: {}",
                i + 1,
                err
            );
        }

        // 4. 第 4 次尝试：rate_limited（重置后再次达上限）
        let err = handler.handle(&wrong_req).await.unwrap_err();
        assert!(
            err.to_string().contains("rate_limited"),
            "重置后第 4 次尝试应为 rate_limited，实际: {}",
            err
        );
    }

    /// `record_failure` 通过 `limiteron::incr_with_ttl` 原子递增计数器。
    ///
    /// 验证：
    /// - 首次失败：count=1
    /// - 后续失败：count 递增（不重置 TTL，窗口起点保持）
    #[tokio::test]
    async fn password_rate_limiter_record_failure_increments_count() {
        let limiter = PasswordRateLimiter::new(5, 300);
        // 首次失败：count 应为 1
        limiter.record_failure("alice").await;
        assert!(
            limiter.check("alice").await,
            "count=1 < max_attempts=5，应允许"
        );
        // 第 2、3 次失败：count 应分别为 2、3
        limiter.record_failure("alice").await;
        limiter.record_failure("alice").await;
        assert!(
            limiter.check("alice").await,
            "count=3 < max_attempts=5，应允许"
        );
        // 验证 entry_count 反映活跃 entry
        assert_eq!(limiter.entry_count().await, 1, "应仅 1 个 entry");
    }

    /// `check` 在失败次数达阈值时返回 `false`（账户锁定）。
    #[tokio::test]
    async fn password_rate_limiter_check_returns_false_at_threshold() {
        let limiter = PasswordRateLimiter::new(3, 300);
        // 3 次失败后，第 4 次 check 应返回 false
        limiter.record_failure("bob").await;
        limiter.record_failure("bob").await;
        limiter.record_failure("bob").await;
        // count=3 = max_attempts=3，应锁定
        assert!(
            !limiter.check("bob").await,
            "count=3 = max_attempts=3，应锁定（check 返回 false）"
        );
    }

    /// `check` 对未失败的 username 返回 `true`（无 entry = 未锁定）。
    #[tokio::test]
    async fn password_rate_limiter_check_passes_for_new_user() {
        let limiter = PasswordRateLimiter::new(3, 300);
        assert!(
            limiter.check("new-user").await,
            "未失败的 username 应允许尝试（check 返回 true）"
        );
        assert_eq!(limiter.entry_count().await, 0, "无失败记录时 entry_count=0");
    }

    /// `reset` 清除指定 username 的计数（验证成功后调用）。
    #[tokio::test]
    async fn password_rate_limiter_reset_clears_counter() {
        let limiter = PasswordRateLimiter::new(3, 300);
        limiter.record_failure("carol").await;
        limiter.record_failure("carol").await;
        assert_eq!(limiter.entry_count().await, 1, "失败 2 次后应有 1 个 entry");
        // 验证成功后 reset
        limiter.reset("carol").await;
        assert_eq!(limiter.entry_count().await, 0, "reset 后应无 entry");
        // reset 后再次失败应从 1 开始（而非继续累加）
        limiter.record_failure("carol").await;
        assert!(
            limiter.check("carol").await,
            "reset 后重新计数，count=1 < max_attempts=3，应允许"
        );
    }

    /// 不同 username 的计数器相互独立（验证 per-username 维度隔离）。
    #[tokio::test]
    async fn password_rate_limiter_users_are_independent() {
        let limiter = PasswordRateLimiter::new(2, 300);
        // alice 失败 2 次（达阈值，锁定）
        limiter.record_failure("alice").await;
        limiter.record_failure("alice").await;
        assert!(!limiter.check("alice").await, "alice 应被锁定");
        // bob 未失败，应允许
        assert!(limiter.check("bob").await, "bob 应允许（独立计数器）");
        assert_eq!(limiter.entry_count().await, 1, "应仅 alice 1 个 entry");
    }

    /// `max_attempts=0` 会被 clamp 到 1（避免所有请求被锁）。
    #[tokio::test]
    async fn password_rate_limiter_max_attempts_zero_clamps_to_one() {
        let limiter = PasswordRateLimiter::new(0, 300);
        // max_attempts 被 clamp 到 1，首次失败后即锁定
        limiter.record_failure("dave").await;
        // count=1 = max_attempts=1（clamped），应锁定
        assert!(
            !limiter.check("dave").await,
            "max_attempts=0 被 clamp 到 1，首次失败后应锁定"
        );
    }

    // === OAuth2 scope 校验测试 ===

    /// client_credentials 请求超出 allowed_scopes 的 scope 返回 invalid_scope。
    /// make_full_client 的 allowed_scopes = ["read", "write"]，请求 "admin" 应被拒绝。
    #[tokio::test]
    async fn handle_client_credentials_scope_not_allowed() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("cc-scope-001"))
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "cc-scope-001".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: Some("admin".into()),
            username: None,
            password: None,
        };
        let err = handler.handle(&req).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid_scope"),
            "期望 invalid_scope 错误，实际: {}",
            err
        );
    }

    /// client_credentials 请求部分 scope 超出 allowed_scopes 也应拒绝。
    /// 请求 "read admin"（read 合法，admin 不合法）应返回 invalid_scope。
    #[tokio::test]
    async fn handle_client_credentials_partial_scope_not_allowed() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("cc-scope-002"))
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "cc-scope-002".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: Some("read admin".into()),
            username: None,
            password: None,
        };
        let err = handler.handle(&req).await.unwrap_err();
        assert!(err.to_string().contains("invalid_scope"));
    }

    /// password grant 请求超出 allowed_scopes 的 scope 返回 invalid_scope。
    #[tokio::test]
    async fn handle_password_scope_not_allowed() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("pw-scope-001"))
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "password".into(),
            client_id: "pw-scope-001".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: Some("admin".into()),
            username: Some("alice".into()),
            password: Some("wonderland".into()),
        };
        let err = handler.handle(&req).await.unwrap_err();
        assert!(
            err.to_string().contains("invalid_scope"),
            "期望 invalid_scope 错误，实际: {}",
            err
        );
    }

    /// 空 allowed_scopes 的客户端允许任意 scope（向后兼容）。
    #[tokio::test]
    async fn handle_client_credentials_empty_allowed_scopes_allows_any() {
        let (handler, _) = make_handler();
        // 空 allowed_scopes 表示允许任意 scope
        let client = OAuth2Client::new(
            "cc-empty-scopes",
            "secret-123",
            vec!["https://app.example.com/cb".into()],
            vec![GrantType::ClientCredentials],
            vec![],
        )
        .unwrap();
        handler.store.create(client).await.unwrap();

        let req = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "cc-empty-scopes".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: Some("any-scope".into()),
            username: None,
            password: None,
        };
        let resp = handler
            .handle(&req)
            .await
            .expect("空 allowed_scopes 应允许任意 scope");
        assert_eq!(resp.scope.as_deref(), Some("any-scope"));
    }

    // === revoke / introspect 辅助方法测试 ===

    #[tokio::test]
    async fn get_access_token_record_after_issue() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("rec-001"))
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "rec-001".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: Some("read write".into()),
            username: None,
            password: None,
        };
        let resp = handler.handle(&req).await.unwrap();

        let record = handler
            .get_access_token_record(&resp.access_token)
            .await
            .unwrap()
            .expect("应存在");
        assert_eq!(record.client_id, "rec-001");
        assert!(record.user_id.is_none(), "client_credentials 无 user_id");
        assert_eq!(record.scopes, vec!["read", "write"]);
        assert_eq!(record.token_type, "access");
    }

    #[tokio::test]
    async fn revoke_token_makes_it_inaccessible() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_full_client("rev-001"))
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "rev-001".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };
        let resp = handler.handle(&req).await.unwrap();

        // 撤销前：存在
        assert!(handler
            .get_access_token_record(&resp.access_token)
            .await
            .unwrap()
            .is_some());

        // 撤销
        handler.revoke_token(&resp.access_token).await.unwrap();

        // 撤销后：不存在
        assert!(handler
            .get_access_token_record(&resp.access_token)
            .await
            .unwrap()
            .is_none());
    }

    #[test]
    fn generate_token_produces_unique() {
        let t1 = generate_token();
        let t2 = generate_token();
        assert_ne!(t1, t2);
        assert!(t1.len() >= 43);
    }

    // === TokenRateLimiter 速率限制测试（B5）===

    /// `TokenRateLimiter::new()` 使用默认配置（10 req/s per-client + 5 req/min per-username）。
    #[test]
    fn token_rate_limiter_new_uses_defaults() {
        let limiter = TokenRateLimiter::new();
        assert_eq!(limiter.client_max, 10);
        assert_eq!(limiter.client_window_secs, 1);
        assert_eq!(limiter.username_max, 5);
        assert_eq!(limiter.username_window_secs, 60);
    }

    /// `Default::default()` 与 `new()` 等价。
    #[test]
    fn token_rate_limiter_default_equals_new() {
        let limiter = TokenRateLimiter::default();
        assert_eq!(limiter.client_max, 10);
        assert_eq!(limiter.username_max, 5);
    }

    /// `with_limits(0, 0, 0, 0)` 被 clamp 到 (1, 1, 1, 1)，避免 max=0 导致全部被拒。
    #[test]
    fn token_rate_limiter_with_limits_zero_clamps_to_one() {
        let limiter = TokenRateLimiter::with_limits(0, 0, 0, 0);
        assert_eq!(limiter.client_max, 1);
        assert_eq!(limiter.client_window_secs, 1);
        assert_eq!(limiter.username_max, 1);
        assert_eq!(limiter.username_window_secs, 1);
    }

    /// per-client_id 限速：前 N 次允许，第 N+1 次拒绝。
    #[tokio::test]
    async fn token_rate_limiter_check_client_allows_within_limit() {
        let limiter = TokenRateLimiter::with_limits(3, 60, 100, 60);
        for i in 0..3 {
            assert!(
                limiter.check_client("client-A").await,
                "第 {} 次应允许",
                i + 1
            );
        }
        assert!(
            !limiter.check_client("client-A").await,
            "第 4 次应拒绝（超 client_max=3）"
        );
    }

    /// per-client_id 隔离：不同 client_id 独立计数。
    #[tokio::test]
    async fn token_rate_limiter_check_client_isolates_clients() {
        let limiter = TokenRateLimiter::with_limits(2, 60, 100, 60);
        assert!(limiter.check_client("client-A").await);
        assert!(limiter.check_client("client-A").await);
        assert!(!limiter.check_client("client-A").await, "client-A 达上限");
        // client-B 独立计数，仍允许
        assert!(
            limiter.check_client("client-B").await,
            "client-B 应允许（独立计数器）"
        );
    }

    /// per-username 限速：前 N 次允许，第 N+1 次拒绝。
    #[tokio::test]
    async fn token_rate_limiter_check_username_allows_within_limit() {
        let limiter = TokenRateLimiter::with_limits(100, 60, 3, 60);
        for i in 0..3 {
            assert!(
                limiter.check_username("alice").await,
                "第 {} 次应允许",
                i + 1
            );
        }
        assert!(
            !limiter.check_username("alice").await,
            "第 4 次应拒绝（超 username_max=3）"
        );
    }

    /// per-username 隔离：不同 username 独立计数。
    #[tokio::test]
    async fn token_rate_limiter_check_username_isolates_users() {
        let limiter = TokenRateLimiter::with_limits(100, 60, 2, 60);
        assert!(limiter.check_username("alice").await);
        assert!(limiter.check_username("alice").await);
        assert!(!limiter.check_username("alice").await, "alice 达上限");
        // bob 独立计数
        assert!(
            limiter.check_username("bob").await,
            "bob 应允许（独立计数器）"
        );
    }

    /// `handle_with_authorization` per-client_id 限速：超阈值后返回 rate_limited。
    ///
    /// client_max=2，前 2 次 client_credentials grant 成功，第 3 次被限速。
    #[tokio::test]
    async fn handle_with_authorization_rate_limited_after_client_threshold() {
        let limiter = Arc::new(TokenRateLimiter::with_limits(2, 60, 100, 60));
        let (handler, _) = make_handler();
        let handler = handler.with_token_rate_limiter(limiter);
        handler
            .store
            .create(make_full_client("rl-cid"))
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "rl-cid".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };

        // 前 2 次成功
        for i in 0..2 {
            let resp = handler.handle(&req).await;
            assert!(resp.is_ok(), "第 {} 次应成功，实际: {:?}", i + 1, resp);
        }

        // 第 3 次被 per-client_id 限速
        let err = handler.handle(&req).await.unwrap_err();
        assert!(
            err.to_string().contains("rate_limited"),
            "第 3 次应被限速，实际: {}",
            err
        );
    }

    /// per-client_id 限速通过 Basic Auth 头提取 client_id（body 中 client_id 为空时）。
    #[tokio::test]
    async fn handle_with_authorization_rate_limits_by_basic_auth_client_id() {
        let limiter = Arc::new(TokenRateLimiter::with_limits(1, 60, 100, 60));
        let (handler, _) = make_handler();
        let handler = handler.with_token_rate_limiter(limiter);
        handler
            .store
            .create(make_full_client("ba-rl"))
            .await
            .unwrap();

        let credentials = STANDARD.encode("ba-rl:secret-123");
        let auth_header = format!("Basic {}", credentials);

        let req = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "".into(), // body 中为空，依赖 Basic Auth
            client_secret: "".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };

        // 第 1 次成功
        let _ = handler
            .handle_with_authorization(&req, Some(&auth_header))
            .await
            .expect("第 1 次应成功");

        // 第 2 次被限速（通过 Basic Auth 提取的 client_id 限速）
        let err = handler
            .handle_with_authorization(&req, Some(&auth_header))
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("rate_limited"),
            "第 2 次应被限速（Basic Auth client_id），实际: {}",
            err
        );
    }

    /// `handle_password` per-username 限速：超阈值后返回 rate_limited。
    ///
    /// username_max=2，前 2 次成功登录，第 3 次被 per-username 限速。
    #[tokio::test]
    async fn handle_password_rate_limited_after_username_threshold() {
        let limiter = Arc::new(TokenRateLimiter::with_limits(100, 60, 2, 60));
        let (handler, _) = make_handler();
        let handler = handler.with_token_rate_limiter(limiter);
        handler
            .store
            .create(make_full_client("pw-url-001"))
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "password".into(),
            client_id: "pw-url-001".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: Some("alice".into()),
            password: Some("wonderland".into()),
        };

        // 前 2 次成功
        for i in 0..2 {
            let resp = handler.handle(&req).await;
            assert!(resp.is_ok(), "第 {} 次应成功，实际: {:?}", i + 1, resp);
        }

        // 第 3 次被 per-username 限速
        let err = handler.handle(&req).await.unwrap_err();
        assert!(
            err.to_string().contains("rate_limited"),
            "第 3 次应被 per-username 限速，实际: {}",
            err
        );
    }

    /// 未注入 `TokenRateLimiter` 时不启用限速（向后兼容）。
    ///
    /// 连续 50 次请求仍全部成功。
    #[tokio::test]
    async fn handle_without_token_rate_limiter_no_limit() {
        let (handler, _) = make_handler();
        // 未注入 token_rate_limiter
        handler
            .store
            .create(make_full_client("nrl-cid"))
            .await
            .unwrap();

        let req = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: "nrl-cid".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };

        // 连续 50 次也应成功（无限速）
        for _ in 0..50 {
            let _ = handler.handle(&req).await.expect("无限速应全部成功");
        }
    }
}

// ============================================================================
// v0.7.1 统一 Refresh Token 轮换集成测试（db-sqlite feature）
// ============================================================================

#[cfg(all(test, feature = "db-sqlite"))]
mod refresh_rotation_tests {
    use super::*;
    use crate::dao::{init_dbnexus, BulwarkMigration};
    use crate::oauth2_server::authorize::AuthorizeHandler;
    use crate::oauth2_server::client::{DaoOAuth2ClientStore, GrantType, OAuth2Client};
    use crate::protocol::jwt::refresh::RefreshTokenRotation;
    use crate::protocol::jwt::JwtHandler;
    use dbnexus::DbPool;
    use std::path::PathBuf;
    use std::sync::{Arc, RwLock};

    /// 定位项目根目录的 migrations/sqlite/ 目录。
    fn project_migrations_dir() -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir)
            .join("migrations")
            .join("sqlite")
    }

    /// 创建并初始化 SQLite in-memory 数据库。
    async fn setup_db() -> DbPool {
        let pool = init_dbnexus("sqlite::memory:")
            .await
            .expect("init_dbnexus 应成功");
        let migration = BulwarkMigration::with_base_dir(pool.clone(), project_migrations_dir());
        migration.migrate_core().await.expect("migrate_core 应成功");
        pool
    }

    /// 创建测试用 PasswordVerifier。
    struct TestPasswordVerifier;
    #[async_trait]
    impl PasswordVerifier for TestPasswordVerifier {
        async fn verify(&self, username: &str, password: &str) -> BulwarkResult<Option<i64>> {
            if username == "alice" && password == "wonderland" {
                Ok(Some(5001))
            } else {
                Ok(None)
            }
        }
    }

    /// 创建注入 RefreshTokenRotation 的 TokenHandler。
    async fn make_handler_with_rotation() -> TokenHandler {
        let pool = setup_db().await;
        let dao = Arc::new(crate::dao::MockDao::new());
        let store = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
        let authorize_handler = Arc::new(AuthorizeHandler::new(
            store.clone(),
            dao.clone(),
            "https://auth.example.com/login".into(),
        ));
        let jwt_handler = Arc::new(JwtHandler::new("test_secret"));
        let rotation = Arc::new(RefreshTokenRotation::new(
            pool,
            jwt_handler,
            Arc::new(RwLock::new(1)),
        ));
        TokenHandler::new(store, dao, authorize_handler)
            .with_password_verifier(Arc::new(TestPasswordVerifier))
            .with_refresh_rotation(rotation)
    }

    /// 创建未注入 RefreshTokenRotation 的 TokenHandler（fallback 路径）。
    fn make_handler_without_rotation() -> TokenHandler {
        let dao = Arc::new(crate::dao::MockDao::new());
        let store = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
        let authorize_handler = Arc::new(AuthorizeHandler::new(
            store.clone(),
            dao.clone(),
            "https://auth.example.com/login".into(),
        ));
        TokenHandler::new(store, dao, authorize_handler)
            .with_password_verifier(Arc::new(TestPasswordVerifier))
    }

    /// 创建支持所有 grant type 的客户端。
    fn make_full_client(id: &str) -> OAuth2Client {
        OAuth2Client::new(
            id,
            "secret-123",
            vec!["https://app.example.com/cb".into()],
            vec![
                GrantType::AuthorizationCode,
                GrantType::RefreshToken,
                GrantType::ClientCredentials,
                GrantType::Password,
            ],
            vec!["read".into(), "write".into()],
        )
        .unwrap()
    }

    /// 通过 authorize 端点获取授权码。
    async fn get_auth_code(handler: &TokenHandler, client_id: &str, verifier: &str) -> String {
        let challenge = crate::oauth2_server::authorize::generate_code_challenge(verifier);
        let req = crate::oauth2_server::authorize::AuthorizeRequest {
            response_type: "code".into(),
            client_id: client_id.into(),
            redirect_uri: "https://app.example.com/cb".into(),
            scope: Some("read".into()),
            state: Some("xyz".into()),
            code_challenge: challenge,
            code_challenge_method: "S256".into(),
        };
        let resp = handler
            .authorize_handler
            .authorize(&req, Some(1001))
            .await
            .unwrap();
        match resp {
            crate::oauth2_server::authorize::AuthorizeResponse::Redirect { location } => location
                .split("code=")
                .nth(1)
                .unwrap()
                .split('&')
                .next()
                .unwrap()
                .to_string(),
            _ => panic!("期望 Redirect"),
        }
    }

    /// T006: `TokenHandler::with_refresh_rotation` 构造成功。
    #[tokio::test(flavor = "multi_thread")]
    async fn token_handler_with_refresh_rotation() {
        let handler = make_handler_with_rotation().await;
        assert!(
            handler.refresh_rotation.is_some(),
            "注入后 refresh_rotation 应为 Some"
        );
    }

    /// T007: 注入 rotation 后，authorization_code grant 签发的 refresh_token 存在于 refresh_tokens 表。
    #[tokio::test(flavor = "multi_thread")]
    async fn issue_tokens_with_rotation_uses_issue_method() {
        let handler = make_handler_with_rotation().await;
        let client = make_full_client("rot-auth-001");
        // 先注册客户端
        handler
            .store
            .create(client.clone())
            .await
            .expect("create client 应成功");

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code = get_auth_code(&handler, "rot-auth-001", verifier).await;

        let req = TokenRequest {
            grant_type: "authorization_code".into(),
            client_id: "rot-auth-001".into(),
            client_secret: "secret-123".into(),
            code: Some(code),
            redirect_uri: Some("https://app.example.com/cb".into()),
            code_verifier: Some(verifier.into()),
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };
        let resp = handler.handle(&req).await.expect("token 签发应成功");
        assert!(resp.refresh_token.is_some(), "应返回 refresh_token");

        // 验证 refresh_token 存在于 refresh_tokens 表
        let rotation = handler.refresh_rotation.as_ref().unwrap();
        let record = rotation
            .validate(resp.refresh_token.as_ref().unwrap())
            .await
            .expect("validate 应成功");
        assert!(record.is_some(), "refresh_token 应在 refresh_tokens 表中");
        let record = record.unwrap();
        assert_eq!(record.client_id, Some("rot-auth-001".to_string()));
    }

    /// T008: 注入 rotation 后，refresh_token grant type 返回新 refresh_token（轮换）。
    #[tokio::test(flavor = "multi_thread")]
    async fn handle_refresh_token_with_rotation_rotates() {
        let handler = make_handler_with_rotation().await;
        let client = make_full_client("rot-refresh-001");
        handler.store.create(client.clone()).await.unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code = get_auth_code(&handler, "rot-refresh-001", verifier).await;

        // 签发初始 token
        let issue_req = TokenRequest {
            grant_type: "authorization_code".into(),
            client_id: "rot-refresh-001".into(),
            client_secret: "secret-123".into(),
            code: Some(code),
            redirect_uri: Some("https://app.example.com/cb".into()),
            code_verifier: Some(verifier.into()),
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };
        let issue_resp = handler.handle(&issue_req).await.unwrap();
        let old_refresh = issue_resp.refresh_token.expect("应有 refresh_token");

        // 使用 refresh_token 刷新
        let refresh_req = TokenRequest {
            grant_type: "refresh_token".into(),
            client_id: "rot-refresh-001".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: Some(old_refresh.clone()),
            scope: None,
            username: None,
            password: None,
        };
        let refresh_resp = handler.handle(&refresh_req).await.expect("refresh 应成功");
        assert!(
            refresh_resp.refresh_token.is_some(),
            "轮换后应返回新 refresh_token"
        );
        assert_ne!(
            refresh_resp.refresh_token.as_ref().unwrap(),
            &old_refresh,
            "新 refresh_token 应与旧的不同（轮换）"
        );
    }

    /// T008: reuse detection — 同一 refresh_token 两次使用，第二次返回 TokenRevoked。
    #[tokio::test(flavor = "multi_thread")]
    async fn handle_refresh_token_reuse_detection() {
        let handler = make_handler_with_rotation().await;
        let client = make_full_client("rot-reuse-001");
        handler.store.create(client.clone()).await.unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code = get_auth_code(&handler, "rot-reuse-001", verifier).await;

        // 签发初始 token
        let issue_req = TokenRequest {
            grant_type: "authorization_code".into(),
            client_id: "rot-reuse-001".into(),
            client_secret: "secret-123".into(),
            code: Some(code),
            redirect_uri: Some("https://app.example.com/cb".into()),
            code_verifier: Some(verifier.into()),
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };
        let issue_resp = handler.handle(&issue_req).await.unwrap();
        let old_refresh = issue_resp.refresh_token.expect("应有 refresh_token");

        // 第一次 refresh：成功
        let refresh_req = TokenRequest {
            grant_type: "refresh_token".into(),
            client_id: "rot-reuse-001".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: Some(old_refresh.clone()),
            scope: None,
            username: None,
            password: None,
        };
        let _first = handler
            .handle(&refresh_req)
            .await
            .expect("第一次 refresh 应成功");

        // 第二次 refresh（重用）：应返回 TokenRevoked
        let result = handler.handle(&refresh_req).await;
        assert!(
            matches!(&result, Err(BulwarkError::TokenRevoked(_))),
            "重用已消费的 refresh token 应返回 TokenRevoked，实际: {:?}",
            result
        );
    }

    /// T007/T008 fallback: 未注入 rotation 时退化为 DAO 路径（轮换 + 删除旧 token）。
    #[tokio::test(flavor = "multi_thread")]
    async fn handle_refresh_token_without_rotation_fallback() {
        let handler = make_handler_without_rotation();
        let client = make_full_client("rot-fallback-001");
        handler.store.create(client.clone()).await.unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code = get_auth_code(&handler, "rot-fallback-001", verifier).await;

        // 签发初始 token
        let issue_req = TokenRequest {
            grant_type: "authorization_code".into(),
            client_id: "rot-fallback-001".into(),
            client_secret: "secret-123".into(),
            code: Some(code),
            redirect_uri: Some("https://app.example.com/cb".into()),
            code_verifier: Some(verifier.into()),
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };
        let issue_resp = handler.handle(&issue_req).await.unwrap();
        let old_refresh = issue_resp.refresh_token.expect("应有 refresh_token");

        // 使用 refresh_token 刷新（fallback 路径轮换 + 删除旧 token）
        let refresh_req = TokenRequest {
            grant_type: "refresh_token".into(),
            client_id: "rot-fallback-001".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: Some(old_refresh.clone()),
            scope: None,
            username: None,
            password: None,
        };
        let refresh_resp = handler.handle(&refresh_req).await.expect("refresh 应成功");
        // fallback 路径现在轮换 — 应返回新 refresh_token
        assert!(
            refresh_resp.refresh_token.is_some(),
            "VULN-0009: Fallback 路径应轮换返回新 refresh_token"
        );
        assert_ne!(
            refresh_resp.refresh_token.as_ref().unwrap(),
            &old_refresh,
            "VULN-0009: 新 refresh_token 应与旧的不同"
        );

        // 旧 refresh_token 应已删除，重用返回 invalid_grant
        let reuse_err = handler.handle(&refresh_req).await.unwrap_err();
        assert!(
            reuse_err.to_string().contains("invalid_grant"),
            "VULN-0009: 重用旧 refresh_token 应返回 invalid_grant，实际: {}",
            reuse_err
        );
    }

    /// T012: 端到端集成测试 — authorization_code → refresh → reuse detection → revoke_chain。
    ///
    /// 完整流程：
    /// 1. authorization_code grant 签发初始 refresh_token（token1）
    /// 2. refresh_token grant 轮换 token1 → token2（token1 revoked=1）
    /// 3. refresh_token grant 轮换 token2 → token3（token2 revoked=1）
    /// 4. 重用 token1 → TokenRevoked（reuse detection 触发 revoke_chain）
    /// 5. 验证 token1 / token2 均为 revoked=1（链式撤销）
    /// 6. 验证 token3 仍有效（revoked=0）
    #[tokio::test(flavor = "multi_thread")]
    async fn oauth2_full_flow_with_refresh_rotation() {
        let handler = make_handler_with_rotation().await;
        let client = make_full_client("rot-e2e-001");
        handler.store.create(client.clone()).await.unwrap();

        // 1. authorization_code grant 签发初始 token
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let code = get_auth_code(&handler, "rot-e2e-001", verifier).await;
        let issue_req = TokenRequest {
            grant_type: "authorization_code".into(),
            client_id: "rot-e2e-001".into(),
            client_secret: "secret-123".into(),
            code: Some(code),
            redirect_uri: Some("https://app.example.com/cb".into()),
            code_verifier: Some(verifier.into()),
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };
        let issue_resp = handler.handle(&issue_req).await.expect("签发 token");
        let token1 = issue_resp.refresh_token.expect("应有 refresh_token");

        // 2. 第一次 refresh：token1 → token2（轮换）
        let refresh_req_1 = TokenRequest {
            grant_type: "refresh_token".into(),
            client_id: "rot-e2e-001".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: Some(token1.clone()),
            scope: None,
            username: None,
            password: None,
        };
        let resp1 = handler
            .handle(&refresh_req_1)
            .await
            .expect("第一次 refresh");
        let token2 = resp1.refresh_token.expect("应返回新 refresh_token");
        assert_ne!(&token2, &token1, "token2 应与 token1 不同");

        // 3. 第二次 refresh：token2 → token3（轮换）
        let refresh_req_2 = TokenRequest {
            grant_type: "refresh_token".into(),
            client_id: "rot-e2e-001".into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: Some(token2.clone()),
            scope: None,
            username: None,
            password: None,
        };
        let resp2 = handler
            .handle(&refresh_req_2)
            .await
            .expect("第二次 refresh");
        let token3 = resp2.refresh_token.expect("应返回新 refresh_token");
        assert_ne!(&token3, &token2, "token3 应与 token2 不同");

        // 4. 重用 token1 → TokenRevoked（reuse detection）
        let reuse_result = handler.handle(&refresh_req_1).await;
        assert!(
            matches!(&reuse_result, Err(BulwarkError::TokenRevoked(_))),
            "重用 token1 应返回 TokenRevoked，实际: {:?}",
            reuse_result
        );

        // 5. 验证整条链 token1 / token2 / token3 均已 revoked（链式撤销）
        // revoke_chain 撤销给定 token 及其所有子代（安全最佳实践：泄露一个即吊销全部）
        let rotation = handler.refresh_rotation.as_ref().unwrap();
        let token1_record = rotation.validate(&token1).await.expect("validate token1");
        assert!(
            token1_record.is_none(),
            "token1 应已 revoked（validate 返回 None）"
        );
        let token2_record = rotation.validate(&token2).await.expect("validate token2");
        assert!(
            token2_record.is_none(),
            "token2 应已 revoked（链式撤销子代，validate 返回 None）"
        );
        let token3_record = rotation.validate(&token3).await.expect("validate token3");
        assert!(
            token3_record.is_none(),
            "token3 应已 revoked（链式撤销孙代，validate 返回 None）"
        );
    }
}
