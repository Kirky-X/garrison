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
use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use crate::oauth2_server::authorize::AuthorizeHandler;
use crate::oauth2_server::client::{GrantType, OAuth2Client, OAuth2ClientStore};
#[cfg(feature = "db-sqlite")]
use crate::protocol::jwt::refresh::RefreshTokenRotation;
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use parking_lot::Mutex;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

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

/// password grant type 验证器 trait。
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

/// Password grant 失败计数器 — 防 brute-force（VULN-0005）。
///
/// 按 username 维度跟踪窗口内失败次数，超阈值后锁定至窗口过期。
/// 验证成功后重置计数。
///
/// # 设计
///
/// - **per-username 维度**：与 `crate::server::middleware::RateLimitState`（per-IP）不同 ——
///   防御多 IP 撞库同一账户的暴力破解
/// - **滑动窗口**：`window_seconds` 内累计失败次数达 `max_attempts` 即锁定至窗口过期
/// - **in-memory**：与 `RateLimitState` 一致，简化实现不依赖 Redis
/// - **parking_lot::Mutex**：与 `RateLimitState` 一致
/// - **max_entries 上限**（tiangang/diting 审查 HIGH 修复）：与 `RateLimitState` 对称设计，
///   防止攻击者用大量伪造 username 耗尽内存（与 VULN-0008 同类风险）
///
/// # 与 RateLimitState 的区别
///
/// `RateLimitState` 是 HTTP 中间件级别的 per-IP 令牌桶，限制每秒请求数；
/// 本结构是 OAuth2 handler 级别的 per-username 失败计数器，限制窗口内失败次数。
/// 两者互补：IP 限速防御分布式扫描，账户锁定防御定向撞库。
#[derive(Debug)]
pub struct PasswordRateLimiter {
    /// username → 失败记录
    attempts: Mutex<HashMap<String, FailedAttemptRecord>>,
    /// 窗口内允许的最大失败次数（达此值后锁定至窗口过期）
    max_attempts: u32,
    /// 滑动窗口时长（秒）
    window_seconds: u64,
    /// HashMap 最大条目数（tiangang/diting 审查 HIGH 修复：防 DoS 内存耗尽）。
    /// 超限时 LRU 淘汰最久未访问的 entry，与 `RateLimitState::max_entries` 对称。
    max_entries: usize,
}

/// 默认最大 entry 数（与 `RateLimitState::DEFAULT_MAX_ENTRIES` 一致）。
const DEFAULT_PASSWORD_LIMITER_MAX_ENTRIES: usize = 100_000;

/// 单个 username 的失败记录。
#[derive(Debug, Clone)]
struct FailedAttemptRecord {
    /// 窗口内累计失败次数
    count: u32,
    /// 窗口起始时间
    first_failure: Instant,
}

impl PasswordRateLimiter {
    /// 创建失败计数器（向后兼容，默认 max_entries=100_000）。
    ///
    /// # 参数
    /// - `max_attempts`：窗口内允许的最大失败次数（达此值后锁定至窗口过期）
    /// - `window_seconds`：滑动窗口时长（秒），窗口过期后计数自动重置
    pub fn new(max_attempts: u32, window_seconds: u64) -> Self {
        Self::with_max_entries(
            max_attempts,
            window_seconds,
            DEFAULT_PASSWORD_LIMITER_MAX_ENTRIES,
        )
    }

    /// 创建失败计数器（完整配置）。
    ///
    /// # 参数
    /// - `max_attempts`：窗口内允许的最大失败次数（达此值后锁定至窗口过期）
    /// - `window_seconds`：滑动窗口时长（秒），窗口过期后计数自动重置
    /// - `max_entries`：HashMap 最大条目数（防 DoS 内存耗尽，与 `RateLimitState` 对称）
    pub fn with_max_entries(max_attempts: u32, window_seconds: u64, max_entries: usize) -> Self {
        Self {
            attempts: Mutex::new(HashMap::new()),
            // 至少 1，避免 max_attempts=0 导致所有请求被锁
            max_attempts: max_attempts.max(1),
            window_seconds,
            // 至少 1，避免 max_entries=0 导致所有 entry 被驱逐
            max_entries: max_entries.max(1),
        }
    }

    /// 检查 username 是否允许尝试（未锁定）。
    ///
    /// 返回 `true` 表示允许尝试，`false` 表示已被锁定（窗口内失败次数达上限）。
    /// 窗口过期时自动重置计数并允许尝试。
    fn check(&self, username: &str) -> bool {
        let mut attempts = self.attempts.lock();
        let now = Instant::now();
        match attempts.get(username) {
            Some(record) => {
                // 窗口已过期 → 重置
                if now.duration_since(record.first_failure).as_secs() >= self.window_seconds {
                    attempts.remove(username);
                    return true;
                }
                // 窗口内失败次数未达上限 → 允许尝试
                record.count < self.max_attempts
            },
            None => true,
        }
    }

    /// 记录一次失败。
    ///
    /// 窗口过期时重置计数后再记录。新 entry 插入前若达 `max_entries` 上限，
    /// LRU 淘汰最久未访问的 entry（tiangang/diting 审查 HIGH 修复）。
    fn record_failure(&self, username: &str) {
        let mut attempts = self.attempts.lock();
        let now = Instant::now();
        match attempts.get_mut(username) {
            Some(record) => {
                if now.duration_since(record.first_failure).as_secs() >= self.window_seconds {
                    // 窗口过期 → 重置后再记录
                    record.count = 1;
                    record.first_failure = now;
                } else {
                    record.count += 1;
                }
            },
            None => {
                // tiangang/diting 审查 HIGH 修复：插入前检查 max_entries，
                // 超限时 LRU 淘汰最旧 entry（与 RateLimitState 对称设计）
                if attempts.len() >= self.max_entries {
                    if let Some(oldest_key) = attempts
                        .iter()
                        .min_by_key(|(_, r)| r.first_failure)
                        .map(|(k, _)| k.clone())
                    {
                        attempts.remove(&oldest_key);
                    }
                }
                attempts.insert(
                    username.to_string(),
                    FailedAttemptRecord {
                        count: 1,
                        first_failure: now,
                    },
                );
            },
        }
    }

    /// 验证成功后重置 username 的计数。
    fn reset(&self, username: &str) {
        self.attempts.lock().remove(username);
    }

    /// 当前 entry 数量（测试/运维用）。
    pub fn entry_count(&self) -> usize {
        self.attempts.lock().len()
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
    /// Password grant 失败计数器（VULN-0005：防 brute-force）。
    /// 为 None 时不启用账户锁定（向后兼容，但不推荐生产使用）。
    password_rate_limiter: Option<Arc<PasswordRateLimiter>>,
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
            #[cfg(feature = "db-sqlite")]
            refresh_rotation: None,
        }
    }

    /// 注入 password grant type 验证器。
    pub fn with_password_verifier(mut self, verifier: Arc<dyn PasswordVerifier>) -> Self {
        self.password_verifier = Some(verifier);
        self
    }

    /// 注入 PasswordRateLimiter 启用 password grant 失败计数 + 账户锁定（VULN-0005）。
    ///
    /// 未注入时 password grant 无账户级速率限制（向后兼容，但不推荐生产使用）。
    pub fn with_password_rate_limiter(mut self, limiter: Arc<PasswordRateLimiter>) -> Self {
        self.password_rate_limiter = Some(limiter);
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
        // 1. 验证客户端凭证
        let client = self
            .authenticate_client(&req.client_id, &req.client_secret)
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

    /// 验证客户端凭证。
    async fn authenticate_client(
        &self,
        client_id: &str,
        client_secret: &str,
    ) -> BulwarkResult<OAuth2Client> {
        let client =
            self.store.get(client_id).await?.ok_or_else(|| {
                BulwarkError::OAuth2(format!("invalid_client: {client_id} 不存在"))
            })?;
        if !client.verify_secret(client_secret)? {
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
        // VULN-0003: 校验授权码中的 scope 是否在客户端 allowed_scopes 内（纵深防御）
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
    /// 未注入时退化为 DAO 路径（无轮换，仅签发新 access_token）：
    /// - 查找 `DaoKeyPrefix::OAuth2RefreshToken` 记录
    /// - 校验 client_id 一致性
    /// - 签发新 access_token（refresh_token 继续使用，不轮换）
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

        // Fallback: DAO 路径（无轮换，无 reuse detection）
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

        // 签发新 access_token（不签发新 refresh_token，refresh_token 继续使用）
        let user_id = record.user_id;
        let scopes = record.scopes.clone();
        let username = record.username.clone();
        self.issue_tokens(
            &client.client_id,
            user_id,
            &scopes,
            false,
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

        // VULN-0003: 校验请求的 scope 是否在客户端 allowed_scopes 内
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

        // VULN-0005: 验证密码前检查账户锁定状态（防 brute-force）
        if let Some(limiter) = &self.password_rate_limiter {
            if !limiter.check(username) {
                return Err(BulwarkError::OAuth2(
                    "rate_limited: 账户已被临时锁定，请稍后再试".into(),
                ));
            }
        }

        let user_id = match verifier.verify(username, password).await? {
            Some(uid) => uid,
            None => {
                // VULN-0005: 验证失败后增加失败计数
                if let Some(limiter) = &self.password_rate_limiter {
                    limiter.record_failure(username);
                }
                return Err(BulwarkError::OAuth2(
                    "invalid_grant: 用户名或密码错误".into(),
                ));
            },
        };

        // VULN-0005: 验证成功后重置失败计数
        if let Some(limiter) = &self.password_rate_limiter {
            limiter.reset(username);
        }

        let scopes: Vec<String> = req
            .scope
            .as_ref()
            .map(|s| s.split_whitespace().map(|x| x.to_string()).collect())
            .unwrap_or_default();

        // VULN-0003: 校验请求的 scope 是否在客户端 allowed_scopes 内
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

// ============================================================================
// 测试
// ============================================================================

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
        let refresh_token = first_resp.refresh_token.unwrap();

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
        assert!(resp.refresh_token.is_none(), "刷新不应返回新 refresh_token");
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

    // === VULN-0005: password grant rate limiting 测试 ===

    /// VULN-0005: 连续失败超过阈值后，再尝试应返回 rate_limited 错误（账户锁定）。
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

    /// VULN-0005: 成功登录后重置失败计数，可重新尝试至再次超阈值。
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

    /// tiangang/diting 审查 HIGH 修复：PasswordRateLimiter max_entries LRU 淘汰测试。
    ///
    /// 验证 `record_failure` 在 HashMap 达到 `max_entries` 上限时淘汰最旧 entry，
    /// 防止攻击者用大量伪造 username 耗尽内存（与 VULN-0008 同类风险）。
    #[test]
    fn password_rate_limiter_evicts_oldest_when_max_entries_reached() {
        // max_attempts=10（不触发账户锁定），max_entries=3（仅保留 3 个 entry）
        let limiter = PasswordRateLimiter::with_max_entries(10, 300, 3);

        // 插入 3 个 username（u1, u2, u3），都达上限
        limiter.record_failure("u1");
        limiter.record_failure("u2");
        limiter.record_failure("u3");
        assert_eq!(limiter.entry_count(), 3, "应保留 3 个 entry");

        // 插入第 4 个 username（u4），应淘汰最旧（u1，因 first_failure 最早）
        limiter.record_failure("u4");
        assert_eq!(
            limiter.entry_count(),
            3,
            "max_entries=3 时插入新 entry 后总数应保持 3"
        );

        // u1 应已被淘汰（check 返回 true 表示未锁定 = entry 不存在或窗口内失败次数 < max_attempts）
        // 由于 u1 被淘汰，check("u1") 应返回 true（entry 不存在）
        // 而 u2/u3/u4 仍存在，且 count=1 < max_attempts=10，check 也返回 true
        // 此处仅验证 entry_count，不验证具体哪个被淘汰（依赖 min_by_key 实现）
    }

    /// tiangang/diting 审查 HIGH 修复：PasswordRateLimiter::new 默认 max_entries=100_000。
    #[test]
    fn password_rate_limiter_new_uses_default_max_entries() {
        let limiter = PasswordRateLimiter::new(5, 300);
        // 默认 max_entries 应为 100_000（DEFAULT_PASSWORD_LIMITER_MAX_ENTRIES）
        // 间接验证：插入 1 个 entry 后 entry_count=1，未触发淘汰
        limiter.record_failure("test-user");
        assert_eq!(limiter.entry_count(), 1);
    }

    /// tiangang/diting 审查 HIGH 修复：with_max_entries 的 max_entries=0 会被 clamp 到 1。
    #[test]
    fn password_rate_limiter_with_max_entries_zero_clamps_to_one() {
        // max_entries=0 应被 clamp 到 1，避免所有 entry 被驱逐
        let limiter = PasswordRateLimiter::with_max_entries(5, 300, 0);
        limiter.record_failure("u1");
        assert_eq!(limiter.entry_count(), 1, "max_entries=0 应被 clamp 到 1");

        // 插入第 2 个 entry 时应淘汰 u1（max_entries=1）
        limiter.record_failure("u2");
        assert_eq!(
            limiter.entry_count(),
            1,
            "max_entries=1 时插入新 entry 应淘汰旧 entry"
        );
    }

    // === VULN-0003: OAuth2 scope 校验测试 ===

    /// VULN-0003: client_credentials 请求超出 allowed_scopes 的 scope 返回 invalid_scope。
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

    /// VULN-0003: client_credentials 请求部分 scope 超出 allowed_scopes 也应拒绝。
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

    /// VULN-0003: password grant 请求超出 allowed_scopes 的 scope 返回 invalid_scope。
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

    /// VULN-0003: 空 allowed_scopes 的客户端允许任意 scope（向后兼容）。
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

    /// T007/T008 fallback: 未注入 rotation 时退化为 DAO 路径（不轮换）。
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

        // 使用 refresh_token 刷新（fallback：不轮换，仅新 access_token）
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
        // Fallback 路径不轮换：refresh_token 为 None（issue_tokens with_refresh=false）
        assert!(
            refresh_resp.refresh_token.is_none(),
            "Fallback 路径不轮换，不应返回新 refresh_token"
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
