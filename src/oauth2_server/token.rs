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
use async_trait::async_trait;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Duration, Utc};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

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

/// /oauth2/token handler，处理 4 种 grant type。
pub struct TokenHandler {
    store: Arc<dyn OAuth2ClientStore>,
    dao: Arc<dyn BulwarkDao>,
    authorize_handler: Arc<AuthorizeHandler>,
    password_verifier: Option<Arc<dyn PasswordVerifier>>,
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
        }
    }

    /// 注入 password grant type 验证器。
    pub fn with_password_verifier(mut self, verifier: Arc<dyn PasswordVerifier>) -> Self {
        self.password_verifier = Some(verifier);
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

        // 查找 refresh_token 记录
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

        let user_id = verifier
            .verify(username, password)
            .await?
            .ok_or_else(|| BulwarkError::OAuth2("invalid_grant: 用户名或密码错误".into()))?;

        let scopes: Vec<String> = req
            .scope
            .as_ref()
            .map(|s| s.split_whitespace().map(|x| x.to_string()).collect())
            .unwrap_or_default();

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
            let rt_key = DaoKeyPrefix::OAuth2RefreshToken.build_key(&rt);
            let rt_json = serde_json::to_string(&rt_record)
                .map_err(|e| BulwarkError::Internal(format!("TokenRecord 序列化失败: {e}")))?;
            self.dao
                .set(&rt_key, &rt_json, REFRESH_TOKEN_TTL_SECONDS)
                .await?;
            Some(rt)
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
