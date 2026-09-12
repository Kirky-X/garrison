//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! /oauth2/introspect 端点 — RFC 7662 token 内省。
//!
//! 返回 token 的活跃状态与元数据。有效 token 返回 active=true + scope + client_id + exp，
//! 过期/无效 token 返回 active=false。仅内网端口 :8443 可访问。

use crate::constants::TokenType;
use crate::error::{GarrisonError, GarrisonResult};
use crate::oauth2_server::client::OAuth2ClientStore;
use crate::oauth2_server::token::{TokenHandler, TokenRecord};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// /oauth2/introspect 请求参数。
#[derive(Debug, Clone, Deserialize)]
pub struct IntrospectRequest {
    /// 待查询的 token。
    pub token: String,
    /// token 类型提示（"access_token" 或 "refresh_token"，可选）。
    pub token_type_hint: Option<String>,
    /// 客户端 ID。
    pub client_id: String,
    /// 客户端密钥。
    pub client_secret: String,
}

/// /oauth2/introspect 响应（RFC 7662 §2.2）。
///
/// v0.7.1 补齐 RFC 7662 §2.3 全部字段：username / iat / nbf / aud / iss / jti。
#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct IntrospectResponse {
    /// token 是否活跃（有效且未过期）。
    pub active: bool,
    /// token 类型（"Bearer"）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
    /// 实际授予的 scope（空格分隔）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// 关联的客户端 ID。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    /// 过期时间戳（Unix 秒）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// 关联的用户 ID（client_credentials 无）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// 人类可读的用户标识（RFC 7662 §2.3，password grant type 有值）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// 签发时间（Unix 秒，RFC 7662 §2.3）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// 生效时间（Unix 秒，RFC 7662 §2.3，通常等于 iat）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// 受众（RFC 7662 §2.3，OAuth2 中为 client_id）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// 签发者（RFC 7662 §2.3）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// JWT 唯一标识（RFC 7662 §2.3，对应 TokenRecord.jti）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
}

/// OAuth2 token 签发者标识（RFC 7662 §2.3 `iss` 字段值）。
const OAUTH2_ISSUER: &str = "garrison-oauth2-server";

impl IntrospectResponse {
    /// 创建 inactive 响应（token 无效或过期）。
    pub fn inactive() -> Self {
        Self {
            active: false,
            token_type: None,
            scope: None,
            client_id: None,
            exp: None,
            sub: None,
            username: None,
            iat: None,
            nbf: None,
            aud: None,
            iss: None,
            jti: None,
        }
    }
}

/// /oauth2/introspect handler，处理 token 内省（RFC 7662）。
pub struct IntrospectHandler {
    store: Arc<dyn OAuth2ClientStore>,
    token_handler: Arc<TokenHandler>,
}

impl IntrospectHandler {
    /// 创建 handler。
    pub fn new(store: Arc<dyn OAuth2ClientStore>, token_handler: Arc<TokenHandler>) -> Self {
        Self {
            store,
            token_handler,
        }
    }

    /// 处理 introspect 请求。
    pub async fn handle(&self, req: &IntrospectRequest) -> GarrisonResult<IntrospectResponse> {
        // 1. 客户端认证
        let client = self.store.get(&req.client_id).await?.ok_or_else(|| {
            GarrisonError::OAuth2(format!(
                "oauth2-server-introspect-invalid-client::{}",
                req.client_id
            ))
        })?;
        if !client.verify_secret(&req.client_secret)? {
            return Err(GarrisonError::OAuth2(
                "oauth2-server-introspect-invalid-client-secret".into(),
            ));
        }

        // 2. 按 token_type_hint 选择查找顺序（RFC 7662 §2.1：hint 仅用于优化
        //    查找方向，查不到时 MAY 扩展搜索另一种类型）
        //    refresh token 存储于 `oauth2:rtoken:` 前缀 / rotation SQLite 表，
        //    必须经 get_refresh_token_record 查找，而非恒查 access 记录。
        let record = match req.token_type_hint.as_deref() {
            Some("refresh_token") => {
                match self.token_handler.get_refresh_token_record(&req.token).await? {
                    Some(r) => Some(r),
                    None => self.token_handler.get_access_token_record(&req.token).await?,
                }
            },
            _ => {
                match self.token_handler.get_access_token_record(&req.token).await? {
                    Some(r) => Some(r),
                    None => self.token_handler.get_refresh_token_record(&req.token).await?,
                }
            },
        };

        // 3. 过期判定：DAO TTL 理论上已剔除过期记录，但 rotation 路径的
        //    expires_at 不经 TTL 控制，且防御时钟偏差——过期记录一律 inactive。
        match record {
            Some(record) if record.expires_at > Utc::now() => {
                Ok(Self::response_from_record(record))
            },
            _ => Ok(IntrospectResponse::inactive()),
        }
    }

    /// 从 TokenRecord 构造 active 响应（RFC 7662 §2.3 全字段）。
    fn response_from_record(record: TokenRecord) -> IntrospectResponse {
        let scope = if record.scopes.is_empty() {
            None
        } else {
            Some(record.scopes.join(" "))
        };
        // RFC 7662 §2.3：从 TokenRecord 填充完整字段
        let iat_ts = record.issued_at.timestamp();
        IntrospectResponse {
            active: true,
            token_type: Some(TokenType::Bearer.to_string()),
            scope,
            client_id: Some(record.client_id.clone()),
            exp: Some(record.expires_at.timestamp()),
            sub: record.user_id.map(|id| id.to_string()),
            username: record.username,
            iat: Some(iat_ts),
            nbf: Some(iat_ts), // OAuth2 token 签发即生效，nbf = iat
            aud: Some(record.client_id), // 受众为请求该 token 的客户端
            iss: Some(OAUTH2_ISSUER.into()),
            jti: record.jti,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::{GarrisonDao, InMemoryDao};
    use crate::oauth2_server::authorize::AuthorizeHandler;
    use crate::oauth2_server::client::{DaoOAuth2ClientStore, GrantType, OAuth2Client};
    use crate::oauth2_server::token::{TokenHandler, TokenRequest};

    fn make_handlers() -> (
        IntrospectHandler,
        Arc<InMemoryDao>,
        Arc<TokenHandler>,
        Arc<AuthorizeHandler>,
    ) {
        let dao = Arc::new(InMemoryDao::new());
        let store = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
        let authorize_handler = Arc::new(AuthorizeHandler::new(
            store.clone(),
            dao.clone(),
            "https://auth.example.com/login".into(),
        ));
        let token_handler = Arc::new(TokenHandler::new(
            store.clone(),
            dao.clone(),
            authorize_handler.clone(),
        ));
        let introspect_handler = IntrospectHandler::new(store, token_handler.clone());
        (
            introspect_handler,
            dao,
            token_handler,
            authorize_handler,
        )
    }

    fn make_client(id: &str) -> OAuth2Client {
        OAuth2Client::new(
            id,
            "secret-123",
            vec!["https://app.example.com/cb".into()],
            vec![GrantType::ClientCredentials],
            vec!["read".into(), "write".into()],
        )
        .unwrap()
    }

    /// 创建支持 refresh_token 流程的客户端（authorization_code + refresh_token）。
    fn make_refresh_client(id: &str) -> OAuth2Client {
        OAuth2Client::new(
            id,
            "secret-123",
            vec!["https://app.example.com/cb".into()],
            vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            vec!["read".into(), "write".into()],
        )
        .unwrap()
    }

    /// 通过 authorization_code 流程签发 access_token + refresh_token。
    async fn issue_token_pair(
        authorize_handler: &AuthorizeHandler,
        token_handler: &TokenHandler,
        client_id: &str,
    ) -> (String, String) {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = crate::oauth2_server::authorize::generate_code_challenge(verifier);
        let auth_req = crate::oauth2_server::authorize::AuthorizeRequest {
            response_type: "code".into(),
            client_id: client_id.into(),
            redirect_uri: "https://app.example.com/cb".into(),
            scope: Some("read write".into()),
            state: None,
            code_challenge: challenge,
            code_challenge_method: "S256".into(),
        };
        let resp = match authorize_handler
            .authorize(&auth_req, Some(1001))
            .await
            .unwrap()
        {
            crate::oauth2_server::authorize::AuthorizeResponse::Redirect { location } => location,
            _ => panic!("期望 Redirect"),
        };
        let code = resp
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap()
            .to_string();
        let req = TokenRequest {
            grant_type: "authorization_code".into(),
            client_id: client_id.into(),
            client_secret: "secret-123".into(),
            code: Some(code),
            redirect_uri: Some("https://app.example.com/cb".into()),
            code_verifier: Some(verifier.into()),
            refresh_token: None,
            scope: None,
            username: None,
            password: None,
        };
        let token_resp = token_handler.handle(&req).await.unwrap();
        (
            token_resp.access_token,
            token_resp.refresh_token.expect("应有 refresh_token"),
        )
    }

    async fn issue_token(token_handler: &TokenHandler, client_id: &str) -> String {
        let req = TokenRequest {
            grant_type: "client_credentials".into(),
            client_id: client_id.into(),
            client_secret: "secret-123".into(),
            code: None,
            redirect_uri: None,
            code_verifier: None,
            refresh_token: None,
            scope: Some("read write".into()),
            username: None,
            password: None,
        };
        token_handler.handle(&req).await.unwrap().access_token
    }

    #[tokio::test]
    async fn introspect_active_token() {
        let (handler, _, token_handler, _) = make_handlers();
        handler.store.create(make_client("int-001")).await.unwrap();
        let token = issue_token(&token_handler, "int-001").await;

        let req = IntrospectRequest {
            token,
            token_type_hint: Some("access_token".into()),
            client_id: "int-001".into(),
            client_secret: "secret-123".into(),
        };
        let resp = handler.handle(&req).await.expect("内省");
        assert!(resp.active);
        assert_eq!(resp.token_type.as_deref(), Some("Bearer"));
        assert_eq!(resp.client_id.as_deref(), Some("int-001"));
        assert_eq!(resp.scope.as_deref(), Some("read write"));
        assert!(resp.exp.is_some());
        assert!(resp.sub.is_none(), "client_credentials 无 user_id");
        // RFC 7662 §2.3 新增字段验证
        assert!(resp.iat.is_some(), "iat 必须有值");
        assert!(resp.nbf.is_some(), "nbf 必须有值");
        assert_eq!(resp.iat, resp.nbf, "OAuth2 token 签发即生效，nbf = iat");
        assert_eq!(resp.aud.as_deref(), Some("int-001"), "aud = client_id");
        assert_eq!(resp.iss.as_deref(), Some("garrison-oauth2-server"));
        assert!(resp.jti.is_some(), "jti 必须有值");
        assert!(resp.username.is_none(), "client_credentials 无 username");
    }

    #[tokio::test]
    async fn introspect_nonexistent_token_returns_inactive() {
        let (handler, _, _, _) = make_handlers();
        handler.store.create(make_client("int-002")).await.unwrap();

        let req = IntrospectRequest {
            token: "nonexistent".into(),
            token_type_hint: None,
            client_id: "int-002".into(),
            client_secret: "secret-123".into(),
        };
        let resp = handler.handle(&req).await.expect("内省");
        assert!(!resp.active);
        assert!(resp.token_type.is_none());
        assert!(resp.client_id.is_none());
    }

    #[tokio::test]
    async fn introspect_revoked_token_returns_inactive() {
        let (handler, _, token_handler, _) = make_handlers();
        handler.store.create(make_client("int-003")).await.unwrap();
        let token = issue_token(&token_handler, "int-003").await;

        // 撤销 token
        token_handler.revoke_token(&token).await.unwrap();

        let req = IntrospectRequest {
            token,
            token_type_hint: None,
            client_id: "int-003".into(),
            client_secret: "secret-123".into(),
        };
        let resp = handler.handle(&req).await.expect("内省");
        assert!(!resp.active, "撤销后的 token 应返回 inactive");
    }

    #[tokio::test]
    async fn introspect_invalid_client_id() {
        let (handler, _, _, _) = make_handlers();
        let req = IntrospectRequest {
            token: "some-token".into(),
            token_type_hint: None,
            client_id: "no-such".into(),
            client_secret: "secret".into(),
        };
        let err = handler.handle(&req).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("oauth2-server-introspect-invalid-client"));
    }

    #[tokio::test]
    async fn introspect_invalid_client_secret() {
        let (handler, _, _, _) = make_handlers();
        handler.store.create(make_client("int-004")).await.unwrap();
        let req = IntrospectRequest {
            token: "some-token".into(),
            token_type_hint: None,
            client_id: "int-004".into(),
            client_secret: "wrong".into(),
        };
        let err = handler.handle(&req).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("oauth2-server-introspect-invalid-client"));
    }

    #[test]
    fn inactive_response_all_none() {
        let resp = IntrospectResponse::inactive();
        assert!(!resp.active);
        assert!(resp.token_type.is_none());
        assert!(resp.scope.is_none());
        assert!(resp.client_id.is_none());
        assert!(resp.exp.is_none());
        assert!(resp.sub.is_none());
        // RFC 7662 §2.3 新增字段在 inactive 响应中均为 None
        assert!(resp.username.is_none());
        assert!(resp.iat.is_none());
        assert!(resp.nbf.is_none());
        assert!(resp.aud.is_none());
        assert!(resp.iss.is_none());
        assert!(resp.jti.is_none());
    }

    /// refresh_token 内省：经 `oauth2:rtoken:` 前缀（fallback）/ rotation 表查找，
    /// 不再恒查 access 记录导致 refresh token 恒返回 active=false（RFC 7662）。
    #[tokio::test]
    async fn introspect_refresh_token_returns_active() {
        let (handler, _, token_handler, authorize_handler) = make_handlers();
        handler
            .store
            .create(make_refresh_client("int-rt-001"))
            .await
            .unwrap();
        let (_access, refresh) =
            issue_token_pair(&authorize_handler, &token_handler, "int-rt-001").await;

        // hint = refresh_token
        let req = IntrospectRequest {
            token: refresh.clone(),
            token_type_hint: Some("refresh_token".into()),
            client_id: "int-rt-001".into(),
            client_secret: "secret-123".into(),
        };
        let resp = handler.handle(&req).await.expect("内省");
        assert!(resp.active, "有效的 refresh_token 应返回 active=true");
        assert_eq!(resp.client_id.as_deref(), Some("int-rt-001"));
        assert_eq!(resp.scope.as_deref(), Some("read write"));
    }

    /// token_type_hint 仅是查找提示：refresh token 即使带 access_token hint
    /// 也应能被查到（RFC 7662 §2.1 允许扩展搜索），不得因 hint 错误返回 inactive。
    #[tokio::test]
    async fn introspect_hint_is_only_a_hint_fallback_still_finds() {
        let (handler, _, token_handler, authorize_handler) = make_handlers();
        handler
            .store
            .create(make_refresh_client("int-hint-001"))
            .await
            .unwrap();
        let (access, refresh) =
            issue_token_pair(&authorize_handler, &token_handler, "int-hint-001").await;

        // refresh token + access_token hint → 扩展搜索后仍应 active
        let req = IntrospectRequest {
            token: refresh,
            token_type_hint: Some("access_token".into()),
            client_id: "int-hint-001".into(),
            client_secret: "secret-123".into(),
        };
        let resp = handler.handle(&req).await.expect("内省");
        assert!(resp.active, "hint 错误时不得误报 inactive");

        // access token + refresh_token hint → 同理
        let req = IntrospectRequest {
            token: access,
            token_type_hint: Some("refresh_token".into()),
            client_id: "int-hint-001".into(),
            client_secret: "secret-123".into(),
        };
        let resp = handler.handle(&req).await.expect("内省");
        assert!(resp.active, "hint 指向 refresh 时 access token 也应可查到");
    }

    /// 过期 token 内省必须返回 active=false（即使 DAO 记录尚未被 TTL 清理）。
    #[tokio::test]
    async fn introspect_expired_token_returns_inactive() {
        let (handler, dao, _token_handler, _) = make_handlers();
        handler.store.create(make_client("int-exp-001")).await.unwrap();

        // 直接向 DAO 写入一条已过期的 access token 记录（模拟 TTL 尚未清理的过期记录）
        let expired_record = TokenRecord {
            token: "expired-token-001".into(),
            client_id: "int-exp-001".into(),
            user_id: None,
            scopes: vec!["read".into()],
            token_type: "access".into(),
            expires_at: Utc::now() - chrono::Duration::hours(1),
            issued_at: Utc::now() - chrono::Duration::hours(2),
            jti: Some("expired-jti".into()),
            username: None,
        };
        let key = crate::constants::DaoKeyPrefix::OAuth2AccessToken
            .build_key("expired-token-001");
        dao.set(&key, &serde_json::to_string(&expired_record).unwrap(), 600)
            .await
            .unwrap();

        let req = IntrospectRequest {
            token: "expired-token-001".into(),
            token_type_hint: None,
            client_id: "int-exp-001".into(),
            client_secret: "secret-123".into(),
        };
        let resp = handler.handle(&req).await.expect("内省");
        assert!(!resp.active, "过期 token 应返回 active=false");
        assert!(resp.client_id.is_none(), "inactive 响应不应泄露记录字段");
    }
}
