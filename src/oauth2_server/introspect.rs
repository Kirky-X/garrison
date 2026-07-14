//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! /oauth2/introspect 端点 — RFC 7662 token 内省。
//!
//! 返回 token 的活跃状态与元数据。有效 token 返回 active=true + scope + client_id + exp，
//! 过期/无效 token 返回 active=false。仅内网端口 :8443 可访问。

use crate::constants::TokenType;
use crate::error::{BulwarkError, BulwarkResult};
use crate::oauth2_server::client::OAuth2ClientStore;
use crate::oauth2_server::token::TokenHandler;
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
const OAUTH2_ISSUER: &str = "bulwark-oauth2-server";

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
    pub async fn handle(&self, req: &IntrospectRequest) -> BulwarkResult<IntrospectResponse> {
        // 1. 客户端认证
        let client = self.store.get(&req.client_id).await?.ok_or_else(|| {
            BulwarkError::OAuth2(format!("invalid_client: {} 不存在", req.client_id))
        })?;
        if !client.verify_secret(&req.client_secret)? {
            return Err(BulwarkError::OAuth2(
                "invalid_client: client_secret 不匹配".into(),
            ));
        }

        // 2. 查找 token 记录
        let record = self
            .token_handler
            .get_access_token_record(&req.token)
            .await?;
        match record {
            Some(record) => {
                let scope = if record.scopes.is_empty() {
                    None
                } else {
                    Some(record.scopes.join(" "))
                };
                // RFC 7662 §2.3：从 TokenRecord 填充完整字段
                let iat_ts = record.issued_at.timestamp();
                Ok(IntrospectResponse {
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
                })
            },
            None => Ok(IntrospectResponse::inactive()),
        }
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::MockDao;
    use crate::oauth2_server::authorize::AuthorizeHandler;
    use crate::oauth2_server::client::{DaoOAuth2ClientStore, GrantType, OAuth2Client};
    use crate::oauth2_server::token::{TokenHandler, TokenRequest};

    fn make_handlers() -> (IntrospectHandler, Arc<MockDao>, Arc<TokenHandler>) {
        let dao = Arc::new(MockDao::new());
        let store = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
        let authorize_handler = Arc::new(AuthorizeHandler::new(
            store.clone(),
            dao.clone(),
            "https://auth.example.com/login".into(),
        ));
        let token_handler = Arc::new(TokenHandler::new(
            store.clone(),
            dao.clone(),
            authorize_handler,
        ));
        let introspect_handler = IntrospectHandler::new(store, token_handler.clone());
        (introspect_handler, dao, token_handler)
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
        let (handler, _, token_handler) = make_handlers();
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
        assert_eq!(resp.iss.as_deref(), Some("bulwark-oauth2-server"));
        assert!(resp.jti.is_some(), "jti 必须有值");
        assert!(resp.username.is_none(), "client_credentials 无 username");
    }

    #[tokio::test]
    async fn introspect_nonexistent_token_returns_inactive() {
        let (handler, _, _) = make_handlers();
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
        let (handler, _, token_handler) = make_handlers();
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
        let (handler, _, _) = make_handlers();
        let req = IntrospectRequest {
            token: "some-token".into(),
            token_type_hint: None,
            client_id: "no-such".into(),
            client_secret: "secret".into(),
        };
        let err = handler.handle(&req).await.unwrap_err();
        assert!(err.to_string().contains("invalid_client"));
    }

    #[tokio::test]
    async fn introspect_invalid_client_secret() {
        let (handler, _, _) = make_handlers();
        handler.store.create(make_client("int-004")).await.unwrap();
        let req = IntrospectRequest {
            token: "some-token".into(),
            token_type_hint: None,
            client_id: "int-004".into(),
            client_secret: "wrong".into(),
        };
        let err = handler.handle(&req).await.unwrap_err();
        assert!(err.to_string().contains("invalid_client"));
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
}
