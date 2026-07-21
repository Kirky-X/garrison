//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! /oauth2/revoke 端点 — RFC 7009 token 撤销。
//!
//! 撤销 access_token 或 refresh_token，token 失效后立即不可用。
//! 无论 token 是否有效，始终返回成功（RFC 7009 §2.2 规定不暴露 token 有效性）。

use crate::error::{GarrisonError, GarrisonResult};
use crate::oauth2_server::client::OAuth2ClientStore;
use crate::oauth2_server::token::TokenHandler;
use serde::Deserialize;
use std::sync::Arc;

/// /oauth2/revoke 请求参数。
#[derive(Debug, Clone, Deserialize)]
pub struct RevokeRequest {
    /// 待撤销的 token。
    pub token: String,
    /// token 类型提示（"access_token" 或 "refresh_token"，可选）。
    pub token_type_hint: Option<String>,
    /// 客户端 ID。
    pub client_id: String,
    /// 客户端密钥。
    pub client_secret: String,
}

/// /oauth2/revoke handler，处理 token 撤销（RFC 7009）。
pub struct RevokeHandler {
    store: Arc<dyn OAuth2ClientStore>,
    token_handler: Arc<TokenHandler>,
}

impl RevokeHandler {
    /// 创建 handler。
    pub fn new(store: Arc<dyn OAuth2ClientStore>, token_handler: Arc<TokenHandler>) -> Self {
        Self {
            store,
            token_handler,
        }
    }

    /// 处理 revoke 请求。
    ///
    /// # 返回
    /// - `Ok(())`：撤销成功（无论 token 是否有效，RFC 7009 §2.2）
    /// - `Err`：客户端认证失败
    pub async fn handle(&self, req: &RevokeRequest) -> GarrisonResult<()> {
        // 1. 客户端认证
        let client = self.store.get(&req.client_id).await?.ok_or_else(|| {
            GarrisonError::OAuth2(format!(
                "oauth2-server-revoke-invalid-client::{}",
                req.client_id
            ))
        })?;
        if !client.verify_secret(&req.client_secret)? {
            return Err(GarrisonError::OAuth2(
                "oauth2-server-revoke-invalid-client-secret".into(),
            ));
        }

        // 2. 撤销 token（无论 token 是否有效都返回成功）
        self.token_handler.revoke_token(&req.token).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::MockDao;
    use crate::oauth2_server::authorize::AuthorizeHandler;
    use crate::oauth2_server::client::{DaoOAuth2ClientStore, GrantType, OAuth2Client};
    use crate::oauth2_server::token::{TokenHandler, TokenRequest};

    /// 创建测试用 handler 和 DAO。
    fn make_handlers() -> (RevokeHandler, Arc<MockDao>, Arc<TokenHandler>) {
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
        let revoke_handler = RevokeHandler::new(store, token_handler.clone());
        (revoke_handler, dao, token_handler)
    }

    fn make_client(id: &str) -> OAuth2Client {
        OAuth2Client::new(
            id,
            "secret-123",
            vec!["https://app.example.com/cb".into()],
            vec![GrantType::ClientCredentials],
            vec!["read".into()],
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
            scope: None,
            username: None,
            password: None,
        };
        token_handler.handle(&req).await.unwrap().access_token
    }

    #[tokio::test]
    async fn revoke_valid_access_token() {
        let (handler, _, token_handler) = make_handlers();
        handler.store.create(make_client("rev-001")).await.unwrap();
        let token = issue_token(&token_handler, "rev-001").await;

        // 撤销前：存在
        assert!(token_handler
            .get_access_token_record(&token)
            .await
            .unwrap()
            .is_some());

        let req = RevokeRequest {
            token: token.clone(),
            token_type_hint: Some("access_token".into()),
            client_id: "rev-001".into(),
            client_secret: "secret-123".into(),
        };
        handler.handle(&req).await.expect("撤销");

        // 撤销后：不存在
        assert!(token_handler
            .get_access_token_record(&token)
            .await
            .unwrap()
            .is_none());
    }

    #[tokio::test]
    async fn revoke_nonexistent_token_returns_ok() {
        let (handler, _, _) = make_handlers();
        handler.store.create(make_client("rev-002")).await.unwrap();

        let req = RevokeRequest {
            token: "nonexistent-token".into(),
            token_type_hint: None,
            client_id: "rev-002".into(),
            client_secret: "secret-123".into(),
        };
        // RFC 7009: 无效 token 也返回成功
        handler.handle(&req).await.expect("应成功");
    }

    #[tokio::test]
    async fn revoke_invalid_client_id() {
        let (handler, _, _) = make_handlers();
        let req = RevokeRequest {
            token: "some-token".into(),
            token_type_hint: None,
            client_id: "no-such".into(),
            client_secret: "secret".into(),
        };
        let err = handler.handle(&req).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("oauth2-server-revoke-invalid-client"));
    }

    #[tokio::test]
    async fn revoke_invalid_client_secret() {
        let (handler, _, _) = make_handlers();
        handler.store.create(make_client("rev-003")).await.unwrap();
        let req = RevokeRequest {
            token: "some-token".into(),
            token_type_hint: None,
            client_id: "rev-003".into(),
            client_secret: "wrong".into(),
        };
        let err = handler.handle(&req).await.unwrap_err();
        assert!(err
            .to_string()
            .contains("oauth2-server-revoke-invalid-client"));
    }
}
