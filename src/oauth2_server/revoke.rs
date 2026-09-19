// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! /oauth2/revoke 端点 — RFC 7009 token 撤销。
//!
//! 撤销 access_token 或 refresh_token，token 失效后立即不可用。
//! RFC 7009 §2.2：token 无效 / 已撤销 / 撤销过程出现瞬态错误时，
//! 仍向客户端返回成功，不暴露 token 状态与服务器内部状态；
//! 仅客户端认证失败（invalid_client）返回错误——client_id 与 client_secret
//! 错误使用同一错误串，防止枚举有效 client_id。
//! 另：客户端只能撤销归属自己的 token（记录 client_id 比对），
//! 他人 token 一律视为无效 token 处理。

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
    /// - `Ok(())`：撤销成功；或 token 无效 / 归属其他 client / 撤销过程出现
    ///   瞬态错误（RFC 7009 §2.2 要求一律返回成功，不暴露内部状态）
    /// - `Err`：客户端认证失败（统一 invalid_client 错误串，防枚举）
    pub async fn handle(&self, req: &RevokeRequest) -> GarrisonResult<()> {
        // 1. 客户端认证
        // invalid-client 与 invalid-client-secret 统一为单一错误串
        // （RFC 6749 invalid_client），错误码差异会泄露 client_id 是否有效。
        let client = match self.store.get(&req.client_id).await? {
            Some(c) => c,
            None => {
                return Err(GarrisonError::OAuth2(
                    "oauth2-server-revoke-invalid-client".into(),
                ));
            },
        };
        if !client.verify_secret(&req.client_secret)? {
            return Err(GarrisonError::OAuth2(
                "oauth2-server-revoke-invalid-client".into(),
            ));
        }

        // 2. 撤销 token —— 认证通过后的任何失败（含 DAO 瞬态错误）均不得作为
        // 错误返回给客户端（RFC 7009 §2.2），记录告警后返回成功。
        if let Err(e) = self.revoke_owned_token(req).await {
            tracing::warn!(
                error = %e,
                "oauth2-server-revoke: revocation failed, returning success per RFC 7009 §2.2"
            );
        }
        Ok(())
    }

    /// 撤销归属于该 client 的 token（RFC 7009 §2.1：客户端只能撤销自己的 token）。
    ///
    /// 按提示（或 access 优先）定位 token 记录，比对 `client_id`：
    /// 记录不存在或归属其他 client 时，一律按无效 token 处理——不撤销、成功返回，
    /// 防止任意合法客户端探测 / 撤销他人 token。
    async fn revoke_owned_token(&self, req: &RevokeRequest) -> GarrisonResult<()> {
        let record = match req.token_type_hint.as_deref() {
            Some("refresh_token") => {
                match self
                    .token_handler
                    .get_refresh_token_record(&req.token)
                    .await?
                {
                    Some(r) => Some(r),
                    None => {
                        self.token_handler
                            .get_access_token_record(&req.token)
                            .await?
                    },
                }
            },
            _ => {
                match self
                    .token_handler
                    .get_access_token_record(&req.token)
                    .await?
                {
                    Some(r) => Some(r),
                    None => {
                        self.token_handler
                            .get_refresh_token_record(&req.token)
                            .await?
                    },
                }
            },
        };
        match record {
            Some(record) if record.client_id == req.client_id => {
                self.token_handler.revoke_token(&req.token).await
            },
            // token 不存在，或归属其他 client（视为无效 token，RFC 7009 §2.2）
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::InMemoryDao;
    use crate::oauth2_server::authorize::AuthorizeHandler;
    use crate::oauth2_server::client::{DaoOAuth2ClientStore, GrantType, OAuth2Client};
    use crate::oauth2_server::token::{
        PasswordRateLimiter, TokenHandler, TokenRateLimiter, TokenRequest,
    };

    /// 创建测试用 handler 和 DAO。
    fn make_handlers() -> (RevokeHandler, Arc<InMemoryDao>, Arc<TokenHandler>) {
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
            authorize_handler,
            Arc::new(PasswordRateLimiter::new(1000, 300)),
            Arc::new(TokenRateLimiter::with_limits(100_000, 60, 100_000, 60)),
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

    /// 防枚举：client_id 不存在与 client_secret 错误必须返回完全相同的错误串，
    /// 不得让攻击者通过错误差异探测有效 client_id。
    #[tokio::test]
    async fn revoke_invalid_client_and_secret_are_indistinguishable() {
        let (handler, _, _) = make_handlers();
        handler
            .store
            .create(make_client("rev-enum-001"))
            .await
            .unwrap();

        let bad_id = RevokeRequest {
            token: "some-token".into(),
            token_type_hint: None,
            client_id: "no-such-client".into(),
            client_secret: "secret-123".into(),
        };
        let bad_secret = RevokeRequest {
            token: "some-token".into(),
            token_type_hint: None,
            client_id: "rev-enum-001".into(),
            client_secret: "wrong".into(),
        };
        let err_id = handler.handle(&bad_id).await.unwrap_err().to_string();
        let err_secret = handler.handle(&bad_secret).await.unwrap_err().to_string();
        assert_eq!(
            err_id, err_secret,
            "invalid-client 与 invalid-client-secret 必须统一为单一 invalid_client 错误"
        );
        // 错误串不得回显 client_id（枚举辅助信息）
        assert!(!err_id.contains("no-such-client"));
    }

    /// 归属校验：客户端不得撤销归属其他 client 的 token（RFC 7009 §2.1）。
    /// 他人 token 一律按无效 token 处理：返回成功但不执行撤销。
    #[tokio::test]
    async fn revoke_rejects_token_owned_by_other_client() {
        let (handler, _, token_handler) = make_handlers();
        handler
            .store
            .create(make_client("rev-owner-001"))
            .await
            .unwrap();
        handler
            .store
            .create(make_client("rev-attacker-001"))
            .await
            .unwrap();
        let victim_token = issue_token(&token_handler, "rev-owner-001").await;

        // 攻击者（合法注册客户端）尝试撤销他人 token
        let req = RevokeRequest {
            token: victim_token.clone(),
            token_type_hint: Some("access_token".into()),
            client_id: "rev-attacker-001".into(),
            client_secret: "secret-123".into(),
        };
        // RFC 7009 §2.2：视为无效 token，返回成功
        handler.handle(&req).await.expect("应返回成功");

        // 但受害者的 token 仍然有效（未被撤销）
        assert!(
            token_handler
                .get_access_token_record(&victim_token)
                .await
                .unwrap()
                .is_some(),
            "归属其他 client 的 token 不得被撤销"
        );

        // 属主自己撤销 → 成功且 token 失效
        let own_req = RevokeRequest {
            token: victim_token.clone(),
            token_type_hint: Some("access_token".into()),
            client_id: "rev-owner-001".into(),
            client_secret: "secret-123".into(),
        };
        handler.handle(&own_req).await.expect("属主撤销应成功");
        assert!(token_handler
            .get_access_token_record(&victim_token)
            .await
            .unwrap()
            .is_none());
    }
}
