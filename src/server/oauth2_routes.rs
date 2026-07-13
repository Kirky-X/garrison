//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OAuth2 HTTP 端点路由（feature = "oauth2-server"）。
//!
//! 将 OAuth2 handler 暴露为 HTTP 端点，集成到 BulwarkAuthServer。
//! 与 sdforge_routes.rs（AuthBackend 路由）互补，使用 axum Router::merge 集成。
//!
//! # 端点
//!
//! - 外网：`GET /oauth2/authorize`、`POST /oauth2/token`、`POST /oauth2/revoke`
//! - 内网：`POST /oauth2/introspect`

#![cfg(feature = "oauth2-server")]

use std::sync::Arc;

use axum::extract::{Extension, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use crate::context::BulwarkPrincipal;
use crate::dao::BulwarkDao;
use crate::oauth2_server::authorize::{AuthorizeHandler, AuthorizeRequest, AuthorizeResponse};
use crate::oauth2_server::client::OAuth2ClientStore;
use crate::oauth2_server::introspect::{IntrospectHandler, IntrospectRequest};
use crate::oauth2_server::revoke::{RevokeHandler, RevokeRequest};
use crate::oauth2_server::token::{TokenHandler, TokenRequest};

/// OAuth2 路由共享状态。
///
/// 持有所有 OAuth2 handler，通过 `Arc<OAuth2State>` 注入到 axum Router。
pub struct OAuth2State {
    /// 授权码流程 handler（/oauth2/authorize）。
    pub authorize_handler: Arc<AuthorizeHandler>,
    /// Token 签发 handler（/oauth2/token，4 种 grant type）。
    pub token_handler: Arc<TokenHandler>,
    /// Token 撤销 handler（/oauth2/revoke，RFC 7009）。
    pub revoke_handler: Arc<RevokeHandler>,
    /// Token 内省 handler（/oauth2/introspect，RFC 7662）。
    pub introspect_handler: Arc<IntrospectHandler>,
}

impl OAuth2State {
    /// 创建 OAuth2State，内部构造 4 个 handler。
    pub fn new(
        store: Arc<dyn OAuth2ClientStore>,
        dao: Arc<dyn BulwarkDao>,
        login_url: String,
    ) -> Self {
        let authorize_handler =
            Arc::new(AuthorizeHandler::new(store.clone(), dao.clone(), login_url));
        let token_handler = Arc::new(TokenHandler::new(
            store.clone(),
            dao.clone(),
            authorize_handler.clone(),
        ));
        let revoke_handler = Arc::new(RevokeHandler::new(store.clone(), token_handler.clone()));
        let introspect_handler = Arc::new(IntrospectHandler::new(store, token_handler.clone()));
        Self {
            authorize_handler,
            token_handler,
            revoke_handler,
            introspect_handler,
        }
    }
}

/// 构建外网 OAuth2 路由（authorize/token/revoke）。
pub fn oauth2_external_router(state: Arc<OAuth2State>) -> Router {
    Router::new()
        .route("/oauth2/authorize", get(authorize_endpoint))
        .route("/oauth2/token", post(token_endpoint))
        .route("/oauth2/revoke", post(revoke_endpoint))
        .with_state(state)
}

/// 构建内网 OAuth2 路由（introspect）。
pub fn oauth2_internal_router(state: Arc<OAuth2State>) -> Router {
    Router::new()
        .route("/oauth2/introspect", post(introspect_endpoint))
        .with_state(state)
}

// === HTTP 端点函数（薄包装，调用 handler） ===

async fn authorize_endpoint(
    State(state): State<Arc<OAuth2State>>,
    Query(req): Query<AuthorizeRequest>,
    principal: Option<Extension<BulwarkPrincipal>>,
) -> Response {
    // 从 BulwarkPrincipal Extension 提取 user_id（无 principal 或 login_id 解析失败 → None → LoginRequired）
    let user_id: Option<i64> = principal.and_then(|ext| ext.0.login_id.parse::<i64>().ok());
    match state.authorize_handler.authorize(&req, user_id).await {
        Ok(AuthorizeResponse::Redirect { location }) => {
            (StatusCode::FOUND, [("Location", location)]).into_response()
        },
        Ok(AuthorizeResponse::LoginRequired { login_url }) => {
            (StatusCode::FOUND, [("Location", login_url)]).into_response()
        },
        Err(e) => {
            let (_, error_code, message, _) = e.response_parts();
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": error_code, "message": message })),
            )
                .into_response()
        },
    }
}

async fn token_endpoint(
    State(state): State<Arc<OAuth2State>>,
    Json(req): Json<TokenRequest>,
) -> Response {
    match state.token_handler.handle(&req).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(e) => {
            let (_, error_code, message, _) = e.response_parts();
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": error_code, "message": message })),
            )
                .into_response()
        },
    }
}

async fn revoke_endpoint(
    State(state): State<Arc<OAuth2State>>,
    Json(req): Json<RevokeRequest>,
) -> Response {
    match state.revoke_handler.handle(&req).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => {
            let (_, error_code, message, _) = e.response_parts();
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": error_code, "message": message })),
            )
                .into_response()
        },
    }
}

async fn introspect_endpoint(
    State(state): State<Arc<OAuth2State>>,
    Json(req): Json<IntrospectRequest>,
) -> Response {
    match state.introspect_handler.handle(&req).await {
        Ok(resp) => (StatusCode::OK, Json(resp)).into_response(),
        Err(e) => {
            let (_, error_code, message, _) = e.response_parts();
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": error_code, "message": message })),
            )
                .into_response()
        },
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::{BulwarkDao, MockDao};
    use crate::oauth2_server::client::{
        DaoOAuth2ClientStore, GrantType, OAuth2Client, OAuth2ClientStore,
    };
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// 创建测试用 OAuth2State + store（用于注册客户端）。
    fn make_state() -> (Arc<OAuth2State>, Arc<dyn OAuth2ClientStore>) {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let store: Arc<dyn OAuth2ClientStore> = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
        let state = Arc::new(OAuth2State::new(
            store.clone(),
            dao,
            "https://auth.example.com/login".to_string(),
        ));
        (state, store)
    }

    /// 创建测试用 OAuth2Client（支持 AuthorizationCode + ClientCredentials）。
    fn make_test_client(id: &str) -> OAuth2Client {
        OAuth2Client::new(
            id,
            "secret-123",
            vec!["https://app.example.com/cb".into()],
            vec![GrantType::AuthorizationCode, GrantType::ClientCredentials],
            vec!["read".into()],
        )
        .unwrap()
    }

    // === OAuth2State 构造测试 ===

    #[test]
    fn test_oauth2_state_construction() {
        let (state, _) = make_state();
        // authorize_handler 被 state + token_handler 共享 → strong_count = 2
        assert_eq!(Arc::strong_count(&state.authorize_handler), 2);
        // token_handler 被 state + revoke_handler + introspect_handler 共享 → strong_count = 3
        assert_eq!(Arc::strong_count(&state.token_handler), 3);
        // revoke_handler / introspect_handler 仅被 state 持有 → strong_count = 1
        assert_eq!(Arc::strong_count(&state.revoke_handler), 1);
        assert_eq!(Arc::strong_count(&state.introspect_handler), 1);
    }

    // === 路由存在性测试 ===

    #[tokio::test]
    async fn test_oauth2_external_router_has_authorize_route() {
        let (state, store) = make_state();
        store.create(make_test_client("route-auth")).await.unwrap();
        let app = oauth2_external_router(state);
        // 无 query string → Query 提取失败 → 400（非 404 证明路由存在）
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/oauth2/authorize")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_oauth2_external_router_has_token_route() {
        let (state, _) = make_state();
        let app = oauth2_external_router(state);
        // 空 JSON body → Json 提取失败 → 400（非 404 证明路由存在）
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_oauth2_external_router_has_revoke_route() {
        let (state, _) = make_state();
        let app = oauth2_external_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/revoke")
                    .header("content-type", "application/json")
                    .body(Body::from("{}"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_oauth2_internal_router_has_introspect_route() {
        let (state, store) = make_state();
        store.create(make_test_client("route-int")).await.unwrap();
        let app = oauth2_internal_router(state);
        let body = serde_json::json!({
            "token": "nonexistent",
            "client_id": "route-int",
            "client_secret": "secret-123",
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/introspect")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // token 不存在 → active=false，但返回 200 OK
        assert_eq!(resp.status(), StatusCode::OK);
    }

    // === 端点行为测试 ===

    #[tokio::test]
    async fn test_authorize_endpoint_redirects_when_not_logged_in() {
        let (state, store) = make_state();
        store.create(make_test_client("auth-redir")).await.unwrap();
        let app = oauth2_external_router(state);
        let uri = "/oauth2/authorize?response_type=code&client_id=auth-redir&redirect_uri=https://app.example.com/cb&code_challenge=test-challenge&code_challenge_method=S256";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp
            .headers()
            .get("Location")
            .expect("Location header 必须存在")
            .to_str()
            .unwrap();
        assert!(
            location.starts_with("https://auth.example.com/login"),
            "应重定向到登录页，实际: {location}"
        );
    }

    /// T003: 有 BulwarkPrincipal（Extension）时 authorize 端点返回 Redirect 含 code。
    /// principal.login_id = "1001" → user_id = Some(1001) → 授权成功 → Redirect。
    #[tokio::test]
    async fn test_authorize_endpoint_returns_redirect_with_code_when_principal_present() {
        let (state, store) = make_state();
        store
            .create(make_test_client("auth-principal"))
            .await
            .unwrap();
        let app = oauth2_external_router(state).layer(Extension(BulwarkPrincipal {
            login_id: "1001".to_string(),
        }));
        let uri = "/oauth2/authorize?response_type=code&client_id=auth-principal&redirect_uri=https://app.example.com/cb&code_challenge=test-challenge&code_challenge_method=S256";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp
            .headers()
            .get("Location")
            .expect("Location header 必须存在")
            .to_str()
            .unwrap();
        assert!(
            location.starts_with("https://app.example.com/cb?code="),
            "有 principal 时应重定向到 redirect_uri 含 code，实际: {location}"
        );
    }

    /// T003: 无 BulwarkPrincipal（Extension 缺失）时 authorize 端点返回 LoginRequired。
    #[tokio::test]
    async fn test_authorize_endpoint_returns_login_required_when_no_principal() {
        let (state, store) = make_state();
        store
            .create(make_test_client("auth-no-principal"))
            .await
            .unwrap();
        // 无 .layer(Extension(...)) → principal 提取为 None
        let app = oauth2_external_router(state);
        let uri = "/oauth2/authorize?response_type=code&client_id=auth-no-principal&redirect_uri=https://app.example.com/cb&code_challenge=test-challenge&code_challenge_method=S256";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp
            .headers()
            .get("Location")
            .expect("Location header 必须存在")
            .to_str()
            .unwrap();
        assert!(
            location.starts_with("https://auth.example.com/login"),
            "无 principal 应重定向到登录页，实际: {location}"
        );
    }

    #[tokio::test]
    async fn test_token_endpoint_returns_bad_request_on_invalid_client() {
        let (state, _) = make_state();
        let app = oauth2_external_router(state);
        let body = serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": "no-such-client",
            "client_secret": "secret",
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_revoke_endpoint_returns_no_content_on_success() {
        let (state, store) = make_state();
        store.create(make_test_client("rev-ok")).await.unwrap();
        let app = oauth2_external_router(state);

        // 1. 先通过 client_credentials 签发 token
        let issue_body = serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": "rev-ok",
            "client_secret": "secret-123",
        });
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/json")
                    .body(Body::from(issue_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let token_resp: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let token = token_resp["access_token"].as_str().expect("access_token");

        // 2. 撤销 token
        let revoke_body = serde_json::json!({
            "token": token,
            "client_id": "rev-ok",
            "client_secret": "secret-123",
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/revoke")
                    .header("content-type", "application/json")
                    .body(Body::from(revoke_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }
}
