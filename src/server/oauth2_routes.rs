//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! OAuth2 HTTP 端点路由（feature = "oauth2-server"）。
//!
//! 将 OAuth2 handler 暴露为 HTTP 端点，集成到 GarrisonAuthServer。
//! 与 sdforge_routes.rs（AuthBackend 路由）互补，使用 axum Router::merge 集成。
//!
//! # 端点
//!
//! - 外网：`GET /oauth2/authorize`、`POST /oauth2/token`、`POST /oauth2/revoke`
//! - 内网：`POST /oauth2/introspect`

#![cfg(feature = "oauth2-server")]

use std::sync::Arc;

use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use crate::context::GarrisonPrincipal;
use crate::dao::GarrisonDao;
use crate::oauth2_server::authorize::{AuthorizeHandler, AuthorizeRequest, AuthorizeResponse};
use crate::oauth2_server::client::OAuth2ClientStore;
use crate::oauth2_server::introspect::{IntrospectHandler, IntrospectRequest};
use crate::oauth2_server::revoke::{RevokeHandler, RevokeRequest};
use crate::oauth2_server::token::{
    PasswordRateLimiter, TokenHandler, TokenRateLimiter, TokenRequest,
};

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
    ///
    /// TokenHandler 以安全默认参数构造限速组件（`PasswordRateLimiter::new(5, 300)`
    /// 账户锁定 + `TokenRateLimiter::new()` 端点 QPS 限制），不提供
    /// "未注入 = 无防护"的构造形态。
    pub fn new(
        store: Arc<dyn OAuth2ClientStore>,
        dao: Arc<dyn GarrisonDao>,
        login_url: String,
    ) -> Self {
        let authorize_handler =
            Arc::new(AuthorizeHandler::new(store.clone(), dao.clone(), login_url));
        let token_handler = Arc::new(TokenHandler::new(
            store.clone(),
            dao.clone(),
            authorize_handler.clone(),
            Arc::new(PasswordRateLimiter::new(5, 300)),
            Arc::new(TokenRateLimiter::new()),
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

/// 请求体大小上限（防 DoS：OAuth2 端点参数均为短字符串，64KB 足够）。
const OAUTH2_BODY_LIMIT: usize = 64 * 1024;

/// RFC 6749 §5.1 / §5.2 — token 端点所有响应（含错误）必须带 no-store 缓存头。
fn apply_no_store(mut resp: Response) -> Response {
    let headers = resp.headers_mut();
    headers.insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-store"),
    );
    headers.insert(
        HeaderName::from_static("pragma"),
        HeaderValue::from_static("no-cache"),
    );
    resp
}

/// percent-decode `application/x-www-form-urlencoded` 的键/值（`+` 视为空格）。
fn form_percent_decode(input: &[u8]) -> String {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            },
            b'%' if i + 2 < input.len() => {
                let hex = std::str::from_utf8(&input[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                    },
                    None => {
                        out.push(b'%');
                        i += 1;
                    },
                }
            },
            b => {
                out.push(b);
                i += 1;
            },
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 将 `application/x-www-form-urlencoded` body 解析为 `serde_json::Value` 对象，
/// 复用请求结构体的 `serde_json` 反序列化路径（RFC 6749 §3.2 表单格式，ocr #7612）。
fn parse_form_body(body: &[u8]) -> Result<serde_json::Value, String> {
    let mut map = serde_json::Map::new();
    for pair in body.split(|&b| b == b'&') {
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, |&b| b == b'=');
        let key = form_percent_decode(it.next().unwrap_or_default());
        let value = form_percent_decode(it.next().unwrap_or_default());
        if key.is_empty() {
            return Err("empty form field name".to_string());
        }
        map.insert(key, serde_json::Value::String(value));
    }
    Ok(serde_json::Value::Object(map))
}

/// 按 Content-Type 提取请求结构体：仅接受 `application/x-www-form-urlencoded`
///（RFC 6749 §3.2 / RFC 7009 §2.1 / RFC 7662 §2.2 规定的唯一请求格式）。
///
/// Content-Type 缺失或为其他类型（含 `application/json`）返回
/// 415 Unsupported Media Type；表单解析或字段校验失败返回
/// 400 + RFC 6749 §5.2 `invalid_request` 错误体（均带 no-store 头）。
fn extract_oauth2_request<T: serde::de::DeserializeOwned>(
    content_type: Option<&str>,
    body: &[u8],
) -> Result<T, Box<Response>> {
    let is_form = content_type
        .map(|ct| ct.starts_with("application/x-www-form-urlencoded"))
        .unwrap_or(false);
    if !is_form {
        return Err(Box::new(apply_no_store(
            (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                Json(json!({
                    "error": "invalid_request",
                    "message": "Content-Type must be application/x-www-form-urlencoded"
                })),
            )
                .into_response(),
        )));
    }
    match parse_form_body(body).and_then(|v| serde_json::from_value(v).map_err(|e| e.to_string())) {
        Ok(req) => Ok(req),
        Err(e) => Err(Box::new(apply_no_store(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_request", "message": e })),
            )
                .into_response(),
        ))),
    }
}

/// 429 判定（ocr #2224）：token/revoke handler 的速率限制错误统一以
/// `GarrisonError::OAuth2("rate_limited: ...")` 形态产出（见
/// `oauth2_server::token` 的 `TokenRateLimiter` / `PasswordRateLimiter`）。
/// 本框架的 `GarrisonError` 尚无独立的限速变体，此处按「变体 + 消息前缀」
/// 做类型化匹配（比此前对整个 `Display` 做子串匹配更严格、不受错误文案后续
/// 变化影响），并在 token.rs 侧维持 `rate_limited` 前缀契约。
fn is_rate_limited_error(e: &crate::error::GarrisonError) -> bool {
    matches!(e, crate::error::GarrisonError::OAuth2(msg) if msg.starts_with("rate_limited"))
}

async fn authorize_endpoint(
    State(state): State<Arc<OAuth2State>>,
    Query(req): Query<AuthorizeRequest>,
    principal: Option<Extension<GarrisonPrincipal>>,
) -> Response {
    // 从 GarrisonPrincipal Extension 提取 user_id（无 principal 或 login_id 解析失败 → None → LoginRequired）
    let user_id: Option<i64> = principal.and_then(|ext| ext.0.login_id.parse::<i64>().ok());
    match state.authorize_handler.authorize(&req, user_id).await {
        Ok(AuthorizeResponse::Redirect { location }) => {
            (StatusCode::FOUND, [("Location", location)]).into_response()
        },
        Ok(AuthorizeResponse::LoginRequired { login_url }) => {
            (StatusCode::FOUND, [("Location", login_url)]).into_response()
        },
        Err(e) => {
            let (_, error_code, message, _) = e.response_parts_i18n();
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
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // 提取 Authorization 头（RFC 6749 §2.3.1 HTTP Basic Auth）
    let authorization = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // RFC 6749 §3.2：/token 仅接受 application/x-www-form-urlencoded
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    if body.len() > OAUTH2_BODY_LIMIT {
        return apply_no_store(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_request", "message": "request body too large" })),
            )
                .into_response(),
        );
    }
    let req: TokenRequest = match extract_oauth2_request(content_type, &body) {
        Ok(req) => req,
        Err(resp) => return *resp,
    };

    match state
        .token_handler
        .handle_with_authorization(&req, authorization.as_deref())
        .await
    {
        Ok(resp) => {
            // RFC 6749 §5.1 — token 响应必须含 Cache-Control: no-store + Pragma: no-cache
            apply_no_store((StatusCode::OK, Json(resp)).into_response())
        },
        Err(e) => {
            let (_, error_code, message, _) = e.response_parts_i18n();
            // RFC 6585 §4 — 速率限制错误返回 429 Too Many Requests。
            // ocr #2224：按 GarrisonError::OAuth2 变体 + "rate_limited" 消息前缀
            // 类型化判定（不再对整个 Display 做任意子串匹配）。
            let is_rate_limited = is_rate_limited_error(&e);
            let status = if is_rate_limited {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::BAD_REQUEST
            };
            let body_error: &str = if is_rate_limited {
                "RATE_LIMIT_EXCEEDED"
            } else {
                error_code
            };
            // RFC 6749 §5.1 — token 端点错误响应同样必须 no-store（ocr #2883）
            apply_no_store(
                (
                    status,
                    Json(json!({ "error": body_error, "message": message })),
                )
                    .into_response(),
            )
        },
    }
}

async fn revoke_endpoint(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    let req: RevokeRequest = match extract_oauth2_request(content_type, &body) {
        Ok(req) => req,
        Err(resp) => return *resp,
    };
    match state.revoke_handler.handle(&req).await {
        // RFC 7662 §2.2 — introspect/revoke 响应应带 no-store 缓存控制
        Ok(()) => apply_no_store(StatusCode::NO_CONTENT.into_response()),
        Err(e) => {
            let (_, error_code, message, _) = e.response_parts_i18n();
            apply_no_store(
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": error_code, "message": message })),
                )
                    .into_response(),
            )
        },
    }
}

async fn introspect_endpoint(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    let req: IntrospectRequest = match extract_oauth2_request(content_type, &body) {
        Ok(req) => req,
        Err(resp) => return *resp,
    };
    match state.introspect_handler.handle(&req).await {
        Ok(resp) => apply_no_store((StatusCode::OK, Json(resp)).into_response()),
        Err(e) => {
            let (_, error_code, message, _) = e.response_parts_i18n();
            apply_no_store(
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": error_code, "message": message })),
                )
                    .into_response(),
            )
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::{GarrisonDao, InMemoryDao};
    use crate::oauth2_server::client::{
        DaoOAuth2ClientStore, GrantType, OAuth2Client, OAuth2ClientStore,
    };
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// 创建测试用 OAuth2State + store（用于注册客户端）。
    fn make_state() -> (Arc<OAuth2State>, Arc<dyn OAuth2ClientStore>) {
        let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
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
        // 表单 body 缺字段 → 400（非 404 证明路由存在）
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("grant_type=client_credentials"))
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
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("token=x&client_id=c&client_secret=s"))
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
        let body = "token=nonexistent&client_id=route-int&client_secret=secret-123";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/introspect")
                    .header("content-type", "application/x-www-form-urlencoded")
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

    /// 有 GarrisonPrincipal（Extension）时 authorize 端点返回 Redirect 含 code。
    /// principal.login_id = "1001" → user_id = Some(1001) → 授权成功 → Redirect。
    #[tokio::test]
    async fn test_authorize_endpoint_returns_redirect_with_code_when_principal_present() {
        let (state, store) = make_state();
        store
            .create(make_test_client("auth-principal"))
            .await
            .unwrap();
        let app = oauth2_external_router(state).layer(Extension(GarrisonPrincipal {
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

    /// 无 GarrisonPrincipal（Extension 缺失）时 authorize 端点返回 LoginRequired。
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
        let body = "grant_type=client_credentials&client_id=no-such-client&client_secret=secret";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// token 端点成功响应必须含 Cache-Control: no-store + Pragma: no-cache（RFC 6749 §5.1）。
    #[tokio::test]
    async fn test_token_endpoint_returns_cache_control_no_store_header() {
        let (state, store) = make_state();
        store.create(make_test_client("cc-cid")).await.unwrap();
        let app = oauth2_external_router(state);
        let body = "grant_type=client_credentials&client_id=cc-cid&client_secret=secret-123";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // RFC 6749 §5.1 — 必须含 Cache-Control: no-store
        let cache_control = resp
            .headers()
            .get("cache-control")
            .expect("Cache-Control 头必须存在");
        assert_eq!(
            cache_control.to_str().unwrap(),
            "no-store",
            "Cache-Control 必须为 no-store"
        );
        // RFC 6749 §5.1 — 必须含 Pragma: no-cache
        let pragma = resp.headers().get("pragma").expect("Pragma 头必须存在");
        assert_eq!(
            pragma.to_str().unwrap(),
            "no-cache",
            "Pragma 必须为 no-cache"
        );
    }

    /// token 端点接受 HTTP Basic Auth 头认证客户端（RFC 6749 §2.3.1）。
    #[tokio::test]
    async fn test_token_endpoint_accepts_basic_auth_header() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let (state, store) = make_state();
        store.create(make_test_client("basic-cid")).await.unwrap();
        let app = oauth2_external_router(state);
        // "basic-cid:secret-123" → base64
        let credentials = STANDARD.encode("basic-cid:secret-123");
        let auth_header = format!("Basic {}", credentials);
        let body = "grant_type=client_credentials";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("authorization", &auth_header)
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Basic Auth 认证应成功，body 留空"
        );
    }

    #[tokio::test]
    async fn test_revoke_endpoint_returns_no_content_on_success() {
        let (state, store) = make_state();
        store.create(make_test_client("rev-ok")).await.unwrap();
        let app = oauth2_external_router(state);

        // 1. 先通过 client_credentials 签发 token
        let issue_body = "grant_type=client_credentials&client_id=rev-ok&client_secret=secret-123";
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(issue_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let token_resp: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let token = token_resp["access_token"].as_str().expect("access_token");

        // 2. 撤销 token（RFC 7009 §2.1 表单格式）
        let revoke_body = format!("token={}&client_id=rev-ok&client_secret=secret-123", token);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/revoke")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(revoke_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    // === /token 端点速率限制测试（B5）===

    /// /token 端点超速率限制时返回 429 Too Many Requests（RFC 6585 §4）。
    ///
    /// 注入 `TokenRateLimiter`（client_max=1），第 2 次请求应返回 429 + `RATE_LIMIT_EXCEEDED`。
    #[tokio::test]
    async fn test_token_endpoint_returns_429_on_rate_limit_exceeded() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
        let store: Arc<dyn OAuth2ClientStore> = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
        let authorize_handler = Arc::new(AuthorizeHandler::new(
            store.clone(),
            dao.clone(),
            "https://auth.example.com/login".to_string(),
        ));
        let token_handler = Arc::new(TokenHandler::new(
            store.clone(),
            dao.clone(),
            authorize_handler.clone(),
            Arc::new(PasswordRateLimiter::new(1000, 300)),
            Arc::new(TokenRateLimiter::with_limits(1, 60, 100, 60)),
        ));
        let revoke_handler = Arc::new(RevokeHandler::new(store.clone(), token_handler.clone()));
        let introspect_handler =
            Arc::new(IntrospectHandler::new(store.clone(), token_handler.clone()));
        let state = Arc::new(OAuth2State {
            authorize_handler,
            token_handler,
            revoke_handler,
            introspect_handler,
        });

        store.create(make_test_client("rl-429")).await.unwrap();
        let app = oauth2_external_router(state);

        let body = "grant_type=client_credentials&client_id=rl-429&client_secret=secret-123";

        // 第 1 次成功（200 OK）
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // 第 2 次被限速（429 Too Many Requests）
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "超速率限制应返回 429"
        );

        // 验证响应体含 RATE_LIMIT_EXCEEDED error code
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            resp_json["error"].as_str().unwrap(),
            "RATE_LIMIT_EXCEEDED",
            "error code 应为 RATE_LIMIT_EXCEEDED"
        );
    }

    /// /token 端点非 rate_limited 错误返回 400（与限速 429 区分）。
    #[tokio::test]
    async fn test_token_endpoint_returns_400_on_non_rate_limited_error() {
        let (state, store) = make_state();
        store.create(make_test_client("nrl-400")).await.unwrap();
        let app = oauth2_external_router(state);

        // 用错误 client_secret 触发 OAuth2 错误（非 rate_limited）
        let body = "grant_type=client_credentials&client_id=nrl-400&client_secret=wrong-secret";

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // 非 rate_limited 错误应返回 400（非 429）
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    // === 表单格式（RFC 6749 §3.2）+ 错误响应 no-store 测试（ocr #7612 / #2883）===

    /// token 端点接受 application/x-www-form-urlencoded 请求体（RFC 6749 §3.2）。
    #[tokio::test]
    async fn test_token_endpoint_accepts_form_urlencoded() {
        let (state, store) = make_state();
        store.create(make_test_client("form-tok")).await.unwrap();
        let app = oauth2_external_router(state);
        let body = "grant_type=client_credentials&client_id=form-tok&client_secret=secret-123";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header(
                        "content-type",
                        "application/x-www-form-urlencoded;charset=UTF-8",
                    )
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "表单编码的 token 请求应被接受（RFC 6749 §3.2）"
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(resp_json["access_token"].as_str().is_some());
    }

    /// token 端点表单体支持 percent-encoding 与 `+` 空格。
    #[test]
    fn parse_form_body_decodes_percent_and_plus() {
        let value =
            parse_form_body(b"grant_type=password&username=a%40b.com+cd%26x&code=%E4%B8%AD")
                .unwrap();
        assert_eq!(value["username"], "a@b.com cd&x");
        assert_eq!(value["code"], "中");
    }

    /// 畸形请求体返回 400 + invalid_request（不再 panic / 500）。
    #[tokio::test]
    async fn test_token_endpoint_malformed_body_returns_400_invalid_request() {
        let (state, _) = make_state();
        let app = oauth2_external_router(state);
        // 空字段名 → parse_form_body 解析失败
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("grant_type=a&=b"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let cache_control = resp
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let pragma = resp
            .headers()
            .get("pragma")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(resp_json["error"], "invalid_request");
        // 错误响应同样必须 no-store（RFC 6749 §5.1）
        assert_eq!(cache_control.as_deref(), Some("no-store"));
        assert_eq!(pragma.as_deref(), Some("no-cache"));
    }

    /// Content-Type 缺失时返回 415 Unsupported Media Type（RFC 6749 §3.2 唯一格式）。
    #[tokio::test]
    async fn test_token_endpoint_missing_content_type_returns_415() {
        let (state, _) = make_state();
        let app = oauth2_external_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .body(Body::from(
                        "grant_type=client_credentials&client_id=x&client_secret=y",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
    }

    /// Content-Type 为 `application/json` 时返回 415（JSON 已不再被接受）。
    #[tokio::test]
    async fn test_token_endpoint_json_content_type_returns_415() {
        let (state, _) = make_state();
        let app = oauth2_external_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"grant_type":"client_credentials"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(resp_json["error"], "invalid_request");
    }
}
