//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 外网路由（面向用户）。
//!
//! 暴露 3 个端点：
//! - `POST /api/v1/auth/login` — 登录，返回 token
//! - `POST /api/v1/auth/logout` — 登出
//! - `POST /api/v1/auth/refresh` — 刷新 token（renew_to_equivalent）
//!
//! # 设计
//!
//! - **State 共享**：通过 `State<Arc<dyn AuthBackend>>` 注入后端
//! - **统一响应**：`BulwarkResult<T>` → `ApiResponse<T>`，错误转为 `error_code` + `message`
//! - **错误码映射**：复用 `BulwarkError::response_parts()` 获取标准错误码

use axum::extract::State;
use axum::routing::post;
use axum::{Json, Router};
use std::sync::Arc;

use crate::backend::types::{ApiResponse, LoginRequest, LogoutRequest, RenewToEquivalentRequest};
use crate::backend::AuthBackend;
use crate::error::BulwarkError;

/// 将 `BulwarkResult<T>` 转换为 `ApiResponse<T>`。
///
/// Ok → `ApiResponse::ok(data)`
/// Err → `ApiResponse::err(error_code, message)`，error_code 来自 `response_parts()`
pub fn to_api_response<T>(result: Result<T, BulwarkError>) -> ApiResponse<T> {
    match result {
        Ok(data) => ApiResponse::ok(data),
        Err(e) => {
            let (_, error_code, message, _) = e.response_parts();
            ApiResponse::err(error_code, message)
        },
    }
}

/// login handler — 执行登录，返回 token。
pub async fn login_handler(
    State(backend): State<Arc<dyn AuthBackend>>,
    Json(req): Json<LoginRequest>,
) -> Json<ApiResponse<String>> {
    let result = backend.login(&req.login_id, &req.params).await;
    Json(to_api_response(result))
}

/// logout handler — 登出指定 token。
pub async fn logout_handler(
    State(backend): State<Arc<dyn AuthBackend>>,
    Json(req): Json<LogoutRequest>,
) -> Json<ApiResponse<()>> {
    let result = backend.logout(&req.token).await;
    Json(to_api_response(result))
}

/// refresh handler — 刷新 token（renew_to_equivalent）。
pub async fn refresh_handler(
    State(backend): State<Arc<dyn AuthBackend>>,
    Json(req): Json<RenewToEquivalentRequest>,
) -> Json<ApiResponse<String>> {
    let result = backend.renew_to_equivalent(&req.token).await;
    Json(to_api_response(result))
}

/// 构建外网路由。
///
/// 调用方负责添加 middleware（如 rate_limit_middleware）。
pub fn external_router(backend: Arc<dyn AuthBackend>) -> Router {
    Router::new()
        .route("/api/v1/auth/login", post(login_handler))
        .route("/api/v1/auth/logout", post(logout_handler))
        .route("/api/v1/auth/refresh", post(refresh_handler))
        .with_state(backend)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::types::LoginParams;
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// 测试用 Mock AuthBackend。
    struct MockAuthBackend;

    #[async_trait]
    impl AuthBackend for MockAuthBackend {
        async fn login(
            &self,
            login_id: &str,
            _params: &LoginParams,
        ) -> Result<String, BulwarkError> {
            Ok(format!("token-{}", login_id))
        }
        async fn logout(&self, _token: &str) -> Result<(), BulwarkError> {
            Ok(())
        }
        async fn check_login(&self, token: &str) -> Result<bool, BulwarkError> {
            Ok(token.starts_with("token-"))
        }
        async fn check_permission(
            &self,
            _token: &str,
            _permission: &str,
        ) -> Result<(), BulwarkError> {
            Ok(())
        }
        async fn check_role(&self, _token: &str, _role: &str) -> Result<(), BulwarkError> {
            Ok(())
        }
        async fn check_safe(&self, _token: &str) -> Result<bool, BulwarkError> {
            Ok(false)
        }
        async fn check_disable(&self, _token: &str) -> Result<bool, BulwarkError> {
            Ok(false)
        }
        async fn check_api_key(
            &self,
            _api_key: &str,
            _namespace: &str,
        ) -> Result<(), BulwarkError> {
            Ok(())
        }
        async fn get_token_info(
            &self,
            token: &str,
        ) -> Result<crate::backend::types::TokenInfo, BulwarkError> {
            Ok(crate::backend::types::TokenInfo {
                token: token.to_string(),
                created_at: 1000,
                last_active_at: 2000,
            })
        }
        async fn get_session(
            &self,
            token: &str,
        ) -> Result<crate::backend::types::SessionData, BulwarkError> {
            Ok(crate::backend::types::SessionData {
                token: token.to_string(),
                login_id: "mock-user".to_string(),
                created_at: 1000,
                last_active_at: 2000,
                attrs: std::collections::HashMap::new(),
                device: None,
                ip: None,
                user_agent: None,
                safe_services: std::collections::HashMap::new(),
                #[cfg(feature = "dynamic-active-timeout")]
                dynamic_active_timeout: None,
                #[cfg(feature = "anonymous-session")]
                is_anon: false,
            })
        }
        async fn kickout(&self, _login_id: &str) -> Result<(), BulwarkError> {
            Ok(())
        }
        async fn switch_to(
            &self,
            _token: &str,
            _target_login_id: &str,
        ) -> Result<(), BulwarkError> {
            Ok(())
        }
        async fn renew_to_equivalent(&self, token: &str) -> Result<String, BulwarkError> {
            Ok(format!("renewed-{}", token))
        }
    }

    fn make_backend() -> Arc<dyn AuthBackend> {
        Arc::new(MockAuthBackend)
    }

    #[tokio::test]
    async fn test_login_handler_returns_token() {
        let app = external_router(make_backend());
        let body = serde_json::json!({
            "login_id": "user1",
            "params": LoginParams::default()
        });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(resp_json["data"], "token-user1");
    }

    #[tokio::test]
    async fn test_logout_handler_succeeds() {
        let app = external_router(make_backend());
        let body = serde_json::json!({ "token": "some-token" });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/logout")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(resp_json.get("error_code").is_none() || resp_json["error_code"].is_null());
    }

    #[tokio::test]
    async fn test_refresh_handler_returns_new_token() {
        let app = external_router(make_backend());
        let body = serde_json::json!({ "token": "old-token" });
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/refresh")
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(resp_json["data"], "renewed-old-token");
    }

    #[tokio::test]
    async fn test_to_api_response_ok() {
        let resp: ApiResponse<String> = to_api_response(Ok("data".to_string()));
        assert_eq!(resp.data.as_deref(), Some("data"));
        assert!(resp.error_code.is_none());
    }

    #[tokio::test]
    async fn test_to_api_response_err() {
        let resp: ApiResponse<String> =
            to_api_response(Err(BulwarkError::InvalidToken("bad token".to_string())));
        assert!(resp.data.is_none());
        assert_eq!(resp.error_code.as_deref(), Some("INVALID_TOKEN"));
    }
}
