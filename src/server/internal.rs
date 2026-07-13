//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 内网路由（服务间调用）。
//!
//! 暴露 12 个端点：
//! - `POST /api/v1/auth/check-login` — 校验登录状态
//! - `POST /api/v1/auth/check-permission` — 校验权限
//! - `POST /api/v1/auth/check-role` — 校验角色
//! - `POST /api/v1/auth/check-safe` — 校验二级认证
//! - `POST /api/v1/auth/check-disable` — 校验封禁状态
//! - `POST /api/v1/auth/check-api-key` — 校验 API Key
//! - `POST /api/v1/auth/get-token-info` — 获取 token 信息
//! - `POST /api/v1/auth/get-session` — 获取 session
//! - `POST /api/v1/auth/kickout` — 踢出登录主体
//! - `POST /api/v1/auth/switch-to` — 切换登录主体
//! - `POST /api/v1/auth/renew-to-equivalent` — 续期 token
//! - `GET /api/v1/auth/health` — 健康检查
//!
//! # 设计
//!
//! - **State 共享**：通过 `State<Arc<dyn AuthBackend>>` 注入后端
//! - **错误码映射**：复用 `external::to_api_response` 逻辑
//! - **无请求体端点**：`GET /health` 直接返回 `ApiResponse::ok("ok")`

use axum::extract::State;
use axum::routing::{get, post};
use axum::{Json, Router};
use std::sync::Arc;

use crate::backend::types::{
    ApiResponse, CheckApiKeyRequest, CheckLoginRequest, CheckPermissionRequest, CheckRoleRequest,
    KickoutRequest, SessionData, SwitchToRequest, TokenInfo,
};
use crate::backend::AuthBackend;

// 复用 external 的错误转换逻辑（避免重复实现 — Rule 8）
use super::external::to_api_response;

/// check-login handler。
pub async fn check_login_handler(
    State(backend): State<Arc<dyn AuthBackend>>,
    Json(req): Json<CheckLoginRequest>,
) -> Json<ApiResponse<bool>> {
    let result = backend.check_login(&req.token).await;
    Json(to_api_response(result))
}

/// check-permission handler。
pub async fn check_permission_handler(
    State(backend): State<Arc<dyn AuthBackend>>,
    Json(req): Json<CheckPermissionRequest>,
) -> Json<ApiResponse<()>> {
    let result = backend.check_permission(&req.token, &req.permission).await;
    Json(to_api_response(result))
}

/// check-role handler。
pub async fn check_role_handler(
    State(backend): State<Arc<dyn AuthBackend>>,
    Json(req): Json<CheckRoleRequest>,
) -> Json<ApiResponse<()>> {
    let result = backend.check_role(&req.token, &req.role).await;
    Json(to_api_response(result))
}

/// check-safe handler。
pub async fn check_safe_handler(
    State(backend): State<Arc<dyn AuthBackend>>,
    Json(req): Json<CheckLoginRequest>,
) -> Json<ApiResponse<bool>> {
    let result = backend.check_safe(&req.token).await;
    Json(to_api_response(result))
}

/// check-disable handler。
pub async fn check_disable_handler(
    State(backend): State<Arc<dyn AuthBackend>>,
    Json(req): Json<CheckLoginRequest>,
) -> Json<ApiResponse<bool>> {
    let result = backend.check_disable(&req.token).await;
    Json(to_api_response(result))
}

/// check-api-key handler。
pub async fn check_api_key_handler(
    State(backend): State<Arc<dyn AuthBackend>>,
    Json(req): Json<CheckApiKeyRequest>,
) -> Json<ApiResponse<()>> {
    let result = backend.check_api_key(&req.api_key, &req.namespace).await;
    Json(to_api_response(result))
}

/// get-token-info handler。
pub async fn get_token_info_handler(
    State(backend): State<Arc<dyn AuthBackend>>,
    Json(req): Json<CheckLoginRequest>,
) -> Json<ApiResponse<TokenInfo>> {
    let result = backend.get_token_info(&req.token).await;
    Json(to_api_response(result))
}

/// get-session handler。
pub async fn get_session_handler(
    State(backend): State<Arc<dyn AuthBackend>>,
    Json(req): Json<CheckLoginRequest>,
) -> Json<ApiResponse<SessionData>> {
    let result = backend.get_session(&req.token).await;
    Json(to_api_response(result))
}

/// kickout handler。
pub async fn kickout_handler(
    State(backend): State<Arc<dyn AuthBackend>>,
    Json(req): Json<KickoutRequest>,
) -> Json<ApiResponse<()>> {
    let result = backend.kickout(&req.login_id).await;
    Json(to_api_response(result))
}

/// switch-to handler。
pub async fn switch_to_handler(
    State(backend): State<Arc<dyn AuthBackend>>,
    Json(req): Json<SwitchToRequest>,
) -> Json<ApiResponse<()>> {
    let result = backend.switch_to(&req.token, &req.target_login_id).await;
    Json(to_api_response(result))
}

/// renew-to-equivalent handler。
pub async fn renew_to_equivalent_handler(
    State(backend): State<Arc<dyn AuthBackend>>,
    Json(req): Json<CheckLoginRequest>,
) -> Json<ApiResponse<String>> {
    let result = backend.renew_to_equivalent(&req.token).await;
    Json(to_api_response(result))
}

/// health handler — 返回 "ok"，无请求体。
pub async fn health_handler() -> Json<ApiResponse<&'static str>> {
    Json(ApiResponse::ok("ok"))
}

/// 构建内网路由。
///
/// 调用方负责添加 middleware（如 api_key_auth_middleware + audit_log_middleware）。
pub fn internal_router(backend: Arc<dyn AuthBackend>) -> Router {
    Router::new()
        .route("/api/v1/auth/check-login", post(check_login_handler))
        .route(
            "/api/v1/auth/check-permission",
            post(check_permission_handler),
        )
        .route("/api/v1/auth/check-role", post(check_role_handler))
        .route("/api/v1/auth/check-safe", post(check_safe_handler))
        .route("/api/v1/auth/check-disable", post(check_disable_handler))
        .route("/api/v1/auth/check-api-key", post(check_api_key_handler))
        .route("/api/v1/auth/get-token-info", post(get_token_info_handler))
        .route("/api/v1/auth/get-session", post(get_session_handler))
        .route("/api/v1/auth/kickout", post(kickout_handler))
        .route("/api/v1/auth/switch-to", post(switch_to_handler))
        .route(
            "/api/v1/auth/renew-to-equivalent",
            post(renew_to_equivalent_handler),
        )
        .route("/api/v1/auth/health", get(health_handler))
        .with_state(backend)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::types::LoginParams;
    use crate::error::BulwarkError;
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// 测试用 Mock AuthBackend（返回可预测的固定数据）。
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
            Ok(token.starts_with("valid-"))
        }
        async fn check_permission(
            &self,
            token: &str,
            permission: &str,
        ) -> Result<(), BulwarkError> {
            if token.is_empty() {
                return Err(BulwarkError::InvalidToken("token 为空".to_string()));
            }
            if permission == "denied" {
                return Err(BulwarkError::NotPermission("无权限".to_string()));
            }
            Ok(())
        }
        async fn check_role(&self, _token: &str, _role: &str) -> Result<(), BulwarkError> {
            Ok(())
        }
        async fn check_safe(&self, _token: &str) -> Result<bool, BulwarkError> {
            Ok(true)
        }
        async fn check_disable(&self, _token: &str) -> Result<bool, BulwarkError> {
            Ok(false)
        }
        async fn check_api_key(&self, api_key: &str, _namespace: &str) -> Result<(), BulwarkError> {
            if api_key == "invalid" {
                return Err(BulwarkError::InvalidToken("API Key 无效".to_string()));
            }
            Ok(())
        }
        async fn get_token_info(&self, token: &str) -> Result<TokenInfo, BulwarkError> {
            Ok(TokenInfo {
                token: token.to_string(),
                created_at: 1000,
                last_active_at: 2000,
            })
        }
        async fn get_session(&self, token: &str) -> Result<SessionData, BulwarkError> {
            Ok(SessionData {
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

    /// 发送 POST 请求到 router 并返回响应 JSON。
    async fn post_json(router: Router, uri: &str, body: serde_json::Value) -> serde_json::Value {
        let resp = router
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn test_check_login_returns_true() {
        let app = internal_router(make_backend());
        let body = serde_json::json!({ "token": "valid-token" });
        let resp_json = post_json(app, "/api/v1/auth/check-login", body).await;
        assert_eq!(resp_json["data"], true);
    }

    #[tokio::test]
    async fn test_check_login_returns_false() {
        let app = internal_router(make_backend());
        let body = serde_json::json!({ "token": "invalid-token" });
        let resp_json = post_json(app, "/api/v1/auth/check-login", body).await;
        assert_eq!(resp_json["data"], false);
    }

    #[tokio::test]
    async fn test_check_permission_succeeds() {
        let app = internal_router(make_backend());
        let body = serde_json::json!({ "token": "valid", "permission": "user:read" });
        let resp_json = post_json(app, "/api/v1/auth/check-permission", body).await;
        assert!(resp_json.get("error_code").is_none() || resp_json["error_code"].is_null());
    }

    #[tokio::test]
    async fn test_check_permission_denied() {
        let app = internal_router(make_backend());
        let body = serde_json::json!({ "token": "valid", "permission": "denied" });
        let resp_json = post_json(app, "/api/v1/auth/check-permission", body).await;
        assert_eq!(resp_json["error_code"], "NOT_PERMISSION");
    }

    #[tokio::test]
    async fn test_check_safe_returns_true() {
        let app = internal_router(make_backend());
        let body = serde_json::json!({ "token": "valid" });
        let resp_json = post_json(app, "/api/v1/auth/check-safe", body).await;
        assert_eq!(resp_json["data"], true);
    }

    #[tokio::test]
    async fn test_check_disable_returns_false() {
        let app = internal_router(make_backend());
        let body = serde_json::json!({ "token": "valid" });
        let resp_json = post_json(app, "/api/v1/auth/check-disable", body).await;
        assert_eq!(resp_json["data"], false);
    }

    #[tokio::test]
    async fn test_get_token_info() {
        let app = internal_router(make_backend());
        let body = serde_json::json!({ "token": "my-token" });
        let resp_json = post_json(app, "/api/v1/auth/get-token-info", body).await;
        assert_eq!(resp_json["data"]["token"], "my-token");
        assert_eq!(resp_json["data"]["created_at"], 1000);
    }

    #[tokio::test]
    async fn test_get_session() {
        let app = internal_router(make_backend());
        let body = serde_json::json!({ "token": "my-token" });
        let resp_json = post_json(app, "/api/v1/auth/get-session", body).await;
        assert_eq!(resp_json["data"]["token"], "my-token");
        assert_eq!(resp_json["data"]["login_id"], "mock-user");
    }

    #[tokio::test]
    async fn test_kickout_succeeds() {
        let app = internal_router(make_backend());
        let body = serde_json::json!({ "login_id": "user1" });
        let resp_json = post_json(app, "/api/v1/auth/kickout", body).await;
        assert!(resp_json.get("error_code").is_none() || resp_json["error_code"].is_null());
    }

    #[tokio::test]
    async fn test_switch_to_succeeds() {
        let app = internal_router(make_backend());
        let body = serde_json::json!({ "token": "tok", "target_login_id": "user2" });
        let resp_json = post_json(app, "/api/v1/auth/switch-to", body).await;
        assert!(resp_json.get("error_code").is_none() || resp_json["error_code"].is_null());
    }

    #[tokio::test]
    async fn test_renew_to_equivalent() {
        let app = internal_router(make_backend());
        let body = serde_json::json!({ "token": "old-token" });
        let resp_json = post_json(app, "/api/v1/auth/renew-to-equivalent", body).await;
        assert_eq!(resp_json["data"], "renewed-old-token");
    }

    #[tokio::test]
    async fn test_health_handler() {
        let app = internal_router(make_backend());
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/auth/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(resp_json["data"], "ok");
    }

    #[tokio::test]
    async fn test_check_api_key_invalid() {
        let app = internal_router(make_backend());
        let body = serde_json::json!({ "api_key": "invalid", "namespace": "default" });
        let resp_json = post_json(app, "/api/v1/auth/check-api-key", body).await;
        assert_eq!(resp_json["error_code"], "INVALID_TOKEN");
    }
}
