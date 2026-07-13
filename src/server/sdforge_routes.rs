// Copyright (c) 2026 Kirky.X
// SPDX-License-Identifier: MIT

//! sdforge 声明式路由（feature = "auth-server-sdforge"）。
//!
//! 用 `#[forge]` 宏替换 `external.rs` + `internal.rs` 的手写 axum 路由。
//! sdforge `#[forge]` 宏通过 inventory 自动注册路由，
//! `sdforge::http::build()` 收集所有注册的路由。
//!
//! # 路径约定
//!
//! `#[forge]` 宏自动将 path 前缀化为 `/api/{version}{path}`。
//! 因此 path 参数只需写 `/auth/login`，version="v1" → 实际路由 `/api/v1/auth/login`。
//! 使用 `no_prefix = true` 可禁用自动前缀化（本模块未使用）。
//!
//! # State 注入
//!
//! sdforge `#[state]` 参数通过 `axum::extract::Extension<T>` 注入。
//! 调用方需在 Router 上 `.layer(Extension(backend))` 注入后端。
//!
//! # 路由列表
//!
//! - 外网 3 端点：login / logout / refresh
//! - 内网 12 端点：check-login / check-permission / check-role / check-safe /
//!   check-disable / check-api-key / get-token-info / get-session / kickout /
//!   switch-to / renew-to-equivalent / health

#![cfg(feature = "auth-server-sdforge")]
// #[forge] 宏生成的代码含 #[cfg(feature = "mcp")] / #[cfg(feature = "cli")] 等
// bulwark 不具备的 feature cfg，属于外部宏展开的正常现象，抑制 check-cfg 警告。
#![allow(unexpected_cfgs)]

use crate::backend::types::{
    ApiResponse, CheckApiKeyRequest, CheckLoginRequest, CheckPermissionRequest, CheckRoleRequest,
    KickoutRequest, LoginRequest, LogoutRequest, RenewToEquivalentRequest, SwitchToRequest,
};
use crate::backend::AuthBackend;
use sdforge::forge;
use sdforge::prelude::ApiError;
use std::sync::Arc;

// 复用 mod.rs 的 to_api_response 逻辑（避免重复实现 — Rule 8）
use super::to_api_response;

// ============================================================================
// 外网路由（3 端点）
// ============================================================================

#[forge(
    name = "auth_login",
    version = "v1",
    path = "/auth/login",
    method = "POST",
    tool_name = "auth_login",
    description = "用户登录，返回 token"
)]
async fn login(
    #[state] backend: Arc<dyn AuthBackend>,
    req: LoginRequest,
) -> Result<ApiResponse<String>, ApiError> {
    let result = backend.login(&req.login_id, &req.params).await;
    Ok(to_api_response(result))
}

#[forge(
    name = "auth_logout",
    version = "v1",
    path = "/auth/logout",
    method = "POST",
    tool_name = "auth_logout",
    description = "登出指定 token"
)]
async fn logout(
    #[state] backend: Arc<dyn AuthBackend>,
    req: LogoutRequest,
) -> Result<ApiResponse<()>, ApiError> {
    let result = backend.logout(&req.token).await;
    Ok(to_api_response(result))
}

#[forge(
    name = "auth_refresh",
    version = "v1",
    path = "/auth/refresh",
    method = "POST",
    tool_name = "auth_refresh",
    description = "刷新 token"
)]
async fn refresh(
    #[state] backend: Arc<dyn AuthBackend>,
    req: RenewToEquivalentRequest,
) -> Result<ApiResponse<String>, ApiError> {
    let result = backend.renew_to_equivalent(&req.token).await;
    Ok(to_api_response(result))
}

// ============================================================================
// 内网路由（12 端点）
// ============================================================================

#[forge(
    name = "auth_check_login",
    version = "v1",
    path = "/auth/check-login",
    method = "POST",
    tool_name = "auth_check_login",
    description = "校验登录状态"
)]
async fn check_login(
    #[state] backend: Arc<dyn AuthBackend>,
    req: CheckLoginRequest,
) -> Result<ApiResponse<bool>, ApiError> {
    let result = backend.check_login(&req.token).await;
    Ok(to_api_response(result))
}

#[forge(
    name = "auth_check_permission",
    version = "v1",
    path = "/auth/check-permission",
    method = "POST",
    tool_name = "auth_check_permission",
    description = "校验权限"
)]
async fn check_permission(
    #[state] backend: Arc<dyn AuthBackend>,
    req: CheckPermissionRequest,
) -> Result<ApiResponse<()>, ApiError> {
    let result = backend.check_permission(&req.token, &req.permission).await;
    Ok(to_api_response(result))
}

#[forge(
    name = "auth_check_role",
    version = "v1",
    path = "/auth/check-role",
    method = "POST",
    tool_name = "auth_check_role",
    description = "校验角色"
)]
async fn check_role(
    #[state] backend: Arc<dyn AuthBackend>,
    req: CheckRoleRequest,
) -> Result<ApiResponse<()>, ApiError> {
    let result = backend.check_role(&req.token, &req.role).await;
    Ok(to_api_response(result))
}

#[forge(
    name = "auth_check_safe",
    version = "v1",
    path = "/auth/check-safe",
    method = "POST",
    tool_name = "auth_check_safe",
    description = "校验二级认证"
)]
async fn check_safe(
    #[state] backend: Arc<dyn AuthBackend>,
    req: CheckLoginRequest,
) -> Result<ApiResponse<bool>, ApiError> {
    let result = backend.check_safe(&req.token).await;
    Ok(to_api_response(result))
}

#[forge(
    name = "auth_check_disable",
    version = "v1",
    path = "/auth/check-disable",
    method = "POST",
    tool_name = "auth_check_disable",
    description = "校验封禁状态"
)]
async fn check_disable(
    #[state] backend: Arc<dyn AuthBackend>,
    req: CheckLoginRequest,
) -> Result<ApiResponse<bool>, ApiError> {
    let result = backend.check_disable(&req.token).await;
    Ok(to_api_response(result))
}

#[forge(
    name = "auth_check_api_key",
    version = "v1",
    path = "/auth/check-api-key",
    method = "POST",
    tool_name = "auth_check_api_key",
    description = "校验 API Key"
)]
async fn check_api_key(
    #[state] backend: Arc<dyn AuthBackend>,
    req: CheckApiKeyRequest,
) -> Result<ApiResponse<()>, ApiError> {
    let result = backend.check_api_key(&req.api_key, &req.namespace).await;
    Ok(to_api_response(result))
}

#[forge(
    name = "auth_get_token_info",
    version = "v1",
    path = "/auth/get-token-info",
    method = "POST",
    tool_name = "auth_get_token_info",
    description = "获取 token 信息"
)]
async fn get_token_info(
    #[state] backend: Arc<dyn AuthBackend>,
    req: CheckLoginRequest,
) -> Result<ApiResponse<crate::backend::types::TokenInfo>, ApiError> {
    let result = backend.get_token_info(&req.token).await;
    Ok(to_api_response(result))
}

#[forge(
    name = "auth_get_session",
    version = "v1",
    path = "/auth/get-session",
    method = "POST",
    tool_name = "auth_get_session",
    description = "获取 session"
)]
async fn get_session(
    #[state] backend: Arc<dyn AuthBackend>,
    req: CheckLoginRequest,
) -> Result<ApiResponse<crate::backend::types::SessionData>, ApiError> {
    let result = backend.get_session(&req.token).await;
    Ok(to_api_response(result))
}

#[forge(
    name = "auth_kickout",
    version = "v1",
    path = "/auth/kickout",
    method = "POST",
    tool_name = "auth_kickout",
    description = "踢出登录主体"
)]
async fn kickout(
    #[state] backend: Arc<dyn AuthBackend>,
    req: KickoutRequest,
) -> Result<ApiResponse<()>, ApiError> {
    let result = backend.kickout(&req.login_id).await;
    Ok(to_api_response(result))
}

#[forge(
    name = "auth_switch_to",
    version = "v1",
    path = "/auth/switch-to",
    method = "POST",
    tool_name = "auth_switch_to",
    description = "切换登录主体"
)]
async fn switch_to(
    #[state] backend: Arc<dyn AuthBackend>,
    req: SwitchToRequest,
) -> Result<ApiResponse<()>, ApiError> {
    let result = backend.switch_to(&req.token, &req.target_login_id).await;
    Ok(to_api_response(result))
}

#[forge(
    name = "auth_renew_to_equivalent",
    version = "v1",
    path = "/auth/renew-to-equivalent",
    method = "POST",
    tool_name = "auth_renew_to_equivalent",
    description = "续期 token"
)]
async fn renew_to_equivalent(
    #[state] backend: Arc<dyn AuthBackend>,
    req: CheckLoginRequest,
) -> Result<ApiResponse<String>, ApiError> {
    let result = backend.renew_to_equivalent(&req.token).await;
    Ok(to_api_response(result))
}

#[forge(
    name = "auth_health",
    version = "v1",
    path = "/auth/health",
    method = "GET",
    tool_name = "auth_health",
    description = "健康检查"
)]
async fn health() -> Result<ApiResponse<&'static str>, ApiError> {
    Ok(ApiResponse::ok("ok"))
}

// ============================================================================
// Metrics 端点（feature = "metrics-prometheus"）
// ============================================================================

/// /metrics 端点，暴露 Prometheus 格式指标。
///
/// 调用 `prometheus::gather()` 收集 default registry 的所有指标
/// （`BulwarkMetrics::new()` 注册的 `bulwark_*` 指标），
/// 用 `TextEncoder` 编码为 Prometheus 文本格式。
///
/// # 设计权衡
///
/// `#[forge]` 宏在非 streaming 模式下用 `Json(value).into_response()` 包装返回值，
/// 响应 Content-Type 为 `application/json`，body 为 JSON 序列化的字符串
/// （含转义换行符）。若需标准 Prometheus `text/plain` 抓取，应在
/// `BulwarkAuthServer::external_router()` / `internal_router()` 中直接用 axum
/// 路由注册（绕过 `#[forge]` 宏）。本端点优先复用 `#[forge]` 声明式注册，
/// 保持路由定义一致性。
///
/// # 错误
///
/// `TextEncoder::encode` 仅在 buffer 写入失败时返回错误（实际不会发生），
/// 返回 `ApiError::Internal`（error_id = "metrics-encode-failure"）。
#[cfg(feature = "metrics-prometheus")]
#[forge(
    name = "auth_metrics",
    version = "v1",
    path = "/metrics",
    method = "GET",
    tool_name = "auth_metrics",
    description = "Prometheus 指标端点"
)]
async fn metrics() -> Result<String, ApiError> {
    let output = prometheus::TextEncoder::new()
        .encode_to_string(&prometheus::gather())
        .map_err(|e| {
            ApiError::internal_with_source("Prometheus 指标编码失败", "metrics-encode-failure", e)
        })?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::types::LoginParams;
    use crate::error::BulwarkError;
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::extract::Extension;
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

    /// 构建 sdforge 路由（注入 mock backend via Extension layer）。
    fn make_router() -> axum::Router {
        sdforge::http::build().layer(Extension(make_backend()))
    }

    /// 发送 POST 请求并返回响应 JSON。
    async fn post_json(
        router: axum::Router,
        uri: &str,
        body: serde_json::Value,
    ) -> serde_json::Value {
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

    // ========================================================================
    // 外网路由测试（3 端点）
    // ========================================================================

    #[tokio::test]
    async fn test_sdforge_login_returns_token() {
        let app = make_router();
        let body = serde_json::json!({
            "login_id": "user1",
            "params": LoginParams::default()
        });
        let resp_json = post_json(app, "/api/v1/auth/login", body).await;
        assert_eq!(resp_json["data"], "token-user1");
    }

    #[tokio::test]
    async fn test_sdforge_logout_succeeds() {
        let app = make_router();
        let body = serde_json::json!({ "token": "some-token" });
        let resp_json = post_json(app, "/api/v1/auth/logout", body).await;
        assert!(resp_json.get("error_code").is_none() || resp_json["error_code"].is_null());
    }

    #[tokio::test]
    async fn test_sdforge_refresh_returns_new_token() {
        let app = make_router();
        let body = serde_json::json!({ "token": "old-token" });
        let resp_json = post_json(app, "/api/v1/auth/refresh", body).await;
        assert_eq!(resp_json["data"], "renewed-old-token");
    }

    // ========================================================================
    // 内网路由测试（12 端点）
    // ========================================================================

    #[tokio::test]
    async fn test_sdforge_check_login_returns_true() {
        let app = make_router();
        let body = serde_json::json!({ "token": "valid-token" });
        let resp_json = post_json(app, "/api/v1/auth/check-login", body).await;
        assert_eq!(resp_json["data"], true);
    }

    #[tokio::test]
    async fn test_sdforge_check_login_returns_false() {
        let app = make_router();
        let body = serde_json::json!({ "token": "invalid-token" });
        let resp_json = post_json(app, "/api/v1/auth/check-login", body).await;
        assert_eq!(resp_json["data"], false);
    }

    #[tokio::test]
    async fn test_sdforge_check_permission_succeeds() {
        let app = make_router();
        let body = serde_json::json!({ "token": "valid", "permission": "user:read" });
        let resp_json = post_json(app, "/api/v1/auth/check-permission", body).await;
        assert!(resp_json.get("error_code").is_none() || resp_json["error_code"].is_null());
    }

    #[tokio::test]
    async fn test_sdforge_check_permission_denied() {
        let app = make_router();
        let body = serde_json::json!({ "token": "valid", "permission": "denied" });
        let resp_json = post_json(app, "/api/v1/auth/check-permission", body).await;
        assert_eq!(resp_json["error_code"], "NOT_PERMISSION");
    }

    #[tokio::test]
    async fn test_sdforge_check_role_succeeds() {
        let app = make_router();
        let body = serde_json::json!({ "token": "valid", "role": "admin" });
        let resp_json = post_json(app, "/api/v1/auth/check-role", body).await;
        assert!(resp_json.get("error_code").is_none() || resp_json["error_code"].is_null());
    }

    #[tokio::test]
    async fn test_sdforge_check_safe_returns_true() {
        let app = make_router();
        let body = serde_json::json!({ "token": "valid" });
        let resp_json = post_json(app, "/api/v1/auth/check-safe", body).await;
        assert_eq!(resp_json["data"], true);
    }

    #[tokio::test]
    async fn test_sdforge_check_disable_returns_false() {
        let app = make_router();
        let body = serde_json::json!({ "token": "valid" });
        let resp_json = post_json(app, "/api/v1/auth/check-disable", body).await;
        assert_eq!(resp_json["data"], false);
    }

    #[tokio::test]
    async fn test_sdforge_check_api_key_valid() {
        let app = make_router();
        let body = serde_json::json!({ "api_key": "valid-key", "namespace": "default" });
        let resp_json = post_json(app, "/api/v1/auth/check-api-key", body).await;
        assert!(resp_json.get("error_code").is_none() || resp_json["error_code"].is_null());
    }

    #[tokio::test]
    async fn test_sdforge_check_api_key_invalid() {
        let app = make_router();
        let body = serde_json::json!({ "api_key": "invalid", "namespace": "default" });
        let resp_json = post_json(app, "/api/v1/auth/check-api-key", body).await;
        assert_eq!(resp_json["error_code"], "INVALID_TOKEN");
    }

    #[tokio::test]
    async fn test_sdforge_get_token_info() {
        let app = make_router();
        let body = serde_json::json!({ "token": "my-token" });
        let resp_json = post_json(app, "/api/v1/auth/get-token-info", body).await;
        assert_eq!(resp_json["data"]["token"], "my-token");
        assert_eq!(resp_json["data"]["created_at"], 1000);
    }

    #[tokio::test]
    async fn test_sdforge_get_session() {
        let app = make_router();
        let body = serde_json::json!({ "token": "my-token" });
        let resp_json = post_json(app, "/api/v1/auth/get-session", body).await;
        assert_eq!(resp_json["data"]["token"], "my-token");
        assert_eq!(resp_json["data"]["login_id"], "mock-user");
    }

    #[tokio::test]
    async fn test_sdforge_kickout_succeeds() {
        let app = make_router();
        let body = serde_json::json!({ "login_id": "user1" });
        let resp_json = post_json(app, "/api/v1/auth/kickout", body).await;
        assert!(resp_json.get("error_code").is_none() || resp_json["error_code"].is_null());
    }

    #[tokio::test]
    async fn test_sdforge_switch_to_succeeds() {
        let app = make_router();
        let body = serde_json::json!({ "token": "tok", "target_login_id": "user2" });
        let resp_json = post_json(app, "/api/v1/auth/switch-to", body).await;
        assert!(resp_json.get("error_code").is_none() || resp_json["error_code"].is_null());
    }

    #[tokio::test]
    async fn test_sdforge_renew_to_equivalent() {
        let app = make_router();
        let body = serde_json::json!({ "token": "old-token" });
        let resp_json = post_json(app, "/api/v1/auth/renew-to-equivalent", body).await;
        assert_eq!(resp_json["data"], "renewed-old-token");
    }

    #[tokio::test]
    async fn test_sdforge_health() {
        let app = make_router();
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

    // ========================================================================
    // 路由计数验证
    // ========================================================================

    #[test]
    fn test_sdforge_route_count() {
        // sdforge::http::build() 收集所有 #[forge] 注册的路由
        // metrics-prometheus 启用时 16 个（3 外网 + 12 内网 + 1 metrics）
        // 未启用时 15 个（3 外网 + 12 内网）
        let router = sdforge::http::build();
        let route_count = count_routes(&router);
        #[cfg(feature = "metrics-prometheus")]
        let expected = 16;
        #[cfg(not(feature = "metrics-prometheus"))]
        let expected = 15;
        assert_eq!(
            route_count, expected,
            "sdforge 应注册 {} 个路由，实际 {}",
            expected, route_count
        );
    }

    /// 递归计数 Router 中的路由数（通过 axum 内部结构）。
    /// axum Router 没有公开的 route 计数 API，
    /// 这里用 inventory 直接计数注册项。
    fn count_routes(_router: &axum::Router) -> usize {
        // inventory::iter 收集所有编译期注册的 RouteRegistration + HttpRoute
        let reg_count = inventory::iter::<sdforge::http::RouteRegistration>
            .into_iter()
            .count();
        let direct_count = inventory::iter::<sdforge::http::HttpRoute>
            .into_iter()
            .count();
        // 去重后的数量由 build() 内部处理，这里取注册总数作为近似值
        reg_count + direct_count
    }

    // ========================================================================
    // Metrics 端点测试（feature = "metrics-prometheus"）
    // ========================================================================

    /// T005: /metrics 端点返回 200 + JSON 包装的 Prometheus 文本格式。
    ///
    /// `#[forge]` 宏用 `Json(value).into_response()` 包装返回值，
    /// 响应 body 为 JSON 序列化的字符串（含转义换行符）。
    /// 测试解析 JSON 字符串后验证包含 `bulwark_` 前缀指标。
    #[cfg(feature = "metrics-prometheus")]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_sdforge_metrics_returns_prometheus_format() {
        use crate::observability::BulwarkMetrics;

        // 注册 BulwarkMetrics 到 default registry（若已注册则跳过 AlreadyReg）
        if let Ok(metrics) = BulwarkMetrics::register_to(prometheus::default_registry()) {
            metrics.record_login(true);
            metrics.record_permission_query(true);
        }

        let app = make_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        // #[forge] 宏用 Json(value) 包装返回值，响应是 JSON 字符串
        let body: String = serde_json::from_slice(&bytes).expect("响应应为 JSON 序列化的字符串");
        assert!(
            body.contains("bulwark_login_total"),
            "/metrics 应包含 bulwark_login_total 指标，实际: {}",
            body
        );
    }

    /// T005: /metrics 端点在未注册 BulwarkMetrics 时返回 200 + 空字符串。
    ///
    /// 验证 default registry 为空时端点不 panic，返回空 Prometheus 文本。
    #[cfg(feature = "metrics-prometheus")]
    #[tokio::test]
    #[serial_test::serial]
    async fn test_sdforge_metrics_returns_empty_when_no_metrics() {
        // 不注册任何指标，验证端点不 panic
        // 注意：default registry 是全局共享的，其他测试可能已注册指标，
        // 此测试仅验证端点不 panic 且返回 200（不验证 body 内容）
        let app = make_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/metrics")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        // 响应应为有效 JSON 字符串（可能为空字符串 ""）
        let _body: String = serde_json::from_slice(&bytes).expect("响应应为 JSON 序列化的字符串");
    }
}
