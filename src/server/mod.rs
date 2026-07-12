//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! BulwarkAuthServer — 将 AuthBackend 方法暴露为 HTTP 端点的 axum 服务器。
//!
//! # 双端口架构
//!
//! - **外网端口**（external_port）：面向用户，仅暴露 login/logout/refresh 3 个端点
//! - **内网端口**（internal_port）：面向服务间调用，暴露 check-*/get-*/kickout 等 12 个端点
//!
//! # 中间件
//!
//! - 外网：rate_limit_middleware（基于 IP 限速）+ audit_log_middleware
//! - 内网：api_key_auth_middleware（X-API-Key 验证）+ audit_log_middleware
//!
//! # 使用
//!
//! ```ignore
//! use bulwark::backend::BackendEmbedded;
//! use bulwark::server::BulwarkAuthServer;
//! use std::sync::Arc;
//!
//! let backend: Arc<dyn bulwark::backend::AuthBackend> = Arc::new(BackendEmbedded::new());
//! let server = BulwarkAuthServer::new(backend)
//!     .with_external_port(8080)
//!     .with_internal_port(8081)
//!     .with_internal_api_key("secret-api-key")
//!     .with_rate_limit(100);
//! server.listen().await?;
//! ```

use std::sync::Arc;

use axum::Router;

use crate::backend::AuthBackend;
use crate::error::{BulwarkError, BulwarkResult};

pub mod external;
pub mod internal;
pub mod middleware;

pub use middleware::{api_key_auth_middleware, audit_log_middleware, rate_limit_middleware};

/// Auth Server 配置。
#[derive(Debug, Clone)]
pub struct AuthServerConfig {
    /// 外网端口（面向用户）。
    pub external_port: u16,
    /// 内网端口（服务间调用）。
    pub internal_port: u16,
    /// 每个 IP 每秒允许的外网请求数（默认 100）。
    pub external_rate_limit_per_ip: u32,
    /// 内网 API Key（用于 X-API-Key 头校验）。
    pub internal_api_key: String,
}

impl Default for AuthServerConfig {
    fn default() -> Self {
        Self {
            external_port: 8080,
            internal_port: 8081,
            external_rate_limit_per_ip: 100,
            internal_api_key: "bulwark-internal-key".to_string(),
        }
    }
}

/// BulwarkAuthServer — 双端口 axum 认证服务器。
///
/// 通过 builder 方法配置端口、限速、API Key，最终调用 `listen()` 启动。
pub struct BulwarkAuthServer {
    backend: Arc<dyn AuthBackend>,
    config: AuthServerConfig,
}

impl BulwarkAuthServer {
    /// 创建 Auth Server 实例。
    ///
    /// # 参数
    /// - `backend`：认证后端（BackendEmbedded 或 BackendRemote）
    pub fn new(backend: Arc<dyn AuthBackend>) -> Self {
        Self {
            backend,
            config: AuthServerConfig::default(),
        }
    }

    /// 设置外网端口（默认 8080）。
    pub fn with_external_port(mut self, port: u16) -> Self {
        self.config.external_port = port;
        self
    }

    /// 设置内网端口（默认 8081）。
    pub fn with_internal_port(mut self, port: u16) -> Self {
        self.config.internal_port = port;
        self
    }

    /// 设置外网每 IP 限速（默认 100 req/s）。
    pub fn with_rate_limit(mut self, limit: u32) -> Self {
        self.config.external_rate_limit_per_ip = limit;
        self
    }

    /// 设置内网 API Key（用于 X-API-Key 头校验）。
    pub fn with_internal_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.config.internal_api_key = api_key.into();
        self
    }

    /// 构建外网路由（含 rate_limit + audit_log middleware）。
    ///
    /// 用于测试时通过 `tower::ServiceExt::oneshot` 发送请求，避免实际 listen。
    pub fn external_router(&self) -> Router {
        let rate_limit_state = Arc::new(middleware::RateLimitState::new(
            self.config.external_rate_limit_per_ip,
        ));
        external::external_router(self.backend.clone())
            .layer(axum::middleware::from_fn_with_state(
                rate_limit_state,
                rate_limit_middleware,
            ))
            .layer(axum::middleware::from_fn(audit_log_middleware))
    }

    /// 构建内网路由（含 api_key_auth + audit_log middleware）。
    ///
    /// 用于测试时通过 `tower::ServiceExt::oneshot` 发送请求，避免实际 listen。
    pub fn internal_router(&self) -> Router {
        let api_key_state = Arc::new(middleware::ApiKeyState {
            api_key: self.config.internal_api_key.clone(),
        });
        internal::internal_router(self.backend.clone())
            .layer(axum::middleware::from_fn_with_state(
                api_key_state,
                api_key_auth_middleware,
            ))
            .layer(axum::middleware::from_fn(audit_log_middleware))
    }

    /// 同时启动外网和内网两个 axum 服务器。
    ///
    /// 两个服务器并行运行，任一服务器异常退出时整体返回错误。
    pub async fn listen(self) -> BulwarkResult<()> {
        let external_addr = format!("0.0.0.0:{}", self.config.external_port);
        let internal_addr = format!("0.0.0.0:{}", self.config.internal_port);

        let external_listener = tokio::net::TcpListener::bind(&external_addr)
            .await
            .map_err(|e| BulwarkError::Internal(format!("绑定外网端口失败: {}", e)))?;
        let internal_listener = tokio::net::TcpListener::bind(&internal_addr)
            .await
            .map_err(|e| BulwarkError::Internal(format!("绑定内网端口失败: {}", e)))?;

        let external_router = self.external_router();
        let internal_router = self.internal_router();

        tracing::info!(
            external_port = self.config.external_port,
            internal_port = self.config.internal_port,
            "BulwarkAuthServer 启动"
        );

        let external_handle = tokio::spawn(async move {
            if let Err(e) = axum::serve(external_listener, external_router).await {
                tracing::error!(error = %e, "外网服务器异常");
                return Err(BulwarkError::Internal(format!("外网服务器异常: {}", e)));
            }
            Ok(())
        });

        let internal_handle = tokio::spawn(async move {
            if let Err(e) = axum::serve(internal_listener, internal_router).await {
                tracing::error!(error = %e, "内网服务器异常");
                return Err(BulwarkError::Internal(format!("内网服务器异常: {}", e)));
            }
            Ok(())
        });

        // 任一服务器异常即返回错误
        tokio::select! {
            res = external_handle => {
                res.map_err(|e| BulwarkError::Internal(format!("外网 task panic: {}", e)))?
            },
            res = internal_handle => {
                res.map_err(|e| BulwarkError::Internal(format!("内网 task panic: {}", e)))?
            },
        }
    }
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
        async fn login(&self, login_id: &str, _params: &LoginParams) -> BulwarkResult<String> {
            Ok(format!("token-{}", login_id))
        }
        async fn logout(&self, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_login(&self, token: &str) -> BulwarkResult<bool> {
            Ok(token.starts_with("token-"))
        }
        async fn check_permission(&self, _token: &str, _permission: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_role(&self, _token: &str, _role: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_safe(&self, _token: &str) -> BulwarkResult<bool> {
            Ok(false)
        }
        async fn check_disable(&self, _token: &str) -> BulwarkResult<bool> {
            Ok(false)
        }
        async fn check_api_key(&self, _api_key: &str, _namespace: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn get_token_info(
            &self,
            token: &str,
        ) -> BulwarkResult<crate::backend::types::TokenInfo> {
            Ok(crate::backend::types::TokenInfo {
                token: token.to_string(),
                created_at: 1000,
                last_active_at: 2000,
            })
        }
        async fn get_session(
            &self,
            token: &str,
        ) -> BulwarkResult<crate::backend::types::SessionData> {
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
            })
        }
        async fn kickout(&self, _login_id: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn switch_to(&self, _token: &str, _target_login_id: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn renew_to_equivalent(&self, token: &str) -> BulwarkResult<String> {
            Ok(format!("renewed-{}", token))
        }
    }

    fn make_server() -> BulwarkAuthServer {
        let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
        BulwarkAuthServer::new(backend)
            .with_internal_api_key("test-api-key")
            .with_rate_limit(100)
    }

    #[tokio::test]
    async fn test_external_router_handles_login() {
        let server = make_server();
        let app = server.external_router();
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
    async fn test_internal_router_handles_health() {
        let server = make_server();
        let app = server.internal_router();
        // health 端点需要 API Key
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/auth/health")
                    .header("x-api-key", "test-api-key")
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
    async fn test_internal_router_rejects_missing_api_key() {
        let server = make_server();
        let app = server.internal_router();
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
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_external_router_rate_limit() {
        let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
        let server = BulwarkAuthServer::new(backend)
            .with_internal_api_key("test-api-key")
            .with_rate_limit(2);
        let app = server.external_router();
        let body = serde_json::json!({
            "login_id": "user1",
            "params": LoginParams::default()
        });

        // 前 2 个请求成功
        for _ in 0..2 {
            let resp = app
                .clone()
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
        }

        // 第 3 个请求被限速
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
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_builder_methods() {
        let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
        let server = BulwarkAuthServer::new(backend)
            .with_external_port(9000)
            .with_internal_port(9001)
            .with_rate_limit(50)
            .with_internal_api_key("my-key");

        assert_eq!(server.config.external_port, 9000);
        assert_eq!(server.config.internal_port, 9001);
        assert_eq!(server.config.external_rate_limit_per_ip, 50);
        assert_eq!(server.config.internal_api_key, "my-key");
    }

    #[tokio::test]
    async fn test_default_config() {
        let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
        let server = BulwarkAuthServer::new(backend);
        assert_eq!(server.config.external_port, 8080);
        assert_eq!(server.config.internal_port, 8081);
        assert_eq!(server.config.external_rate_limit_per_ip, 100);
    }
}
