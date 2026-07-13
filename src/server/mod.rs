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

#[cfg(feature = "tls")]
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;

use crate::backend::types::ApiResponse;
use crate::backend::AuthBackend;
use crate::error::{BulwarkError, BulwarkResult};

pub mod middleware;

#[cfg(feature = "auth-server-sdforge")]
pub mod sdforge_routes;

#[cfg(feature = "oauth2-server")]
pub mod oauth2_routes;

pub use middleware::{
    api_key_auth_middleware, audit_log_middleware, external_path_filter, internal_path_filter,
    rate_limit_middleware,
};

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
            internal_api_key: String::new(),
        }
    }
}

/// TLS 配置（证书 + 私钥文件路径）。
///
/// 通过 [`BulwarkAuthServer::with_tls`] 设置，启用后 `listen()` 使用
/// `axum_server::bind_rustls` 替代 `axum::serve`，实现 HTTPS/TLS 终止。
///
/// # Feature 门控
///
/// 仅在 `tls` feature 启用时编译。
#[cfg(feature = "tls")]
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// PEM 格式证书文件路径。
    pub cert_path: PathBuf,
    /// PEM 格式私钥文件路径。
    pub key_path: PathBuf,
}

/// BulwarkAuthServer — 双端口 axum 认证服务器。
///
/// 通过 builder 方法配置端口、限速、API Key，最终调用 `listen()` 启动。
pub struct BulwarkAuthServer {
    backend: Arc<dyn AuthBackend>,
    config: AuthServerConfig,
    #[cfg(feature = "oauth2-server")]
    oauth2_state: Option<Arc<oauth2_routes::OAuth2State>>,
    #[cfg(feature = "tls")]
    tls_config: Option<TlsConfig>,
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
            #[cfg(feature = "oauth2-server")]
            oauth2_state: None,
            #[cfg(feature = "tls")]
            tls_config: None,
        }
    }

    /// 用 trait-kit AsyncKit 构建后端（可选路径，feature = "backend-kit"）。
    ///
    /// 替换手写 `BulwarkAuthServer::new(Arc::new(BackendEmbedded::new()))`。
    /// 从已构建的 `AsyncKit<Ready>` 中 require `BackendModule` 的 capability
    /// （`Arc<dyn AuthBackend>`），委托给 [`Self::new`]。
    ///
    /// # 参数
    /// - `kit`：已调用 `kit.build().await` 完成的 `AsyncKit<Ready>`
    ///
    /// # 错误
    /// - `BulwarkError::Internal`：kit 中未注册/未构建 `BackendModule`
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use trait_kit::kit::AsyncKit;
    /// use bulwark::backend::BackendModule;
    ///
    /// let mut kit = AsyncKit::new();
    /// kit.register::<BackendModule>().unwrap();
    /// let kit = kit.build().await.unwrap();
    /// let server = BulwarkAuthServer::new_with_kit(kit).await.unwrap();
    /// ```
    #[cfg(feature = "backend-kit")]
    pub async fn new_with_kit(
        kit: trait_kit::kit::AsyncKit<trait_kit::kit::AsyncReady>,
    ) -> BulwarkResult<Self> {
        use crate::backend::BackendModule;
        let backend = kit.require::<BackendModule>().map_err(|e| {
            BulwarkError::Internal(format!("kit require BackendModule failed: {}", e))
        })?;
        Ok(Self::new(backend))
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

    /// 注入 OAuth2 状态，启用 4 个 OAuth2 端点（feature = "oauth2-server"）。
    ///
    /// 外网端口添加 authorize/token/revoke，内网端口添加 introspect。
    #[cfg(feature = "oauth2-server")]
    pub fn with_oauth2(mut self, state: Arc<oauth2_routes::OAuth2State>) -> Self {
        self.oauth2_state = Some(state);
        self
    }

    /// 启用 HTTPS/TLS 终止（feature = "tls"）。
    ///
    /// 设置证书和私钥文件路径后，`listen()` 使用 `axum_server::bind_rustls`
    /// 替代 `axum::serve`，对外网和内网端口均启用 TLS。
    ///
    /// # 参数
    /// - `cert_path`：PEM 格式证书文件路径
    /// - `key_path`：PEM 格式私钥文件路径
    ///
    /// # 示例
    ///
    /// ```ignore
    /// let server = BulwarkAuthServer::new(backend)
    ///     .with_tls("/etc/bulwark/cert.pem", "/etc/bulwark/key.pem");
    /// server.listen().await?;
    /// ```
    #[cfg(feature = "tls")]
    pub fn with_tls(mut self, cert_path: impl Into<PathBuf>, key_path: impl Into<PathBuf>) -> Self {
        self.tls_config = Some(TlsConfig {
            cert_path: cert_path.into(),
            key_path: key_path.into(),
        });
        self
    }

    /// 构建外网路由（sdforge + path-filter + rate_limit + audit_log）。
    ///
    /// 用 `sdforge::http::build()` 收集所有 `#[forge]` 路由（15 端点），
    /// 通过 `external_path_filter` 中间件仅放行 3 个外网路径（login/logout/refresh），
    /// 其余内网路径返回 404。
    ///
    /// 中间件栈（从外到内）：audit_log → rate_limit → external_path_filter → handler
    ///
    /// 用于测试时通过 `tower::ServiceExt::oneshot` 发送请求，避免实际 listen。
    pub fn external_router(&self) -> Router {
        use axum::Extension;
        let rate_limit_state = Arc::new(middleware::RateLimitState::new(
            self.config.external_rate_limit_per_ip,
        ));
        let router = sdforge::http::build()
            .layer(Extension(self.backend.clone()))
            .layer(axum::middleware::from_fn(middleware::external_path_filter))
            .layer(axum::middleware::from_fn_with_state(
                rate_limit_state,
                rate_limit_middleware,
            ))
            .layer(axum::middleware::from_fn(audit_log_middleware));

        #[cfg(feature = "oauth2-server")]
        let router = {
            if let Some(state) = &self.oauth2_state {
                router.merge(oauth2_routes::oauth2_external_router(state.clone()))
            } else {
                router
            }
        };

        router
    }

    /// 构建内网路由（sdforge + path-filter + api_key_auth + audit_log）。
    ///
    /// 用 `sdforge::http::build()` 收集所有 `#[forge]` 路由（15 端点），
    /// 通过 `internal_path_filter` 中间件拒绝 3 个外网路径（login/logout/refresh），
    /// 其余内网路径放行（由 api_key_auth 保护）。
    ///
    /// 中间件栈（从外到内）：audit_log → api_key_auth → internal_path_filter → handler
    ///
    /// 用于测试时通过 `tower::ServiceExt::oneshot` 发送请求，避免实际 listen。
    pub fn internal_router(&self) -> Router {
        use axum::Extension;
        let api_key_state = Arc::new(middleware::ApiKeyState {
            api_key: self.config.internal_api_key.clone(),
        });
        let router = sdforge::http::build()
            .layer(Extension(self.backend.clone()))
            .layer(axum::middleware::from_fn(middleware::internal_path_filter))
            .layer(axum::middleware::from_fn_with_state(
                api_key_state,
                api_key_auth_middleware,
            ))
            .layer(axum::middleware::from_fn(audit_log_middleware));

        #[cfg(feature = "oauth2-server")]
        let router = {
            if let Some(state) = &self.oauth2_state {
                router.merge(oauth2_routes::oauth2_internal_router(state.clone()))
            } else {
                router
            }
        };

        router
    }

    /// 同时启动外网和内网两个 axum 服务器。
    ///
    /// 两个服务器并行运行，任一服务器异常退出时整体返回错误。
    ///
    /// # TLS 终止
    ///
    /// 启用 `tls` feature 且调用 `with_tls()` 后，两个端口均使用
    /// `axum_server::bind_rustls` 替代 `axum::serve`，实现 HTTPS/TLS 终止。
    pub async fn listen(self) -> BulwarkResult<()> {
        let external_addr = format!("0.0.0.0:{}", self.config.external_port);
        let internal_addr = format!("0.0.0.0:{}", self.config.internal_port);

        #[cfg(feature = "tls")]
        let tls_config_ext = self.tls_config.clone();
        #[cfg(feature = "tls")]
        let tls_config_int = self.tls_config.clone();

        let external_router = self.external_router();
        let internal_router = self.internal_router();

        tracing::info!(
            external_port = self.config.external_port,
            internal_port = self.config.internal_port,
            "BulwarkAuthServer 启动"
        );

        let mut external_handle = tokio::spawn(async move {
            #[cfg(feature = "tls")]
            if let Some(tc) = tls_config_ext.as_ref() {
                let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
                    &tc.cert_path,
                    &tc.key_path,
                )
                .await
                .map_err(|e| BulwarkError::Internal(format!("加载外网 TLS 配置失败: {}", e)))?;
                let addr: std::net::SocketAddr = external_addr
                    .parse()
                    .map_err(|e| BulwarkError::Internal(format!("外网地址解析失败: {}", e)))?;
                return axum_server::bind_rustls(addr, rustls_config)
                    .serve(external_router.into_make_service())
                    .await
                    .map_err(|e| BulwarkError::Internal(format!("外网服务器异常: {}", e)));
            }

            let external_listener = tokio::net::TcpListener::bind(&external_addr)
                .await
                .map_err(|e| BulwarkError::Internal(format!("绑定外网端口失败: {}", e)))?;
            if let Err(e) = axum::serve(external_listener, external_router).await {
                tracing::error!(error = %e, "外网服务器异常");
                return Err(BulwarkError::Internal(format!("外网服务器异常: {}", e)));
            }
            Ok(())
        });

        let mut internal_handle = tokio::spawn(async move {
            #[cfg(feature = "tls")]
            if let Some(tc) = tls_config_int.as_ref() {
                let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
                    &tc.cert_path,
                    &tc.key_path,
                )
                .await
                .map_err(|e| BulwarkError::Internal(format!("加载内网 TLS 配置失败: {}", e)))?;
                let addr: std::net::SocketAddr = internal_addr
                    .parse()
                    .map_err(|e| BulwarkError::Internal(format!("内网地址解析失败: {}", e)))?;
                return axum_server::bind_rustls(addr, rustls_config)
                    .serve(internal_router.into_make_service())
                    .await
                    .map_err(|e| BulwarkError::Internal(format!("内网服务器异常: {}", e)));
            }

            let internal_listener = tokio::net::TcpListener::bind(&internal_addr)
                .await
                .map_err(|e| BulwarkError::Internal(format!("绑定内网端口失败: {}", e)))?;
            if let Err(e) = axum::serve(internal_listener, internal_router).await {
                tracing::error!(error = %e, "内网服务器异常");
                return Err(BulwarkError::Internal(format!("内网服务器异常: {}", e)));
            }
            Ok(())
        });

        // 任一服务器异常即返回错误，M-1: 显式 abort 另一个 task 避免资源泄漏
        tokio::select! {
            res = &mut external_handle => {
                internal_handle.abort();
                res.map_err(|e| BulwarkError::Internal(format!("外网 task panic: {}", e)))?
            },
            res = &mut internal_handle => {
                external_handle.abort();
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
                #[cfg(feature = "dynamic-active-timeout")]
                dynamic_active_timeout: None,
                #[cfg(feature = "anonymous-session")]
                is_anon: false,
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
        assert!(
            server.config.internal_api_key.is_empty(),
            "Default internal_api_key 必须为空（fail-closed，M-SAST-1/M-5）"
        );
    }

    /// 测试 new_with_kit 通过 AsyncKit 构建后端并创建 server。
    #[cfg(feature = "backend-kit")]
    #[tokio::test]
    async fn test_new_with_kit_builds_server() {
        use crate::backend::BackendModule;
        use trait_kit::kit::AsyncKit;

        let mut kit = AsyncKit::new();
        kit.register::<BackendModule>()
            .expect("register BackendModule failed");
        let kit = kit.build().await.expect("kit build failed");
        let server = BulwarkAuthServer::new_with_kit(kit)
            .await
            .expect("new_with_kit failed");
        // 验证 server 用默认配置创建
        assert_eq!(server.config.external_port, 8080);
        assert_eq!(server.config.internal_port, 8081);
    }

    /// 测试 new_with_kit 在 kit 未注册 BackendModule 时返回错误。
    #[cfg(feature = "backend-kit")]
    #[tokio::test]
    async fn test_new_with_kit_missing_module_fails() {
        use trait_kit::kit::AsyncKit;

        let kit = AsyncKit::new();
        let kit = kit.build().await.expect("empty build should succeed");
        let result = BulwarkAuthServer::new_with_kit(kit).await;
        assert!(
            result.is_err(),
            "new_with_kit 应在 kit 未注册 BackendModule 时返回错误"
        );
    }

    /// 测试 with_tls 设置 TLS 配置（feature = "tls"）。
    ///
    /// 验证 with_tls(cert_path, key_path) 后 server.tls_config 含正确的证书/密钥路径。
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn test_with_tls_sets_config() {
        let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
        let server =
            BulwarkAuthServer::new(backend).with_tls("/path/to/cert.pem", "/path/to/key.pem");

        let tls_config = server
            .tls_config
            .as_ref()
            .expect("with_tls 后 tls_config 必须为 Some");
        assert_eq!(
            tls_config.cert_path,
            std::path::PathBuf::from("/path/to/cert.pem")
        );
        assert_eq!(
            tls_config.key_path,
            std::path::PathBuf::from("/path/to/key.pem")
        );
    }

    /// 测试未调用 with_tls 时 tls_config 为 None（feature = "tls"）。
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn test_without_tls_config_is_none() {
        let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
        let server = BulwarkAuthServer::new(backend);
        assert!(
            server.tls_config.is_none(),
            "未调用 with_tls 时 tls_config 必须为 None"
        );
    }

    /// 测试 with_tls 链式调用不破坏其他 builder 设置（feature = "tls"）。
    #[cfg(feature = "tls")]
    #[tokio::test]
    async fn test_with_tls_chainable() {
        let backend: Arc<dyn AuthBackend> = Arc::new(MockAuthBackend);
        let server = BulwarkAuthServer::new(backend)
            .with_external_port(9000)
            .with_internal_port(9001)
            .with_rate_limit(50)
            .with_internal_api_key("my-key")
            .with_tls("/cert.pem", "/key.pem");

        assert_eq!(server.config.external_port, 9000);
        assert_eq!(server.config.internal_port, 9001);
        assert_eq!(server.config.external_rate_limit_per_ip, 50);
        assert_eq!(server.config.internal_api_key, "my-key");
        assert!(server.tls_config.is_some());
    }

    // ========================================================================
    // to_api_response 测试
    // ========================================================================

    /// 测试 to_api_response 在 Ok 时返回包含数据的成功响应。
    #[test]
    fn test_to_api_response_ok() {
        let result: Result<i32, BulwarkError> = Ok(42);
        let resp = to_api_response(result);
        assert_eq!(resp.data, Some(42));
        assert!(resp.error_code.is_none());
        assert!(resp.message.is_none());
    }

    /// 测试 to_api_response 在 Err 时返回包含错误码和消息的失败响应。
    #[test]
    fn test_to_api_response_err() {
        let result: Result<i32, BulwarkError> =
            Err(BulwarkError::Internal("test error".to_string()));
        let resp = to_api_response(result);
        assert!(resp.data.is_none());
        assert_eq!(resp.error_code.as_deref(), Some("INTERNAL_ERROR"));
        assert_eq!(resp.message.as_deref(), Some("内部错误"));
    }

    // ========================================================================
    // 路由 path-filter 测试
    // ========================================================================

    /// 测试外网路由拒绝内网路径（返回 404）。
    ///
    /// external_path_filter 中间件仅放行 login/logout/refresh，
    /// 内网端点（如 check/login）应被拦截。
    #[tokio::test]
    async fn test_external_router_rejects_internal_path() {
        let server = make_server();
        let app = server.external_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/auth/check/login")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// 测试内网路由拒绝外网路径（返回 404）。
    ///
    /// internal_path_filter 中间件拒绝 login/logout/refresh，
    /// 即使携带有效 API Key 也应被拦截。
    #[tokio::test]
    async fn test_internal_router_rejects_external_path() {
        let server = make_server();
        let app = server.internal_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/auth/login")
                    .header("x-api-key", "test-api-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// 测试内网路由在 API Key 错误时返回 401。
    #[tokio::test]
    async fn test_internal_router_rejects_wrong_api_key() {
        let server = make_server();
        let app = server.internal_router();
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/api/v1/auth/health")
                    .header("x-api-key", "wrong-api-key")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // ========================================================================
    // AuthServerConfig 测试
    // ========================================================================

    /// 测试 AuthServerConfig::default() 返回正确的默认值。
    #[test]
    fn test_auth_server_config_default() {
        let config = AuthServerConfig::default();
        assert_eq!(config.external_port, 8080);
        assert_eq!(config.internal_port, 8081);
        assert_eq!(config.external_rate_limit_per_ip, 100);
        assert!(
            config.internal_api_key.is_empty(),
            "Default internal_api_key 必须为空（fail-closed）"
        );
    }
}
