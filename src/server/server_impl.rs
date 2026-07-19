//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `BulwarkAuthServer` 的实现下沉（builder 方法、路由构建、listen），
//! 与 [`crate::server`] 中的类型定义（struct/config）分离，遵循 mod 接口隔离原则。

#[cfg(feature = "tls")]
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;

#[cfg(feature = "oauth2-server")]
use super::oauth2_routes;
#[cfg(feature = "tls")]
use super::TlsConfig;
use super::{api_key_auth_middleware, audit_log_middleware, rate_limit_middleware};
use super::{middleware, AuthServerConfig, BulwarkAuthServer};
use crate::backend::types::ApiResponse;
use crate::backend::AuthBackend;
use crate::error::{BulwarkError, BulwarkResult};

/// 将 `BulwarkResult<T>` 转换为 `ApiResponse<T>`。
///
/// Ok → `ApiResponse::ok(data)`
/// Err → `ApiResponse::err(error_code, message)`，error_code 来自 `response_parts_i18n()`
///
/// `message` 字段通过 i18n 层翻译为当前 locale 文本，避免硬编码中文泄露到响应体。
pub fn to_api_response<T>(result: Result<T, BulwarkError>) -> ApiResponse<T> {
    match result {
        Ok(data) => ApiResponse::ok(data),
        Err(e) => {
            let (_, error_code, message, _) = e.response_parts_i18n();
            ApiResponse::err(error_code, message)
        },
    }
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
            #[cfg(feature = "tenant-isolation")]
            tenant_resolver: None,
            #[cfg(feature = "oauth2-server")]
            oauth2_state: None,
            #[cfg(feature = "tls")]
            tls_config: None,
        }
    }

    /// 用 trait-kit AsyncKit 构建后端（可选路径，feature = "backend-kit"）。
    ///
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

    /// 设置限速 HashMap 最大条目数（默认 100_000）。
    ///
    /// 超过此值时 LRU 淘汰最久未访问的 bucket，防 DoS 内存耗尽。
    pub fn with_rate_limit_max_entries(mut self, max_entries: usize) -> Self {
        self.config.rate_limit_max_entries = max_entries;
        self
    }

    /// 设置可信代理 IP 列表。
    ///
    /// 仅来自这些 IP 的请求的 X-Forwarded-For 头被信任，其余使用连接 IP。
    pub fn with_trusted_proxies(mut self, proxies: Vec<std::net::IpAddr>) -> Self {
        self.config.rate_limit_trusted_proxies = proxies;
        self
    }

    /// 设置内网 API Key（用于 X-API-Key 头校验）。
    pub fn with_internal_api_key(mut self, api_key: impl Into<String>) -> Self {
        self.config.internal_api_key = api_key.into();
        self
    }

    /// 注入租户解析器（feature = "tenant-isolation"）。
    ///
    /// `Some(resolver)` 时，`external_router` / `internal_router` 自动注入
    /// `tenant_resolution_middleware`，从请求 headers 解析 `TenantContext` 并
    /// 在 `TENANT` task_local scope 内执行下游 handler——使 `check_permission`
    /// / `check_role` / 审计日志等能通过 `current_tenant_id_or_error()` 读取租户上下文。
    ///
    /// `None` 时跳过租户中间件（向后兼容单租户场景）。
    ///
    /// # 参数
    /// - `resolver`：`Arc<dyn TenantResolver>`（如 `HeaderTenantResolver` /
    ///   `SubdomainTenantResolver` / `ClaimTenantResolver`）
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use bulwark::context::tenant::HeaderTenantResolver;
    /// use std::sync::Arc;
    ///
    /// let server = BulwarkAuthServer::new(backend)
    ///     .with_tenant_resolver(Some(Arc::new(HeaderTenantResolver)));
    /// ```
    #[cfg(feature = "tenant-isolation")]
    pub fn with_tenant_resolver(
        mut self,
        resolver: Option<Arc<dyn crate::context::tenant::TenantResolver>>,
    ) -> Self {
        self.tenant_resolver = resolver;
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

    /// 构建外网路由（sdforge + path-filter + rate_limit + audit_log + tenant_resolution）。
    ///
    /// 用 `sdforge::http::build()` 收集所有 `#[forge]` 路由（15 端点），
    /// 通过 `external_path_filter` 中间件仅放行 3 个外网路径（login/logout/refresh），
    /// 其余内网路径返回 404。
    ///
    /// 中间件栈（从外到内）：
    /// `audit_log → rate_limit → external_path_filter → tenant_resolution? → handler`
    ///
    /// `tenant_resolution_middleware` 仅在 `tenant-isolation` feature 启用且
    /// `with_tenant_resolver(Some(..))` 设置时注入。
    ///
    /// 用于测试时通过 `tower::ServiceExt::oneshot` 发送请求，避免实际 listen。
    pub fn external_router(&self) -> Router {
        use axum::Extension;
        let rate_limit_state = Arc::new(middleware::RateLimitState::with_options(
            self.config.external_rate_limit_per_ip,
            self.config.rate_limit_max_entries,
            self.config.rate_limit_trusted_proxies.clone(),
        ));
        let router = sdforge::http::build()
            .layer(Extension(self.backend.clone()))
            .layer(axum::middleware::from_fn(middleware::external_path_filter))
            .layer(axum::middleware::from_fn_with_state(
                rate_limit_state,
                rate_limit_middleware,
            ))
            .layer(axum::middleware::from_fn(audit_log_middleware));

        // 租户中间件：tenant-isolation feature 启用且注入 resolver 时才挂载
        #[cfg(feature = "tenant-isolation")]
        let router = {
            if let Some(resolver) = &self.tenant_resolver {
                router.layer(axum::middleware::from_fn_with_state(
                    resolver.clone(),
                    crate::router::tenant_resolution_middleware,
                ))
            } else {
                router
            }
        };

        #[cfg(feature = "oauth2-server")]
        let router = {
            if let Some(state) = &self.oauth2_state {
                let oauth2_router = oauth2_routes::oauth2_external_router(state.clone())
                    .layer(axum::middleware::from_fn(
                        middleware::principal_inject_middleware,
                    ))
                    .layer(Extension(self.backend.clone()));

                // 租户中间件：axum merge 不合并 layer，必须为 OAuth2 router 单独注入。
                // 否则 login 写入 key 含 tenant 前缀（`tenant:0:session:xxx`），
                // 而 OAuth2 端点（principal_inject_middleware → backend.get_session）
                // 读时无 TENANT scope 导致 key 不带前缀（`session:xxx`），命中失败。
                #[cfg(feature = "tenant-isolation")]
                let oauth2_router = {
                    if let Some(resolver) = &self.tenant_resolver {
                        oauth2_router.layer(axum::middleware::from_fn_with_state(
                            resolver.clone(),
                            crate::router::tenant_resolution_middleware,
                        ))
                    } else {
                        oauth2_router
                    }
                };

                router.merge(oauth2_router)
            } else {
                router
            }
        };

        router
    }

    /// 构建内网路由（sdforge + path-filter + api_key_auth + audit_log + tenant_resolution）。
    ///
    /// 用 `sdforge::http::build()` 收集所有 `#[forge]` 路由（15 端点），
    /// 通过 `internal_path_filter` 中间件拒绝 3 个外网路径（login/logout/refresh），
    /// 其余内网路径放行（由 api_key_auth 保护）。
    ///
    /// 中间件栈（从外到内）：
    /// `audit_log → api_key_auth → internal_path_filter → tenant_resolution? → handler`
    ///
    /// `tenant_resolution_middleware` 仅在 `tenant-isolation` feature 启用且
    /// `with_tenant_resolver(Some(..))` 设置时注入。
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

        // 租户中间件：tenant-isolation feature 启用且注入 resolver 时才挂载
        #[cfg(feature = "tenant-isolation")]
        let router = {
            if let Some(resolver) = &self.tenant_resolver {
                router.layer(axum::middleware::from_fn_with_state(
                    resolver.clone(),
                    crate::router::tenant_resolution_middleware,
                ))
            } else {
                router
            }
        };

        #[cfg(feature = "oauth2-server")]
        let router = {
            if let Some(state) = &self.oauth2_state {
                let oauth2_router = oauth2_routes::oauth2_internal_router(state.clone());

                // 租户中间件：与 external_router 同理，axum merge 不合并 layer。
                // introspect 端点需在 TENANT scope 内读 access_token（与 token_endpoint 写入前缀一致）。
                #[cfg(feature = "tenant-isolation")]
                let oauth2_router = {
                    if let Some(resolver) = &self.tenant_resolver {
                        oauth2_router.layer(axum::middleware::from_fn_with_state(
                            resolver.clone(),
                            crate::router::tenant_resolution_middleware,
                        ))
                    } else {
                        oauth2_router
                    }
                };

                router.merge(oauth2_router)
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
            "BulwarkAuthServer starting"
        );

        let mut external_handle = tokio::spawn(async move {
            #[cfg(feature = "tls")]
            if let Some(tc) = tls_config_ext.as_ref() {
                let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
                    &tc.cert_path,
                    &tc.key_path,
                )
                .await
                .map_err(|e| BulwarkError::Internal(format!("server-external-tls-load::{}", e)))?;
                let addr: std::net::SocketAddr = external_addr.parse().map_err(|e| {
                    BulwarkError::Internal(format!("server-external-addr-parse::{}", e))
                })?;
                return axum_server::bind_rustls(addr, rustls_config)
                    .serve(
                        external_router
                            .into_make_service_with_connect_info::<std::net::SocketAddr>(),
                    )
                    .await
                    .map_err(|e| {
                        BulwarkError::Internal(format!("server-external-server-error::{}", e))
                    });
            }

            let external_listener = tokio::net::TcpListener::bind(&external_addr)
                .await
                .map_err(|e| BulwarkError::Internal(format!("server-external-bind::{}", e)))?;
            if let Err(e) = axum::serve(
                external_listener,
                external_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            )
            .await
            {
                tracing::error!(error = %e, "external server error");
                return Err(BulwarkError::Internal(format!(
                    "server-external-server-error::{}",
                    e
                )));
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
                .map_err(|e| BulwarkError::Internal(format!("server-internal-tls-load::{}", e)))?;
                let addr: std::net::SocketAddr = internal_addr.parse().map_err(|e| {
                    BulwarkError::Internal(format!("server-internal-addr-parse::{}", e))
                })?;
                return axum_server::bind_rustls(addr, rustls_config)
                    .serve(internal_router.into_make_service())
                    .await
                    .map_err(|e| {
                        BulwarkError::Internal(format!("server-internal-server-error::{}", e))
                    });
            }

            let internal_listener = tokio::net::TcpListener::bind(&internal_addr)
                .await
                .map_err(|e| BulwarkError::Internal(format!("server-internal-bind::{}", e)))?;
            if let Err(e) = axum::serve(internal_listener, internal_router).await {
                tracing::error!(error = %e, "internal server error");
                return Err(BulwarkError::Internal(format!(
                    "server-internal-server-error::{}",
                    e
                )));
            }
            Ok(())
        });

        // 任一服务器异常即返回错误，M-1: 显式 abort 另一个 task 避免资源泄漏
        tokio::select! {
            res = &mut external_handle => {
                internal_handle.abort();
                res.map_err(|e| BulwarkError::Internal(format!("server-external-task-panic::{}", e)))?
            },
            res = &mut internal_handle => {
                external_handle.abort();
                res.map_err(|e| BulwarkError::Internal(format!("server-internal-task-panic::{}", e)))?
            },
        }
    }
}
