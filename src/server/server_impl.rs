//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `GarrisonAuthServer` 的实现下沉（builder 方法、路由构建、listen），
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
use super::{middleware, AuthServerConfig, GarrisonAuthServer};
use crate::backend::types::ApiResponse;
use crate::backend::AuthBackend;
use crate::error::{GarrisonError, GarrisonResult};

/// 将 `GarrisonResult<T>` 转换为 `ApiResponse<T>`。
///
/// Ok → `ApiResponse::ok(data)`
/// Err → `ApiResponse::err(error_code, message)`，error_code 来自 `response_parts_i18n()`
///
/// `message` 字段通过 i18n 层翻译为当前 locale 文本，避免硬编码中文泄露到响应体。
pub fn to_api_response<T>(result: Result<T, GarrisonError>) -> ApiResponse<T> {
    match result {
        Ok(data) => ApiResponse::ok(data),
        Err(e) => {
            let (_, error_code, message, _) = e.response_parts_i18n();
            ApiResponse::err(error_code, message)
        },
    }
}

impl GarrisonAuthServer {
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
    /// - `GarrisonError::Internal`：kit 中未注册/未构建 `BackendModule`
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use trait_kit::kit::AsyncKit;
    /// use garrison::backend::BackendModule;
    ///
    /// let mut kit = AsyncKit::new();
    /// kit.register::<BackendModule>().unwrap();
    /// let kit = kit.build().await.unwrap();
    /// let server = GarrisonAuthServer::new_with_kit(kit).await.unwrap();
    /// ```
    #[cfg(feature = "backend-kit")]
    pub async fn new_with_kit(
        kit: trait_kit::kit::AsyncKit<trait_kit::kit::AsyncReady>,
    ) -> GarrisonResult<Self> {
        use crate::backend::BackendModule;
        let backend = kit.require::<BackendModule>().map_err(|e| {
            GarrisonError::Internal(format!("kit require BackendModule failed: {}", e))
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

    /// 是否启用外网登录端点（默认 `false`，secure-by-default）。
    ///
    /// 框架的 login 端点不校验任何凭证（Sa-Token 模型：业务层先验密码、
    /// 框架只负责签发会话）。禁用时外网端口对 `POST /api/v1/auth/login`
    /// 一律返回 404。开启前请确保业务侧已注入凭证校验，否则任何主体
    /// 都能获取任意用户的有效会话；开启后 `listen()` 启动时输出 warn。
    pub fn with_external_login_enabled(mut self, enabled: bool) -> Self {
        self.config.external_login_enabled = enabled;
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

    /// 设置外网请求体大小上限（字节，默认 256KB）。
    ///
    /// 超过此限制的请求返回 `413 Payload Too Large`。
    pub fn with_external_body_limit(mut self, limit: usize) -> Self {
        self.config.external_body_limit = limit;
        self
    }

    /// 设置内网请求体大小上限（字节，默认 1MB）。
    ///
    /// 超过此限制的请求返回 `413 Payload Too Large`。
    pub fn with_internal_body_limits(mut self, limit: usize) -> Self {
        self.config.internal_body_limit = limit;
        self
    }

    /// 注入租户解析器（feature = "tenant-isolation"）。
    ///
    /// `Some(resolver)` 时，`external_router` / `internal_router` 自动注入
    /// `tenant_resolution_middleware`，从请求 headers 解析 `TenantContext` 并
    /// 在 `TENANT` task_local scope 内执行下游 handler——使 `check_permission`
    /// / `check_role` / 审计日志等能通过 `current_tenant_id_or_error()` 读取租户上下文。
    ///
    /// `None` 表示未启用租户隔离（单租户部署），不注入租户中间件。
    ///
    /// # 参数
    /// - `resolver`：`Arc<dyn TenantResolver>`（如 `HeaderTenantResolver` /
    ///   `SubdomainTenantResolver` / `ClaimTenantResolver`）
    ///
    /// # 示例
    ///
    /// ```ignore
    /// use garrison::context::tenant::HeaderTenantResolver;
    /// use std::sync::Arc;
    ///
    /// let server = GarrisonAuthServer::new(backend)
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
    /// let server = GarrisonAuthServer::new(backend)
    ///     .with_tls("/etc/garrison/cert.pem", "/etc/garrison/key.pem");
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
    /// 用 `sdforge::http::build()` 收集所有 `#[forge]` 路由（15 基础 + metrics-prometheus 时 +1），
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
        // fix-security-gaps: 可信代理列表注入 Extension，供 inject_client_ip middleware 读取
        let trusted_proxies =
            middleware::TrustedProxies(self.config.rate_limit_trusted_proxies.clone());
        let router = sdforge::http::build()
            .layer(Extension(self.backend.clone()))
            // C-1: 外网 login 端点默认关闭（secure-by-default）。
            // 框架 login 不校验凭证，业务方注入凭证校验后经
            // with_external_login_enabled(true) 显式开启。
            .layer(axum::middleware::from_fn_with_state(
                middleware::ExternalLoginGate(self.config.external_login_enabled),
                middleware::external_login_gate,
            ))
            .layer(axum::middleware::from_fn(middleware::external_path_filter))
            // fix-security-gaps: IP 自动注入 middleware（path_filter 之后、rate_limit 之前）
            .layer(axum::middleware::from_fn(
                middleware::inject_login_client_ip,
            ))
            .layer(axum::middleware::from_fn(middleware::inject_client_ip))
            // H-8: User-Agent 注入 middleware（在 inject_client_ip 之后）
            .layer(axum::middleware::from_fn(middleware::inject_user_agent))
            .layer(Extension(trusted_proxies))
            .layer(axum::middleware::from_fn_with_state(
                rate_limit_state,
                rate_limit_middleware,
            ));

        // 安全头中间件：rate_limit 之后、audit_log 之前
        // （axum layer 反序执行：audit_log → security_headers → rate_limit → path_filter）
        #[cfg(feature = "web-security-headers")]
        let router = router.layer(axum::middleware::from_fn(
            crate::web::security_headers::security_headers_middleware,
        ));

        let router = router.layer(axum::middleware::from_fn(audit_log_middleware));

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

        // 请求体大小限制（最外层，确保所有 body extractor 受控）
        router.layer(axum::extract::DefaultBodyLimit::max(
            self.config.external_body_limit,
        ))
    }

    /// 构建内网路由（sdforge + path-filter + api_key_auth + rate_limit + audit_log + tenant_resolution）。
    ///
    /// 用 `sdforge::http::build()` 收集所有 `#[forge]` 路由（15 基础 + metrics-prometheus 时 +1），
    /// 通过 `internal_path_filter` 中间件拒绝 3 个外网路径（login/logout/refresh），
    /// 其余内网路径放行（由 api_key_auth 保护）。
    ///
    /// # 内网路由保护（ocr #2234 / #3425）
    ///
    /// - 内网路由同样挂载 `rate_limit_middleware`（限速参数复用外网配置：
    ///   `external_rate_limit_per_ip` / `rate_limit_max_entries` / `rate_limit_trusted_proxies`），
    ///   防止持有合法 API Key 的调用方无限速打满后端资源。
    /// - OAuth2 内网路由（introspect）**先 merge 再统一挂中间件**：axum `merge` 不继承
    ///   layer，若 introspect 路由在挂 layer 后 merge 会绕过 `api_key_auth`。
    ///
    /// 中间件栈（从外到内）：
    /// `tenant_resolution? → audit_log → rate_limit → api_key_auth → internal_path_filter → handler`
    ///
    /// 用于测试时通过 `tower::ServiceExt::oneshot` 发送请求，避免实际 listen。
    pub fn internal_router(&self) -> Router {
        use axum::Extension;
        let api_key_state = Arc::new(middleware::ApiKeyState {
            api_key: self.config.internal_api_key.clone(),
        });
        // ocr #2234: 内网路由限速状态（参数与外网一致，独立 bucket 实例）
        let rate_limit_state = Arc::new(middleware::RateLimitState::with_options(
            self.config.external_rate_limit_per_ip,
            self.config.rate_limit_max_entries,
            self.config.rate_limit_trusted_proxies.clone(),
        ));

        let router = sdforge::http::build().layer(Extension(self.backend.clone()));

        // ocr #3425: OAuth2 内网路由（introspect）先 merge，再统一在内网 router 上
        // 挂 path_filter / api_key_auth / rate_limit / audit_log，
        // 确保 merge 进来的路由不绕过 api_key_auth（axum merge 不继承 layer）。
        #[cfg(feature = "oauth2-server")]
        let router = {
            if let Some(state) = &self.oauth2_state {
                router.merge(oauth2_routes::oauth2_internal_router(state.clone()))
            } else {
                router
            }
        };

        let router = router
            .layer(axum::middleware::from_fn(middleware::internal_path_filter))
            .layer(axum::middleware::from_fn_with_state(
                api_key_state,
                api_key_auth_middleware,
            ))
            .layer(axum::middleware::from_fn_with_state(
                rate_limit_state,
                rate_limit_middleware,
            ))
            .layer(axum::middleware::from_fn(audit_log_middleware));

        // 租户中间件：tenant-isolation feature 启用且注入 resolver 时才挂载
        // （覆盖全部内网路由，含 merge 进来的 introspect，读取 tenant 前缀 key）
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

        // 请求体大小限制（最外层，确保所有 body extractor 受控）
        router.layer(axum::extract::DefaultBodyLimit::max(
            self.config.internal_body_limit,
        ))
    }

    /// 同时启动外网和内网两个 axum 服务器。
    ///
    /// 两个服务器并行运行，任一服务器异常退出时整体返回错误。
    ///
    /// # TLS 终止
    ///
    /// 启用 `tls` feature 且调用 `with_tls()` 后，两个端口均使用
    /// `axum_server::bind_rustls` 替代 `axum::serve`，实现 HTTPS/TLS 终止。
    ///
    /// # 优雅停机（feature = "server-graceful-shutdown"）
    ///
    /// SIGTERM / SIGINT 触发后：停止接收新连接，等待在途请求完成（drain），
    /// 复用 manager cleanup task 的 watch 基建语义。TLS 路径经
    /// `axum_server::Handle::graceful_shutdown`（30s 上限）等效实现。
    pub async fn listen(self) -> GarrisonResult<()> {
        // 启动前校验配置合法性
        self.config.validate().map_err(GarrisonError::Config)?;

        // 信号监听 → Notify 广播给两个端口 serve future
        #[cfg(feature = "server-graceful-shutdown")]
        let shutdown_notify = {
            let notify = Arc::new(tokio::sync::Notify::new());
            let n2 = Arc::clone(&notify);
            tokio::spawn(async move {
                shutdown_signal().await;
                n2.notify_waiters();
            });
            notify
        };

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
            "GarrisonAuthServer starting"
        );
        // C-1: 显式开启外网 login 时提醒业务方凭证校验责任
        if self.config.external_login_enabled {
            tracing::warn!(
                external_port = self.config.external_port,
                "external login endpoint ENABLED (external_login_enabled=true): \
                 GarrisonAuthServer does NOT verify credentials; ensure the \
                 business layer validates credentials before exposing this port"
            );
        }

        // 每 task 专属克隆（async move 捕获整块环境，须在闭包外克隆）
        #[cfg(feature = "server-graceful-shutdown")]
        let shutdown_notify_ext = Arc::clone(&shutdown_notify);
        #[cfg(feature = "server-graceful-shutdown")]
        let shutdown_notify_int = Arc::clone(&shutdown_notify);

        let mut external_handle = tokio::spawn(async move {
            #[cfg(feature = "server-graceful-shutdown")]
            let shutdown_notify = shutdown_notify_ext;
            #[cfg(feature = "tls")]
            if let Some(tc) = tls_config_ext.as_ref() {
                let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
                    &tc.cert_path,
                    &tc.key_path,
                )
                .await
                .map_err(|e| GarrisonError::Internal(format!("server-external-tls-load::{}", e)))?;
                let addr: std::net::SocketAddr = external_addr.parse().map_err(|e| {
                    GarrisonError::Internal(format!("server-external-addr-parse::{}", e))
                })?;
                // TLS 路径经 axum_server::Handle 等效实现优雅停机（30s drain 上限）
                #[cfg(feature = "server-graceful-shutdown")]
                let handle = {
                    let handle = axum_server::Handle::new();
                    let h2 = handle.clone();
                    let notify = Arc::clone(&shutdown_notify);
                    tokio::spawn(async move {
                        notify.notified().await;
                        h2.graceful_shutdown(std::time::Duration::from_secs(30));
                    });
                    handle
                };
                let bind = axum_server::bind_rustls(addr, rustls_config);
                #[cfg(feature = "server-graceful-shutdown")]
                let bind = bind.handle(handle);
                return bind
                    .serve(
                        external_router
                            .into_make_service_with_connect_info::<std::net::SocketAddr>(),
                    )
                    .await
                    .map_err(|e| {
                        GarrisonError::Internal(format!("server-external-server-error::{}", e))
                    });
            }

            let external_listener = tokio::net::TcpListener::bind(&external_addr)
                .await
                .map_err(|e| GarrisonError::Internal(format!("server-external-bind::{}", e)))?;
            let serve = axum::serve(
                external_listener,
                external_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            );
            // 信号触发后停止接收新连接并 drain 在途请求
            #[cfg(feature = "server-graceful-shutdown")]
            let serve = serve.with_graceful_shutdown(async move {
                shutdown_notify.notified().await;
            });
            if let Err(e) = serve.await {
                tracing::error!(error = %e, "external server error");
                return Err(GarrisonError::Internal(format!(
                    "server-external-server-error::{}",
                    e
                )));
            }
            Ok(())
        });

        let mut internal_handle = tokio::spawn(async move {
            #[cfg(feature = "server-graceful-shutdown")]
            let shutdown_notify = shutdown_notify_int;
            #[cfg(feature = "tls")]
            if let Some(tc) = tls_config_int.as_ref() {
                let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(
                    &tc.cert_path,
                    &tc.key_path,
                )
                .await
                .map_err(|e| GarrisonError::Internal(format!("server-internal-tls-load::{}", e)))?;
                let addr: std::net::SocketAddr = internal_addr.parse().map_err(|e| {
                    GarrisonError::Internal(format!("server-internal-addr-parse::{}", e))
                })?;
                // TLS 路径经 axum_server::Handle 等效实现优雅停机（30s drain 上限）
                #[cfg(feature = "server-graceful-shutdown")]
                let handle = {
                    let handle = axum_server::Handle::new();
                    let h2 = handle.clone();
                    let notify = Arc::clone(&shutdown_notify);
                    tokio::spawn(async move {
                        notify.notified().await;
                        h2.graceful_shutdown(std::time::Duration::from_secs(30));
                    });
                    handle
                };
                let bind = axum_server::bind_rustls(addr, rustls_config);
                #[cfg(feature = "server-graceful-shutdown")]
                let bind = bind.handle(handle);
                return bind
                    .serve(
                        // ocr #2236: 内网 TLS 路径同样注入 ConnectInfo，
                        // 与外网路径对齐（限速/IP 提取中间件依赖 ConnectInfo<SocketAddr>）
                        internal_router
                            .into_make_service_with_connect_info::<std::net::SocketAddr>(),
                    )
                    .await
                    .map_err(|e| {
                        GarrisonError::Internal(format!("server-internal-server-error::{}", e))
                    });
            }

            let internal_listener = tokio::net::TcpListener::bind(&internal_addr)
                .await
                .map_err(|e| GarrisonError::Internal(format!("server-internal-bind::{}", e)))?;
            let serve = axum::serve(
                internal_listener,
                // ocr #2236: 内网非 TLS 路径同样注入 ConnectInfo（与外网对齐）
                internal_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            );
            // 信号触发后停止接收新连接并 drain 在途请求
            #[cfg(feature = "server-graceful-shutdown")]
            let serve = serve.with_graceful_shutdown(async move {
                shutdown_notify.notified().await;
            });
            if let Err(e) = serve.await {
                tracing::error!(error = %e, "internal server error");
                return Err(GarrisonError::Internal(format!(
                    "server-internal-server-error::{}",
                    e
                )));
            }
            Ok(())
        });

        // 任一服务器异常即返回错误， 显式 abort 另一个 task 避免资源泄漏
        tokio::select! {
            res = &mut external_handle => {
                internal_handle.abort();
                res.map_err(|e| GarrisonError::Internal(format!("server-external-task-panic::{}", e)))?
            },
            res = &mut internal_handle => {
                external_handle.abort();
                res.map_err(|e| GarrisonError::Internal(format!("server-internal-task-panic::{}", e)))?
            },
        }
    }
}

// ============================================================================
// 优雅停机（feature = "server-graceful-shutdown"）
// ============================================================================

#[cfg(feature = "server-graceful-shutdown")]
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            },
            Err(e) => {
                // 信号处理器安装失败（罕见）：不 panic，退化为仅监听 Ctrl-C
                tracing::warn!(error = %e, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            },
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!(
        "shutdown signal received; stopping new connections and draining in-flight requests"
    );
}

#[cfg(all(test, feature = "server-graceful-shutdown"))]
mod graceful_shutdown_tests {
    use super::*;
    use axum::routing::get;

    /// 触发 shutdown 通知后 serve future 完成（监听停止）；
    /// 触发前到达的在途请求完整收到响应（drain 语义）。
    #[tokio::test]
    async fn graceful_shutdown_drains_and_stops() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind 应成功");
        let addr = listener.local_addr().unwrap();
        // serve 侧持有专属克隆，外层 notify 留作触发端
        let serve_notify = Arc::clone(&notify);

        let app = Router::new().route(
            "/ping",
            get(|| async {
                // 模拟在途处理耗时
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                "pong"
            }),
        );
        let serve = tokio::spawn(async move {
            let serve = axum::serve(
                listener,
                app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
            );
            serve
                .with_graceful_shutdown(async move { serve_notify.notified().await })
                .await
        });

        // 在途请求先于关闭信号到达并应完整完成
        let client = reqwest::get(format!("http://{addr}/ping"))
            .await
            .expect("请求应成功");
        assert_eq!(client.status(), 200);
        assert_eq!(client.text().await.unwrap(), "pong");

        // 触发关闭：serve future 应在超时内完成（监听停止 + drain 完成）
        notify.notify_waiters();
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), serve).await;
        assert!(
            result.is_ok(),
            "shutdown 通知后 serve 应在超时内完成（graceful drain）"
        );
        assert!(result.unwrap().is_ok(), "serve 任务不应 panic");

        // 关闭后新连接被拒绝/超时（监听已停止）
        let new_conn = tokio::time::timeout(
            std::time::Duration::from_millis(300),
            reqwest::get(format!("http://{addr}/ping")),
        )
        .await;
        assert!(
            new_conn.is_err() || new_conn.unwrap().is_err(),
            "shutdown 后新请求应失败（监听已停止）"
        );
    }
}
