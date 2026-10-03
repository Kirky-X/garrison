// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `GarrisonAuthServer` 的实现下沉（builder 方法、路由构建、listen），
//! 与 [`crate::server`] 中的类型定义（struct/config）分离，遵循 mod 接口隔离原则。

#[cfg(feature = "tls")]
use std::path::PathBuf;
use std::sync::Arc;

use axum::Router;

#[cfg(feature = "oauth2-server")]
use super::oauth2_routes;
#[cfg(feature = "protocol-qrlogin")]
use super::qrlogin_routes;
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

/// OAuth2 启动期维护：reconcile 引用已删 client 的孤儿 consent 行。
///
/// `listen()` 在监听端口前调用（R18 / R-consent-004「启动 reconcile 清理
/// 已删 client 的 consent 行」）。内联 await 而非后台 spawn：清理在首个
/// authorize 请求前完成（确定性语义），代价是启动耗时受 consent 键数量
/// 约束（keys 扫描 + 逐键比对，低频启动路径可接受）。
///
/// 维护性操作 fail-open：失败仅告警不阻断启动——孤儿行只是垃圾数据
/// （已删 client 的 authorize 过不了 client 存活校验，残留行不影响鉴权
/// 正确性），下次启动或运维显式调用 `AuthorizeHandler::reconcile_consents`
/// 可重试。
#[cfg(feature = "oauth2-server")]
async fn oauth2_consent_startup_reconcile(state: &oauth2_routes::OAuth2State) {
    match state.authorize_handler.reconcile_consents().await {
        Ok((removed, kept)) if removed > 0 => {
            tracing::info!(
                removed,
                kept,
                "oauth2 consent startup reconcile: removed orphan consent rows of deleted clients"
            );
        },
        Ok((_, kept)) => {
            tracing::debug!(kept, "oauth2 consent startup reconcile: no orphan rows");
        },
        Err(e) => {
            tracing::warn!(
                error = %e,
                "oauth2 consent startup reconcile failed (fail-open); orphan rows \
                 (if any) remain — retry on next restart or via reconcile_consents"
            );
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
            #[cfg(feature = "protocol-qrlogin")]
            qrlogin_state: None,
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

    /// 设置内网 API Key 认证失败锁定（GAR-25）。
    ///
    /// # 参数
    /// - `threshold`：同源 IP 连续失败阈值，达到后窗口期内一律 429；`0` 禁用
    /// - `window_secs`：锁定窗口秒数
    pub fn with_api_key_lockout(mut self, threshold: u32, window_secs: u64) -> Self {
        self.config.api_key_lockout_threshold = threshold;
        self.config.api_key_lockout_window_secs = window_secs;
        self
    }

    /// 是否透传内网 `/readyz` 的 `checks[].details`（默认 **false**，GAR-14）。
    ///
    /// details 可能包含内部依赖拓扑（host、延迟等），默认剥离仅保留
    /// name/healthy；显式开启后方可在内网探针中输出诊断细节。
    pub fn with_health_details(mut self, enabled: bool) -> Self {
        self.config.health_details_enabled = enabled;
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
    /// .with_tenant_resolver(Some(Arc::new(HeaderTenantResolver)));
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

    /// 注入扫码登录状态，启用 4 个扫码登录端点（feature = "protocol-qrlogin"）。
    ///
    /// 外网端口添加 create/poll/scan/confirm。
    #[cfg(feature = "protocol-qrlogin")]
    pub fn with_qrlogin(mut self, state: Arc<qrlogin_routes::QrLoginHttpState>) -> Self {
        self.qrlogin_state = Some(state);
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
    /// .with_tls("/etc/garrison/cert.pem", "/etc/garrison/key.pem");
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
            // GAR-27: Json extractor rejection（400/415/422）统一清洗，
            // 不向调用方回显内部类型名/字段名/字节偏移
            .layer(axum::middleware::from_fn(
                middleware::sanitize_json_rejection_middleware,
            ))
            .layer(axum::middleware::from_fn(middleware::inject_client_ip))
            // User-Agent 注入 middleware（在 inject_client_ip 之后）
            .layer(axum::middleware::from_fn(middleware::inject_user_agent))
            .layer(Extension(trusted_proxies))
            .layer(axum::middleware::from_fn_with_state(
                rate_limit_state.clone(),
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

        #[cfg(feature = "protocol-qrlogin")]
        let router = {
            if let Some(state) = &self.qrlogin_state {
                // 注：qrlogin 存储键为全局命名空间（garrison:qrlogin:*，租户记在
                // 会话 JSON 内），刻意不注入 tenant_resolution_middleware——匿名
                // create/poll 与带租户头的 scan/confirm 必须命中同一批 key。
                //
                // axum merge 不继承 layer：qrlogin router 必须在 merge 前自带与
                // 主栈同构的中间件（rate_limit / client_ip / user_agent /
                // audit_log），否则 4 个端点将绕过外网限流与审计（与下方
                // oauth2 router 单独注入同一语义）。
                let qrlogin_router = qrlogin_routes::qrlogin_external_router(state.clone())
                    .layer(axum::middleware::from_fn(middleware::inject_client_ip))
                    .layer(axum::middleware::from_fn(middleware::inject_user_agent))
                    .layer(Extension(middleware::TrustedProxies(
                        self.config.rate_limit_trusted_proxies.clone(),
                    )))
                    .layer(axum::middleware::from_fn_with_state(
                        rate_limit_state.clone(),
                        middleware::rate_limit_middleware,
                    ))
                    .layer(axum::middleware::from_fn(audit_log_middleware));
                router.merge(qrlogin_router)
            } else {
                router
            }
        };

        // 请求体大小限制（最外层，确保所有 body extractor 受控）
        let router = router.layer(axum::extract::DefaultBodyLimit::max(
            self.config.external_body_limit,
        ));

        // server-health-check：K8s liveness 探针 merge 在最外层——axum merge 不继承
        // layer，探针绕过 path_filter/rate_limit/audit 全部中间件（K8s 探针惯例）。
        // GAR-14：外网端口仅暴露最小化 /healthz（无版本号），/readyz 仅挂内网。
        #[cfg(feature = "server-health-check")]
        let router = router.merge(Self::external_health_probe_router());

        router
    }

    /// 外网健康探针路由（server-health-check feature）。
    ///
    /// GAR-14 最小语义：外网仅 `/healthz`，响应只含 `{"status":"healthy"}`——
    /// 不暴露 sdforge 版本号，不暴露 `/readyz`（readiness 拓扑仅限内网）。
    #[cfg(feature = "server-health-check")]
    fn external_health_probe_router() -> Router {
        use axum::routing::get;
        Router::new().route("/healthz", get(super::health::liveness_handler))
    }

    /// 内网健康探针路由（server-health-check feature）。
    ///
    /// `/healthz` 最小语义同外网；`/readyz` 依据已注册 readiness check 返回
    /// 200/503（业务方经 `sdforge::health::register_readiness_check_fn` 注册），
    /// `checks[].details` 仅在 `health_details_enabled=true` 时透传（默认剥离）。
    #[cfg(feature = "server-health-check")]
    fn internal_health_probe_router(&self) -> Router {
        use axum::routing::get;
        Router::new()
            .route("/healthz", get(super::health::liveness_handler))
            .route("/readyz", get(super::health::readiness_handler))
            .with_state(super::health::HealthDetailsEnabled(
                self.config.health_details_enabled,
            ))
    }

    /// 构建内网路由（sdforge + path-filter + api_key_auth + rate_limit + audit_log + tenant_resolution）。
    ///
    /// 用 `sdforge::http::build()` 收集所有 `#[forge]` 路由（15 基础 + metrics-prometheus 时 +1），
    /// 通过 `internal_path_filter` 中间件拒绝 3 个外网路径（login/logout/refresh），
    /// 其余内网路径放行（由 api_key_auth 保护）。
    ///
    /// # 内网路由保护
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
        // GAR-25: 认证失败锁定由配置驱动（threshold=0 禁用）
        let api_key_state = Arc::new(middleware::ApiKeyState {
            api_key: self.config.internal_api_key.clone(),
            lockout: Arc::new(super::api_key_lockout::ApiKeyLockout::new(
                self.config.api_key_lockout_threshold,
                self.config.api_key_lockout_window_secs,
            )),
        });
        // 内网路由限速状态（参数与外网一致，独立 bucket 实例）
        let rate_limit_state = Arc::new(middleware::RateLimitState::with_options(
            self.config.external_rate_limit_per_ip,
            self.config.rate_limit_max_entries,
            self.config.rate_limit_trusted_proxies.clone(),
        ));

        let router = sdforge::http::build().layer(Extension(self.backend.clone()));

        // OAuth2 内网路由（introspect）先 merge，再统一在内网 router 上
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
            // GAR-27: 内网端点同样统一清洗 Json rejection（类型名不因内网信任
            // 边界而豁免——单 key 泄露即可触达）
            .layer(axum::middleware::from_fn(
                middleware::sanitize_json_rejection_middleware,
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
        let router = router.layer(axum::extract::DefaultBodyLimit::max(
            self.config.internal_body_limit,
        ));

        // server-health-check：内网探针同样 merge 在最外层（绕过 api_key_auth，
        // K8s 探针不持有 API Key）；/readyz 的 details 经配置门控（GAR-14）
        #[cfg(feature = "server-health-check")]
        let router = router.merge(self.internal_health_probe_router());

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
    ///
    /// # 优雅停机（feature = "server-graceful-shutdown"）
    ///
    /// SIGTERM / SIGINT 触发后：停止接收新连接，等待在途请求完成（drain），
    /// 复用 manager cleanup task 的 watch 基建语义。TLS 路径经
    /// `axum_server::Handle::graceful_shutdown`（30s 上限）等效实现。
    pub async fn listen(self) -> GarrisonResult<()> {
        // 启动前校验配置合法性
        self.config.validate().map_err(GarrisonError::Config)?;

        // 启动期维护（R18 R-consent-004）：清理引用已删 client 的孤儿 consent 行。
        // fail-open：维护失败仅告警，不阻断启动（见函数文档）。
        #[cfg(feature = "oauth2-server")]
        if let Some(state) = &self.oauth2_state {
            oauth2_consent_startup_reconcile(state).await;
        }

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
                        h2.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
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
                        h2.graceful_shutdown(Some(std::time::Duration::from_secs(30)));
                    });
                    handle
                };
                let bind = axum_server::bind_rustls(addr, rustls_config);
                #[cfg(feature = "server-graceful-shutdown")]
                let bind = bind.handle(handle);
                return bind
                    .serve(
                        // 内网 TLS 路径同样注入 ConnectInfo，
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
                // 内网非 TLS 路径同样注入 ConnectInfo（与外网对齐）
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

#[cfg(all(test, feature = "oauth2-server"))]
mod oauth2_startup_reconcile_tests {
    use super::*;
    use crate::dao::{GarrisonDao, InMemoryDao};
    use crate::oauth2_server::client::{
        DaoOAuth2ClientStore, GrantType, OAuth2Client, OAuth2ClientStore,
    };

    fn make_client(id: &str) -> OAuth2Client {
        OAuth2Client::new(
            id,
            "secret-123",
            vec!["https://app.example.com/cb".into()],
            vec![GrantType::AuthorizationCode],
            vec!["read".into()],
        )
        .unwrap()
    }

    /// listen() 启动接线的实测：删除 client 后启动清理对应 consent 行，
    /// 存活 client 的记录原样保留（R-consent-004「删除 client 后启动清理
    /// 对应行」的启动路径用例；reconcile 本体的分支语义见
    /// authorize.rs `reconcile_removes_orphan_consent_and_keeps_live`）。
    #[tokio::test]
    async fn startup_reconcile_removes_orphan_and_keeps_live() {
        let dao = Arc::new(InMemoryDao::new());
        let store: Arc<DaoOAuth2ClientStore> = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
        let state = oauth2_routes::OAuth2State::new(
            store.clone(),
            dao.clone(),
            "https://auth.example.com/login".into(),
        );
        store.create(make_client("reconcile-live")).await.unwrap();
        store.create(make_client("reconcile-dead")).await.unwrap();
        let handler = &state.authorize_handler;
        handler
            .grant_consent(0, 9101, "reconcile-live", &["read".into()], &[])
            .await
            .unwrap();
        handler
            .grant_consent(0, 9102, "reconcile-dead", &["read".into()], &[])
            .await
            .unwrap();
        store.delete("reconcile-dead").await.unwrap();

        // listen() 启动路径调用的正是本函数（见 listen() 的 oauth2-server 分支）
        oauth2_consent_startup_reconcile(&state).await;

        assert!(
            dao.get("oauth2:consent:0:9102:reconcile-dead")
                .await
                .unwrap()
                .is_none(),
            "启动 reconcile 应清理已删 client 的孤儿 consent 行"
        );
        assert!(
            dao.get("oauth2:consent:0:9101:reconcile-live")
                .await
                .unwrap()
                .is_some(),
            "存活 client 的 consent 行应保留"
        );
    }

    /// keys() 直接报错的 DAO：不实现 `keys()` 即命中默认 NotImplemented
    /// Err，恰好充当 reconcile 首步（client list 扫描）的故障注入。
    struct ReconcileFailingDao;

    #[async_trait::async_trait]
    impl crate::dao::GarrisonDao for ReconcileFailingDao {
        async fn get(&self, _key: &str) -> GarrisonResult<Option<String>> {
            Ok(None)
        }
        async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }
        async fn update(&self, _key: &str, _value: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }
        async fn delete(&self, _key: &str) -> GarrisonResult<()> {
            Ok(())
        }

        crate::atomic_test_fallback!();
    }

    /// reconcile 失败 fail-open：DAO 故障（keys() Err）不向启动路径传播
    /// 错误、不 panic——listen() 不因维护性清理失败而拒绝启动。
    #[tokio::test]
    async fn startup_reconcile_failure_is_fail_open() {
        let dao: Arc<dyn crate::dao::GarrisonDao> = Arc::new(ReconcileFailingDao);
        let store = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
        let state =
            oauth2_routes::OAuth2State::new(store, dao, "https://auth.example.com/login".into());

        // 不 panic、不 Err——错误仅记录告警（fail-open 语义，见函数文档）
        oauth2_consent_startup_reconcile(&state).await;
    }
}
