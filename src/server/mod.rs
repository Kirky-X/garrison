// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! GarrisonAuthServer — 将 AuthBackend 方法暴露为 HTTP 端点的 axum 服务器。
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
//! use garrison::backend::BackendEmbedded;
//! use garrison::server::GarrisonAuthServer;
//! use std::sync::Arc;
//!
//! let backend: Arc<dyn garrison::backend::AuthBackend> = Arc::new(BackendEmbedded::new());
//! let server = GarrisonAuthServer::new(backend)
//! .with_external_port(8080)
//! .with_internal_port(8081)
//! .with_internal_api_key("secret-api-key")
//! .with_rate_limit(100);
//! server.listen().await?;
//! ```

#[cfg(feature = "tls")]
use std::path::PathBuf;
use std::sync::Arc;

use crate::backend::AuthBackend;
#[cfg(feature = "tenant-isolation")]
use crate::context::tenant::TenantResolver;

/// Server bootstrap configuration (binding, TLS, graceful shutdown settings).
pub mod config;
pub mod middleware;

#[cfg(feature = "auth-server-sdforge")]
pub mod sdforge_routes;

#[cfg(feature = "oauth2-server")]
pub mod oauth2_routes;

mod server_impl;

pub use middleware::{
    api_key_auth_middleware, audit_log_middleware, external_path_filter, inject_client_ip,
    inject_login_client_ip, inject_user_agent, internal_path_filter, rate_limit_middleware,
    ClientIp, TrustedProxies,
};
#[cfg(feature = "session-hijack-detection")]
pub use middleware::{current_client_ip, current_user_agent};
pub use server_impl::to_api_response;

/// Auth Server 配置。
///
/// `Debug` 实现为手动实现：`internal_api_key` 以 `[REDACTED]` 输出，
/// 防止误打日志/错误报告时泄露机密。
#[derive(Clone)]
pub struct AuthServerConfig {
    /// 外网端口（面向用户）。
    pub external_port: u16,
    /// 内网端口（服务间调用）。
    pub internal_port: u16,
    /// 每个 IP 每秒允许的外网请求数（默认 100）。
    pub external_rate_limit_per_ip: u32,
    /// 限速 HashMap 最大条目数（默认 100_000）。
    pub rate_limit_max_entries: usize,
    /// 可信代理 IP 列表（仅这些 IP 的 X-Forwarded-For 被信任）。
    pub rate_limit_trusted_proxies: Vec<std::net::IpAddr>,
    /// 内网 API Key（用于 X-API-Key 头校验）。
    pub internal_api_key: String,
    /// 外网请求体大小上限（字节，默认 256KB）。
    pub external_body_limit: usize,
    /// 内网请求体大小上限（字节，默认 1MB）。
    pub internal_body_limit: usize,
    /// 是否启用外网登录端点（默认 **false**，secure-by-default）。
    ///
    /// 框架的 login 端点不校验任何凭证（Sa-Token 模型：业务层先验密码、
    /// 框架只负责签发会话），因此默认关闭外网 `/api/v1/auth/login`（返回 404）。
    /// 业务方注入自己的凭证校验后，通过 `with_external_login_enabled(true)`
    /// 或直接构造本字段显式开启；开启时 `listen()` 启动输出 warn 提醒。
    pub external_login_enabled: bool,
}

impl std::fmt::Debug for AuthServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthServerConfig")
            .field("external_port", &self.external_port)
            .field("internal_port", &self.internal_port)
            .field(
                "external_rate_limit_per_ip",
                &self.external_rate_limit_per_ip,
            )
            .field("rate_limit_max_entries", &self.rate_limit_max_entries)
            .field(
                "rate_limit_trusted_proxies",
                &self.rate_limit_trusted_proxies,
            )
            .field("internal_api_key", &"[REDACTED]")
            .field("external_body_limit", &self.external_body_limit)
            .field("internal_body_limit", &self.internal_body_limit)
            .field("external_login_enabled", &self.external_login_enabled)
            .finish()
    }
}

/// TLS 配置（证书 + 私钥文件路径）。
///
/// 通过 [`GarrisonAuthServer::with_tls`] 设置，启用后 `listen()` 使用
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

/// GarrisonAuthServer — 双端口 axum 认证服务器。
///
/// 通过 builder 方法配置端口、限速、API Key，最终调用 `listen()` 启动。
pub struct GarrisonAuthServer {
    backend: Arc<dyn AuthBackend>,
    config: AuthServerConfig,
    /// 租户解析器（feature = "tenant-isolation"）。
    ///
    /// `Some(resolver)` 时，external_router / internal_router 自动注入
    /// `tenant_resolution_middleware`，从请求 headers 解析 `TenantContext` 并
    /// 在 `TENANT` task_local scope 内执行下游 handler。
    /// `None` 表示未启用租户隔离（单租户部署），不注入租户中间件。
    #[cfg(feature = "tenant-isolation")]
    tenant_resolver: Option<Arc<dyn TenantResolver>>,
    #[cfg(feature = "oauth2-server")]
    oauth2_state: Option<Arc<oauth2_routes::OAuth2State>>,
    #[cfg(feature = "tls")]
    tls_config: Option<TlsConfig>,
}

#[cfg(test)]
mod tests;
