//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

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
//!     .with_external_port(8080)
//!     .with_internal_port(8081)
//!     .with_internal_api_key("secret-api-key")
//!     .with_rate_limit(100);
//! server.listen().await?;
//! ```

#[cfg(feature = "tls")]
use std::path::PathBuf;
use std::sync::Arc;

use crate::backend::AuthBackend;
#[cfg(feature = "tenant-isolation")]
use crate::context::tenant::TenantResolver;

pub mod config;
pub mod middleware;

#[cfg(feature = "auth-server-sdforge")]
pub mod sdforge_routes;

#[cfg(feature = "oauth2-server")]
pub mod oauth2_routes;

mod server_impl;

pub use middleware::{
    api_key_auth_middleware, audit_log_middleware, external_path_filter, internal_path_filter,
    rate_limit_middleware,
};
pub use server_impl::to_api_response;

/// Auth Server 配置。
#[derive(Debug, Clone)]
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
    /// `None` 时跳过租户中间件（向后兼容单租户场景或测试桩）。
    #[cfg(feature = "tenant-isolation")]
    tenant_resolver: Option<Arc<dyn TenantResolver>>,
    #[cfg(feature = "oauth2-server")]
    oauth2_state: Option<Arc<oauth2_routes::OAuth2State>>,
    #[cfg(feature = "tls")]
    tls_config: Option<TlsConfig>,
}

#[cfg(test)]
mod tests;
