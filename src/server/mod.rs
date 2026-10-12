// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! GarrisonAuthServer — 将 AuthBackend 方法暴露为 HTTP 端点的 axum 服务器。
//!
//! 双端口：外网（external_port）仅 login/logout/refresh 3 个端点，配 rate_limit（按 IP）+
//! audit + sanitize_json_rejection 中间件；内网（internal_port）暴露 check-*/get-*/kickout 等
//! 12 个端点，配 api_key_auth（失败锁定）+ audit + sanitize 中间件。爆破防护边界：内网 API Key
//! 失败锁定与每 IP 令牌桶限速均为**单实例内存态**——单进程内可阻断爆破与限流刷量，但 429 后约 1 秒
//! 桶即补满、无递进惩罚/封禁升级，多实例不共享锁定状态；生产（尤其多副本）应启用
//! `firewall-bruteforce`（ban-manager）与 `ban-sync` 获得跨实例递进封禁。
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

/// Server 启动配置（端口绑定、TLS、优雅停机）。
pub mod config;
pub mod middleware;

/// 内网 API Key 认证失败锁定状态。
pub mod api_key_lockout;

#[cfg(feature = "server-health-check")]
pub mod health;

#[cfg(feature = "auth-server-sdforge")]
pub mod sdforge_routes;

#[cfg(feature = "oauth2-server")]
pub mod oauth2_routes;

/// 扫码登录 HTTP 端点路由（feature = "protocol-qrlogin"）。
#[cfg(feature = "protocol-qrlogin")]
pub mod qrlogin_routes;

mod server_impl;

pub use api_key_lockout::ApiKeyLockout;
/// 可信代理内网地址判定（回环 / RFC1918 / link-local / IPv6 ULA）：库层单一实现，`AuthServerConfig::validate` 与参考部署 bin 的 `parse_trusted_proxies` 共用本函数。
pub use config::is_private_proxy_addr;
pub use middleware::{
    api_key_auth_middleware, audit_log_middleware, external_path_filter, inject_client_ip,
    inject_login_client_ip, inject_user_agent, internal_path_filter, rate_limit_middleware,
    sanitize_json_rejection_middleware, ClientIp, TrustedProxies,
};
#[cfg(feature = "session-hijack-detection")]
pub use middleware::{current_client_ip, current_user_agent};
pub use server_impl::to_api_response;

/// 内网 API Key 最小长度（字节）：管理面承载 check-*/kickout 等特权端点，下限对齐 HS256 密钥 32 字节，由 `AuthServerConfig::validate` 统一强制。
pub const MIN_INTERNAL_API_KEY_LEN: usize = 32;

/// 外网登录暴露确认串：开启外网 login 端点时须显式声明已知风险并传入本串（非机密，原样输出）。
pub const EXTERNAL_LOGIN_ACK: &str = "i-understand-no-credential-check";

/// Auth Server 配置。
///
/// `Debug` 手动实现：`internal_api_key` 以 `[REDACTED]` 输出，防误打日志/错误报告泄露机密。
#[derive(Clone)]
pub struct AuthServerConfig {
    /// 外网端口（面向用户）。
    pub external_port: u16,
    /// 外网端口绑定地址（默认 **0.0.0.0**，既有 `listen()` 行为不变）；安全敏感部署应经 `with_external_bind` 显式收口（参考部署 bin 缺省 127.0.0.1）。
    pub external_bind: std::net::IpAddr,
    /// 内网端口（服务间调用）。
    pub internal_port: u16,
    /// 内网端口绑定地址（默认 **0.0.0.0**，语义同 `external_bind`）。
    pub internal_bind: std::net::IpAddr,
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
    /// 是否启用外网登录端点（默认 **false**，secure-by-default）：框架 login 端点不校验任何凭证（Sa-Token 模型：业务层先验密码、框架只负责签发会话），因此默认关闭外网 `/api/v1/auth/login`（返回 404）；业务方注入凭证校验后经 `with_external_login_enabled(true)` 显式开启，开启时 `listen()` 启动输出 warn 提醒。
    pub external_login_enabled: bool,
    /// 内网 API Key 认证失败锁定阈值（默认 10；**0 = 禁用锁定**）：同一源 IP 连续认证失败（缺失/错误/重复 `X-API-Key`）达到阈值后，窗口期内一律 429 + `Retry-After`，成功认证即清零；`GARRISON_API_KEY_LOCKOUT_THRESHOLD` 可覆盖。
    pub api_key_lockout_threshold: u32,
    /// API Key 失败锁定窗口秒数（默认 300，`GARRISON_API_KEY_LOCKOUT_WINDOW_SECS` 可覆盖）。
    pub api_key_lockout_window_secs: u64,
    /// 内网 `/readyz` 探针是否透传 `checks[].details`（默认 **false**）：details 可能含内部依赖拓扑（host、延迟等），默认剥离仅保留 name/healthy；经 `GARRISON_HEALTH_DETAILS=true` 或 `with_health_details(true)` 显式开启。
    pub health_details_enabled: bool,
    /// 严格安全档（默认 **false**，只告警不拒绝）：`true` 时短内网 API Key 与未确认的外网登录暴露在 `validate()` 直接返回错误；`false` 时同样条件只输出带迁移指引的 `tracing::warn!`。
    pub strict_security: bool,
    /// 外网登录暴露确认串（默认 `None`）。
    ///
    /// 启用外网登录端点且绑定非回环时，须传入与 [`EXTERNAL_LOGIN_ACK`] 完全相等的确认串（非机密）。
    pub external_login_ack: Option<String>,
}

impl std::fmt::Debug for AuthServerConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthServerConfig")
            .field("external_port", &self.external_port)
            .field("external_bind", &self.external_bind)
            .field("internal_port", &self.internal_port)
            .field("internal_bind", &self.internal_bind)
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
            .field("api_key_lockout_threshold", &self.api_key_lockout_threshold)
            .field(
                "api_key_lockout_window_secs",
                &self.api_key_lockout_window_secs,
            )
            .field("health_details_enabled", &self.health_details_enabled)
            .field("strict_security", &self.strict_security)
            .field("external_login_ack", &self.external_login_ack)
            .finish()
    }
}

/// TLS 配置（PEM 证书 + 私钥文件路径，仅 `tls` feature 下编译）：经 [`GarrisonAuthServer::with_tls`] 设置，启用后 `listen()` 用 `axum_server::bind_rustls` 替代 `axum::serve`，实现 HTTPS/TLS 终止。
#[cfg(feature = "tls")]
#[derive(Debug, Clone)]
pub struct TlsConfig {
    /// PEM 格式证书文件路径。
    pub cert_path: PathBuf,
    /// PEM 格式私钥文件路径。
    pub key_path: PathBuf,
}

/// GarrisonAuthServer — 双端口 axum 认证服务器；通过 builder 方法配置端口、限速、API Key，最终调用 `listen()` 启动。
pub struct GarrisonAuthServer {
    backend: Arc<dyn AuthBackend>,
    config: AuthServerConfig,
    /// 租户解析器（feature = "tenant-isolation"）：`Some` 时 external/internal router 自动注入 `tenant_resolution_middleware`（解析 `TenantContext` 并在 `TENANT` task_local scope 内执行 handler）；`None` 为单租户部署，不注入。
    #[cfg(feature = "tenant-isolation")]
    tenant_resolver: Option<Arc<dyn TenantResolver>>,
    #[cfg(feature = "oauth2-server")]
    oauth2_state: Option<Arc<oauth2_routes::OAuth2State>>,
    /// 扫码登录路由状态（feature = "protocol-qrlogin"）。
    #[cfg(feature = "protocol-qrlogin")]
    qrlogin_state: Option<Arc<qrlogin_routes::QrLoginHttpState>>,
    #[cfg(feature = "tls")]
    tls_config: Option<TlsConfig>,
}

#[cfg(test)]
mod tests;
