//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OAuth2 协议模块，提供 Authorization Code / Client Credentials / Password / Refresh Token 四种授权流程。
//!
//! 对应 OAuth2 协议支持，
//! 基于 `reqwest` crate 实现 HTTP 请求。
//!
//! 仅在启用 `protocol-oauth2` 特性时编译。
//!
//! ## 设计决策
//!
//! - `OAuth2Client` 不持久化 token，由业务方决定存储方式。
//! - HTTP 客户端使用 `reqwest` 0.13（rustls-tls，禁用 native-tls）。
//! - 实现四种授权流程：Authorization Code / Client Credentials / Password / Refresh Token（）。
//! - 支持 Token Introspection (RFC 7662)：通过 `OAuth2Client::introspect_token` 查询 token 状态（）。

use serde::{Deserialize, Serialize};

/// OIDC 扩展模块。
///
/// 提供 `OidcHandler` 用于签发/验证 OIDC id_token + discovery endpoint 元数据生成。
/// 仅在启用 `protocol-oidc` feature 时编译。
#[cfg(feature = "protocol-oidc")]
pub mod oidc;

/// Scope Handler 注册表模块。
///
/// 提供 `ScopeHandler` trait + `ScopeRegistry` 动态注册表，用于在 OAuth2 token
/// 请求前对 scope 进行客户端策略校验。仅在启用 `oauth2-scope-handler` feature 时编译。
#[cfg(feature = "oauth2-scope-handler")]
pub mod scope;

/// Keycloak OIDC RP 模块。
///
/// 提供 `KeycloakProvider` 作为 OIDC 依赖方（RP），对接 Keycloak IdP：
/// - `KeycloakConfig`：配置 base_url / client_id / client_secret / redirect_uri
/// - `KeycloakProvider`：discover（fetch discovery metadata）/ verify_id_token（JWKS 验签）
///   / exchange_code（authorization_code → token set）
/// - `KeycloakClaims`：Keycloak 特有 claim（realm_access.roles / resource_access / tenant_id）
///
/// 仅在启用 `keycloak-oidc` feature 时编译。
#[cfg(feature = "keycloak-oidc")]
pub mod keycloak;

/// OAuth2 客户端实现模块。
///
/// 提供 [`OAuth2Client`]（OAuth2 协议客户端），实现 Authorization Code / Client
/// Credentials / Password / Refresh Token 四种授权流程，以及 Token Introspection
/// (RFC 7662)。仅在启用 `protocol-oauth2` feature 时编译。
pub mod client;

/// OAuth2 客户端 re-export。
///
/// 通过 `pub use` 将 `client::OAuth2Client` 暴露在 `protocol::oauth2` 命名空间根，
/// 供外部以 `garrison::protocol::oauth2::OAuth2Client` 直接使用。
pub use client::OAuth2Client;

/// OAuth2 令牌响应。
///
/// 授权服务器返回的 JSON 通过 `Deserialize` 解析。
/// 可选字段使用 `#[serde(default)]` 以容忍授权服务器省略部分字段。
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TokenResponse {
    /// 访问令牌（必填）。
    pub access_token: String,
    /// 令牌类型（必填，通常为 "Bearer"）。
    pub token_type: String,
    /// 过期时间（秒，可选）。
    #[serde(default)]
    pub expires_in: Option<i64>,
    /// 刷新令牌（可选）。
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// 作用域（可选）。
    #[serde(default)]
    pub scope: Option<String>,
}

/// Token Introspection 响应。
///
/// 表示授权服务器对 token 的 introspection 结果。`active` 字段为必填，
/// 其他字段在 `active=true` 时由授权服务器按需返回；`active=false` 时通常省略。
///
/// # 字段语义（RFC 7662 §2.2）
/// - `active`: token 是否当前有效（必填）。
/// - `scope`: token 的 scope 列表（空格分隔字符串）。
/// - `client_id`: token 关联的客户端 ID。
/// - `username`: token 关联的人类可读用户名。
/// - `token_type`: token 类型（如 "Bearer"）。
/// - `exp`: token 过期时间（Unix 时间戳）。
/// - `iat`: token 签发时间（Unix 时间戳）。
/// - `nbf`: token 生效时间（Unix 时间戳，之前不可用）。
/// - `sub`: token 主体标识（通常为用户 ID）。
/// - `aud`: token 受众（预期消费者）。
/// - `iss`: token 签发者。
/// - `jti`: token 唯一标识。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenIntrospectionResponse {
    /// token 是否当前有效（必填，RFC 7662 §2.2）。
    pub active: bool,
    /// token 的 scope 列表（空格分隔字符串，RFC 7662 §2.2）。
    #[serde(default)]
    pub scope: Option<String>,
    /// token 关联的客户端 ID（RFC 7662 §2.2）。
    #[serde(default)]
    pub client_id: Option<String>,
    /// token 关联的人类可读用户名（RFC 7662 §2.2）。
    #[serde(default)]
    pub username: Option<String>,
    /// token 类型（如 "Bearer"，RFC 7662 §2.2）。
    #[serde(default)]
    pub token_type: Option<String>,
    /// token 过期时间（Unix 时间戳，RFC 7662 §2.2）。
    #[serde(default)]
    pub exp: Option<i64>,
    /// token 签发时间（Unix 时间戳，RFC 7662 §2.2）。
    #[serde(default)]
    pub iat: Option<i64>,
    /// token 生效时间（Unix 时间戳，之前不可用，RFC 7662 §2.2）。
    #[serde(default)]
    pub nbf: Option<i64>,
    /// token 主体标识（通常为用户 ID，RFC 7662 §2.2）。
    #[serde(default)]
    pub sub: Option<String>,
    /// token 受众（预期消费者，RFC 7662 §2.2）。
    #[serde(default)]
    pub aud: Option<String>,
    /// token 签发者（RFC 7662 §2.2）。
    #[serde(default)]
    pub iss: Option<String>,
    /// token 唯一标识（RFC 7662 §2.2）。
    #[serde(default)]
    pub jti: Option<String>,
}

// ============================================================================
// OAuth2Client struct + impl + Drop 已迁移至 `client.rs`（规则 25：mod.rs 接口隔离）。
// URL 编码工具由 `percent-encoding` crate 提供，详见 `client.rs` 中的 `url_encode`。
// ============================================================================

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
