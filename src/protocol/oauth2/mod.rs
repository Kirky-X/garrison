// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! OAuth2 协议模块（`protocol-oauth2` feature）：Authorization Code / Client Credentials / Password / Refresh Token 四种流程 + Token Introspection (RFC 7662)。
//!
//! `OAuth2Client` 不持久化 token，由业务方决定存储方式；HTTP 客户端使用 `reqwest` 0.13（rustls-tls，禁用 native-tls）。

use serde::{Deserialize, Serialize};

/// OIDC 扩展模块（`protocol-oidc` feature）：`OidcHandler` 签发/验证 id_token，并生成 discovery endpoint 元数据。
#[cfg(feature = "protocol-oidc")]
pub mod oidc;

/// Scope Handler 注册表（`oauth2-scope-handler` feature）：`ScopeHandler` trait + `ScopeRegistry`，在 token 请求前做客户端 scope 策略校验。
#[cfg(feature = "oauth2-scope-handler")]
pub mod scope;

/// Keycloak OIDC RP 模块（`keycloak-oidc` feature）：`KeycloakProvider` 提供 discover / verify_id_token（JWKS 验签）/ exchange_code。
#[cfg(feature = "keycloak-oidc")]
pub mod keycloak;

/// OAuth2 客户端实现模块（四种授权流程 + Token Introspection，`protocol-oauth2` feature）。
pub mod client;

/// Re-export `OAuth2Client` 到模块根，可直接以 `garrison::protocol::oauth2::OAuth2Client` 引用。
pub use client::OAuth2Client;

/// OAuth2 令牌响应；可选字段因带 `#[serde(default)]`，容忍授权服务器省略。
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TokenResponse {
    /// 访问令牌。
    pub access_token: String,
    /// 令牌类型（通常为 "Bearer"）。
    pub token_type: String,
    /// 过期时间（秒）。
    #[serde(default)]
    pub expires_in: Option<i64>,
    /// 刷新令牌。
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// 作用域。
    #[serde(default)]
    pub scope: Option<String>,
}

/// Token Introspection 响应（字段语义见 RFC 7662 §2.2）：`active` 必填，其他字段在 `active=true` 时按需返回。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenIntrospectionResponse {
    /// token 是否当前有效（必填）。
    pub active: bool,
    /// token 的 scope 列表（空格分隔字符串）。
    #[serde(default)]
    pub scope: Option<String>,
    /// token 关联的客户端 ID。
    #[serde(default)]
    pub client_id: Option<String>,
    /// token 关联的人类可读用户名。
    #[serde(default)]
    pub username: Option<String>,
    /// token 类型（如 "Bearer"）。
    #[serde(default)]
    pub token_type: Option<String>,
    /// 过期时间（Unix 时间戳）。
    #[serde(default)]
    pub exp: Option<i64>,
    /// 签发时间（Unix 时间戳）。
    #[serde(default)]
    pub iat: Option<i64>,
    /// 生效时间（Unix 时间戳，之前不可用）。
    #[serde(default)]
    pub nbf: Option<i64>,
    /// 主体标识（通常为用户 ID）。
    #[serde(default)]
    pub sub: Option<String>,
    /// 受众（预期消费者）。
    #[serde(default)]
    pub aud: Option<String>,
    /// 签发者。
    #[serde(default)]
    pub iss: Option<String>,
    /// token 唯一标识。
    #[serde(default)]
    pub jti: Option<String>,
}

// `OAuth2Client` 的 struct/impl/Drop 位于 `client.rs`（mod.rs 接口隔离）；URL 编码见其中的 `url_encode`。

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
