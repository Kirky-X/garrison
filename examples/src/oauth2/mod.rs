//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OAuth2 / OIDC / SSO 示例模块。

#[cfg(feature = "keycloak-oidc")]
pub mod keycloak_oidc;
#[cfg(feature = "protocol-oauth2")]
pub mod oauth2_flow;
#[cfg(feature = "protocol-oauth2")]
pub mod oauth2_pkce;
#[cfg(feature = "oauth2-server")]
pub mod oauth2_server_flow;
#[cfg(feature = "protocol-oidc")]
pub mod oidc_handler;
#[cfg(feature = "oauth2-scope-handler")]
pub mod scope_handler;
#[cfg(feature = "social-alipay")]
pub mod social_alipay;
#[cfg(feature = "protocol-sso")]
pub mod sso_flow;
#[cfg(feature = "protocol-sso-server")]
pub mod sso_server;
#[cfg(feature = "protocol-oauth2")]
pub mod token_introspection;
