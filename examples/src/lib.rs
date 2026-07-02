//! Bulwark 官方示例集库模块。
//!
//! 每个 bin 的核心逻辑提取为 `pub fn run()`（或 `pub async fn run()`），
//! 由 `src/bin/<name>.rs` 作为 thin wrapper 调用，并由 `tests/<name>.rs` 进行测试。
//!
//! # 模块分类
//!
//! - **always-on**：无需 feature 即可编译（exception_handling / json_template / token_styles / custom_plugin / permission_check / auth_logic_impl / config_loader）
//! - **feature-gated**：需对应 feature 才可编译（sign_utils / httpbasic_login / ...）
//!
//! # 运行示例
//!
//! ```sh
//! cargo run -p bulwark-examples --bin <name> --features full
//! ```

// ====================================================================
// always-on 模块（无需 feature 门控）
// ====================================================================

pub mod auth_logic_impl;
pub mod config_loader;
pub mod custom_plugin;
pub mod exception_handling;
pub mod json_template;
pub mod permission_check;
pub mod token_styles;

// ====================================================================
// feature-gated 模块
// ====================================================================

#[cfg(feature = "secure-sign")]
pub mod sign_utils;

#[cfg(feature = "secure-httpbasic")]
pub mod httpbasic_login;

#[cfg(feature = "secure-httpdigest")]
pub mod httpdigest_login;

#[cfg(feature = "protocol-sign")]
pub mod sign_protocol;

#[cfg(feature = "protocol-apikey")]
pub mod apikey_management;

#[cfg(feature = "protocol-temp")]
pub mod temp_credential;

#[cfg(feature = "listener")]
pub mod event_listener;

#[cfg(feature = "protocol-jwt")]
pub mod jwt_login;

#[cfg(feature = "protocol-oauth2")]
pub mod oauth2_flow;

#[cfg(feature = "protocol-sso")]
pub mod sso_flow;

#[cfg(feature = "secure-totp")]
pub mod totp_login;

#[cfg(feature = "cache-memory")]
pub mod session_management;

#[cfg(feature = "cache-memory")]
pub mod dao_operations;

#[cfg(feature = "web-axum")]
pub mod context_request;

#[cfg(all(feature = "cache-memory", feature = "web-axum"))]
pub mod strategy_firewall;

#[cfg(all(feature = "cache-memory", feature = "web-axum"))]
pub mod manager_lifecycle;

#[cfg(all(feature = "cache-memory", feature = "web-axum"))]
pub mod basic_login;

#[cfg(all(feature = "cache-memory", feature = "web-axum"))]
pub mod axum_integration;

// ====================================================================
// 0.4.0 新增 feature-gated 模块
// ====================================================================

#[cfg(feature = "protocol-oidc")]
pub mod oidc_handler;

#[cfg(feature = "oauth2-scope-handler")]
pub mod scope_handler;

#[cfg(feature = "protocol-sso-server")]
pub mod sso_server;

#[cfg(feature = "alone-cache")]
pub mod alone_cache;

#[cfg(feature = "parameter-query")]
pub mod parameter_query;
