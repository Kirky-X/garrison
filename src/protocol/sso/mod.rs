// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 单点登录 (SSO) 协议模块（`protocol-sso` feature），提供 ticket 签发/校验/销毁。
//!
//! ticket 经 `GarrisonDao` 存储，TTL 60 秒、一次性使用。
//!
//! ## Key 命名空间
//!
//! 票据存于 `garrison:sso:ticket:<ticket>`，与 session/sign/apikey/temp 隔离。

// SSO Server 独立抽象模块（`protocol-sso-server` feature，依赖 `protocol-sso`）。
#[cfg(feature = "protocol-sso-server")]
pub mod server;

#[cfg(feature = "protocol-sso-server")]
pub use server::SsoServer;

// SAML 2.0 协议支持。
pub mod saml;

// OIDC RP 协议支持。
pub mod oidc;

/// Re-export OIDC 核心类型：经 `garrison::protocol::sso::*` 直接访问，无需 `oidc::` 前缀。
pub use oidc::{DefaultOidcProvider, OidcDiscoveryConfig, OidcProvider, OidcUserInfo};

// Redis pub/sub SsoChannel 实现（`cache-redis` + `protocol-sso-server` feature 同时启用时编译）。
#[cfg(all(feature = "cache-redis", feature = "protocol-sso-server"))]
pub mod channel;

use crate::dao::GarrisonDao;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// `SsoClient` 实现（接口隔离：impl 块与顶层签名函数不放 `mod.rs`）。
pub(crate) mod client;

/// SSO ticket 存储的 JSON 数据，`pub(crate)` 供 `server` 复用，避免格式漂移。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SsoTicketData {
    /// 登录主体标识。
    pub(crate) login_id: String,
    /// 客户端标识。
    pub(crate) client_id: i64,
}

/// SSO 客户端，经 `Arc<dyn GarrisonDao>` 存储 ticket（TTL 默认 60 秒），可多线程共享。
///
/// # Ticket 签名
///
/// 格式 `{64_hex_random}.{hmac_b64}`，用 HMAC-SHA256 签名防伪造；secret 必传且不可为空。
pub struct SsoClient {
    /// DAO 抽象层，用于票据存储。
    dao: Arc<dyn GarrisonDao>,
    /// 票据 TTL（秒）。
    ticket_ttl_seconds: u64,
    /// HMAC 签名密钥（所有 ticket 必须签名）。
    secret: String,
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
