//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 单点登录 (SSO) 协议模块，提供 ticket 签发/校验/销毁能力。
//!
//! 对应 SSO 单点登录支持，
//! 通过 `BulwarkDao` 存储 ticket（TTL 60 秒，一次性使用）。
//!
//! 仅在启用 `protocol-sso` 特性时编译。
//!
//! ## Key 命名空间
//!
//! 所有 SSO 票据存储在 `bulwark:sso:ticket:<ticket>` 命名空间下，
//! 与 session/sign/apikey/temp 模块隔离。

// SSO Server 独立抽象模块。
// 仅在启用 `protocol-sso-server` 特性时编译，依赖 `protocol-sso`。
#[cfg(feature = "protocol-sso-server")]
pub mod server;

// 模块重导出：通过 mod 路径访问子模块类型（避免外部代码引用具体文件路径）
#[cfg(feature = "protocol-sso-server")]
pub use server::SsoServer;

// SAML 2.0 协议支持。
pub mod saml;

// OIDC RP 协议支持。
pub mod oidc;

/// Re-export OIDC 核心类型（Rule 25：mod.rs 暴露接口）。
///
/// 通过 `bulwark::protocol::sso::OidcProvider` / `DefaultOidcProvider`
/// / `OidcDiscoveryConfig` / `OidcUserInfo` 直接访问，无需 `oidc::` 前缀。
pub use oidc::{DefaultOidcProvider, OidcDiscoveryConfig, OidcProvider, OidcUserInfo};

// Redis pub/sub SsoChannel 实现。
// 仅在 cache-redis + protocol-sso-server feature 同时启用时编译。
#[cfg(all(feature = "cache-redis", feature = "protocol-sso-server"))]
pub mod channel;

use crate::dao::BulwarkDao;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// `SsoClient` 实现模块。
///
/// 从 `mod.rs` 迁移以符合规则 25（mod.rs 接口隔离）：
/// impl 块与顶层 `fn sign_ticket` / `fn verify_ticket_signature` 不允许留在 `mod.rs`。
/// `server.rs` 通过 `use super::client::{sign_ticket, verify_ticket_signature}` 直接引用。
pub(crate) mod client;

/// SSO ticket 存储的 JSON 数据。
///
/// `pub(crate)` 暴露以供 `server` 模块复用，避免跨模块重复定义导致格式漂移（M6 修复）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SsoTicketData {
    /// 登录主体标识。
    pub(crate) login_id: String,
    /// 客户端标识。
    pub(crate) client_id: i64,
}

/// SSO 客户端，提供 ticket 签发/校验/销毁。
///
/// 持有 `Arc<dyn BulwarkDao>` 用于票据存储，TTL 默认 60 秒。
/// 实现 `Send + Sync`，可在多线程环境共享。
///
/// # Ticket 签名（依据安全审计 M5）
///
/// 所有 ticket 使用 HMAC-SHA256 签名，格式为 `{64_hex_random}.{hmac_b64}`。
/// 即使 DAO 层被攻破或存在 key 碰撞，攻击者也无法伪造有效签名。
/// secret 由 `new(dao, secret)` 必传，禁止空 secret。
pub struct SsoClient {
    /// DAO 抽象层，用于票据存储。
    dao: Arc<dyn BulwarkDao>,
    /// 票据 TTL（秒）。
    ticket_ttl_seconds: u64,
    /// HMAC 签名密钥（M5 修复：所有 ticket 必须签名）。
    secret: String,
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
