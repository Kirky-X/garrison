//! 协议层模块，包含各协议插件子模块。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的协议层插件集合，
//! 提供 OAuth2、SSO、JWT、签名、API Key、临时凭证等协议支持。
//!
//! 各子模块通过独立特性门控，按需编译。
//!
//! 该模块在 0.1.0 为占位实现，完整功能将在 0.2.0+ 提供。

// ====================================================================
// 协议子模块（特性门控）
// ====================================================================

/// OAuth2 协议插件模块。
#[cfg(feature = "protocol-oauth2")]
pub mod oauth2;

/// 单点登录 (SSO) 协议插件模块。
#[cfg(feature = "protocol-sso")]
pub mod sso;

/// JWT 协议插件模块。
#[cfg(feature = "protocol-jwt")]
pub mod jwt;

/// 签名协议插件模块。
#[cfg(feature = "protocol-sign")]
pub mod sign;

/// API Key 协议插件模块。
#[cfg(feature = "protocol-apikey")]
pub mod apikey;

/// 临时凭证协议插件模块。
#[cfg(feature = "protocol-temp")]
pub mod temp;
