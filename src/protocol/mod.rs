//! 协议层模块，包含各协议插件子模块。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的协议层插件集合，
//! 提供 OAuth2、SSO、JWT、签名、API Key、临时凭证等协议支持。
//!
//! 各子模块通过独立特性门控，按需编译。0.2.0 已实现全部协议子模块。

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

/// 社交登录协议插件模块（0.5.0 新增，依据 proposal H2 / spec social-login）。
///
/// 启用 `social-wechat` 或 `social-alipay` feature 时编译。提供 `SocialLoginProvider` trait
/// 抽象与 `WechatProvider` / `AlipayProvider` 实现。
#[cfg(any(feature = "social-wechat", feature = "social-alipay"))]
pub mod social;
