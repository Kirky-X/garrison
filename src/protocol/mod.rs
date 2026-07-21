//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 协议层模块，包含各协议插件子模块。
//!
//! 对应 协议层插件集合，
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

/// 社交登录协议插件模块。
///
/// 启用 `social-wechat` 或 `social-alipay` feature 时编译。提供 `SocialLoginProvider` trait
/// 抽象与 `WechatProvider` / `AlipayProvider` 实现。
#[cfg(any(feature = "social-wechat", feature = "social-alipay"))]
pub mod social;

// ============================================================================
// loc! 宏：异常 detail 的 i18n 翻译
// ============================================================================

/// 按 locale 翻译异常 detail。i18n 基础层已无条件编译，始终优先查 FTL 翻译。
///
/// 供社交登录（wechat/alipay）与 Keycloak 等模块在构造 `GarrisonError` detail 字符串时
/// 使用，实现中英文切换。宏定义位于 crate 根（`crate::loc`），此处 re-export 以兼容
/// 既有 `crate::protocol::loc` 调用。
///
/// # 参数
///
/// - `$key`：FTL message key（如 `"wechat-token-request-failed"`）
/// - `$fallback`：FTL 缺失 key 时返回的 `String` 表达式（须与原硬编码消息完全一致）
/// - `($arg_k, $arg_v)`：可选的命名参数（如 `("detail", &e.to_string())`），对应 FTL 中的 `{$detail}`
///
/// # 示例
///
/// ```ignore
/// use crate::error::GarrisonError;
/// use crate::protocol::loc;
///
/// // 带参数
/// let err = GarrisonError::Network(loc!(
///     "wechat-token-request-failed",
///     format!("wechat token request failed: {}", e),
///     ("detail", &e.to_string())
/// ));
///
/// // 不带参数
/// let err = GarrisonError::Network(loc!(
///     "wechat-response-missing-openid",
///     "wechat response missing openid field".to_string()
/// ));
/// ```
pub use crate::loc;
