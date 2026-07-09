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

// ============================================================================
// loc! 宏：异常 detail 的 i18n 翻译（0.6.0 新增，依据 T021）
// ============================================================================

/// 按 locale 翻译异常 detail，未启用 `i18n` 特性时返回 fallback。
///
/// 供社交登录（wechat/alipay）与 Keycloak 等模块在构造 `BulwarkError` detail 字符串时
/// 使用，实现中英文切换。
///
/// # 参数
///
/// - `$key`：FTL message key（如 `"wechat-token-request-failed"`）
/// - `$fallback`：未启用 `i18n` 特性时返回的 `String` 表达式（须与原硬编码消息完全一致）
/// - `($arg_k, $arg_v)`：可选的命名参数（如 `("detail", &e.to_string())`），对应 FTL 中的 `{$detail}`
///
/// # 行为
///
/// - `i18n` 特性启用：调用 [`crate::i18n::translate_detail`] 查询 fluent bundle，返回本地化字符串
/// - `i18n` 特性未启用：直接返回 `$fallback`，行为与 0.5.x 硬编码一致
///
/// # 示例
///
/// ```ignore
/// use crate::error::BulwarkError;
/// use crate::protocol::loc;
///
/// // 带参数
/// let err = BulwarkError::Network(loc!(
///     "wechat-token-request-failed",
///     format!("wechat token request failed: {}", e),
///     ("detail", &e.to_string())
/// ));
///
/// // 不带参数
/// let err = BulwarkError::Network(loc!(
///     "wechat-response-missing-openid",
///     "wechat response missing openid field".to_string()
/// ));
/// ```
#[macro_export]
macro_rules! loc {
    ($key:expr, $fallback:expr $(, ($arg_k:expr, $arg_v:expr))*) => {{
        #[cfg(feature = "i18n")]
        {
            $crate::i18n::translate_detail($key, &[$(($arg_k, $arg_v)),*])
        }
        #[cfg(not(feature = "i18n"))]
        {
            $fallback
        }
    }};
}
