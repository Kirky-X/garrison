// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 协议层模块：OAuth2、SSO、JWT、签名、API Key、临时凭证、邀请码、扫码登录、WebAuthn、社交登录等协议插件，各子模块按 feature 门控编译。

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

/// 邀请码定向注册协议插件模块。
#[cfg(feature = "protocol-invitation")]
pub mod invitation;

/// 第一方扫码登录协议模块（两票分离状态机：Web 端扫码、App 端确认）。
#[cfg(feature = "protocol-qrlogin")]
pub mod qrlogin;

/// WebAuthn/Passkey 凭据 SPI 与注册/认证仪式模块。
#[cfg(feature = "protocol-webauthn")]
pub mod webauthn;

/// 社交登录协议插件模块。
///
/// 核心类型（`SocialLoginProvider` trait / `SocialUserInfo` / `SocialLoginService` / `validation`）无 feature 门控，始终编译（外部 crate 无需启用具体 provider 即可注册自定义实现）；内置 provider（`wechat` / `alipay`）仍需对应 feature。
pub mod social;

/// loc! 宏：异常 detail 的 i18n 翻译。
///
/// 按 locale 翻译异常 detail（i18n 基础层无条件编译），供社交登录与 Keycloak 等模块在构造
/// `GarrisonError` detail 时实现中英文切换；宏定义位于 crate 根，此处 re-export。
/// 参数：FTL message key、FTL 缺失时的 fallback 表达式（须与原硬编码消息一致）、可选命名参数（对应 FTL 的 `{$arg}`）。
/// # 示例
///
/// ```ignore
/// use crate::error::GarrisonError;
/// use crate::protocol::loc;
///
/// // 带参数
/// let err = GarrisonError::Network(loc!(
/// "wechat-token-request-failed",
/// format!("wechat token request failed: {}", e),
/// ("detail", &e.to_string())
/// ));
///
/// // 不带参数
/// let err = GarrisonError::Network(loc!(
/// "wechat-response-missing-openid",
/// "wechat response missing openid field".to_string()
/// ));
/// ```
pub use crate::loc;
