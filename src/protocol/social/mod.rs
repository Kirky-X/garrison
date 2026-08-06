//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 社交登录协议插件模块。
//!
//! 提供 `SocialLoginProvider` trait 抽象社交登录第三方平台（微信/支付宝），
//! 统一 `get_authorization_url` / `exchange_token` / `get_user_info` 三个 OAuth2 流程方法。
//!
//! ## 子模块
//!
//! - `wechat`：微信扫码登录（`WechatProvider`，需 `social-wechat` feature）
//! - `alipay`：支付宝授权登录（`AlipayProvider`，需 `social-alipay` feature）
//!
//! ## 与 OAuth2 模块的关系
//!
//! `protocol::oauth2` 提供通用 OAuth2 客户端（Authorization Code / Client Credentials / Password），
//! 本模块针对社交平台特化（微信/支付宝的自定义 API 签名、用户信息格式）。

use crate::error::GarrisonResult;
use async_trait::async_trait;
use serde_json::Value;

// ============================================================================
// provider_names：内置社交平台名称常量
// ============================================================================

/// 内置社交登录平台名称常量。
///
/// `SocialUserInfo.provider` 字段使用 `String` 而非枚举，允许外部 crate 自定义 provider
/// 注册到 `SocialLoginService`。本模块为内置 provider（wechat/alipay/wechat_mini_app）
/// 提供标准化的名称常量，外部 crate 应使用自己的常量（如 `pub const HUAWEI: &str = "huawei"`）
/// 以避免与内置 provider 冲突。
pub mod provider_names {
    /// 微信开放平台扫码登录。
    pub const WECHAT: &str = "wechat";
    /// 支付宝开放平台授权登录。
    pub const ALIPAY: &str = "alipay";
    /// 微信小程序登录。
    pub const WECHAT_MINI_APP: &str = "wechat_mini_app";
}

// ============================================================================
// SocialUserInfo：社交用户信息
// ============================================================================

/// 社交用户信息。
///
/// `exchange_token` / `get_user_info` 方法的返回类型，承载第三方平台返回的用户字段。
///
/// `provider` 字段为 `String` 类型（非枚举），允许外部 crate 自定义 provider 标识。
/// 内置 provider 用 [`provider_names`] 模块的常量（`"wechat"` / `"alipay"` / `"wechat_mini_app"`）。
#[derive(Debug, Clone)]
pub struct SocialUserInfo {
    /// 用户来源平台标识（字符串，外部 crate 可自定义）。
    pub provider: String,
    /// 第三方平台用户唯一 ID（微信 openid / 支付宝 user_id / 华为 openID）。
    pub provider_user_id: String,
    /// 用户昵称（可能为空）。
    pub nickname: Option<String>,
    /// 用户头像 URL（可能为空）。
    pub avatar: Option<String>,
    /// 跨应用统一 ID（微信 unionid / 华为 unionID，用于同一开发者主体下多应用账号打通）。
    pub union_id: Option<String>,
    /// 第三方平台原始响应 JSON（调试用，不应依赖其结构）。
    pub raw: Value,
}

// ============================================================================
// 子模块声明
// ============================================================================

/// 微信扫码登录 provider。
///
/// 启用 `social-wechat` feature 时编译。
#[cfg(feature = "social-wechat")]
pub mod wechat;

/// 支付宝授权登录 provider。
///
/// 启用 `social-alipay` feature 时编译。
#[cfg(feature = "social-alipay")]
pub mod alipay;

// ============================================================================
// urlencoding：社交登录 URL 编码工具（公共模块）
// ============================================================================

/// 社交登录 URL 编码工具。
///
/// 提供对查询参数值的百分号编码，保留 RFC 3986 unreserved 字符。
/// 各 social provider（wechat/alipay）与外部 crate 自定义 provider 共用，
/// 避免每个 provider 重复实现编码逻辑。
pub mod urlencoding;

/// 社交登录 provider 名称校验工具。
///
/// 提供 [`validation::is_valid_provider_name`] 函数，校验 provider 标识符格式合法性。
/// 供 garrison 内部与外部 crate（如 sinnan）共用，确保校验规则单一来源（DIP）。
pub mod validation;

// ============================================================================
// SocialBindingService（feature = "db-sqlite"）
// ============================================================================

/// 社交账号绑定服务。
///
/// 提供 `find_or_create` 语义：首次社交登录时自动创建绑定关系并生成新 `login_id`，
/// 后续登录返回已有 `login_id`（幂等）。
///
/// # 设计
///
/// struct 仅持有 `dao: Arc<dyn GarrisonDao>`，SQL 操作通过
/// `GarrisonDaoDbnexus`（KV + SQL 统一实现）委托执行，
/// 业务层不再直接持有 `DbPool`。
///
/// # 表结构
///
/// ```sql
/// CREATE TABLE social_bindings (
///     id               INTEGER PRIMARY KEY AUTOINCREMENT,
///     tenant_id        INTEGER NOT NULL DEFAULT 0,
///     login_id         TEXT    NOT NULL,
///     provider         TEXT    NOT NULL,
///     provider_user_id TEXT    NOT NULL,
///     union_id         TEXT,
///     created_at       INTEGER NOT NULL,
///     UNIQUE(tenant_id, provider, provider_user_id)
/// );
/// ```
///
/// `UNIQUE(tenant_id, provider, provider_user_id)` 保证同一租户下同一社交账号仅绑定一个 login_id。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub struct SocialBindingService {
    /// 数据访问抽象（通过 `GarrisonDaoDbnexus` 实现 SQL 操作）。
    pub dao: std::sync::Arc<dyn crate::dao::GarrisonDao>,
}

/// `SocialBindingService` 实现模块（任意 db 后端 feature）。
///
/// 从 `mod.rs` 迁移以符合规则 25（mod.rs 接口隔离）：
/// impl 块不允许留在 `mod.rs`。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub(crate) mod service;

/// `SocialLoginService` 注册中心模块。
///
/// 提供 `SocialLoginService` 类型，外部 crate 可注册自定义 `SocialLoginProvider` 实现
/// （如华为 Account Kit），实现扩展点架构。
pub mod registry;

// ============================================================================
// re-export：社交登录错误码常量（H5 架构修复：消除跨 crate 模块路径耦合）
// ============================================================================
//
// 外部 crate（如 sinnan）通过 `garrison::protocol::social::ERR_SOCIAL_PROVIDER_*`
// 直接引用常量，无需深入 `registry` 子模块路径。
// 这符合规则10 接口隔离：mod.rs 暴露公共 API，隐藏内部模块结构。

/// 社交登录 provider 未注册错误码（re-export 自 `registry` 模块）。
///
/// 消费方用此常量做 `starts_with` 匹配，避免硬编码字符串契约。
pub use registry::ERR_SOCIAL_PROVIDER_NOT_REGISTERED;

/// 社交登录 provider 名称格式非法错误码（re-export 自 `registry` 模块）。
pub use registry::ERR_SOCIAL_PROVIDER_NAME_INVALID;

// ============================================================================
// SocialLoginProvider trait：社交登录抽象
// ============================================================================

/// 社交登录服务提供方 trait。
///
/// 定义三个异步方法覆盖 OAuth2 授权码流程：
/// - `get_authorization_url`：拼接授权页 URL（用户跳转到第三方平台授权）
/// - `exchange_token`：用授权码换取 access_token + provider_user_id（仅完成 code → access_token 一步，nickname/avatar 为 None，调用方需再调 `get_user_info`）
/// - `get_user_info`：用 access_token 获取用户信息（用于已缓存 token 的场景）
///
/// # 实现
///
/// - `WechatProvider`（`social-wechat` feature）
/// - `AlipayProvider`（`social-alipay` feature）
#[async_trait]
pub trait SocialLoginProvider: Send + Sync {
    /// 拼接第三方平台授权页 URL。
    ///
    /// # 参数
    /// - `state`: OAuth2 state 参数（CSRF 防护，调用方生成随机串并缓存校验）
    /// - `redirect_uri`: 授权回调 URL（需在第三方平台配置白名单）
    async fn get_authorization_url(
        &self,
        state: &str,
        redirect_uri: &str,
    ) -> GarrisonResult<String>;

    /// 用授权码换取用户信息。
    ///
    /// 用授权码换取完整用户信息（含 provider_user_id + nickname + avatar）。
    ///
    /// 实现必须返回完整 `SocialUserInfo`（必要时内部调用 `get_user_info`）。
    /// `social_callback` handler 直接使用返回的 `provider_user_id` 创建绑定，
    /// 若 `provider_user_id` 为空会导致 500（fail-closed）。
    ///
    /// # 参数
    /// - `code`: 授权码（第三方平台回调时附在 query 参数，一次性消费）
    /// - `state`: OAuth2 state 参数（校验一致性，防 CSRF）
    async fn exchange_token(&self, code: &str, state: &str) -> GarrisonResult<SocialUserInfo>;

    /// 用 access_token 获取用户信息。
    ///
    /// 用于已缓存 access_token 的场景（避免重复授权）。
    ///
    /// # 参数
    /// - `access_token`: 第三方平台访问令牌
    async fn get_user_info(&self, access_token: &str) -> GarrisonResult<SocialUserInfo>;
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
