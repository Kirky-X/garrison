// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 社交登录协议插件模块：`SocialLoginProvider` trait 抽象第三方平台（微信/支付宝），统一 `get_authorization_url` / `exchange_token` / `get_user_info` 三个 OAuth2 流程方法。
//!
//! 与 `protocol::oauth2`（通用 OAuth2 客户端）不同，本模块针对社交平台特化（自定义 API 签名、用户信息格式）；
//! 子模块 `wechat`（`social-wechat`）与 `alipay`（`social-alipay`）按 feature 编译。

use crate::error::GarrisonResult;
use async_trait::async_trait;
use serde_json::Value;

// provider_names：内置社交平台名称常量

/// 内置社交登录平台名称常量。
///
/// `SocialUserInfo.provider` 为 `String` 而非枚举，允许外部 crate 自定义 provider；外部 crate 应使用自己的常量（如 `pub const HUAWEI: &str = "huawei"`）避免与内置 provider 冲突。
pub mod provider_names {
    /// 微信开放平台扫码登录。
    pub const WECHAT: &str = "wechat";
    /// 支付宝开放平台授权登录。
    pub const ALIPAY: &str = "alipay";
    /// 微信小程序登录。
    pub const WECHAT_MINI_APP: &str = "wechat_mini_app";
}

// SocialUserInfo：社交用户信息

/// 社交用户信息（`exchange_token` / `get_user_info` 方法的返回类型）。
///
/// `provider` 为 `String` 非枚举，允许外部 crate 自定义 provider 标识；内置 provider 用 [`provider_names`] 常量。
///
/// # Debug 脱敏
///
/// 手动实现 `Debug`（不派生）：`raw` 可能含 `access_token` / `session_key` / PII，故仅打印 `<redacted: N bytes>` 摘要，其余字段原样输出。
#[derive(Clone)]
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
    /// 第三方平台原始响应 JSON（调试用，不应依赖其结构）：内置 provider 已剥离 `access_token` / `session_key`（见 `wechat::strip_sensitive_fields`），但仍可能含 PII，禁止原样打印/持久化。
    pub raw: Value,
}

impl std::fmt::Debug for SocialUserInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // raw 不进 Debug 输出，仅以字节数摘要标注。
        f.debug_struct("SocialUserInfo")
            .field("provider", &self.provider)
            .field("provider_user_id", &self.provider_user_id)
            .field("nickname", &self.nickname)
            .field("avatar", &self.avatar)
            .field("union_id", &self.union_id)
            .field(
                "raw",
                &format_args!(
                    "<redacted: {} bytes>",
                    serde_json::to_vec(&self.raw).map(|v| v.len()).unwrap_or(0)
                ),
            )
            .finish()
    }
}

// 子模块声明

/// 微信扫码登录 provider（`social-wechat` feature）。
#[cfg(feature = "social-wechat")]
pub mod wechat;

/// 支付宝授权登录 provider（`social-alipay` feature）。
#[cfg(feature = "social-alipay")]
pub mod alipay;

// urlencoding：社交登录 URL 编码工具（公共模块）

/// 社交登录 URL 编码工具（各 social provider 与外部 crate 共用，避免重复实现）。
pub mod urlencoding;

/// 社交登录 provider 名称校验工具，供 garrison 与外部 crate（如 sinnan）共用（DIP：规则单一来源）。
pub mod validation;

// SocialBindingService（feature = "db-sqlite"）

/// 社交账号绑定服务：`find_or_create` 首次社交登录创建绑定并生成新 `login_id`，后续返回已有值（幂等）。
///
/// # 设计
///
/// 仅持有 `dao: Arc<dyn GarrisonDao>`，SQL 经 `GarrisonDaoDbnexus`（KV + SQL 统一实现）委托执行，业务层不直接持有 `DbPool`。
///
/// # 表结构
///
/// ```sql
/// CREATE TABLE social_bindings (
/// id INTEGER PRIMARY KEY AUTOINCREMENT,
/// tenant_id INTEGER NOT NULL DEFAULT 0,
/// login_id TEXT NOT NULL,
/// provider TEXT NOT NULL,
/// provider_user_id TEXT NOT NULL,
/// union_id TEXT,
/// created_at INTEGER NOT NULL,
/// UNIQUE(tenant_id, provider, provider_user_id)
/// );
/// ```
///
/// `UNIQUE(tenant_id, provider, provider_user_id)` 保证同一租户下同一社交账号仅绑定一个 login_id。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub struct SocialBindingService {
    /// 数据访问抽象（通过 `GarrisonDaoDbnexus` 实现 SQL 操作）。
    pub dao: std::sync::Arc<dyn crate::dao::GarrisonDao>,
}

/// `SocialBindingService` 实现（接口隔离：impl 不放 `mod.rs`）。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub(crate) mod service;

/// `SocialLoginService` 注册中心：外部 crate 可注册自定义 `SocialLoginProvider`（如华为 Account Kit）。
pub mod registry;

// re-export：社交登录错误码常量
//
// 外部 crate（如 sinnan）经 `garrison::protocol::social::ERR_SOCIAL_PROVIDER_*` 直接引用，
// 无需深入 `registry` 子模块路径（接口隔离：mod.rs 暴露公共 API）。

/// 社交登录 provider 未注册错误码（消费方用 `starts_with` 匹配，避免硬编码字符串契约）。
pub use registry::ERR_SOCIAL_PROVIDER_NOT_REGISTERED;

/// 社交登录 provider 名称格式非法错误码。
pub use registry::ERR_SOCIAL_PROVIDER_NAME_INVALID;

// SocialLoginProvider trait：社交登录抽象

/// 社交登录服务提供方 trait，三个异步方法覆盖 OAuth2 授权码流程；实现见 `WechatProvider`（`social-wechat`）与 `AlipayProvider`（`social-alipay`）。
#[async_trait]
pub trait SocialLoginProvider: Send + Sync {
    /// 拼接第三方平台授权页 URL；`state` 为 CSRF 防护（调用方生成随机串并缓存校验），`redirect_uri` 需在第三方平台配置白名单。
    async fn get_authorization_url(
        &self,
        state: &str,
        redirect_uri: &str,
    ) -> GarrisonResult<String>;

    /// 用授权码换取用户信息（含 `provider_user_id` + nickname + avatar，必要时内部调用 `get_user_info`）。
    ///
    /// 授权码 `code` 为第三方平台回调 query 参数、一次性消费（`state` 校验一致性，防 CSRF）。
    ///
    /// # 实现者契约（必须遵守）
    ///
    /// - **`provider_user_id` 非空**：为空串（字段缺失或为空）时必须返回 `Err`（如 `GarrisonError::Network`），
    ///   不得返回空串 `Ok`——`social_callback` handler 直接用该值创建绑定，空串会绕过绑定幂等约束并引发 500。
    ///   推荐 `.filter(|s| !s.is_empty())` 后 `ok_or_else`（参考 `wechat::WechatProvider::exchange_token`）。
    /// - **`raw` 不得含敏感凭据**：返回前剥离 `access_token` / `session_key`（参考 `wechat::strip_sensitive_fields`）。
    async fn exchange_token(&self, code: &str, state: &str) -> GarrisonResult<SocialUserInfo>;

    /// 用 access_token 获取用户信息（用于已缓存 token、避免重复授权的场景）。
    async fn get_user_info(&self, access_token: &str) -> GarrisonResult<SocialUserInfo>;
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
