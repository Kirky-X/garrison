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
// SocialProvider enum：社交平台标识
// ============================================================================

/// 社交登录平台标识。
///
/// 用于 `SocialUserInfo.provider` 字段标识用户来源平台。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SocialProvider {
    /// 微信开放平台扫码登录。
    Wechat,
    /// 支付宝开放平台授权登录。
    Alipay,
    /// 微信小程序登录（v0.5.0+ 预留，实现推迟到 v0.5.1+）。
    WechatMiniApp,
}

// ============================================================================
// SocialUserInfo：社交用户信息
// ============================================================================

/// 社交用户信息。
///
/// `exchange_token` / `get_user_info` 方法的返回类型，承载第三方平台返回的用户字段。
#[derive(Debug, Clone)]
pub struct SocialUserInfo {
    /// 用户来源平台标识。
    pub provider: SocialProvider,
    /// 第三方平台用户唯一 ID（微信 openid / 支付宝 user_id）。
    pub provider_user_id: String,
    /// 用户昵称（可能为空）。
    pub nickname: Option<String>,
    /// 用户头像 URL（可能为空）。
    pub avatar: Option<String>,
    /// 跨应用统一 ID（微信 unionid，用于同一开发者主体下多应用账号打通）。
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
// SocialBindingService（feature = "db-sqlite"）
// ============================================================================

/// 社交账号绑定服务。
///
/// 提供 `find_or_create` 语义：首次社交登录时自动创建绑定关系并生成新 `login_id`，
/// 后续登录返回已有 `login_id`（幂等）。
///
/// # 设计决策（Decision Matrix 方案 A）
///
/// struct 同时持有：
/// - `pool: DbPool`：执行 SQL 查询/插入（`social_bindings` 表）
/// - `dao: Arc<dyn GarrisonDao>`：缓存层抽象（保留扩展点，当前未使用）
///
/// 与 `RoleHierarchyService` 模式一致：GarrisonDao 是 KV 缓存抽象，
/// 不支持 SQL SELECT/INSERT，故 `find_or_create` 实际用 `pool` 查 SQL。
/// `GarrisonDao` trait 的 `find_social_binding` / `insert_social_binding`
/// 默认方法返回 `NotImplemented`，仅为满足 spec trait 契约。
///
/// # 表结构
///
/// ```sql
/// CREATE TABLE social_bindings (
///     id               INTEGER PRIMARY KEY AUTOINCREMENT,
///     tenant_id        INTEGER NOT NULL DEFAULT 0,
///     login_id         INTEGER NOT NULL,
///     provider         TEXT    NOT NULL,
///     provider_user_id TEXT    NOT NULL,
///     union_id         TEXT,
///     created_at       INTEGER NOT NULL,
///     UNIQUE(tenant_id, provider, provider_user_id)
/// );
/// ```
///
/// `UNIQUE(tenant_id, provider, provider_user_id)` 保证同一租户下同一社交账号仅绑定一个 login_id。
#[cfg(feature = "db-sqlite")]
pub struct SocialBindingService {
    /// SQLite 连接池（查 `social_bindings` 表）。
    pub pool: dbnexus::DbPool,
    /// 缓存层抽象（保留扩展点，当前未使用）。
    pub dao: std::sync::Arc<dyn crate::dao::GarrisonDao>,
}

/// `SocialBindingService` 实现模块（feature = "db-sqlite"）。
///
/// 从 `mod.rs` 迁移以符合规则 25（mod.rs 接口隔离）：
/// impl 块与顶层 `fn provider_to_str` 不允许留在 `mod.rs`。
#[cfg(feature = "db-sqlite")]
pub(crate) mod service;

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
    /// 仅完成 code → access_token 步骤；返回的 SocialUserInfo 中 nickname/avatar 为 None，调用方需再调 `get_user_info` 获取用户资料。
    ///
    /// # 参数
    /// - `code`: 授权码（第三方平台回调时附在 query 参数）
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
