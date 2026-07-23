//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! AuthBackend — 认证后端统一抽象。
//!
//! 提供 13 个 async 方法的 trait 接口，支持两种部署模式：
//! - **BackendEmbedded**（`backend-embedded` feature）：进程内认证，委托 GarrisonManager
//! - **BackendRemote**（`backend-remote` feature）：HTTP 客户端，连接远程 Auth Server
//!
//! # 设计原则
//!
//! - **trait + dyn object 切换**（Rule 2 简洁优先）：不使用 typestate 模式，
//!   AuthBackend 只是一个 trait，通过 `Arc<dyn AuthBackend>` 在 Embedded/Remote 间切换
//! - **方法签名接受 token 参数**：与 GarrisonUtil 静态方法（从 task_local 获取 token）不同，
//!   AuthBackend 方法显式接受 token/login_id 参数，适用于远程调用场景
//! - **复用现有类型**（Rule 8）：LoginParams / TokenInfo / SessionData 复用 garrison 现有类型

use crate::error::GarrisonResult;
use async_trait::async_trait;

pub mod types;

#[cfg(feature = "backend-embedded")]
pub mod embedded;

#[cfg(feature = "backend-remote")]
pub mod remote;

#[cfg(feature = "backend-kit")]
pub mod kit_builder;

#[cfg(test)]
mod tests;

pub use types::*;

#[cfg(feature = "backend-embedded")]
pub use embedded::BackendEmbedded;

#[cfg(feature = "backend-remote")]
pub use remote::BackendRemote;

#[cfg(feature = "backend-kit")]
pub use kit_builder::{BackendKitError, BackendModule};

/// 认证后端统一抽象。
///
/// 13 个 async 方法覆盖登录/登出/校验/查询/管理全生命周期。
/// 通过 `Arc<dyn AuthBackend>` 实现 Embedded/Remote 模式切换。
///
/// # 方法分类
///
/// | 分类 | 方法 |
/// |------|------|
/// | 登录/登出 | `login` / `logout` |
/// | 状态校验 | `check_login` / `check_safe` / `check_disable` |
/// | 权限校验 | `check_permission` / `check_role` / `check_api_key` |
/// | 信息查询 | `get_token_info` / `get_session` |
/// | 会话管理 | `kickout` / `switch_to` / `renew_to_equivalent` |
#[async_trait]
pub trait AuthBackend: Send + Sync {
    /// 执行登录，返回生成的 token。
    ///
    /// # 参数
    /// - `login_id`：登录主体标识
    /// - `params`：登录参数（设备/IP/UA/remember_me/require_mfa）
    async fn login(&self, login_id: &str, params: &LoginParams) -> GarrisonResult<String>;

    /// 执行登出，销毁指定 token 的会话。
    async fn logout(&self, token: &str) -> GarrisonResult<()>;

    /// 校验 token 是否处于登录状态。
    ///
    /// 返回 `true` 表示已登录且未过期，`false` 表示未登录或已过期。
    async fn check_login(&self, token: &str) -> GarrisonResult<bool>;

    /// 校验 token 是否拥有指定权限。
    ///
    /// 返回 `Ok(())` 表示有权限，返回 `Err` 表示无权限或 token 无效。
    async fn check_permission(&self, token: &str, permission: &str) -> GarrisonResult<()>;

    /// 校验 token 是否拥有指定角色。
    ///
    /// 返回 `Ok(())` 表示有角色，返回 `Err` 表示无角色或 token 无效。
    async fn check_role(&self, token: &str, role: &str) -> GarrisonResult<()>;

    /// 校验 token 是否处于二级认证（Safe Auth）状态。
    ///
    /// 返回 `true` 表示已开启二级认证，`false` 表示未开启。
    async fn check_safe(&self, token: &str) -> GarrisonResult<bool>;

    /// 校验 token 是否被禁用。
    ///
    /// 返回 `true` 表示已禁用，`false` 表示未禁用。
    async fn check_disable(&self, token: &str) -> GarrisonResult<bool>;

    /// 校验 API Key 是否有效。
    ///
    /// # 参数
    /// - `api_key`：API Key 字符串
    /// - `namespace`：命名空间（租户隔离标识）
    async fn check_api_key(&self, api_key: &str, namespace: &str) -> GarrisonResult<()>;

    /// 获取 token 的基本信息。
    ///
    /// 返回 `TokenInfo`（token 字符串 / 创建时间 / 最后活跃时间）。
    async fn get_token_info(&self, token: &str) -> GarrisonResult<TokenInfo>;

    /// 获取 token 的 session 数据。
    ///
    /// 返回 `SessionData`（login_id / 创建时间 / 活跃时间 / 自定义属性 / 设备信息）。
    async fn get_session(&self, token: &str) -> GarrisonResult<SessionData>;

    /// 踢出指定登录主体的所有会话。
    async fn kickout(&self, login_id: &str) -> GarrisonResult<()>;

    /// 切换登录主体（保持当前 token，切换 login_id）。
    ///
    /// 将当前 token 关联的会话切换到 `target_login_id`，
    /// 保留原 token 字符串与 session attrs（device/ip/ua 等），
    /// 在 attrs["switched_from"] 记录原始 login_id。
    async fn switch_to(&self, token: &str, target_login_id: &str) -> GarrisonResult<()>;

    /// 续期 token 到等价的新 token。
    ///
    /// 返回续期后的新 token 字符串。
    async fn renew_to_equivalent(&self, token: &str) -> GarrisonResult<String>;
}
