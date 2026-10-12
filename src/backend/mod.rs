// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! AuthBackend — 认证后端统一抽象。
//!
//! 13 个 async 方法的 trait 接口，支持两种部署模式：BackendEmbedded
//! （`backend-embedded` feature，进程内认证、委托 GarrisonManager）与 BackendRemote
//! （`backend-remote` feature，HTTP 客户端连接远程 Auth Server）。
//!
//! 设计取舍：经 `Arc<dyn AuthBackend>` 切换两种模式（简洁优先，不用 typestate）；
//! 方法签名显式接受 token/login_id 参数，区别于 GarrisonUtil 静态方法从
//! task_local 隐式获取，适配远程调用场景；LoginParams / TokenInfo / SessionData
//! 复用现有类型。

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

/// 认证后端统一抽象：13 个 async 方法覆盖登录 / 登出 / 校验 / 查询 / 管理
/// 全生命周期，经 `Arc<dyn AuthBackend>` 实现 Embedded/Remote 模式切换。
#[async_trait]
pub trait AuthBackend: Send + Sync {
    /// 执行登录，返回生成的 token（params 含设备/IP/UA/remember_me/require_mfa）。
    async fn login(&self, login_id: &str, params: &LoginParams) -> GarrisonResult<String>;

    /// 执行登出，销毁指定 token 的会话。
    async fn logout(&self, token: &str) -> GarrisonResult<()>;

    /// 校验 token 是否处于登录状态（已登录且未过期）。
    async fn check_login(&self, token: &str) -> GarrisonResult<bool>;

    /// 校验 token 是否拥有指定权限（无权限或 token 无效返回 `Err`）。
    async fn check_permission(&self, token: &str, permission: &str) -> GarrisonResult<()>;

    /// 校验 token 是否拥有指定角色（无角色或 token 无效返回 `Err`）。
    async fn check_role(&self, token: &str, role: &str) -> GarrisonResult<()>;

    /// 校验 token 是否处于二级认证（Safe Auth）状态。
    async fn check_safe(&self, token: &str) -> GarrisonResult<bool>;

    /// 校验 token 是否被禁用。
    async fn check_disable(&self, token: &str) -> GarrisonResult<bool>;

    /// 校验 API Key 是否有效（namespace 为租户隔离标识）。
    async fn check_api_key(&self, api_key: &str, namespace: &str) -> GarrisonResult<()>;

    /// 获取 token 的基本信息（TokenInfo）。
    async fn get_token_info(&self, token: &str) -> GarrisonResult<TokenInfo>;

    /// 获取 token 的 session 数据（SessionData）。
    async fn get_session(&self, token: &str) -> GarrisonResult<SessionData>;

    /// 踢出指定登录主体的所有会话。
    ///
    /// 并发安全：对同一 `login_id` 的并发 `kickout` 必须幂等；与 `switch_to` /
    /// `renew_to_equivalent` 并发时调用方应自行序列化，否则最终状态不确定。
    async fn kickout(&self, login_id: &str) -> GarrisonResult<()>;

    /// 切换登录主体（保持当前 token，切换 login_id）。
    ///
    /// 保留原 token 与 session attrs（device/ip/ua 等），在 `attrs["switched_from"]`
    /// 记录原始 login_id。并发安全：对同一 token 的并发 `switch_to` 最终 `login_id`
    /// 不确定，调用方应确保会话管理操作串行化。
    async fn switch_to(&self, token: &str, target_login_id: &str) -> GarrisonResult<()>;

    /// 续期 token 到等价的新 token。
    ///
    /// 安全契约：实现**必须**在返回新 token 后原子吊销原 token；调用方收到新 token
    /// 后应立即停用原 token。无法保证原子吊销（如分布式场景）时，实现须在文档中明示。
    async fn renew_to_equivalent(&self, token: &str) -> GarrisonResult<String>;
}
