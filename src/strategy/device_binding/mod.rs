//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 设备绑定策略模块，定义新设备检测与二级认证要求的可插拔契约。
//!
//! [`DeviceBindingPolicy`] trait 抽象了登录场景下的设备绑定决策：
//! - [`is_new_device`](DeviceBindingPolicy::is_new_device)：检测设备是否为该登录主体的新设备
//! - [`require_secondary_auth`](DeviceBindingPolicy::require_secondary_auth)：判断新设备是否需要二级认证
//!
//! 三种内置实现（由后续任务提供）：
//! - `StrictBinding`：新设备强制二级认证（T010）
//! - `LooseBinding`：新设备仅告警不阻断（T011）
//! - `Disabled`：完全禁用设备绑定（T012）
//!
//! 此模块仅在启用 `device-binding` 特性时编译（依赖 `security-alert`）。

use crate::error::BulwarkResult;
use async_trait::async_trait;

/// 设备绑定策略 trait，定义新设备检测与二级认证要求契约。
///
/// 实现方在登录流程中调用，依据历史设备列表判断当前设备是否为新设备，
/// 并决定是否需要触发二级认证。trait 绑定 `Send + Sync`，可作为
/// `dyn DeviceBindingPolicy` 使用（对象安全：所有方法参数为 `&str`，无泛型）。
///
/// # 内置实现
///
/// - `StrictBinding`：新设备强制二级认证（T010）
/// - `LooseBinding`：新设备仅告警不阻断（T011）
/// - `Disabled`：完全禁用设备绑定（T012）
#[async_trait]
pub trait DeviceBindingPolicy: Send + Sync {
    /// 检测指定 `device_id` 是否为 `login_id` 的新设备。
    ///
    /// 实现方通常查询该登录主体的历史设备列表，判断当前设备是否首次出现。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `device_id`: 待检测的设备标识。
    ///
    /// # 返回
    /// - `Ok(true)`: 新设备（历史设备列表中不存在）。
    /// - `Ok(false)`: 已知设备。
    /// - `Err`: 查询历史设备列表失败（如 DAO 异常），透传 `BulwarkError`。
    async fn is_new_device(&self, login_id: &str, device_id: &str) -> BulwarkResult<bool>;

    /// 判断新设备是否需要触发二级认证。
    ///
    /// 实现方依据绑定策略（strict / loose / disabled）决定是否要求二级认证。
    /// 对已知设备通常返回 `Ok(false)`。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `device_id`: 待检测的设备标识。
    ///
    /// # 返回
    /// - `Ok(true)`: 需要二级认证（如 strict 模式下新设备）。
    /// - `Ok(false)`: 不需要二级认证（loose 模式或已知设备）。
    /// - `Err`: 查询失败，透传 `BulwarkError`。
    async fn require_secondary_auth(&self, login_id: &str, device_id: &str) -> BulwarkResult<bool>;
}
