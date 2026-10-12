// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 设备绑定策略模块,定义新设备检测与二级认证要求的可插拔契约。
//!
//! 内置 `StrictBinding`(新设备强制二级认证)、`LooseBinding`(仅告警不阻断)、`Disabled`(完全禁用),仅在启用 `device-binding` 特性(依赖 `security-alert`)时编译。

/// 宽松绑定策略实现模块。
pub mod loose;
/// 策略实现模块:Disabled 策略与共用工具函数。
pub mod policies;
/// 严格绑定策略实现模块。
pub mod strict;

#[cfg(test)]
mod tests;

pub use loose::LooseBinding;
pub use policies::Disabled;
pub use strict::StrictBinding;

use crate::error::GarrisonResult;
use async_trait::async_trait;

/// 设备绑定策略 trait:方法参数均为 `&str`、无泛型,故对象安全,可作 `dyn DeviceBindingPolicy` 使用。
#[async_trait]
pub trait DeviceBindingPolicy: Send + Sync {
    /// 检测 `device_id` 是否为 `login_id` 的新设备;查询历史设备列表失败时透传 `GarrisonError`。
    async fn is_new_device(&self, login_id: &str, device_id: &str) -> GarrisonResult<bool>;

    /// 判断新设备是否需要二级认证;已知设备通常返回 `Ok(false)`,查询失败透传 `GarrisonError`。
    async fn require_secondary_auth(&self, login_id: &str, device_id: &str)
        -> GarrisonResult<bool>;
}
