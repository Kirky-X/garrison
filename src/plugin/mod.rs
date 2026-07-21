//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 插件模块，定义插件 trait 与编译期注册。
//!
//! 通过 `inventory` crate 实现编译期插件注册（替代 Java SPI），
//! 插件在编译期通过 `inventory::submit!` 注册，运行期通过 `inventory::iter!` 收集。
//!
//! 0.2.0 提供完整的生命周期钩子（on_login/on_logout/on_permission_check），
//! 插件失败仅记录 `tracing::warn!`，不中断主流程。

use crate::error::GarrisonResult;
use std::sync::Arc;

/// Garrison 插件 trait，提供生命周期钩子抽象。
///
/// 所有钩子方法 MUST 提供默认空实现（返回 `Ok(())`），使插件方可选择性覆盖。
/// trait 绑定 `Send + Sync`，插件可在多线程环境共享。
///
/// `login_id` 为 `&str`（v0.5.2 迁移：原 i64 → String，与全局 login_id 迁移一致）。
pub trait GarrisonPlugin: Send + Sync {
    /// 插件名称，用于唯一标识。
    fn name(&self) -> &str;

    /// 登录成功后被调用。
    ///
    /// 默认空实现返回 `Ok(())`。
    fn on_login(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> {
        Ok(())
    }

    /// 登出操作完成后被调用。
    ///
    /// 默认空实现返回 `Ok(())`。
    fn on_logout(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> {
        Ok(())
    }

    /// 权限校验发生时被调用。
    ///
    /// 用于"观测不干预"场景（如审计日志），不修改校验结果。
    /// 默认空实现返回 `Ok(())`。
    fn on_permission_check(&self, _login_id: &str, _permission: &str) -> GarrisonResult<()> {
        Ok(())
    }
}

/// 插件工厂函数指针，返回 `Arc<dyn GarrisonPlugin>`。
pub type GarrisonPluginFactoryFn = fn() -> Arc<dyn GarrisonPlugin>;

/// 插件注册条目，用于 `inventory` 收集。
///
/// 通过 `inventory::submit! { GarrisonPluginEntry { factory: my_plugin_factory } }` 注册插件，
/// 运行期通过 `inventory::iter::<GarrisonPluginEntry>()` 遍历。
pub struct GarrisonPluginEntry {
    /// 插件工厂函数。
    pub factory: GarrisonPluginFactoryFn,
}

// 编译期插件注册收集点
inventory::collect!(GarrisonPluginEntry);

/// 插件管理器，收集并管理所有已注册插件。
///
/// 在 `GarrisonManager::init` 时通过 `inventory::iter` 收集所有已注册插件。
/// 插件方法返回 `Err` 时仅记录 `tracing::warn!` 日志，不中断主流程。
pub struct GarrisonPluginManager {
    /// 已注册的插件列表。
    plugins: Vec<Arc<dyn GarrisonPlugin>>,
}

mod manager_impl;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
