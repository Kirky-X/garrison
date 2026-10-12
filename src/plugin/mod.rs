// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 插件模块，定义插件 trait 与编译期注册（`inventory` 实现：`submit!` 注册、`iter!` 收集，替代 Java SPI）。
//! 生命周期钩子 on_login/on_logout/on_permission_check；插件失败仅记录 `tracing::warn!`，不中断主流程。

use crate::error::GarrisonResult;
use std::sync::Arc;

/// Garrison 插件 trait：钩子方法 MUST 提供默认空实现（返回 `Ok(())`）供选择性覆盖，trait 绑定 `Send + Sync` 可多线程共享。
pub trait GarrisonPlugin: Send + Sync {
    /// 插件名称，用于唯一标识。
    fn name(&self) -> &str;

    /// 登录成功后被调用（默认空实现返回 `Ok(())`）。
    ///
    /// `token` 为登录凭据：实现方不得记录其任何片段（含前缀）到日志或审计输出；如需关联请记录 `login_id` 或 token 哈希摘要。
    fn on_login(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> {
        Ok(())
    }

    /// 登出操作完成后被调用（默认空实现）；`token` 为凭据不得记录任何片段（见 `on_login` 凭据警示）。
    fn on_logout(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> {
        Ok(())
    }

    /// 权限校验发生时被调用，用于"观测不干预"场景（如审计日志），不修改校验结果；默认空实现返回 `Ok(())`。
    fn on_permission_check(&self, _login_id: &str, _permission: &str) -> GarrisonResult<()> {
        Ok(())
    }
}

/// 插件工厂函数指针，返回 `Arc<dyn GarrisonPlugin>`。
pub type GarrisonPluginFactoryFn = fn() -> Arc<dyn GarrisonPlugin>;

/// 插件注册条目：`inventory::submit! { GarrisonPluginEntry { factory } }` 注册，`inventory::iter::<GarrisonPluginEntry>()` 运行期遍历。
pub struct GarrisonPluginEntry {
    /// 插件工厂函数。
    pub factory: GarrisonPluginFactoryFn,
}

inventory::collect!(GarrisonPluginEntry);

/// 插件管理器：`GarrisonManager::builder()` 时经 `inventory::iter` 收集全部已注册插件；钩子返回 `Err` 或工厂 panic 均仅记录 `tracing::warn!` 并跳过，不中断主流程（隔离细节见 `new()`）。
///
/// # ⚠️ 凭据警示
///
/// 钩子 `token` 参数是凭据：插件实现不得将其（含前缀）写入日志、审计或任何输出——8 字符前缀也足以帮助攻击者验证猜测/重放；关联日志请记录 `login_id` 或 token 哈希（如 SHA-256 前 8 字节 hex）。
pub struct GarrisonPluginManager {
    /// 已注册的插件列表。
    plugins: Vec<Arc<dyn GarrisonPlugin>>,
}

mod manager_impl;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
