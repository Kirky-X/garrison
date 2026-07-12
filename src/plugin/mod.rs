//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 插件模块，定义插件 trait 与编译期注册。
//!
//! [借鉴 Sa-Token] 通过 `inventory` crate 实现编译期插件注册（替代 Java SPI），
//! 插件在编译期通过 `inventory::submit!` 注册，运行期通过 `inventory::iter!` 收集。
//!
//! 0.2.0 提供完整的生命周期钩子（on_login/on_logout/on_permission_check），
//! 插件失败仅记录 `tracing::warn!`，不中断主流程。

use crate::error::BulwarkResult;
use std::sync::Arc;

/// Bulwark 插件 trait，提供生命周期钩子抽象。
///
/// 所有钩子方法 MUST 提供默认空实现（返回 `Ok(())`），使插件方可选择性覆盖。
/// trait 绑定 `Send + Sync`，插件可在多线程环境共享。
///
/// `login_id` 为 `&str`（v0.5.2 迁移：原 i64 → String，与全局 login_id 迁移一致）。
pub trait BulwarkPlugin: Send + Sync {
    /// 插件名称，用于唯一标识。
    fn name(&self) -> &str;

    /// 登录成功后被调用。
    ///
    /// 默认空实现返回 `Ok(())`。
    fn on_login(&self, _login_id: &str, _token: &str) -> BulwarkResult<()> {
        Ok(())
    }

    /// 登出操作完成后被调用。
    ///
    /// 默认空实现返回 `Ok(())`。
    fn on_logout(&self, _login_id: &str, _token: &str) -> BulwarkResult<()> {
        Ok(())
    }

    /// 权限校验发生时被调用。
    ///
    /// 用于"观测不干预"场景（如审计日志），不修改校验结果。
    /// 默认空实现返回 `Ok(())`。
    fn on_permission_check(&self, _login_id: &str, _permission: &str) -> BulwarkResult<()> {
        Ok(())
    }
}

/// 插件工厂函数指针，返回 `Arc<dyn BulwarkPlugin>`。
pub type BulwarkPluginFactoryFn = fn() -> Arc<dyn BulwarkPlugin>;

/// 插件注册条目，用于 `inventory` 收集。
///
/// 通过 `inventory::submit! { BulwarkPluginEntry { factory: my_plugin_factory } }` 注册插件，
/// 运行期通过 `inventory::iter::<BulwarkPluginEntry>()` 遍历。
pub struct BulwarkPluginEntry {
    /// 插件工厂函数。
    pub factory: BulwarkPluginFactoryFn,
}

// 编译期插件注册收集点
inventory::collect!(BulwarkPluginEntry);

/// 插件管理器，收集并管理所有已注册插件。
///
/// 在 `BulwarkManager::init` 时通过 `inventory::iter` 收集所有已注册插件。
/// 插件方法返回 `Err` 时仅记录 `tracing::warn!` 日志，不中断主流程。
pub struct BulwarkPluginManager {
    /// 已注册的插件列表。
    plugins: Vec<Arc<dyn BulwarkPlugin>>,
}

impl BulwarkPluginManager {
    /// 创建插件管理器并收集所有已注册插件。
    pub fn new() -> Self {
        use std::iter::Iterator;
        let plugins: Vec<Arc<dyn BulwarkPlugin>> = inventory::iter::<BulwarkPluginEntry>()
            .map(|entry| (entry.factory)())
            .collect();
        for p in &plugins {
            tracing::info!("已加载插件: {}", p.name());
        }
        Self { plugins }
    }

    /// 返回已注册插件数量。
    pub fn count(&self) -> usize {
        self.plugins.len()
    }

    /// 调用所有插件的 `on_login` 钩子。
    ///
    /// 单个插件失败仅记录 `tracing::warn!`，不中断后续插件调用。
    pub fn on_login(&self, login_id: &str, token: &str) {
        for plugin in &self.plugins {
            if let Err(e) = plugin.on_login(login_id, token) {
                tracing::warn!("插件 {} on_login 失败: {}", plugin.name(), e);
            }
        }
    }

    /// 调用所有插件的 `on_logout` 钩子。
    ///
    /// 单个插件失败仅记录 `tracing::warn!`，不中断后续插件调用。
    pub fn on_logout(&self, login_id: &str, token: &str) {
        for plugin in &self.plugins {
            if let Err(e) = plugin.on_logout(login_id, token) {
                tracing::warn!("插件 {} on_logout 失败: {}", plugin.name(), e);
            }
        }
    }

    /// 调用所有插件的 `on_permission_check` 钩子。
    ///
    /// 单个插件失败仅记录 `tracing::warn!`，不中断后续插件调用。
    pub fn on_permission_check(&self, login_id: &str, permission: &str) {
        for plugin in &self.plugins {
            if let Err(e) = plugin.on_permission_check(login_id, permission) {
                tracing::warn!("插件 {} on_permission_check 失败: {}", plugin.name(), e);
            }
        }
    }
}

impl Default for BulwarkPluginManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests {
    use super::mock::{reset_counters, OkPlugin, LOGIN_CALLS, LOGOUT_CALLS, PERM_CHECK_CALLS};
    use super::*;
    use serial_test::serial;
    use std::sync::atomic::Ordering;

    // ========================================================================
    // BulwarkPlugin trait 测试
    // ========================================================================

    /// 默认实现返回 Ok(())（spec Scenario：生命周期钩子有默认空实现）。
    #[test]
    #[serial]
    fn default_hooks_return_ok() {
        struct EmptyPlugin;
        impl BulwarkPlugin for EmptyPlugin {
            fn name(&self) -> &str {
                "empty"
            }
        }
        let plugin = EmptyPlugin;
        assert!(plugin.on_login("1", "t").is_ok());
        assert!(plugin.on_logout("1", "t").is_ok());
        assert!(plugin.on_permission_check("1", "p").is_ok());
    }

    /// name 方法必须由实现方提供（spec Scenario）。
    #[test]
    #[serial]
    fn name_must_be_provided() {
        let plugin = OkPlugin;
        assert_eq!(plugin.name(), "ok-plugin");
    }

    // ========================================================================
    // BulwarkPluginManager 测试
    // ========================================================================

    /// manager 收集所有已注册插件（spec Scenario）。
    #[test]
    #[serial]
    fn manager_collects_registered_plugins() {
        let manager = BulwarkPluginManager::new();
        // 至少 2 个插件（OkPlugin + ErrPlugin）
        assert!(manager.count() >= 2);
    }

    /// on_login 调用所有插件钩子（spec Scenario）。
    #[test]
    #[serial]
    fn on_login_invokes_all_plugins() {
        reset_counters();
        let manager = BulwarkPluginManager::new();
        manager.on_login("1001", "T1");
        // OkPlugin 的 on_login 应被调用至少 1 次
        assert!(LOGIN_CALLS.load(Ordering::SeqCst) >= 1);
    }

    /// on_logout 调用所有插件钩子（spec Scenario）。
    #[test]
    #[serial]
    fn on_logout_invokes_all_plugins() {
        reset_counters();
        let manager = BulwarkPluginManager::new();
        manager.on_logout("1001", "T1");
        assert!(LOGOUT_CALLS.load(Ordering::SeqCst) >= 1);
    }

    /// on_permission_check 调用所有插件钩子（spec Scenario）。
    #[test]
    #[serial]
    fn on_permission_check_invokes_all_plugins() {
        reset_counters();
        let manager = BulwarkPluginManager::new();
        manager.on_permission_check("1001", "user:read");
        assert!(PERM_CHECK_CALLS.load(Ordering::SeqCst) >= 1);
    }

    /// 插件失败不中断主流程（spec Scenario）。
    #[test]
    #[serial]
    fn plugin_failure_does_not_interrupt() {
        reset_counters();
        let manager = BulwarkPluginManager::new();
        // ErrPlugin 的 on_login 返回 Err，但 OkPlugin 的 on_login 仍应被调用
        manager.on_login("1001", "T1");
        // OkPlugin 的计数器应 >= 1（证明 ErrPlugin 的失败没有中断）
        assert!(LOGIN_CALLS.load(Ordering::SeqCst) >= 1);
    }

    /// Default trait 实现等价于 new()。
    #[test]
    #[serial]
    fn default_equals_new() {
        let m1 = BulwarkPluginManager::new();
        let m2 = BulwarkPluginManager::default();
        assert_eq!(m1.count(), m2.count());
    }
}
