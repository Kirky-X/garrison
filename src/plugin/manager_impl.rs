//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! GarrisonPluginManager 实现块（从 mod.rs 迁移）。

use super::*;

impl GarrisonPluginManager {
    /// 创建插件管理器并收集所有已注册插件。
    ///
    /// # panic 隔离（ocr #2594）
    ///
    /// 单个插件工厂 panic 被 `catch_unwind` 捕获并降级为 `tracing::warn!`，
    /// 该插件被跳过，其余插件照常加载，应用启动不中断。与
    /// `listener::manager_impl` 的监听器隔离语义一致。注意 release profile
    /// 配置 `panic = "abort"` 时此隔离退化为进程终止（见 Cargo.toml 说明）。
    pub fn new() -> Self {
        use std::iter::Iterator;
        use std::panic::{catch_unwind, AssertUnwindSafe};
        let plugins: Vec<Arc<dyn GarrisonPlugin>> = inventory::iter::<GarrisonPluginEntry>()
            .filter_map(|entry| {
                // AssertUnwindSafe：工厂函数不承诺 UnwindSafe，
                // 此处仅隔离 panic 不重入工厂，跨 catch_unwind 使用安全
                match catch_unwind(AssertUnwindSafe(|| (entry.factory)())) {
                    Ok(plugin) => Some(plugin),
                    Err(panic_payload) => {
                        let msg = panic_payload
                            .downcast_ref::<&str>()
                            .map(|s| (*s).to_string())
                            .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                            .unwrap_or_else(|| "unknown panic".to_string());
                        tracing::warn!("plugin factory panicked, plugin skipped: {}", msg);
                        None
                    },
                }
            })
            .collect();
        for p in &plugins {
            tracing::info!("plugin loaded: {}", p.name());
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
                tracing::warn!("plugin {} on_login failed: {}", plugin.name(), e);
            }
        }
    }

    /// 调用所有插件的 `on_logout` 钩子。
    ///
    /// 单个插件失败仅记录 `tracing::warn!`，不中断后续插件调用。
    pub fn on_logout(&self, login_id: &str, token: &str) {
        for plugin in &self.plugins {
            if let Err(e) = plugin.on_logout(login_id, token) {
                tracing::warn!("plugin {} on_logout failed: {}", plugin.name(), e);
            }
        }
    }

    /// 调用所有插件的 `on_permission_check` 钩子。
    ///
    /// 单个插件失败仅记录 `tracing::warn!`，不中断后续插件调用。
    pub fn on_permission_check(&self, login_id: &str, permission: &str) {
        for plugin in &self.plugins {
            if let Err(e) = plugin.on_permission_check(login_id, permission) {
                tracing::warn!("plugin {} on_permission_check failed: {}", plugin.name(), e);
            }
        }
    }
}

impl Default for GarrisonPluginManager {
    fn default() -> Self {
        Self::new()
    }
}
