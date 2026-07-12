//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! BulwarkPluginManager 实现块（从 mod.rs 迁移）。

use super::*;

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
