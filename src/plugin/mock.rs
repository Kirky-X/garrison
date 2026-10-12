// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 插件层测试 mock（仅 `#[cfg(test)]` 编译）：`OkPlugin` / `ErrPlugin` 经 `inventory` 注册，供 `plugin::tests` 复用。

use super::{GarrisonPlugin, GarrisonPluginEntry};
use crate::error::{GarrisonError, GarrisonResult};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

/// 计数器，记录钩子被调用次数。
pub static LOGIN_CALLS: AtomicUsize = AtomicUsize::new(0);
pub static LOGOUT_CALLS: AtomicUsize = AtomicUsize::new(0);
pub static PERM_CHECK_CALLS: AtomicUsize = AtomicUsize::new(0);

/// 成功插件，所有钩子返回 Ok(())。
pub struct OkPlugin;

impl GarrisonPlugin for OkPlugin {
    fn name(&self) -> &str {
        "ok-plugin"
    }
    fn on_login(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> {
        LOGIN_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn on_logout(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> {
        LOGOUT_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn on_permission_check(&self, _login_id: &str, _permission: &str) -> GarrisonResult<()> {
        PERM_CHECK_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// 失败插件，所有钩子返回 Err。
pub struct ErrPlugin;

impl GarrisonPlugin for ErrPlugin {
    fn name(&self) -> &str {
        "err-plugin"
    }
    fn on_login(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> {
        Err(GarrisonError::Internal(
            "plugin-on-login-failed".to_string(),
        ))
    }
    fn on_logout(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> {
        Err(GarrisonError::Internal(
            "plugin-on-logout-failed".to_string(),
        ))
    }
    fn on_permission_check(&self, _login_id: &str, _permission: &str) -> GarrisonResult<()> {
        Err(GarrisonError::Internal(
            "plugin-on-permission-check-failed::".to_string(),
        ))
    }
}

pub fn ok_plugin_factory() -> Arc<dyn GarrisonPlugin> {
    Arc::new(OkPlugin)
}

pub fn err_plugin_factory() -> Arc<dyn GarrisonPlugin> {
    Arc::new(ErrPlugin)
}

inventory::submit! {
    GarrisonPluginEntry { factory: ok_plugin_factory }
}
inventory::submit! {
    GarrisonPluginEntry { factory: err_plugin_factory }
}

/// 重置所有计数器。
pub fn reset_counters() {
    LOGIN_CALLS.store(0, Ordering::SeqCst);
    LOGOUT_CALLS.store(0, Ordering::SeqCst);
    PERM_CHECK_CALLS.store(0, Ordering::SeqCst);
}
