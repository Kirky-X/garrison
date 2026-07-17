//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! plugin 模块测试（从 mod.rs 迁移，Rule 25 合规）。

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
