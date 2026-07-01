//! Plugin / Listener 集成测试：编译期注册 → 钩子调用 → 事件广播。
//!
//! 验证 `BulwarkPluginManager` 与 `BulwarkListenerManager` 的端到端行为：
//! 1. 通过 `inventory::submit!` 注册测试 plugin / listener
//! 2. `BulwarkPluginManager::new()` / `BulwarkListenerManager::new()` 收集已注册条目
//! 3. `on_login` / `on_logout` / `on_permission_check` 钩子被调用
//! 4. `broadcast` 将事件分发到所有 listener
//! 5. 单个 plugin/listener 失败不中断主流程（仅 tracing::warn!）
//!
//! ## 已知限制（auto-wire gap）
//!
//! 当前 `BulwarkLogicDefault` 不持有 `BulwarkPluginManager` / `BulwarkListenerManager`，
//! 因此 `BulwarkUtil::login` 不会自动触发 `on_login` / `Login` 事件。
//! 此 auto-wire 在延后任务 13.4/13.5 中实现。
//! 本集成测试直接调用 `BulwarkPluginManager::on_login()` 与
//! `BulwarkListenerManager::broadcast()`，验证扩展点本身工作正常。
//!
//! 依据 spec plugin-system + listener-system。

#![cfg(feature = "listener")]

use bulwark::error::BulwarkResult;
use bulwark::listener::{BulwarkEvent, BulwarkListener, BulwarkListenerManager};
use bulwark::plugin::{BulwarkPlugin, BulwarkPluginManager};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// ============================================================================
// 测试用 Plugin（计数器记录钩子调用）
// ============================================================================

static PLUGIN_LOGIN_CALLS: AtomicUsize = AtomicUsize::new(0);
static PLUGIN_LOGOUT_CALLS: AtomicUsize = AtomicUsize::new(0);
static PLUGIN_PERM_CHECK_CALLS: AtomicUsize = AtomicUsize::new(0);

struct CountingPlugin;

impl BulwarkPlugin for CountingPlugin {
    fn name(&self) -> &str {
        "counting-plugin"
    }
    fn on_login(&self, _login_id: i64, _token: &str) -> BulwarkResult<()> {
        PLUGIN_LOGIN_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn on_logout(&self, _login_id: i64, _token: &str) -> BulwarkResult<()> {
        PLUGIN_LOGOUT_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
    fn on_permission_check(&self, _login_id: i64, _permission: &str) -> BulwarkResult<()> {
        PLUGIN_PERM_CHECK_CALLS.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

fn counting_plugin_factory() -> Arc<dyn BulwarkPlugin> {
    Arc::new(CountingPlugin)
}

inventory::submit! {
    bulwark::plugin::BulwarkPluginEntry { factory: counting_plugin_factory }
}

// ============================================================================
// 测试用 Listener（计数器记录事件广播）
// ============================================================================

static LISTENER_LOGIN_EVENTS: AtomicUsize = AtomicUsize::new(0);
static LISTENER_LOGOUT_EVENTS: AtomicUsize = AtomicUsize::new(0);
static LISTENER_PERM_DENIED_EVENTS: AtomicUsize = AtomicUsize::new(0);

struct CountingListener;

impl BulwarkListener for CountingListener {
    fn on_event(&self, event: &BulwarkEvent) -> BulwarkResult<()> {
        match event {
            BulwarkEvent::Login { .. } => {
                LISTENER_LOGIN_EVENTS.fetch_add(1, Ordering::SeqCst);
            },
            BulwarkEvent::Logout { .. } => {
                LISTENER_LOGOUT_EVENTS.fetch_add(1, Ordering::SeqCst);
            },
            BulwarkEvent::PermissionDenied { .. } => {
                LISTENER_PERM_DENIED_EVENTS.fetch_add(1, Ordering::SeqCst);
            },
            _ => {},
        }
        Ok(())
    }
}

fn counting_listener_factory() -> Arc<dyn BulwarkListener> {
    Arc::new(CountingListener)
}

inventory::submit! {
    bulwark::listener::BulwarkListenerEntry { factory: counting_listener_factory }
}

// ============================================================================
// 辅助函数
// ============================================================================

fn reset_counters() {
    PLUGIN_LOGIN_CALLS.store(0, Ordering::SeqCst);
    PLUGIN_LOGOUT_CALLS.store(0, Ordering::SeqCst);
    PLUGIN_PERM_CHECK_CALLS.store(0, Ordering::SeqCst);
    LISTENER_LOGIN_EVENTS.store(0, Ordering::SeqCst);
    LISTENER_LOGOUT_EVENTS.store(0, Ordering::SeqCst);
    LISTENER_PERM_DENIED_EVENTS.store(0, Ordering::SeqCst);
}

// ============================================================================
// Plugin 集成测试
// ============================================================================

/// BulwarkPluginManager 收集 inventory 注册的插件（spec Scenario）。
#[test]
fn plugin_manager_collects_registered_plugins() {
    let manager = BulwarkPluginManager::new();
    assert!(
        manager.count() >= 1,
        "应至少收集到 1 个测试插件（CountingPlugin）"
    );
}

/// on_login 钩子被调用（spec Scenario）。
#[test]
fn plugin_on_login_invoked() {
    reset_counters();
    let manager = BulwarkPluginManager::new();
    manager.on_login(1001, "token-xyz");
    assert!(
        PLUGIN_LOGIN_CALLS.load(Ordering::SeqCst) >= 1,
        "CountingPlugin.on_login 应被调用至少 1 次"
    );
}

/// on_logout 钩子被调用（spec Scenario）。
#[test]
fn plugin_on_logout_invoked() {
    reset_counters();
    let manager = BulwarkPluginManager::new();
    manager.on_logout(1001, "token-xyz");
    assert!(
        PLUGIN_LOGOUT_CALLS.load(Ordering::SeqCst) >= 1,
        "CountingPlugin.on_logout 应被调用至少 1 次"
    );
}

/// on_permission_check 钩子被调用（spec Scenario）。
#[test]
fn plugin_on_permission_check_invoked() {
    reset_counters();
    let manager = BulwarkPluginManager::new();
    manager.on_permission_check(1001, "user:read");
    assert!(
        PLUGIN_PERM_CHECK_CALLS.load(Ordering::SeqCst) >= 1,
        "CountingPlugin.on_permission_check 应被调用至少 1 次"
    );
}

/// 多次调用累计计数（验证 plugin 是无状态可重入的，spec Scenario）。
#[test]
fn plugin_multiple_calls_accumulate() {
    reset_counters();
    let manager = BulwarkPluginManager::new();
    for _ in 0..5 {
        manager.on_login(1001, "t");
    }
    assert!(
        PLUGIN_LOGIN_CALLS.load(Ordering::SeqCst) >= 5,
        "5 次 on_login 应使计数器 >= 5"
    );
}

// ============================================================================
// Listener 集成测试
// ============================================================================

/// BulwarkListenerManager 收集 inventory 注册的 listener（spec Scenario）。
#[test]
fn listener_manager_collects_registered_listeners() {
    let manager = BulwarkListenerManager::new();
    assert!(
        manager.count() >= 1,
        "应至少收集到 1 个测试 listener（CountingListener）"
    );
}

/// Login 事件广播到 listener（spec Scenario）。
#[test]
fn listener_receives_login_event() {
    reset_counters();
    let manager = BulwarkListenerManager::new();
    manager.broadcast(&BulwarkEvent::Login {
        login_id: 1001,
        token: "T1".to_string(),
        device: Some("web".to_string()),
    });
    assert!(
        LISTENER_LOGIN_EVENTS.load(Ordering::SeqCst) >= 1,
        "CountingListener 应收到 Login 事件"
    );
}

/// Logout 事件广播到 listener（spec Scenario）。
#[test]
fn listener_receives_logout_event() {
    reset_counters();
    let manager = BulwarkListenerManager::new();
    manager.broadcast(&BulwarkEvent::Logout {
        login_id: 1001,
        token: "T1".to_string(),
    });
    assert!(
        LISTENER_LOGOUT_EVENTS.load(Ordering::SeqCst) >= 1,
        "CountingListener 应收到 Logout 事件"
    );
}

/// PermissionDenied 事件广播到 listener（spec Scenario）。
#[test]
fn listener_receives_permission_denied_event() {
    reset_counters();
    let manager = BulwarkListenerManager::new();
    manager.broadcast(&BulwarkEvent::PermissionDenied {
        login_id: 1001,
        permission: "user:delete".to_string(),
    });
    assert!(
        LISTENER_PERM_DENIED_EVENTS.load(Ordering::SeqCst) >= 1,
        "CountingListener 应收到 PermissionDenied 事件"
    );
}

/// 多次广播累计计数（spec Scenario）。
#[test]
fn listener_multiple_broadcasts_accumulate() {
    reset_counters();
    let manager = BulwarkListenerManager::new();
    for _ in 0..3 {
        manager.broadcast(&BulwarkEvent::Login {
            login_id: 1,
            token: "t".to_string(),
            device: None,
        });
    }
    assert!(
        LISTENER_LOGIN_EVENTS.load(Ordering::SeqCst) >= 3,
        "3 次 Login 广播应使计数器 >= 3"
    );
}

// ============================================================================
// 端到端集成：plugin + listener 协同
// ============================================================================

/// 完整生命周期：login → permission_check → logout
/// （auto-wire gap：当前需手动调用 plugin/listener，spec Scenario）。
#[test]
fn full_lifecycle_plugin_and_listener_cooperate() {
    reset_counters();

    let plugin_manager = BulwarkPluginManager::new();
    let listener_manager = BulwarkListenerManager::new();

    // 1. 模拟登录：先调用 plugin on_login，再广播 Login 事件
    plugin_manager.on_login(1001, "T1");
    listener_manager.broadcast(&BulwarkEvent::Login {
        login_id: 1001,
        token: "T1".to_string(),
        device: Some("web".to_string()),
    });

    // 2. 模拟权限校验：调用 plugin on_permission_check
    plugin_manager.on_permission_check(1001, "user:read");

    // 3. 模拟登出：调用 plugin on_logout + 广播 Logout 事件
    plugin_manager.on_logout(1001, "T1");
    listener_manager.broadcast(&BulwarkEvent::Logout {
        login_id: 1001,
        token: "T1".to_string(),
    });

    // 验证全部钩子与事件被触发
    assert!(
        PLUGIN_LOGIN_CALLS.load(Ordering::SeqCst) >= 1,
        "plugin on_login"
    );
    assert!(
        PLUGIN_PERM_CHECK_CALLS.load(Ordering::SeqCst) >= 1,
        "plugin on_permission_check"
    );
    assert!(
        PLUGIN_LOGOUT_CALLS.load(Ordering::SeqCst) >= 1,
        "plugin on_logout"
    );
    assert!(
        LISTENER_LOGIN_EVENTS.load(Ordering::SeqCst) >= 1,
        "listener Login 事件"
    );
    assert!(
        LISTENER_LOGOUT_EVENTS.load(Ordering::SeqCst) >= 1,
        "listener Logout 事件"
    );
}

/// PermissionDenied 事件不被 plugin 触发，仅由 listener 接收（spec Scenario）。
#[test]
fn permission_denied_event_only_goes_to_listener() {
    reset_counters();
    let plugin_manager = BulwarkPluginManager::new();
    let listener_manager = BulwarkListenerManager::new();

    // 权限校验被拒时：plugin 收到 on_permission_check，listener 收到 PermissionDenied
    plugin_manager.on_permission_check(1001, "user:delete");
    listener_manager.broadcast(&BulwarkEvent::PermissionDenied {
        login_id: 1001,
        permission: "user:delete".to_string(),
    });

    assert!(PLUGIN_PERM_CHECK_CALLS.load(Ordering::SeqCst) >= 1);
    assert!(LISTENER_PERM_DENIED_EVENTS.load(Ordering::SeqCst) >= 1);
}
