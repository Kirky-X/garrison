//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 自定义插件示例：演示 GarrisonPlugin trait 与 GarrisonPluginManager 生命周期钩子。
//!
//! 对应模块：`src/plugin/mod.rs`（always on，无需 feature）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p garrison-examples --bin custom_plugin --features full
//! ```

use garrison::error::GarrisonResult;
use garrison::plugin::{GarrisonPlugin, GarrisonPluginEntry, GarrisonPluginManager};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// ============================================================================
// 自定义插件：通过 inventory 编译期注册
// ============================================================================

/// 计数器：记录各钩子被调用的次数。
static LOGIN_CALLS: AtomicUsize = AtomicUsize::new(0);
static LOGOUT_CALLS: AtomicUsize = AtomicUsize::new(0);
static PERM_CHECK_CALLS: AtomicUsize = AtomicUsize::new(0);

/// 审计插件：记录登录/登出/权限校验事件（观测不干预）。
struct AuditPlugin;

impl GarrisonPlugin for AuditPlugin {
    fn name(&self) -> &str {
        "audit-plugin"
    }

    fn on_login(&self, login_id: &str, token: &str) -> GarrisonResult<()> {
        LOGIN_CALLS.fetch_add(1, Ordering::SeqCst);
        println!(
            "    [AuditPlugin] on_login: login_id={}, token={}...",
            login_id,
            &token[..8.min(token.len())]
        );
        Ok(())
    }

    fn on_logout(&self, login_id: &str, token: &str) -> GarrisonResult<()> {
        LOGOUT_CALLS.fetch_add(1, Ordering::SeqCst);
        println!(
            "    [AuditPlugin] on_logout: login_id={}, token={}...",
            login_id,
            &token[..8.min(token.len())]
        );
        Ok(())
    }

    fn on_permission_check(&self, login_id: &str, permission: &str) -> GarrisonResult<()> {
        PERM_CHECK_CALLS.fetch_add(1, Ordering::SeqCst);
        println!(
            "    [AuditPlugin] on_permission_check: login_id={}, permission={}",
            login_id, permission
        );
        Ok(())
    }
}

/// 失败插件：所有钩子返回 Err（验证主流程不被中断）。
struct FailingPlugin;

impl GarrisonPlugin for FailingPlugin {
    fn name(&self) -> &str {
        "failing-plugin"
    }

    fn on_login(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> {
        Err(garrison::error::GarrisonError::Internal(
            "FailingPlugin on_login 故意失败".to_string(),
        ))
    }

    fn on_logout(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> {
        Err(garrison::error::GarrisonError::Internal(
            "FailingPlugin on_logout 故意失败".to_string(),
        ))
    }

    fn on_permission_check(&self, _login_id: &str, _permission: &str) -> GarrisonResult<()> {
        Err(garrison::error::GarrisonError::Internal(
            "FailingPlugin on_permission_check 故意失败".to_string(),
        ))
    }
}

/// 工厂函数：返回 AuditPlugin 实例。
fn audit_plugin_factory() -> Arc<dyn GarrisonPlugin> {
    Arc::new(AuditPlugin)
}

/// 工厂函数：返回 FailingPlugin 实例。
fn failing_plugin_factory() -> Arc<dyn GarrisonPlugin> {
    Arc::new(FailingPlugin)
}

// 编译期注册插件（替代 Java SPI）
inventory::submit! {
    GarrisonPluginEntry { factory: audit_plugin_factory }
}
inventory::submit! {
    GarrisonPluginEntry { factory: failing_plugin_factory }
}

/// 运行自定义插件示例。
///
/// 演示 GarrisonPlugin trait 实现、inventory 编译期注册、
/// GarrisonPluginManager 收集与调用钩子、单个插件失败不中断主流程。
pub fn run() -> GarrisonResult<()> {
    println!("=== Garrison 自定义插件示例 ===\n");

    // ----------------------------------------------------------------
    // 1. GarrisonPluginManager 收集所有已注册插件
    // ----------------------------------------------------------------
    let manager = GarrisonPluginManager::new();
    println!("[1] GarrisonPluginManager::new()");
    println!("    已注册插件数量 = {}", manager.count());
    assert!(manager.count() >= 2); // AuditPlugin + FailingPlugin
    println!();

    // ----------------------------------------------------------------
    // 2. on_login 钩子（登录成功后调用）
    // ----------------------------------------------------------------
    println!("[2] on_login(1001, \"T1-uuid-token\"):");
    let before = LOGIN_CALLS.load(Ordering::SeqCst);
    manager.on_login("1001", "T1-uuid-token");
    let after = LOGIN_CALLS.load(Ordering::SeqCst);
    // FailingPlugin 失败，但 AuditPlugin 仍被调用
    assert!(after > before);
    println!(
        "    AuditPlugin on_login 调用次数 +{}（FailingPlugin 失败未中断）\n",
        after - before
    );

    // ----------------------------------------------------------------
    // 3. on_permission_check 钩子（权限校验时调用，观测不干预）
    // ----------------------------------------------------------------
    println!("[3] on_permission_check(1001, \"user:read\"):");
    manager.on_permission_check("1001", "user:read");
    assert!(PERM_CHECK_CALLS.load(Ordering::SeqCst) >= 1);
    println!();

    // ----------------------------------------------------------------
    // 4. on_logout 钩子（登出后调用）
    // ----------------------------------------------------------------
    println!("[4] on_logout(1001, \"T1-uuid-token\"):");
    manager.on_logout("1001", "T1-uuid-token");
    assert!(LOGOUT_CALLS.load(Ordering::SeqCst) >= 1);
    println!();

    // ----------------------------------------------------------------
    // 5. 验证各钩子总调用次数
    // ----------------------------------------------------------------
    println!("[5] AuditPlugin 钩子调用统计:");
    println!(
        "    on_login            = {}",
        LOGIN_CALLS.load(Ordering::SeqCst)
    );
    println!(
        "    on_logout           = {}",
        LOGOUT_CALLS.load(Ordering::SeqCst)
    );
    println!(
        "    on_permission_check = {}",
        PERM_CHECK_CALLS.load(Ordering::SeqCst)
    );
    assert!(LOGIN_CALLS.load(Ordering::SeqCst) >= 1);
    assert!(LOGOUT_CALLS.load(Ordering::SeqCst) >= 1);
    assert!(PERM_CHECK_CALLS.load(Ordering::SeqCst) >= 1);
    println!("    ✓ 所有钩子均被调用\n");

    // ----------------------------------------------------------------
    // 6. Default trait 等价于 new()
    // ----------------------------------------------------------------
    let m1 = GarrisonPluginManager::new();
    let m2 = GarrisonPluginManager::default();
    assert_eq!(m1.count(), m2.count());
    println!(
        "[6] Default::default() 等价于 new()：count={} ✓\n",
        m2.count()
    );

    println!("=== 示例执行完成 ===");
    Ok(())
}
