//! 事件监听器示例：演示 BulwarkListener trait 与 BulwarkListenerManager。
//!
//! 对应模块：`src/listener/mod.rs`（feature: listener）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin event_listener --features listener
//! ```

use async_trait::async_trait;
use bulwark::error::BulwarkResult;
use bulwark::listener::{
    BulwarkEvent, BulwarkListener, BulwarkListenerEntry, BulwarkListenerManager,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// ============================================================================
// 自定义监听器：通过 inventory 编译期注册
// ============================================================================

/// 计数器：记录 on_event 被调用的次数。
static EVENT_CALLS: AtomicUsize = AtomicUsize::new(0);

/// 审计日志监听器：记录所有事件到计数器（模拟写日志）。
struct AuditListener;

#[async_trait]
impl BulwarkListener for AuditListener {
    async fn on_event(&self, event: &BulwarkEvent) -> BulwarkResult<()> {
        EVENT_CALLS.fetch_add(1, Ordering::SeqCst);
        match event {
            BulwarkEvent::Login {
                login_id,
                token,
                device,
            } => {
                println!(
                    "    [AuditListener] Login: login_id={}, token={}..., device={:?}",
                    login_id,
                    &token[..8.min(token.len())],
                    device
                );
            },
            BulwarkEvent::Logout { login_id, token } => {
                println!(
                    "    [AuditListener] Logout: login_id={}, token={}...",
                    login_id,
                    &token[..8.min(token.len())]
                );
            },
            BulwarkEvent::PermissionCheck {
                login_id,
                permission,
            } => {
                println!(
                    "    [AuditListener] PermissionCheck: login_id={}, permission={}",
                    login_id, permission
                );
            },
            BulwarkEvent::TokenExpired { token } => {
                println!(
                    "    [AuditListener] TokenExpired: token={}...",
                    &token[..8.min(token.len())]
                );
            },
            _ => {
                println!("    [AuditListener] 事件: {:?}", event);
            },
        }
        Ok(())
    }
}

/// 失败监听器：on_event 始终返回 Err（验证广播不被中断）。
struct FailingListener;

#[async_trait]
impl BulwarkListener for FailingListener {
    async fn on_event(&self, _event: &BulwarkEvent) -> BulwarkResult<()> {
        Err(bulwark::error::BulwarkError::Internal(
            "FailingListener 故意失败".to_string(),
        ))
    }
}

/// 工厂函数：返回 AuditListener 实例。
fn audit_listener_factory() -> Arc<dyn BulwarkListener> {
    Arc::new(AuditListener)
}

/// 工厂函数：返回 FailingListener 实例。
fn failing_listener_factory() -> Arc<dyn BulwarkListener> {
    Arc::new(FailingListener)
}

// 编译期注册监听器（替代 Java SPI）
inventory::submit! {
    BulwarkListenerEntry { factory: audit_listener_factory }
}
inventory::submit! {
    BulwarkListenerEntry { factory: failing_listener_factory }
}

/// 运行事件监听器示例。
///
/// 演示 BulwarkListener trait 实现、inventory 编译期注册、
/// BulwarkListenerManager 收集并广播事件、单个监听器失败不中断广播。
pub async fn run() -> BulwarkResult<()> {
    println!("=== Bulwark 事件监听器示例 ===\n");

    // ----------------------------------------------------------------
    // 1. BulwarkListenerManager 收集所有已注册监听器
    // ----------------------------------------------------------------
    let manager = BulwarkListenerManager::new();
    println!("[1] BulwarkListenerManager::new()");
    println!("    已注册监听器数量 = {}", manager.count());
    assert!(manager.count() >= 2); // AuditListener + FailingListener
    println!();

    // ----------------------------------------------------------------
    // 2. 广播 Login 事件
    // ----------------------------------------------------------------
    println!("[2] broadcast(Login):");
    let login_event = BulwarkEvent::Login {
        login_id: 1001,
        token: "T1-uuid-token-abcd".to_string(),
        device: Some("web".to_string()),
    };
    let before = EVENT_CALLS.load(Ordering::SeqCst);
    manager.broadcast(&login_event).await;
    let after = EVENT_CALLS.load(Ordering::SeqCst);
    // FailingListener 失败，但 AuditListener 仍被调用
    assert!(after > before);
    println!(
        "    AuditListener 调用次数 +{}（FailingListener 失败未中断广播）\n",
        after - before
    );

    // ----------------------------------------------------------------
    // 3. 广播 Logout / PermissionCheck / TokenExpired 事件
    // ----------------------------------------------------------------
    println!("[3] 广播多种事件类型:");

    let logout_event = BulwarkEvent::Logout {
        login_id: 1001,
        token: "T1-uuid-token-abcd".to_string(),
    };
    manager.broadcast(&logout_event).await;

    let denied_event = BulwarkEvent::PermissionCheck {
        login_id: 1001,
        permission: "user:delete".to_string(),
    };
    manager.broadcast(&denied_event).await;

    let expired_event = BulwarkEvent::TokenExpired {
        token: "T1-uuid-token-abcd".to_string(),
    };
    manager.broadcast(&expired_event).await;
    println!();

    // ----------------------------------------------------------------
    // 4. 验证监听器总调用次数
    // ----------------------------------------------------------------
    let total_calls = EVENT_CALLS.load(Ordering::SeqCst);
    println!("[4] AuditListener 总调用次数 = {}（4 个事件）", total_calls);
    assert!(total_calls >= 4);
    println!("    ✓ 每个事件都触发了 AuditListener.on_event\n");

    // ----------------------------------------------------------------
    // 5. BulwarkEvent 派生 Debug + Clone
    // ----------------------------------------------------------------
    println!("[5] BulwarkEvent 派生 Debug + Clone:");
    let event = BulwarkEvent::Kickout {
        login_id: 2002,
        token: "T2-token".to_string(),
        reason: "管理员强制下线".to_string(),
    };
    let cloned = event.clone();
    let debug_str = format!("{:?}", event);
    println!("    Debug = {}", debug_str);
    println!(
        "    Clone 后匹配 Kickout: {}",
        matches!(cloned, BulwarkEvent::Kickout { .. })
    );
    println!();

    println!("=== 示例执行完成 ===");
    Ok(())
}
