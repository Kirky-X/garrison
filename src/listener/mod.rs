//! 监听器模块，提供事件订阅抽象与编译期注册。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `SaTokenListener`，
//! 通过 `inventory` crate 实现编译期监听器注册（替代 Java SPI）。
//!
//! 与 `plugin` 模块的区别：
//! - `BulwarkPlugin`：主动钩子（在特定方法前后被调用，如 `on_login`）
//! - `BulwarkListener`：被动订阅（订阅 `BulwarkEvent` 枚举的变体）
//!
//! 此模块仅在启用 `listener` 特性时编译。
//! 监听器失败仅记录 `tracing::warn!`，不中断主流程。

use crate::error::BulwarkResult;
use std::sync::Arc;

/// 事件枚举，定义框架广播的所有事件变体（依据 spec listener-system）。
///
/// 派生 `Debug`、`Clone`，便于在监听器中复制与打印。
#[derive(Debug, Clone)]
pub enum BulwarkEvent {
    /// 登录成功事件。
    Login {
        /// 登录主体标识。
        login_id: i64,
        /// 登录后生成的 token。
        token: String,
        /// 登录设备信息（可选）。
        device: Option<String>,
    },
    /// 登出事件。
    Logout {
        /// 登录主体标识。
        login_id: i64,
        /// 被登出的 token。
        token: String,
    },
    /// 被踢下线事件。
    Kickout {
        /// 登录主体标识。
        login_id: i64,
        /// 被踢下线的 token。
        token: String,
        /// 踢出原因。
        reason: String,
    },
    /// 权限校验被拒事件。
    PermissionDenied {
        /// 登录主体标识。
        login_id: i64,
        /// 被拒的权限字符串。
        permission: String,
    },
    /// 角色校验被拒事件。
    RoleDenied {
        /// 登录主体标识。
        login_id: i64,
        /// 被拒的角色字符串。
        role: String,
    },
    /// Token 过期事件。
    TokenExpired {
        /// 过期的 token。
        token: String,
    },
}

/// 监听器 trait，提供事件订阅抽象（依据 spec listener-system）。
///
/// trait 绑定 `Send + Sync`，核心方法为 `on_event`，实现方按事件类型选择性处理。
/// 与 `BulwarkPlugin` 的区别：plugin 是"主动钩子"（在特定方法前后被调用），
/// listener 是"被动订阅"（订阅事件类型）。
pub trait BulwarkListener: Send + Sync {
    /// 事件处理方法（依据 spec listener-system）。
    ///
    /// 实现方按事件类型选择性处理，默认空实现返回 `Ok(())`。
    /// 监听器实现应快速返回或内部 spawn，避免阻塞主流程。
    fn on_event(&self, _event: &BulwarkEvent) -> BulwarkResult<()> {
        Ok(())
    }
}

/// 监听器工厂函数指针，返回 `Arc<dyn BulwarkListener>`（依据 spec listener-system）。
pub type BulwarkListenerFactoryFn = fn() -> Arc<dyn BulwarkListener>;

/// 监听器注册条目，用于 `inventory` 收集（依据 spec listener-system）。
///
/// 通过 `inventory::submit! { BulwarkListenerEntry { factory: my_listener_factory } }` 注册监听器，
/// 运行期通过 `inventory::iter::<BulwarkListenerEntry>()` 遍历。
pub struct BulwarkListenerEntry {
    /// 监听器工厂函数。
    pub factory: BulwarkListenerFactoryFn,
}

// 编译期监听器注册收集点
inventory::collect!(BulwarkListenerEntry);

/// 监听器管理器，收集并管理所有已注册监听器（依据 spec listener-system）。
///
/// 在 `BulwarkManager::init` 时通过 `inventory::iter` 收集所有已注册监听器。
/// `broadcast` 方法同步遍历所有监听器调用 `on_event`，
/// 单个监听器失败时仅记录 `tracing::warn!` 日志，不中断广播。
pub struct BulwarkListenerManager {
    /// 已注册的监听器列表。
    listeners: Vec<Arc<dyn BulwarkListener>>,
}

impl BulwarkListenerManager {
    /// 创建监听器管理器并收集所有已注册监听器（依据 spec listener-system）。
    pub fn new() -> Self {
        use std::iter::Iterator;
        let listeners: Vec<Arc<dyn BulwarkListener>> = inventory::iter::<BulwarkListenerEntry>()
            .map(|entry| (entry.factory)())
            .collect();
        for l in &listeners {
            tracing::info!(
                "已加载监听器: {}",
                std::any::type_name::<Arc<dyn BulwarkListener>>()
            );
            let _ = l; // 避免 unused 警告
        }
        Self { listeners }
    }

    /// 返回已注册监听器数量。
    pub fn count(&self) -> usize {
        self.listeners.len()
    }

    /// 广播事件到所有已注册监听器（依据 spec listener-system）。
    ///
    /// 同步遍历所有监听器的 `on_event` 方法，单个监听器失败仅记录 `tracing::warn!`，
    /// 不中断广播，最终返回 `Ok(())`。
    pub fn broadcast(&self, event: &BulwarkEvent) {
        for listener in &self.listeners {
            if let Err(e) = listener.on_event(event) {
                tracing::warn!("监听器 on_event 失败: {}", e);
            }
        }
    }
}

impl Default for BulwarkListenerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    // ========================================================================
    // 测试用 Mock 监听器
    // ========================================================================

    /// 计数器，记录 on_event 被调用次数。
    static EVENT_CALLS: AtomicUsize = AtomicUsize::new(0);

    /// 成功监听器，on_event 返回 Ok(())。
    struct OkListener;

    impl BulwarkListener for OkListener {
        fn on_event(&self, _event: &BulwarkEvent) -> BulwarkResult<()> {
            EVENT_CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// 失败监听器，on_event 返回 Err。
    struct ErrListener;

    impl BulwarkListener for ErrListener {
        fn on_event(&self, _event: &BulwarkEvent) -> BulwarkResult<()> {
            Err(crate::error::BulwarkError::Internal(
                "on_event 失败".to_string(),
            ))
        }
    }

    fn ok_listener_factory() -> Arc<dyn BulwarkListener> {
        Arc::new(OkListener)
    }

    fn err_listener_factory() -> Arc<dyn BulwarkListener> {
        Arc::new(ErrListener)
    }

    // 注册测试监听器到 inventory
    inventory::submit! {
        BulwarkListenerEntry { factory: ok_listener_factory }
    }
    inventory::submit! {
        BulwarkListenerEntry { factory: err_listener_factory }
    }

    /// 重置计数器。
    fn reset_counters() {
        EVENT_CALLS.store(0, Ordering::SeqCst);
    }

    // ========================================================================
    // BulwarkEvent 枚举测试（依据 spec listener-system）
    // ========================================================================

    /// Login 事件携带 login_id、token 与 device（spec Scenario）。
    #[test]
    fn login_event_carries_login_id_token_device() {
        let event = BulwarkEvent::Login {
            login_id: 1001,
            token: "T1".to_string(),
            device: Some("web".to_string()),
        };
        match event {
            BulwarkEvent::Login {
                login_id,
                token,
                device,
            } => {
                assert_eq!(login_id, 1001);
                assert_eq!(token, "T1");
                assert_eq!(device, Some("web".to_string()));
            },
            _ => panic!("期望 Login 事件"),
        }
    }

    /// Logout 事件携带 login_id 与 token（spec Scenario）。
    #[test]
    fn logout_event_carries_login_id_and_token() {
        let event = BulwarkEvent::Logout {
            login_id: 1001,
            token: "T1".to_string(),
        };
        match event {
            BulwarkEvent::Logout { login_id, token } => {
                assert_eq!(login_id, 1001);
                assert_eq!(token, "T1");
            },
            _ => panic!("期望 Logout 事件"),
        }
    }

    /// Kickout 事件携带踢出原因（spec Scenario）。
    #[test]
    fn kickout_event_carries_reason() {
        let event = BulwarkEvent::Kickout {
            login_id: 1001,
            token: "T1".to_string(),
            reason: "管理员强制下线".to_string(),
        };
        match event {
            BulwarkEvent::Kickout {
                login_id,
                token,
                reason,
            } => {
                assert_eq!(login_id, 1001);
                assert_eq!(token, "T1");
                assert_eq!(reason, "管理员强制下线");
            },
            _ => panic!("期望 Kickout 事件"),
        }
    }

    /// PermissionDenied 事件携带被拒权限（spec Scenario）。
    #[test]
    fn permission_denied_event_carries_permission() {
        let event = BulwarkEvent::PermissionDenied {
            login_id: 1001,
            permission: "user:delete".to_string(),
        };
        match event {
            BulwarkEvent::PermissionDenied {
                login_id,
                permission,
            } => {
                assert_eq!(login_id, 1001);
                assert_eq!(permission, "user:delete");
            },
            _ => panic!("期望 PermissionDenied 事件"),
        }
    }

    /// RoleDenied 事件携带被拒角色（spec Scenario）。
    #[test]
    fn role_denied_event_carries_role() {
        let event = BulwarkEvent::RoleDenied {
            login_id: 1001,
            role: "admin".to_string(),
        };
        match event {
            BulwarkEvent::RoleDenied { login_id, role } => {
                assert_eq!(login_id, 1001);
                assert_eq!(role, "admin");
            },
            _ => panic!("期望 RoleDenied 事件"),
        }
    }

    /// TokenExpired 事件携带过期 token（spec Scenario）。
    #[test]
    fn token_expired_event_carries_token() {
        let event = BulwarkEvent::TokenExpired {
            token: "T1".to_string(),
        };
        match event {
            BulwarkEvent::TokenExpired { token } => {
                assert_eq!(token, "T1");
            },
            _ => panic!("期望 TokenExpired 事件"),
        }
    }

    /// BulwarkEvent 派生 Debug 与 Clone（spec Requirement）。
    #[test]
    fn event_derives_debug_and_clone() {
        let event = BulwarkEvent::Login {
            login_id: 1001,
            token: "T1".to_string(),
            device: None,
        };
        // Clone
        let cloned = event.clone();
        match cloned {
            BulwarkEvent::Login { login_id, .. } => assert_eq!(login_id, 1001),
            _ => panic!("clone 后应为 Login"),
        }
        // Debug
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("Login"));
    }

    // ========================================================================
    // BulwarkListener trait 测试（依据 spec listener-system）
    // ========================================================================

    /// 默认 on_event 返回 Ok(())（spec Scenario：监听器需实现 on_event 方法）。
    #[test]
    fn default_on_event_returns_ok() {
        struct EmptyListener;
        impl BulwarkListener for EmptyListener {}
        let listener = EmptyListener;
        let event = BulwarkEvent::Login {
            login_id: 1,
            token: "t".to_string(),
            device: None,
        };
        assert!(listener.on_event(&event).is_ok());
    }

    // ========================================================================
    // BulwarkListenerManager 测试（依据 spec listener-system）
    // ========================================================================

    /// manager 收集所有已注册监听器（spec Scenario）。
    #[test]
    fn manager_collects_registered_listeners() {
        let manager = BulwarkListenerManager::new();
        // 至少 2 个监听器（OkListener + ErrListener）
        assert!(manager.count() >= 2);
    }

    /// broadcast 调用所有监听器（spec Scenario）。
    #[test]
    fn broadcast_invokes_all_listeners() {
        reset_counters();
        let manager = BulwarkListenerManager::new();
        let event = BulwarkEvent::Login {
            login_id: 1001,
            token: "T1".to_string(),
            device: Some("web".to_string()),
        };
        manager.broadcast(&event);
        // OkListener 的 on_event 应被调用至少 1 次
        assert!(EVENT_CALLS.load(Ordering::SeqCst) >= 1);
    }

    /// 单个监听器失败不中断广播（spec Scenario）。
    #[test]
    fn broadcast_listener_failure_does_not_interrupt() {
        reset_counters();
        let manager = BulwarkListenerManager::new();
        let event = BulwarkEvent::Logout {
            login_id: 1001,
            token: "T1".to_string(),
        };
        manager.broadcast(&event);
        // ErrListener 失败，但 OkListener 仍应被调用
        assert!(EVENT_CALLS.load(Ordering::SeqCst) >= 1);
    }

    /// Default trait 实现等价于 new()。
    #[test]
    fn default_equals_new() {
        let m1 = BulwarkListenerManager::new();
        let m2 = BulwarkListenerManager::default();
        assert_eq!(m1.count(), m2.count());
    }
}
