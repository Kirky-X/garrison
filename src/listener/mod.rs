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
/// 派生 `Debug`、`Clone`、`PartialEq`，便于在监听器中复制、打印与比较。
#[derive(Debug, Clone, PartialEq)]
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
    /// 登录失败事件（v0.4.2 新增，依据 spec listener-events-extend R-001）。
    ///
    /// 在 `login_with_password` 失败路径广播（user_not_found / wrong_password）。
    /// 注意：login_id 字段使用 `i64` 而非 `LoginId` newtype，以保持与现有 6 个变体一致
    ///（偏差 D-Phase11-1，依据规则 11 惯例优先于新颖）。
    LoginFailure {
        /// 登录主体标识。
        login_id: i64,
        /// 失败原因（"user_not_found" / "wrong_password"）。
        reason: String,
    },
    /// Token 刷新事件（v0.4.2 新增，依据 spec listener-events-extend R-001）。
    ///
    /// 在 `refresh_token` 成功路径广播，携带旧 token 与新 token。
    TokenRefresh {
        /// 登录主体标识。
        login_id: i64,
        /// 刷新前的旧 token。
        old_token: String,
        /// 刷新后的新 token。
        new_token: String,
    },
    /// Token 主动吊销事件（v0.4.2 新增，依据 spec listener-events-extend R-001）。
    ///
    /// 在 `BulwarkLogic::revoke_token` 调用时广播（携带被吊销的 token）。
    /// 与 `Logout` 事件的区别：`revoke_token` 语义为"token 失效"（如 OAuth2 token revocation），
    /// `Logout` 语义为"用户主动登出"（携带 login_id+token）。
    TokenRevoke {
        /// 被吊销的 token。
        token: String,
    },
    /// 会话超时事件（v0.4.2 新增，依据 spec listener-events-extend R-001）。
    ///
    /// 在 `check_login_simple` / `check_login_mixin` 判定 token 无效时广播。
    /// 若 token session 完全不存在（无法获取 login_id）则跳过广播。
    SessionTimeout {
        /// 登录主体标识。
        login_id: i64,
        /// 超时的 token。
        token: String,
    },
    /// 账号锁定事件（v0.4.2 新增，依据 spec listener-events-extend R-001）。
    ///
    /// 在 `check_brute_force` 阻断路径广播（暴力破解检测触发）。
    AccountLocked {
        /// 登录主体标识。
        login_id: i64,
        /// 锁定原因（如 "brute_force: 5 failures in 1h"）。
        reason: String,
    },
    /// 防火墙阻断事件（v0.4.2 新增，依据 spec listener-events-extend R-001）。
    ///
    /// 在 `check_login_hooks` 任一 hook 返回 Err 时广播。
    FirewallBlock {
        /// 登录主体标识。
        login_id: i64,
        /// 阻断原因（hook 错误信息）。
        reason: String,
    },
    /// API Key 轮换事件（v0.4.2 新增，依据 spec listener-events-extend R-001）。
    ///
    /// 在 `ApiKeyHandler::rotate` 成功路径广播。
    ApiKeyRotate {
        /// 轮换前的旧 key。
        old_key: String,
        /// 轮换后的新 key。
        new_key: String,
    },
    /// 临时凭据消费事件（v0.4.2 新增，依据 spec listener-events-extend R-001）。
    ///
    /// 在 `TempCredentialHandler::consume` 成功消费时广播（value 为 Some 时）。
    TempCredentialConsumed {
        /// 被消费的凭据 key。
        key: String,
        /// 凭据载荷值。
        value: String,
    },
    /// 配置热重载事件（v0.4.2 新增，依据 spec listener-events-extend R-001）。
    ///
    /// **注意**：当前未集成 broadcast，因为 `ConfigLoader` trait 未定义 `reload` 方法。
    /// v0.5.0+ 实现 `ConfigLoader::reload` + 全局 `BulwarkManager::update_config` 后
    /// 在对应路径补充广播（依据 spec listener-events-extend Out of Scope）。
    ConfigReload {
        /// 重载原因。
        reason: String,
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
    use serial_test::serial;
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
    #[serial]
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
    #[serial]
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
    #[serial]
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
    #[serial]
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
    #[serial]
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
    #[serial]
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
    #[serial]
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
    #[serial]
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
    #[serial]
    fn manager_collects_registered_listeners() {
        let manager = BulwarkListenerManager::new();
        // 至少 2 个监听器（OkListener + ErrListener）
        assert!(manager.count() >= 2);
    }

    /// broadcast 调用所有监听器（spec Scenario）。
    #[test]
    #[serial]
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
    #[serial]
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
    #[serial]
    fn default_equals_new() {
        let m1 = BulwarkListenerManager::new();
        let m2 = BulwarkListenerManager::default();
        assert_eq!(m1.count(), m2.count());
    }

    /// 验证 new() 在 tracing subscriber 已初始化时正确求值 info! 宏参数。
    ///
    /// 覆盖 BulwarkListenerManager::new() 中 `tracing::info!` 宏的参数求值路径
    /// （line 117: `std::any::type_name::<Arc<dyn BulwarkListener>>()`）。
    /// tracing::info! 在无 subscriber 时短路不求值参数，需确保 subscriber 已设置。
    #[test]
    #[serial]
    fn manager_new_with_tracing_subscriber() {
        // 确保 tracing subscriber 已初始化（幂等，已设置时返回 Err 被忽略）
        #[cfg(any(feature = "tracing-log", feature = "metrics-prometheus"))]
        {
            let _ = tracing_subscriber::fmt().try_init();
        }
        let manager = BulwarkListenerManager::new();
        assert!(manager.count() >= 2);
    }

    /// 验证 broadcast 对 PermissionDenied 事件正确分发。
    #[test]
    #[serial]
    fn broadcast_permission_denied_event() {
        reset_counters();
        let manager = BulwarkListenerManager::new();
        let event = BulwarkEvent::PermissionDenied {
            login_id: 1001,
            permission: "user:delete".to_string(),
        };
        manager.broadcast(&event);
        assert!(EVENT_CALLS.load(Ordering::SeqCst) >= 1);
    }

    /// 验证 broadcast 对 RoleDenied 事件正确分发。
    #[test]
    #[serial]
    fn broadcast_role_denied_event() {
        reset_counters();
        let manager = BulwarkListenerManager::new();
        let event = BulwarkEvent::RoleDenied {
            login_id: 1001,
            role: "admin".to_string(),
        };
        manager.broadcast(&event);
        assert!(EVENT_CALLS.load(Ordering::SeqCst) >= 1);
    }

    /// 验证 broadcast 对 TokenExpired 事件正确分发。
    #[test]
    #[serial]
    fn broadcast_token_expired_event() {
        reset_counters();
        let manager = BulwarkListenerManager::new();
        let event = BulwarkEvent::TokenExpired {
            token: "expired-token".to_string(),
        };
        manager.broadcast(&event);
        assert!(EVENT_CALLS.load(Ordering::SeqCst) >= 1);
    }

    /// 验证 broadcast 对 Kickout 事件正确分发。
    #[test]
    #[serial]
    fn broadcast_kickout_event() {
        reset_counters();
        let manager = BulwarkListenerManager::new();
        let event = BulwarkEvent::Kickout {
            login_id: 1001,
            token: "t1".to_string(),
            reason: "强制下线".to_string(),
        };
        manager.broadcast(&event);
        assert!(EVENT_CALLS.load(Ordering::SeqCst) >= 1);
    }

    // ========================================================================
    // 0.4.2 新增：9 个新事件变体测试（依据 spec listener-events-extend R-001）
    // ========================================================================

    /// LoginFailure 事件携带 login_id 与 reason，派生 Debug/Clone/PartialEq
    /// （依据 spec listener-events-extend R-001）。
    #[test]
    #[serial]
    fn login_failure_event_carries_login_id_and_reason() {
        let event = BulwarkEvent::LoginFailure {
            login_id: 1001,
            reason: "wrong_password".to_string(),
        };
        match event.clone() {
            BulwarkEvent::LoginFailure { login_id, reason } => {
                assert_eq!(login_id, 1001);
                assert_eq!(reason, "wrong_password");
            },
            _ => panic!("期望 LoginFailure 事件"),
        }
        let cloned = event.clone();
        assert_eq!(event, cloned);
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("LoginFailure"));
    }

    /// TokenRefresh 事件携带 login_id/old_token/new_token，派生 Debug/Clone/PartialEq
    /// （依据 spec listener-events-extend R-001）。
    #[test]
    #[serial]
    fn token_refresh_event_carries_tokens() {
        let event = BulwarkEvent::TokenRefresh {
            login_id: 1001,
            old_token: "old-tok".to_string(),
            new_token: "new-tok".to_string(),
        };
        match event.clone() {
            BulwarkEvent::TokenRefresh {
                login_id,
                old_token,
                new_token,
            } => {
                assert_eq!(login_id, 1001);
                assert_eq!(old_token, "old-tok");
                assert_eq!(new_token, "new-tok");
            },
            _ => panic!("期望 TokenRefresh 事件"),
        }
        let cloned = event.clone();
        assert_eq!(event, cloned);
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("TokenRefresh"));
    }

    /// TokenRevoke 事件携带 token，派生 Debug/Clone/PartialEq
    /// （依据 spec listener-events-extend R-001）。
    #[test]
    #[serial]
    fn token_revoke_event_carries_token() {
        let event = BulwarkEvent::TokenRevoke {
            token: "revoke-tok".to_string(),
        };
        match event.clone() {
            BulwarkEvent::TokenRevoke { token } => {
                assert_eq!(token, "revoke-tok");
            },
            _ => panic!("期望 TokenRevoke 事件"),
        }
        let cloned = event.clone();
        assert_eq!(event, cloned);
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("TokenRevoke"));
    }

    /// SessionTimeout 事件携带 login_id/token，派生 Debug/Clone/PartialEq
    /// （依据 spec listener-events-extend R-001）。
    #[test]
    #[serial]
    fn session_timeout_event_carries_login_id_and_token() {
        let event = BulwarkEvent::SessionTimeout {
            login_id: 1001,
            token: "expired-tok".to_string(),
        };
        match event.clone() {
            BulwarkEvent::SessionTimeout { login_id, token } => {
                assert_eq!(login_id, 1001);
                assert_eq!(token, "expired-tok");
            },
            _ => panic!("期望 SessionTimeout 事件"),
        }
        let cloned = event.clone();
        assert_eq!(event, cloned);
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("SessionTimeout"));
    }

    /// AccountLocked 事件携带 login_id/reason，派生 Debug/Clone/PartialEq
    /// （依据 spec listener-events-extend R-001）。
    #[test]
    #[serial]
    fn account_locked_event_carries_login_id_and_reason() {
        let event = BulwarkEvent::AccountLocked {
            login_id: 1001,
            reason: "brute_force".to_string(),
        };
        match event.clone() {
            BulwarkEvent::AccountLocked { login_id, reason } => {
                assert_eq!(login_id, 1001);
                assert_eq!(reason, "brute_force");
            },
            _ => panic!("期望 AccountLocked 事件"),
        }
        let cloned = event.clone();
        assert_eq!(event, cloned);
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("AccountLocked"));
    }

    /// FirewallBlock 事件携带 login_id/reason，派生 Debug/Clone/PartialEq
    /// （依据 spec listener-events-extend R-001）。
    #[test]
    #[serial]
    fn firewall_block_event_carries_login_id_and_reason() {
        let event = BulwarkEvent::FirewallBlock {
            login_id: 1001,
            reason: "frequency_exceeded".to_string(),
        };
        match event.clone() {
            BulwarkEvent::FirewallBlock { login_id, reason } => {
                assert_eq!(login_id, 1001);
                assert_eq!(reason, "frequency_exceeded");
            },
            _ => panic!("期望 FirewallBlock 事件"),
        }
        let cloned = event.clone();
        assert_eq!(event, cloned);
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("FirewallBlock"));
    }

    /// ApiKeyRotate 事件携带 old_key/new_key，派生 Debug/Clone/PartialEq
    /// （依据 spec listener-events-extend R-001）。
    #[test]
    #[serial]
    fn api_key_rotate_event_carries_keys() {
        let event = BulwarkEvent::ApiKeyRotate {
            old_key: "old-key".to_string(),
            new_key: "new-key".to_string(),
        };
        match event.clone() {
            BulwarkEvent::ApiKeyRotate { old_key, new_key } => {
                assert_eq!(old_key, "old-key");
                assert_eq!(new_key, "new-key");
            },
            _ => panic!("期望 ApiKeyRotate 事件"),
        }
        let cloned = event.clone();
        assert_eq!(event, cloned);
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("ApiKeyRotate"));
    }

    /// TempCredentialConsumed 事件携带 key/value，派生 Debug/Clone/PartialEq
    /// （依据 spec listener-events-extend R-001）。
    #[test]
    #[serial]
    fn temp_credential_consumed_event_carries_key_and_value() {
        let event = BulwarkEvent::TempCredentialConsumed {
            key: "invite-key".to_string(),
            value: "payload".to_string(),
        };
        match event.clone() {
            BulwarkEvent::TempCredentialConsumed { key, value } => {
                assert_eq!(key, "invite-key");
                assert_eq!(value, "payload");
            },
            _ => panic!("期望 TempCredentialConsumed 事件"),
        }
        let cloned = event.clone();
        assert_eq!(event, cloned);
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("TempCredentialConsumed"));
    }

    /// ConfigReload 事件携带 reason，派生 Debug/Clone/PartialEq
    /// （依据 spec listener-events-extend R-001）。
    #[test]
    #[serial]
    fn config_reload_event_carries_reason() {
        let event = BulwarkEvent::ConfigReload {
            reason: "manual".to_string(),
        };
        match event.clone() {
            BulwarkEvent::ConfigReload { reason } => {
                assert_eq!(reason, "manual");
            },
            _ => panic!("期望 ConfigReload 事件"),
        }
        let cloned = event.clone();
        assert_eq!(event, cloned);
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("ConfigReload"));
    }
}
