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
use async_trait::async_trait;
use std::sync::Arc;

/// 审计日志子模块（v0.5.0 新增，依据 proposal H3）。
///
/// 启用 `audit-log` feature 时编译，提供 `AuditLogListener` 持久化事件到 `audit_logs` 表。
#[cfg(feature = "audit-log")]
pub mod audit;

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
    /// 权限校验事件（v0.5.0 重命名：原 PermissionDenied → PermissionCheck，对齐 spec R-audit-log-005）。
    PermissionCheck {
        /// 登录主体标识。
        login_id: i64,
        /// 被校验的权限字符串。
        permission: String,
    },
    /// 角色校验事件（v0.5.0 重命名：原 RoleDenied → RoleCheck，对齐 spec R-audit-log-005）。
    RoleCheck {
        /// 登录主体标识。
        login_id: i64,
        /// 被校验的角色字符串。
        role: String,
    },
    /// Token 过期事件。
    TokenExpired {
        /// 过期的 token。
        token: String,
    },
    /// 登录失败事件（v0.4.2 新增，依据 spec listener-events-extend R-001）。
    ///
    /// 在 `login_with_password` 失败路径广播（invalid_credentials / hash_format_error）。
    /// 注意：login_id 字段使用 `i64` 而非 `LoginId` newtype，以保持与现有 6 个变体一致
    ///（偏差 D-Phase11-1，依据规则 11 惯例优先于新颖）。
    LoginFailure {
        /// 登录主体标识。
        login_id: i64,
        /// 失败原因（"invalid_credentials" / "hash_format_error"）。
        ///
        /// v0.4.2 安全审计 A-014: user_not_found 与 wrong_password 统一为 "invalid_credentials"，
        /// 防止日志/事件泄露用户存在性（防用户枚举）。
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
    /// Token 主动吊销事件（v0.5.0 重命名：原 TokenRevoke → RevokeToken，对齐 spec R-audit-log-005）。
    ///
    /// 在 `BulwarkLogic::revoke_token` 调用时广播（携带被吊销的 token）。
    /// 与 `Logout` 事件的区别：`revoke_token` 语义为"token 失效"（如 OAuth2 token revocation），
    /// `Logout` 语义为"用户主动登出"（携带 login_id+token）。
    RevokeToken {
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
    /// API Key 轮换事件（v0.5.0 重命名：原 ApiKeyRotate → TokenRotate，对齐 spec R-audit-log-005）。
    ///
    /// 在 `ApiKeyHandler::rotate` 成功路径广播。
    TokenRotate {
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
    // ========================================================================
    // v0.5.0 新增变体（spec R-audit-log-005 要求，T076 Green）
    // ========================================================================
    /// 社交登录事件（v0.5.0 新增，spec R-audit-log-005）。
    ///
    /// 在社交登录（微信/支付宝等）成功时广播。
    SocialLogin {
        /// 社交登录 provider 名称（如 "wechat" / "alipay"）。
        provider: String,
        /// 社交平台返回的用户 ID。
        user_id: String,
        /// 关联的本地 login_id（首次登录可能为 None，绑定后才有）。
        login_id: Option<i64>,
    },
    /// 租户切换事件（v0.5.0 新增，spec R-audit-log-005）。
    ///
    /// 在用户切换租户上下文时广播。
    TenantSwitch {
        /// 登录主体标识。
        login_id: i64,
        /// 切换前的租户 ID。
        from_tenant: i64,
        /// 切换后的租户 ID。
        to_tenant: i64,
    },
    /// 设备封禁事件（v0.5.0 新增，spec R-audit-log-005）。
    ///
    /// 在设备被风控封禁时广播。
    DeviceBlock {
        /// 登录主体标识。
        login_id: i64,
        /// 被封禁的设备标识。
        device: String,
    },
    /// 设备解封事件（v0.5.0 新增，spec R-audit-log-005）。
    ///
    /// 在设备被封禁后解封时广播。
    DeviceUnblock {
        /// 登录主体标识。
        login_id: i64,
        /// 被解封的设备标识。
        device: String,
    },
    /// 配置热重载事件（v0.5.0 新增，spec R-audit-log-005）。
    ///
    /// 在运行时配置被热重载时广播。
    ConfigReload {
        /// 新配置版本号。
        config_version: u32,
    },
}

/// 监听器 trait，提供事件订阅抽象（依据 spec listener-system）。
///
/// trait 绑定 `Send + Sync`，核心方法为 `on_event`，实现方按事件类型选择性处理。
/// 与 `BulwarkPlugin` 的区别：plugin 是"主动钩子"（在特定方法前后被调用），
/// listener 是"被动订阅"（订阅事件类型）。
#[async_trait]
pub trait BulwarkListener: Send + Sync {
    /// 事件处理方法（依据 spec listener-system）。
    ///
    /// 实现方按事件类型选择性处理，默认空实现返回 `Ok(())`。
    /// 监听器实现应快速返回或内部 spawn，避免阻塞主流程。
    ///
    /// v0.5.0 改为 async（依据 proposal H3）：支持 SQL-backed 监听器（如 AuditLogListener）
    /// 执行异步持久化操作。所有实现与调用方需 `.await`。
    async fn on_event(&self, _event: &BulwarkEvent) -> BulwarkResult<()> {
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
    /// 异步遍历所有监听器的 `on_event` 方法，单个监听器失败仅记录 `tracing::warn!`，
    /// 不中断广播，最终返回 `Ok(())`。
    ///
    /// v0.5.0 改为 async（依据 proposal H3）：`on_event` 改为 async 后，broadcast 需 `.await`。
    pub async fn broadcast(&self, event: &BulwarkEvent) {
        for listener in &self.listeners {
            if let Err(e) = listener.on_event(event).await {
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

    #[async_trait]
    impl BulwarkListener for OkListener {
        async fn on_event(&self, _event: &BulwarkEvent) -> BulwarkResult<()> {
            EVENT_CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    /// 失败监听器，on_event 返回 Err。
    struct ErrListener;

    #[async_trait]
    impl BulwarkListener for ErrListener {
        async fn on_event(&self, _event: &BulwarkEvent) -> BulwarkResult<()> {
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

    /// PermissionCheck 事件携带被校验权限（spec Scenario，v0.5.0 重命名）。
    #[test]
    #[serial]
    fn permission_check_event_carries_permission() {
        let event = BulwarkEvent::PermissionCheck {
            login_id: 1001,
            permission: "user:delete".to_string(),
        };
        match event {
            BulwarkEvent::PermissionCheck {
                login_id,
                permission,
            } => {
                assert_eq!(login_id, 1001);
                assert_eq!(permission, "user:delete");
            },
            _ => panic!("期望 PermissionCheck 事件"),
        }
    }

    /// RoleCheck 事件携带被校验角色（spec Scenario，v0.5.0 重命名）。
    #[test]
    #[serial]
    fn role_check_event_carries_role() {
        let event = BulwarkEvent::RoleCheck {
            login_id: 1001,
            role: "admin".to_string(),
        };
        match event {
            BulwarkEvent::RoleCheck { login_id, role } => {
                assert_eq!(login_id, 1001);
                assert_eq!(role, "admin");
            },
            _ => panic!("期望 RoleCheck 事件"),
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
    // T075-T076: BulwarkEvent 14 变体（spec R-audit-log-005）
    // ========================================================================

    /// T075 Red: 验证 `BulwarkEvent` 含 spec R-audit-log-005 要求的 14 个变体。
    ///
    /// spec 要求变体：`Login`/`Logout`/`Kickout`/`LoginFailure`/`RevokeToken`/
    /// `PermissionCheck`/`RoleCheck`/`TokenRefresh`/`TokenRotate`/`SocialLogin`/
    /// `TenantSwitch`/`DeviceBlock`/`DeviceUnblock`/`ConfigReload`。
    ///
    /// Rule 7 冲突暴露（kueiku Decision Matrix 分析结论：方案 C，不向后兼容）：
    /// - 现有 `TokenRevoke`/`PermissionDenied`/`RoleDenied`/`ApiKeyRotate` 语义与 spec 重复但名称不同
    /// - 用户决策："不向后兼容" → 重命名对齐 spec
    /// - 现有独有变体（`TokenExpired`/`SessionTimeout`/`AccountLocked`/`FirewallBlock`/`TempCredentialConsumed`）保留
    ///   （功能完整：暴力破解检测/会话超时/防火墙阻断等关键安全事件不能丢失）
    /// - 最终变体数 19（spec 14 + 现有独有 5）
    #[test]
    #[serial]
    fn bulwark_event_includes_14_variants() {
        // 1. Login
        let e = BulwarkEvent::Login {
            login_id: 1,
            token: "t".into(),
            device: None,
        };
        assert!(matches!(e, BulwarkEvent::Login { .. }));

        // 2. Logout
        let e = BulwarkEvent::Logout {
            login_id: 1,
            token: "t".into(),
        };
        assert!(matches!(e, BulwarkEvent::Logout { .. }));

        // 3. Kickout
        let e = BulwarkEvent::Kickout {
            login_id: 1,
            token: "t".into(),
            reason: "r".into(),
        };
        assert!(matches!(e, BulwarkEvent::Kickout { .. }));

        // 4. LoginFailure
        let e = BulwarkEvent::LoginFailure {
            login_id: 1,
            reason: "r".into(),
        };
        assert!(matches!(e, BulwarkEvent::LoginFailure { .. }));

        // 5. RevokeToken（原 TokenRevoke 重命名）
        let e = BulwarkEvent::RevokeToken { token: "t".into() };
        assert!(matches!(e, BulwarkEvent::RevokeToken { .. }));

        // 6. PermissionCheck（原 PermissionDenied 重命名）
        let e = BulwarkEvent::PermissionCheck {
            login_id: 1,
            permission: "p".into(),
        };
        assert!(matches!(e, BulwarkEvent::PermissionCheck { .. }));

        // 7. RoleCheck（原 RoleDenied 重命名）
        let e = BulwarkEvent::RoleCheck {
            login_id: 1,
            role: "r".into(),
        };
        assert!(matches!(e, BulwarkEvent::RoleCheck { .. }));

        // 8. TokenRefresh（保留现有字段）
        let e = BulwarkEvent::TokenRefresh {
            login_id: 1,
            old_token: "t1".into(),
            new_token: "t2".into(),
        };
        assert!(matches!(e, BulwarkEvent::TokenRefresh { .. }));

        // 9. TokenRotate（原 ApiKeyRotate 重命名）
        let e = BulwarkEvent::TokenRotate {
            old_key: "k1".into(),
            new_key: "k2".into(),
        };
        assert!(matches!(e, BulwarkEvent::TokenRotate { .. }));

        // 10. SocialLogin（新增）
        let e = BulwarkEvent::SocialLogin {
            provider: "wechat".into(),
            user_id: "u".into(),
            login_id: Some(1),
        };
        assert!(matches!(e, BulwarkEvent::SocialLogin { .. }));

        // 11. TenantSwitch（新增）
        let e = BulwarkEvent::TenantSwitch {
            login_id: 1,
            from_tenant: 100,
            to_tenant: 200,
        };
        assert!(matches!(e, BulwarkEvent::TenantSwitch { .. }));

        // 12. DeviceBlock（新增）
        let e = BulwarkEvent::DeviceBlock {
            login_id: 1,
            device: "d".into(),
        };
        assert!(matches!(e, BulwarkEvent::DeviceBlock { .. }));

        // 13. DeviceUnblock（新增）
        let e = BulwarkEvent::DeviceUnblock {
            login_id: 1,
            device: "d".into(),
        };
        assert!(matches!(e, BulwarkEvent::DeviceUnblock { .. }));

        // 14. ConfigReload（新增）
        let e = BulwarkEvent::ConfigReload { config_version: 1 };
        assert!(matches!(e, BulwarkEvent::ConfigReload { .. }));
    }

    // ========================================================================
    // BulwarkListener trait 测试（依据 spec listener-system）
    // ========================================================================

    /// 默认 on_event 返回 Ok(())（spec Scenario：监听器需实现 on_event 方法）。
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn default_on_event_returns_ok() {
        struct EmptyListener;
        #[async_trait]
        impl BulwarkListener for EmptyListener {}
        let listener = EmptyListener;
        let event = BulwarkEvent::Login {
            login_id: 1,
            token: "t".to_string(),
            device: None,
        };
        assert!(listener.on_event(&event).await.is_ok());
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
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn broadcast_invokes_all_listeners() {
        reset_counters();
        let manager = BulwarkListenerManager::new();
        let event = BulwarkEvent::Login {
            login_id: 1001,
            token: "T1".to_string(),
            device: Some("web".to_string()),
        };
        manager.broadcast(&event).await;
        // OkListener 的 on_event 应被调用至少 1 次
        assert!(EVENT_CALLS.load(Ordering::SeqCst) >= 1);
    }

    /// 单个监听器失败不中断广播（spec Scenario）。
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn broadcast_listener_failure_does_not_interrupt() {
        reset_counters();
        let manager = BulwarkListenerManager::new();
        let event = BulwarkEvent::Logout {
            login_id: 1001,
            token: "T1".to_string(),
        };
        manager.broadcast(&event).await;
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

    /// 验证 broadcast 对 PermissionCheck 事件正确分发（v0.5.0 重命名）。
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn broadcast_permission_check_event() {
        reset_counters();
        let manager = BulwarkListenerManager::new();
        let event = BulwarkEvent::PermissionCheck {
            login_id: 1001,
            permission: "user:delete".to_string(),
        };
        manager.broadcast(&event).await;
        assert!(EVENT_CALLS.load(Ordering::SeqCst) >= 1);
    }

    /// 验证 broadcast 对 RoleCheck 事件正确分发（v0.5.0 重命名）。
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn broadcast_role_check_event() {
        reset_counters();
        let manager = BulwarkListenerManager::new();
        let event = BulwarkEvent::RoleCheck {
            login_id: 1001,
            role: "admin".to_string(),
        };
        manager.broadcast(&event).await;
        assert!(EVENT_CALLS.load(Ordering::SeqCst) >= 1);
    }

    /// 验证 broadcast 对 TokenExpired 事件正确分发。
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn broadcast_token_expired_event() {
        reset_counters();
        let manager = BulwarkListenerManager::new();
        let event = BulwarkEvent::TokenExpired {
            token: "expired-token".to_string(),
        };
        manager.broadcast(&event).await;
        assert!(EVENT_CALLS.load(Ordering::SeqCst) >= 1);
    }

    /// 验证 broadcast 对 Kickout 事件正确分发。
    #[tokio::test(flavor = "multi_thread")]
    #[serial]
    async fn broadcast_kickout_event() {
        reset_counters();
        let manager = BulwarkListenerManager::new();
        let event = BulwarkEvent::Kickout {
            login_id: 1001,
            token: "t1".to_string(),
            reason: "强制下线".to_string(),
        };
        manager.broadcast(&event).await;
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

    /// RevokeToken 事件携带 token，派生 Debug/Clone/PartialEq
    /// （v0.5.0 重命名：原 TokenRevoke → RevokeToken，依据 spec R-audit-log-005）。
    #[test]
    #[serial]
    fn revoke_token_event_carries_token() {
        let event = BulwarkEvent::RevokeToken {
            token: "revoke-tok".to_string(),
        };
        match event.clone() {
            BulwarkEvent::RevokeToken { token } => {
                assert_eq!(token, "revoke-tok");
            },
            _ => panic!("期望 RevokeToken 事件"),
        }
        let cloned = event.clone();
        assert_eq!(event, cloned);
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("RevokeToken"));
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

    /// TokenRotate 事件携带 old_key/new_key，派生 Debug/Clone/PartialEq
    /// （v0.5.0 重命名：原 ApiKeyRotate → TokenRotate，依据 spec R-audit-log-005）。
    #[test]
    #[serial]
    fn token_rotate_event_carries_keys() {
        let event = BulwarkEvent::TokenRotate {
            old_key: "old-key".to_string(),
            new_key: "new-key".to_string(),
        };
        match event.clone() {
            BulwarkEvent::TokenRotate { old_key, new_key } => {
                assert_eq!(old_key, "old-key");
                assert_eq!(new_key, "new-key");
            },
            _ => panic!("期望 TokenRotate 事件"),
        }
        let cloned = event.clone();
        assert_eq!(event, cloned);
        let debug_str = format!("{:?}", event);
        assert!(debug_str.contains("TokenRotate"));
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
}
