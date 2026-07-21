//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! listener 模块测试（从 mod.rs 迁移，Rule 25 合规）。

use super::mock::{reset_counters, EVENT_CALLS};
use super::*;
use serial_test::serial;
use std::sync::atomic::Ordering;

// ========================================================================
// GarrisonEvent 枚举测试
// ========================================================================

/// Login 事件携带 login_id、token 与 device（spec Scenario）。
#[test]
#[serial]
fn login_event_carries_login_id_token_device() {
    let event = GarrisonEvent::Login {
        login_id: "1001".to_string(),
        token: "T1".to_string(),
        device: Some("web".to_string()),
        request_context: None,
    };
    match event {
        GarrisonEvent::Login {
            login_id,
            token,
            device,
            ..
        } => {
            assert_eq!(login_id, "1001".to_string());
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
    let event = GarrisonEvent::Logout {
        login_id: "1001".to_string(),
        token: "T1".to_string(),
        request_context: None,
    };
    match event {
        GarrisonEvent::Logout {
            login_id, token, ..
        } => {
            assert_eq!(login_id, "1001".to_string());
            assert_eq!(token, "T1");
        },
        _ => panic!("期望 Logout 事件"),
    }
}

/// Kickout 事件携带踢出原因（spec Scenario）。
#[test]
#[serial]
fn kickout_event_carries_reason() {
    let event = GarrisonEvent::Kickout {
        login_id: "1001".to_string(),
        token: "T1".to_string(),
        reason: "管理员强制下线".to_string(),
        request_context: None,
    };
    match event {
        GarrisonEvent::Kickout {
            login_id,
            token,
            reason,
            ..
        } => {
            assert_eq!(login_id, "1001".to_string());
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
    let event = GarrisonEvent::PermissionCheck {
        login_id: "1001".to_string(),
        permission: "user:delete".to_string(),
        request_context: None,
    };
    match event {
        GarrisonEvent::PermissionCheck {
            login_id,
            permission,
            ..
        } => {
            assert_eq!(login_id, "1001".to_string());
            assert_eq!(permission, "user:delete");
        },
        _ => panic!("期望 PermissionCheck 事件"),
    }
}

/// RoleCheck 事件携带被校验角色（spec Scenario，v0.5.0 重命名）。
#[test]
#[serial]
fn role_check_event_carries_role() {
    let event = GarrisonEvent::RoleCheck {
        login_id: "1001".to_string(),
        role: "admin".to_string(),
        request_context: None,
    };
    match event {
        GarrisonEvent::RoleCheck { login_id, role, .. } => {
            assert_eq!(login_id, "1001".to_string());
            assert_eq!(role, "admin");
        },
        _ => panic!("期望 RoleCheck 事件"),
    }
}

/// TokenExpired 事件携带过期 token（spec Scenario）。
#[test]
#[serial]
fn token_expired_event_carries_token() {
    let event = GarrisonEvent::TokenExpired {
        token: "T1".to_string(),
        request_context: None,
    };
    match event {
        GarrisonEvent::TokenExpired { token, .. } => {
            assert_eq!(token, "T1");
        },
        _ => panic!("期望 TokenExpired 事件"),
    }
}

/// GarrisonEvent 派生 Debug 与 Clone（spec Requirement）。
#[test]
#[serial]
fn event_derives_debug_and_clone() {
    let event = GarrisonEvent::Login {
        login_id: "1001".to_string(),
        token: "T1".to_string(),
        device: None,
        request_context: None,
    };
    // Clone
    let cloned = event.clone();
    match cloned {
        GarrisonEvent::Login { login_id, .. } => assert_eq!(login_id, "1001".to_string()),
        _ => panic!("clone 后应为 Login"),
    }
    // Debug
    let debug_str = format!("{:?}", event);
    assert!(debug_str.contains("Login"));
}

// ========================================================================
// T075-GarrisonEvent 14 变体（spec R-audit-log-005）
// ========================================================================

/// T075 Red: 验证 `GarrisonEvent` 含 spec R-audit-log-005 要求的 14 个变体。
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
fn garrison_event_includes_14_variants() {
    // 1. Login
    let e = GarrisonEvent::Login {
        login_id: "1".to_string(),
        token: "t".into(),
        device: None,
        request_context: None,
    };
    assert!(matches!(e, GarrisonEvent::Login { .. }));

    // 2. Logout
    let e = GarrisonEvent::Logout {
        login_id: "1".to_string(),
        token: "t".into(),
        request_context: None,
    };
    assert!(matches!(e, GarrisonEvent::Logout { .. }));

    // 3. Kickout
    let e = GarrisonEvent::Kickout {
        login_id: "1".to_string(),
        token: "t".into(),
        reason: "r".into(),
        request_context: None,
    };
    assert!(matches!(e, GarrisonEvent::Kickout { .. }));

    // 4. LoginFailure
    let e = GarrisonEvent::LoginFailure {
        login_id: "1".to_string(),
        reason: "r".into(),
        request_context: None,
    };
    assert!(matches!(e, GarrisonEvent::LoginFailure { .. }));

    // 5. RevokeToken（原 TokenRevoke 重命名）
    let e = GarrisonEvent::RevokeToken {
        token: "t".into(),
        request_context: None,
    };
    assert!(matches!(e, GarrisonEvent::RevokeToken { .. }));

    // 6. PermissionCheck（原 PermissionDenied 重命名）
    let e = GarrisonEvent::PermissionCheck {
        login_id: "1".to_string(),
        permission: "p".into(),
        request_context: None,
    };
    assert!(matches!(e, GarrisonEvent::PermissionCheck { .. }));

    // 7. RoleCheck（原 RoleDenied 重命名）
    let e = GarrisonEvent::RoleCheck {
        login_id: "1".to_string(),
        role: "r".into(),
        request_context: None,
    };
    assert!(matches!(e, GarrisonEvent::RoleCheck { .. }));

    // 8. TokenRefresh（保留现有字段）
    let e = GarrisonEvent::TokenRefresh {
        login_id: "1".to_string(),
        old_token: "t1".into(),
        new_token: "t2".into(),
        request_context: None,
    };
    assert!(matches!(e, GarrisonEvent::TokenRefresh { .. }));

    // 9. TokenRotate（原 ApiKeyRotate 重命名）
    let e = GarrisonEvent::TokenRotate {
        old_key: "k1".into(),
        new_key: "k2".into(),
        request_context: None,
    };
    assert!(matches!(e, GarrisonEvent::TokenRotate { .. }));

    // 10. SocialLogin（新增）
    let e = GarrisonEvent::SocialLogin {
        provider: "wechat".into(),
        user_id: "u".into(),
        login_id: Some("1".to_string()),
        request_context: None,
    };
    assert!(matches!(e, GarrisonEvent::SocialLogin { .. }));

    // 11. TenantSwitch（新增）
    let e = GarrisonEvent::TenantSwitch {
        login_id: "1".to_string(),
        from_tenant: 100,
        to_tenant: 200,
        request_context: None,
    };
    assert!(matches!(e, GarrisonEvent::TenantSwitch { .. }));

    // 12. DeviceBlock（新增）
    let e = GarrisonEvent::DeviceBlock {
        login_id: "1".to_string(),
        device: "d".into(),
        request_context: None,
    };
    assert!(matches!(e, GarrisonEvent::DeviceBlock { .. }));

    // 13. DeviceUnblock（新增）
    let e = GarrisonEvent::DeviceUnblock {
        login_id: "1".to_string(),
        device: "d".into(),
        request_context: None,
    };
    assert!(matches!(e, GarrisonEvent::DeviceUnblock { .. }));

    // 14. ConfigReload（新增）
    let e = GarrisonEvent::ConfigReload {
        config_version: 1,
        request_context: None,
    };
    assert!(matches!(e, GarrisonEvent::ConfigReload { .. }));
}

// ========================================================================
// GarrisonListener trait 测试
// ========================================================================

/// 默认 on_event 返回 Ok(())（spec Scenario：监听器需实现 on_event 方法）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn default_on_event_returns_ok() {
    struct EmptyListener;
    #[async_trait]
    impl GarrisonListener for EmptyListener {}
    let listener = EmptyListener;
    let event = GarrisonEvent::Login {
        login_id: "1".to_string(),
        token: "t".to_string(),
        device: None,
        request_context: None,
    };
    assert!(listener.on_event(&event).await.is_ok());
}

// ========================================================================
// GarrisonListenerManager 测试
// ========================================================================

/// manager 收集所有已注册监听器（spec Scenario）。
#[test]
#[serial]
fn manager_collects_registered_listeners() {
    let manager = GarrisonListenerManager::new();
    // 至少 2 个监听器（OkListener + ErrListener）
    assert!(manager.count() >= 2);
}

/// broadcast 调用所有监听器（spec Scenario）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn broadcast_invokes_all_listeners() {
    reset_counters();
    let manager = GarrisonListenerManager::new();
    let event = GarrisonEvent::Login {
        login_id: "1001".to_string(),
        token: "T1".to_string(),
        device: Some("web".to_string()),
        request_context: None,
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
    let manager = GarrisonListenerManager::new();
    let event = GarrisonEvent::Logout {
        login_id: "1001".to_string(),
        token: "T1".to_string(),
        request_context: None,
    };
    manager.broadcast(&event).await;
    // ErrListener 失败，但 OkListener 仍应被调用
    assert!(EVENT_CALLS.load(Ordering::SeqCst) >= 1);
}

/// Default trait 实现等价于 new()。
#[test]
#[serial]
fn default_equals_new() {
    let m1 = GarrisonListenerManager::new();
    let m2 = GarrisonListenerManager::default();
    assert_eq!(m1.count(), m2.count());
}

/// 验证 new() 在 tracing subscriber 已初始化时正确求值 info! 宏参数。
///
/// 覆盖 GarrisonListenerManager::new() 中 `tracing::info!` 宏的参数求值路径
/// （line 117: `std::any::type_name::<Arc<dyn GarrisonListener>>()`）。
/// tracing::info! 在无 subscriber 时短路不求值参数，需确保 subscriber 已设置。
#[test]
#[serial]
fn manager_new_with_tracing_subscriber() {
    // 确保 tracing subscriber 已初始化（幂等，已设置时返回 Err 被忽略）
    #[cfg(any(feature = "tracing-log", feature = "metrics-prometheus"))]
    {
        let _ = tracing_subscriber::fmt().try_init();
    }
    let manager = GarrisonListenerManager::new();
    assert!(manager.count() >= 2);
}

/// 验证 broadcast 对 PermissionCheck 事件正确分发。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn broadcast_permission_check_event() {
    reset_counters();
    let manager = GarrisonListenerManager::new();
    let event = GarrisonEvent::PermissionCheck {
        login_id: "1001".to_string(),
        permission: "user:delete".to_string(),
        request_context: None,
    };
    manager.broadcast(&event).await;
    assert!(EVENT_CALLS.load(Ordering::SeqCst) >= 1);
}

/// 验证 broadcast 对 RoleCheck 事件正确分发。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn broadcast_role_check_event() {
    reset_counters();
    let manager = GarrisonListenerManager::new();
    let event = GarrisonEvent::RoleCheck {
        login_id: "1001".to_string(),
        role: "admin".to_string(),
        request_context: None,
    };
    manager.broadcast(&event).await;
    assert!(EVENT_CALLS.load(Ordering::SeqCst) >= 1);
}

/// 验证 broadcast 对 TokenExpired 事件正确分发。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn broadcast_token_expired_event() {
    reset_counters();
    let manager = GarrisonListenerManager::new();
    let event = GarrisonEvent::TokenExpired {
        token: "expired-token".to_string(),
        request_context: None,
    };
    manager.broadcast(&event).await;
    assert!(EVENT_CALLS.load(Ordering::SeqCst) >= 1);
}

/// 验证 broadcast 对 Kickout 事件正确分发。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn broadcast_kickout_event() {
    reset_counters();
    let manager = GarrisonListenerManager::new();
    let event = GarrisonEvent::Kickout {
        login_id: "1001".to_string(),
        token: "t1".to_string(),
        reason: "强制下线".to_string(),
        request_context: None,
    };
    manager.broadcast(&event).await;
    assert!(EVENT_CALLS.load(Ordering::SeqCst) >= 1);
}

// ========================================================================
// 9 个新事件变体测试
// ========================================================================

/// LoginFailure 事件携带 login_id 与 reason，派生 Debug/Clone/PartialEq
#[test]
#[serial]
fn login_failure_event_carries_login_id_and_reason() {
    let event = GarrisonEvent::LoginFailure {
        login_id: "1001".to_string(),
        reason: "wrong_password".to_string(),
        request_context: None,
    };
    match event.clone() {
        GarrisonEvent::LoginFailure {
            login_id, reason, ..
        } => {
            assert_eq!(login_id, "1001".to_string());
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
#[test]
#[serial]
fn token_refresh_event_carries_tokens() {
    let event = GarrisonEvent::TokenRefresh {
        login_id: "1001".to_string(),
        old_token: "old-tok".to_string(),
        new_token: "new-tok".to_string(),
        request_context: None,
    };
    match event.clone() {
        GarrisonEvent::TokenRefresh {
            login_id,
            old_token,
            new_token,
            ..
        } => {
            assert_eq!(login_id, "1001".to_string());
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
#[test]
#[serial]
fn revoke_token_event_carries_token() {
    let event = GarrisonEvent::RevokeToken {
        token: "revoke-tok".to_string(),
        request_context: None,
    };
    match event.clone() {
        GarrisonEvent::RevokeToken { token, .. } => {
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
#[test]
#[serial]
fn session_timeout_event_carries_login_id_and_token() {
    let event = GarrisonEvent::SessionTimeout {
        login_id: "1001".to_string(),
        token: "expired-tok".to_string(),
        request_context: None,
    };
    match event.clone() {
        GarrisonEvent::SessionTimeout {
            login_id, token, ..
        } => {
            assert_eq!(login_id, "1001".to_string());
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
#[test]
#[serial]
fn account_locked_event_carries_login_id_and_reason() {
    let event = GarrisonEvent::AccountLocked {
        login_id: "1001".to_string(),
        reason: "brute_force".to_string(),
        request_context: None,
    };
    match event.clone() {
        GarrisonEvent::AccountLocked {
            login_id, reason, ..
        } => {
            assert_eq!(login_id, "1001".to_string());
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
#[test]
#[serial]
fn firewall_block_event_carries_login_id_and_reason() {
    let event = GarrisonEvent::FirewallBlock {
        login_id: "1001".to_string(),
        reason: "frequency_exceeded".to_string(),
        request_context: None,
    };
    match event.clone() {
        GarrisonEvent::FirewallBlock {
            login_id, reason, ..
        } => {
            assert_eq!(login_id, "1001".to_string());
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
#[test]
#[serial]
fn token_rotate_event_carries_keys() {
    let event = GarrisonEvent::TokenRotate {
        old_key: "old-key".to_string(),
        new_key: "new-key".to_string(),
        request_context: None,
    };
    match event.clone() {
        GarrisonEvent::TokenRotate {
            old_key, new_key, ..
        } => {
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
#[test]
#[serial]
fn temp_credential_consumed_event_carries_key_and_value() {
    let event = GarrisonEvent::TempCredentialConsumed {
        key: "invite-key".to_string(),
        value: "payload".to_string(),
        request_context: None,
    };
    match event.clone() {
        GarrisonEvent::TempCredentialConsumed { key, value, .. } => {
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
