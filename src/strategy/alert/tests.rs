// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! strategy/alert 模块测试（从 mod.rs 迁移）。

use super::*;
use std::sync::atomic::{AtomicUsize, Ordering};

// ========================================================================
// SecurityAlertEvent 枚举构造测试
// ========================================================================

/// AnomalyLogin 事件能正确构造并携带字段。
#[test]
fn anomaly_login_event_constructs() {
    let event = SecurityAlertEvent::AnomalyLogin {
        login_id: "1001".to_string(),
        anomaly_type: AnomalyType::IpChanged,
        detail: "IP 从 1.2.3.4 变为 5.6.7.8".to_string(),
        trace_id: "trace-001".to_string(),
    };
    match event {
        SecurityAlertEvent::AnomalyLogin {
            login_id,
            anomaly_type,
            detail,
            trace_id,
        } => {
            assert_eq!(login_id, "1001");
            assert_eq!(anomaly_type, AnomalyType::IpChanged);
            assert_eq!(detail, "IP 从 1.2.3.4 变为 5.6.7.8");
            assert_eq!(trace_id, "trace-001");
        },
        _ => panic!("期望 AnomalyLogin 事件"),
    }
}

/// NewDeviceLogin 事件能正确构造并携带字段。
#[test]
fn new_device_login_event_constructs() {
    let event = SecurityAlertEvent::NewDeviceLogin {
        login_id: "1001".to_string(),
        device_id: "dev-001".to_string(),
        ip: Some("1.2.3.4".to_string()),
    };
    match event {
        SecurityAlertEvent::NewDeviceLogin {
            login_id,
            device_id,
            ip,
        } => {
            assert_eq!(login_id, "1001");
            assert_eq!(device_id, "dev-001");
            assert_eq!(ip, Some("1.2.3.4".to_string()));
        },
        _ => panic!("期望 NewDeviceLogin 事件"),
    }
}

/// DisableTriggered 事件能正确构造并携带字段。
#[test]
fn disable_triggered_event_constructs() {
    let event = SecurityAlertEvent::DisableTriggered {
        login_id: "1001".to_string(),
        service: "default".to_string(),
        level: 2,
    };
    match event {
        SecurityAlertEvent::DisableTriggered {
            login_id,
            service,
            level,
        } => {
            assert_eq!(login_id, "1001");
            assert_eq!(service, "default");
            assert_eq!(level, 2);
        },
        _ => panic!("期望 DisableTriggered 事件"),
    }
}

/// PrivilegeEscalation 事件能正确构造并携带字段。
#[test]
fn privilege_escalation_event_constructs() {
    let event = SecurityAlertEvent::PrivilegeEscalation {
        login_id: "1001".to_string(),
        old_roles: vec!["user".to_string()],
        new_roles: vec!["admin".to_string(), "user".to_string()],
    };
    match event {
        SecurityAlertEvent::PrivilegeEscalation {
            login_id,
            old_roles,
            new_roles,
        } => {
            assert_eq!(login_id, "1001");
            assert_eq!(old_roles, vec!["user".to_string()]);
            assert_eq!(new_roles, vec!["admin".to_string(), "user".to_string()]);
        },
        _ => panic!("期望 PrivilegeEscalation 事件"),
    }
}

/// SensitiveOperation 事件能正确构造并携带字段。
#[test]
fn sensitive_operation_event_constructs() {
    let event = SecurityAlertEvent::SensitiveOperation {
        login_id: "1001".to_string(),
        operation: "delete".to_string(),
        resource: "user:1002".to_string(),
    };
    match event {
        SecurityAlertEvent::SensitiveOperation {
            login_id,
            operation,
            resource,
        } => {
            assert_eq!(login_id, "1001");
            assert_eq!(operation, "delete");
            assert_eq!(resource, "user:1002");
        },
        _ => panic!("期望 SensitiveOperation 事件"),
    }
}

// ========================================================================
// AnomalyType 枚举相等性比较测试
// ========================================================================

/// AnomalyType 各变体相等性比较正确。
#[test]
fn anomaly_type_equality() {
    assert_eq!(AnomalyType::IpChanged, AnomalyType::IpChanged);
    assert_eq!(AnomalyType::DeviceChanged, AnomalyType::DeviceChanged);
    assert_eq!(AnomalyType::GeoJump, AnomalyType::GeoJump);
    assert_eq!(
        AnomalyType::RapidSuccessiveLogin,
        AnomalyType::RapidSuccessiveLogin
    );
    assert_ne!(AnomalyType::IpChanged, AnomalyType::DeviceChanged);
    assert_ne!(AnomalyType::GeoJump, AnomalyType::RapidSuccessiveLogin);
}

// ========================================================================
// AlertListenerManager 测试
// ========================================================================

/// new() 创建空管理器，count 为 0。
#[test]
fn new_creates_empty_manager() {
    let manager = AlertListenerManager::new();
    assert_eq!(manager.count(), 0, "新创建的 manager 应为空");
}

/// add_listener 后 count 增加。
#[test]
fn add_listener_increases_count() {
    let manager = AlertListenerManager::new();
    struct NoopListener;
    #[async_trait]
    impl AlertListener for NoopListener {}
    manager.add_listener(Arc::new(NoopListener));
    assert_eq!(manager.count(), 1, "添加 1 个 listener 后 count 应为 1");
    manager.add_listener(Arc::new(NoopListener));
    assert_eq!(manager.count(), 2, "添加 2 个 listener 后 count 应为 2");
}

/// broadcast_alert 空 manager 不报错。
#[tokio::test]
async fn broadcast_alert_empty_manager_no_error() {
    let manager = AlertListenerManager::new();
    let event = SecurityAlertEvent::AnomalyLogin {
        login_id: "1001".to_string(),
        anomaly_type: AnomalyType::IpChanged,
        detail: "test".to_string(),
        trace_id: "t1".to_string(),
    };
    // 空 manager 广播应正常完成不 panic
    manager.broadcast_alert(&event).await;
}

/// broadcast_alert 调用所有 listener 的 on_alert。
#[tokio::test]
async fn broadcast_alert_invokes_all_listeners() {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    CALLS.store(0, Ordering::SeqCst);

    struct CountingListener;
    #[async_trait]
    impl AlertListener for CountingListener {
        async fn on_alert(&self, _event: &SecurityAlertEvent) -> GarrisonResult<()> {
            CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    let manager = AlertListenerManager::new();
    manager.add_listener(Arc::new(CountingListener));
    manager.add_listener(Arc::new(CountingListener));
    let event = SecurityAlertEvent::NewDeviceLogin {
        login_id: "1001".to_string(),
        device_id: "dev-1".to_string(),
        ip: None,
    };
    manager.broadcast_alert(&event).await;
    assert_eq!(CALLS.load(Ordering::SeqCst), 2, "两个 listener 都应被调用");
}

/// listener 失败时不中断广播（Err listener + Ok listener 都被调用）。
#[tokio::test]
async fn broadcast_alert_listener_failure_does_not_interrupt() {
    static OK_CALLS: AtomicUsize = AtomicUsize::new(0);
    static ERR_CALLS: AtomicUsize = AtomicUsize::new(0);
    OK_CALLS.store(0, Ordering::SeqCst);
    ERR_CALLS.store(0, Ordering::SeqCst);

    struct OkListener;
    #[async_trait]
    impl AlertListener for OkListener {
        async fn on_alert(&self, _event: &SecurityAlertEvent) -> GarrisonResult<()> {
            OK_CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    struct ErrListener;
    #[async_trait]
    impl AlertListener for ErrListener {
        async fn on_alert(&self, _event: &SecurityAlertEvent) -> GarrisonResult<()> {
            ERR_CALLS.fetch_add(1, Ordering::SeqCst);
            Err(crate::error::GarrisonError::Internal(
                "on_alert 失败".to_string(),
            ))
        }
    }

    let manager = AlertListenerManager::new();
    // Err listener 先注册，Ok listener 后注册，验证 Err 不中断后续广播
    manager.add_listener(Arc::new(ErrListener));
    manager.add_listener(Arc::new(OkListener));
    let event = SecurityAlertEvent::SensitiveOperation {
        login_id: "1001".to_string(),
        operation: "delete".to_string(),
        resource: "user:1002".to_string(),
    };
    manager.broadcast_alert(&event).await;
    assert_eq!(
        ERR_CALLS.load(Ordering::SeqCst),
        1,
        "ErrListener 应被调用 1 次"
    );
    assert_eq!(
        OK_CALLS.load(Ordering::SeqCst),
        1,
        "OkListener 应被调用 1 次（Err 不中断广播）"
    );
}

/// listener panic 行为覆盖（补测试断言）。
///
/// 当前 `broadcast_alert` 实现（manager_impl.rs）**无 catch_unwind/panic 恢复**：
/// listener 的 `on_alert` panic 会传播出 `broadcast_alert` 并中止广播循环，
/// 剩余 listener 不再被通知。本测试经 `tokio::spawn` 任务边界捕获 panic
/// （JoinError::is_panic），固化该行为：
/// 1. panic 确实传播出 `broadcast_alert`（会中断调用方）；
/// 2. 剩余 listener 计数为 0（未被通知）。
///
/// 该测试同时是行为哨兵：未来若为 `broadcast_alert` 引入 `catch_unwind`
/// （`AssertUnwindSafe`）恢复逻辑，应同步将断言改为
/// "panic 被捕获 + 剩余 listener 仍被通知"。
#[tokio::test]
async fn broadcast_alert_listener_panic_propagates_and_aborts_broadcast() {
    static PANIC_CALLS: AtomicUsize = AtomicUsize::new(0);
    static AFTER_CALLS: AtomicUsize = AtomicUsize::new(0);
    PANIC_CALLS.store(0, Ordering::SeqCst);
    AFTER_CALLS.store(0, Ordering::SeqCst);

    struct PanickingListener;
    #[async_trait]
    impl AlertListener for PanickingListener {
        async fn on_alert(&self, _event: &SecurityAlertEvent) -> GarrisonResult<()> {
            PANIC_CALLS.fetch_add(1, Ordering::SeqCst);
            panic!("listener on_alert panic");
        }
    }

    struct AfterListener;
    #[async_trait]
    impl AlertListener for AfterListener {
        async fn on_alert(&self, _event: &SecurityAlertEvent) -> GarrisonResult<()> {
            AFTER_CALLS.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
    }

    let manager = AlertListenerManager::new();
    // panic listener 先注册，AfterListener 后注册（panic 后不应被通知）
    manager.add_listener(Arc::new(PanickingListener));
    manager.add_listener(Arc::new(AfterListener));
    let event = SecurityAlertEvent::SensitiveOperation {
        login_id: "1001".to_string(),
        operation: "delete".to_string(),
        resource: "user:1002".to_string(),
    };

    // 经 tokio::spawn 运行广播：panic 被任务边界捕获为 JoinError，便于断言
    let handle = tokio::spawn(async move { manager.broadcast_alert(&event).await });
    let joined = handle.await;
    assert!(
        matches!(&joined, Err(e) if e.is_panic()),
        "listener panic 应传播出 broadcast_alert（当前实现无 panic 恢复），实际: {:?}",
        joined
    );
    assert_eq!(
        PANIC_CALLS.load(Ordering::SeqCst),
        1,
        "panic listener 应被调用 1 次"
    );
    assert_eq!(
        AFTER_CALLS.load(Ordering::SeqCst),
        0,
        "panic 中止广播循环，剩余 listener 不被通知（固化当前行为）"
    );
}

/// Default trait 实现等价于 new()。
#[test]
fn default_equals_new() {
    let m1 = AlertListenerManager::new();
    let m2 = AlertListenerManager::default();
    assert_eq!(m1.count(), m2.count());
}
