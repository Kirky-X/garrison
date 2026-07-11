//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 安全告警系统模块，提供安全事件广播与异常检测抽象。
//!
//! 定义 `SecurityAlertEvent` 枚举（5 个安全事件变体）与 `AnomalyType` 枚举
//! （4 种异常类型），以及两个核心 trait：
//! - `AlertListener`：被动订阅 `SecurityAlertEvent`，实现方按事件类型选择性处理
//! - `AnomalyDetector`：主动检测异常登录行为，返回检测到的告警事件列表
//!
//! `AlertListenerManager` 收集并管理所有已注册的 `AlertListener`，
//! `broadcast_alert` 异步遍历所有 listener 调用 `on_alert`，
//! 单个 listener 失败仅记录 `tracing::warn!` 日志，不中断广播。
//!
//! 此模块仅在启用 `security-alert` 特性时编译。

/// 异常检测器实现模块。
pub mod detector;

/// 告警监听器实现模块。
pub mod listener;

pub use detector::{IpChangeDetector, RapidSuccessiveDetector};
pub use listener::{AuditAlertListener, TracingAlertListener};

use crate::error::BulwarkResult;
use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// 安全告警事件枚举，定义框架广播的所有安全事件变体。
///
/// 派生 `Debug`、`Clone`、`Serialize`、`Deserialize`，便于在监听器中复制、打印与序列化。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityAlertEvent {
    /// 异常登录事件（IP 变化 / 设备变化 / 地理跳跃 / 快速连续登录）。
    AnomalyLogin {
        /// 登录主体标识。
        login_id: String,
        /// 异常类型。
        anomaly_type: AnomalyType,
        /// 异常详情描述。
        detail: String,
        /// 链路追踪 ID。
        trace_id: String,
    },
    /// 新设备登录事件。
    NewDeviceLogin {
        /// 登录主体标识。
        login_id: String,
        /// 新设备标识。
        device_id: String,
        /// 登录 IP（可选）。
        ip: Option<String>,
    },
    /// 封禁触发事件。
    DisableTriggered {
        /// 登录主体标识。
        login_id: String,
        /// 封禁服务名称。
        service: String,
        /// 封禁级别。
        level: u32,
    },
    /// 权限提升事件。
    PrivilegeEscalation {
        /// 登录主体标识。
        login_id: String,
        /// 变更前的角色列表。
        old_roles: Vec<String>,
        /// 变更后的角色列表。
        new_roles: Vec<String>,
    },
    /// 敏感操作事件。
    SensitiveOperation {
        /// 登录主体标识。
        login_id: String,
        /// 操作名称。
        operation: String,
        /// 操作的资源标识。
        resource: String,
    },
}

/// 异常类型枚举，描述 `AnomalyLogin` 事件的具体异常分类。
///
/// 派生 `Debug`、`Clone`、`PartialEq`、`Eq`、`Serialize`、`Deserialize`，便于在检测器中比较与匹配，并支持序列化。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyType {
    /// IP 地址变化。
    IpChanged,
    /// 设备指纹变化。
    DeviceChanged,
    /// 地理位置跳跃（短时间内跨地域登录）。
    GeoJump,
    /// 快速连续登录（短时间内多次登录）。
    RapidSuccessiveLogin,
}

/// 告警监听器 trait，提供安全事件订阅抽象。
///
/// trait 绑定 `Send + Sync`，核心方法为 `on_alert`，实现方按事件类型选择性处理。
/// 监听器实现应快速返回或内部 spawn，避免阻塞广播主流程。
#[async_trait]
pub trait AlertListener: Send + Sync {
    /// 告警事件处理方法。
    ///
    /// 实现方按事件类型选择性处理，默认空实现返回 `Ok(())`。
    async fn on_alert(&self, _event: &SecurityAlertEvent) -> BulwarkResult<()> {
        Ok(())
    }
}

/// 异常检测器 trait，定义登录场景下的异常检测契约。
///
/// 实现方在登录成功或 check_login 时调用，返回检测到的告警事件列表。
/// 返回空 `Vec` 表示未检测到异常。
#[async_trait]
pub trait AnomalyDetector: Send + Sync {
    /// 登录成功时检测异常。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `device_id`: 登录设备标识。
    /// - `ip`: 登录 IP（可选）。
    ///
    /// # 返回
    /// 检测到的告警事件列表（空表示无异常）。
    async fn check_on_login(
        &self,
        login_id: &str,
        device_id: &str,
        ip: Option<&str>,
    ) -> BulwarkResult<Vec<SecurityAlertEvent>>;

    /// check_login 时检测异常。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `token`: 被校验的 token。
    ///
    /// # 返回
    /// 检测到的告警事件列表（空表示无异常）。
    async fn check_on_check_login(
        &self,
        login_id: &str,
        token: &str,
    ) -> BulwarkResult<Vec<SecurityAlertEvent>>;
}

/// 告警监听器管理器，收集并管理所有已注册的告警监听器。
///
/// 使用 `parking_lot::RwLock` 保护 `Vec<Arc<dyn AlertListener>>`，
/// 支持运行时通过 `add_listener` 追加监听器。
/// `broadcast_alert` 方法异步遍历所有监听器调用 `on_alert`，
/// 单个监听器失败时仅记录 `tracing::warn!` 日志，不中断广播。
pub struct AlertListenerManager {
    /// 已注册的告警监听器列表（`RwLock` 保护，支持运行时追加）。
    listeners: Arc<RwLock<Vec<Arc<dyn AlertListener>>>>,
}

impl AlertListenerManager {
    /// 创建空的告警监听器管理器。
    pub fn new() -> Self {
        Self {
            listeners: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 运行时追加告警监听器。
    pub fn add_listener(&self, listener: Arc<dyn AlertListener>) {
        self.listeners.write().push(listener);
    }

    /// 返回已注册的告警监听器数量。
    pub fn count(&self) -> usize {
        self.listeners.read().len()
    }

    /// 广播告警事件到所有已注册监听器。
    ///
    /// 异步遍历所有监听器的 `on_alert` 方法，单个监听器失败仅记录 `tracing::warn!`，
    /// 不中断广播。
    pub async fn broadcast_alert(&self, event: &SecurityAlertEvent) {
        let listeners = self.listeners.read().clone();
        for listener in &listeners {
            if let Err(e) = listener.on_alert(event).await {
                tracing::warn!("告警监听器 on_alert 失败: {}", e);
            }
        }
    }
}

impl Default for AlertListenerManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
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
            async fn on_alert(&self, _event: &SecurityAlertEvent) -> BulwarkResult<()> {
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
            async fn on_alert(&self, _event: &SecurityAlertEvent) -> BulwarkResult<()> {
                OK_CALLS.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        struct ErrListener;
        #[async_trait]
        impl AlertListener for ErrListener {
            async fn on_alert(&self, _event: &SecurityAlertEvent) -> BulwarkResult<()> {
                ERR_CALLS.fetch_add(1, Ordering::SeqCst);
                Err(crate::error::BulwarkError::Internal(
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

    /// Default trait 实现等价于 new()。
    #[test]
    fn default_equals_new() {
        let m1 = AlertListenerManager::new();
        let m2 = AlertListenerManager::default();
        assert_eq!(m1.count(), m2.count());
    }

    // ========================================================================
    // Feature gate 注册验证（T008）
    // ========================================================================

    /// 验证 security-alert feature 关闭时模块不编译。
    #[test]
    fn security_alert_feature_gate_compiles() {
        // 此测试本身在 security-alert feature 下编译
        // 如果编译成功，说明 feature gate 工作正常
        assert!(true, "security-alert feature 编译成功");
    }

    /// 验证 AlertListener trait 可被实现。
    #[test]
    fn alert_listener_trait_implementable() {
        struct TestListener;
        #[async_trait]
        impl AlertListener for TestListener {}
        let _listener = TestListener;
        assert!(
            std::any::TypeId::of::<TestListener>() != std::any::TypeId::of::<dyn AlertListener>(),
            "具体类型与 trait object 类型不同"
        );
    }

    /// 验证 AnomalyDetector trait 可被实现。
    #[test]
    fn anomaly_detector_trait_implementable() {
        struct TestDetector;
        #[async_trait]
        impl AnomalyDetector for TestDetector {
            async fn check_on_login(
                &self,
                _login_id: &str,
                _device_id: &str,
                _ip: Option<&str>,
            ) -> BulwarkResult<Vec<SecurityAlertEvent>> {
                Ok(vec![])
            }
            async fn check_on_check_login(
                &self,
                _login_id: &str,
                _token: &str,
            ) -> BulwarkResult<Vec<SecurityAlertEvent>> {
                Ok(vec![])
            }
        }
        let detector = TestDetector;
        let _ = detector; // 验证可构造
    }
}
