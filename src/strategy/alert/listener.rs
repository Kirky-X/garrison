//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 告警监听器实现模块，提供基于 `tracing` 的默认告警监听器。

use crate::error::BulwarkResult;
use async_trait::async_trait;

use super::{AlertListener, SecurityAlertEvent};

#[cfg(test)]
use super::AnomalyType;

/// 基于 `tracing` 的告警监听器，将告警事件记录到日志。
///
/// 这是默认的告警监听器实现，通过 `tracing::warn!` 记录所有安全告警事件。
/// 业务方可实现 `AlertListener` trait 替换为其他处理方式（如写入数据库、发送 web-hook）。
#[derive(Debug, Default)]
pub struct TracingAlertListener;

impl TracingAlertListener {
    /// 创建一个新的 `TracingAlertListener` 实例。
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl AlertListener for TracingAlertListener {
    async fn on_alert(&self, event: &SecurityAlertEvent) -> BulwarkResult<()> {
        match event {
            SecurityAlertEvent::AnomalyLogin {
                login_id,
                anomaly_type,
                detail,
                trace_id,
            } => {
                tracing::warn!(
                    login_id = %login_id,
                    anomaly_type = ?anomaly_type,
                    detail = %detail,
                    trace_id = %trace_id,
                    "异常登录告警"
                );
            },
            SecurityAlertEvent::NewDeviceLogin {
                login_id,
                device_id,
                ip,
            } => {
                tracing::warn!(
                    login_id = %login_id,
                    device_id = %device_id,
                    ip = ?ip,
                    "新设备登录告警"
                );
            },
            SecurityAlertEvent::DisableTriggered {
                login_id,
                service,
                level,
            } => {
                tracing::warn!(
                    login_id = %login_id,
                    service = %service,
                    level = level,
                    "封禁触发告警"
                );
            },
            SecurityAlertEvent::PrivilegeEscalation {
                login_id,
                old_roles,
                new_roles,
            } => {
                tracing::warn!(
                    login_id = %login_id,
                    old_roles = ?old_roles,
                    new_roles = ?new_roles,
                    "权限提升告警"
                );
            },
            SecurityAlertEvent::SensitiveOperation {
                login_id,
                operation,
                resource,
            } => {
                tracing::warn!(
                    login_id = %login_id,
                    operation = %operation,
                    resource = %resource,
                    "敏感操作告警"
                );
            },
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // TracingAlertListener 构造测试
    // ========================================================================

    /// `new()` 返回 `TracingAlertListener` 实例。
    #[test]
    fn tracing_alert_listener_new_returns_instance() {
        let _listener = TracingAlertListener::new();
        // 构造成功即通过（无字段可断言）
    }

    /// `Default::default()` 返回 `TracingAlertListener` 实例。
    #[test]
    fn tracing_alert_listener_default_returns_instance() {
        let _listener = TracingAlertListener::default();
        // 构造成功即通过（无字段可断言）
    }

    // ========================================================================
    // on_alert 各变体返回 Ok 测试
    // ========================================================================

    /// `on_alert` 处理 `AnomalyLogin` 事件返回 `Ok(())`。
    #[tokio::test]
    async fn on_alert_anomaly_login_returns_ok() {
        let listener = TracingAlertListener::new();
        let event = SecurityAlertEvent::AnomalyLogin {
            login_id: "1001".to_string(),
            anomaly_type: AnomalyType::IpChanged,
            detail: "IP 从 1.2.3.4 变为 5.6.7.8".to_string(),
            trace_id: "trace-001".to_string(),
        };
        let result = listener.on_alert(&event).await;
        assert!(result.is_ok(), "AnomalyLogin 事件应返回 Ok");
    }

    /// `on_alert` 处理 `NewDeviceLogin` 事件返回 `Ok(())`。
    #[tokio::test]
    async fn on_alert_new_device_login_returns_ok() {
        let listener = TracingAlertListener::new();
        let event = SecurityAlertEvent::NewDeviceLogin {
            login_id: "1001".to_string(),
            device_id: "dev-001".to_string(),
            ip: Some("1.2.3.4".to_string()),
        };
        let result = listener.on_alert(&event).await;
        assert!(result.is_ok(), "NewDeviceLogin 事件应返回 Ok");
    }

    /// `on_alert` 处理 `DisableTriggered` 事件返回 `Ok(())`。
    #[tokio::test]
    async fn on_alert_disable_triggered_returns_ok() {
        let listener = TracingAlertListener::new();
        let event = SecurityAlertEvent::DisableTriggered {
            login_id: "1001".to_string(),
            service: "default".to_string(),
            level: 2,
        };
        let result = listener.on_alert(&event).await;
        assert!(result.is_ok(), "DisableTriggered 事件应返回 Ok");
    }

    /// `on_alert` 处理 `PrivilegeEscalation` 事件返回 `Ok(())`。
    #[tokio::test]
    async fn on_alert_privilege_escalation_returns_ok() {
        let listener = TracingAlertListener::new();
        let event = SecurityAlertEvent::PrivilegeEscalation {
            login_id: "1001".to_string(),
            old_roles: vec!["user".to_string()],
            new_roles: vec!["admin".to_string(), "user".to_string()],
        };
        let result = listener.on_alert(&event).await;
        assert!(result.is_ok(), "PrivilegeEscalation 事件应返回 Ok");
    }

    /// `on_alert` 处理 `SensitiveOperation` 事件返回 `Ok(())`。
    #[tokio::test]
    async fn on_alert_sensitive_operation_returns_ok() {
        let listener = TracingAlertListener::new();
        let event = SecurityAlertEvent::SensitiveOperation {
            login_id: "1001".to_string(),
            operation: "delete".to_string(),
            resource: "user:1002".to_string(),
        };
        let result = listener.on_alert(&event).await;
        assert!(result.is_ok(), "SensitiveOperation 事件应返回 Ok");
    }

    /// 遍历所有事件变体调用 `on_alert`，确保不 panic。
    #[tokio::test]
    async fn on_alert_all_variants_no_panic() {
        let listener = TracingAlertListener::new();
        let events = vec![
            SecurityAlertEvent::AnomalyLogin {
                login_id: "1001".to_string(),
                anomaly_type: AnomalyType::IpChanged,
                detail: "IP 变化".to_string(),
                trace_id: "t1".to_string(),
            },
            SecurityAlertEvent::NewDeviceLogin {
                login_id: "1001".to_string(),
                device_id: "dev-1".to_string(),
                ip: None,
            },
            SecurityAlertEvent::DisableTriggered {
                login_id: "1001".to_string(),
                service: "default".to_string(),
                level: 1,
            },
            SecurityAlertEvent::PrivilegeEscalation {
                login_id: "1001".to_string(),
                old_roles: vec![],
                new_roles: vec!["admin".to_string()],
            },
            SecurityAlertEvent::SensitiveOperation {
                login_id: "1001".to_string(),
                operation: "delete".to_string(),
                resource: "user:1002".to_string(),
            },
        ];
        for event in &events {
            // 每个变体调用 on_alert 不应 panic
            let _ = listener.on_alert(event).await;
        }
    }
}
