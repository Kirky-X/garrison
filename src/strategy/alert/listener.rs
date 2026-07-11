//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 告警监听器实现模块，提供基于 `tracing` 的默认告警监听器与基于 DAO 的审计日志监听器。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use std::sync::Arc;

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

/// 审计日志告警监听器，将告警事件持久化到 DAO。
///
/// 将 `SecurityAlertEvent` 序列化为 JSON 写入 `BulwarkDao`，
/// key 格式 `audit:alert:{trace_id_or_uuid}`。
/// 用于安全告警的持久化审计追踪。
///
/// # 错误处理
///
/// 与 `TracingAlertListener` 不同，`on_alert` 写入 DAO 失败时返回 `Err`，
/// 由 [`AlertListenerManager::broadcast_alert`](crate::strategy::alert::AlertListenerManager::broadcast_alert)
/// 捕获并记录 `tracing::warn!` 日志。审计失败不会中断告警广播，但会在日志中显性记录。
/// 这确保了审计日志的持久化失败不会被完全静默吞掉，同时不阻断其他监听器的执行。
pub struct AuditAlertListener {
    /// DAO 实例，用于持久化审计日志条目。
    dao: Arc<dyn BulwarkDao>,
    /// 审计日志 TTL（秒），默认 86400（24 小时）。
    ttl_seconds: u64,
}

impl AuditAlertListener {
    /// 创建新的 `AuditAlertListener`，TTL 默认 86400 秒（24 小时）。
    ///
    /// # 参数
    /// - `dao`: DAO 实例（`Arc<dyn BulwarkDao>`），用于写入审计日志。
    pub fn new(dao: Arc<dyn BulwarkDao>) -> Self {
        Self {
            dao,
            ttl_seconds: 86_400,
        }
    }

    /// 创建新的 `AuditAlertListener`，指定自定义 TTL。
    ///
    /// # 参数
    /// - `dao`: DAO 实例（`Arc<dyn BulwarkDao>`）。
    /// - `ttl_seconds`: 审计日志存活秒数（0 表示永久驻留）。
    pub fn with_ttl(dao: Arc<dyn BulwarkDao>, ttl_seconds: u64) -> Self {
        Self { dao, ttl_seconds }
    }
}

#[async_trait]
impl AlertListener for AuditAlertListener {
    async fn on_alert(&self, event: &SecurityAlertEvent) -> BulwarkResult<()> {
        // AnomalyLogin 变体使用事件自带的 trace_id 作为 identifier，
        // 其他变体生成新的 UUID 作为 identifier。
        let identifier = match event {
            SecurityAlertEvent::AnomalyLogin { trace_id, .. } => trace_id.clone(),
            _ => uuid::Uuid::new_v4().to_string(),
        };
        let key = format!("audit:alert:{}", identifier);
        let json = serde_json::to_string(event).map_err(|e| {
            BulwarkError::Internal(format!("序列化 SecurityAlertEvent 为 JSON 失败: {}", e))
        })?;
        self.dao.set(&key, &json, self.ttl_seconds).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // on_alert 各变体返回 Ok 测试（验证 match 分支穷尽性 + 不 panic）
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

    // ========================================================================
    // AuditAlertListener 测试
    // ========================================================================

    /// `new()` 返回 `AuditAlertListener` 实例。
    #[test]
    fn audit_alert_listener_new_returns_instance() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(crate::dao::tests::MockDao::new());
        let _listener = AuditAlertListener::new(dao);
        // 构造成功即通过（无公共字段可直接断言）
    }

    /// `on_alert` 处理 `AnomalyLogin` 事件写入 DAO，key 包含 trace_id。
    #[tokio::test]
    async fn on_alert_anomaly_login_writes_to_dao() {
        let dao = Arc::new(crate::dao::tests::MockDao::new());
        let listener = AuditAlertListener::new(dao.clone());
        let event = SecurityAlertEvent::AnomalyLogin {
            login_id: "1001".to_string(),
            anomaly_type: AnomalyType::IpChanged,
            detail: "IP 从 1.2.3.4 变为 5.6.7.8".to_string(),
            trace_id: "trace-007".to_string(),
        };
        listener.on_alert(&event).await.unwrap();
        // AnomalyLogin 使用 trace_id 作为 key identifier
        let json = dao.get("audit:alert:trace-007").await.unwrap();
        assert!(
            json.is_some(),
            "AnomalyLogin 事件应写入 DAO（key 含 trace_id）"
        );
        let json = json.unwrap();
        assert!(json.contains("AnomalyLogin"), "JSON 应包含事件类型");
        assert!(json.contains("1001"), "JSON 应包含 login_id");
        assert!(json.contains("trace-007"), "JSON 应包含 trace_id");
        assert!(json.contains("IpChanged"), "JSON 应包含 anomaly_type");
    }

    /// `on_alert` 处理 `NewDeviceLogin` 事件写入 DAO。
    #[tokio::test]
    async fn on_alert_new_device_login_writes_to_dao() {
        let dao = Arc::new(crate::dao::tests::MockDao::new());
        let listener = AuditAlertListener::new(dao.clone());
        let event = SecurityAlertEvent::NewDeviceLogin {
            login_id: "1001".to_string(),
            device_id: "dev-001".to_string(),
            ip: Some("1.2.3.4".to_string()),
        };
        listener.on_alert(&event).await.unwrap();
        // NewDeviceLogin 使用 UUID 作为 key，通过 keys 扫描定位
        let keys = dao.keys("audit:alert:*").await.unwrap();
        assert_eq!(keys.len(), 1, "应写入 1 条审计日志");
        let json = dao.get(&keys[0]).await.unwrap();
        assert!(json.is_some(), "审计日志应存在");
        let json = json.unwrap();
        assert!(json.contains("NewDeviceLogin"), "JSON 应包含事件类型");
        assert!(json.contains("1001"), "JSON 应包含 login_id");
        assert!(json.contains("dev-001"), "JSON 应包含 device_id");
    }

    /// `on_alert` 处理 `DisableTriggered` 事件写入 DAO。
    #[tokio::test]
    async fn on_alert_disable_triggered_writes_to_dao() {
        let dao = Arc::new(crate::dao::tests::MockDao::new());
        let listener = AuditAlertListener::new(dao.clone());
        let event = SecurityAlertEvent::DisableTriggered {
            login_id: "1001".to_string(),
            service: "default".to_string(),
            level: 2,
        };
        listener.on_alert(&event).await.unwrap();
        let keys = dao.keys("audit:alert:*").await.unwrap();
        assert_eq!(keys.len(), 1, "应写入 1 条审计日志");
        let json = dao.get(&keys[0]).await.unwrap();
        assert!(json.is_some(), "审计日志应存在");
        let json = json.unwrap();
        assert!(json.contains("DisableTriggered"), "JSON 应包含事件类型");
        assert!(json.contains("1001"), "JSON 应包含 login_id");
        assert!(json.contains("default"), "JSON 应包含 service");
        assert!(json.contains("2"), "JSON 应包含 level");
    }

    /// `on_alert` 处理 `PrivilegeEscalation` 事件写入 DAO。
    #[tokio::test]
    async fn on_alert_privilege_escalation_writes_to_dao() {
        let dao = Arc::new(crate::dao::tests::MockDao::new());
        let listener = AuditAlertListener::new(dao.clone());
        let event = SecurityAlertEvent::PrivilegeEscalation {
            login_id: "1001".to_string(),
            old_roles: vec!["user".to_string()],
            new_roles: vec!["admin".to_string(), "user".to_string()],
        };
        listener.on_alert(&event).await.unwrap();
        let keys = dao.keys("audit:alert:*").await.unwrap();
        assert_eq!(keys.len(), 1, "应写入 1 条审计日志");
        let json = dao.get(&keys[0]).await.unwrap();
        assert!(json.is_some(), "审计日志应存在");
        let json = json.unwrap();
        assert!(json.contains("PrivilegeEscalation"), "JSON 应包含事件类型");
        assert!(json.contains("1001"), "JSON 应包含 login_id");
        assert!(json.contains("admin"), "JSON 应包含 new_roles 中的角色");
    }

    /// `on_alert` 处理 `SensitiveOperation` 事件写入 DAO。
    #[tokio::test]
    async fn on_alert_sensitive_operation_writes_to_dao() {
        let dao = Arc::new(crate::dao::tests::MockDao::new());
        let listener = AuditAlertListener::new(dao.clone());
        let event = SecurityAlertEvent::SensitiveOperation {
            login_id: "1001".to_string(),
            operation: "delete".to_string(),
            resource: "user:1002".to_string(),
        };
        listener.on_alert(&event).await.unwrap();
        let keys = dao.keys("audit:alert:*").await.unwrap();
        assert_eq!(keys.len(), 1, "应写入 1 条审计日志");
        let json = dao.get(&keys[0]).await.unwrap();
        assert!(json.is_some(), "审计日志应存在");
        let json = json.unwrap();
        assert!(json.contains("SensitiveOperation"), "JSON 应包含事件类型");
        assert!(json.contains("1001"), "JSON 应包含 login_id");
        assert!(json.contains("delete"), "JSON 应包含 operation");
        assert!(json.contains("user:1002"), "JSON 应包含 resource");
    }
}
