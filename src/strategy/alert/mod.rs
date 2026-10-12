// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 安全告警系统模块，提供安全事件广播与异常检测抽象。
//!
//! 定义 `SecurityAlertEvent`（5 个安全事件变体）、`AnomalyType`（5 种异常类型）与两个 trait：
//! `AlertListener`（被动订阅事件）、`AnomalyDetector`（主动检测异常登录）。
//! `AlertListenerManager::broadcast_alert` 遍历 listener 调用 `on_alert`，单个失败仅 warn 不中断广播；仅在启用 `security-alert` 特性时编译。

/// 异常检测器实现模块。
pub mod detector;

/// 告警监听器实现模块。
pub mod listener;

#[cfg(feature = "session-hijack-detection")]
pub use detector::SessionHijackDetector;
pub use detector::{IpChangeDetector, RapidSuccessiveDetector};
pub use listener::{AuditAlertListener, TracingAlertListener};

use crate::error::GarrisonResult;
use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// 安全告警事件枚举，定义框架广播的所有安全事件变体。
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalyType {
    /// IP 地址变化。
    IpChanged,
    /// 设备指纹变化。
    DeviceChanged,
    /// 地理位置跳跃（短时间内跨地域的登录）。
    GeoJump,
    /// 快速连续登录（短时间内多次登录）。
    RapidSuccessiveLogin,
    /// 会话劫持疑似（当前请求 IP 与会话创建时存储的 IP 不一致）。
    SessionHijackSuspected,
}

/// 告警监听器 trait，提供安全事件订阅抽象；实现方按事件类型选择性处理，应快速返回或内部 spawn，避免阻塞广播主流程。
#[async_trait]
pub trait AlertListener: Send + Sync {
    /// 告警事件处理；默认空实现返回 `Ok(())`。
    async fn on_alert(&self, _event: &SecurityAlertEvent) -> GarrisonResult<()> {
        Ok(())
    }
}

/// 异常检测器 trait，定义登录场景下的异常检测契约：登录成功或 check_login 时调用，返回检测到的告警事件列表（空表示无异常）。
#[async_trait]
pub trait AnomalyDetector: Send + Sync {
    /// 登录成功时检测异常，返回告警事件列表（空表示无异常）。
    async fn check_on_login(
        &self,
        login_id: &str,
        device_id: &str,
        ip: Option<&str>,
    ) -> GarrisonResult<Vec<SecurityAlertEvent>>;

    /// check_login 时检测异常，返回告警事件列表（空表示无异常）。
    async fn check_on_check_login(
        &self,
        login_id: &str,
        token: &str,
    ) -> GarrisonResult<Vec<SecurityAlertEvent>>;
}

/// 告警监听器管理器：`RwLock` 保护监听器列表，支持运行时追加；
/// 广播时单个监听器失败仅记录 `tracing::warn!`，不中断。
pub struct AlertListenerManager {
    /// 已注册的告警监听器列表（`RwLock` 保护，支持运行时追加）。
    listeners: Arc<RwLock<Vec<Arc<dyn AlertListener>>>>,
}

mod manager_impl;

#[cfg(test)]
mod tests;
