//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 宽松设备绑定策略实现。
//!
//! [`LooseBinding`] 实现 [`DeviceBindingPolicy`]（super::DeviceBindingPolicy）：
//! - `is_new_device`：同 [`StrictBinding`] 逻辑，遍历 `TokenSession.device` 字段
//! - `require_secondary_auth`：总是返回 `Ok(false)`（仅告警不阻断），并广播 `NewDeviceLogin` 事件
//!
//! 新设备时通过 [`AlertListenerManager::broadcast_alert`](crate::strategy::alert::AlertListenerManager::broadcast_alert) 广播
//! [`SecurityAlertEvent::NewDeviceLogin`](crate::strategy::alert::SecurityAlertEvent::NewDeviceLogin) 事件，业务方监听器可记录审计日志或
//! 触发风控流程，但登录主流程不被阻断。
//!
//! `AlertListenerManager` 为 `Option`，`None` 时跳过广播（向后兼容无告警系统场景）。
//!
//! # HIGH-001 修复
//!
//! `require_secondary_auth` 不再重复调用 `is_new_device`（调用方已先调用过，避免重复 DAO 查询）。
//! 调用方（`session.rs` login 流程）仅在 `is_new_device == true` 时才调用此方法，
//! 因此直接执行告警广播并返回 `Ok(false)`。

use crate::error::BulwarkResult;
use crate::session::BulwarkSession;
use crate::strategy::alert::{AlertListenerManager, SecurityAlertEvent};
use async_trait::async_trait;
use std::sync::Arc;

use super::DeviceBindingPolicy;

/// 宽松设备绑定策略：新设备仅告警不阻断。
///
/// 持有 [`BulwarkSession`] 引用与可选的 [`AlertListenerManager`]。新设备时
/// `require_secondary_auth` 仍返回 `Ok(false)`（不触发二级认证），但会通过
/// `AlertListenerManager` 广播 [`SecurityAlertEvent::NewDeviceLogin`] 事件。
///
/// # 向后兼容
///
/// `alert_manager` 为 `None` 时跳过广播，行为等价于 [`super::Disabled`]（但
/// `is_new_device` 仍正常检测），适用于未启用告警系统的部署。
pub struct LooseBinding {
    /// 会话管理器引用，用于查询历史 session 的 device 字段。
    session: Arc<BulwarkSession>,
    /// 可选的告警监听器管理器，`None` 时跳过广播。
    alert_manager: Option<Arc<AlertListenerManager>>,
}

impl LooseBinding {
    /// 创建 [`LooseBinding`] 实例（无告警管理器）。
    ///
    /// # 参数
    /// - `session`: 会话管理器引用（`Arc<BulwarkSession>`）。
    pub fn new(session: Arc<BulwarkSession>) -> Self {
        Self {
            session,
            alert_manager: None,
        }
    }

    /// 创建 [`LooseBinding`] 实例并注入告警管理器。
    ///
    /// # 参数
    /// - `session`: 会话管理器引用。
    /// - `alert_manager`: 告警监听器管理器，新设备时通过它广播 `NewDeviceLogin` 事件。
    pub fn with_alert_manager(
        session: Arc<BulwarkSession>,
        alert_manager: Arc<AlertListenerManager>,
    ) -> Self {
        Self {
            session,
            alert_manager: Some(alert_manager),
        }
    }
}

#[async_trait]
impl DeviceBindingPolicy for LooseBinding {
    async fn is_new_device(&self, login_id: &str, device_id: &str) -> BulwarkResult<bool> {
        super::policies::check_is_new_device(&self.session, login_id, device_id).await
    }

    async fn require_secondary_auth(&self, login_id: &str, device_id: &str) -> BulwarkResult<bool> {
        // HIGH-001 修复：调用方已通过 is_new_device 确认是新设备，不再重复 DAO 查询。
        // 直接广播 NewDeviceLogin 事件（若注入了 alert_manager），然后返回 false（不阻断）。
        if let Some(mgr) = &self.alert_manager {
            let event = SecurityAlertEvent::NewDeviceLogin {
                login_id: login_id.to_string(),
                device_id: device_id.to_string(),
                ip: None,
            };
            mgr.broadcast_alert(&event).await;
        }
        Ok(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::error::BulwarkResult;
    use crate::stp::LoginParams;
    use crate::strategy::alert::AlertListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// 辅助函数：创建带 MockDao 的 Arc<BulwarkSession>。
    fn make_session() -> (Arc<MockDao>, Arc<BulwarkSession>) {
        let dao: Arc<MockDao> = Arc::new(MockDao::new());
        let session = Arc::new(BulwarkSession::new(dao.clone(), 3600, 86400));
        (dao, session)
    }

    /// 辅助函数：创建带指定 device 的 token session。
    async fn create_session_with_device(
        session: &BulwarkSession,
        login_id: &str,
        token: &str,
        device: &str,
    ) {
        let params = LoginParams {
            device: Some(device.to_string()),
            ..Default::default()
        };
        session
            .create_token_session(login_id, token, &params)
            .await
            .unwrap();
    }

    /// 计数监听器：记录 on_alert 调用次数 + 最近一次事件。
    struct CountingListener {
        count: AtomicUsize,
        last_event: Mutex<Option<SecurityAlertEvent>>,
    }

    impl CountingListener {
        fn new() -> Self {
            Self {
                count: AtomicUsize::new(0),
                last_event: Mutex::new(None),
            }
        }

        fn call_count(&self) -> usize {
            self.count.load(Ordering::SeqCst)
        }

        fn last_event(&self) -> Option<SecurityAlertEvent> {
            self.last_event.lock().unwrap().clone()
        }
    }

    #[async_trait]
    impl AlertListener for CountingListener {
        async fn on_alert(&self, event: &SecurityAlertEvent) -> BulwarkResult<()> {
            self.count.fetch_add(1, Ordering::SeqCst);
            *self.last_event.lock().unwrap() = Some(event.clone());
            Ok(())
        }
    }

    /// 辅助函数：构造带 CountingListener 的 AlertListenerManager。
    fn make_alert_manager_with_counter() -> (Arc<AlertListenerManager>, Arc<CountingListener>) {
        let mgr = Arc::new(AlertListenerManager::new());
        let counter = Arc::new(CountingListener::new());
        mgr.add_listener(counter.clone());
        (mgr, counter)
    }

    // ========================================================================
    // require_secondary_auth + 告警广播测试
    // ========================================================================

    /// 新设备时广播 NewDeviceLogin 事件，listener 收到 1 次调用且事件类型正确。
    #[tokio::test]
    async fn new_device_broadcasts_alert() {
        let (_dao, session) = make_session();
        create_session_with_device(&session, "1001", "T1", "web-chrome").await;
        let (mgr, counter) = make_alert_manager_with_counter();

        let policy = LooseBinding::with_alert_manager(session, mgr);
        let require = policy
            .require_secondary_auth("1001", "mobile-ios")
            .await
            .unwrap();

        // LooseBinding 总是返回 false（仅告警不阻断）
        assert!(!require, "LooseBinding require_secondary_auth 应返回 false");
        // listener 应被调用 1 次
        assert_eq!(counter.call_count(), 1, "新设备应广播 1 次告警事件");
        // 验证事件类型为 NewDeviceLogin
        match counter.last_event() {
            Some(SecurityAlertEvent::NewDeviceLogin {
                login_id,
                device_id,
                ip,
            }) => {
                assert_eq!(login_id, "1001");
                assert_eq!(device_id, "mobile-ios");
                assert!(ip.is_none(), "ip 应为 None");
            },
            other => panic!("期望 NewDeviceLogin 事件，实际: {:?}", other),
        }
    }

    /// HIGH-001 修复后 require_secondary_auth 总是广播告警（调用方已通过 is_new_device 确认是新设备）。
    #[tokio::test]
    async fn require_secondary_auth_always_broadcasts_after_high001_fix() {
        let (_dao, session) = make_session();
        create_session_with_device(&session, "1001", "T1", "web-chrome").await;
        let (mgr, counter) = make_alert_manager_with_counter();

        let policy = LooseBinding::with_alert_manager(session, mgr);
        // 即使传入已知设备，require_secondary_auth 也广播告警
        // 因为调用方（session.rs login 流程）仅在 is_new_device == true 时才调用此方法
        let require = policy
            .require_secondary_auth("1001", "web-chrome")
            .await
            .unwrap();

        assert!(!require, "LooseBinding require_secondary_auth 应返回 false");
        assert_eq!(
            counter.call_count(),
            1,
            "HIGH-001 修复后总是广播告警（调用方已确认是新设备）"
        );
    }

    /// require_secondary_auth 对新设备/旧设备均返回 false（仅告警不阻断）。
    #[tokio::test]
    async fn require_secondary_auth_always_returns_false() {
        let (_dao, session) = make_session();
        create_session_with_device(&session, "1001", "T1", "web-chrome").await;
        let (mgr, _counter) = make_alert_manager_with_counter();

        let policy = LooseBinding::with_alert_manager(session, mgr);
        // 新设备
        let r1 = policy
            .require_secondary_auth("1001", "mobile-ios")
            .await
            .unwrap();
        assert!(!r1, "新设备 require_secondary_auth 应返回 false");
        // 旧设备
        let r2 = policy
            .require_secondary_auth("1001", "web-chrome")
            .await
            .unwrap();
        assert!(!r2, "旧设备 require_secondary_auth 应返回 false");
    }

    /// 无 alert_manager 时新设备不报错（向后兼容）。
    #[tokio::test]
    async fn no_alert_manager_does_not_error() {
        let (_dao, session) = make_session();
        create_session_with_device(&session, "1001", "T1", "web-chrome").await;

        // LooseBinding::new 不注入 alert_manager
        let policy = LooseBinding::new(session);
        let require = policy
            .require_secondary_auth("1001", "mobile-ios")
            .await
            .unwrap();

        // 仍返回 false（不阻断），且不报错
        assert!(
            !require,
            "无 alert_manager 时 require_secondary_auth 应仍返回 false"
        );
    }

    /// 无 session 时新设备广播告警。
    #[tokio::test]
    async fn no_session_broadcasts_alert_for_new_device() {
        let (_dao, session) = make_session();
        let (mgr, counter) = make_alert_manager_with_counter();

        let policy = LooseBinding::with_alert_manager(session, mgr);
        let require = policy
            .require_secondary_auth("1001", "web-chrome")
            .await
            .unwrap();

        assert!(!require, "LooseBinding require_secondary_auth 应返回 false");
        assert_eq!(
            counter.call_count(),
            1,
            "无历史 session 时新设备应广播 1 次告警"
        );
    }

    /// HIGH-001 修复后多 session 场景下 require_secondary_auth 总是广播（调用方已确认是新设备）。
    #[tokio::test]
    async fn multiple_sessions_always_broadcasts_after_high001_fix() {
        let (_dao, session) = make_session();
        create_session_with_device(&session, "1001", "T1", "web-chrome").await;
        create_session_with_device(&session, "1001", "T2", "mobile-ios").await;
        create_session_with_device(&session, "1001", "T3", "api-client").await;
        let (mgr, counter) = make_alert_manager_with_counter();

        let policy = LooseBinding::with_alert_manager(session, mgr);

        // HIGH-001 修复后，require_secondary_auth 不再自己调用 is_new_device
        // 调用方已确认是新设备，因此无论传入什么 device_id 都会广播
        let _ = policy
            .require_secondary_auth("1001", "mobile-ios")
            .await
            .unwrap();
        assert_eq!(
            counter.call_count(),
            1,
            "HIGH-001 修复后第一次调用应广播 1 次"
        );

        let _ = policy
            .require_secondary_auth("1001", "tablet-android")
            .await
            .unwrap();
        assert_eq!(
            counter.call_count(),
            2,
            "HIGH-001 修复后第二次调用应再广播 1 次（总计 2 次）"
        );
    }
}
