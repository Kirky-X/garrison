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
//! `AlertListenerManager` 为 `Option`，`None` 表示未部署告警系统，此时跳过广播。
//!
//! # HIGH-001 修复 + 新设备校验（issue #2160）
//!
//! `require_secondary_auth` 不再重复信任调用方的 `is_new_device` 结果：
//! 本方法**内部自行调用 `is_new_device`**，仅在确认是新设备时才广播
//! （与文档"新设备时广播"一致）。即使调用方契约被破坏（未先调用
//! `is_new_device` 就调用本方法），已知设备的登录也不会产生误报广播。
//! 代价是新设备路径多一次 DAO 查询（换取语义自洽，消除对调用方的隐式依赖）。
//!
//! # IP 透传（issue #2159）
//!
//! trait 方法 `require_secondary_auth` 签名无 IP 参数（调用方 stp 层契约约束，
//! 无法破坏性变更），事件中 `ip` 为 `None`；需要携带真实来源 IP 的调用方
//! 请改用本类型固有的 [`LooseBinding::require_secondary_auth_with_ip`]。

use crate::error::GarrisonResult;
use crate::session::GarrisonSession;
use crate::strategy::alert::{AlertListenerManager, SecurityAlertEvent};
use async_trait::async_trait;
use std::sync::Arc;

use super::DeviceBindingPolicy;

/// 宽松设备绑定策略：新设备仅告警不阻断。
///
/// 持有 [`GarrisonSession`] 引用与可选的 [`AlertListenerManager`]。新设备时
/// `require_secondary_auth` 仍返回 `Ok(false)`（不触发二级认证），但会通过
/// `AlertListenerManager` 广播 [`SecurityAlertEvent::NewDeviceLogin`] 事件。
///
/// # 未部署告警系统时（None）
///
/// `alert_manager` 为 `None` 时跳过广播，行为等价于 [`super::Disabled`]（但
/// `is_new_device` 仍正常检测），适用于未启用告警系统的部署。
pub struct LooseBinding {
    /// 会话管理器引用，用于查询历史 session 的 device 字段。
    session: Arc<GarrisonSession>,
    /// 可选的告警监听器管理器，`None` 时跳过广播。
    alert_manager: Option<Arc<AlertListenerManager>>,
}

impl LooseBinding {
    /// 创建 [`LooseBinding`] 实例（无告警管理器）。
    ///
    /// # 参数
    /// - `session`: 会话管理器引用（`Arc<GarrisonSession>`）。
    pub fn new(session: Arc<GarrisonSession>) -> Self {
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
        session: Arc<GarrisonSession>,
        alert_manager: Arc<AlertListenerManager>,
    ) -> Self {
        Self {
            session,
            alert_manager: Some(alert_manager),
        }
    }

    /// 二级认证判定（带请求来源 IP）：新设备时广播 `NewDeviceLogin`（事件携带 `ip`）。
    ///
    /// 内部先调用 [`is_new_device`](DeviceBindingPolicy::is_new_device) 确认设备
    /// 新颖性（issue #2160：不信任调用方契约，已知设备不广播），新设备时经
    /// `alert_manager` 广播事件（`ip` 为调用方透传的真实来源 IP，issue #2159），
    /// 并返回 `Ok(false)`（宽松模式不阻断登录）。
    ///
    /// trait 方法 [`require_secondary_auth`](DeviceBindingPolicy::require_secondary_auth)
    /// 因签名无 IP 参数（stp 调用方契约约束）以 `ip=None` 委托本方法；
    /// 拥有请求 IP 的调用方应直接调用本方法。
    pub async fn require_secondary_auth_with_ip(
        &self,
        login_id: &str,
        device_id: &str,
        ip: Option<&str>,
    ) -> GarrisonResult<bool> {
        // 新设备校验（issue #2160）：仅新设备才广播，与文档"新设备时广播"一致。
        let is_new = self.is_new_device(login_id, device_id).await?;
        if !is_new {
            return Ok(false);
        }
        if let Some(mgr) = &self.alert_manager {
            let event = SecurityAlertEvent::NewDeviceLogin {
                login_id: login_id.to_string(),
                device_id: device_id.to_string(),
                ip: ip.map(|s| s.to_string()),
            };
            mgr.broadcast_alert(&event).await;
        }
        Ok(false)
    }
}

#[async_trait]
impl DeviceBindingPolicy for LooseBinding {
    async fn is_new_device(&self, login_id: &str, device_id: &str) -> GarrisonResult<bool> {
        super::policies::check_is_new_device(&self.session, login_id, device_id).await
    }

    async fn require_secondary_auth(
        &self,
        login_id: &str,
        device_id: &str,
    ) -> GarrisonResult<bool> {
        // trait 签名无 ip 参数（stp 调用方契约约束），ip 透传请用
        // require_secondary_auth_with_ip；此处内部自行做新设备校验后再广播。
        self.require_secondary_auth_with_ip(login_id, device_id, None)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::error::GarrisonResult;
    use crate::stp::LoginParams;
    use crate::strategy::alert::AlertListener;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;

    /// 辅助函数：创建带 MockDao 的 Arc<GarrisonSession>。
    fn make_session() -> (Arc<MockDao>, Arc<GarrisonSession>) {
        let dao: Arc<MockDao> = Arc::new(MockDao::new());
        let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
        (dao, session)
    }

    /// 辅助函数：创建带指定 device 的 token session。
    async fn create_session_with_device(
        session: &GarrisonSession,
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
        async fn on_alert(&self, event: &SecurityAlertEvent) -> GarrisonResult<()> {
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

    /// 已知设备调用 require_secondary_auth 不广播（issue #2160 修复：
    /// 内部自行调用 is_new_device，不信任调用方契约，消除误报广播）。
    #[tokio::test]
    async fn require_secondary_auth_known_device_does_not_broadcast() {
        let (_dao, session) = make_session();
        create_session_with_device(&session, "1001", "T1", "web-chrome").await;
        let (mgr, counter) = make_alert_manager_with_counter();

        let policy = LooseBinding::with_alert_manager(session, mgr);
        // "web-chrome" 是已知设备（T1），即使调用方未先调 is_new_device 也不广播
        let require = policy
            .require_secondary_auth("1001", "web-chrome")
            .await
            .unwrap();

        assert!(!require, "LooseBinding require_secondary_auth 应返回 false");
        assert_eq!(
            counter.call_count(),
            0,
            "已知设备不应广播告警（issue #2160 修复）"
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

    /// 无 alert_manager 时新设备不报错（None = 未部署告警系统，跳过广播）。
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

    /// 新设备校验后按设备新颖性广播：已知设备不广播，新设备广播（issue #2160 修复）。
    #[tokio::test]
    async fn multiple_sessions_broadcast_only_for_new_device() {
        let (_dao, session) = make_session();
        create_session_with_device(&session, "1001", "T1", "web-chrome").await;
        create_session_with_device(&session, "1001", "T2", "mobile-ios").await;
        create_session_with_device(&session, "1001", "T3", "api-client").await;
        let (mgr, counter) = make_alert_manager_with_counter();

        let policy = LooseBinding::with_alert_manager(session, mgr);

        // "mobile-ios" 是已知设备（T2）→ 不广播
        let _ = policy
            .require_secondary_auth("1001", "mobile-ios")
            .await
            .unwrap();
        assert_eq!(
            counter.call_count(),
            0,
            "已知设备不应广播（issue #2160 修复）"
        );

        // "tablet-android" 是新设备 → 广播 1 次
        let _ = policy
            .require_secondary_auth("1001", "tablet-android")
            .await
            .unwrap();
        assert_eq!(counter.call_count(), 1, "新设备应广播 1 次（总计 1 次）");
    }

    /// require_secondary_auth_with_ip 将真实来源 IP 透传到 NewDeviceLogin 事件
    /// （issue #2159 修复）。
    #[tokio::test]
    async fn with_ip_variant_forwards_ip_to_event() {
        let (_dao, session) = make_session();
        create_session_with_device(&session, "1001", "T1", "web-chrome").await;
        let (mgr, counter) = make_alert_manager_with_counter();

        let policy = LooseBinding::with_alert_manager(session, mgr);
        let require = policy
            .require_secondary_auth_with_ip("1001", "mobile-ios", Some("203.0.113.9"))
            .await
            .unwrap();

        assert!(!require, "宽松模式应返回 false 不阻断");
        match counter.last_event() {
            Some(SecurityAlertEvent::NewDeviceLogin { ip, .. }) => {
                assert_eq!(
                    ip.as_deref(),
                    Some("203.0.113.9"),
                    "事件应携带透传的真实来源 IP"
                );
            },
            other => panic!("期望 NewDeviceLogin 事件，实际: {:?}", other),
        }

        // trait 方法（无 ip 参数）事件 ip 仍为 None
        let _ = policy
            .require_secondary_auth("1001", "tablet-android")
            .await
            .unwrap();
        match counter.last_event() {
            Some(SecurityAlertEvent::NewDeviceLogin { ip, .. }) => {
                assert!(ip.is_none(), "trait 方法路径事件 ip 应为 None");
            },
            other => panic!("期望 NewDeviceLogin 事件，实际: {:?}", other),
        }
    }
}
