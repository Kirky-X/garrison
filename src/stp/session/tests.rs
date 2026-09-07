#[cfg(test)]
mod tests {
    // jwt_secret 的 `.into()` 是跨 feature 兼容的必要转换：protocol-zeroize 下字段
    // 类型为 Zeroizing<String>，feature 关闭时退化为 String，被 clippy 误报。
    #![allow(clippy::useless_conversion)]
    // 显式导入：子模块 `use super::*;` 不导入父模块的私有 `use` 项
    use crate::config::GarrisonConfig;
    use crate::config::ReplacedLoginExitMode;
    use crate::error::{GarrisonError, GarrisonResult};
    use crate::stp::core::GarrisonCore;
    use crate::stp::{GarrisonLogicDefault, JwtMode, LoginParams, SessionLogic};
    use async_trait::async_trait;
    use serial_test::serial;
    use std::sync::Arc;

    /// 最小 mock：实现 `GarrisonCore` + 9 个必需 `SessionLogic` 方法
    /// （`login_by_token` 有默认实现，无需覆写）。
    struct MockSession {
        config: Arc<GarrisonConfig>,
    }

    impl GarrisonCore for MockSession {
        fn config(&self) -> Arc<GarrisonConfig> {
            Arc::clone(&self.config)
        }
    }

    #[async_trait]
    impl SessionLogic for MockSession {
        async fn login(&self, _login_id: &str, _params: &LoginParams) -> GarrisonResult<String> {
            Ok("mock-token".to_string())
        }
        async fn login_with_token(&self, _login_id: &str, _token: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn logout(&self) -> GarrisonResult<()> {
            Ok(())
        }
        async fn logout_by_login_id(&self, _login_id: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn kickout(&self, _login_id: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn kickout_by_token(&self, _token: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn revoke_token(&self, _token: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn check_login(&self) -> GarrisonResult<bool> {
            Ok(true)
        }
        async fn get_login_id(&self) -> GarrisonResult<Option<String>> {
            Ok(Some("42".to_string()))
        }
    }

    /// 验证 `login` 接受 `&str`（Numeric 与 String 形式）。
    /// 调用方通过 `GarrisonUtil::login("42")` 或 `GarrisonUtil::login(42i64.to_string())`。
    #[tokio::test]
    async fn login_accepts_str_ref() {
        let mock = MockSession {
            config: Arc::new(GarrisonConfig::default()),
        };
        let t1 = mock.login("42", &LoginParams::default()).await.unwrap();
        let t2 = mock.login("alice", &LoginParams::default()).await.unwrap();
        assert_eq!(t1, "mock-token");
        assert_eq!(t2, "mock-token");
    }

    /// 验证 `login_with_token` 接受 `&str`。
    #[tokio::test]
    async fn login_with_token_accepts_str_ref() {
        let mock = MockSession {
            config: Arc::new(GarrisonConfig::default()),
        };
        mock.login_with_token("user-uuid", "tok").await.unwrap();
    }

    /// 验证 `get_login_id` 返回 `String`（v0.5.2 返回类型迁移）。
    #[tokio::test]
    async fn get_login_id_returns_string() {
        let mock = MockSession {
            config: Arc::new(GarrisonConfig::default()),
        };
        let id = mock.get_login_id().await.unwrap().unwrap();
        assert_eq!(id, "42");
    }

    /// 验证 `login_by_token` 默认实现返回 `NotImplemented`。
    #[tokio::test]
    async fn login_by_token_default_returns_not_implemented() {
        let mock = MockSession {
            config: Arc::new(GarrisonConfig::default()),
        };
        let result = mock.login_by_token("external").await;
        assert!(
            matches!(result, Err(GarrisonError::NotImplemented(_))),
            "默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// 验证 `revoke_all_sessions` 默认实现返回 `NotImplemented`。
    #[tokio::test]
    async fn revoke_all_sessions_default_returns_not_implemented() {
        let mock = MockSession {
            config: Arc::new(GarrisonConfig::default()),
        };
        let result = mock.revoke_all_sessions("1001").await;
        assert!(
            matches!(result, Err(GarrisonError::NotImplemented(_))),
            "默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// 验证 `get_active_sessions` 默认实现返回 `NotImplemented`。
    #[tokio::test]
    async fn get_active_sessions_default_returns_not_implemented() {
        let mock = MockSession {
            config: Arc::new(GarrisonConfig::default()),
        };
        let result = mock.get_active_sessions("1001").await;
        assert!(
            matches!(result, Err(GarrisonError::NotImplemented(_))),
            "默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// 覆盖率补充：调用 MockSession 所有未覆盖方法。
    #[tokio::test]
    async fn mock_session_all_methods_coverage() {
        let mock = MockSession {
            config: Arc::new(GarrisonConfig::default()),
        };
        // GarrisonCore
        let _ = mock.config();
        // SessionLogic 未覆盖方法
        let _ = mock.logout().await.unwrap();
        let _ = mock.logout_by_login_id("u1").await.unwrap();
        let _ = mock.kickout("u1").await.unwrap();
        let _ = mock.kickout_by_token("t1").await.unwrap();
        let _ = mock.revoke_token("t1").await.unwrap();
        let _ = mock.check_login().await.unwrap();
    }

    // ========================================================================
    // T006: AnomalyDetector 集成测试（security-alert feature）
    // ========================================================================

    #[cfg(feature = "security-extra")]
    mod anomaly_integration {
        use super::*;
        use crate::dao::GarrisonDao;
        use crate::session::GarrisonSession;
        use crate::stp::with_current_token;
        use crate::strategy::alert::{
            AlertListener, AlertListenerManager, AnomalyDetector, AnomalyType, SecurityAlertEvent,
        };
        use crate::strategy::GarrisonPermissionStrategy;
        use async_trait::async_trait;
        use parking_lot::Mutex;
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        // --------------------------------------------------------------------
        // MockDao：HashMap + Instant 模拟 TTL（与 stp/tests.rs 同模式）
        // --------------------------------------------------------------------

        struct MockDao {
            store: Mutex<HashMap<String, (String, Option<Instant>)>>,
        }

        impl MockDao {
            fn new() -> Self {
                Self {
                    store: Mutex::new(HashMap::new()),
                }
            }
        }

        #[async_trait]
        impl GarrisonDao for MockDao {
            async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
                let mut store = self.store.lock();
                match store.get(key) {
                    Some((value, expire_at)) => {
                        if let Some(deadline) = expire_at {
                            if Instant::now() >= *deadline {
                                store.remove(key);
                                return Ok(None);
                            }
                        }
                        Ok(Some(value.clone()))
                    },
                    None => Ok(None),
                }
            }
            async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
                let expire_at = if ttl_seconds == 0 {
                    None
                } else {
                    Some(Instant::now() + Duration::from_secs(ttl_seconds))
                };
                self.store
                    .lock()
                    .insert(key.to_string(), (value.to_string(), expire_at));
                Ok(())
            }
            async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
                let mut store = self.store.lock();
                match store.get_mut(key) {
                    Some((existing, _)) => {
                        *existing = value.to_string();
                        Ok(())
                    },
                    None => Err(GarrisonError::Dao(format!("dao-key-not-found::{}", key))),
                }
            }
            async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
                let mut store = self.store.lock();
                match store.get_mut(key) {
                    Some((_, expire_at)) => {
                        *expire_at = if seconds == 0 {
                            None
                        } else {
                            Some(Instant::now() + Duration::from_secs(seconds))
                        };
                        Ok(())
                    },
                    None => Err(GarrisonError::Dao(format!("dao-key-not-found::{}", key))),
                }
            }
            async fn delete(&self, key: &str) -> GarrisonResult<()> {
                self.store.lock().remove(key);
                Ok(())
            }
            crate::atomic_test_fallback!();
        }

        // --------------------------------------------------------------------
        // MockFirewall：no-op 权限策略，允许所有登录
        // --------------------------------------------------------------------

        struct MockFirewall;

        #[async_trait]
        impl GarrisonPermissionStrategy for MockFirewall {
            async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
                Ok(vec![])
            }
            async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
                Ok(vec![])
            }
            async fn check_permission(
                &self,
                _login_id: &str,
                _permission: &str,
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role(&self, _login_id: &str, _role: &str) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role_any(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role_all(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
        }

        // --------------------------------------------------------------------
        // MockAnomalyDetector：记录调用，可配置返回事件或错误
        // --------------------------------------------------------------------

        struct MockAnomalyDetector {
            login_call_count: AtomicUsize,
            check_login_call_count: AtomicUsize,
            login_events: Mutex<Vec<SecurityAlertEvent>>,
            check_login_events: Mutex<Vec<SecurityAlertEvent>>,
            fail_on_login: bool,
            fail_on_check_login: bool,
        }

        impl MockAnomalyDetector {
            fn new() -> Self {
                Self {
                    login_call_count: AtomicUsize::new(0),
                    check_login_call_count: AtomicUsize::new(0),
                    login_events: Mutex::new(Vec::new()),
                    check_login_events: Mutex::new(Vec::new()),
                    fail_on_login: false,
                    fail_on_check_login: false,
                }
            }

            fn with_login_event(event: SecurityAlertEvent) -> Self {
                let det = Self::new();
                det.login_events.lock().push(event);
                det
            }

            fn with_check_login_event(event: SecurityAlertEvent) -> Self {
                let det = Self::new();
                det.check_login_events.lock().push(event);
                det
            }

            fn failing_on_login() -> Self {
                let mut det = Self::new();
                det.fail_on_login = true;
                det
            }

            fn failing_on_check_login() -> Self {
                let mut det = Self::new();
                det.fail_on_check_login = true;
                det
            }

            fn login_calls(&self) -> usize {
                self.login_call_count.load(Ordering::SeqCst)
            }

            fn check_login_calls(&self) -> usize {
                self.check_login_call_count.load(Ordering::SeqCst)
            }
        }

        #[async_trait]
        impl AnomalyDetector for MockAnomalyDetector {
            async fn check_on_login(
                &self,
                _login_id: &str,
                _device_id: &str,
                _ip: Option<&str>,
            ) -> GarrisonResult<Vec<SecurityAlertEvent>> {
                self.login_call_count.fetch_add(1, Ordering::SeqCst);
                if self.fail_on_login {
                    return Err(GarrisonError::Internal(
                        "stp-mock-login-detection-failed::".to_string(),
                    ));
                }
                Ok(self.login_events.lock().clone())
            }

            async fn check_on_check_login(
                &self,
                _login_id: &str,
                _token: &str,
            ) -> GarrisonResult<Vec<SecurityAlertEvent>> {
                self.check_login_call_count.fetch_add(1, Ordering::SeqCst);
                if self.fail_on_check_login {
                    return Err(GarrisonError::Internal(
                        "stp-mock-check-login-detection-failed::".to_string(),
                    ));
                }
                Ok(self.check_login_events.lock().clone())
            }
        }

        // --------------------------------------------------------------------
        // CountingAlertListener：记录接收到的告警事件
        // --------------------------------------------------------------------

        struct CountingAlertListener {
            received: Mutex<Vec<SecurityAlertEvent>>,
        }

        impl CountingAlertListener {
            fn new() -> Self {
                Self {
                    received: Mutex::new(Vec::new()),
                }
            }

            fn count(&self) -> usize {
                self.received.lock().len()
            }

            fn events(&self) -> Vec<SecurityAlertEvent> {
                self.received.lock().clone()
            }
        }

        #[async_trait]
        impl AlertListener for CountingAlertListener {
            async fn on_alert(&self, event: &SecurityAlertEvent) -> GarrisonResult<()> {
                self.received.lock().push(event.clone());
                Ok(())
            }
        }

        // --------------------------------------------------------------------
        // 辅助函数
        // --------------------------------------------------------------------

        /// 创建带异常检测器的 GarrisonLogicDefault。
        fn make_logic_with_anomaly(
            detector: Arc<dyn AnomalyDetector>,
            listener_manager: Arc<AlertListenerManager>,
        ) -> GarrisonLogicDefault {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall);
            GarrisonLogicDefault::new(session, Arc::new(config), firewall)
                .with_anomaly_detector(detector)
                .with_alert_listener_manager(listener_manager)
        }

        /// 创建不带检测器的 GarrisonLogicDefault（向后兼容测试用）。
        fn make_logic_without_anomaly() -> GarrisonLogicDefault {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall);
            GarrisonLogicDefault::new(session, Arc::new(config), firewall)
        }

        fn sample_anomaly_event(login_id: &str) -> SecurityAlertEvent {
            SecurityAlertEvent::AnomalyLogin {
                login_id: login_id.to_string(),
                anomaly_type: AnomalyType::IpChanged,
                detail: "IP 变化检测".to_string(),
                trace_id: "trace-t006".to_string(),
            }
        }

        // --------------------------------------------------------------------
        // 6 个集成测试
        // --------------------------------------------------------------------

        /// login 时 detector 返回告警事件，验证 broadcast 被调用。
        #[tokio::test]
        async fn test_login_triggers_anomaly_alert() {
            let listener = Arc::new(CountingAlertListener::new());
            let manager = Arc::new(AlertListenerManager::new());
            manager.add_listener(listener.clone() as Arc<dyn AlertListener>);
            let detector = Arc::new(MockAnomalyDetector::with_login_event(sample_anomaly_event(
                "1001",
            )));
            let logic = make_logic_with_anomaly(detector.clone(), manager);

            let token = logic
                .login("1001", &LoginParams::default())
                .await
                .expect("login 应成功");

            assert!(!token.is_empty(), "login 应返回非空 token");
            assert_eq!(detector.login_calls(), 1, "check_on_login 应被调用 1 次");
            assert_eq!(listener.count(), 1, "应广播 1 个告警事件");
            let events = listener.events();
            assert!(
                matches!(&events[0], SecurityAlertEvent::AnomalyLogin { login_id, .. } if login_id == "1001"),
                "广播的事件应为 AnomalyLogin(login_id=1001)"
            );
        }

        /// check_login 时 detector 返回告警事件，验证 broadcast 被调用。
        #[tokio::test]
        async fn test_check_login_triggers_anomaly_alert() {
            let listener = Arc::new(CountingAlertListener::new());
            let manager = Arc::new(AlertListenerManager::new());
            manager.add_listener(listener.clone() as Arc<dyn AlertListener>);
            let detector = Arc::new(MockAnomalyDetector::with_check_login_event(
                sample_anomaly_event("1001"),
            ));
            let logic = Arc::new(make_logic_with_anomaly(detector.clone(), manager));

            let token = logic.login("1001", &LoginParams::default()).await.unwrap();

            let valid =
                with_current_token(token, async { logic.check_login().await.unwrap() }).await;

            assert!(valid, "check_login 应返回 true（有效 token）");
            assert_eq!(
                detector.check_login_calls(),
                1,
                "check_on_check_login 应被调用 1 次"
            );
            assert_eq!(listener.count(), 1, "应广播 1 个告警事件");
        }

        /// detector 返回 Err，login 仍成功返回 token。
        #[tokio::test]
        async fn test_login_detection_failure_does_not_interrupt() {
            let listener = Arc::new(CountingAlertListener::new());
            let manager = Arc::new(AlertListenerManager::new());
            manager.add_listener(listener.clone() as Arc<dyn AlertListener>);
            let detector = Arc::new(MockAnomalyDetector::failing_on_login());
            let logic = make_logic_with_anomaly(detector.clone(), manager);

            let token = logic
                .login("1001", &LoginParams::default())
                .await
                .expect("检测失败时 login 仍应成功");

            assert!(!token.is_empty(), "login 应返回非空 token");
            assert_eq!(detector.login_calls(), 1, "check_on_login 应被调用 1 次");
            assert_eq!(listener.count(), 0, "检测失败时不应广播事件");
        }

        /// detector 返回 Err，check_login 仍返回原结果。
        #[tokio::test]
        async fn test_check_login_detection_failure_does_not_interrupt() {
            let listener = Arc::new(CountingAlertListener::new());
            let manager = Arc::new(AlertListenerManager::new());
            manager.add_listener(listener.clone() as Arc<dyn AlertListener>);
            let detector = Arc::new(MockAnomalyDetector::failing_on_check_login());
            let logic = Arc::new(make_logic_with_anomaly(detector.clone(), manager));

            let token = logic.login("1001", &LoginParams::default()).await.unwrap();

            let valid =
                with_current_token(token, async { logic.check_login().await.unwrap() }).await;

            assert!(valid, "检测失败时 check_login 仍应返回 true");
            assert_eq!(
                detector.check_login_calls(),
                1,
                "check_on_check_login 应被调用 1 次"
            );
            assert_eq!(listener.count(), 0, "检测失败时不应广播事件");
        }

        /// 未注入 detector 时 login 正常工作（向后兼容）。
        #[tokio::test]
        async fn test_login_without_detector_backward_compatible() {
            let logic = make_logic_without_anomaly();
            let token = logic
                .login("1001", &LoginParams::default())
                .await
                .expect("未注入 detector 时 login 应正常工作");
            assert!(!token.is_empty(), "login 应返回非空 token");

            let ts = logic
                .session
                .get_token_session(&token)
                .await
                .unwrap()
                .expect("会话应已创建");
            assert_eq!(ts.login_id, "1001");
        }

        /// 未注入 detector 时 check_login 正常工作（向后兼容）。
        #[tokio::test]
        async fn test_check_login_without_detector_backward_compatible() {
            let logic = Arc::new(make_logic_without_anomaly());
            let token = logic.login("1001", &LoginParams::default()).await.unwrap();

            let valid =
                with_current_token(token, async { logic.check_login().await.unwrap() }).await;

            assert!(valid, "未注入 detector 时 check_login 应返回 true");
        }
    }

    // ========================================================================
    // T013: DeviceBindingPolicy 集成测试（device-binding feature）
    // ========================================================================

    #[cfg(feature = "device-binding")]
    mod device_binding_integration {
        use super::*;
        use crate::config::GarrisonConfig;
        use crate::dao::tests::MockDao;
        use crate::session::GarrisonSession;
        use crate::strategy::alert::{AlertListener, AlertListenerManager, SecurityAlertEvent};
        use crate::strategy::device_binding::{Disabled, LooseBinding, StrictBinding};
        use crate::strategy::GarrisonPermissionStrategy;
        use async_trait::async_trait;
        use parking_lot::Mutex;
        use std::sync::Arc;

        // --------------------------------------------------------------------
        // MockFirewall：no-op 权限策略，允许所有登录
        // --------------------------------------------------------------------

        struct MockFirewall;

        #[async_trait]
        impl GarrisonPermissionStrategy for MockFirewall {
            async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
                Ok(vec![])
            }
            async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
                Ok(vec![])
            }
            async fn check_permission(
                &self,
                _login_id: &str,
                _permission: &str,
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role(&self, _login_id: &str, _role: &str) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role_any(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
            async fn check_role_all(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> GarrisonResult<bool> {
                Ok(true)
            }
        }

        // --------------------------------------------------------------------
        // CountingAlertListener：记录接收到的告警事件
        // --------------------------------------------------------------------

        struct CountingAlertListener {
            received: Mutex<Vec<SecurityAlertEvent>>,
        }

        impl CountingAlertListener {
            fn new() -> Self {
                Self {
                    received: Mutex::new(Vec::new()),
                }
            }

            fn count(&self) -> usize {
                self.received.lock().len()
            }

            fn events(&self) -> Vec<SecurityAlertEvent> {
                self.received.lock().clone()
            }
        }

        #[async_trait]
        impl AlertListener for CountingAlertListener {
            async fn on_alert(&self, event: &SecurityAlertEvent) -> GarrisonResult<()> {
                self.received.lock().push(event.clone());
                Ok(())
            }
        }

        // --------------------------------------------------------------------
        // 辅助函数
        // --------------------------------------------------------------------

        /// 创建带 MockDao 的 GarrisonLogicDefault（无设备绑定策略，供测试自定义注入）。
        fn make_logic_base() -> GarrisonLogicDefault {
            let dao: Arc<MockDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall);
            GarrisonLogicDefault::new(session, Arc::new(config), firewall)
        }

        // --------------------------------------------------------------------
        // 7 个集成测试（A10 新增 hard block 验证）
        // --------------------------------------------------------------------

        /// A10 修复：strict 模式下新设备 login 被 hard block（require_secondary_auth=true
        /// → 返回 `Err(NotPermission)`），login 失败且不创建 session。
        #[tokio::test]
        async fn test_strict_mode_new_device_triggers_mfa() {
            let logic = make_logic_base();
            // 注入 StrictBinding（共享 logic.session，检测历史 session）
            let policy = Arc::new(StrictBinding::new(logic.session.clone()));
            let logic = logic.with_device_binding_policy(policy);

            // 无历史 session → is_new_device=true → require_secondary_auth=true → hard block
            let params = LoginParams {
                device: Some("web-chrome".to_string()),
                ..Default::default()
            };
            let result = logic.login("1001", &params).await;

            // A10: login 应返回 Err(NotPermission) 而非成功
            assert!(
                result.is_err(),
                "strict 模式新设备 login 应被 hard block 阻断（A10 修复）"
            );
            match result {
                Err(GarrisonError::NotPermission(msg)) => {
                    assert_eq!(
                        msg, "secondary auth required",
                        "错误消息应为 'secondary auth required'"
                    );
                },
                Err(other) => panic!("期望 NotPermission 错误，实际: {:?}", other),
                Ok(_) => panic!("strict 模式新设备 login 不应成功（A10 hard block）"),
            }
        }

        /// A10 修复：strict 模式新设备 login 被阻断后不创建 session（无孤儿会话泄漏）。
        #[tokio::test]
        async fn test_strict_mode_new_device_block_creates_no_session() {
            let logic = make_logic_base();
            let policy = Arc::new(StrictBinding::new(logic.session.clone()));
            let logic = logic.with_device_binding_policy(policy);

            let params = LoginParams {
                device: Some("web-chrome".to_string()),
                ..Default::default()
            };
            // login 被阻断
            let _ = logic.login("1001", &params).await;

            // 验证无 session 被创建
            let tokens = logic.session.get_tokens_by_login_id("1001");
            assert!(
                tokens.is_empty(),
                "hard block 后不应创建任何 session（无孤儿会话）"
            );
        }

        /// strict 模式下旧设备 login 不触发 MFA（policy.is_new_device=false →
        /// require_secondary_auth 不调用 → params.require_mfa=false）。
        #[tokio::test]
        async fn test_strict_mode_old_device_no_mfa() {
            let logic = make_logic_base();
            // 预创建带 device="web-chrome" 的历史 session
            let pre_params = LoginParams {
                device: Some("web-chrome".to_string()),
                ..Default::default()
            };
            logic
                .session
                .create_token_session("1001", "pre-token-T2", &pre_params)
                .await
                .unwrap();

            // 注入 StrictBinding
            let policy = Arc::new(StrictBinding::new(logic.session.clone()));
            let logic = logic.with_device_binding_policy(policy);

            // 用同一 device 登录 → is_new_device=false → require_mfa 不触发
            let params = LoginParams {
                device: Some("web-chrome".to_string()),
                ..Default::default()
            };
            let token = logic
                .login("1001", &params)
                .await
                .expect("strict 模式旧设备 login 应成功");

            assert!(!token.is_empty(), "login 应返回非空 token");
            assert_ne!(token, "pre-token-T2", "应创建新 token（is_share=false）");
            // 验证新 session 已创建
            let ts = logic
                .session
                .get_token_session(&token)
                .await
                .unwrap()
                .expect("新会话应已创建");
            assert_eq!(ts.device.as_deref(), Some("web-chrome"));
        }

        /// loose 模式下新设备 login 广播告警但不阻断（require_secondary_auth=false →
        /// params.require_mfa=false），AlertListener 收到 NewDeviceLogin 事件。
        #[tokio::test]
        async fn test_loose_mode_new_device_alerts_no_block() {
            let listener = Arc::new(CountingAlertListener::new());
            let manager = Arc::new(AlertListenerManager::new());
            manager.add_listener(listener.clone() as Arc<dyn AlertListener>);

            let logic = make_logic_base();
            // 注入 LooseBinding（带告警管理器）
            let policy = Arc::new(LooseBinding::with_alert_manager(
                logic.session.clone(),
                manager,
            ));
            let logic = logic.with_device_binding_policy(policy);

            // 无历史 session → is_new_device=true → require_secondary_auth 广播告警 + 返回 false
            let params = LoginParams {
                device: Some("mobile-ios".to_string()),
                ..Default::default()
            };
            let token = logic
                .login("1001", &params)
                .await
                .expect("loose 模式新设备 login 应成功（不阻断）");

            assert!(!token.is_empty(), "login 应返回非空 token");
            // 验证告警已广播
            assert_eq!(
                listener.count(),
                1,
                "loose 模式新设备应广播 1 次 NewDeviceLogin 告警"
            );
            let events = listener.events();
            match &events[0] {
                SecurityAlertEvent::NewDeviceLogin {
                    login_id,
                    device_id,
                    ..
                } => {
                    assert_eq!(login_id, "1001");
                    assert_eq!(device_id, "mobile-ios");
                },
                other => panic!("期望 NewDeviceLogin 事件，实际: {:?}", other),
            }
        }

        /// disabled 模式下任何设备 login 不受影响（is_new_device=false →
        /// require_secondary_auth 不调用 → params.require_mfa=false）。
        #[tokio::test]
        async fn test_disabled_mode_no_impact() {
            let logic = make_logic_base();
            let policy = Arc::new(Disabled);
            let logic = logic.with_device_binding_policy(policy);

            let params = LoginParams {
                device: Some("any-device".to_string()),
                ..Default::default()
            };
            let token = logic
                .login("1001", &params)
                .await
                .expect("disabled 模式 login 应成功");

            assert!(!token.is_empty(), "login 应返回非空 token");
            let ts = logic
                .session
                .get_token_session(&token)
                .await
                .unwrap()
                .expect("会话应已创建");
            assert_eq!(ts.login_id, "1001");
        }

        /// 未注入 policy 时 login 正常工作（向后兼容），params.require_mfa=false。
        #[tokio::test]
        async fn test_no_policy_backward_compatible() {
            let logic = make_logic_base();
            // 不注入 device_binding_policy

            let params = LoginParams {
                device: Some("web-chrome".to_string()),
                ..Default::default()
            };
            let token = logic
                .login("1001", &params)
                .await
                .expect("未注入 policy 时 login 应正常工作");

            assert!(!token.is_empty(), "login 应返回非空 token");
            let ts = logic
                .session
                .get_token_session(&token)
                .await
                .unwrap()
                .expect("会话应已创建");
            assert_eq!(ts.login_id, "1001");
        }

        /// LoginParams::default().require_mfa 默认为 false。
        #[test]
        fn test_require_mfa_default_false() {
            let params = LoginParams::default();
            assert!(
                !params.require_mfa,
                "LoginParams::default().require_mfa 应为 false"
            );
        }
    }

    // ========================================================================
    // T014: three-tier-cache 集成测试（three-tier-cache feature）
    // 验证 R-three-tier-cache-005: logout/logout_by_login_id 调用 invalidate
    // ========================================================================

    #[cfg(feature = "three-tier-cache")]
    mod three_tier_cache_integration {
        use super::*;
        use crate::cache::UserCacheService;
        use crate::dao::GarrisonDao;
        use crate::session::GarrisonSession;
        use crate::stp::with_current_token;
        use crate::strategy::GarrisonPermissionStrategy;
        use async_trait::async_trait;
        use parking_lot::Mutex;
        use std::collections::HashMap;
        use std::sync::atomic::{AtomicU32, Ordering};
        use std::sync::Arc;
        use std::time::{Duration, Instant};

        /// 计数 DAO：记录 delete 调用次数与 key 列表。
        struct CountingDao {
            store: Mutex<HashMap<String, (String, Option<Instant>)>>,
            delete_count: AtomicU32,
            delete_keys: Mutex<Vec<String>>,
        }

        impl CountingDao {
            fn new() -> Self {
                Self {
                    store: Mutex::new(HashMap::new()),
                    delete_count: AtomicU32::new(0),
                    delete_keys: Mutex::new(Vec::new()),
                }
            }

            fn delete_count(&self) -> u32 {
                self.delete_count.load(Ordering::SeqCst)
            }

            fn delete_keys(&self) -> Vec<String> {
                self.delete_keys.lock().clone()
            }

            /// 直接插入（绕过 TTL 逻辑，测试预备数据用）。
            fn insert_direct(&self, key: &str, value: &str) {
                self.store
                    .lock()
                    .insert(key.to_string(), (value.to_string(), None));
            }
        }

        #[async_trait]
        impl GarrisonDao for CountingDao {
            async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
                let mut store = self.store.lock();
                match store.get(key) {
                    Some((value, expire_at)) => {
                        if let Some(deadline) = expire_at {
                            if Instant::now() >= *deadline {
                                store.remove(key);
                                return Ok(None);
                            }
                        }
                        Ok(Some(value.clone()))
                    },
                    None => Ok(None),
                }
            }

            async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
                let expire_at = if ttl_seconds == 0 {
                    None
                } else {
                    Some(Instant::now() + Duration::from_secs(ttl_seconds))
                };
                self.store
                    .lock()
                    .insert(key.to_string(), (value.to_string(), expire_at));
                Ok(())
            }

            async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
                let mut store = self.store.lock();
                match store.get_mut(key) {
                    Some((existing, _)) => {
                        *existing = value.to_string();
                        Ok(())
                    },
                    None => Err(GarrisonError::Dao(format!("dao-key-not-found::{}", key))),
                }
            }

            async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
                let mut store = self.store.lock();
                match store.get_mut(key) {
                    Some((_, expire_at)) => {
                        *expire_at = if seconds == 0 {
                            None
                        } else {
                            Some(Instant::now() + Duration::from_secs(seconds))
                        };
                        Ok(())
                    },
                    None => Err(GarrisonError::Dao(format!("dao-key-not-found::{}", key))),
                }
            }

            async fn delete(&self, key: &str) -> GarrisonResult<()> {
                self.delete_count.fetch_add(1, Ordering::SeqCst);
                self.delete_keys.lock().push(key.to_string());
                self.store.lock().remove(key);
                Ok(())
            }
            crate::atomic_test_fallback!();
        }

        /// 最小 firewall mock（提供 L3 回调数据源）。
        struct MockFirewall;

        #[async_trait]
        impl GarrisonPermissionStrategy for MockFirewall {
            async fn check_permission(
                &self,
                _login_id: &str,
                _permission: &str,
            ) -> GarrisonResult<bool> {
                Ok(true)
            }

            async fn check_role(&self, _login_id: &str, _role: &str) -> GarrisonResult<bool> {
                Ok(true)
            }

            async fn check_role_any(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> GarrisonResult<bool> {
                Ok(true)
            }

            async fn check_role_all(
                &self,
                _login_id: &str,
                _roles: &[&str],
            ) -> GarrisonResult<bool> {
                Ok(true)
            }

            async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
                Ok(vec!["user:read".to_string()])
            }

            async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
                Ok(vec!["admin".to_string()])
            }

            async fn get_user_info(&self, _login_id: &str) -> GarrisonResult<Option<String>> {
                Ok(Some("user-info".to_string()))
            }
        }

        /// 构造带 UserCacheService 的 GarrisonLogicDefault。
        fn make_logic_with_cache(dao: Arc<CountingDao>) -> GarrisonLogicDefault {
            let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall);
            let cache_service = Arc::new(
                UserCacheService::new(
                    dao.clone() as Arc<dyn GarrisonDao>,
                    firewall.clone(),
                    30,
                    300,
                    10_000,
                )
                .expect("UserCacheService::new 应成功"),
            );
            GarrisonLogicDefault::new(session, Arc::new(config), firewall)
                .with_user_cache_service(cache_service)
        }

        /// logout() 注入 cache service 时应调用 invalidate（删除 perm/role/user 3 个缓存 key）。
        #[tokio::test]
        async fn logout_invalidates_user_cache() {
            // atomic + 默认 trait 方法覆盖
            {
                let d = CountingDao::new();
                let _ = d.set_if_absent("a", "v", 60).await;
                let _ = d.get_and_delete("a").await;
                let _ = d.incr("c", 60).await;
                let _ = d.decr("c").await;
                let _ = d.rename("a", "b").await;
                let _ = d.compare_and_swap("b", None, "v", 60).await;
                let _ = d.set_permanent("p", "v").await;
                let _ = d.get_timeout("k").await;
                let _ = d.get_with_ttl("k").await;
                let _ = d.keys("*").await;
                let _ = d.find_social_binding(0, "w", "o").await;
                let _ = d.insert_social_binding(0, "u", "w", "o", None, 0).await;
                let _ = d.compare_and_update_if_greater("k", 1, 60).await;
                let _ = d.eval_lua("r", vec![], vec![]).await;
                let _ = d.insert_credit_consumption(0, "r", 1, 1, 1, 0).await;
                let _ = d.query_credit_consumption(0, 0, 0).await;
                let _ = d.query_role_hierarchy_edges(0).await;
                let _ = d.insert_role_hierarchy_edge(0, "c", "p").await;
                let _ = d.delete_role_hierarchy_edge(0, "c", "p").await;
            }
            let dao = Arc::new(CountingDao::new());
            let logic = Arc::new(make_logic_with_cache(dao.clone()));

            // 登录用户
            let token = logic
                .login("1001", &LoginParams::default())
                .await
                .expect("login 应成功");

            // 预填充缓存（模拟 get_permissions 已调用过）
            dao.insert_direct("perm:cache:1001", r#"["user:read"]"#);
            dao.insert_direct("role:cache:1001", r#"["admin"]"#);
            dao.insert_direct("user:cache:1001", r#""user-info""#);
            assert_eq!(dao.delete_count(), 0, "预填充后 delete 次数应为 0");

            // 调用 logout（需设置 current_token task-local）
            with_current_token(token, async {
                logic.logout().await.expect("logout 应成功");
            })
            .await;

            // 验证 invalidate 被调用：perm/role/user 3 个缓存 key 在删除列表中
            // （总 delete 次数可能包含 session.logout 销毁 token-session 的 delete）
            let deleted = dao.delete_keys();
            assert!(
                deleted.contains(&"perm:cache:1001".to_string()),
                "logout 应删除 perm:cache:1001，实际删除: {:?}",
                deleted
            );
            assert!(
                deleted.contains(&"role:cache:1001".to_string()),
                "logout 应删除 role:cache:1001"
            );
            assert!(
                deleted.contains(&"user:cache:1001".to_string()),
                "logout 应删除 user:cache:1001"
            );
        }

        /// logout_by_login_id() 注入 cache service 时应调用 invalidate。
        #[tokio::test]
        async fn logout_by_login_id_invalidates_user_cache() {
            let dao = Arc::new(CountingDao::new());
            let logic = Arc::new(make_logic_with_cache(dao.clone()));

            // 登录用户
            let _token = logic
                .login("2002", &LoginParams::default())
                .await
                .expect("login 应成功");

            // 预填充缓存
            dao.insert_direct("perm:cache:2002", r#"["user:read"]"#);
            dao.insert_direct("role:cache:2002", r#"["admin"]"#);
            dao.insert_direct("user:cache:2002", r#""user-info""#);

            logic
                .logout_by_login_id("2002")
                .await
                .expect("logout_by_login_id 应成功");

            // 验证 perm/role/user 3 个缓存 key 被删除
            let deleted = dao.delete_keys();
            assert!(deleted.contains(&"perm:cache:2002".to_string()));
            assert!(deleted.contains(&"role:cache:2002".to_string()));
            assert!(deleted.contains(&"user:cache:2002".to_string()));
        }

        /// 未注入 cache service 时 logout 不 panic（向后兼容）。
        #[tokio::test]
        async fn logout_without_cache_service_backward_compatible() {
            let dao: Arc<dyn GarrisonDao> = Arc::new(CountingDao::new());
            let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall);
            // 不注入 user_cache_service
            let logic = Arc::new(GarrisonLogicDefault::new(
                session,
                Arc::new(config),
                firewall,
            ));

            let token = logic
                .login("3003", &LoginParams::default())
                .await
                .expect("login 应成功");

            with_current_token(token, async {
                logic.logout().await.expect("logout 应成功（无缓存服务）");
            })
            .await;
        }
    }

    // ========================================================================
    // 覆盖率补充测试：覆盖 check_login 三种模式、auto_renewal、错误路径等
    // 使用 `GarrisonLogicDefault` + `crate::stp::mock::{MockDao, MockFirewall}`
    // ========================================================================

    mod session_coverage_tests {
        use super::*;
        use crate::dao::GarrisonDao;
        use crate::session::GarrisonSession;
        use crate::stp::mock::{MockDao, MockFirewall};
        use crate::stp::with_current_token;
        use crate::strategy::GarrisonPermissionStrategy;
        use std::sync::Arc;

        // --------------------------------------------------------------------
        // 辅助函数
        // --------------------------------------------------------------------

        /// 创建基础 GarrisonLogicDefault（uuid token_style，throw 可配置）。
        fn make_logic(throw_on_not_login: bool) -> GarrisonLogicDefault {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = throw_on_not_login;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            GarrisonLogicDefault::new(session, Arc::new(config), firewall)
        }

        /// 创建 JWT 模式 GarrisonLogicDefault（token_style=jwt + 自定义 jwt_secret + jwt_mode）。
        #[cfg(feature = "protocol-jwt")]
        fn make_jwt_logic(
            throw_on_not_login: bool,
            jwt_mode: JwtMode,
            secret: &str,
        ) -> GarrisonLogicDefault {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = throw_on_not_login;
            // 安全默认：stateless JWT 必须启用撤销（T017 互斥校验），
            // 需要无撤销组合的测试请自行构造 config。
            config.enable_jwt_revocation = true;
            config.token_style = "jwt".to_string();
            config.jwt_secret = secret.to_string().into();
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            GarrisonLogicDefault::new(session, Arc::new(config), firewall).with_jwt_mode(jwt_mode)
        }

        // --------------------------------------------------------------------
        // check_login：无 token 路径
        // --------------------------------------------------------------------

        /// 无 current_token + throw_on_not_login=true → Err Session("未登录")。
        #[tokio::test]
        async fn check_login_no_token_throws_when_configured() {
            let logic = make_logic(true);
            let result = logic.check_login().await;
            assert!(
                matches!(result, Err(GarrisonError::Session(ref msg)) if msg == "stp-not-login::"),
                "无 token + throw_on_not_login=true 应返回 Err(Session(\"stp-not-login::\"))，实际: {:?}",
                result
            );
        }

        /// 无 current_token + throw_on_not_login=false → Ok(false)。
        #[tokio::test]
        async fn check_login_no_token_returns_false_when_not_throwing() {
            let logic = make_logic(false);
            let result = logic.check_login().await;
            assert!(
                result.is_ok(),
                "无 token + throw_on_not_login=false 应返回 Ok，实际: {:?}",
                result
            );
            assert!(
                !result.unwrap(),
                "无 token + throw_on_not_login=false 应返回 false"
            );
        }

        // --------------------------------------------------------------------
        // check_login_stateless 测试（需 protocol-jwt feature）
        // --------------------------------------------------------------------

        /// Stateless 模式 + 有效 JWT → Ok(true)。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn check_login_stateless_valid_jwt_returns_true() {
            let secret = "coverage-secret-stateless-valid-32bytes!!";
            // 安全组合：jwt_mode=Stateless + enable_jwt_revocation=true（T017 互斥校验要求）
            let logic = make_jwt_logic(true, JwtMode::Stateless, secret);
            let handler = crate::protocol::jwt::JwtHandler::new(secret);
            let jwt_token = handler
                .sign("stateless-user-001", 3600)
                .expect("JWT 签发应成功");

            let result = with_current_token(jwt_token, async { logic.check_login().await }).await;
            assert!(
                result.is_ok(),
                "Stateless + 有效 JWT 应返回 Ok，实际: {:?}",
                result
            );
            assert!(result.unwrap(), "Stateless + 有效 JWT 应返回 true");
        }

        /// Stateless 模式 + 无效 JWT → Err InvalidToken。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn check_login_stateless_invalid_token_returns_error() {
            let logic = make_jwt_logic(
                true,
                JwtMode::Stateless,
                "coverage-secret-stateless-0123456789",
            );
            let result = with_current_token("invalid.jwt.token".to_string(), async {
                logic.check_login().await
            })
            .await;
            assert!(
                matches!(result, Err(GarrisonError::InvalidToken(_))),
                "Stateless + 无效 JWT 应返回 Err(InvalidToken)，实际: {:?}",
                result
            );
        }

        /// Stateless 模式 + token_style != jwt → Err Config。
        #[cfg(feature = "protocol-jwt")]
        #[serial]
        #[tokio::test]
        async fn check_login_stateless_wrong_token_style_returns_config_error() {
            // token_style=uuid 但 jwt_mode=Stateless
            let logic = make_logic(false).with_jwt_mode(JwtMode::Stateless);
            let result =
                with_current_token("any-token".to_string(), async { logic.check_login().await })
                    .await;
            assert!(
                matches!(result, Err(GarrisonError::Config(ref msg)) if msg.contains("stp-stateless-requires")),
                "Stateless + token_style=uuid 应返回 Err(Config(...Stateless...))，实际: {:?}",
                result
            );
        }

        /// T017：token_style=jwt + jwt_mode=Stateless + enable_jwt_revocation=false 互斥，
        /// 启动校验 fail-closed 返回 Config 错误（不可吊销的永久 JWT 凭证）。不依赖 token 合法性。
        #[cfg(feature = "protocol-jwt")]
        #[serial]
        #[tokio::test]
        async fn check_login_stateless_without_revocation_rejected() {
            let mut config = GarrisonConfig::default_config();
            config.token_style = "jwt".to_string();
            config.enable_jwt_revocation = false;
            config.allow_stateless_jwt_no_revocation = false;
            config.throw_on_not_login = false;
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
            let firewall = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = GarrisonLogicDefault::new(session, Arc::new(config), firewall)
                .with_jwt_mode(JwtMode::Stateless);
            let result = with_current_token("any.token.here".to_string(), async {
                logic.check_login().await
            })
            .await;
            assert!(
                matches!(result, Err(GarrisonError::Config(ref msg)) if msg.contains("stp-stateless-jwt-requires-revocation")),
                "stateless JWT 未启用撤销应 fail-closed 返回 Config 错误，实际: {:?}",
                result
            );
        }

        /// T017 正例：启用 `allow_stateless_jwt_no_revocation` 风险接受开关后，
        /// 该组合被放行（需有效 JWT 才能真正通过 verify）。
        #[cfg(feature = "protocol-jwt")]
        #[serial]
        #[tokio::test]
        async fn check_login_stateless_risk_accept_flag_allows() {
            let secret = "coverage-secret-stateless-0123456789";
            let mut config = GarrisonConfig::default_config();
            config.token_style = "jwt".to_string();
            config.enable_jwt_revocation = false;
            config.allow_stateless_jwt_no_revocation = true;
            config.throw_on_not_login = false;
            config.jwt_secret = secret.to_string().into();
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
            let firewall = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = GarrisonLogicDefault::new(session, Arc::new(config), firewall)
                .with_jwt_mode(JwtMode::Stateless);
            let handler = crate::protocol::jwt::JwtHandler::new(secret);
            let jwt_token = handler.sign("risk-accept-user", 3600).unwrap();
            let result = with_current_token(jwt_token, async { logic.check_login().await }).await;
            assert!(
                matches!(result, Ok(true)),
                "显式风险接受开关开启时 stateless JWT 应放行（有效 JWT），实际: {:?}",
                result
            );
        }

        // --------------------------------------------------------------------
        // check_login_simple 测试
        // --------------------------------------------------------------------

        /// Simple 模式 + 无效 token + throw_on_not_login=false → Ok(false)。
        #[tokio::test]
        async fn check_login_simple_invalid_token_returns_false() {
            let logic = make_logic(false).with_jwt_mode(JwtMode::Simple);
            let result = with_current_token("nonexistent-token".to_string(), async {
                logic.check_login().await
            })
            .await;
            assert!(
                result.is_ok(),
                "Simple + 无效 token + throw=false 应返回 Ok，实际: {:?}",
                result
            );
            assert!(
                !result.unwrap(),
                "Simple + 无效 token + throw=false 应返回 false"
            );
        }

        // --------------------------------------------------------------------
        // check_login_mixin 测试（默认模式，无效 token 路径）
        // --------------------------------------------------------------------

        /// Mixin 模式 + 无效 token + throw_on_not_login=true → Err Session。
        #[tokio::test]
        async fn check_login_mixin_invalid_token_throws() {
            let logic = make_logic(true).with_jwt_mode(JwtMode::Mixin);
            let result = with_current_token("nonexistent-token".to_string(), async {
                logic.check_login().await
            })
            .await;
            assert!(
                matches!(result, Err(GarrisonError::Session(ref msg)) if msg == "stp-not-login::"),
                "Mixin + 无效 token + throw=true 应返回 Err(Session(\"stp-not-login::\"))，实际: {:?}",
                result
            );
        }

        // --------------------------------------------------------------------
        // check_and_renew 测试（auto_renewal_threshold 路径）
        // --------------------------------------------------------------------

        /// threshold <= 0 → Ok(None)（未启用续签）。
        #[tokio::test]
        async fn check_and_renew_threshold_zero_returns_none() {
            let logic = make_logic(false);
            let result = logic.check_and_renew("any-token").await;
            assert!(
                result.is_ok(),
                "threshold <= 0 应返回 Ok，实际: {:?}",
                result
            );
            assert!(
                result.unwrap().is_none(),
                "threshold <= 0 应返回 None（未启用续签）"
            );
        }

        /// threshold > 0 + TTL 充足 → Ok(None)（无需续签）。
        #[tokio::test]
        async fn check_and_renew_ttl_sufficient_returns_none() {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            // session timeout=3600s，与 config.timeout 对齐以避免百分比计算偏差
            let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            config.auto_renewal_threshold = 50;
            config.timeout = 3600;
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = GarrisonLogicDefault::new(session, Arc::new(config), firewall);

            let token = logic
                .login("renew-user-001", &LoginParams::default())
                .await
                .unwrap();
            let result = logic.check_and_renew(&token).await;
            assert!(result.is_ok(), "TTL 充足应返回 Ok，实际: {:?}", result);
            assert!(result.unwrap().is_none(), "TTL 充足应返回 None（无需续签）");
        }

        /// threshold > 0 + TTL 低于阈值 + 无 auth_logic → Err Config（非 JWT 路径）。
        #[cfg(feature = "protocol-jwt")]
        #[tokio::test]
        async fn check_and_renew_no_auth_logic_returns_config_error() {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            // session timeout=5s，与 config.timeout 对齐
            let session = Arc::new(GarrisonSession::new(dao, 5, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            config.auto_renewal_threshold = 95;
            config.timeout = 5;
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = GarrisonLogicDefault::new(session, Arc::new(config), firewall);

            let token = logic
                .login("renew-user-002", &LoginParams::default())
                .await
                .unwrap();
            // 等待 TTL 衰减至阈值以下（5s * 5% = 250ms 后即低于 95%）
            tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
            let result = logic.check_and_renew(&token).await;
            assert!(
                matches!(result, Err(GarrisonError::Config(ref msg)) if msg.contains("stp-auto-renewal-no-auth-logic")),
                "TTL 低 + 无 auth_logic 应返回 Err(Config(...auth_logic...))，实际: {:?}",
                result
            );
        }

        // --------------------------------------------------------------------
        // generate_token 错误路径
        // --------------------------------------------------------------------

        /// 未知 token_style → Err Config("config-unknown-token-style")。
        #[tokio::test]
        async fn generate_token_unknown_style_returns_config_error() {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "unknown-style".to_string();
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = GarrisonLogicDefault::new(session, Arc::new(config), firewall);

            let result = logic.login("test-user", &LoginParams::default()).await;
            assert!(
                matches!(result, Err(GarrisonError::Config(ref msg)) if msg.contains("stp-unknown-token-style")),
                "未知 token_style 应返回 Err(Config(...stp-unknown-token-style...))，实际: {:?}",
                result
            );
        }

        // --------------------------------------------------------------------
        // refresh_access_token 错误路径
        // --------------------------------------------------------------------

        /// 未注入 RefreshTokenRotation → Err NotImplemented。
        #[tokio::test]
        async fn refresh_access_token_returns_not_implemented() {
            let logic = make_logic(false);
            let result = logic.refresh_access_token("any-refresh-token").await;
            assert!(
                matches!(result, Err(GarrisonError::NotImplemented(_))),
                "未注入 RefreshTokenRotation 应返回 Err(NotImplemented)，实际: {:?}",
                result
            );
        }

        // --------------------------------------------------------------------
        // revoke_all_sessions 测试
        // --------------------------------------------------------------------

        /// 无 token 时返回 0。
        #[tokio::test]
        async fn revoke_all_sessions_returns_zero_for_no_tokens() {
            let logic = make_logic(false);
            let count = logic.revoke_all_sessions("no-sessions-user").await.unwrap();
            assert_eq!(count, 0, "无 token 时应返回 0，实际: {}", count);
        }

        /// 有 token 时全部吊销并返回 count。
        #[tokio::test]
        async fn revoke_all_sessions_revokes_all_tokens() {
            let logic = make_logic(false);
            let t1 = logic
                .login("revoke-user-001", &LoginParams::default())
                .await
                .unwrap();
            let t2 = logic
                .login("revoke-user-001", &LoginParams::default())
                .await
                .unwrap();
            let t3 = logic
                .login("revoke-user-001", &LoginParams::default())
                .await
                .unwrap();

            let count = logic.revoke_all_sessions("revoke-user-001").await.unwrap();
            assert_eq!(count, 3, "应吊销 3 个会话，实际: {}", count);

            // 验证所有 token 已被吊销
            assert!(
                logic
                    .session
                    .get_token_session(&t1)
                    .await
                    .unwrap()
                    .is_none(),
                "t1 应被吊销"
            );
            assert!(
                logic
                    .session
                    .get_token_session(&t2)
                    .await
                    .unwrap()
                    .is_none(),
                "t2 应被吊销"
            );
            assert!(
                logic
                    .session
                    .get_token_session(&t3)
                    .await
                    .unwrap()
                    .is_none(),
                "t3 应被吊销"
            );
        }

        // --------------------------------------------------------------------
        // get_active_sessions 测试
        // --------------------------------------------------------------------

        /// get_active_sessions 过滤掉失效 token。
        #[tokio::test]
        async fn get_active_sessions_filters_invalid_tokens() {
            let logic = make_logic(false);
            let t1 = logic
                .login("active-user-001", &LoginParams::default())
                .await
                .unwrap();
            let t2 = logic
                .login("active-user-001", &LoginParams::default())
                .await
                .unwrap();
            // 手动吊销 t1（模拟 token 失效）
            logic.session.logout(&t1).await.unwrap();

            let active = logic.get_active_sessions("active-user-001").await.unwrap();
            assert_eq!(
                active.len(),
                1,
                "应只有 1 个活跃会话（t2），实际: {}",
                active.len()
            );
            assert_eq!(active[0], t2, "活跃会话应为 t2，实际: {:?}", active);
        }

        // --------------------------------------------------------------------
        // get_login_id 测试
        // --------------------------------------------------------------------

        /// 无 current_token → Ok(None)。
        #[tokio::test]
        async fn get_login_id_no_current_token_returns_none() {
            let logic = make_logic(false);
            let result = logic.get_login_id().await;
            assert!(
                result.is_ok(),
                "无 current_token 应返回 Ok，实际: {:?}",
                result
            );
            assert!(result.unwrap().is_none(), "无 current_token 应返回 None");
        }

        // --------------------------------------------------------------------
        // login_inner: is_share 路径
        // --------------------------------------------------------------------

        /// is_share=true 时复用现有有效 token。
        #[tokio::test]
        async fn login_with_is_share_reuses_existing_token() {
            let mut logic = make_logic(false);
            Arc::make_mut(&mut logic.config).is_share = true;

            let t1 = logic
                .login("share-valid-001", &LoginParams::default())
                .await
                .unwrap();
            let t2 = logic
                .login("share-valid-001", &LoginParams::default())
                .await
                .unwrap();
            assert_eq!(t1, t2, "is_share=true 应复用现有有效 token");
        }

        /// is_share=true + token 已失效 → 清理后创建新会话。
        #[tokio::test]
        async fn login_with_is_share_creates_new_when_existing_invalid() {
            let mut logic = make_logic(false);
            Arc::make_mut(&mut logic.config).is_share = true;

            let t1 = logic
                .login("share-invalid-001", &LoginParams::default())
                .await
                .unwrap();
            // 手动吊销 t1（模拟 token 失效）
            logic.session.logout(&t1).await.unwrap();
            assert!(
                logic
                    .session
                    .get_token_session(&t1)
                    .await
                    .unwrap()
                    .is_none(),
                "t1 应已失效"
            );

            // 第二次登录：is_share=true 但旧 token 失效，应创建新 token
            let t2 = logic
                .login("share-invalid-001", &LoginParams::default())
                .await
                .unwrap();
            assert_ne!(t1, t2, "is_share=true 但旧 token 失效时应创建新 token");
            assert!(
                logic
                    .session
                    .get_token_session(&t2)
                    .await
                    .unwrap()
                    .is_some(),
                "新 token 应有对应 session"
            );
        }

        // --------------------------------------------------------------------
        // login_inner: NewDevice 模式（is_concurrent=false）允许首次登录
        // --------------------------------------------------------------------

        /// NewDevice 模式 + 无旧会话 → 允许登录。
        #[tokio::test]
        async fn login_new_device_mode_allows_first_login() {
            let mut logic = make_logic(false);
            Arc::make_mut(&mut logic.config).is_concurrent = false;
            Arc::make_mut(&mut logic.config).replaced_login_exit_mode =
                ReplacedLoginExitMode::NewDevice;

            let token = logic
                .login("new-device-first-001", &LoginParams::default())
                .await;
            assert!(
                token.is_ok(),
                "NewDevice 模式 + 无旧会话应允许登录，实际: {:?}",
                token
            );
            assert!(!token.unwrap().is_empty(), "应返回非空 token");
        }

        // ==================================================================
        // Listener 广播测试：logout / kickout / revoke_token
        // ==================================================================

        #[cfg(feature = "listener")]
        mod listener_tests {
            use super::*;
            use crate::config::OverflowLogoutMode;
            use crate::listener::{GarrisonEvent, GarrisonListener, GarrisonListenerManager};
            use crate::stp::{Clock, MockClock};
            use parking_lot::Mutex;

            /// 记录事件监听器，捕获广播的 GarrisonEvent 用于断言。
            struct RecordingListener {
                events: Mutex<Vec<GarrisonEvent>>,
            }

            impl RecordingListener {
                fn new() -> Self {
                    Self {
                        events: Mutex::new(Vec::new()),
                    }
                }

                fn captured(&self) -> Vec<GarrisonEvent> {
                    self.events.lock().clone()
                }
            }

            #[async_trait]
            impl GarrisonListener for RecordingListener {
                async fn on_event(
                    &self,
                    event: &GarrisonEvent,
                ) -> crate::error::GarrisonResult<()> {
                    self.events.lock().push(event.clone());
                    Ok(())
                }
            }

            /// 创建带 listener_manager 的 GarrisonLogicDefault，返回 (logic, recorder)。
            fn make_logic_with_listener(
                throw_on_not_login: bool,
            ) -> (GarrisonLogicDefault, Arc<RecordingListener>) {
                let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
                let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
                let mut config = GarrisonConfig::default_config();
                config.throw_on_not_login = throw_on_not_login;
                config.token_style = "uuid".to_string();
                let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                    has_permission: true,
                    has_role: true,
                });
                let recorder = Arc::new(RecordingListener::new());
                let lm = Arc::new(GarrisonListenerManager::new());
                lm.register(recorder.clone() as Arc<dyn GarrisonListener>);
                let logic = GarrisonLogicDefault::new(session, Arc::new(config), firewall)
                    .with_listener_manager(lm);
                (logic, recorder)
            }

            /// logout 广播 Logout 事件。
            ///
            /// 覆盖 lines 251-286：current_token 存在 → session.logout → broadcast Logout。
            #[tokio::test]
            async fn logout_broadcasts_logout_event() {
                let (logic, recorder) = make_logic_with_listener(false);
                let token = logic
                    .login("logout-user-001", &LoginParams::default())
                    .await
                    .unwrap();

                let result =
                    with_current_token(token.clone(), async { logic.logout().await }).await;
                assert!(result.is_ok(), "logout 应返回 Ok，实际: {:?}", result);

                let events = recorder.captured();
                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        GarrisonEvent::Logout {
                            login_id,
                            token: t,
                            ..
                        } if login_id == "logout-user-001" && t == &token
                    )),
                    "应广播 Logout 事件 (login_id=logout-user-001)，实际事件: {:?}",
                    events
                );
            }

            /// kickout 广播 Kickout 事件。
            ///
            /// 覆盖 lines 300-315：logout_by_login_id → broadcast Kickout。
            #[tokio::test]
            async fn kickout_broadcasts_kickout_event() {
                let (logic, recorder) = make_logic_with_listener(false);
                logic
                    .login("kickout-user-001", &LoginParams::default())
                    .await
                    .unwrap();

                let result = logic.kickout("kickout-user-001").await;
                assert!(result.is_ok(), "kickout 应返回 Ok，实际: {:?}", result);

                let events = recorder.captured();
                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        GarrisonEvent::Kickout {
                            login_id,
                            reason,
                            ..
                        } if login_id == "kickout-user-001" && reason == "管理员强制下线"
                    )),
                    "应广播 Kickout 事件 (login_id=kickout-user-001)，实际事件: {:?}",
                    events
                );
            }

            /// revoke_token 广播 RevokeToken 事件。
            ///
            /// 覆盖 lines 322-335：session.logout → broadcast RevokeToken。
            #[tokio::test]
            async fn revoke_token_broadcasts_revoke_event() {
                let (logic, recorder) = make_logic_with_listener(false);
                let token = logic
                    .login("revoke-user-001", &LoginParams::default())
                    .await
                    .unwrap();

                let result = logic.revoke_token(&token).await;
                assert!(result.is_ok(), "revoke_token 应返回 Ok，实际: {:?}", result);

                let events = recorder.captured();
                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        GarrisonEvent::RevokeToken { token: t, .. } if t == &token
                    )),
                    "应广播 RevokeToken 事件 (token={})，实际事件: {:?}",
                    token,
                    events
                );
            }

            // ==================================================================
            // enforce_max_login_count 测试
            // ==================================================================

            /// max=0 时不做任何操作（no-op）。
            ///
            /// 覆盖 lines 647-649：max == 0 → return Ok(())。
            #[tokio::test]
            async fn enforce_max_login_count_zero_is_noop() {
                let logic = make_logic(false);
                let token = logic
                    .login("max-user-001", &LoginParams::default())
                    .await
                    .unwrap();

                let result = logic.enforce_max_login_count("max-user-001", 0).await;
                assert!(result.is_ok(), "max=0 应返回 Ok，实际: {:?}", result);
                assert!(
                    logic
                        .session
                        .get_token_session(&token)
                        .await
                        .unwrap()
                        .is_some(),
                    "max=0 时 session 应仍然存在"
                );
            }

            /// 超过 max_login_count 时踢出最旧会话，OverflowLogoutMode::Logout 广播 Logout 事件。
            ///
            /// 覆盖 lines 651-709（Logout 模式分支 lines 678-685）。
            #[tokio::test]
            async fn enforce_max_login_count_evicts_oldest_with_logout_mode() {
                let (logic, recorder) = make_logic_with_listener(false);
                let t1 = logic
                    .login("max-logout-001", &LoginParams::default())
                    .await
                    .unwrap();
                let _t2 = logic
                    .login("max-logout-001", &LoginParams::default())
                    .await
                    .unwrap();
                let _t3 = logic
                    .login("max-logout-001", &LoginParams::default())
                    .await
                    .unwrap();

                let result = logic.enforce_max_login_count("max-logout-001", 1).await;
                assert!(result.is_ok(), "enforce 应返回 Ok，实际: {:?}", result);
                // t1 是最旧的，应被踢出
                assert!(
                    logic
                        .session
                        .get_token_session(&t1)
                        .await
                        .unwrap()
                        .is_none(),
                    "最旧 token 应已被踢出"
                );

                let events = recorder.captured();
                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        GarrisonEvent::Logout { login_id, token, .. } if login_id == "max-logout-001"
                            && token == &t1
                    )),
                    "应广播 Logout 事件 (最旧 token 被踢出)，实际事件: {:?}",
                    events
                );
            }

            /// OverflowLogoutMode::Kickout 广播 Kickout 事件。
            ///
            /// 覆盖 lines 686-694（Kickout 模式分支）。
            #[tokio::test]
            async fn enforce_max_login_count_evicts_oldest_with_kickout_mode() {
                let (mut logic, recorder) = make_logic_with_listener(false);
                Arc::make_mut(&mut logic.config).overflow_logout_mode = OverflowLogoutMode::Kickout;
                let t1 = logic
                    .login("max-kickout-001", &LoginParams::default())
                    .await
                    .unwrap();
                let _t2 = logic
                    .login("max-kickout-001", &LoginParams::default())
                    .await
                    .unwrap();

                let result = logic.enforce_max_login_count("max-kickout-001", 1).await;
                assert!(result.is_ok(), "enforce 应返回 Ok，实际: {:?}", result);

                let events = recorder.captured();
                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        GarrisonEvent::Kickout {
                            login_id,
                            token,
                            reason,
                            ..
                        } if login_id == "max-kickout-001"
                            && token == &t1
                            && reason == "超过最大登录数限制"
                    )),
                    "应广播 Kickout 事件 (reason=超过最大登录数限制)，实际事件: {:?}",
                    events
                );
            }

            /// OverflowLogoutMode::Replaced 广播 Replaced 事件。
            ///
            /// 覆盖 lines 695-704（Replaced 模式分支）。
            #[tokio::test]
            async fn enforce_max_login_count_evicts_oldest_with_replaced_mode() {
                let (mut logic, recorder) = make_logic_with_listener(false);
                Arc::make_mut(&mut logic.config).overflow_logout_mode =
                    OverflowLogoutMode::Replaced;
                let t1 = logic
                    .login("max-replaced-001", &LoginParams::default())
                    .await
                    .unwrap();
                let _t2 = logic
                    .login("max-replaced-001", &LoginParams::default())
                    .await
                    .unwrap();

                let result = logic.enforce_max_login_count("max-replaced-001", 1).await;
                assert!(result.is_ok(), "enforce 应返回 Ok，实际: {:?}", result);

                let events = recorder.captured();
                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        GarrisonEvent::Replaced {
                            login_id,
                            token,
                            reason,
                            ..
                        } if login_id == "max-replaced-001" && token == &t1
                    )),
                    "应广播 Replaced 事件，实际事件: {:?}",
                    events
                );
            }

            // ==================================================================
            // login_by_token 测试（token_style=simple，verify_token 路径）
            // ==================================================================

            /// login_by_token 通过 verify_token 解析 login_id 并创建会话，广播 Login 事件。
            ///
            /// 覆盖 lines 416-440：无 auth_logic → self.verify_token → session.create → broadcast Login。
            ///
            /// A11: SimpleTokenStyle 改为 HMAC-SHA256 签名格式 `<login_id>\x1f<uuid>.<hmac>`，
            /// 需用 SimpleTokenStyle::new(secret).generate 生成合法 token（secret 与 config.jwt_secret 一致）。
            #[cfg(feature = "secure-simple-token")]
            #[tokio::test]
            async fn login_by_token_creates_session_and_broadcasts_login() {
                let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
                let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
                let mut config = GarrisonConfig::default_config();
                config.throw_on_not_login = false;
                config.token_style = "simple".to_string();
                // A11: simple 模式下 verify_token 委托 SimpleTokenStyle（需 HMAC），
                // 设置非空 jwt_secret 避免 fail-closed。
                const SESSION_SIMPLE_TEST_SECRET: &str =
                    "stp-session-simple-test-secret-0123456789";
                config.jwt_secret = SESSION_SIMPLE_TEST_SECRET.to_string().into();
                let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                    has_permission: true,
                    has_role: true,
                });
                let recorder = Arc::new(RecordingListener::new());
                let lm = Arc::new(GarrisonListenerManager::new());
                lm.register(recorder.clone() as Arc<dyn GarrisonListener>);
                let logic = GarrisonLogicDefault::new(session, Arc::new(config), firewall)
                    .with_listener_manager(lm);

                // A11: 用 SimpleTokenStyle 生成合法 HMAC token（与 verify_token 使用相同 secret）
                use crate::core::token::Token;
                let style = crate::core::token::SimpleTokenStyle::new(
                    SESSION_SIMPLE_TEST_SECRET.to_string(),
                );
                let external_token = style.generate("externaluser001", 3600).unwrap();
                let result = logic.login_by_token(&external_token).await;
                assert!(
                    result.is_ok(),
                    "login_by_token 应返回 Ok，实际: {:?}",
                    result
                );

                // 验证会话已创建
                assert!(
                    logic
                        .session
                        .get_token_session(&external_token)
                        .await
                        .unwrap()
                        .is_some(),
                    "login_by_token 后应存在 Token-Session"
                );

                let events = recorder.captured();
                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        GarrisonEvent::Login {
                            login_id,
                            token,
                            ..
                        } if login_id == "externaluser001" && token == &external_token
                    )),
                    "应广播 Login 事件 (login_id=externaluser001)，实际事件: {:?}",
                    events
                );
            }

            // ==================================================================
            // check_and_update_hover 测试（session_hover_timeout + MockClock）
            // ==================================================================

            /// 悬停超时后 check_login 返回 false 并广播 SessionTimeout 事件。
            ///
            /// 覆盖 lines 834-865：session_hover_timeout > 0 + last_active 过期 → logout + broadcast。
            #[tokio::test]
            async fn check_and_update_hover_evicts_on_timeout() {
                let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
                let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
                let mut config = GarrisonConfig::default_config();
                config.throw_on_not_login = false;
                config.token_style = "uuid".to_string();
                config.session_hover_timeout = 1; // 1 second
                let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                    has_permission: true,
                    has_role: true,
                });
                let clock = Arc::new(MockClock::new(chrono::Utc::now()));
                let recorder = Arc::new(RecordingListener::new());
                let lm = Arc::new(GarrisonListenerManager::new());
                lm.register(recorder.clone() as Arc<dyn GarrisonListener>);
                let logic = GarrisonLogicDefault::new(session, Arc::new(config), firewall)
                    .with_listener_manager(lm)
                    .with_clock(clock.clone() as Arc<dyn Clock>);

                let token = logic
                    .login("hover-user-001", &LoginParams::default())
                    .await
                    .unwrap();

                // 手动设置 last_active_at 为当前 MockClock 时间
                let now_millis = clock.now().timestamp_millis();
                logic
                    .session
                    .update_last_active_at("hover-user-001", now_millis);

                // 推进 MockClock 2 秒（超过 1 秒悬停超时）
                clock.advance(chrono::Duration::seconds(2));

                let result =
                    with_current_token(token.clone(), async { logic.check_login().await }).await;
                assert!(
                    result.is_ok(),
                    "悬停超时 + throw=false 时 check_login 应返回 Ok，实际: {:?}",
                    result
                );
                assert!(!result.unwrap(), "悬停超时后 check_login 应返回 false");

                let events = recorder.captured();
                assert!(
                    events.iter().any(|e| matches!(
                        e,
                        GarrisonEvent::SessionTimeout {
                            login_id,
                            token: t,
                            ..
                        } if login_id == "hover-user-001" && t == &token
                    )),
                    "应广播 SessionTimeout 事件，实际事件: {:?}",
                    events
                );
            }

            /// 悬停超时 + throw_on_not_login=true → Err(Session("会话悬停超时"))。
            ///
            /// 覆盖 lines 857-859：throw_on_not_login=true → return Err。
            #[tokio::test]
            async fn check_and_update_hover_evicts_on_timeout_throws() {
                let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
                let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
                let mut config = GarrisonConfig::default_config();
                config.throw_on_not_login = true;
                config.token_style = "uuid".to_string();
                config.session_hover_timeout = 1;
                let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                    has_permission: true,
                    has_role: true,
                });
                let clock = Arc::new(MockClock::new(chrono::Utc::now()));
                let logic = GarrisonLogicDefault::new(session, Arc::new(config), firewall)
                    .with_clock(clock.clone() as Arc<dyn Clock>);

                let token = logic
                    .login("hover-user-002", &LoginParams::default())
                    .await
                    .unwrap();
                let now_millis = clock.now().timestamp_millis();
                logic
                    .session
                    .update_last_active_at("hover-user-002", now_millis);
                clock.advance(chrono::Duration::seconds(2));

                let result = with_current_token(token, async { logic.check_login().await }).await;
                assert!(
                    matches!(result, Err(GarrisonError::Session(ref msg)) if msg == "stp-session-timeout::"),
                    "悬停超时 + throw=true 应返回 Err(Session(\"会话悬停超时\"))，实际: {:?}",
                    result
                );
            }
        } // end listener_tests

        // ==================================================================
        // login_with_token / kickout_by_token / logout 无 token 路径
        // ==================================================================

        /// login_with_token 创建会话后，check_login 返回 true。
        ///
        /// 覆盖 lines 247-249：`self.session.create(login_id, token)` 路径。
        #[tokio::test]
        async fn login_with_token_creates_session() {
            let logic = make_logic(false);
            logic
                .login_with_token("lwt-user-001", "custom-token-001")
                .await
                .unwrap();
            // 验证会话已创建
            let ts = logic
                .session
                .get_token_session("custom-token-001")
                .await
                .unwrap()
                .expect("login_with_token 后应存在 Token-Session");
            assert_eq!(ts.login_id, "lwt-user-001");
        }

        /// T018：login_with_token 经由 create_session_with_quota 执行最大登录数配额，
        /// 创建第 max_login_count+1 个会话时最旧会话被踢出。
        #[tokio::test]
        async fn login_with_token_enforces_max_login_count_evicts_oldest() {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.max_login_count = 2;
            config.is_concurrent = true;
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = GarrisonLogicDefault::new(session, Arc::new(config), firewall);

            logic
                .login_with_token("quota-user", "qt-token-001")
                .await
                .unwrap();
            logic
                .login_with_token("quota-user", "qt-token-002")
                .await
                .unwrap();
            logic
                .login_with_token("quota-user", "qt-token-003")
                .await
                .unwrap();

            // 第 3 个登录（> max_login_count=2）应踢出最旧 token qt-token-001
            let oldest = logic
                .session
                .get_token_session("qt-token-001")
                .await
                .unwrap();
            assert!(
                oldest.is_none(),
                "第 max_login_count+1 个会话应踢出最旧 token qt-token-001，实际: {:?}",
                oldest
            );
            // qt-token-002 / qt-token-003 仍保留
            assert!(
                logic
                    .session
                    .get_token_session("qt-token-002")
                    .await
                    .unwrap()
                    .is_some(),
                "qt-token-002 应保留"
            );
            assert!(
                logic
                    .session
                    .get_token_session("qt-token-003")
                    .await
                    .unwrap()
                    .is_some(),
                "qt-token-003 应保留"
            );
        }

        /// token 已关联其他 login_id 时 `login_with_token` 应返回 Err。
        ///
        /// 模拟攻击者拿到 alice 的 token 后，调用 `login_with_token("attacker", T1)`
        /// 试图在 attacker 名下创建会话以实现会话劫持。应拒绝，避免同一 token
        /// 同时映射到两个 login_id（dual-mapping）。
        ///
        /// 覆盖 `login_with_token` 中新增的 token 唯一性检查分支。
        #[tokio::test]
        async fn login_with_token_returns_error_when_token_already_associated() {
            let logic = make_logic(false);
            // alice 先用 T1 登录（合法占有 T1）
            logic
                .login_with_token("alice-001", "shared-token-T1")
                .await
                .expect("alice 首次登录应成功");

            // 攻击者尝试用同一 token 在自己名下创建会话
            let result = logic
                .login_with_token("attacker-002", "shared-token-T1")
                .await;
            assert!(
                result.is_err(),
                "token 已关联 alice 时，attacker 重复关联应返回 Err，避免 dual-mapping。实际: {:?}",
                result
            );

            // 验证 token 仍归属 alice（未被覆盖）
            let ts = logic
                .session
                .get_token_session("shared-token-T1")
                .await
                .unwrap()
                .expect("T1 的 Token-Session 应保留");
            assert_eq!(
                ts.login_id, "alice-001",
                "token 应仍归属原 login_id（alice），未被 attacker 抢占"
            );
        }

        // ==================================================================
        // A8: login_with_token 入口校验（会话固定/劫持防护）
        // ==================================================================

        /// A8: 空 `login_id` 应被拒绝。
        ///
        /// 攻击场景：攻击者尝试用空 login_id 创建无主会话，绕过账号绑定。
        /// 期望返回 `InvalidParam`，且不创建任何会话。
        #[tokio::test]
        async fn a8_login_with_token_rejects_empty_login_id() {
            let logic = make_logic(false);
            let result = logic.login_with_token("", "valid-token-001").await;
            assert!(
                matches!(result, Err(GarrisonError::InvalidParam(_))),
                "空 login_id 应返回 InvalidParam，实际: {:?}",
                result
            );
            // 验证未创建会话（fail-closed）
            assert!(
                logic
                    .session
                    .get_token_session("valid-token-001")
                    .await
                    .unwrap()
                    .is_none(),
                "校验失败时不应创建会话"
            );
        }

        /// A8: 空 `token` 应被拒绝。
        ///
        /// 攻击场景：空 token 无法标识会话，且可能在下游 DAO 层产生异常键。
        /// 期望返回 `InvalidParam`。
        #[tokio::test]
        async fn a8_login_with_token_rejects_empty_token() {
            let logic = make_logic(false);
            let result = logic.login_with_token("user-001", "").await;
            assert!(
                matches!(result, Err(GarrisonError::InvalidParam(_))),
                "空 token 应返回 InvalidParam，实际: {:?}",
                result
            );
        }

        /// A8: 过短 token（< 8 字节）应被拒绝。
        ///
        /// 攻击场景：过短 token 易碰撞/伪造（如 "0"/"1"/"abc"），
        /// 攻击者可枚举短 token 劫持他人会话。
        /// 期望返回 `InvalidParam`。
        #[tokio::test]
        async fn a8_login_with_token_rejects_too_short_token() {
            let logic = make_logic(false);
            // 7 字节 token（< 8 下限）
            let result = logic.login_with_token("user-001", "short12").await;
            assert!(
                matches!(result, Err(GarrisonError::InvalidParam(_))),
                "过短 token 应返回 InvalidParam，实际: {:?}",
                result
            );
        }

        /// A8: 超长 token（> 256 字节）应被拒绝。
        ///
        /// 攻击场景：超长 token 可触发 DAO 存储放大 / 序列化开销过大（DoS）。
        /// 期望返回 `InvalidParam`。
        #[tokio::test]
        async fn a8_login_with_token_rejects_too_long_token() {
            let logic = make_logic(false);
            // 257 字节 token（> 256 上限）
            let long_token = "a".repeat(257);
            let result = logic.login_with_token("user-001", &long_token).await;
            assert!(
                matches!(result, Err(GarrisonError::InvalidParam(_))),
                "超长 token 应返回 InvalidParam，实际: {:?}",
                result
            );
        }

        /// A8: 含控制字符的 token 应被拒绝。
        ///
        /// 攻击场景：控制字符（如 `\r\n`）可触发 CRLF 注入 / HTTP header
        /// smuggling / 日志污染。例如 token="valid\r\nX-Evil: 1" 可在日志
        /// 或下游 HTTP 客户端注入伪造 header。
        /// 期望返回 `InvalidParam`。
        #[tokio::test]
        async fn a8_login_with_token_rejects_token_with_control_chars() {
            let logic = make_logic(false);
            // 含 \r\n 的 token（CRLF 注入向量）
            let result = logic
                .login_with_token("user-001", "valid-token\r\nX-Evil: 1")
                .await;
            assert!(
                matches!(result, Err(GarrisonError::InvalidParam(_))),
                "含控制字符的 token 应返回 InvalidParam，实际: {:?}",
                result
            );
            // 含 NUL 字节的 token（二进制注入向量）
            let result2 = logic.login_with_token("user-001", "valid\0token").await;
            assert!(
                matches!(result2, Err(GarrisonError::InvalidParam(_))),
                "含 NUL 字节的 token 应返回 InvalidParam，实际: {:?}",
                result2
            );
        }

        /// A8: 边界值 — 8 字节 token 应通过校验（下限包含）。
        ///
        /// 验证 `8..=256` 区间为闭区间，避免 off-by-one 错误。
        #[tokio::test]
        async fn a8_login_with_token_accepts_min_length_token() {
            let logic = make_logic(false);
            // 恰好 8 字节 token（下限包含）
            logic
                .login_with_token("user-001", "12345678")
                .await
                .expect("8 字节 token 应通过校验");
            // 验证会话已创建
            let ts = logic
                .session
                .get_token_session("12345678")
                .await
                .unwrap()
                .expect("8 字节 token 应已创建会话");
            assert_eq!(ts.login_id, "user-001");
        }

        /// A8: 边界值 — 256 字节 token 应通过校验（上限包含）。
        ///
        /// 验证 `8..=256` 区间为闭区间，避免 off-by-one 错误。
        #[tokio::test]
        async fn a8_login_with_token_accepts_max_length_token() {
            let logic = make_logic(false);
            // 恰好 256 字节 token（上限包含）
            let max_token = "a".repeat(256);
            logic
                .login_with_token("user-001", &max_token)
                .await
                .expect("256 字节 token 应通过校验");
            // 验证会话已创建
            let ts = logic
                .session
                .get_token_session(&max_token)
                .await
                .unwrap()
                .expect("256 字节 token 应已创建会话");
            assert_eq!(ts.login_id, "user-001");
        }

        /// kickout_by_token 销毁指定 token 的会话。
        ///
        /// 覆盖 lines 317-320：`self.session.logout(token)` 路径。
        #[tokio::test]
        async fn kickout_by_token_destroys_session() {
            let logic = make_logic(false);
            let token = logic
                .login("kbt-user-001", &LoginParams::default())
                .await
                .unwrap();
            assert!(
                logic
                    .session
                    .get_token_session(&token)
                    .await
                    .unwrap()
                    .is_some(),
                "login 后应存在 session"
            );
            logic.kickout_by_token(&token).await.unwrap();
            assert!(
                logic
                    .session
                    .get_token_session(&token)
                    .await
                    .unwrap()
                    .is_none(),
                "kickout_by_token 后 session 应被销毁"
            );
        }

        /// logout 无 current_token 时幂等返回 Ok。
        ///
        /// 覆盖 lines 283-285：`Err(_) => Ok(())` 分支。
        #[tokio::test]
        async fn logout_without_token_returns_ok() {
            let logic = make_logic(false);
            // 不设置 current_token，直接调用 logout
            let result = logic.logout().await;
            assert!(
                result.is_ok(),
                "无 current_token 时 logout 应幂等返回 Ok，实际: {:?}",
                result
            );
        }

        // ==================================================================
        // generate_token 不同 token_style 测试
        // ==================================================================

        /// token_style=random_64 生成 64 字符 token。
        ///
        /// 覆盖 lines 720-724：`random_64` 分支（两个 simple UUID 拼接）。
        #[tokio::test]
        async fn generate_token_random_64_style() {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "random_64".to_string();
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = GarrisonLogicDefault::new(session, Arc::new(config), firewall);

            let token = logic
                .login("r64-user-001", &LoginParams::default())
                .await
                .unwrap();
            // random_64 = 两个 simple UUID 拼接 = 32 + 32 = 64 字符
            assert_eq!(
                token.len(),
                64,
                "random_64 token 应为 64 字符，实际: {} 字符",
                token.len()
            );
            // 验证全部为十六进制字符
            assert!(
                token.chars().all(|c| c.is_ascii_hexdigit()),
                "random_64 token 应全部为十六进制字符"
            );
        }

        /// token_style=simple 复用 `SimpleTokenStyle`（HMAC 签名），主登录路径产出的 token
        /// 格式为 `<login_id>\x1f<uuid>.<hmac>`，且可被同一 `SimpleTokenStyle::verify` 通过
        /// （R-sessiontokenconsistency-002：单点真相，generate 与 verify 不再格式分裂）。
        #[cfg(feature = "secure-simple-token")]
        #[tokio::test]
        async fn generate_token_simple_style_is_hmac_and_verifiable() {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "simple".to_string();
            config.jwt_secret = "gen-simple-secret-aaaabbbbccccdddd0".to_string().into();
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = GarrisonLogicDefault::new(session, Arc::new(config.clone()), firewall);

            // 主登录路径产出 token
            let token = logic
                .login("simple-user-001", &LoginParams::default())
                .await
                .unwrap();
            // 格式：login_id \x1f uuid . hmac
            assert!(token.contains('\x1f'), "simple token 应包含 \\x1f 分隔符");
            assert!(token.contains('.'), "simple token 应包含 HMAC 分隔点");

            // 同一 SimpleTokenStyle（同 secret）verify 应通过并解析出相同 login_id
            use crate::core::token::Token;
            let style =
                crate::core::token::SimpleTokenStyle::new(config.jwt_secret.as_str().to_string());
            let verified = style.verify(&token).unwrap();
            assert_eq!(
                verified,
                Some("simple-user-001".to_string()),
                "simple token 应能被同一 SimpleTokenStyle::verify 通过并解析出 login_id"
            );

            // AuthLogic 路径（login 即同一方法）产出格式一致，可被同一 verify 通过
            let token2 = logic
                .login("simple-user-001", &LoginParams::default())
                .await
                .unwrap();
            assert_eq!(
                style.verify(&token2).unwrap(),
                Some("simple-user-001".to_string()),
                "AuthLogic 路径产出的 simple token 应同样可被 SimpleTokenStyle::verify 通过"
            );
        }

        /// token_style=simple 未启用 `secure-simple-token` feature 时 fail-closed 返回 Config 错误。
        #[cfg(not(feature = "secure-simple-token"))]
        #[serial]
        #[tokio::test]
        async fn generate_token_simple_style_requires_feature() {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "simple".to_string();
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = GarrisonLogicDefault::new(session, Arc::new(config), firewall);

            let result = logic
                .login("simple-user-001", &LoginParams::default())
                .await;
            assert!(
                matches!(result, Err(GarrisonError::Config(_))),
                "未启用 secure-simple-token 时 simple token 生成应 fail-closed 返回 Config 错误"
            );
        }

        /// token_style=jwt 生成 JWT token。
        ///
        /// 覆盖 lines 726-739：`jwt` 分支（委托 JwtHandler::sign）。
        #[cfg(feature = "protocol-jwt")]
        #[serial]
        #[tokio::test]
        async fn generate_token_jwt_style() {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "jwt".to_string();
            config.jwt_secret = "gen-jwt-secret-aaaabbbbccccdddd0".to_string().into();
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = GarrisonLogicDefault::new(session, Arc::new(config), firewall);

            let token = logic
                .login("jwt-user-001", &LoginParams::default())
                .await
                .unwrap();
            // JWT token 包含两个点（header.payload.signature）
            assert_eq!(
                token.matches('.').count(),
                2,
                "JWT token 应包含 2 个点，实际: {} 个",
                token.matches('.').count()
            );
        }

        // ==================================================================
        // check_login_mixin + 有效 token 路径
        // ==================================================================

        /// Mixin 模式 + 有效 token → Ok(true)。
        ///
        /// 覆盖 lines 808-821：valid=true → check_and_update_hover → check_and_renew → Ok(true)。
        #[serial]
        #[tokio::test]
        async fn check_login_mixin_valid_token_returns_true() {
            let logic = make_logic(false).with_jwt_mode(JwtMode::Mixin);
            let token = logic
                .login("mixin-user-001", &LoginParams::default())
                .await
                .unwrap();
            let result = with_current_token(token, async { logic.check_login().await }).await;
            assert!(
                result.is_ok(),
                "Mixin + 有效 token 应返回 Ok，实际: {:?}",
                result
            );
            assert!(result.unwrap(), "Mixin + 有效 token 应返回 true");
        }

        /// Simple 模式 + 有效 token → Ok(true)。
        ///
        /// 覆盖 lines 891-903：valid=true → check_and_update_hover → check_and_renew → Ok(true)。
        #[tokio::test]
        async fn check_login_simple_valid_token_returns_true() {
            let logic = make_logic(false).with_jwt_mode(JwtMode::Simple);
            let token = logic
                .login("simple-check-user-001", &LoginParams::default())
                .await
                .unwrap();
            let result = with_current_token(token, async { logic.check_login().await }).await;
            assert!(
                result.is_ok(),
                "Simple + 有效 token 应返回 Ok，实际: {:?}",
                result
            );
            assert!(result.unwrap(), "Simple + 有效 token 应返回 true");
        }

        // ==================================================================
        // refresh_access_token 错误路径（protocol-jwt + db-sqlite）
        // ==================================================================

        /// 启用 protocol-jwt + db-sqlite 但未注入 RefreshTokenRotation → NotImplemented。
        ///
        /// 覆盖 lines 444-452：`#[cfg(all(protocol-jwt, db-sqlite))]` 分支
        /// 中 `refresh_token_rotation` 未注入返回 NotImplemented。
        #[cfg(all(feature = "protocol-jwt", feature = "db-sqlite"))]
        #[tokio::test]
        async fn refresh_access_token_with_jwt_no_rotation_returns_not_implemented() {
            let logic = make_logic(false);
            let result = logic.refresh_access_token("any-refresh").await;
            assert!(
                matches!(result, Err(GarrisonError::NotImplemented(ref msg)) if msg.contains("stp-refresh-access-token-no-rotation")),
                "未注入 RefreshTokenRotation 应返回 NotImplemented 包含 'stp-refresh-access-token-no-rotation'，实际: {:?}",
                result
            );
        }

        // ==================================================================
        // NewDevice 模式拒绝登录路径
        // ==================================================================

        /// NewDevice 模式 + 已有有效旧会话 → 拒绝新登录。
        ///
        /// 覆盖 lines 500-514：`NewDevice` 分支中存在有效旧会话时返回 NotLogin。
        #[tokio::test]
        async fn login_new_device_mode_rejects_when_existing_session() {
            let mut logic = make_logic(false);
            Arc::make_mut(&mut logic.config).is_concurrent = false;
            Arc::make_mut(&mut logic.config).replaced_login_exit_mode =
                ReplacedLoginExitMode::NewDevice;

            // 首次登录成功
            let _t1 = logic
                .login("new-device-reject-001", &LoginParams::default())
                .await
                .unwrap();

            // 第二次登录应被拒绝（NewDevice 模式 + 已有有效旧会话）
            let result = logic
                .login("new-device-reject-001", &LoginParams::default())
                .await;
            assert!(
                matches!(result, Err(GarrisonError::NotLogin(ref msg)) if msg.contains("stp-new-device-login-rejected")),
                "NewDevice 模式 + 已有旧会话应返回 NotLogin 包含 'NewDevice'，实际: {:?}",
                result
            );
        }

        // ==================================================================
        // OldDevice 模式踢出旧会话
        // ==================================================================

        /// OldDevice 模式 + is_concurrent=false → 踢出旧会话后创建新会话。
        ///
        /// 覆盖 lines 496-499：`OldDevice` 分支调用 kickout。
        #[tokio::test]
        async fn login_old_device_mode_kickouts_old_session() {
            let mut logic = make_logic(false);
            Arc::make_mut(&mut logic.config).is_concurrent = false;
            Arc::make_mut(&mut logic.config).replaced_login_exit_mode =
                ReplacedLoginExitMode::OldDevice;

            let t1 = logic
                .login("old-device-001", &LoginParams::default())
                .await
                .unwrap();
            let t2 = logic
                .login("old-device-001", &LoginParams::default())
                .await
                .unwrap();
            // 旧 token 应被踢出
            assert!(
                logic
                    .session
                    .get_token_session(&t1)
                    .await
                    .unwrap()
                    .is_none(),
                "OldDevice 模式下旧 token 应被踢出"
            );
            // 新 token 应有效
            assert!(
                logic
                    .session
                    .get_token_session(&t2)
                    .await
                    .unwrap()
                    .is_some(),
                "新 token 应有效"
            );
            assert_ne!(t1, t2, "新旧 token 应不同");
        }

        // ==================================================================
        // enforce_max_login_count：tokens <= max 不操作
        // ==================================================================

        /// tokens 数量 <= max 时不踢出任何会话。
        ///
        /// 覆盖 lines 651-654：`tokens.len() <= max → return Ok(())`。
        #[tokio::test]
        async fn enforce_max_login_count_within_limit_no_op() {
            let logic = make_logic(false);
            let t1 = logic
                .login("max-nop-001", &LoginParams::default())
                .await
                .unwrap();
            let _t2 = logic
                .login("max-nop-001", &LoginParams::default())
                .await
                .unwrap();

            // max=5，tokens=2，不踢出
            logic
                .enforce_max_login_count("max-nop-001", 5)
                .await
                .unwrap();
            assert!(
                logic
                    .session
                    .get_token_session(&t1)
                    .await
                    .unwrap()
                    .is_some(),
                "tokens <= max 时 t1 应仍存在"
            );
        }

        // ==================================================================
        // get_login_id + current_token 但无 session
        // ==================================================================

        /// get_login_id + current_token 存在但 session 不存在 → Ok(None)。
        ///
        /// 覆盖 lines 407-413：`current_token → get_token_session → None → Ok(None)` 路径。
        #[tokio::test]
        async fn get_login_id_token_without_session_returns_none() {
            let logic = make_logic(false);
            let result = with_current_token("nonexistent-token".to_string(), async {
                logic.get_login_id().await
            })
            .await;
            assert!(
                result.is_ok(),
                "token 无对应 session 时应返回 Ok，实际: {:?}",
                result
            );
            assert!(
                result.unwrap().is_none(),
                "token 无对应 session 时应返回 None"
            );
        }
    }

    // ========================================================================
    // T014: JWT 撤销黑名单测试（H-14）
    // ========================================================================

    #[cfg(feature = "protocol-jwt")]
    mod jwt_revocation_tests {
        use super::*;
        use crate::dao::GarrisonDao;
        use crate::session::GarrisonSession;
        use crate::stp::mock::{MockDao, MockFirewall};
        use crate::stp::with_current_token;
        use crate::strategy::GarrisonPermissionStrategy;
        use std::sync::Arc;

        /// 创建 JWT 模式 logic + 共享 MockDao（用于验证黑名单写入）。
        fn make_jwt_revocation_logic(
            enable_revocation: bool,
        ) -> (GarrisonLogicDefault, Arc<MockDao>) {
            let dao = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "jwt".to_string();
            config.jwt_secret = "jwt-revocation-test-secret-32bytes!".to_string().into();
            config.enable_jwt_revocation = enable_revocation;
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let logic = GarrisonLogicDefault::new(session, Arc::new(config), firewall)
                .with_jwt_mode(JwtMode::Stateless);
            (logic, dao)
        }

        /// logout 后 jti 写入黑名单（dao.get 返回 Some）。
        #[serial]
        #[tokio::test]
        async fn logout_writes_jti_to_blacklist() {
            let (logic, dao) = make_jwt_revocation_logic(true);
            let handler =
                crate::protocol::jwt::JwtHandler::new("jwt-revocation-test-secret-32bytes!");
            let token = logic
                .login("user-1", &LoginParams::default())
                .await
                .unwrap();

            // 提取 jti
            let claims = handler.verify(&token).unwrap();
            let jti = claims.jti.expect("JWT 应包含 jti");

            // 执行 logout（需设置 current_token）
            with_current_token(token, async {
                logic.logout().await.expect("logout 应成功");
            })
            .await;

            // 验证黑名单已写入
            let key = format!("jwt:blacklist:{}", jti);
            let value = dao.get(&key).await.unwrap();
            assert!(value.is_some(), "logout 后 jti 应被写入黑名单");
            assert_eq!(value.unwrap(), "1");
        }

        /// stateless 模式对已撤销 JWT 返回 TokenRevoked 错误。
        #[serial]
        #[tokio::test]
        async fn stateless_rejects_revoked_jwt() {
            let (logic, _dao) = make_jwt_revocation_logic(true);
            let token = logic
                .login("user-2", &LoginParams::default())
                .await
                .unwrap();

            // 先 logout 将 jti 加入黑名单
            with_current_token(token.clone(), async {
                logic.logout().await.expect("logout 应成功");
            })
            .await;

            // stateless check_login 应返回 TokenRevoked
            let result = with_current_token(token, async { logic.check_login().await }).await;

            assert!(
                matches!(&result, Err(GarrisonError::TokenRevoked(_))),
                "已撤销 JWT 应返回 TokenRevoked，实际: {:?}",
                result
            );
        }

        /// 未过期且未撤销的 JWT 正常通过 stateless check_login。
        #[serial]
        #[tokio::test]
        async fn stateless_accepts_valid_jwt() {
            let (logic, _dao) = make_jwt_revocation_logic(true);
            let token = logic
                .login("user-3", &LoginParams::default())
                .await
                .unwrap();

            // 不 logout，直接 check_login
            let result = with_current_token(token, async { logic.check_login().await }).await;

            assert!(result.is_ok(), "有效 JWT 应返回 Ok，实际: {:?}", result);
            assert!(result.unwrap(), "有效 JWT 应返回 true");
        }

        /// enable_jwt_revocation=false 时 logout 不写黑名单。
        #[serial]
        #[tokio::test]
        async fn no_blacklist_when_revocation_disabled() {
            let (logic, dao) = make_jwt_revocation_logic(false);
            let handler =
                crate::protocol::jwt::JwtHandler::new("jwt-revocation-test-secret-32bytes!");
            let token = logic
                .login("user-4", &LoginParams::default())
                .await
                .unwrap();

            let claims = handler.verify(&token).unwrap();
            let jti = claims.jti.expect("JWT 应包含 jti");

            with_current_token(token, async {
                logic.logout().await.expect("logout 应成功");
            })
            .await;

            // 黑名单不应有记录
            let key = format!("jwt:blacklist:{}", jti);
            let value = dao.get(&key).await.unwrap();
            assert!(
                value.is_none(),
                "enable_jwt_revocation=false 时 logout 不应写入黑名单"
            );
        }
    }
}

#[cfg(all(test, feature = "firewall-bruteforce"))]
mod firewall_tests {
    use crate::config::GarrisonConfig;
    use crate::dao::tests::MockDao;
    use crate::error::GarrisonError;
    use crate::manager::GarrisonManager;
    use crate::stp::mock::MockInterface;
    use crate::stp::{with_current_ip, with_current_token, GarrisonUtil, LoginParams};
    // setup() 会 reset_for_test() 覆盖全局单例并替换 DAO：并发线程下彼此的
    // brute-force 计数被清零 → `brute_force_blocks_ip_after_repeated_failed_check_login`
    // 基线 flaky（#5 失败 #4/#6 通过）。按仓库惯例（account/metrics.rs）串行化。
    use serial_test::serial;

    async fn setup() {
        GarrisonManager::reset_for_test();
        let dao: std::sync::Arc<dyn crate::dao::GarrisonDao> = std::sync::Arc::new(MockDao::new());
        // 关闭 throw_on_not_login：使无效 token 返回 Ok(false)（认证失败），
        // 从而触发 brute-force 计数路径。
        let mut config = GarrisonConfig::default();
        config.throw_on_not_login = false;
        let config = std::sync::Arc::new(config);
        let interface: std::sync::Arc<dyn crate::stp::GarrisonInterface> =
            std::sync::Arc::new(MockInterface);
        GarrisonManager::builder()
            .dao(dao)
            .config(config)
            .interface(interface)
            .build()
            .await
            .unwrap();
    }

    /// CRIT-010: 同一 IP 反复认证失败 → 触发暴力破解封禁（FirewallBlocked）。
    #[tokio::test]
    #[serial]
    async fn brute_force_blocks_ip_after_repeated_failed_check_login() {
        setup().await;
        let ip = "203.0.113.5".to_string();
        let blocked = with_current_ip(ip.clone(), async {
            with_current_token("bogus-token".to_string(), async {
                let mut blocked = false;
                for _ in 0..12 {
                    if let Err(GarrisonError::FirewallBlocked(_)) =
                        GarrisonUtil::check_login().await
                    {
                        blocked = true;
                        break;
                    }
                }
                blocked
            })
            .await
        })
        .await;
        assert!(
            blocked,
            "重复认证失败应触发 IP 封禁（返回 FirewallBlocked）"
        );
    }

    /// CRIT-010: 认证成功路径应清零失败计数（不触发封禁）。
    #[tokio::test]
    #[serial]
    async fn successful_login_resets_failure_count() {
        setup().await;
        let ip = "198.51.100.7".to_string();
        // 先制造若干失败计数，再执行一次成功登录（无 token 的 check_login 失败不算，
        // 这里用 login 成功路径验证清零逻辑：login 成功会 delete 计数键）。
        with_current_ip(ip.clone(), async {
            // 失败计数累积
            for _ in 0..3 {
                with_current_token("bogus".to_string(), async {
                    let _ = GarrisonUtil::check_login().await;
                })
                .await;
            }
            // 成功登录（login 对任意合法 login_id 创建会话）
            let _ = GarrisonUtil::login("legit-user", &LoginParams::default()).await;
        })
        .await;

        // 清零后再次失败不应立即封禁（计数已重置，需重新累积）。
        let blocked_immediately = with_current_ip(ip.clone(), async {
            with_current_token("bogus2".to_string(), async {
                let mut blocked = false;
                // 仅 1 次失败，远未达阈值
                if let Err(GarrisonError::FirewallBlocked(_)) = GarrisonUtil::check_login().await {
                    blocked = true;
                }
                blocked
            })
            .await
        })
        .await;
        assert!(
            !blocked_immediately,
            "成功登录后失败计数应被清零，单次失败不应立即封禁"
        );
    }

    /// T010: 启用 firewall feature 时 builder 应自动注入 firewall_hook。
    #[tokio::test]
    #[serial]
    async fn builder_auto_wires_firewall_hook() {
        setup().await;
        let injected = crate::manager::GarrisonManager::logic()
            .unwrap()
            .firewall_hook_injected();
        assert!(
            injected,
            "firewall feature 启用时 builder 应自动注入 firewall_hook（避免 dead-code）"
        );
    }
}
