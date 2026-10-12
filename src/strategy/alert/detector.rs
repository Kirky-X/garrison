// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 异常检测器实现模块，提供 IP 变化检测与快速连续登录检测。

use crate::error::GarrisonResult;
use crate::i18n::translate_detail;
use crate::session::GarrisonSession;
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use super::{AnomalyDetector, AnomalyType, SecurityAlertEvent};

#[cfg(feature = "session-hijack-detection")]
use crate::config::SessionHijackMode;

/// IP 变化检测器，对比当前登录 IP 与历史最近活跃 session 的 IP。
///
/// `check_on_login` 取 `last_active_at` 最大的 session 的 IP 与当前登录 IP 对比，不同则发出 `AnomalyLogin { anomaly_type: IpChanged }`；
/// `check_on_check_login` 签名不含当前 IP，无法检测，返回空 Vec（会话劫持检测请用 `SessionHijackDetector`）。
pub struct IpChangeDetector {
    /// 会话管理器引用，用于查询历史 session。
    session: Arc<GarrisonSession>,
}

impl IpChangeDetector {
    /// 创建 `IpChangeDetector` 实例。
    pub fn new(session: Arc<GarrisonSession>) -> Self {
        Self { session }
    }
}

#[async_trait]
impl AnomalyDetector for IpChangeDetector {
    async fn check_on_login(
        &self,
        login_id: &str,
        _device_id: &str,
        ip: Option<&str>,
    ) -> GarrisonResult<Vec<SecurityAlertEvent>> {
        // 无当前 IP 不告警
        let current_ip = match ip {
            Some(ip) => ip,
            None => return Ok(Vec::new()),
        };

        let tokens = self.session.get_tokens_by_login_id(login_id);
        if tokens.is_empty() {
            return Ok(Vec::new());
        }

        // 取 last_active_at 最大的 session;单个 token 读取失败仅 warn 跳过而非 `?` 传播(避免 transient 错误抑制其余 token 的告警)。
        let mut latest_ip: Option<String> = None;
        let mut latest_active_at: i64 = i64::MIN;
        for token in &tokens {
            match self.session.get_token_session(token).await {
                Ok(Some(ts)) => {
                    if ts.last_active_at > latest_active_at {
                        latest_active_at = ts.last_active_at;
                        latest_ip = ts.ip;
                    }
                },
                Ok(None) => {},
                Err(e) => {
                    tracing::warn!(
                        login_id,
                        token = token.get(..8).unwrap_or(token),
                        error = %e,
                        "IpChangeDetector: token session read failed, skipping token (detection continues)"
                    );
                },
            }
        }

        let historical_ip = match latest_ip {
            Some(ip) => ip,
            None => return Ok(Vec::new()),
        };

        if historical_ip == current_ip {
            return Ok(Vec::new());
        }

        Ok(vec![SecurityAlertEvent::AnomalyLogin {
            login_id: login_id.to_string(),
            anomaly_type: AnomalyType::IpChanged,
            detail: translate_detail(
                "alert-ip-changed",
                &[("arg0", historical_ip.as_str()), ("arg1", current_ip)],
            ),
            trace_id: Uuid::new_v4().to_string(),
        }])
    }

    async fn check_on_check_login(
        &self,
        _login_id: &str,
        _token: &str,
    ) -> GarrisonResult<Vec<SecurityAlertEvent>> {
        Ok(Vec::new())
    }
}

/// 会话劫持检测器，对比当前请求 IP 与会话创建时存储的 IP（仅在 `session-hijack-detection` feature 启用时编译）。
///
/// 在 `check_on_check_login` 路径工作：经 `tokio::task_local!` 取当前请求 IP（由 `inject_client_ip` middleware 注入），
/// 与 `TokenSession` 存储 IP 对比，两者均 `Some` 且不同即疑似劫持。
/// 行为模式：`AlertOnly`（默认）广播 `SessionHijackSuspected` 告警；`Kickout` 广播并调用 `session.logout(token)` 踢出。
#[cfg(feature = "session-hijack-detection")]
pub struct SessionHijackDetector {
    /// 会话管理器引用，用于查询/销毁 token session。
    session: Arc<GarrisonSession>,
    /// 检测到劫持时的行为模式。
    mode: SessionHijackMode,
}

#[cfg(feature = "session-hijack-detection")]
impl SessionHijackDetector {
    /// 创建 `SessionHijackDetector` 实例。
    pub fn new(session: Arc<GarrisonSession>, mode: SessionHijackMode) -> Self {
        Self { session, mode }
    }
}

#[cfg(feature = "session-hijack-detection")]
#[async_trait]
impl AnomalyDetector for SessionHijackDetector {
    async fn check_on_login(
        &self,
        _login_id: &str,
        _device_id: &str,
        _ip: Option<&str>,
    ) -> GarrisonResult<Vec<SecurityAlertEvent>> {
        // 劫持检测仅在 check_login 路径工作（需要 task_local 上下文）
        Ok(Vec::new())
    }

    async fn check_on_check_login(
        &self,
        login_id: &str,
        token: &str,
    ) -> GarrisonResult<Vec<SecurityAlertEvent>> {
        let current_ip = match crate::server::middleware::current_client_ip() {
            Some(ip) => ip,
            None => return Ok(Vec::new()), // 非 HTTP 路径（无 task_local 上下文）不检测
        };

        let stored_ip = match self.session.get_token_session(token).await? {
            Some(ts) => match ts.ip {
                Some(ip) => ip,
                None => return Ok(Vec::new()),
            },
            None => return Ok(Vec::new()),
        };

        if current_ip == stored_ip {
            return Ok(Vec::new());
        }

        let detail = translate_detail(
            "session-ip-mismatch",
            &[("arg0", stored_ip.as_str()), ("arg1", current_ip.as_str())],
        );

        // Kickout 模式踢出疑似被劫持的会话
        if self.mode == SessionHijackMode::Kickout {
            if let Err(e) = self.session.logout(token).await {
                tracing::warn!(error = %e, token = &token[..token.len().min(8)], "SessionHijackDetector: kickout failed");
            }
        }

        Ok(vec![SecurityAlertEvent::AnomalyLogin {
            login_id: login_id.to_string(),
            anomaly_type: AnomalyType::SessionHijackSuspected,
            detail,
            trace_id: Uuid::new_v4().to_string(),
        }])
    }
}

/// 快速连续登录检测器，检查同一 login_id 的同时在线 token 数量是否超过阈值（默认 5，经 `with_threshold` 自定义）。
///
/// `check_on_login` 逐个 `get_token_session` 验证存活性，**只统计未过期 token**（过期项不计入，避免长期堆积造成误报），
/// 活跃数 >= 阈值时发出 `AnomalyLogin { anomaly_type: RapidSuccessiveLogin }`。
/// 不区分 token 创建时间，长期多设备在线也会触发；单个 token 读取失败仅 warn 跳过，全部失败则计数 0、不告警（对 DAO 故障
/// fail-open）；需时间窗口语义时应另实现 `AnomalyDetector`；`check_on_check_login` 不触发检测，返回空 Vec。
pub struct RapidSuccessiveDetector {
    /// 会话管理器引用，用于查询 token 列表。
    session: Arc<GarrisonSession>,
    /// 触发告警的 token 数量阈值。
    threshold: usize,
}

impl RapidSuccessiveDetector {
    /// 创建 `RapidSuccessiveDetector` 实例，默认阈值 5。
    pub fn new(session: Arc<GarrisonSession>) -> Self {
        Self {
            session,
            threshold: 5,
        }
    }

    /// 创建 `RapidSuccessiveDetector` 实例，自定义阈值。
    pub fn with_threshold(session: Arc<GarrisonSession>, threshold: usize) -> Self {
        Self { session, threshold }
    }
}

#[async_trait]
impl AnomalyDetector for RapidSuccessiveDetector {
    async fn check_on_login(
        &self,
        login_id: &str,
        _device_id: &str,
        _ip: Option<&str>,
    ) -> GarrisonResult<Vec<SecurityAlertEvent>> {
        let tokens = self.session.get_tokens_by_login_id(login_id);

        // 逐个验证存活性,只统计未过期 token(直接 len() 会把索引中的过期项计入造成误报);单 token 失败 warn 跳过,与 IpChangeDetector 聚合策略一致。
        let mut count = 0usize;
        for token in &tokens {
            match self.session.get_token_session(token).await {
                Ok(Some(_)) => count += 1,
                Ok(None) => {},
                Err(e) => {
                    tracing::warn!(
                        login_id,
                        token = token.get(..8).unwrap_or(token),
                        error = %e,
                        "RapidSuccessiveDetector: token session read failed, skipping token"
                    );
                },
            }
        }

        if count >= self.threshold {
            return Ok(vec![SecurityAlertEvent::AnomalyLogin {
                login_id: login_id.to_string(),
                anomaly_type: AnomalyType::RapidSuccessiveLogin,
                detail: translate_detail(
                    "alert-rapid-successive",
                    &[
                        ("arg0", &count.to_string()),
                        ("arg1", &self.threshold.to_string()),
                    ],
                ),
                trace_id: Uuid::new_v4().to_string(),
            }]);
        }

        Ok(Vec::new())
    }

    async fn check_on_check_login(
        &self,
        _login_id: &str,
        _token: &str,
    ) -> GarrisonResult<Vec<SecurityAlertEvent>> {
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::dao::GarrisonDao;
    use crate::session::TokenSession;
    use crate::stp::LoginParams;

    /// 辅助函数：创建带 MockDao 的 GarrisonSession（Arc 包装）。
    fn make_session() -> (Arc<MockDao>, Arc<GarrisonSession>) {
        let dao: Arc<MockDao> = Arc::new(MockDao::new());
        let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
        (dao, session)
    }

    /// 辅助函数：创建带指定 IP 的 token session。
    async fn create_session_with_ip(
        session: &GarrisonSession,
        login_id: &str,
        token: &str,
        ip: &str,
    ) {
        let params = LoginParams {
            ip: Some(ip.to_string()),
            ..Default::default()
        };
        session
            .create_token_session(login_id, token, &params)
            .await
            .unwrap();
    }

    /// 辅助函数：直接修改 DAO 中 token session 的 last_active_at。
    async fn set_last_active_at(dao: &MockDao, token: &str, last_active_at: i64) {
        let key = format!("token:session:{}", token);
        let json = dao.get(&key).await.unwrap().unwrap();
        let mut ts: TokenSession = serde_json::from_str(&json).unwrap();
        ts.last_active_at = last_active_at;
        let new_json = serde_json::to_string(&ts).unwrap();
        dao.set(&key, &new_json, 3600).await.unwrap();
    }

    // IpChangeDetector 测试

    /// 历史 IP 与当前 IP 相同时返回空 Vec。
    #[tokio::test]
    async fn ip_same_no_alert() {
        let (_dao, session) = make_session();
        create_session_with_ip(&session, "1001", "T1", "1.2.3.4").await;

        let detector = IpChangeDetector::new(session);
        let alerts = detector
            .check_on_login("1001", "dev-1", Some("1.2.3.4"))
            .await
            .unwrap();
        assert!(alerts.is_empty(), "IP 相同时不应告警");
    }

    /// 历史 IP 与当前 IP 不同时返回 AnomalyLogin。
    #[tokio::test]
    async fn ip_different_emits_alert() {
        let (_dao, session) = make_session();
        create_session_with_ip(&session, "1001", "T1", "1.2.3.4").await;

        let detector = IpChangeDetector::new(session);
        let alerts = detector
            .check_on_login("1001", "dev-1", Some("5.6.7.8"))
            .await
            .unwrap();
        assert_eq!(alerts.len(), 1, "IP 不同时应返回 1 个告警");
        match &alerts[0] {
            SecurityAlertEvent::AnomalyLogin { detail, .. } => {
                assert!(detail.contains("1.2.3.4"), "detail 应包含历史 IP");
                assert!(detail.contains("5.6.7.8"), "detail 应包含当前 IP");
            },
            _ => panic!("期望 AnomalyLogin 事件"),
        }
    }

    /// 无历史 session 时返回空 Vec。
    #[tokio::test]
    async fn no_history_no_alert() {
        let (_dao, session) = make_session();
        let detector = IpChangeDetector::new(session);
        let alerts = detector
            .check_on_login("1001", "dev-1", Some("1.2.3.4"))
            .await
            .unwrap();
        assert!(alerts.is_empty(), "无历史 session 时不应告警");
    }

    /// 当前 IP 为 None 时返回空 Vec。
    #[tokio::test]
    async fn no_current_ip_no_alert() {
        let (_dao, session) = make_session();
        create_session_with_ip(&session, "1001", "T1", "1.2.3.4").await;

        let detector = IpChangeDetector::new(session);
        let alerts = detector
            .check_on_login("1001", "dev-1", None)
            .await
            .unwrap();
        assert!(alerts.is_empty(), "当前 IP 为 None 时不应告警");
    }

    /// check_on_login 返回 Ok。
    #[tokio::test]
    async fn check_on_login_returns_ok() {
        let (_dao, session) = make_session();
        create_session_with_ip(&session, "1001", "T1", "1.2.3.4").await;

        let detector = IpChangeDetector::new(session);
        let result = detector
            .check_on_login("1001", "dev-1", Some("1.2.3.4"))
            .await;
        assert!(result.is_ok(), "check_on_login 应返回 Ok");
    }

    /// check_on_check_login 返回空 Vec。
    #[tokio::test]
    async fn check_on_check_login_returns_empty() {
        let (_dao, session) = make_session();
        create_session_with_ip(&session, "1001", "T1", "1.2.3.4").await;

        let detector = IpChangeDetector::new(session);
        let alerts = detector.check_on_check_login("1001", "T1").await.unwrap();
        assert!(alerts.is_empty(), "check_on_check_login 应返回空 Vec");
    }

    /// 多个 session 时使用最近活跃的 IP 对比。
    #[tokio::test]
    async fn multiple_sessions_uses_latest_ip() {
        let (dao, session) = make_session();
        create_session_with_ip(&session, "1001", "T1", "1.1.1.1").await;
        create_session_with_ip(&session, "1001", "T2", "2.2.2.2").await;

        // 将 T1 的 last_active_at 设为更早的时间，使 T2 成为最近活跃的
        set_last_active_at(&dao, "T1", 1000).await;

        let detector = IpChangeDetector::new(session);
        // 当前 IP 为 3.3.3.3，应与 T2 的 IP (2.2.2.2) 对比
        let alerts = detector
            .check_on_login("1001", "dev-1", Some("3.3.3.3"))
            .await
            .unwrap();
        assert_eq!(alerts.len(), 1, "应返回 1 个告警");
        match &alerts[0] {
            SecurityAlertEvent::AnomalyLogin { detail, .. } => {
                assert!(
                    detail.contains("2.2.2.2"),
                    "detail 应包含最近活跃 session 的 IP (2.2.2.2)，实际: {}",
                    detail
                );
                assert!(
                    !detail.contains("1.1.1.1"),
                    "detail 不应包含旧 session 的 IP"
                );
            },
            _ => panic!("期望 AnomalyLogin 事件"),
        }
    }

    /// 告警事件的 anomaly_type 为 IpChanged。
    #[tokio::test]
    async fn alert_contains_correct_anomaly_type() {
        let (_dao, session) = make_session();
        create_session_with_ip(&session, "1001", "T1", "1.2.3.4").await;

        let detector = IpChangeDetector::new(session);
        let alerts = detector
            .check_on_login("1001", "dev-1", Some("5.6.7.8"))
            .await
            .unwrap();
        assert_eq!(alerts.len(), 1);
        match &alerts[0] {
            SecurityAlertEvent::AnomalyLogin { anomaly_type, .. } => {
                assert_eq!(
                    *anomaly_type,
                    AnomalyType::IpChanged,
                    "anomaly_type 应为 IpChanged"
                );
            },
            _ => panic!("期望 AnomalyLogin 事件"),
        }
    }

    // RapidSuccessiveDetector 测试

    /// 辅助函数：为指定 login_id 创建 N 个 token session。
    async fn create_n_tokens(session: &GarrisonSession, login_id: &str, count: usize) {
        for i in 0..count {
            let token = format!("T{}", i);
            session
                .create_token_session(login_id, &token, &LoginParams::default())
                .await
                .unwrap();
        }
    }

    /// token 数量 < 阈值时返回空 Vec。
    #[tokio::test]
    async fn below_threshold_no_alert() {
        let (_dao, session) = make_session();
        create_n_tokens(&session, "1001", 3).await;

        let detector = RapidSuccessiveDetector::new(session);
        let alerts = detector
            .check_on_login("1001", "dev-1", None)
            .await
            .unwrap();
        assert!(alerts.is_empty(), "token 数量 < 阈值时不应告警");
    }

    /// token 数量 >= 阈值时返回 AnomalyLogin。
    #[tokio::test]
    async fn above_threshold_emits_alert() {
        let (_dao, session) = make_session();
        create_n_tokens(&session, "1001", 6).await;

        let detector = RapidSuccessiveDetector::new(session);
        let alerts = detector
            .check_on_login("1001", "dev-1", None)
            .await
            .unwrap();
        assert_eq!(alerts.len(), 1, "token 数量 >= 阈值时应返回 1 个告警");
    }

    /// token 数量 == 阈值时返回告警（边界条件：>= 触发）。
    #[tokio::test]
    async fn threshold_boundary() {
        let (_dao, session) = make_session();
        create_n_tokens(&session, "1001", 3).await;

        let detector = RapidSuccessiveDetector::with_threshold(session, 3);
        let alerts = detector
            .check_on_login("1001", "dev-1", None)
            .await
            .unwrap();
        assert_eq!(alerts.len(), 1, "token 数量 == 阈值时应返回告警（>= 触发）");
    }

    /// 无历史 token 时返回空 Vec。
    #[tokio::test]
    async fn no_existing_tokens_no_alert() {
        let (_dao, session) = make_session();
        let detector = RapidSuccessiveDetector::new(session);
        let alerts = detector
            .check_on_login("1001", "dev-1", None)
            .await
            .unwrap();
        assert!(alerts.is_empty(), "无历史 token 时不应告警");
    }

    /// check_on_check_login 返回空 Vec。
    #[tokio::test]
    async fn rapid_check_on_check_login_returns_empty() {
        let (_dao, session) = make_session();
        create_n_tokens(&session, "1001", 6).await;

        let detector = RapidSuccessiveDetector::new(session);
        let alerts = detector.check_on_check_login("1001", "T0").await.unwrap();
        assert!(alerts.is_empty(), "check_on_check_login 应返回空 Vec");
    }

    /// 告警事件的 anomaly_type 为 RapidSuccessiveLogin。
    #[tokio::test]
    async fn rapid_alert_contains_correct_anomaly_type() {
        let (_dao, session) = make_session();
        create_n_tokens(&session, "1001", 5).await;

        let detector = RapidSuccessiveDetector::new(session);
        let alerts = detector
            .check_on_login("1001", "dev-1", None)
            .await
            .unwrap();
        assert_eq!(alerts.len(), 1);
        match &alerts[0] {
            SecurityAlertEvent::AnomalyLogin { anomaly_type, .. } => {
                assert_eq!(
                    *anomaly_type,
                    AnomalyType::RapidSuccessiveLogin,
                    "anomaly_type 应为 RapidSuccessiveLogin"
                );
            },
            _ => panic!("期望 AnomalyLogin 事件"),
        }
    }

    /// 过期 token 不计入同时在线数量：6 个索引 token 中 4 个回拨 `last_active_at` 至 timeout（3600s）之前使其过期，仅剩 2 个活跃 < 阈值 5，不告警。
    #[tokio::test]
    async fn expired_tokens_are_not_counted() {
        let (dao, session) = make_session();
        create_n_tokens(&session, "1001", 6).await;
        for i in 0..4 {
            set_last_active_at(&dao, &format!("T{}", i), 1000).await;
        }

        let detector = RapidSuccessiveDetector::new(session);
        let alerts = detector
            .check_on_login("1001", "dev-1", None)
            .await
            .unwrap();
        assert!(
            alerts.is_empty(),
            "4 个过期 token 不应计入，仅 2 个活跃 < 阈值 5，不应告警"
        );
    }

    /// 单个 token session 损坏（读取失败）不中断 IpChangeDetector 检测（错误聚合，warn 跳过该 token 继续处理剩余）。
    #[tokio::test]
    async fn corrupted_token_session_does_not_break_detection() {
        let (dao, session) = make_session();
        create_session_with_ip(&session, "1001", "T1", "1.2.3.4").await;
        create_session_with_ip(&session, "1001", "T2", "9.9.9.9").await;
        // 注入损坏 JSON：T2 读取时反序列化失败（get_token_session 返回 Err）
        dao.set("token:session:T2", "{invalid-json}", 3600)
            .await
            .unwrap();

        let detector = IpChangeDetector::new(session);
        // T1（IP 1.2.3.4）仍可读：应基于 T1 完成检测并告警，而不是因 T2 的 Err 中断整个检测
        let alerts = detector
            .check_on_login("1001", "dev-1", Some("5.6.7.8"))
            .await
            .expect("单 token 损坏不应使整个检测失败");
        assert_eq!(alerts.len(), 1, "应基于可读 token 完成 IP 变化检测");
    }

    // SessionHijackDetector 测试

    #[cfg(feature = "session-hijack-detection")]
    mod hijack_tests {
        use super::*;
        use crate::config::SessionHijackMode;
        use crate::server::middleware::{CLIENT_IP, CLIENT_USER_AGENT};

        /// 辅助函数：创建带指定 IP 和 UA 的 token session。
        async fn create_session_with_ip_ua(
            session: &GarrisonSession,
            login_id: &str,
            token: &str,
            ip: Option<&str>,
            ua: Option<&str>,
        ) {
            let params = LoginParams {
                ip: ip.map(|s| s.to_string()),
                user_agent: ua.map(|s| s.to_string()),
                ..Default::default()
            };
            session
                .create_token_session(login_id, token, &params)
                .await
                .unwrap();
        }

        /// 在 task_local 上下文中运行检测器测试。
        async fn with_client_ip<F, R>(ip: Option<&str>, f: F) -> R
        where
            F: AsyncFnOnce() -> R,
        {
            let ip_owned = ip.map(|s| s.to_string());
            CLIENT_IP
                .scope(
                    std::cell::RefCell::new(ip_owned),
                    CLIENT_USER_AGENT.scope(std::cell::RefCell::new(None), f()),
                )
                .await
        }

        /// IP 相同不告警。
        #[tokio::test]
        async fn hijack_ip_same_no_alert() {
            let (_dao, session) = make_session();
            create_session_with_ip_ua(&session, "1001", "T1", Some("1.2.3.4"), None).await;

            let detector =
                SessionHijackDetector::new(session.clone(), SessionHijackMode::AlertOnly);
            let alerts = with_client_ip(Some("1.2.3.4"), || async {
                detector.check_on_check_login("1001", "T1").await.unwrap()
            })
            .await;
            assert!(alerts.is_empty(), "IP 相同时不应告警");
        }

        /// IP 不同且均为 Some 时产生 SessionHijackSuspected 事件。
        #[tokio::test]
        async fn hijack_ip_different_emits_alert() {
            let (_dao, session) = make_session();
            create_session_with_ip_ua(&session, "1001", "T1", Some("1.2.3.4"), None).await;

            let detector =
                SessionHijackDetector::new(session.clone(), SessionHijackMode::AlertOnly);
            let alerts = with_client_ip(Some("5.6.7.8"), || async {
                detector.check_on_check_login("1001", "T1").await.unwrap()
            })
            .await;
            assert_eq!(alerts.len(), 1, "IP 不同时应返回 1 个告警");
            match &alerts[0] {
                SecurityAlertEvent::AnomalyLogin {
                    anomaly_type,
                    detail,
                    ..
                } => {
                    assert_eq!(*anomaly_type, AnomalyType::SessionHijackSuspected);
                    assert!(detail.contains("1.2.3.4"), "detail 应包含存储 IP");
                    assert!(detail.contains("5.6.7.8"), "detail 应包含当前 IP");
                },
                _ => panic!("期望 AnomalyLogin 事件"),
            }
        }

        /// 存储 IP 为 None 时不告警。
        #[tokio::test]
        async fn hijack_stored_ip_none_no_alert() {
            let (_dao, session) = make_session();
            create_session_with_ip_ua(&session, "1001", "T1", None, None).await;

            let detector =
                SessionHijackDetector::new(session.clone(), SessionHijackMode::AlertOnly);
            let alerts = with_client_ip(Some("1.2.3.4"), || async {
                detector.check_on_check_login("1001", "T1").await.unwrap()
            })
            .await;
            assert!(alerts.is_empty(), "存储 IP 为 None 时不应告警");
        }

        /// 当前 IP 为 None 时不告警。
        #[tokio::test]
        async fn hijack_current_ip_none_no_alert() {
            let (_dao, session) = make_session();
            create_session_with_ip_ua(&session, "1001", "T1", Some("1.2.3.4"), None).await;

            let detector =
                SessionHijackDetector::new(session.clone(), SessionHijackMode::AlertOnly);
            // 不设置 task_local 上下文（current_client_ip 返回 None）
            let alerts = detector.check_on_check_login("1001", "T1").await.unwrap();
            assert!(alerts.is_empty(), "当前 IP 为 None 时不应告警");
        }

        /// Kickout 模式下检测到劫持时 token session 被删除。
        #[tokio::test]
        async fn hijack_kickout_mode_deletes_session() {
            let (_dao, session) = make_session();
            create_session_with_ip_ua(&session, "1001", "T1", Some("1.2.3.4"), None).await;

            assert!(session.get_token_session("T1").await.unwrap().is_some());

            let detector = SessionHijackDetector::new(session.clone(), SessionHijackMode::Kickout);
            let alerts = with_client_ip(Some("5.6.7.8"), || async {
                detector.check_on_check_login("1001", "T1").await.unwrap()
            })
            .await;
            assert_eq!(alerts.len(), 1, "应返回 1 个告警");
            assert!(
                session.get_token_session("T1").await.unwrap().is_none(),
                "Kickout 模式下 token session 应被删除"
            );
        }

        /// check_on_login 始终返回空 Vec。
        #[tokio::test]
        async fn hijack_check_on_login_returns_empty() {
            let (_dao, session) = make_session();
            let detector = SessionHijackDetector::new(session, SessionHijackMode::AlertOnly);
            let alerts = detector
                .check_on_login("1001", "dev-1", Some("1.2.3.4"))
                .await
                .unwrap();
            assert!(alerts.is_empty(), "check_on_login 应返回空 Vec");
        }
    }
}
