//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 异常检测器实现模块，提供 IP 变化检测与快速连续登录检测。

use crate::error::BulwarkResult;
use crate::session::BulwarkSession;
use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use super::{AnomalyDetector, AnomalyType, SecurityAlertEvent};

/// IP 变化检测器，对比当前登录 IP 与历史最近 session 的 IP。
///
/// 实现 `AnomalyDetector` trait，在 `check_on_login` 时：
/// 1. 通过 `BulwarkSession::get_tokens_by_login_id` 获取该 login_id 的所有 token
/// 2. 逐个获取 `TokenSession`，找到 `last_active_at` 最大的 session
/// 3. 取其 IP 作为历史 IP，与当前登录 IP 对比
/// 4. 不同则发出 `AnomalyLogin { anomaly_type: IpChanged }`
///
/// `check_on_check_login` 因签名不含当前 IP 参数，无法检测 IP 变化，返回空 Vec。
pub struct IpChangeDetector {
    /// 会话管理器引用，用于查询历史 session。
    session: Arc<BulwarkSession>,
}

impl IpChangeDetector {
    /// 创建 `IpChangeDetector` 实例。
    ///
    /// # 参数
    /// - `session`: 会话管理器引用（`Arc<BulwarkSession>`）。
    pub fn new(session: Arc<BulwarkSession>) -> Self {
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
    ) -> BulwarkResult<Vec<SecurityAlertEvent>> {
        // 无当前 IP 不告警
        let current_ip = match ip {
            Some(ip) => ip,
            None => return Ok(Vec::new()),
        };

        let tokens = self.session.get_tokens_by_login_id(login_id);
        if tokens.is_empty() {
            return Ok(Vec::new()); // 无历史 session 不告警
        }

        // 找到 last_active_at 最大的 session
        let mut latest_ip: Option<String> = None;
        let mut latest_active_at: i64 = i64::MIN;
        for token in &tokens {
            if let Some(ts) = self.session.get_token_session(token).await? {
                if ts.last_active_at > latest_active_at {
                    latest_active_at = ts.last_active_at;
                    latest_ip = ts.ip;
                }
            }
        }

        // 历史 IP 为 None 时不告警（无历史 IP 可对比）
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
            detail: format!("IP 从 {} 变为 {}", historical_ip, current_ip),
            trace_id: Uuid::new_v4().to_string(),
        }])
    }

    async fn check_on_check_login(
        &self,
        _login_id: &str,
        _token: &str,
    ) -> BulwarkResult<Vec<SecurityAlertEvent>> {
        // check_on_check_login 签名不含当前 IP，无法检测 IP 变化
        Ok(Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::dao::BulwarkDao;
    use crate::session::TokenSession;
    use crate::stp::LoginParams;

    /// 辅助函数：创建带 MockDao 的 BulwarkSession（Arc 包装）。
    fn make_session() -> (Arc<MockDao>, Arc<BulwarkSession>) {
        let dao: Arc<MockDao> = Arc::new(MockDao::new());
        let session = Arc::new(BulwarkSession::new(dao.clone(), 3600, 86400));
        (dao, session)
    }

    /// 辅助函数：创建带指定 IP 的 token session。
    async fn create_session_with_ip(
        session: &BulwarkSession,
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

    // ========================================================================
    // IpChangeDetector 测试
    // ========================================================================

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
        // 创建两个 session，T1 的 IP 为 1.1.1.1，T2 的 IP 为 2.2.2.2
        create_session_with_ip(&session, "1001", "T1", "1.1.1.1").await;
        create_session_with_ip(&session, "1001", "T2", "2.2.2.2").await;

        // 将 T1 的 last_active_at 设为更早的时间，使 T2 成为最近活跃的
        set_last_active_at(&dao, "T1", 1000).await;
        // T2 的 last_active_at 保持为当前时间（远大于 1000）

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
}
