// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 严格设备绑定策略实现:`StrictBinding` 经 `get_tokens_by_login_id` + `get_token_session` 遍历历史
//! session 判断新设备(不依赖 `device` 模块,避免 feature gate 耦合);`require_secondary_auth` 直接
//! 返回 `Ok(true)`(调用方已先经 `is_new_device` 确认)。

use crate::error::GarrisonResult;
use crate::session::GarrisonSession;
use async_trait::async_trait;
use std::sync::Arc;

use super::DeviceBindingPolicy;

/// 严格设备绑定策略：新设备强制触发二级认证。
///
/// `is_new_device` 遍历历史 `TokenSession.device` 判断新颖性(空 `device_id` 返回 `Ok(false)`,见 `policies`)。
/// `require_secondary_auth` 无条件返回 `Ok(true)`、忽略两个参数且无任何运行时前置校验——"仅在新设备确认后调用"
/// 是隐式调用方契约(stp 层 `check_device_binding` 已按此顺序接线);误用后果是全部登录被要求二级认证,方向为
/// fail-closed(只可能错误拦截,不可能错误放行),fail-closed 部署还必须在上游拒绝空设备标识。
pub struct StrictBinding {
    /// 会话管理器引用，用于查询历史 session 的 device 字段。
    session: Arc<GarrisonSession>,
}

impl StrictBinding {
    /// 创建 [`StrictBinding`] 实例。
    pub fn new(session: Arc<GarrisonSession>) -> Self {
        Self { session }
    }
}

#[async_trait]
impl DeviceBindingPolicy for StrictBinding {
    async fn is_new_device(&self, login_id: &str, device_id: &str) -> GarrisonResult<bool> {
        super::policies::check_is_new_device(&self.session, login_id, device_id).await
    }

    /// 是否需要二级认证：**无条件返回 `Ok(true)`**（严格模式常量决策，忽略参数、不查 DAO）；
    /// "仅在新设备确认后调用"是隐式调用方契约(详见类型文档),误用方向为 fail-closed(过度阻断全部登录)。
    async fn require_secondary_auth(
        &self,
        login_id: &str,
        _device_id: &str,
    ) -> GarrisonResult<bool> {
        // 调用方已通过 is_new_device 确认是新设备,直接返回 true;debug! 留痕使该 no-op 决策可审计。
        tracing::debug!(
            login_id,
            "StrictBinding::require_secondary_auth: unconditional true (new-device confirmed by caller contract)"
        );
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::stp::LoginParams;

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

    // is_new_device 测试

    /// 历史 session 中不存在 device_id 时返回 true（新设备）。
    #[tokio::test]
    async fn is_new_device_returns_true_for_new_device() {
        let (_dao, session) = make_session();
        create_session_with_device(&session, "1001", "T1", "web-chrome").await;

        let policy = StrictBinding::new(session);
        let is_new = policy.is_new_device("1001", "mobile-ios").await.unwrap();
        assert!(
            is_new,
            "device_id 不在历史 session 中时应返回 true（新设备）"
        );
    }

    /// 历史 session 中存在 device_id 时返回 false（已知设备）。
    #[tokio::test]
    async fn is_new_device_returns_false_for_known_device() {
        let (_dao, session) = make_session();
        create_session_with_device(&session, "1001", "T1", "web-chrome").await;

        let policy = StrictBinding::new(session);
        let is_new = policy.is_new_device("1001", "web-chrome").await.unwrap();
        assert!(
            !is_new,
            "device_id 在历史 session 中时应返回 false（已知设备）"
        );
    }

    /// 无任何历史 session 时返回 true（新设备）。
    #[tokio::test]
    async fn is_new_device_returns_true_when_no_sessions() {
        let (_dao, session) = make_session();

        let policy = StrictBinding::new(session);
        let is_new = policy.is_new_device("1001", "web-chrome").await.unwrap();
        assert!(is_new, "无历史 session 时应返回 true（新设备）");
    }

    /// 空 device_id 返回 false（无设备标识不视为新设备）。
    #[tokio::test]
    async fn is_new_device_returns_false_for_empty_device_id() {
        let (_dao, session) = make_session();
        create_session_with_device(&session, "1001", "T1", "web-chrome").await;

        let policy = StrictBinding::new(session);
        let is_new = policy.is_new_device("1001", "").await.unwrap();
        assert!(
            !is_new,
            "空 device_id 应返回 false（无设备标识不视为新设备）"
        );
    }

    // require_secondary_auth 测试

    /// 新设备时 require_secondary_auth 返回 true（强制二级认证）。
    #[tokio::test]
    async fn require_secondary_auth_returns_true_for_new_device() {
        let (_dao, session) = make_session();
        create_session_with_device(&session, "1001", "T1", "web-chrome").await;

        let policy = StrictBinding::new(session);
        let require = policy
            .require_secondary_auth("1001", "mobile-ios")
            .await
            .unwrap();
        assert!(
            require,
            "新设备应触发二级认证（require_secondary_auth 返回 true）"
        );
    }

    /// require_secondary_auth 总是返回 true（调用方已通过 is_new_device 确认是新设备）。
    #[tokio::test]
    async fn require_secondary_auth_always_returns_true_after_high001_fix() {
        let (_dao, session) = make_session();
        create_session_with_device(&session, "1001", "T1", "web-chrome").await;

        let policy = StrictBinding::new(session);
        // 即使传入已知设备也返回 true:调用方(session.rs login 流程)仅在 is_new_device == true 后调用本方法。
        let require = policy
            .require_secondary_auth("1001", "web-chrome")
            .await
            .unwrap();
        assert!(
            require,
            "HIGH-001 修复后 require_secondary_auth 总是返回 true（调用方已确认是新设备）"
        );
    }

    /// 无 session 时 require_secondary_auth 返回 true（新设备）。
    #[tokio::test]
    async fn require_secondary_auth_returns_true_when_no_sessions() {
        let (_dao, session) = make_session();

        let policy = StrictBinding::new(session);
        let require = policy
            .require_secondary_auth("1001", "web-chrome")
            .await
            .unwrap();
        assert!(require, "无历史 session 时应触发二级认证（新设备）");
    }

    /// 多 session 部分匹配时返回 false（已知设备，任一匹配即可）。
    #[tokio::test]
    async fn is_new_device_returns_false_when_partial_match() {
        let (_dao, session) = make_session();
        // 三个 session，其中 T2 的 device 为 mobile-ios
        create_session_with_device(&session, "1001", "T1", "web-chrome").await;
        create_session_with_device(&session, "1001", "T2", "mobile-ios").await;
        create_session_with_device(&session, "1001", "T3", "api-client").await;

        let policy = StrictBinding::new(session);
        let is_new = policy.is_new_device("1001", "mobile-ios").await.unwrap();
        assert!(
            !is_new,
            "多 session 中任一 device 匹配时应返回 false（已知设备）"
        );
        let is_new = policy
            .is_new_device("1001", "tablet-android")
            .await
            .unwrap();
        assert!(is_new, "多 session 中均不匹配时应返回 true（新设备）");
    }
}
