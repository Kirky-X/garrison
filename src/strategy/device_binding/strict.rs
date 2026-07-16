//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 严格设备绑定策略实现。
//!
//! [`StrictBinding`] 实现 [`DeviceBindingPolicy`]（super::DeviceBindingPolicy）：
//! - `is_new_device`：遍历 `login_id` 的所有 `TokenSession`，若全部 session 的
//!   `device` 字段都不等于 `device_id`，则视为新设备
//! - `require_secondary_auth`：直接返回 `Ok(true)`（调用方已通过 `is_new_device` 确认是新设备）
//!
//! 设计参考 [`crate::strategy::alert::IpChangeDetector`]：持有 `Arc<BulwarkSession>`，
//! 通过 `get_tokens_by_login_id` + `get_token_session` 遍历历史 session，
//! 不依赖 `device` 模块（避免 feature gate 耦合）。

use crate::error::BulwarkResult;
use crate::session::BulwarkSession;
use async_trait::async_trait;
use std::sync::Arc;

use super::DeviceBindingPolicy;

/// 严格设备绑定策略：新设备强制触发二级认证。
///
/// 持有 [`BulwarkSession`] 引用，通过遍历历史 `TokenSession.device` 字段
/// 判断当前 `device_id` 是否为新设备。新设备时 `require_secondary_auth` 返回 `Ok(true)`，
/// 阻断登录流程并要求二级认证；旧设备返回 `Ok(false)` 直接放行。
///
/// # 空设备标识
///
/// `is_new_device` 对空 `device_id` 返回 `Ok(false)`（无设备标识不视为新设备），
/// 避免无设备信息的登录被错误阻断。
///
/// # HIGH-001 修复
///
/// `require_secondary_auth` 不再重复调用 `is_new_device`（调用方已先调用过，避免重复 DAO 查询）。
/// 调用方（`session.rs` login 流程）仅在 `is_new_device == true` 时才调用此方法，
/// 因此直接返回 `Ok(true)`。
pub struct StrictBinding {
    /// 会话管理器引用，用于查询历史 session 的 device 字段。
    session: Arc<BulwarkSession>,
}

impl StrictBinding {
    /// 创建 [`StrictBinding`] 实例。
    ///
    /// # 参数
    /// - `session`: 会话管理器引用（`Arc<BulwarkSession>`）。
    pub fn new(session: Arc<BulwarkSession>) -> Self {
        Self { session }
    }
}

#[async_trait]
impl DeviceBindingPolicy for StrictBinding {
    async fn is_new_device(&self, login_id: &str, device_id: &str) -> BulwarkResult<bool> {
        super::policies::check_is_new_device(&self.session, login_id, device_id).await
    }

    async fn require_secondary_auth(
        &self,
        _login_id: &str,
        _device_id: &str,
    ) -> BulwarkResult<bool> {
        // 调用方已通过 is_new_device 确认是新设备，直接返回 true（强制二级认证）
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::stp::LoginParams;

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

    // ========================================================================
    // is_new_device 测试
    // ========================================================================

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

    // ========================================================================
    // require_secondary_auth 测试
    // ========================================================================

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

    /// HIGH-001 修复后 require_secondary_auth 总是返回 true（调用方已通过 is_new_device 确认是新设备）。
    #[tokio::test]
    async fn require_secondary_auth_always_returns_true_after_high001_fix() {
        let (_dao, session) = make_session();
        create_session_with_device(&session, "1001", "T1", "web-chrome").await;

        let policy = StrictBinding::new(session);
        // 即使传入已知设备，require_secondary_auth 也返回 true
        // 因为调用方（session.rs login 流程）仅在 is_new_device == true 时才调用此方法
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
        // mobile-ios 在 T2 中存在 → 不是新设备
        let is_new = policy.is_new_device("1001", "mobile-ios").await.unwrap();
        assert!(
            !is_new,
            "多 session 中任一 device 匹配时应返回 false（已知设备）"
        );
        // 不存在的设备仍返回 true
        let is_new = policy
            .is_new_device("1001", "tablet-android")
            .await
            .unwrap();
        assert!(is_new, "多 session 中均不匹配时应返回 true（新设备）");
    }
}
