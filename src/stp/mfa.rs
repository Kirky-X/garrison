//! MfaLogic trait — 二级认证（MFA）与账号禁用校验契约。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 从 v0.5.2 起，从 `BulwarkLogic` 上帝 trait 拆分；本 trait 承接 MFA 校验与
//! 账号禁用检查 2 个方法。super-trait 为 [`SessionLogic`]
//! （MFA 检查依赖当前登录状态）。

use super::BulwarkLogicDefault;
use crate::error::{BulwarkError, BulwarkResult};
use crate::stp::session::SessionLogic;
use async_trait::async_trait;

/// MFA 逻辑 trait，定义二级认证与账号禁用校验契约。
///
/// [借鉴 Sa-Token] 对应 `StpLogic` 的 `checkSafe` / `checkDisable` 部分。
///
/// # 默认实现（向后兼容）
///
/// - [`check_safe`](Self::check_safe)：默认返回 `Ok(())`（未启用 MFA，兼容 0.2.x）。
///   业务方覆写以接入 TOTP MFA 校验。
/// - [`check_disable`](Self::check_disable)：默认返回 `Ok(())`（未实现禁用账号库，兼容 0.2.x）。
///   业务方覆写以查询当前 login_id 是否在禁用列表中。
#[async_trait]
pub trait MfaLogic: SessionLogic {
    /// 检查二级认证（MFA）状态。
    ///
    /// 默认实现返回 `Ok(())`（未启用 MFA，向后兼容 0.2.x）。
    /// 业务方覆写此方法以接入 TOTP MFA 校验：检查当前会话是否已完成二级认证。
    ///
    /// # 返回
    /// - `Ok(())`: 已通过二级认证或未启用 MFA。
    /// - `Err(BulwarkError::Session)`: 未通过二级认证。
    async fn check_safe(&self) -> BulwarkResult<()> {
        Ok(())
    }

    /// 检查账号是否被禁用。
    ///
    /// 默认实现返回 `Ok(())`（未实现禁用账号库，向后兼容 0.2.x）。
    /// 业务方覆写此方法以接入禁用账号检查：查询当前 login_id 是否在禁用列表中。
    ///
    /// # 返回
    /// - `Ok(())`: 账号未禁用。
    /// - `Err(BulwarkError::DisableService)`: 账号已封禁（0.6.1 起推荐使用专用异常）。
    async fn check_disable(&self) -> BulwarkResult<()> {
        Ok(())
    }

    /// 构造账号被封禁异常。
    ///
    /// 业务方在自定义 `check_disable` 实现中调用此关联函数抛出专用异常：
    ///
    /// ```ignore
    /// async fn check_disable(&self) -> BulwarkResult<()> {
    ///     if account_is_banned().await {
    ///         return Err(Self::disable_service("default", None));
    ///     }
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # 参数
    /// - `service`: 被封禁的服务名（如 "default" / "oidc"）。
    /// - `until`: 定时解封时间；`None` 表示永久封禁。
    fn disable_service(
        service: &str,
        until: Option<chrono::DateTime<chrono::Utc>>,
    ) -> BulwarkError {
        BulwarkError::DisableService {
            service: service.to_string(),
            until,
        }
    }

    /// 构造未完成二次认证异常。
    ///
    /// 业务方在自定义 `check_safe` 实现中调用此关联函数抛出专用异常：
    ///
    /// ```ignore
    /// async fn check_safe(&self) -> BulwarkResult<()> {
    ///     if !mfa_completed().await {
    ///         return Err(Self::not_safe("MFA_TOTP_REQUIRED"));
    ///     }
    ///     Ok(())
    /// }
    /// ```
    ///
    /// # 参数
    /// - `reason`: 未完成认证的原因标识（如 "MFA_TOTP_REQUIRED" / "WEBAUTHN_REQUIRED"）。
    fn not_safe(reason: &str) -> BulwarkError {
        BulwarkError::NotSafe {
            reason: reason.to_string(),
        }
    }
}

// ============================================================================
// BulwarkLogicDefault impl
// ============================================================================

#[async_trait]
impl MfaLogic for BulwarkLogicDefault {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BulwarkConfig;
    use crate::error::BulwarkResult;
    use crate::stp::core::BulwarkCore;
    use crate::stp::session::SessionLogic;
    use std::sync::Arc;

    /// 最小 mock：实现 `BulwarkCore` + `SessionLogic`（9 必需方法）。
    /// `MfaLogic` 2 个方法均有默认实现，空 impl 即可获得全部默认行为。
    struct MockMfa {
        config: Arc<BulwarkConfig>,
    }

    impl BulwarkCore for MockMfa {
        fn config(&self) -> Arc<BulwarkConfig> {
            Arc::clone(&self.config)
        }
    }

    #[async_trait]
    impl SessionLogic for MockMfa {
        async fn login(
            &self,
            _login_id: &str,
            _params: &crate::stp::LoginParams,
        ) -> BulwarkResult<String> {
            Ok("mock-token".to_string())
        }
        async fn login_with_token(&self, _login_id: &str, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn logout(&self) -> BulwarkResult<()> {
            Ok(())
        }
        async fn logout_by_login_id(&self, _login_id: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn kickout(&self, _login_id: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn kickout_by_token(&self, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn revoke_token(&self, _token: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_login(&self) -> BulwarkResult<bool> {
            Ok(true)
        }
        async fn get_login_id(&self) -> BulwarkResult<Option<String>> {
            Ok(Some("42".to_string()))
        }
    }

    #[async_trait]
    impl MfaLogic for MockMfa {}

    #[tokio::test]
    async fn check_safe_default_ok() {
        let mock = MockMfa {
            config: Arc::new(BulwarkConfig::default()),
        };
        mock.check_safe().await.unwrap();
    }

    #[tokio::test]
    async fn check_disable_default_ok() {
        let mock = MockMfa {
            config: Arc::new(BulwarkConfig::default()),
        };
        mock.check_disable().await.unwrap();
    }

    // ========================================================================
    // disable_service / not_safe 构造方法测试
    // ========================================================================

    /// 验证 `disable_service` 构造正确的 `BulwarkError::DisableService` 变体。
    ///
    /// 覆盖 spec R-error-005：service 字段正确传递，until=None 表示永久封禁。
    #[test]
    fn disable_service_constructs_correct_error() {
        let err = MockMfa::disable_service("default", None);
        match err {
            BulwarkError::DisableService { service, until } => {
                assert_eq!(service, "default");
                assert!(until.is_none(), "until=None 表示永久封禁");
            },
            other => panic!("期望 DisableService 变体，实际: {:?}", other),
        }
    }

    /// 验证 `disable_service` 带 until 时间戳时正确传递。
    #[test]
    fn disable_service_with_until_timestamp() {
        let until = chrono::DateTime::parse_from_rfc3339("2026-12-31T23:59:59Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let err = MockMfa::disable_service("oidc", Some(until));
        match err {
            BulwarkError::DisableService { service, until: u } => {
                assert_eq!(service, "oidc");
                assert!(u.is_some(), "until 应为 Some");
                assert_eq!(u.unwrap().to_rfc3339(), "2026-12-31T23:59:59+00:00");
            },
            other => panic!("期望 DisableService 变体，实际: {:?}", other),
        }
    }

    /// 验证 `not_safe` 构造正确的 `BulwarkError::NotSafe` 变体。
    ///
    /// 覆盖 spec R-error-005：reason 字段正确传递。
    #[test]
    fn not_safe_constructs_correct_error() {
        let err = MockMfa::not_safe("MFA_TOTP_REQUIRED");
        match err {
            BulwarkError::NotSafe { reason } => {
                assert_eq!(reason, "MFA_TOTP_REQUIRED");
            },
            other => panic!("期望 NotSafe 变体，实际: {:?}", other),
        }
    }

    /// 验证 `not_safe` 可构造 Display 输出包含 reason。
    #[test]
    fn not_safe_display_includes_reason() {
        let err = MockMfa::not_safe("WEBAUTHN_REQUIRED");
        let display = err.to_string();
        assert!(
            display.contains("WEBAUTHN_REQUIRED"),
            "Display 应包含 reason，实际: {}",
            display
        );
        assert!(
            display.contains("未完成二次认证"),
            "Display 应包含中文描述，实际: {}",
            display
        );
    }
}
