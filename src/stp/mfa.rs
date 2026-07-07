//! MfaLogic trait — 二级认证（MFA）与账号禁用校验契约。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 从 v0.5.2 起，从 `BulwarkLogic` 上帝 trait 拆分；本 trait 承接 MFA 校验与
//! 账号禁用检查 2 个方法。super-trait 为 [`SessionLogic`]
//! （MFA 检查依赖当前登录状态）。

use crate::error::BulwarkResult;
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
    /// 检查二级认证（MFA）状态（0.3.0 新增，依据 spec annotation-handling）。
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

    /// 检查账号是否被禁用（0.3.0 新增，依据 spec annotation-handling）。
    ///
    /// 默认实现返回 `Ok(())`（未实现禁用账号库，向后兼容 0.2.x）。
    /// 业务方覆写此方法以接入禁用账号检查：查询当前 login_id 是否在禁用列表中。
    ///
    /// # 返回
    /// - `Ok(())`: 账号未禁用。
    /// - `Err(BulwarkError::Session)`: 账号已禁用。
    async fn check_disable(&self) -> BulwarkResult<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BulwarkConfig;
    use crate::error::BulwarkResult;
    use crate::stp::core::BulwarkCore;
    use crate::stp::login_id::LoginId;
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
        async fn login(&self, _login_id: impl Into<LoginId> + Send) -> BulwarkResult<String> {
            Ok("mock-token".to_string())
        }
        async fn login_with_token(
            &self,
            _login_id: impl Into<LoginId> + Send,
            _token: &str,
        ) -> BulwarkResult<()> {
            Ok(())
        }
        async fn logout(&self) -> BulwarkResult<()> {
            Ok(())
        }
        async fn logout_by_login_id(
            &self,
            _login_id: impl Into<LoginId> + Send,
        ) -> BulwarkResult<()> {
            Ok(())
        }
        async fn kickout(&self, _login_id: impl Into<LoginId> + Send) -> BulwarkResult<()> {
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
        async fn get_login_id(&self) -> BulwarkResult<Option<LoginId>> {
            Ok(Some(LoginId::Numeric(42)))
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
}
