//! PermissionLogic trait — 权限与角色校验契约。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 从 v0.5.2 起，从 `BulwarkLogic` 上帝 trait 拆分；本 trait 承接权限/角色校验 2 个方法。
//! super-trait 为 [`SessionLogic`]（权限校验需先通过 `get_login_id` 获取当前登录主体）。

use crate::error::BulwarkResult;
use crate::stp::session::SessionLogic;
use async_trait::async_trait;

/// 权限逻辑 trait，定义权限与角色校验契约。
///
/// [借鉴 Sa-Token] 对应 `StpLogic` 的 `checkPermission` / `checkRole` 部分。
///
/// # 方法
///
/// - [`check_permission`](Self::check_permission)：校验当前登录主体是否持有指定权限。
/// - [`check_role`](Self::check_role)：校验当前登录主体是否持有指定角色。
///
/// # 错误
///
/// - 未登录且 `throw_on_not_login=true`：`BulwarkError::NotLogin`。
/// - 未登录且 `throw_on_not_login=false`：降级为 `BulwarkError::NotPermission` / `NotRole`。
/// - 未持有权限/角色：`BulwarkError::NotPermission` / `NotRole`。
#[async_trait]
pub trait PermissionLogic: SessionLogic {
    /// 校验权限：检查当前登录主体是否持有指定权限。
    ///
    /// # 参数
    /// - `permission`: 权限标识字符串。
    ///
    /// # 返回
    /// 成功（持有权限）返回 `Ok(())`。
    ///
    /// # 错误
    /// - 未登录且 `throw_on_not_login=true`：`BulwarkError::NotLogin`。
    /// - 未登录且 `throw_on_not_login=false`：降级为 `BulwarkError::NotPermission`。
    /// - 未持有权限：`BulwarkError::NotPermission`。
    async fn check_permission(&self, permission: &str) -> BulwarkResult<()>;

    /// 校验角色：检查当前登录主体是否持有指定角色。
    ///
    /// # 参数
    /// - `role`: 角色标识字符串。
    ///
    /// # 返回
    /// 成功（持有角色）返回 `Ok(())`。
    ///
    /// # 错误
    /// - 未登录且 `throw_on_not_login=true`：`BulwarkError::NotLogin`。
    /// - 未登录且 `throw_on_not_login=false`：降级为 `BulwarkError::NotRole`。
    /// - 未持有角色：`BulwarkError::NotRole`。
    async fn check_role(&self, role: &str) -> BulwarkResult<()>;
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

    /// 最小 mock：实现 `BulwarkCore` + `SessionLogic`（9 必需方法）+ `PermissionLogic`（2 方法）。
    struct MockPermission {
        config: Arc<BulwarkConfig>,
        has_permission: bool,
    }

    impl BulwarkCore for MockPermission {
        fn config(&self) -> Arc<BulwarkConfig> {
            Arc::clone(&self.config)
        }
    }

    #[async_trait]
    impl SessionLogic for MockPermission {
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
    impl PermissionLogic for MockPermission {
        async fn check_permission(&self, _permission: &str) -> BulwarkResult<()> {
            if self.has_permission {
                Ok(())
            } else {
                Err(crate::error::BulwarkError::NotPermission(
                    "mock: not permission".to_string(),
                ))
            }
        }
        async fn check_role(&self, _role: &str) -> BulwarkResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn check_permission_grants_when_has() {
        let mock = MockPermission {
            config: Arc::new(BulwarkConfig::default()),
            has_permission: true,
        };
        mock.check_permission("user:read").await.unwrap();
    }

    #[tokio::test]
    async fn check_permission_denies_when_not_has() {
        let mock = MockPermission {
            config: Arc::new(BulwarkConfig::default()),
            has_permission: false,
        };
        let result = mock.check_permission("user:read").await;
        assert!(matches!(
            result,
            Err(crate::error::BulwarkError::NotPermission(_))
        ));
    }
}
