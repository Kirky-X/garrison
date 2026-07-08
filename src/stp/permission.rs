//! PermissionLogic trait — 权限与角色校验契约。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 从 v0.5.2 起，从 `BulwarkLogic` 上帝 trait 拆分；本 trait 承接权限/角色校验 2 个方法。
//! super-trait 为 [`SessionLogic`]（权限校验需先通过 `get_login_id` 获取当前登录主体）。

use super::BulwarkLogicDefault;
use crate::context::tenant::current_tenant_id;
use crate::core::permission::AuthRequest;
use crate::error::{BulwarkError, BulwarkResult};
#[cfg(feature = "listener")]
use crate::listener::BulwarkEvent;
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

// ============================================================================
// BulwarkLogicDefault impl
// ============================================================================

#[async_trait]
impl PermissionLogic for BulwarkLogicDefault {
    async fn check_permission(&self, permission: &str) -> BulwarkResult<()> {
        // spec scenario "未登录抛出异常"：未登录时依据 throw_on_not_login 抛错
        let login_id = match self.get_login_id().await? {
            Some(id) => id,
            None => {
                // emit metrics：未登录视为 deny
                #[cfg(feature = "metrics-prometheus")]
                if let Some(m) = &self.metrics {
                    m.record_permission_query(false);
                }
                return if self.config.throw_on_not_login {
                    Err(BulwarkError::NotLogin("未登录，无法校验权限".to_string()))
                } else {
                    // throw_on_not_login=false：未登录视为无权限，抛 NotPermission
                    Err(BulwarkError::NotPermission(permission.to_string()))
                };
            },
        };
        // v0.5.0：优先委托 PermissionChecker（若注入），走 authorize + Decision 路径
        // 并广播 PermissionCheck 事件供 AuditLogListener 记录审计日志（依据 proposal H3/H7）
        if let Some(pc) = &self.permission_checker {
            let request = AuthRequest {
                login_id: login_id.clone(),
                tenant_id: current_tenant_id(),
                action: permission.to_string(),
                resource: None,
                context: serde_json::Value::Null,
            };
            let decision = pc.authorize(&request).await?;

            // 广播 PermissionCheck 事件（audit listener 据此写审计日志）
            #[cfg(feature = "listener")]
            if let Some(lm) = &self.listener_manager {
                lm.broadcast(&BulwarkEvent::PermissionCheck {
                    login_id,
                    permission: permission.to_string(),
                })
                .await;
            }

            #[cfg(feature = "metrics-prometheus")]
            if let Some(m) = &self.metrics {
                m.record_permission_query(decision.allowed);
            }

            return if decision.allowed {
                Ok(())
            } else {
                Err(BulwarkError::NotPermission(permission.to_string()))
            };
        }

        // 回退到 firewall 路径（permission_checker 未注入时）
        let has_perm = self
            .firewall
            .check_permission(&login_id, permission)
            .await?;
        // emit metrics：权限查询结果
        #[cfg(feature = "metrics-prometheus")]
        if let Some(m) = &self.metrics {
            m.record_permission_query(has_perm);
        }
        if has_perm {
            Ok(())
        } else {
            Err(BulwarkError::NotPermission(permission.to_string()))
        }
    }

    async fn check_role(&self, role: &str) -> BulwarkResult<()> {
        // spec scenario "未登录抛出异常"：未登录时依据 throw_on_not_login 抛错
        let login_id = match self.get_login_id().await? {
            Some(id) => id,
            None => {
                // emit metrics：未登录视为 deny
                #[cfg(feature = "metrics-prometheus")]
                if let Some(m) = &self.metrics {
                    m.record_role_query(false);
                }
                return if self.config.throw_on_not_login {
                    Err(BulwarkError::NotLogin("未登录，无法校验角色".to_string()))
                } else {
                    // throw_on_not_login=false：未登录视为无角色，抛 NotRole
                    Err(BulwarkError::NotRole(role.to_string()))
                };
            },
        };
        // 委托 BulwarkPermissionStrategy 做角色校验
        let has_role = self.firewall.check_role(&login_id, role).await?;
        // emit metrics：角色查询结果
        #[cfg(feature = "metrics-prometheus")]
        if let Some(m) = &self.metrics {
            m.record_role_query(has_role);
        }
        if has_role {
            Ok(())
        } else {
            Err(BulwarkError::NotRole(role.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::BulwarkConfig;
    use crate::error::BulwarkResult;
    use crate::stp::core::BulwarkCore;
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
        async fn login(&self, _login_id: &str) -> BulwarkResult<String> {
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
