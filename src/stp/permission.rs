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
/// [借鉴 Sa-Token] 对应 `StpLogic` 的 `checkPermission` / `checkRole` / `hasPermission` / `hasRole` 部分。
///
/// # 方法
///
/// - [`check_permission`](Self::check_permission)：校验权限，未持有抛 `NotPermission`。
/// - [`check_role`](Self::check_role)：校验角色，未持有抛 `NotRole`。
/// - [`has_permission`](Self::has_permission)：检查是否持有权限，返回布尔值（0.6.1 新增）。
/// - [`has_role`](Self::has_role)：检查是否持有角色，返回布尔值（0.6.1 新增）。
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

    /// 检查当前登录主体是否持有指定权限（0.6.1 新增，依据 spec bulwark-util-api R-util-api-001，对应 FRD §5.3.2 hasPermission）。
    ///
    /// 与 [`check_permission`](Self::check_permission) 的区别：本方法返回布尔值而非抛出异常。
    /// 未登录或未持有权限均返回 `Ok(false)`，不抛出 `NotLogin` / `NotPermission`。
    ///
    /// # 参数
    /// - `permission`: 权限标识字符串。
    ///
    /// # 返回
    /// - `Ok(true)`: 当前会话持有该权限。
    /// - `Ok(false)`: 当前会话未持有该权限或未登录。
    ///
    /// # 错误
    /// - DAO 层错误等非权限性错误：透传 `BulwarkError`。
    ///
    /// # 默认实现
    ///
    /// 包装 [`check_permission`](Self::check_permission)，将 `NotPermission` / `NotLogin`
    /// 映射为 `Ok(false)`，其余错误透传。业务方可覆写以直接查询权限列表（避免异常开销）。
    async fn has_permission(&self, permission: &str) -> BulwarkResult<bool> {
        match self.check_permission(permission).await {
            Ok(()) => Ok(true),
            Err(BulwarkError::NotPermission(_)) => Ok(false),
            Err(BulwarkError::NotLogin(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// 检查当前登录主体是否持有指定角色（0.6.1 新增，依据 spec bulwark-util-api R-util-api-002，对应 FRD §5.3.2 hasRole）。
    ///
    /// 与 [`check_role`](Self::check_role) 的区别：本方法返回布尔值而非抛出异常。
    /// 未登录或未持有角色均返回 `Ok(false)`，不抛出 `NotLogin` / `NotRole`。
    ///
    /// # 参数
    /// - `role`: 角色标识字符串。
    ///
    /// # 返回
    /// - `Ok(true)`: 当前会话持有该角色。
    /// - `Ok(false)`: 当前会话未持有该角色或未登录。
    ///
    /// # 错误
    /// - DAO 层错误等非角色性错误：透传 `BulwarkError`。
    ///
    /// # 默认实现
    ///
    /// 包装 [`check_role`](Self::check_role)，将 `NotRole` / `NotLogin`
    /// 映射为 `Ok(false)`，其余错误透传。业务方可覆写以直接查询角色列表（避免异常开销）。
    async fn has_role(&self, role: &str) -> BulwarkResult<bool> {
        match self.check_role(role).await {
            Ok(()) => Ok(true),
            Err(BulwarkError::NotRole(_)) => Ok(false),
            Err(BulwarkError::NotLogin(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// 获取当前登录主体的权限列表（0.6.1 新增，依据 spec bulwark-util-api R-util-api-003，对应 FRD §5.3.2 getPermissionList）。
    ///
    /// 从当前会话上下文获取 login_id 后委托 `BulwarkPermissionStrategy` 查询权限数据。
    /// 未登录时返回 `Ok(vec![])`（非抛出异常），适用于 UI 渲染等无需强制登录的场景。
    ///
    /// # 返回
    /// - `Ok(permissions)`: 权限标识字符串列表（如 `["user:read", "user:write"]`），可为空。
    ///
    /// # 错误
    /// - 数据源访问失败：透传 `BulwarkError`。
    ///
    /// # 默认实现
    ///
    /// 返回 `Err(NotImplemented)`；`BulwarkLogicDefault` 覆写为委托 `firewall.get_permission_list(login_id)`。
    async fn get_permission_list(&self) -> BulwarkResult<Vec<String>> {
        Err(BulwarkError::NotImplemented(
            "get_permission_list 未实现（默认实现，需在 BulwarkLogicDefault 或业务实现中覆写）"
                .to_string(),
        ))
    }

    /// 获取当前登录主体的角色列表（0.6.1 新增，依据 spec bulwark-util-api R-util-api-004，对应 FRD §5.3.2 getRoleList）。
    ///
    /// 从当前会话上下文获取 login_id 后委托 `BulwarkPermissionStrategy` 查询角色数据。
    /// 未登录时返回 `Ok(vec![])`。
    ///
    /// # 返回
    /// - `Ok(roles)`: 角色标识字符串列表（如 `["admin", "user"]`），可为空。
    ///
    /// # 错误
    /// - 数据源访问失败：透传 `BulwarkError`。
    ///
    /// # 默认实现
    ///
    /// 返回 `Err(NotImplemented)`；`BulwarkLogicDefault` 覆写为委托 `firewall.get_role_list(login_id)`。
    async fn get_role_list(&self) -> BulwarkResult<Vec<String>> {
        Err(BulwarkError::NotImplemented(
            "get_role_list 未实现（默认实现，需在 BulwarkLogicDefault 或业务实现中覆写）"
                .to_string(),
        ))
    }
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

    async fn get_permission_list(&self) -> BulwarkResult<Vec<String>> {
        // 未登录返回空列表（非抛出异常，适用于 UI 渲染等无需强制登录的场景）
        let login_id = match self.get_login_id().await? {
            Some(id) => id,
            None => return Ok(vec![]),
        };
        self.firewall.get_permission_list(&login_id).await
    }

    async fn get_role_list(&self) -> BulwarkResult<Vec<String>> {
        let login_id = match self.get_login_id().await? {
            Some(id) => id,
            None => return Ok(vec![]),
        };
        self.firewall.get_role_list(&login_id).await
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

    // ========================================================================
    // has_permission / has_role 默认实现测试（0.6.1 新增，依据 R-util-api-001/002）
    // ========================================================================

    /// 可配置 check_permission/check_role 返回值的 mock，用于测试 has_permission/has_role 默认实现。
    ///
    /// `perm_result` / `role_result` 为预设返回值，覆盖 Ok / NotPermission / NotLogin / Dao 四类分支。
    struct MockPermissionHas {
        config: Arc<BulwarkConfig>,
        perm_result: BulwarkResult<()>,
        role_result: BulwarkResult<()>,
    }

    impl BulwarkCore for MockPermissionHas {
        fn config(&self) -> Arc<BulwarkConfig> {
            Arc::clone(&self.config)
        }
    }

    #[async_trait]
    impl SessionLogic for MockPermissionHas {
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
    impl PermissionLogic for MockPermissionHas {
        async fn check_permission(&self, _permission: &str) -> BulwarkResult<()> {
            // 克隆预设结果（BulwarkError 不实现 Clone，用相同变体重建）
            match &self.perm_result {
                Ok(()) => Ok(()),
                Err(crate::error::BulwarkError::NotPermission(s)) => {
                    Err(crate::error::BulwarkError::NotPermission(s.clone()))
                },
                Err(crate::error::BulwarkError::NotLogin(s)) => {
                    Err(crate::error::BulwarkError::NotLogin(s.clone()))
                },
                Err(crate::error::BulwarkError::Dao(s)) => {
                    Err(crate::error::BulwarkError::Dao(s.clone()))
                },
                Err(e) => panic!("MockPermissionHas 不支持此错误变体: {:?}", e),
            }
        }
        async fn check_role(&self, _role: &str) -> BulwarkResult<()> {
            match &self.role_result {
                Ok(()) => Ok(()),
                Err(crate::error::BulwarkError::NotRole(s)) => {
                    Err(crate::error::BulwarkError::NotRole(s.clone()))
                },
                Err(crate::error::BulwarkError::NotLogin(s)) => {
                    Err(crate::error::BulwarkError::NotLogin(s.clone()))
                },
                Err(crate::error::BulwarkError::Dao(s)) => {
                    Err(crate::error::BulwarkError::Dao(s.clone()))
                },
                Err(e) => panic!("MockPermissionHas 不支持此错误变体: {:?}", e),
            }
        }
    }

    fn ok_perm_mock() -> MockPermissionHas {
        MockPermissionHas {
            config: Arc::new(BulwarkConfig::default()),
            perm_result: Ok(()),
            role_result: Ok(()),
        }
    }

    /// has_permission：check_permission 返回 Ok → has_permission 返回 Ok(true)。
    #[tokio::test]
    async fn has_permission_returns_true_when_check_ok() {
        let mock = ok_perm_mock();
        assert!(mock.has_permission("user:read").await.unwrap());
    }

    /// has_permission：check_permission 返回 NotPermission → has_permission 返回 Ok(false)。
    #[tokio::test]
    async fn has_permission_returns_false_when_not_permission() {
        let mut mock = ok_perm_mock();
        mock.perm_result = Err(BulwarkError::NotPermission("user:read".to_string()));
        assert!(!mock.has_permission("user:read").await.unwrap());
    }

    /// has_permission：check_permission 返回 NotLogin → has_permission 返回 Ok(false)。
    #[tokio::test]
    async fn has_permission_returns_false_when_not_login() {
        let mut mock = ok_perm_mock();
        mock.perm_result = Err(BulwarkError::NotLogin("未登录".to_string()));
        assert!(!mock.has_permission("user:read").await.unwrap());
    }

    /// has_permission：check_permission 返回 Dao 错误 → has_permission 透传错误（不吞错）。
    #[tokio::test]
    async fn has_permission_propagates_dao_error() {
        let mut mock = ok_perm_mock();
        mock.perm_result = Err(BulwarkError::Dao("连接失败".to_string()));
        let result = mock.has_permission("user:read").await;
        assert!(
            matches!(result, Err(BulwarkError::Dao(ref s)) if s.contains("连接失败")),
            "Dao 错误应透传，实际: {:?}",
            result
        );
    }

    /// has_role：check_role 返回 Ok → has_role 返回 Ok(true)。
    #[tokio::test]
    async fn has_role_returns_true_when_check_ok() {
        let mock = ok_perm_mock();
        assert!(mock.has_role("admin").await.unwrap());
    }

    /// has_role：check_role 返回 NotRole → has_role 返回 Ok(false)。
    #[tokio::test]
    async fn has_role_returns_false_when_not_role() {
        let mut mock = ok_perm_mock();
        mock.role_result = Err(BulwarkError::NotRole("admin".to_string()));
        assert!(!mock.has_role("admin").await.unwrap());
    }

    /// has_role：check_role 返回 NotLogin → has_role 返回 Ok(false)。
    #[tokio::test]
    async fn has_role_returns_false_when_not_login() {
        let mut mock = ok_perm_mock();
        mock.role_result = Err(BulwarkError::NotLogin("未登录".to_string()));
        assert!(!mock.has_role("admin").await.unwrap());
    }

    /// has_role：check_role 返回 Dao 错误 → has_role 透传错误。
    #[tokio::test]
    async fn has_role_propagates_dao_error() {
        let mut mock = ok_perm_mock();
        mock.role_result = Err(BulwarkError::Dao("连接失败".to_string()));
        let result = mock.has_role("admin").await;
        assert!(
            matches!(result, Err(BulwarkError::Dao(ref s)) if s.contains("连接失败")),
            "Dao 错误应透传，实际: {:?}",
            result
        );
    }

    /// 复用现有 MockPermission（bool 字段）验证 has_permission 默认实现与 check_permission 一致性。
    #[tokio::test]
    async fn has_permission_true_when_mock_field_true() {
        let mock = MockPermission {
            config: Arc::new(BulwarkConfig::default()),
            has_permission: true,
        };
        assert!(mock.has_permission("user:read").await.unwrap());
    }

    /// 复用现有 MockPermission（bool=false）验证 has_permission 返回 false。
    #[tokio::test]
    async fn has_permission_false_when_mock_field_false() {
        let mock = MockPermission {
            config: Arc::new(BulwarkConfig::default()),
            has_permission: false,
        };
        assert!(!mock.has_permission("user:read").await.unwrap());
    }

    // ========================================================================
    // get_permission_list / get_role_list 默认实现测试（0.6.1 新增，依据 R-util-api-003/004）
    // ========================================================================

    /// get_permission_list 默认实现返回 NotImplemented（未覆写时）。
    #[tokio::test]
    async fn get_permission_list_default_returns_not_implemented() {
        let mock = ok_perm_mock();
        let result = mock.get_permission_list().await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(ref s)) if s.contains("get_permission_list")),
            "默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    /// get_role_list 默认实现返回 NotImplemented（未覆写时）。
    #[tokio::test]
    async fn get_role_list_default_returns_not_implemented() {
        let mock = ok_perm_mock();
        let result = mock.get_role_list().await;
        assert!(
            matches!(result, Err(BulwarkError::NotImplemented(ref s)) if s.contains("get_role_list")),
            "默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }
}
