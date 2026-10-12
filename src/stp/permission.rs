// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! PermissionLogic trait — 权限与角色校验契约。
//! super-trait 为 [`SessionLogic`]（校验前需经 `get_login_id` 获取当前登录主体）。

use super::GarrisonLogicDefault;
// tenant-isolation 启用时租户缺失强制 fail-closed；关闭时无租户上下文，TENANT 缺失视为租户 0（单租户）
#[cfg(feature = "tenant-isolation")]
use crate::context::tenant::current_tenant_id_or_error;
#[cfg(not(feature = "tenant-isolation"))]
use crate::context::tenant::TENANT;
use crate::core::permission::AuthRequest;
use crate::error::{GarrisonError, GarrisonResult};
#[cfg(feature = "listener")]
use crate::listener::GarrisonEvent;
use crate::stp::session::SessionLogic;
use async_trait::async_trait;

/// 权限逻辑 trait，定义权限与角色校验契约（对应 `StpLogic` 的 checkPermission / checkRole / hasPermission / hasRole 部分）。
/// `check_*` 未登录且 `throw_on_not_login=true` 返回 `NotLogin`，`false` 时降级为 `NotPermission` / `NotRole`；未持有权限/角色同后者。
#[async_trait]
pub trait PermissionLogic: SessionLogic {
    /// 校验权限：未持有返回 `NotPermission`；未登录且 `throw_on_not_login=true` 返回 `NotLogin`，否则降级 `NotPermission`。
    async fn check_permission(&self, permission: &str) -> GarrisonResult<()>;

    /// 校验角色：未持有返回 `NotRole`；未登录且 `throw_on_not_login=true` 返回 `NotLogin`，否则降级 `NotRole`。
    async fn check_role(&self, role: &str) -> GarrisonResult<()>;

    /// 检查是否持有指定权限：返回布尔不抛错，未登录或未持有均 `Ok(false)`，DAO 等非权限错误透传。
    /// 默认包装 [`check_permission`](Self::check_permission) 把 `NotPermission` / `NotLogin` 映射为 `Ok(false)`；业务方可覆写直接查权限列表（避免异常开销）。
    async fn has_permission(&self, permission: &str) -> GarrisonResult<bool> {
        match self.check_permission(permission).await {
            Ok(()) => Ok(true),
            Err(GarrisonError::NotPermission(_)) => Ok(false),
            Err(GarrisonError::NotLogin(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// 检查是否持有指定角色：返回布尔不抛错，未登录或未持有均 `Ok(false)`，DAO 等非角色错误透传。
    /// 默认包装 [`check_role`](Self::check_role) 把 `NotRole` / `NotLogin` 映射为 `Ok(false)`；业务方可覆写直接查角色列表（避免异常开销）。
    async fn has_role(&self, role: &str) -> GarrisonResult<bool> {
        match self.check_role(role).await {
            Ok(()) => Ok(true),
            Err(GarrisonError::NotRole(_)) => Ok(false),
            Err(GarrisonError::NotLogin(_)) => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// 获取当前登录主体的权限列表：未登录返回 `Ok(vec![])`（不抛错，适用于 UI 渲染等场景）。
    /// 默认返回 `Err(NotImplemented)`；`GarrisonLogicDefault` 覆写为委托 `firewall.get_permission_list(login_id)`。
    async fn get_permission_list(&self) -> GarrisonResult<Vec<String>> {
        Err(GarrisonError::NotImplemented(
            "stp-not-implemented::get_permission_list".to_string(),
        ))
    }

    /// 获取当前登录主体的角色列表：未登录返回 `Ok(vec![])`。
    /// 默认返回 `Err(NotImplemented)`；`GarrisonLogicDefault` 覆写为委托 `firewall.get_role_list(login_id)`。
    async fn get_role_list(&self) -> GarrisonResult<Vec<String>> {
        Err(GarrisonError::NotImplemented(
            "stp-not-implemented::get_role_list".to_string(),
        ))
    }
}

// GarrisonLogicDefault impl

#[async_trait]
impl PermissionLogic for GarrisonLogicDefault {
    async fn check_permission(&self, permission: &str) -> GarrisonResult<()> {
        let login_id = match self.get_login_id().await? {
            Some(id) => id,
            None => {
                #[cfg(feature = "metrics-prometheus")]
                if let Some(m) = &self.metrics {
                    m.record_permission_query(false);
                }
                return if self.config.throw_on_not_login {
                    Err(GarrisonError::NotLogin("stp-not-login::".to_string()))
                } else {
                    Err(GarrisonError::NotPermission(permission.to_string()))
                };
            },
        };
        // 注入 PermissionChecker 时优先走 authorize + Decision 路径，并广播 PermissionCheck 供审计。
        if let Some(pc) = &self.permission_checker {
            #[cfg(not(feature = "tenant-isolation"))]
            let tenant_id = TENANT.try_get().map(|ctx| ctx.tenant_id).unwrap_or(0);
            #[cfg(feature = "tenant-isolation")]
            let tenant_id = current_tenant_id_or_error()?;
            let request = AuthRequest {
                login_id: login_id.clone(),
                tenant_id,
                action: permission.to_string(),
                resource: None,
                context: serde_json::Value::Null,
            };
            let decision = pc.authorize(&request).await?;

            #[cfg(feature = "listener")]
            if let Some(lm) = &self.listener_manager {
                lm.broadcast(&GarrisonEvent::PermissionCheck {
                    login_id,
                    permission: permission.to_string(),
                    request_context: None,
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
                Err(GarrisonError::NotPermission(permission.to_string()))
            };
        }

        // 回退 firewall 路径：同样传 tenant_id 做隔离，否则 tenant-isolation 启用且 checker 未注入时隔离被绕过（默认实现把请求级租户纳入权限缓存键）。
        #[cfg(not(feature = "tenant-isolation"))]
        let tenant_id = TENANT.try_get().map(|ctx| ctx.tenant_id).unwrap_or(0);
        #[cfg(feature = "tenant-isolation")]
        let tenant_id = current_tenant_id_or_error()?;
        let has_perm = self
            .firewall
            .check_permission_in_tenant(tenant_id, &login_id, permission)
            .await?;
        #[cfg(feature = "metrics-prometheus")]
        if let Some(m) = &self.metrics {
            m.record_permission_query(has_perm);
        }
        if has_perm {
            Ok(())
        } else {
            Err(GarrisonError::NotPermission(permission.to_string()))
        }
    }

    async fn check_role(&self, role: &str) -> GarrisonResult<()> {
        let login_id = match self.get_login_id().await? {
            Some(id) => id,
            None => {
                #[cfg(feature = "metrics-prometheus")]
                if let Some(m) = &self.metrics {
                    m.record_role_query(false);
                }
                return if self.config.throw_on_not_login {
                    Err(GarrisonError::NotLogin("stp-not-login::".to_string()))
                } else {
                    Err(GarrisonError::NotRole(role.to_string()))
                };
            },
        };
        // 注入 checker 时走 has_role + RoleCheck 事件（角色语义；与 check_permission 的 checker 分支对齐）。
        if let Some(pc) = &self.permission_checker {
            // tenant-isolation 启用时无租户上下文 fail-closed（与 firewall 回退路径对齐）
            #[cfg(feature = "tenant-isolation")]
            current_tenant_id_or_error()?;
            let has_role = pc.has_role(&login_id, role).await?;

            #[cfg(feature = "listener")]
            if let Some(lm) = &self.listener_manager {
                lm.broadcast(&GarrisonEvent::RoleCheck {
                    login_id,
                    role: role.to_string(),
                    request_context: None,
                })
                .await;
            }

            #[cfg(feature = "metrics-prometheus")]
            if let Some(m) = &self.metrics {
                m.record_role_query(has_role);
            }

            return if has_role {
                Ok(())
            } else {
                Err(GarrisonError::NotRole(role.to_string()))
            };
        }

        // 租户隔离：经 `check_role_in_tenant` 传 tenant_id，防止跨租户角色检查绕过。
        #[cfg(not(feature = "tenant-isolation"))]
        let tenant_id = TENANT.try_get().map(|ctx| ctx.tenant_id).unwrap_or(0);
        #[cfg(feature = "tenant-isolation")]
        let tenant_id = current_tenant_id_or_error()?;
        let has_role = self
            .firewall
            .check_role_in_tenant(tenant_id, &login_id, role)
            .await?;
        #[cfg(feature = "metrics-prometheus")]
        if let Some(m) = &self.metrics {
            m.record_role_query(has_role);
        }
        if has_role {
            Ok(())
        } else {
            Err(GarrisonError::NotRole(role.to_string()))
        }
    }

    async fn get_permission_list(&self) -> GarrisonResult<Vec<String>> {
        let login_id = match self.get_login_id().await? {
            Some(id) => id,
            None => return Ok(vec![]),
        };
        self.firewall.get_permission_list(&login_id).await
    }

    async fn get_role_list(&self) -> GarrisonResult<Vec<String>> {
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
    use crate::config::GarrisonConfig;
    use crate::error::GarrisonResult;
    use crate::stp::core::GarrisonCore;
    use crate::stp::session::SessionLogic;
    use crate::stp::LoginParams;
    use std::sync::Arc;

    /// 最小 mock：实现 `GarrisonCore` + `SessionLogic`（9 必需方法）+ `PermissionLogic`（2 方法）。
    struct MockPermission {
        config: Arc<GarrisonConfig>,
        has_permission: bool,
    }

    impl GarrisonCore for MockPermission {
        fn config(&self) -> Arc<GarrisonConfig> {
            Arc::clone(&self.config)
        }
    }

    #[async_trait]
    impl SessionLogic for MockPermission {
        async fn login(
            &self,
            _login_id: &str,
            _params: &crate::stp::LoginParams,
        ) -> GarrisonResult<String> {
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

    #[async_trait]
    impl PermissionLogic for MockPermission {
        async fn check_permission(&self, _permission: &str) -> GarrisonResult<()> {
            if self.has_permission {
                Ok(())
            } else {
                Err(crate::error::GarrisonError::NotPermission(
                    "mock: not permission".to_string(),
                ))
            }
        }
        async fn check_role(&self, _role: &str) -> GarrisonResult<()> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn check_permission_grants_when_has() {
        let mock = MockPermission {
            config: Arc::new(GarrisonConfig::default()),
            has_permission: true,
        };
        mock.check_permission("user:read").await.unwrap();
    }

    #[tokio::test]
    async fn check_permission_denies_when_not_has() {
        let mock = MockPermission {
            config: Arc::new(GarrisonConfig::default()),
            has_permission: false,
        };
        let result = mock.check_permission("user:read").await;
        assert!(matches!(
            result,
            Err(crate::error::GarrisonError::NotPermission(_))
        ));
    }

    /// 调用 MockPermission 的所有 SessionLogic + GarrisonCore + PermissionLogic 方法以确保覆盖。
    #[tokio::test]
    async fn mock_permission_all_methods() {
        let mock = MockPermission {
            config: Arc::new(GarrisonConfig::default()),
            has_permission: true,
        };
        let _ = mock.config();
        let params = LoginParams::default();
        let _ = mock.login("u1", &params).await.unwrap();
        let _ = mock.login_with_token("u1", "tok").await;
        let _ = mock.logout().await;
        let _ = mock.logout_by_login_id("u1").await;
        let _ = mock.kickout("u1").await;
        let _ = mock.kickout_by_token("tok").await;
        let _ = mock.revoke_token("tok").await;
        let _ = mock.check_login().await.unwrap();
        let _ = mock.get_login_id().await.unwrap();
        let _ = mock.check_permission("user:read").await;
        let _ = mock.check_role("admin").await;
    }

    /// 调用 MockPermissionHas 的所有 SessionLogic + GarrisonCore 方法以确保覆盖。
    #[tokio::test]
    async fn mock_permission_has_all_methods() {
        let mock = MockPermissionHas {
            config: Arc::new(GarrisonConfig::default()),
            perm_result: Ok(()),
            role_result: Ok(()),
        };
        let _ = mock.config();
        let params = LoginParams::default();
        let _ = mock.login("u1", &params).await.unwrap();
        let _ = mock.login_with_token("u1", "tok").await;
        let _ = mock.logout().await;
        let _ = mock.logout_by_login_id("u1").await;
        let _ = mock.kickout("u1").await;
        let _ = mock.kickout_by_token("tok").await;
        let _ = mock.revoke_token("tok").await;
        let _ = mock.check_login().await.unwrap();
        let _ = mock.get_login_id().await.unwrap();
        let _ = mock.check_permission("user:read").await;
        let _ = mock.check_role("admin").await;
    }

    // has_permission / has_role 默认实现测试

    /// 可配置 check_permission/check_role 返回值的 mock：`perm_result` / `role_result` 覆盖 Ok / NotPermission / NotLogin / Dao 分支。
    struct MockPermissionHas {
        config: Arc<GarrisonConfig>,
        perm_result: GarrisonResult<()>,
        role_result: GarrisonResult<()>,
    }

    impl GarrisonCore for MockPermissionHas {
        fn config(&self) -> Arc<GarrisonConfig> {
            Arc::clone(&self.config)
        }
    }

    #[async_trait]
    impl SessionLogic for MockPermissionHas {
        async fn login(
            &self,
            _login_id: &str,
            _params: &crate::stp::LoginParams,
        ) -> GarrisonResult<String> {
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

    #[async_trait]
    impl PermissionLogic for MockPermissionHas {
        async fn check_permission(&self, _permission: &str) -> GarrisonResult<()> {
            // 克隆预设结果（GarrisonError 不实现 Clone，用相同变体重建）
            match &self.perm_result {
                Ok(()) => Ok(()),
                Err(crate::error::GarrisonError::NotPermission(s)) => {
                    Err(crate::error::GarrisonError::NotPermission(s.clone()))
                },
                Err(crate::error::GarrisonError::NotLogin(s)) => {
                    Err(crate::error::GarrisonError::NotLogin(s.clone()))
                },
                Err(crate::error::GarrisonError::Dao(s)) => {
                    Err(crate::error::GarrisonError::Dao(s.clone()))
                },
                Err(e) => panic!("MockPermissionHas 不支持此错误变体: {:?}", e),
            }
        }
        async fn check_role(&self, _role: &str) -> GarrisonResult<()> {
            match &self.role_result {
                Ok(()) => Ok(()),
                Err(crate::error::GarrisonError::NotRole(s)) => {
                    Err(crate::error::GarrisonError::NotRole(s.clone()))
                },
                Err(crate::error::GarrisonError::NotLogin(s)) => {
                    Err(crate::error::GarrisonError::NotLogin(s.clone()))
                },
                Err(crate::error::GarrisonError::Dao(s)) => {
                    Err(crate::error::GarrisonError::Dao(s.clone()))
                },
                Err(e) => panic!("MockPermissionHas 不支持此错误变体: {:?}", e),
            }
        }
    }

    fn ok_perm_mock() -> MockPermissionHas {
        MockPermissionHas {
            config: Arc::new(GarrisonConfig::default()),
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
        mock.perm_result = Err(GarrisonError::NotPermission("user:read".to_string()));
        assert!(!mock.has_permission("user:read").await.unwrap());
    }

    /// has_permission：check_permission 返回 NotLogin → has_permission 返回 Ok(false)。
    #[tokio::test]
    async fn has_permission_returns_false_when_not_login() {
        let mut mock = ok_perm_mock();
        mock.perm_result = Err(GarrisonError::NotLogin("未登录".to_string()));
        assert!(!mock.has_permission("user:read").await.unwrap());
    }

    /// has_permission：check_permission 返回 Dao 错误 → has_permission 透传错误（不吞错）。
    #[tokio::test]
    async fn has_permission_propagates_dao_error() {
        let mut mock = ok_perm_mock();
        mock.perm_result = Err(GarrisonError::Dao("连接失败".to_string()));
        let result = mock.has_permission("user:read").await;
        assert!(
            matches!(result, Err(GarrisonError::Dao(ref s)) if s.contains("连接失败")),
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
        mock.role_result = Err(GarrisonError::NotRole("admin".to_string()));
        assert!(!mock.has_role("admin").await.unwrap());
    }

    /// has_role：check_role 返回 NotLogin → has_role 返回 Ok(false)。
    #[tokio::test]
    async fn has_role_returns_false_when_not_login() {
        let mut mock = ok_perm_mock();
        mock.role_result = Err(GarrisonError::NotLogin("未登录".to_string()));
        assert!(!mock.has_role("admin").await.unwrap());
    }

    /// has_role：check_role 返回 Dao 错误 → has_role 透传错误。
    #[tokio::test]
    async fn has_role_propagates_dao_error() {
        let mut mock = ok_perm_mock();
        mock.role_result = Err(GarrisonError::Dao("连接失败".to_string()));
        let result = mock.has_role("admin").await;
        assert!(
            matches!(result, Err(GarrisonError::Dao(ref s)) if s.contains("连接失败")),
            "Dao 错误应透传，实际: {:?}",
            result
        );
    }

    /// 复用现有 MockPermission（bool 字段）验证 has_permission 默认实现与 check_permission 一致性。
    #[tokio::test]
    async fn has_permission_true_when_mock_field_true() {
        let mock = MockPermission {
            config: Arc::new(GarrisonConfig::default()),
            has_permission: true,
        };
        assert!(mock.has_permission("user:read").await.unwrap());
    }

    /// 复用现有 MockPermission（bool=false）验证 has_permission 返回 false。
    #[tokio::test]
    async fn has_permission_false_when_mock_field_false() {
        let mock = MockPermission {
            config: Arc::new(GarrisonConfig::default()),
            has_permission: false,
        };
        assert!(!mock.has_permission("user:read").await.unwrap());
    }

    // get_permission_list / get_role_list 默认实现测试

    /// get_permission_list 默认实现返回 NotImplemented（未覆写时）。
    #[tokio::test]
    async fn get_permission_list_default_returns_not_implemented() {
        let mock = ok_perm_mock();
        let result = mock.get_permission_list().await;
        assert!(
            matches!(result, Err(GarrisonError::NotImplemented(ref s)) if s.contains("get_permission_list")),
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
            matches!(result, Err(GarrisonError::NotImplemented(ref s)) if s.contains("get_role_list")),
            "默认实现应返回 NotImplemented，实际: {:?}",
            result
        );
    }

    // GarrisonLogicDefault impl 覆盖测试：firewall 路径 + get_permission_list/get_role_list

    mod default_impl_coverage {
        use super::*;
        use crate::context::tenant::with_default_tenant;
        use crate::dao::GarrisonDao;
        use crate::session::GarrisonSession;
        use crate::stp::mock::{MockDao, MockFirewall};
        use crate::stp::with_current_token;
        use crate::strategy::GarrisonPermissionStrategy;
        use std::sync::Arc;

        fn make_logic(
            throw_on_not_login: bool,
            has_permission: bool,
            has_role: bool,
        ) -> GarrisonLogicDefault {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = throw_on_not_login;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission,
                has_role,
            });
            GarrisonLogicDefault::new(
                session,
                Arc::new(config),
                firewall,
                Arc::new(crate::account::disable::DefaultDisableRepository::new(
                    dao.clone(),
                )),
            )
        }

        // check_permission：未登录路径

        /// 未登录 + throw_on_not_login=true → Err(NotLogin)。
        #[tokio::test]
        async fn check_permission_no_login_throws_not_login() {
            let logic = make_logic(true, true, true);
            let result = logic.check_permission("user:read").await;
            assert!(
                matches!(result, Err(GarrisonError::NotLogin(_))),
                "未登录 + throw=true 应返回 NotLogin，实际: {:?}",
                result
            );
        }

        /// 未登录 + throw_on_not_login=false → Err(NotPermission)。
        #[tokio::test]
        async fn check_permission_no_login_returns_not_permission() {
            let logic = make_logic(false, true, true);
            let result = logic.check_permission("user:read").await;
            assert!(
                matches!(result, Err(GarrisonError::NotPermission(_))),
                "未登录 + throw=false 应返回 NotPermission，实际: {:?}",
                result
            );
        }

        // check_permission：已登录 + firewall 路径

        /// 已登录 + firewall.has_permission=true → Ok(())。
        #[tokio::test]
        async fn check_permission_logged_in_with_perm_returns_ok() {
            let logic = make_logic(false, true, true);
            let token = logic
                .login("perm-user-001", &crate::stp::LoginParams::default())
                .await
                .unwrap();
            let result = with_current_token(token, async {
                with_default_tenant(async { logic.check_permission("user:read").await }).await
            })
            .await;
            assert!(
                result.is_ok(),
                "已登录 + has_permission=true 应返回 Ok，实际: {:?}",
                result
            );
        }

        /// 已登录 + firewall.has_permission=false → Err(NotPermission)。
        #[tokio::test]
        async fn check_permission_logged_in_without_perm_returns_not_permission() {
            let logic = make_logic(false, false, true);
            let token = logic
                .login("perm-user-002", &crate::stp::LoginParams::default())
                .await
                .unwrap();
            let result = with_current_token(token, async {
                with_default_tenant(async { logic.check_permission("user:read").await }).await
            })
            .await;
            assert!(
                matches!(result, Err(GarrisonError::NotPermission(_))),
                "已登录 + has_permission=false 应返回 NotPermission，实际: {:?}",
                result
            );
        }

        // check_role：未登录路径

        /// 未登录 + throw_on_not_login=true → Err(NotLogin)。
        #[tokio::test]
        async fn check_role_no_login_throws_not_login() {
            let logic = make_logic(true, true, true);
            let result = logic.check_role("admin").await;
            assert!(
                matches!(result, Err(GarrisonError::NotLogin(_))),
                "未登录 + throw=true 应返回 NotLogin，实际: {:?}",
                result
            );
        }

        /// 未登录 + throw_on_not_login=false → Err(NotRole)。
        #[tokio::test]
        async fn check_role_no_login_returns_not_role() {
            let logic = make_logic(false, true, true);
            let result = logic.check_role("admin").await;
            assert!(
                matches!(result, Err(GarrisonError::NotRole(_))),
                "未登录 + throw=false 应返回 NotRole，实际: {:?}",
                result
            );
        }

        // check_role：已登录 + firewall 路径

        /// 已登录 + firewall.has_role=true → Ok(())。
        #[tokio::test]
        async fn check_role_logged_in_with_role_returns_ok() {
            let logic = make_logic(false, true, true);
            let token = logic
                .login("role-user-001", &crate::stp::LoginParams::default())
                .await
                .unwrap();
            let result = with_current_token(
                token,
                with_default_tenant(async { logic.check_role("admin").await }),
            )
            .await;
            assert!(
                result.is_ok(),
                "已登录 + has_role=true 应返回 Ok，实际: {:?}",
                result
            );
        }

        /// 已登录 + firewall.has_role=false → Err(NotRole)。
        #[tokio::test]
        async fn check_role_logged_in_without_role_returns_not_role() {
            let logic = make_logic(false, true, false);
            let token = logic
                .login("role-user-002", &crate::stp::LoginParams::default())
                .await
                .unwrap();
            let result = with_current_token(
                token,
                with_default_tenant(async { logic.check_role("admin").await }),
            )
            .await;
            assert!(
                matches!(result, Err(GarrisonError::NotRole(_))),
                "已登录 + has_role=false 应返回 NotRole，实际: {:?}",
                result
            );
        }

        // get_permission_list / get_role_list

        /// 未登录 → get_permission_list 返回空 Vec。
        #[tokio::test]
        async fn get_permission_list_no_login_returns_empty() {
            let logic = make_logic(false, true, true);
            let result = logic.get_permission_list().await;
            assert!(result.is_ok(), "未登录应返回 Ok，实际: {:?}", result);
            assert!(result.unwrap().is_empty(), "未登录应返回空 Vec");
        }

        /// 未登录 → get_role_list 返回空 Vec。
        #[tokio::test]
        async fn get_role_list_no_login_returns_empty() {
            let logic = make_logic(false, true, true);
            let result = logic.get_role_list().await;
            assert!(result.is_ok(), "未登录应返回 Ok，实际: {:?}", result);
            assert!(result.unwrap().is_empty(), "未登录应返回空 Vec");
        }

        /// 已登录 → get_permission_list 委托 firewall（MockFirewall 返回空 Vec）。
        #[tokio::test]
        async fn get_permission_list_logged_in_delegates_to_firewall() {
            let logic = make_logic(false, true, true);
            let token = logic
                .login("list-user-001", &crate::stp::LoginParams::default())
                .await
                .unwrap();
            let result =
                with_current_token(token, async { logic.get_permission_list().await }).await;
            assert!(result.is_ok(), "已登录应返回 Ok，实际: {:?}", result);
        }

        /// 已登录 → get_role_list 委托 firewall。
        #[tokio::test]
        async fn get_role_list_logged_in_delegates_to_firewall() {
            let logic = make_logic(false, true, true);
            let token = logic
                .login("list-user-002", &crate::stp::LoginParams::default())
                .await
                .unwrap();
            let result = with_current_token(token, async { logic.get_role_list().await }).await;
            assert!(result.is_ok(), "已登录应返回 Ok，实际: {:?}", result);
        }

        // has_permission / has_role（通过 GarrisonLogicDefault）

        /// 已登录 + has_permission=true → has_permission 返回 Ok(true)。
        #[tokio::test]
        async fn has_permission_logged_in_with_perm_returns_true() {
            let logic = make_logic(false, true, true);
            let token = logic
                .login("has-perm-001", &crate::stp::LoginParams::default())
                .await
                .unwrap();
            let result = with_current_token(token, async {
                with_default_tenant(async { logic.has_permission("user:read").await }).await
            })
            .await;
            assert!(result.is_ok(), "应返回 Ok，实际: {:?}", result);
            assert!(result.unwrap(), "has_permission=true 应返回 true");
        }

        /// 已登录 + has_role=false → has_role 返回 Ok(false)。
        #[tokio::test]
        async fn has_role_logged_in_without_role_returns_false() {
            let logic = make_logic(false, true, false);
            let token = logic
                .login("has-role-001", &crate::stp::LoginParams::default())
                .await
                .unwrap();
            let result = with_current_token(
                token,
                with_default_tenant(async { logic.has_role("admin").await }),
            )
            .await;
            assert!(result.is_ok(), "应返回 Ok，实际: {:?}", result);
            assert!(!result.unwrap(), "has_role=false 应返回 false");
        }

        /// 无租户上下文时 check_role fail-closed 返回 Err(Config)：tenant-isolation 启用后与 check_permission 一致，防跨租户角色检查绕过。
        #[tokio::test]
        #[cfg(feature = "tenant-isolation")]
        async fn check_role_without_tenant_context_returns_error() {
            let logic = make_logic(false, true, true);
            let token = logic
                .login("tenant-role-001", &crate::stp::LoginParams::default())
                .await
                .unwrap();
            // 故意不包裹 with_default_tenant，验证 fail-closed 语义
            let result = with_current_token(token, async { logic.check_role("admin").await }).await;
            assert!(
                matches!(result, Err(GarrisonError::Config(ref msg)) if msg.contains("tenant")),
                "无租户上下文时 check_role 应返回 Err(Config)，实际: {:?}",
                result
            );
        }
    }

    // permission_checker 注入路径测试：覆盖 check_permission 的 permission_checker 分支

    mod permission_checker_coverage {
        use super::*;
        use crate::context::tenant::with_default_tenant;
        use crate::core::permission::{AuthRequest, Decision, DecisionReason, PermissionChecker};
        use crate::dao::GarrisonDao;
        use crate::session::GarrisonSession;
        use crate::stp::mock::{MockDao, MockFirewall};
        use crate::stp::with_current_token;
        use crate::strategy::GarrisonPermissionStrategy;
        use async_trait::async_trait;
        use std::sync::Arc;

        /// 可配置 authorize 返回值的 mock PermissionChecker。
        struct MockPermissionChecker {
            allowed: bool,
            fail: bool,
        }

        #[async_trait]
        impl PermissionChecker for MockPermissionChecker {
            async fn has_permission(
                &self,
                _login_id: &str,
                _permission: &str,
            ) -> GarrisonResult<bool> {
                Ok(self.allowed)
            }
            async fn has_role(&self, _login_id: &str, _role: &str) -> GarrisonResult<bool> {
                Ok(self.allowed)
            }
            async fn authorize(&self, _request: &AuthRequest) -> GarrisonResult<Decision> {
                if self.fail {
                    return Err(GarrisonError::Dao("stp-dao-connect::".to_string()));
                }
                Ok(Decision {
                    allowed: self.allowed,
                    reason: if self.allowed {
                        DecisionReason::ExplicitAllow
                    } else {
                        DecisionReason::NoMatchingPermission
                    },
                    errors: Vec::new(),
                    checked_permissions: Vec::new(),
                    matched_roles: Vec::new(),
                    trace_id: None,
                })
            }
            async fn has_any_permission(&self, _login_id: &str, _perms: &[&str]) -> bool {
                self.allowed
            }
            async fn has_all_permissions(&self, _login_id: &str, _perms: &[&str]) -> bool {
                self.allowed
            }
        }

        /// 构造带 permission_checker 的 GarrisonLogicDefault。
        fn make_logic_with_checker(allowed: bool, fail: bool) -> GarrisonLogicDefault {
            let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
            let session = Arc::new(GarrisonSession::new(dao.clone(), 3600, 86400, 0));
            let mut config = GarrisonConfig::default_config();
            config.throw_on_not_login = false;
            config.token_style = "uuid".to_string();
            let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(MockFirewall {
                has_permission: true,
                has_role: true,
            });
            let pc: Arc<dyn PermissionChecker> = Arc::new(MockPermissionChecker { allowed, fail });
            GarrisonLogicDefault::new(
                session,
                Arc::new(config),
                firewall,
                Arc::new(crate::account::disable::DefaultDisableRepository::new(
                    dao.clone(),
                )),
            )
            .with_permission_checker(pc)
        }

        /// 已登录 + permission_checker.authorize 返回 allowed=true → Ok(())（覆盖 checker 注入路径 allowed=true 分支）。
        #[tokio::test]
        async fn check_permission_with_checker_allowed_returns_ok() {
            let logic = make_logic_with_checker(true, false);
            let token = logic
                .login("checker-user-001", &crate::stp::LoginParams::default())
                .await
                .unwrap();
            let result = with_current_token(token, async {
                with_default_tenant(async { logic.check_permission("user:read").await }).await
            })
            .await;
            assert!(
                result.is_ok(),
                "permission_checker allowed=true 应返回 Ok，实际: {:?}",
                result
            );
        }

        /// 已登录 + permission_checker.authorize 返回 allowed=false → Err(NotPermission)（覆盖 decision.allowed=false 分支）。
        #[tokio::test]
        async fn check_permission_with_checker_denied_returns_not_permission() {
            let logic = make_logic_with_checker(false, false);
            let token = logic
                .login("checker-user-002", &crate::stp::LoginParams::default())
                .await
                .unwrap();
            let result = with_current_token(token, async {
                with_default_tenant(async { logic.check_permission("user:read").await }).await
            })
            .await;
            assert!(
                matches!(result, Err(GarrisonError::NotPermission(_))),
                "permission_checker allowed=false 应返回 NotPermission，实际: {:?}",
                result
            );
        }

        /// 已登录 + permission_checker.authorize 返回 Err → 透传错误（覆盖 `pc.authorize(...)?` 错误传播路径）。
        #[tokio::test]
        async fn check_permission_with_checker_error_propagates() {
            let logic = make_logic_with_checker(false, true);
            let token = logic
                .login("checker-user-003", &crate::stp::LoginParams::default())
                .await
                .unwrap();
            let result = with_current_token(token, async {
                with_default_tenant(async { logic.check_permission("user:read").await }).await
            })
            .await;
            assert!(
                matches!(result, Err(GarrisonError::Dao(ref s)) if s.contains("stp-dao-connect")),
                "permission_checker authorize 错误应透传，实际: {:?}",
                result
            );
        }

        /// permission_checker 注入时，has_permission 通过 check_permission 委托返回 true（覆盖 checker 路径 + has_permission 默认实现）。
        #[tokio::test]
        async fn has_permission_with_checker_allowed_returns_true() {
            let logic = make_logic_with_checker(true, false);
            let token = logic
                .login("checker-user-004", &crate::stp::LoginParams::default())
                .await
                .unwrap();
            let result = with_current_token(token, async {
                with_default_tenant(async { logic.has_permission("user:read").await }).await
            })
            .await;
            assert!(result.is_ok(), "应返回 Ok，实际: {:?}", result);
            assert!(
                result.unwrap(),
                "permission_checker allowed=true 时 has_permission 应返回 true"
            );
        }

        /// permission_checker 注入时，has_permission 返回 false（allowed=false 路径）。
        #[tokio::test]
        async fn has_permission_with_checker_denied_returns_false() {
            let logic = make_logic_with_checker(false, false);
            let token = logic
                .login("checker-user-005", &crate::stp::LoginParams::default())
                .await
                .unwrap();
            let result = with_current_token(token, async {
                with_default_tenant(async { logic.has_permission("user:read").await }).await
            })
            .await;
            assert!(result.is_ok(), "应返回 Ok，实际: {:?}", result);
            assert!(
                !result.unwrap(),
                "permission_checker allowed=false 时 has_permission 应返回 false"
            );
        }

        /// 直接调用 MockPermissionChecker 的所有方法以确保覆盖。
        #[tokio::test]
        async fn mock_permission_checker_all_methods() {
            let pc = MockPermissionChecker {
                allowed: true,
                fail: false,
            };
            let _ = pc.has_permission("u1", "user:read").await.unwrap();
            let _ = pc.has_role("u1", "admin").await.unwrap();
            let _ = pc
                .has_any_permission("u1", &["user:read", "user:write"])
                .await;
            let _ = pc
                .has_all_permissions("u1", &["user:read", "user:write"])
                .await;
            let req = AuthRequest::new("u1", "user:read");
            let _ = pc.authorize(&req).await.unwrap();
        }
    }
}
