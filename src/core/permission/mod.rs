//! 权限校验模块，定义以 login_id 为入参的权限与角色校验抽象。
//!
//! [借鉴 Sa-Token] 权限认证核心逻辑，对应 Sa-Token 的 `StpLogic.checkPermission / checkRole` 方法。
//!
//! 0.2.0 将 API 改为 login_id-as-input，与 token 格式无关，便于在任意 token 风格下复用。

use async_trait::async_trait;
use std::sync::Arc;

use crate::error::{BulwarkError, BulwarkResult};
use crate::stp::BulwarkInterface;

/// 权限校验 trait，定义以 login_id 为入参的权限与角色校验抽象（依据 spec core-permission）。
///
/// 所有方法 MUST 使用 `async_trait` 标注，trait 绑定 `Send + Sync`。
/// 入参为 `login_id: i64` 而非 token，使权限校验可在任意 token 风格下复用。
#[async_trait]
pub trait PermissionChecker: Send + Sync {
    /// 校验主体是否持有指定权限（依据 spec core-permission）。
    ///
    /// # 返回
    /// - `Ok(true)`: 持有权限。
    /// - `Ok(false)`: 未持有权限。
    /// - `Err(BulwarkError::InvalidToken)`: 权限字符串为空。
    async fn has_permission(&self, login_id: i64, permission: &str) -> BulwarkResult<bool>;

    /// 校验主体是否持有指定角色（依据 spec core-permission）。
    async fn has_role(&self, login_id: i64, role: &str) -> BulwarkResult<bool>;

    /// 断言权限：被拒绝时返回 `Err(BulwarkError::NotPermission)`（依据 spec core-permission）。
    async fn check_permission(&self, login_id: i64, permission: &str) -> BulwarkResult<()>;

    /// 断言角色：被拒绝时返回 `Err(BulwarkError::NotRole)`（依据 spec core-permission）。
    async fn check_role(&self, login_id: i64, role: &str) -> BulwarkResult<()>;

    /// 批量校验权限：任一满足即返回 true（依据 spec core-permission）。
    ///
    /// 内部调用 `has_permission`，遇到错误时该权限视为不满足。
    async fn has_any_permission(&self, login_id: i64, perms: &[&str]) -> bool;

    /// 批量校验权限：全部满足才返回 true（依据 spec core-permission）。
    ///
    /// 内部调用 `has_permission`，遇到错误时该权限视为不满足。
    async fn has_all_permissions(&self, login_id: i64, perms: &[&str]) -> bool;
}

/// `PermissionChecker` 的默认实现，委托 `BulwarkInterface` 获取权限/角色数据后做字符串匹配（依据 spec core-permission）。
///
/// 与 `BulwarkFirewallStrategy` 的职责区分：
/// - `PermissionCheckerDefault`：纯数据查询（返回 bool/Err，无副作用）
/// - `BulwarkFirewallStrategy`：编排（校验 + 抛异常 + 事件广播）
pub struct PermissionCheckerDefault {
    /// 业务接口（提供 get_permission_list / get_role_list）。
    interface: Arc<dyn BulwarkInterface>,
}

impl PermissionCheckerDefault {
    /// 创建新的 `PermissionCheckerDefault` 实例。
    pub fn new(interface: Arc<dyn BulwarkInterface>) -> Self {
        Self { interface }
    }
}

#[async_trait]
impl PermissionChecker for PermissionCheckerDefault {
    async fn has_permission(&self, login_id: i64, permission: &str) -> BulwarkResult<bool> {
        if permission.is_empty() {
            return Err(BulwarkError::InvalidToken("权限字符串不能为空".to_string()));
        }
        let perms = self.interface.get_permission_list(login_id).await?;
        Ok(perms.iter().any(|p| p == permission))
    }

    async fn has_role(&self, login_id: i64, role: &str) -> BulwarkResult<bool> {
        if role.is_empty() {
            return Err(BulwarkError::InvalidToken("角色字符串不能为空".to_string()));
        }
        let roles = self.interface.get_role_list(login_id).await?;
        Ok(roles.iter().any(|r| r == role))
    }

    async fn check_permission(&self, login_id: i64, permission: &str) -> BulwarkResult<()> {
        if self.has_permission(login_id, permission).await? {
            Ok(())
        } else {
            Err(BulwarkError::NotPermission(format!(
                "账号 {} 未持有权限: {}",
                login_id, permission
            )))
        }
    }

    async fn check_role(&self, login_id: i64, role: &str) -> BulwarkResult<()> {
        if self.has_role(login_id, role).await? {
            Ok(())
        } else {
            Err(BulwarkError::NotRole(format!(
                "账号 {} 未持有角色: {}",
                login_id, role
            )))
        }
    }

    async fn has_any_permission(&self, login_id: i64, perms: &[&str]) -> bool {
        for perm in perms {
            if self.has_permission(login_id, perm).await.unwrap_or(false) {
                return true;
            }
        }
        false
    }

    async fn has_all_permissions(&self, login_id: i64, perms: &[&str]) -> bool {
        for perm in perms {
            if !self.has_permission(login_id, perm).await.unwrap_or(false) {
                return false;
            }
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use async_trait::async_trait;
    use std::collections::HashMap;

    /// 测试用 mock BulwarkInterface。
    struct MockInterface {
        permissions: HashMap<i64, Vec<String>>,
        roles: HashMap<i64, Vec<String>>,
    }

    impl MockInterface {
        fn new() -> Self {
            Self {
                permissions: HashMap::new(),
                roles: HashMap::new(),
            }
        }

        fn with_perms(mut self, login_id: i64, perms: Vec<&str>) -> Self {
            self.permissions
                .insert(login_id, perms.iter().map(|s| s.to_string()).collect());
            self
        }

        fn with_roles(mut self, login_id: i64, roles: Vec<&str>) -> Self {
            self.roles
                .insert(login_id, roles.iter().map(|s| s.to_string()).collect());
            self
        }
    }

    #[async_trait]
    impl BulwarkInterface for MockInterface {
        async fn get_permission_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(self.permissions.get(&login_id).cloned().unwrap_or_default())
        }

        async fn get_role_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(self.roles.get(&login_id).cloned().unwrap_or_default())
        }
    }

    /// 创建 PermissionCheckerDefault 实例（账号 1001 持有 user:read/user:write 权限 + admin/user 角色）。
    fn make_checker() -> PermissionCheckerDefault {
        let interface = MockInterface::new()
            .with_perms(1001, vec!["user:read", "user:write"])
            .with_roles(1001, vec!["admin", "user"]);
        let interface_arc: Arc<dyn BulwarkInterface> = Arc::new(interface);
        PermissionCheckerDefault::new(interface_arc)
    }

    // ========================================================================
    // has_permission 测试（依据 spec core-permission）
    // ========================================================================

    /// has_permission 持有权限返回 true（spec Scenario）。
    #[tokio::test]
    async fn has_permission_held_returns_true() {
        let checker = make_checker();
        assert!(checker.has_permission(1001, "user:read").await.unwrap());
    }

    /// has_permission 未持有权限返回 false（spec Scenario）。
    #[tokio::test]
    async fn has_permission_not_held_returns_false() {
        let checker = make_checker();
        assert!(!checker.has_permission(1001, "user:delete").await.unwrap());
    }

    /// has_permission 空字符串返回错误（spec Scenario）。
    #[tokio::test]
    async fn has_permission_empty_string_returns_error() {
        let checker = make_checker();
        let result = checker.has_permission(1001, "").await;
        assert!(result.is_err());
    }

    // ========================================================================
    // has_role 测试（依据 spec core-permission）
    // ========================================================================

    /// has_role 持有角色返回 true（spec Scenario）。
    #[tokio::test]
    async fn has_role_held_returns_true() {
        let checker = make_checker();
        assert!(checker.has_role(1001, "admin").await.unwrap());
    }

    /// has_role 未持有角色返回 false（spec Scenario）。
    #[tokio::test]
    async fn has_role_not_held_returns_false() {
        let checker = make_checker();
        assert!(!checker.has_role(1001, "superadmin").await.unwrap());
    }

    // ========================================================================
    // check_permission 测试（依据 spec core-permission）
    // ========================================================================

    /// check_permission 持有权限返回 Ok(())（spec Scenario）。
    #[tokio::test]
    async fn check_permission_held_returns_ok() {
        let checker = make_checker();
        assert!(checker.check_permission(1001, "user:read").await.is_ok());
    }

    /// check_permission 未持有权限返回 NotPermission 错误（spec Scenario）。
    #[tokio::test]
    async fn check_permission_not_held_returns_error() {
        let checker = make_checker();
        let result = checker.check_permission(1001, "user:delete").await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::NotPermission(_)) => {},
            other => panic!("期望 NotPermission，实际: {:?}", other),
        }
    }

    // ========================================================================
    // check_role 测试（依据 spec core-permission）
    // ========================================================================

    /// check_role 持有角色返回 Ok(())。
    #[tokio::test]
    async fn check_role_held_returns_ok() {
        let checker = make_checker();
        assert!(checker.check_role(1001, "admin").await.is_ok());
    }

    /// check_role 未持有角色返回 NotRole 错误（spec Scenario）。
    #[tokio::test]
    async fn check_role_not_held_returns_error() {
        let checker = make_checker();
        let result = checker.check_role(1001, "superadmin").await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::NotRole(_)) => {},
            other => panic!("期望 NotRole，实际: {:?}", other),
        }
    }

    // ========================================================================
    // has_any_permission 测试（依据 spec core-permission）
    // ========================================================================

    /// has_any_permission 任一匹配返回 true（spec Scenario）。
    #[tokio::test]
    async fn has_any_permission_any_match_returns_true() {
        let checker = make_checker();
        assert!(
            checker
                .has_any_permission(1001, &["user:read", "user:delete"])
                .await
        );
    }

    /// has_any_permission 全不匹配返回 false（spec Scenario）。
    #[tokio::test]
    async fn has_any_permission_no_match_returns_false() {
        let checker = make_checker();
        assert!(
            !checker
                .has_any_permission(1001, &["user:delete", "user:create"])
                .await
        );
    }

    // ========================================================================
    // has_all_permissions 测试（依据 spec core-permission）
    // ========================================================================

    /// has_all_permissions 全部匹配返回 true（spec Scenario）。
    #[tokio::test]
    async fn has_all_permissions_all_match_returns_true() {
        let checker = make_checker();
        assert!(
            checker
                .has_all_permissions(1001, &["user:read", "user:write"])
                .await
        );
    }

    /// has_all_permissions 部分匹配返回 false（spec Scenario）。
    #[tokio::test]
    async fn has_all_permissions_partial_match_returns_false() {
        let checker = make_checker();
        assert!(
            !checker
                .has_all_permissions(1001, &["user:read", "user:delete"])
                .await
        );
    }

    /// has_all_permissions 空列表返回 true（vacuous truth）。
    #[tokio::test]
    async fn has_all_permissions_empty_list_returns_true() {
        let checker = make_checker();
        assert!(checker.has_all_permissions(1001, &[]).await);
    }
}
