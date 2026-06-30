//! 策略模块，提供鉴权策略与可插拔权限策略。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的策略模式设计，
//! 允许通过策略对象定制鉴权行为。
//!
//! ## 权限策略（依据 spec permission-role-check 与 design.md Decision 9）
//!
//! - `BulwarkFirewallStrategy` trait：定义权限/角色校验的可插拔契约
//! - `BulwarkFirewallStrategyDefault`：默认实现，持有 `BulwarkInterface` 回调获取权限/角色数据，
//!   做字符串匹配校验
//!
//! ## 数据来源（依据用户决策：方案 B）
//!
//! 权限/角色数据由业务方实现 `BulwarkInterface` 回调提供（不委托 dbnexus
//! `PermissionProvider` trait，因其 API 模型与 Bulwark 不匹配）。

use crate::error::{BulwarkError, BulwarkResult};
use crate::stp::BulwarkInterface;
use async_trait::async_trait;
use std::sync::Arc;

// ============================================================================
// BulwarkStrategy：Token 生成策略占位（0.2.0+ 实现）
// ============================================================================

/// 鉴权策略，定义可定制的 Token 生成与解析行为。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的 `SaStrategy`，
/// 提供 Token 生成、会话查询等可替换逻辑。
pub struct BulwarkStrategy {
    /// 占位字段。
    _inner: (),
}

impl BulwarkStrategy {
    /// 创建新的策略实例。
    pub fn new() -> Self {
        Self { _inner: () }
    }

    /// 生成 Token 字符串。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    pub fn create_token(&self, login_id: i64) -> BulwarkResult<String> {
        let _ = login_id;
        todo!("0.2.0+ 实现：委托具体 Token 生成策略")
    }

    /// 根据 Token 解析登录主体标识。
    ///
    /// # 参数
    /// - `token`: Token 字符串。
    pub fn parse_login_id(&self, token: &str) -> BulwarkResult<Option<i64>> {
        let _ = token;
        todo!("0.2.0+ 实现：委托具体 Token 解析策略")
    }
}

impl Default for BulwarkStrategy {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// BulwarkFirewallStrategy trait：可插拔权限策略
// ============================================================================

/// 权限策略 trait，定义权限/角色校验的可插拔契约。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的可插拔权限策略，
/// 业务方可通过实现此 trait 替换默认的权限校验逻辑。
///
/// # 默认实现
///
/// `BulwarkFirewallStrategyDefault` 持有 `BulwarkInterface` 回调，
/// 调用 `get_permission_list` / `get_role_list` 获取数据后做字符串匹配。
#[async_trait]
pub trait BulwarkFirewallStrategy: Send + Sync {
    /// 获取主体的权限列表。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    async fn get_permission_list(&self, login_id: i64) -> BulwarkResult<Vec<String>>;

    /// 获取主体的角色列表。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    async fn get_role_list(&self, login_id: i64) -> BulwarkResult<Vec<String>>;

    /// 校验权限：检查主体是否持有指定权限。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `permission`: 权限标识字符串（如 `"user:read"`）。
    ///
    /// # 返回
    /// - `Ok(true)`: 主体持有该权限。
    /// - `Ok(false)`: 主体未持有该权限。
    /// - `Err`: 查询失败或权限字符串非法（如空字符串）。
    async fn check_permission(&self, login_id: i64, permission: &str) -> BulwarkResult<bool>;

    /// 校验角色：检查主体是否持有指定角色。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `role`: 角色标识字符串。
    async fn check_role(&self, login_id: i64, role: &str) -> BulwarkResult<bool>;

    /// 校验角色（任一匹配）：主体持有 `roles` 中任意一个即通过。
    ///
    /// 对应 spec scenario "多角色任一匹配"。
    async fn check_role_any(&self, login_id: i64, roles: &[&str]) -> BulwarkResult<bool>;

    /// 校验角色（全部匹配）：主体需持有 `roles` 中所有角色。
    ///
    /// 对应 spec scenario "多角色全部匹配"。
    async fn check_role_all(&self, login_id: i64, roles: &[&str]) -> BulwarkResult<bool>;
}

// ============================================================================
// BulwarkFirewallStrategyDefault：默认实现（委托 BulwarkInterface 回调）
// ============================================================================

/// `BulwarkFirewallStrategy` 的默认实现，持有 `BulwarkInterface` 回调获取权限/角色数据。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的 `StpInterface` 回调模式：
/// 框架不假定权限/角色数据来源（数据库 / YAML / 内存等），
/// 由业务方实现 `BulwarkInterface` 提供数据，本结构做字符串匹配校验。
///
/// # 数据来源
///
/// 权限/角色数据由 `BulwarkInterface` 回调提供（依据用户决策方案 B），
/// 不委托 dbnexus `PermissionProvider` trait（因其 API 模型与 Bulwark 不匹配）。
pub struct BulwarkFirewallStrategyDefault {
    /// 权限/角色数据回调。
    interface: Arc<dyn BulwarkInterface>,
}

impl BulwarkFirewallStrategyDefault {
    /// 创建默认实现实例。
    ///
    /// # 参数
    /// - `interface`: 权限/角色数据回调（业务方实现）。
    pub fn new(interface: Arc<dyn BulwarkInterface>) -> Self {
        Self { interface }
    }
}

#[async_trait]
impl BulwarkFirewallStrategy for BulwarkFirewallStrategyDefault {
    async fn get_permission_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
        self.interface.get_permission_list(login_id).await
    }

    async fn get_role_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
        self.interface.get_role_list(login_id).await
    }

    async fn check_permission(&self, login_id: i64, permission: &str) -> BulwarkResult<bool> {
        // spec scenario "权限为空字符串"：空字符串抛 InvalidToken
        if permission.is_empty() {
            return Err(BulwarkError::InvalidToken("权限字符串不能为空".to_string()));
        }
        let permissions = self.get_permission_list(login_id).await?;
        Ok(permissions.iter().any(|p| p == permission))
    }

    async fn check_role(&self, login_id: i64, role: &str) -> BulwarkResult<bool> {
        let roles = self.get_role_list(login_id).await?;
        Ok(roles.iter().any(|r| r == role))
    }

    async fn check_role_any(&self, login_id: i64, roles: &[&str]) -> BulwarkResult<bool> {
        let user_roles = self.get_role_list(login_id).await?;
        Ok(roles.iter().any(|r| user_roles.iter().any(|ur| ur == r)))
    }

    async fn check_role_all(&self, login_id: i64, roles: &[&str]) -> BulwarkResult<bool> {
        let user_roles = self.get_role_list(login_id).await?;
        Ok(roles.iter().all(|r| user_roles.iter().any(|ur| ur == r)))
    }
}

// ============================================================================
// 测试（依据 spec permission-role-check 所有 scenario）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    // ------------------------------------------------------------------------
    // MockInterface：模拟业务方实现 BulwarkInterface 回调
    // ------------------------------------------------------------------------

    /// 测试用 BulwarkInterface mock，基于 HashMap 存储 login_id → 权限/角色列表。
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

        /// 设置指定 login_id 的权限列表。
        fn set_permissions(&mut self, login_id: i64, perms: &[&str]) {
            self.permissions
                .insert(login_id, perms.iter().map(|s| s.to_string()).collect());
        }

        /// 设置指定 login_id 的角色列表。
        fn set_roles(&mut self, login_id: i64, roles: &[&str]) {
            self.roles
                .insert(login_id, roles.iter().map(|s| s.to_string()).collect());
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

    /// 辅助函数：创建 BulwarkFirewallStrategyDefault 实例。
    fn make_firewall(interface: MockInterface) -> BulwarkFirewallStrategyDefault {
        BulwarkFirewallStrategyDefault::new(Arc::new(interface))
    }

    // ------------------------------------------------------------------------
    // spec scenario: 持有权限返回 true / 未持有返回 false
    // ------------------------------------------------------------------------

    /// 验证主体持有指定权限时 check_permission 返回 true。
    #[tokio::test]
    async fn check_permission_held_returns_true() {
        let mut iface = MockInterface::new();
        iface.set_permissions(1001, &["user:read", "user:write"]);
        let fw = make_firewall(iface);

        assert!(
            fw.check_permission(1001, "user:read").await.unwrap(),
            "持有权限应返回 true"
        );
    }

    /// 验证主体未持有指定权限时 check_permission 返回 false。
    #[tokio::test]
    async fn check_permission_not_held_returns_false() {
        let mut iface = MockInterface::new();
        iface.set_permissions(1001, &["user:read"]);
        let fw = make_firewall(iface);

        assert!(
            !fw.check_permission(1001, "user:delete").await.unwrap(),
            "未持有权限应返回 false"
        );
    }

    /// spec scenario "权限为空字符串"：空字符串抛 InvalidToken。
    #[tokio::test]
    async fn check_permission_empty_string_errors() {
        let iface = MockInterface::new();
        let fw = make_firewall(iface);

        let result = fw.check_permission(1001, "").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "空权限字符串应抛 InvalidToken"
        );
    }

    /// 验证主体无任何权限记录时 check_permission 返回 false（不抛错）。
    #[tokio::test]
    async fn check_permission_no_record_returns_false() {
        let iface = MockInterface::new();
        let fw = make_firewall(iface);

        assert!(
            !fw.check_permission(9999, "user:read").await.unwrap(),
            "无权限记录的 login_id 应返回 false"
        );
    }

    // ------------------------------------------------------------------------
    // spec scenario: 持有角色返回 true / 未持有返回 false
    // ------------------------------------------------------------------------

    /// 验证主体持有指定角色时 check_role 返回 true。
    #[tokio::test]
    async fn check_role_held_returns_true() {
        let mut iface = MockInterface::new();
        iface.set_roles(1001, &["admin", "user"]);
        let fw = make_firewall(iface);

        assert!(
            fw.check_role(1001, "admin").await.unwrap(),
            "持有角色应返回 true"
        );
    }

    /// 验证主体未持有指定角色时 check_role 返回 false。
    #[tokio::test]
    async fn check_role_not_held_returns_false() {
        let mut iface = MockInterface::new();
        iface.set_roles(1001, &["user"]);
        let fw = make_firewall(iface);

        assert!(
            !fw.check_role(1001, "admin").await.unwrap(),
            "未持有角色应返回 false"
        );
    }

    // ------------------------------------------------------------------------
    // spec scenario: 多角色任一匹配 / 全部匹配
    // ------------------------------------------------------------------------

    /// 验证 check_role_any：主体持有 roles 中任意一个即返回 true。
    #[tokio::test]
    async fn check_role_any_match_returns_true() {
        let mut iface = MockInterface::new();
        iface.set_roles(1001, &["admin"]);
        let fw = make_firewall(iface);

        assert!(
            fw.check_role_any(1001, &["admin", "superadmin"])
                .await
                .unwrap(),
            "持有任一角色应返回 true"
        );
    }

    /// 验证 check_role_any：主体不持有 roles 中任何一个则返回 false。
    #[tokio::test]
    async fn check_role_any_no_match_returns_false() {
        let mut iface = MockInterface::new();
        iface.set_roles(1001, &["user"]);
        let fw = make_firewall(iface);

        assert!(
            !fw.check_role_any(1001, &["admin", "superadmin"])
                .await
                .unwrap(),
            "不持有任一角色应返回 false"
        );
    }

    /// 验证 check_role_all：主体持有 roles 中所有角色才返回 true。
    #[tokio::test]
    async fn check_role_all_all_held_returns_true() {
        let mut iface = MockInterface::new();
        iface.set_roles(1001, &["admin", "user"]);
        let fw = make_firewall(iface);

        assert!(
            fw.check_role_all(1001, &["admin", "user"]).await.unwrap(),
            "持有所有角色应返回 true"
        );
    }

    /// spec scenario "多角色全部匹配"：主体仅持有部分角色时返回 false。
    #[tokio::test]
    async fn check_role_all_partial_held_returns_false() {
        let mut iface = MockInterface::new();
        iface.set_roles(1001, &["admin"]);
        let fw = make_firewall(iface);

        assert!(
            !fw.check_role_all(1001, &["admin", "user"]).await.unwrap(),
            "仅持有部分角色应返回 false"
        );
    }

    /// 验证 check_role_all：空 roles 切片返回 true（空集平凡满足）。
    #[tokio::test]
    async fn check_role_all_empty_roles_returns_true() {
        let mut iface = MockInterface::new();
        iface.set_roles(1001, &["admin"]);
        let fw = make_firewall(iface);

        assert!(
            fw.check_role_all(1001, &[]).await.unwrap(),
            "空 roles 切片应平凡返回 true"
        );
    }

    // ------------------------------------------------------------------------
    // get_permission_list / get_role_list 回调委托验证
    // ------------------------------------------------------------------------

    /// 验证 get_permission_list 委托 BulwarkInterface 回调。
    #[tokio::test]
    async fn get_permission_list_delegates_to_interface() {
        let mut iface = MockInterface::new();
        iface.set_permissions(1001, &["user:read", "user:write"]);
        let fw = make_firewall(iface);

        let perms = fw.get_permission_list(1001).await.unwrap();
        assert_eq!(perms, vec!["user:read", "user:write"]);
    }

    /// 验证 get_role_list 委托 BulwarkInterface 回调。
    #[tokio::test]
    async fn get_role_list_delegates_to_interface() {
        let mut iface = MockInterface::new();
        iface.set_roles(1001, &["admin", "user"]);
        let fw = make_firewall(iface);

        let roles = fw.get_role_list(1001).await.unwrap();
        assert_eq!(roles, vec!["admin", "user"]);
    }

    /// 验证未配置权限的 login_id 返回空列表（不抛错）。
    #[tokio::test]
    async fn get_permission_list_unknown_login_id_returns_empty() {
        let iface = MockInterface::new();
        let fw = make_firewall(iface);

        let perms = fw.get_permission_list(9999).await.unwrap();
        assert!(perms.is_empty(), "未配置权限的 login_id 应返回空列表");
    }
}
