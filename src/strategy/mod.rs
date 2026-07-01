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

use crate::core::permission::PermissionChecker;
use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use crate::plugin::BulwarkPluginManager;
use crate::stp::BulwarkInterface;
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
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
    ///
    /// # 返回
    /// 新建的 `BulwarkStrategy` 实例（占位实现，0.2.0+ 完善）。
    pub fn new() -> Self {
        Self { _inner: () }
    }

    /// 生成 Token 字符串。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 生成的 token 字符串。
    ///
    /// # 错误
    /// 0.2.0+ 实现前返回 `BulwarkError::Internal`（不 panic）。
    pub fn create_token(&self, login_id: i64) -> BulwarkResult<String> {
        let _ = login_id;
        Err(BulwarkError::Internal(
            "create_token not yet implemented (planned for 0.2.0+)".to_string(),
        ))
    }

    /// 根据 Token 解析登录主体标识。
    ///
    /// # 参数
    /// - `token`: Token 字符串。
    ///
    /// # 返回
    /// - `Some(login_id)`: token 有效，返回关联的登录主体标识。
    /// - `None`: token 无效或已过期。
    ///
    /// # 错误
    /// 0.2.0+ 实现前返回 `BulwarkError::Internal`（不 panic）。
    pub fn parse_login_id(&self, token: &str) -> BulwarkResult<Option<i64>> {
        let _ = token;
        Err(BulwarkError::Internal(
            "parse_login_id not yet implemented (planned for 0.2.0+)".to_string(),
        ))
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
    ///
    /// # 返回
    /// 权限标识字符串列表（如 `["user:read", "user:write"]`）。
    ///
    /// # 错误
    /// - 数据回调失败：透传 `BulwarkError`。
    async fn get_permission_list(&self, login_id: i64) -> BulwarkResult<Vec<String>>;

    /// 获取主体的角色列表。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// 角色标识字符串列表（如 `["admin", "user"]`）。
    ///
    /// # 错误
    /// - 数据回调失败：透传 `BulwarkError`。
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
    ///
    /// # 返回
    /// - `Ok(true)`: 主体持有该角色。
    /// - `Ok(false)`: 主体未持有该角色。
    ///
    /// # 错误
    /// - 数据回调失败：透传 `BulwarkError`。
    async fn check_role(&self, login_id: i64, role: &str) -> BulwarkResult<bool>;

    /// 校验角色（任一匹配）：主体持有 `roles` 中任意一个即通过。
    ///
    /// 对应 spec scenario "多角色任一匹配"。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `roles`: 候选角色列表。
    ///
    /// # 返回
    /// - `Ok(true)`: 主体持有 `roles` 中任一角色。
    /// - `Ok(false)`: 主体不持有 `roles` 中任何角色。
    ///
    /// # 错误
    /// - 数据回调失败：透传 `BulwarkError`。
    async fn check_role_any(&self, login_id: i64, roles: &[&str]) -> BulwarkResult<bool>;

    /// 校验角色（全部匹配）：主体需持有 `roles` 中所有角色。
    ///
    /// 对应 spec scenario "多角色全部匹配"。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `roles`: 必须全部持有的角色列表。
    ///
    /// # 返回
    /// - `Ok(true)`: 主体持有 `roles` 中所有角色（空列表平凡满足）。
    /// - `Ok(false)`: 主体仅持有部分或未持有任何角色。
    ///
    /// # 错误
    /// - 数据回调失败：透传 `BulwarkError`。
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
///
/// # 0.2.0 扩展（依据 spec permission-role-check）
///
/// - `permission_checker`：注入后 `check_permission` 委托到 `PermissionChecker`
/// - `dao`：注入后启用权限缓存（`cache_permission` / `get_cached_permission`）
/// - `role_hierarchy`：角色层级映射（如 `"admin" → ["user"]`），空时保持 0.1.0 行为
/// - `plugin_manager`：注入后 `check_permission` 前后触发插件钩子（Err 仅 warn 不中断）
pub struct BulwarkFirewallStrategyDefault {
    /// 权限/角色数据回调。
    interface: Arc<dyn BulwarkInterface>,
    /// 0.2.0：可选 PermissionChecker，注入后 check_permission 委托到它。
    permission_checker: Option<Arc<dyn PermissionChecker>>,
    /// 0.2.0：可选 DAO，用于权限缓存。
    dao: Option<Arc<dyn BulwarkDao>>,
    /// 0.2.0：角色层级映射（如 "admin" → ["user"]），空时保持 0.1.0 行为。
    role_hierarchy: HashMap<String, Vec<String>>,
    /// 0.2.0：可选插件管理器，注入后 check_permission 前后触发钩子。
    plugin_manager: Option<Arc<BulwarkPluginManager>>,
}

impl BulwarkFirewallStrategyDefault {
    /// 创建默认实现实例。
    ///
    /// # 参数
    /// - `interface`: 权限/角色数据回调（业务方实现）。
    ///
    /// # 返回
    /// 新建的 `BulwarkFirewallStrategyDefault` 实例（0.2.0 扩展字段均为 None/空，
    /// 行为与 0.1.0 完全一致）。
    pub fn new(interface: Arc<dyn BulwarkInterface>) -> Self {
        Self {
            interface,
            permission_checker: None,
            dao: None,
            role_hierarchy: HashMap::new(),
            plugin_manager: None,
        }
    }

    /// 注入 `PermissionChecker`，启用委托校验（0.2.0 新增）。
    ///
    /// 注入后 `check_permission` 将委托 `PermissionChecker::has_permission`，
    /// 而非直接调用 `BulwarkInterface::get_permission_list`。
    pub fn with_permission_checker(mut self, pc: Arc<dyn PermissionChecker>) -> Self {
        self.permission_checker = Some(pc);
        self
    }

    /// 注入 `BulwarkDao`，启用权限缓存（0.2.0 新增）。
    ///
    /// 注入后 `check_permission` 会优先读取缓存，未命中时查询并回填。
    pub fn with_dao(mut self, dao: Arc<dyn BulwarkDao>) -> Self {
        self.dao = Some(dao);
        self
    }

    /// 配置角色层级映射（0.2.0 新增）。
    ///
    /// # 参数
    /// - `hierarchy`: 角色层级映射，如 `{"admin": ["user"], "superadmin": ["admin"]}`，
    ///   表示 admin 隐含持有 user，superadmin 隐含持有 admin（多层传递）。
    pub fn with_role_hierarchy(mut self, hierarchy: HashMap<String, Vec<String>>) -> Self {
        self.role_hierarchy = hierarchy;
        self
    }

    /// 注入 `BulwarkPluginManager`，启用插件钩子（0.2.0 新增）。
    ///
    /// 注入后 `check_permission` 前后调用 `BulwarkPluginManager::on_permission_check`，
    /// 插件返回 Err 仅 `tracing::warn!` 不中断主流程。
    pub fn with_plugin_manager(mut self, pm: Arc<BulwarkPluginManager>) -> Self {
        self.plugin_manager = Some(pm);
        self
    }

    /// 展开角色列表（含层级隐含角色）。
    ///
    /// 使用 BFS 遍历 `role_hierarchy`，收集所有直接与间接持有的角色。
    /// 当 `role_hierarchy` 为空时，返回原列表的集合（无扩展）。
    fn expand_roles(&self, roles: &[String]) -> HashSet<String> {
        let mut result = HashSet::new();
        let mut queue: Vec<String> = roles.to_vec();
        while let Some(r) = queue.pop() {
            if result.insert(r.clone()) {
                if let Some(implied) = self.role_hierarchy.get(&r) {
                    queue.extend(implied.iter().cloned());
                }
            }
        }
        result
    }

    /// 缓存权限校验结果（0.2.0 新增，依据 spec permission-role-check）。
    ///
    /// 将校验结果写入 `BulwarkDao`，key 格式 `bulwark:perm:cache:<login_id>:<permission>`。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `permission`: 权限标识字符串。
    /// - `result`: 校验结果（true/false）。
    /// - `ttl_seconds`: 缓存 TTL（秒）。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`；未注入 DAO 时为 no-op。
    ///
    /// # 错误
    /// - DAO 写入失败：透传 `BulwarkError`。
    pub async fn cache_permission(
        &self,
        login_id: i64,
        permission: &str,
        result: bool,
        ttl_seconds: u64,
    ) -> BulwarkResult<()> {
        if let Some(dao) = &self.dao {
            let key = format!("bulwark:perm:cache:{}:{}", login_id, permission);
            dao.set(&key, if result { "true" } else { "false" }, ttl_seconds)
                .await?;
        }
        Ok(())
    }

    /// 读取缓存的权限校验结果（0.2.0 新增，依据 spec permission-role-check）。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `permission`: 权限标识字符串。
    ///
    /// # 返回
    /// - `Some(bool)`: 缓存命中。
    /// - `None`: 缓存未命中或未注入 DAO。
    ///
    /// # 错误
    /// - DAO 读取失败：透传 `BulwarkError`。
    pub async fn get_cached_permission(
        &self,
        login_id: i64,
        permission: &str,
    ) -> BulwarkResult<Option<bool>> {
        if let Some(dao) = &self.dao {
            let key = format!("bulwark:perm:cache:{}:{}", login_id, permission);
            match dao.get(&key).await? {
                Some(v) => Ok(Some(v == "true")),
                None => Ok(None),
            }
        } else {
            Ok(None)
        }
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

        // 0.2.0：插件钩子（before）— 内部已处理 Err 仅 warn 不中断（依据 task 21.3）
        if let Some(pm) = &self.plugin_manager {
            pm.on_permission_check(login_id, permission);
        }

        // 0.2.0：优先读取权限缓存（依据 task 21.4 / spec "check_permission 优先读取缓存"）
        if self.dao.is_some() {
            if let Ok(Some(cached)) = self.get_cached_permission(login_id, permission).await {
                return Ok(cached);
            }
        }

        // 0.2.0：委托 PermissionChecker（若注入），否则回退到 0.1.0 行为
        let result = if let Some(pc) = &self.permission_checker {
            pc.has_permission(login_id, permission).await?
        } else {
            let permissions = self.get_permission_list(login_id).await?;
            permissions.iter().any(|p| p == permission)
        };

        // 0.2.0：写入缓存（失败仅 warn 不中断）
        if let Some(_dao) = &self.dao {
            if let Err(e) = self
                .cache_permission(login_id, permission, result, 300)
                .await
            {
                tracing::warn!(
                    "权限缓存写入失败 (login_id={}, perm={}): {}",
                    login_id,
                    permission,
                    e
                );
            }
        }

        Ok(result)
    }

    async fn check_role(&self, login_id: i64, role: &str) -> BulwarkResult<bool> {
        if role.is_empty() {
            return Err(BulwarkError::InvalidToken("角色字符串不能为空".to_string()));
        }
        let roles = self.get_role_list(login_id).await?;
        // 0.2.0：层级角色展开（依据 task 21.2 / spec "层级角色隐含匹配"）
        if !self.role_hierarchy.is_empty() {
            let expanded = self.expand_roles(&roles);
            Ok(expanded.contains(role))
        } else {
            Ok(roles.iter().any(|r| r == role))
        }
    }

    async fn check_role_any(&self, login_id: i64, roles: &[&str]) -> BulwarkResult<bool> {
        let user_roles = self.get_role_list(login_id).await?;
        // 0.2.0：层级角色展开
        if !self.role_hierarchy.is_empty() {
            let expanded = self.expand_roles(&user_roles);
            Ok(roles.iter().any(|r| expanded.contains(*r)))
        } else {
            Ok(roles.iter().any(|r| user_roles.iter().any(|ur| ur == r)))
        }
    }

    async fn check_role_all(&self, login_id: i64, roles: &[&str]) -> BulwarkResult<bool> {
        let user_roles = self.get_role_list(login_id).await?;
        // 0.2.0：层级角色展开
        if !self.role_hierarchy.is_empty() {
            let expanded = self.expand_roles(&user_roles);
            Ok(roles.iter().all(|r| expanded.contains(*r)))
        } else {
            Ok(roles.iter().all(|r| user_roles.iter().any(|ur| ur == r)))
        }
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

    /// 验证空角色字符串返回 Err（依据 codebase-hardening Task 3.10）。
    ///
    /// 与 `check_permission_empty_string_errors` 对称：
    /// 空角色字符串应抛 `InvalidToken` 错误。
    #[tokio::test]
    async fn check_role_empty_string_errors() {
        let iface = MockInterface::new();
        let fw = make_firewall(iface);

        let result = fw.check_role(1001, "").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "空角色字符串应抛 InvalidToken"
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

    // ------------------------------------------------------------------------
    // BulwarkStrategy 占位实现测试（返回 Internal 错误而非 panic）
    // ------------------------------------------------------------------------

    /// 验证 `BulwarkStrategy::create_token` 在 0.2.0+ 实现前返回 `Internal` 错误。
    ///
    /// 覆盖 `create_token` 方法体（占位实现返回 `Err(BulwarkError::Internal)`）。
    #[test]
    fn strategy_create_token_returns_internal_error() {
        let strategy = BulwarkStrategy::new();
        let result = strategy.create_token(1001);
        assert!(
            matches!(result, Err(BulwarkError::Internal(_))),
            "占位实现应返回 Internal 错误，实际: {:?}",
            result
        );
    }

    /// 验证 `BulwarkStrategy::parse_login_id` 在 0.2.0+ 实现前返回 `Internal` 错误。
    ///
    /// 覆盖 `parse_login_id` 方法体（占位实现返回 `Err(BulwarkError::Internal)`）。
    #[test]
    fn strategy_parse_login_id_returns_internal_error() {
        let strategy = BulwarkStrategy::new();
        let result = strategy.parse_login_id("some-token");
        assert!(
            matches!(result, Err(BulwarkError::Internal(_))),
            "占位实现应返回 Internal 错误，实际: {:?}",
            result
        );
    }

    /// 验证 `BulwarkStrategy::default()` 等价于 `new()`。
    ///
    /// 覆盖 `impl Default for BulwarkStrategy` 的 `default()` 方法。
    #[test]
    fn strategy_default_eq_new() {
        let _strategy = BulwarkStrategy::default();
        // 仅验证可构造（占位结构体无字段可断言）
    }

    // ------------------------------------------------------------------------
    // 0.2.0 新增：PermissionChecker 集成测试（依据 task 21.1）
    // ------------------------------------------------------------------------

    /// 可配置的 MockPermissionChecker，返回预设的权限/角色校验结果。
    struct MockPermissionChecker {
        perm_result: bool,
    }

    #[async_trait]
    impl PermissionChecker for MockPermissionChecker {
        async fn has_permission(&self, _login_id: i64, _permission: &str) -> BulwarkResult<bool> {
            Ok(self.perm_result)
        }
        async fn has_role(&self, _login_id: i64, _role: &str) -> BulwarkResult<bool> {
            Ok(false)
        }
        async fn check_permission(&self, _login_id: i64, _permission: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_role(&self, _login_id: i64, _role: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn has_any_permission(&self, _login_id: i64, _perms: &[&str]) -> bool {
            false
        }
        async fn has_all_permissions(&self, _login_id: i64, _perms: &[&str]) -> bool {
            false
        }
    }

    /// 验证注入 PermissionChecker 后 check_permission 委托到它。
    ///
    /// 对应 spec scenario "PermissionChecker 集成委托校验 (NEW - 0.2.0)"。
    #[tokio::test]
    async fn check_permission_delegates_to_permission_checker() {
        let iface = MockInterface::new();
        let pc = Arc::new(MockPermissionChecker { perm_result: true });
        let fw = BulwarkFirewallStrategyDefault::new(Arc::new(iface)).with_permission_checker(pc);

        // PermissionChecker 返回 true，即使 interface 中无权限记录
        assert!(
            fw.check_permission(1001, "user:read").await.unwrap(),
            "注入 PermissionChecker 后应委托校验，返回 true"
        );
    }

    /// 验证 PermissionChecker 返回 false 时 check_permission 返回 false。
    #[tokio::test]
    async fn check_permission_delegates_returns_false() {
        let iface = MockInterface::new();
        let pc = Arc::new(MockPermissionChecker { perm_result: false });
        let fw = BulwarkFirewallStrategyDefault::new(Arc::new(iface)).with_permission_checker(pc);

        assert!(
            !fw.check_permission(1001, "user:read").await.unwrap(),
            "PermissionChecker 返回 false 时应返回 false"
        );
    }

    /// 验证未注入 PermissionChecker 时回退到 0.1.0 行为（直接查 interface）。
    ///
    /// 对应 spec scenario "未启用 core-permission 回退到 0.1.0 行为 (NEW - 0.2.0)"。
    #[tokio::test]
    async fn check_permission_without_checker_falls_back_to_interface() {
        let mut iface = MockInterface::new();
        iface.set_permissions(1001, &["user:read"]);
        let fw = BulwarkFirewallStrategyDefault::new(Arc::new(iface));

        assert!(
            fw.check_permission(1001, "user:read").await.unwrap(),
            "未注入 PermissionChecker 时应回退到 interface 查询"
        );
    }

    // ------------------------------------------------------------------------
    // 0.2.0 新增：层级角色测试（依据 task 21.2）
    // ------------------------------------------------------------------------

    /// 辅助函数：创建带角色层级的 firewall。
    fn make_firewall_with_hierarchy(
        interface: MockInterface,
        hierarchy: HashMap<String, Vec<String>>,
    ) -> BulwarkFirewallStrategyDefault {
        BulwarkFirewallStrategyDefault::new(Arc::new(interface)).with_role_hierarchy(hierarchy)
    }

    /// 验证层级角色：admin 隐含持有 user。
    ///
    /// 对应 spec scenario "层级角色隐含匹配 (NEW - 0.2.0)"。
    #[tokio::test]
    async fn check_role_hierarchy_admin_implies_user() {
        let mut iface = MockInterface::new();
        iface.set_roles(1001, &["admin"]);
        let mut hierarchy = HashMap::new();
        hierarchy.insert("admin".to_string(), vec!["user".to_string()]);
        let fw = make_firewall_with_hierarchy(iface, hierarchy);

        assert!(
            fw.check_role(1001, "user").await.unwrap(),
            "admin 应隐含持有 user"
        );
        assert!(
            !fw.check_role(1001, "superadmin").await.unwrap(),
            "admin 不隐含 superadmin"
        );
    }

    /// 验证层级角色多层传递：superadmin → admin → user。
    ///
    /// 对应 spec scenario "层级角色多层传递 (NEW - 0.2.0)"。
    #[tokio::test]
    async fn check_role_hierarchy_transitive() {
        let mut iface = MockInterface::new();
        iface.set_roles(1001, &["superadmin"]);
        let mut hierarchy = HashMap::new();
        hierarchy.insert("admin".to_string(), vec!["user".to_string()]);
        hierarchy.insert("superadmin".to_string(), vec!["admin".to_string()]);
        let fw = make_firewall_with_hierarchy(iface, hierarchy);

        assert!(
            fw.check_role(1001, "user").await.unwrap(),
            "superadmin 应多层传递隐含 user"
        );
        assert!(
            fw.check_role(1001, "admin").await.unwrap(),
            "superadmin 应隐含 admin"
        );
    }

    /// 验证未配置 role_hierarchy 时保持 0.1.0 行为。
    ///
    /// 对应 spec scenario "未配置 role_hierarchy 保持 0.1.0 行为 (NEW - 0.2.0)"。
    #[tokio::test]
    async fn check_role_without_hierarchy_keeps_legacy_behavior() {
        let mut iface = MockInterface::new();
        iface.set_roles(1001, &["admin"]);
        let fw = make_firewall(iface); // 无 hierarchy

        assert!(
            !fw.check_role(1001, "user").await.unwrap(),
            "未配置 hierarchy 时 admin 不隐含 user（0.1.0 行为）"
        );
    }

    /// 验证 check_role_any / check_role_all 在层级角色下的行为。
    #[tokio::test]
    async fn check_role_any_all_with_hierarchy() {
        let mut iface = MockInterface::new();
        iface.set_roles(1001, &["admin"]);
        let mut hierarchy = HashMap::new();
        hierarchy.insert("admin".to_string(), vec!["user".to_string()]);
        let fw = make_firewall_with_hierarchy(iface, hierarchy);

        // admin 隐含 user，所以 check_role_any(["user", "guest"]) 应返回 true
        assert!(
            fw.check_role_any(1001, &["user", "guest"]).await.unwrap(),
            "层级展开后应持有 user，check_role_any 应返回 true"
        );
        // admin 隐含 user，但不含 superadmin，check_role_all 应返回 false
        assert!(
            !fw.check_role_all(1001, &["user", "superadmin"])
                .await
                .unwrap(),
            "层级展开后不含 superadmin，check_role_all 应返回 false"
        );
    }

    // ------------------------------------------------------------------------
    // 0.2.0 新增：插件钩子测试（依据 task 21.3）
    // ------------------------------------------------------------------------

    /// 验证注入 PluginManager 后 check_permission 触发插件钩子。
    ///
    /// 对应 spec scenario "插件感知策略触发 on_permission_check (NEW - 0.2.0)"。
    #[tokio::test]
    async fn check_permission_triggers_plugin_hook() {
        let mut iface = MockInterface::new();
        iface.set_permissions(1001, &["user:read"]);
        // BulwarkPluginManager::new() 收集所有 inventory 注册的插件
        let pm = Arc::new(BulwarkPluginManager::new());
        let fw = BulwarkFirewallStrategyDefault::new(Arc::new(iface)).with_plugin_manager(pm);

        // 插件钩子不应中断主流程，校验结果应正常返回
        assert!(
            fw.check_permission(1001, "user:read").await.unwrap(),
            "插件钩子不应影响校验结果"
        );
    }

    /// 验证插件失败不中断 check_permission 主流程。
    ///
    /// 对应 spec scenario "插件短路拒绝权限校验 (NEW - 0.2.0)"。
    /// 注意：当前实现遵循 task 21.3（Err → warn 不中断），不实现 spec 的 Override 机制。
    #[tokio::test]
    async fn check_permission_plugin_failure_does_not_interrupt() {
        let mut iface = MockInterface::new();
        iface.set_permissions(1001, &["user:read"]);
        // PluginManager 包含 ErrPlugin（on_permission_check 返回 Err），
        // 但主流程不应被中断
        let pm = Arc::new(BulwarkPluginManager::new());
        let fw = BulwarkFirewallStrategyDefault::new(Arc::new(iface)).with_plugin_manager(pm);

        assert!(
            fw.check_permission(1001, "user:read").await.unwrap(),
            "插件失败不应中断主流程，校验结果应正常返回 true"
        );
    }

    // ------------------------------------------------------------------------
    // 0.2.0 新增：权限缓存测试（依据 task 21.4）
    // ------------------------------------------------------------------------

    /// 简单的 MockDao，用于权限缓存测试。
    struct MockCacheDao {
        store: parking_lot::Mutex<HashMap<String, String>>,
    }

    impl MockCacheDao {
        fn new() -> Self {
            Self {
                store: parking_lot::Mutex::new(HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl BulwarkDao for MockCacheDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            Ok(self.store.lock().get(key).cloned())
        }
        async fn set(&self, key: &str, value: &str, _ttl_seconds: u64) -> BulwarkResult<()> {
            self.store.lock().insert(key.to_string(), value.to_string());
            Ok(())
        }
        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            self.store.lock().insert(key.to_string(), value.to_string());
            Ok(())
        }
        async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
            Ok(())
        }
        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            self.store.lock().remove(key);
            Ok(())
        }
    }

    /// 验证 cache_permission 写入 DAO，后续 get_cached_permission 返回缓存值。
    ///
    /// 对应 spec scenario "缓存权限校验结果 (NEW - 0.2.0)"。
    #[tokio::test]
    async fn cache_permission_writes_and_reads_back() {
        let dao = Arc::new(MockCacheDao::new());
        let iface = MockInterface::new();
        let fw = BulwarkFirewallStrategyDefault::new(Arc::new(iface)).with_dao(dao.clone());

        fw.cache_permission(1001, "user:read", true, 300)
            .await
            .unwrap();

        let cached = fw.get_cached_permission(1001, "user:read").await.unwrap();
        assert_eq!(cached, Some(true), "缓存应命中并返回 true");

        // 验证 key 格式
        let key = "bulwark:perm:cache:1001:user:read";
        assert_eq!(
            dao.get(key).await.unwrap(),
            Some("true".to_string()),
            "DAO 中应存储 key {}",
            key
        );
    }

    /// 验证 get_cached_permission 未命中时返回 None。
    ///
    /// 对应 spec scenario "读取未命中缓存返回 None (NEW - 0.2.0)"。
    #[tokio::test]
    async fn get_cached_permission_miss_returns_none() {
        let dao = Arc::new(MockCacheDao::new());
        let iface = MockInterface::new();
        let fw = BulwarkFirewallStrategyDefault::new(Arc::new(iface)).with_dao(dao);

        let cached = fw.get_cached_permission(1001, "user:delete").await.unwrap();
        assert!(cached.is_none(), "未缓存的权限应返回 None");
    }

    /// 验证缓存覆盖：相同 key 的第二次写入覆盖第一次。
    ///
    /// 对应 spec scenario "权限变更时刷新缓存 (NEW - 0.2.0)"。
    #[tokio::test]
    async fn cache_permission_overwrite() {
        let dao = Arc::new(MockCacheDao::new());
        let iface = MockInterface::new();
        let fw = BulwarkFirewallStrategyDefault::new(Arc::new(iface)).with_dao(dao);

        // 第一次缓存 true
        fw.cache_permission(1001, "user:read", true, 300)
            .await
            .unwrap();
        assert_eq!(
            fw.get_cached_permission(1001, "user:read").await.unwrap(),
            Some(true)
        );

        // 覆盖为 false
        fw.cache_permission(1001, "user:read", false, 300)
            .await
            .unwrap();
        assert_eq!(
            fw.get_cached_permission(1001, "user:read").await.unwrap(),
            Some(false),
            "覆盖后应返回 false"
        );
    }

    /// 验证 check_permission 优先读取缓存（短路优化）。
    ///
    /// 对应 spec scenario "check_permission 优先读取缓存 (NEW - 0.2.0)"。
    #[tokio::test]
    async fn check_permission_uses_cache_short_circuit() {
        let dao = Arc::new(MockCacheDao::new());
        let mut iface = MockInterface::new();
        // interface 中无 user:read 权限
        iface.set_permissions(1001, &[]);
        let fw = BulwarkFirewallStrategyDefault::new(Arc::new(iface)).with_dao(dao.clone());

        // 预先写入缓存 true（与 interface 实际权限矛盾）
        fw.cache_permission(1001, "user:read", true, 300)
            .await
            .unwrap();

        // check_permission 应短路返回缓存值 true，不查询 interface
        assert!(
            fw.check_permission(1001, "user:read").await.unwrap(),
            "应优先返回缓存结果 true，而非查询 interface"
        );
    }
}
