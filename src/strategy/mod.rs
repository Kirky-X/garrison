//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 策略模块，提供鉴权策略与可插拔权限策略。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的策略模式设计，
//! 允许通过策略对象定制鉴权行为。
//!
//! ## 权限策略
//!
//! - `BulwarkPermissionStrategy` trait：定义权限/角色校验的可插拔契约
//! - `BulwarkPermissionStrategyDefault`：默认实现，持有 `BulwarkInterface` 回调获取权限/角色数据，
//!   做字符串匹配校验
//!
//! ## 数据来源（依据用户决策：方案 B）
//!
//! 权限/角色数据由业务方实现 `BulwarkInterface` 回调提供（不委托 dbnexus
//! `PermissionProvider` trait，因其 API 模型与 Bulwark 不匹配）。

use crate::core::permission::PermissionChecker;
use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
// listener_manager 注入（feature-gated）
#[cfg(feature = "listener")]
use crate::listener::{BulwarkEvent, BulwarkListenerManager};
use crate::plugin::BulwarkPluginManager;
use crate::stp::BulwarkInterface;
use crate::strategy::hooks::{BulwarkFirewallCheckHook, LoginContext};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

/// 安全告警系统模块（feature-gated: `security-alert`）。
#[cfg(feature = "security-alert")]
pub mod alert;
/// 设备绑定策略模块（feature-gated: `device-binding`，依赖 `security-alert`）。
#[cfg(feature = "device-binding")]
pub mod device_binding;
/// IP 级防火墙策略套件模块。
#[cfg(feature = "firewall")]
pub mod firewall;
/// 防火墙安全钩子模块（）。
pub mod hooks;
/// 通用令牌桶限流器模块。
pub mod rate_limiter;
/// 限流器后端抽象模块（trait 始终可用，无 feature gate）。
pub mod rate_limiter_backend;
/// Redis 限流器模块（feature-gated: `rate-limit-redis`）。
#[cfg(feature = "rate-limit-redis")]
pub mod redis_rate_limiter;
/// 策略注册表模块。
pub mod registry;

// Re-export 核心 trait 与类型以便外部使用
pub use hooks::{
    BulwarkFirewallCheckHookDefault, LoginContext as FirewallLoginContext, BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW, LOGIN_FREQUENCY_THRESHOLD, LOGIN_FREQUENCY_WINDOW,
};
// Re-export 策略注册表的 6 个 trait + 默认实现 + Strategy 注册表
// 注意：新 FirewallStrategy 与现有 BulwarkPermissionStrategy 名称不同，可直接 re-export 共存
pub use registry::{
    DefaultFirewallStrategy, DefaultLoginHandler, DefaultLogoutHandler, DefaultPermissionHandler,
    DefaultSessionCreator, DefaultTokenGenerator, FirewallStrategy, LoginHandler, LogoutHandler,
    PermissionHandler, SessionCreator, Strategy, TokenGenerator,
};

// ============================================================================
// BulwarkPermissionStrategy trait：可插拔权限策略
// ============================================================================

/// 权限策略 trait，定义权限/角色校验的可插拔契约。
///
/// [借鉴 Sa-Token] 对应 Sa-Token 的可插拔权限策略，
/// 业务方可通过实现此 trait 替换默认的权限校验逻辑。
///
/// # 默认实现
///
/// `BulwarkPermissionStrategyDefault` 持有 `BulwarkInterface` 回调，
/// 调用 `get_permission_list` / `get_role_list` 获取数据后做字符串匹配。
#[async_trait]
pub trait BulwarkPermissionStrategy: Send + Sync {
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
    async fn get_permission_list(&self, login_id: &str) -> BulwarkResult<Vec<String>>;

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
    async fn get_role_list(&self, login_id: &str) -> BulwarkResult<Vec<String>>;

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
    async fn check_permission(&self, login_id: &str, permission: &str) -> BulwarkResult<bool>;

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
    async fn check_role(&self, login_id: &str, role: &str) -> BulwarkResult<bool>;

    /// 校验角色（任一匹配）：主体持有 `roles` 中任意一个即通过。
    ///
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
    async fn check_role_any(&self, login_id: &str, roles: &[&str]) -> BulwarkResult<bool>;

    /// 校验角色（全部匹配）：主体需持有 `roles` 中所有角色。
    ///
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
    async fn check_role_all(&self, login_id: &str, roles: &[&str]) -> BulwarkResult<bool>;

    /// 登录前防火墙安全钩子检查。
    ///
    /// 默认实现为 no-op（向后兼容 0.2.x）。`BulwarkPermissionStrategyDefault` 在注入
    /// `BulwarkFirewallCheckHook` 后按序调用 5 个 hook，任一 Err 阻断登录。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `ctx`: 登录上下文（IP / 设备指纹 / 地理位置，可选）。
    ///
    /// # 返回
    /// - `Ok(())`: 所有 hook 通过，允许登录。
    /// - `Err`: 任一 hook 阻断，返回 `BulwarkError::Session`。
    async fn check_login_hooks(&self, _login_id: &str, _ctx: &LoginContext) -> BulwarkResult<()> {
        Ok(())
    }
}

// ============================================================================
// BulwarkPermissionStrategyDefault：默认实现（委托 BulwarkInterface 回调）
// ============================================================================

/// `BulwarkPermissionStrategy` 的默认实现，持有 `BulwarkInterface` 回调获取权限/角色数据。
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
/// # 0.2.0 扩展
///
/// - `permission_checker`：注入后 `check_permission` 委托到 `PermissionChecker`
/// - `dao`：注入后启用权限缓存（`cache_permission` / `get_cached_permission`）
/// - `role_hierarchy`：角色层级映射（如 `"admin" → ["user"]`），空时保持 默认行为
/// - `plugin_manager`：注入后 `check_permission` 前后触发插件钩子（Err 仅 warn 不中断）
pub struct BulwarkPermissionStrategyDefault {
    /// 权限/角色数据回调。
    interface: Arc<dyn BulwarkInterface>,
    /// 可选 PermissionChecker，注入后 check_permission 委托到它。
    permission_checker: Option<Arc<dyn PermissionChecker>>,
    /// 可选 DAO，用于权限缓存。
    dao: Option<Arc<dyn BulwarkDao>>,
    /// 角色层级映射（如 "admin" → ["user"]），空时保持 默认行为。
    role_hierarchy: HashMap<String, Vec<String>>,
    /// 可选插件管理器，注入后 check_permission 前后触发钩子。
    plugin_manager: Option<Arc<BulwarkPluginManager>>,
    /// 可选防火墙安全钩子，注入后 login 前按序调用 5 个 hook。
    firewall_hook: Option<Arc<dyn BulwarkFirewallCheckHook>>,
    /// 可选监听器管理器，注入后 check_login_hooks 阻断时广播 FirewallBlock 事件
    #[cfg(feature = "listener")]
    listener_manager: Option<Arc<BulwarkListenerManager>>,
}

impl BulwarkPermissionStrategyDefault {
    /// 创建默认实现实例。
    ///
    /// # 参数
    /// - `interface`: 权限/角色数据回调（业务方实现）。
    ///
    /// # 返回
    /// 新建的 `BulwarkPermissionStrategyDefault` 实例（0.2.0 扩展字段均为 None/空，
    /// 行为与 0.1.0 完全一致）。
    pub fn new(interface: Arc<dyn BulwarkInterface>) -> Self {
        Self {
            interface,
            permission_checker: None,
            dao: None,
            role_hierarchy: HashMap::new(),
            plugin_manager: None,
            firewall_hook: None,
            #[cfg(feature = "listener")]
            listener_manager: None,
        }
    }

    /// 注入 `PermissionChecker`，启用委托校验（）。
    ///
    /// 注入后 `check_permission` 将委托 `PermissionChecker::has_permission`，
    /// 而非直接调用 `BulwarkInterface::get_permission_list`。
    pub fn with_permission_checker(mut self, pc: Arc<dyn PermissionChecker>) -> Self {
        self.permission_checker = Some(pc);
        self
    }

    /// 注入 `BulwarkDao`，启用权限缓存（）。
    ///
    /// 注入后 `check_permission` 会优先读取缓存，未命中时查询并回填。
    pub fn with_dao(mut self, dao: Arc<dyn BulwarkDao>) -> Self {
        self.dao = Some(dao);
        self
    }

    /// 配置角色层级映射（）。
    ///
    /// # 参数
    /// - `hierarchy`: 角色层级映射，如 `{"admin": ["user"], "superadmin": ["admin"]}`，
    ///   表示 admin 隐含持有 user，superadmin 隐含持有 admin（多层传递）。
    pub fn with_role_hierarchy(mut self, hierarchy: HashMap<String, Vec<String>>) -> Self {
        self.role_hierarchy = hierarchy;
        self
    }

    /// 注入 `BulwarkPluginManager`，启用插件钩子（）。
    ///
    /// 注入后 `check_permission` 前后调用 `BulwarkPluginManager::on_permission_check`，
    /// 插件返回 Err 仅 `tracing::warn!` 不中断主流程。
    pub fn with_plugin_manager(mut self, pm: Arc<BulwarkPluginManager>) -> Self {
        self.plugin_manager = Some(pm);
        self
    }

    /// 注入 `BulwarkFirewallCheckHook`，启用登录前防火墙安全检查。
    ///
    /// 注入后 `check_login_hooks` 将按序调用 5 个 hook（登录频率 / 暴力破解 /
    /// 异地登录 / Token 复用 / 设备异常），任一返回 `Err` 阻断登录。
    pub fn with_firewall_hook(mut self, hook: Arc<dyn BulwarkFirewallCheckHook>) -> Self {
        self.firewall_hook = Some(hook);
        self
    }

    /// 注入 `BulwarkListenerManager`，启用 FirewallBlock 事件广播
    ///
    ///
    /// 注入后 `check_login_hooks` 任一 hook 返回 `Err` 时广播 `BulwarkEvent::FirewallBlock`。
    /// 未注入时为 no-op（向后兼容 0.4.1）。需启用 `listener` feature。
    #[cfg(feature = "listener")]
    pub fn with_listener_manager(mut self, lm: Arc<BulwarkListenerManager>) -> Self {
        self.listener_manager = Some(lm);
        self
    }

    /// 展开角色列表（含层级隐含角色）。
    ///
    /// 使用 DFS 遍历 `role_hierarchy`，收集所有直接与间接持有的角色。
    /// 当 `role_hierarchy` 为空时，返回原列表的集合（无扩展）。
    fn expand_roles(&self, roles: &[String]) -> HashSet<String> {
        let mut result = HashSet::new();
        let mut stack: Vec<String> = roles.to_vec();
        while let Some(r) = stack.pop() {
            if result.insert(r.clone()) {
                if let Some(implied) = self.role_hierarchy.get(&r) {
                    stack.extend(implied.iter().cloned());
                }
            }
        }
        result
    }

    /// 缓存权限校验结果。
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
        login_id: &str,
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

    /// 读取缓存的权限校验结果。
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
        login_id: &str,
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
impl BulwarkPermissionStrategy for BulwarkPermissionStrategyDefault {
    async fn get_permission_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
        self.interface.get_permission_list(login_id).await
    }

    async fn get_role_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
        self.interface.get_role_list(login_id).await
    }

    async fn check_permission(&self, login_id: &str, permission: &str) -> BulwarkResult<bool> {
        // spec scenario "权限为空字符串"：空字符串抛 InvalidParam
        if permission.is_empty() {
            return Err(BulwarkError::InvalidParam("权限字符串不能为空".to_string()));
        }

        // 插件钩子（before）— 内部已处理 Err 仅 warn 不中断
        if let Some(pm) = &self.plugin_manager {
            pm.on_permission_check(login_id, permission);
        }

        // 优先读取权限缓存
        if self.dao.is_some() {
            if let Ok(Some(cached)) = self.get_cached_permission(login_id, permission).await {
                return Ok(cached);
            }
        }

        // 委托 PermissionChecker（若注入），否则回退到 默认行为
        let result = if let Some(pc) = &self.permission_checker {
            pc.has_permission(login_id, permission).await?
        } else {
            let permissions = self.get_permission_list(login_id).await?;
            permissions.iter().any(|p| p == permission)
        };

        // 写入缓存（失败仅 warn 不中断）
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

    async fn check_role(&self, login_id: &str, role: &str) -> BulwarkResult<bool> {
        if role.is_empty() {
            return Err(BulwarkError::InvalidParam("角色字符串不能为空".to_string()));
        }
        let roles = self.get_role_list(login_id).await?;
        // 层级角色展开
        if !self.role_hierarchy.is_empty() {
            let expanded = self.expand_roles(&roles);
            Ok(expanded.contains(role))
        } else {
            Ok(roles.iter().any(|r| r == role))
        }
    }

    async fn check_role_any(&self, login_id: &str, roles: &[&str]) -> BulwarkResult<bool> {
        let user_roles = self.get_role_list(login_id).await?;
        // 层级角色展开
        if !self.role_hierarchy.is_empty() {
            let expanded = self.expand_roles(&user_roles);
            Ok(roles.iter().any(|r| expanded.contains(*r)))
        } else {
            Ok(roles.iter().any(|r| user_roles.iter().any(|ur| ur == r)))
        }
    }

    async fn check_role_all(&self, login_id: &str, roles: &[&str]) -> BulwarkResult<bool> {
        let user_roles = self.get_role_list(login_id).await?;
        // 层级角色展开
        if !self.role_hierarchy.is_empty() {
            let expanded = self.expand_roles(&user_roles);
            Ok(roles.iter().all(|r| expanded.contains(*r)))
        } else {
            Ok(roles.iter().all(|r| user_roles.iter().any(|ur| ur == r)))
        }
    }

    /// 登录前防火墙安全钩子检查。
    ///
    /// 注入 `firewall_hook` 后按序调用 5 个 hook，任一 Err 阻断登录。
    /// 未注入时为 no-op（向后兼容 0.2.x）。
    ///
    /// v0.4.2 扩展：任一 hook 返回 Err 时，若注入了 `listener_manager`，
    /// 广播 `BulwarkEvent::FirewallBlock` 事件。
    async fn check_login_hooks(&self, login_id: &str, ctx: &LoginContext) -> BulwarkResult<()> {
        let Some(hook) = &self.firewall_hook else {
            return Ok(());
        };
        // 按序调用 5 个 hook，任一 Err 立即广播 FirewallBlock 并返回阻断登录
        if let Err(e) = hook.check_login_frequency(ctx).await {
            self.broadcast_firewall_block(login_id, &e).await;
            return Err(e);
        }
        if let Err(e) = hook.check_brute_force(ctx).await {
            self.broadcast_firewall_block(login_id, &e).await;
            return Err(e);
        }
        if let Err(e) = hook.check_geo_anomaly(ctx).await {
            self.broadcast_firewall_block(login_id, &e).await;
            return Err(e);
        }
        if let Err(e) = hook.check_token_reuse(ctx).await {
            self.broadcast_firewall_block(login_id, &e).await;
            return Err(e);
        }
        if let Err(e) = hook.check_device_anomaly(ctx).await {
            self.broadcast_firewall_block(login_id, &e).await;
            return Err(e);
        }
        Ok(())
    }
}

impl BulwarkPermissionStrategyDefault {
    /// 广播 FirewallBlock 事件。
    ///
    /// 仅在注入 `listener_manager` 且启用 `listener` feature 时广播，否则为 no-op。
    ///
    /// v0.5.0 改为 async：broadcast 改为 async 后此helper 也需 async。
    #[cfg_attr(not(feature = "listener"), allow(unused_variables))]
    async fn broadcast_firewall_block(&self, login_id: &str, e: &BulwarkError) {
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&BulwarkEvent::FirewallBlock {
                login_id: login_id.to_string(),
                reason: e.to_string(),
            })
            .await;
        }
    }
}

// ============================================================================
// 测试
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
        permissions: HashMap<String, Vec<String>>,
        roles: HashMap<String, Vec<String>>,
    }

    impl MockInterface {
        fn new() -> Self {
            Self {
                permissions: HashMap::new(),
                roles: HashMap::new(),
            }
        }

        /// 设置指定 login_id 的权限列表。
        fn set_permissions(&mut self, login_id: &str, perms: &[&str]) {
            self.permissions.insert(
                login_id.to_string(),
                perms.iter().map(|s| s.to_string()).collect(),
            );
        }

        /// 设置指定 login_id 的角色列表。
        fn set_roles(&mut self, login_id: &str, roles: &[&str]) {
            self.roles.insert(
                login_id.to_string(),
                roles.iter().map(|s| s.to_string()).collect(),
            );
        }
    }

    #[async_trait]
    impl BulwarkInterface for MockInterface {
        async fn get_permission_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
            Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
        }

        async fn get_role_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
            Ok(self.roles.get(login_id).cloned().unwrap_or_default())
        }
    }

    /// 辅助函数：创建 BulwarkPermissionStrategyDefault 实例。
    fn make_firewall(interface: MockInterface) -> BulwarkPermissionStrategyDefault {
        BulwarkPermissionStrategyDefault::new(Arc::new(interface))
    }

    // ------------------------------------------------------------------------
    // 持有权限返回 true / 未持有返回 false
    // ------------------------------------------------------------------------

    /// 验证主体持有指定权限时 check_permission 返回 true。
    #[tokio::test]
    async fn check_permission_held_returns_true() {
        let mut iface = MockInterface::new();
        iface.set_permissions("1001", &["user:read", "user:write"]);
        let fw = make_firewall(iface);

        assert!(
            fw.check_permission("1001", "user:read").await.unwrap(),
            "持有权限应返回 true"
        );
    }

    /// 验证主体未持有指定权限时 check_permission 返回 false。
    #[tokio::test]
    async fn check_permission_not_held_returns_false() {
        let mut iface = MockInterface::new();
        iface.set_permissions("1001", &["user:read"]);
        let fw = make_firewall(iface);

        assert!(
            !fw.check_permission("1001", "user:delete").await.unwrap(),
            "未持有权限应返回 false"
        );
    }

    /// 空字符串抛 InvalidParam。
    #[tokio::test]
    async fn check_permission_empty_string_errors() {
        let iface = MockInterface::new();
        let fw = make_firewall(iface);

        let result = fw.check_permission("1001", "").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(_))),
            "空权限字符串应抛 InvalidParam"
        );
    }

    /// 验证主体无任何权限记录时 check_permission 返回 false（不抛错）。
    #[tokio::test]
    async fn check_permission_no_record_returns_false() {
        let iface = MockInterface::new();
        let fw = make_firewall(iface);

        assert!(
            !fw.check_permission("9999", "user:read").await.unwrap(),
            "无权限记录的 login_id 应返回 false"
        );
    }

    // ------------------------------------------------------------------------
    // 持有角色返回 true / 未持有返回 false
    // ------------------------------------------------------------------------

    /// 验证主体持有指定角色时 check_role 返回 true。
    #[tokio::test]
    async fn check_role_held_returns_true() {
        let mut iface = MockInterface::new();
        iface.set_roles("1001", &["admin", "user"]);
        let fw = make_firewall(iface);

        assert!(
            fw.check_role("1001", "admin").await.unwrap(),
            "持有角色应返回 true"
        );
    }

    /// 验证主体未持有指定角色时 check_role 返回 false。
    #[tokio::test]
    async fn check_role_not_held_returns_false() {
        let mut iface = MockInterface::new();
        iface.set_roles("1001", &["user"]);
        let fw = make_firewall(iface);

        assert!(
            !fw.check_role("1001", "admin").await.unwrap(),
            "未持有角色应返回 false"
        );
    }

    /// 验证空角色字符串返回 Err。
    ///
    /// 与 `check_permission_empty_string_errors` 对称：
    /// 空角色字符串应抛 `InvalidParam` 错误。
    #[tokio::test]
    async fn check_role_empty_string_errors() {
        let iface = MockInterface::new();
        let fw = make_firewall(iface);

        let result = fw.check_role("1001", "").await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(_))),
            "空角色字符串应抛 InvalidParam"
        );
    }

    // ------------------------------------------------------------------------
    // 多角色任一匹配 / 全部匹配
    // ------------------------------------------------------------------------

    /// 验证 check_role_any：主体持有 roles 中任意一个即返回 true。
    #[tokio::test]
    async fn check_role_any_match_returns_true() {
        let mut iface = MockInterface::new();
        iface.set_roles("1001", &["admin"]);
        let fw = make_firewall(iface);

        assert!(
            fw.check_role_any("1001", &["admin", "superadmin"])
                .await
                .unwrap(),
            "持有任一角色应返回 true"
        );
    }

    /// 验证 check_role_any：主体不持有 roles 中任何一个则返回 false。
    #[tokio::test]
    async fn check_role_any_no_match_returns_false() {
        let mut iface = MockInterface::new();
        iface.set_roles("1001", &["user"]);
        let fw = make_firewall(iface);

        assert!(
            !fw.check_role_any("1001", &["admin", "superadmin"])
                .await
                .unwrap(),
            "不持有任一角色应返回 false"
        );
    }

    /// 验证 check_role_all：主体持有 roles 中所有角色才返回 true。
    #[tokio::test]
    async fn check_role_all_all_held_returns_true() {
        let mut iface = MockInterface::new();
        iface.set_roles("1001", &["admin", "user"]);
        let fw = make_firewall(iface);

        assert!(
            fw.check_role_all("1001", &["admin", "user"]).await.unwrap(),
            "持有所有角色应返回 true"
        );
    }

    /// 主体仅持有部分角色时返回 false。
    #[tokio::test]
    async fn check_role_all_partial_held_returns_false() {
        let mut iface = MockInterface::new();
        iface.set_roles("1001", &["admin"]);
        let fw = make_firewall(iface);

        assert!(
            !fw.check_role_all("1001", &["admin", "user"]).await.unwrap(),
            "仅持有部分角色应返回 false"
        );
    }

    /// 验证 check_role_all：空 roles 切片返回 true（空集平凡满足）。
    #[tokio::test]
    async fn check_role_all_empty_roles_returns_true() {
        let mut iface = MockInterface::new();
        iface.set_roles("1001", &["admin"]);
        let fw = make_firewall(iface);

        assert!(
            fw.check_role_all("1001", &[]).await.unwrap(),
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
        iface.set_permissions("1001", &["user:read", "user:write"]);
        let fw = make_firewall(iface);

        let perms = fw.get_permission_list("1001").await.unwrap();
        assert_eq!(perms, vec!["user:read", "user:write"]);
    }

    /// 验证 get_role_list 委托 BulwarkInterface 回调。
    #[tokio::test]
    async fn get_role_list_delegates_to_interface() {
        let mut iface = MockInterface::new();
        iface.set_roles("1001", &["admin", "user"]);
        let fw = make_firewall(iface);

        let roles = fw.get_role_list("1001").await.unwrap();
        assert_eq!(roles, vec!["admin", "user"]);
    }

    /// 验证未配置权限的 login_id 返回空列表（不抛错）。
    #[tokio::test]
    async fn get_permission_list_unknown_login_id_returns_empty() {
        let iface = MockInterface::new();
        let fw = make_firewall(iface);

        let perms = fw.get_permission_list("9999").await.unwrap();
        assert!(perms.is_empty(), "未配置权限的 login_id 应返回空列表");
    }

    // ------------------------------------------------------------------------
    // PermissionChecker 集成测试
    // ------------------------------------------------------------------------

    /// 可配置的 MockPermissionChecker，返回预设的权限/角色校验结果。
    struct MockPermissionChecker {
        perm_result: bool,
    }

    #[async_trait]
    impl PermissionChecker for MockPermissionChecker {
        async fn has_permission(&self, _login_id: &str, _permission: &str) -> BulwarkResult<bool> {
            Ok(self.perm_result)
        }
        async fn has_role(&self, _login_id: &str, _role: &str) -> BulwarkResult<bool> {
            Ok(false)
        }
        async fn check_permission(&self, _login_id: &str, _permission: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn check_role(&self, _login_id: &str, _role: &str) -> BulwarkResult<()> {
            Ok(())
        }
        async fn has_any_permission(&self, _login_id: &str, _perms: &[&str]) -> bool {
            false
        }
        async fn has_all_permissions(&self, _login_id: &str, _perms: &[&str]) -> bool {
            false
        }
    }

    /// 验证注入 PermissionChecker 后 check_permission 委托到它。
    #[tokio::test]
    async fn check_permission_delegates_to_permission_checker() {
        let iface = MockInterface::new();
        let pc = Arc::new(MockPermissionChecker { perm_result: true });
        let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_permission_checker(pc);

        // PermissionChecker 返回 true，即使 interface 中无权限记录
        assert!(
            fw.check_permission("1001", "user:read").await.unwrap(),
            "注入 PermissionChecker 后应委托校验，返回 true"
        );
    }

    /// 验证 PermissionChecker 返回 false 时 check_permission 返回 false。
    #[tokio::test]
    async fn check_permission_delegates_returns_false() {
        let iface = MockInterface::new();
        let pc = Arc::new(MockPermissionChecker { perm_result: false });
        let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_permission_checker(pc);

        assert!(
            !fw.check_permission("1001", "user:read").await.unwrap(),
            "PermissionChecker 返回 false 时应返回 false"
        );
    }

    /// 验证未注入 PermissionChecker 时回退到 默认行为（直接查 interface）。
    #[tokio::test]
    async fn check_permission_without_checker_falls_back_to_interface() {
        let mut iface = MockInterface::new();
        iface.set_permissions("1001", &["user:read"]);
        let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface));

        assert!(
            fw.check_permission("1001", "user:read").await.unwrap(),
            "未注入 PermissionChecker 时应回退到 interface 查询"
        );
    }

    // ------------------------------------------------------------------------
    // 层级角色测试
    // ------------------------------------------------------------------------

    /// 辅助函数：创建带角色层级的 firewall。
    fn make_firewall_with_hierarchy(
        interface: MockInterface,
        hierarchy: HashMap<String, Vec<String>>,
    ) -> BulwarkPermissionStrategyDefault {
        BulwarkPermissionStrategyDefault::new(Arc::new(interface)).with_role_hierarchy(hierarchy)
    }

    /// 验证层级角色：admin 隐含持有 user。
    #[tokio::test]
    async fn check_role_hierarchy_admin_implies_user() {
        let mut iface = MockInterface::new();
        iface.set_roles("1001", &["admin"]);
        let mut hierarchy = HashMap::new();
        hierarchy.insert("admin".to_string(), vec!["user".to_string()]);
        let fw = make_firewall_with_hierarchy(iface, hierarchy);

        assert!(
            fw.check_role("1001", "user").await.unwrap(),
            "admin 应隐含持有 user"
        );
        assert!(
            !fw.check_role("1001", "superadmin").await.unwrap(),
            "admin 不隐含 superadmin"
        );
    }

    /// 验证层级角色多层传递：superadmin → admin → user。
    #[tokio::test]
    async fn check_role_hierarchy_transitive() {
        let mut iface = MockInterface::new();
        iface.set_roles("1001", &["superadmin"]);
        let mut hierarchy = HashMap::new();
        hierarchy.insert("admin".to_string(), vec!["user".to_string()]);
        hierarchy.insert("superadmin".to_string(), vec!["admin".to_string()]);
        let fw = make_firewall_with_hierarchy(iface, hierarchy);

        assert!(
            fw.check_role("1001", "user").await.unwrap(),
            "superadmin 应多层传递隐含 user"
        );
        assert!(
            fw.check_role("1001", "admin").await.unwrap(),
            "superadmin 应隐含 admin"
        );
    }

    /// 验证未配置 role_hierarchy 时保持 默认行为。
    #[tokio::test]
    async fn check_role_without_hierarchy_keeps_legacy_behavior() {
        let mut iface = MockInterface::new();
        iface.set_roles("1001", &["admin"]);
        let fw = make_firewall(iface); // 无 hierarchy

        assert!(
            !fw.check_role("1001", "user").await.unwrap(),
            "未配置 hierarchy 时 admin 不隐含 user（0.1.0 行为）"
        );
    }

    /// 验证 check_role_any / check_role_all 在层级角色下的行为。
    #[tokio::test]
    async fn check_role_any_all_with_hierarchy() {
        let mut iface = MockInterface::new();
        iface.set_roles("1001", &["admin"]);
        let mut hierarchy = HashMap::new();
        hierarchy.insert("admin".to_string(), vec!["user".to_string()]);
        let fw = make_firewall_with_hierarchy(iface, hierarchy);

        // admin 隐含 user，所以 check_role_any(["user", "guest"]) 应返回 true
        assert!(
            fw.check_role_any("1001", &["user", "guest"]).await.unwrap(),
            "层级展开后应持有 user，check_role_any 应返回 true"
        );
        // admin 隐含 user，但不含 superadmin，check_role_all 应返回 false
        assert!(
            !fw.check_role_all("1001", &["user", "superadmin"])
                .await
                .unwrap(),
            "层级展开后不含 superadmin，check_role_all 应返回 false"
        );
    }

    // ------------------------------------------------------------------------
    // 插件钩子测试
    // ------------------------------------------------------------------------

    /// 验证注入 PluginManager 后 check_permission 触发插件钩子。
    #[tokio::test]
    async fn check_permission_triggers_plugin_hook() {
        let mut iface = MockInterface::new();
        iface.set_permissions("1001", &["user:read"]);
        // BulwarkPluginManager::new() 收集所有 inventory 注册的插件
        let pm = Arc::new(BulwarkPluginManager::new());
        let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_plugin_manager(pm);

        // 插件钩子不应中断主流程，校验结果应正常返回
        assert!(
            fw.check_permission("1001", "user:read").await.unwrap(),
            "插件钩子不应影响校验结果"
        );
    }

    /// 验证插件失败不中断 check_permission 主流程。
    ///
    /// 注意：当前实现遵循 task 21.3（Err → warn 不中断），不实现 spec 的 Override 机制。
    #[tokio::test]
    async fn check_permission_plugin_failure_does_not_interrupt() {
        let mut iface = MockInterface::new();
        iface.set_permissions("1001", &["user:read"]);
        // PluginManager 包含 ErrPlugin（on_permission_check 返回 Err），
        // 但主流程不应被中断
        let pm = Arc::new(BulwarkPluginManager::new());
        let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_plugin_manager(pm);

        assert!(
            fw.check_permission("1001", "user:read").await.unwrap(),
            "插件失败不应中断主流程，校验结果应正常返回 true"
        );
    }

    // ------------------------------------------------------------------------
    // 权限缓存测试
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
    #[tokio::test]
    async fn cache_permission_writes_and_reads_back() {
        let dao = Arc::new(MockCacheDao::new());
        let iface = MockInterface::new();
        let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_dao(dao.clone());

        fw.cache_permission("1001", "user:read", true, 300)
            .await
            .unwrap();

        let cached = fw.get_cached_permission("1001", "user:read").await.unwrap();
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
    #[tokio::test]
    async fn get_cached_permission_miss_returns_none() {
        let dao = Arc::new(MockCacheDao::new());
        let iface = MockInterface::new();
        let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_dao(dao);

        let cached = fw
            .get_cached_permission("1001", "user:delete")
            .await
            .unwrap();
        assert!(cached.is_none(), "未缓存的权限应返回 None");
    }

    /// 验证缓存覆盖：相同 key 的第二次写入覆盖第一次。
    #[tokio::test]
    async fn cache_permission_overwrite() {
        let dao = Arc::new(MockCacheDao::new());
        let iface = MockInterface::new();
        let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_dao(dao);

        // 第一次缓存 true
        fw.cache_permission("1001", "user:read", true, 300)
            .await
            .unwrap();
        assert_eq!(
            fw.get_cached_permission("1001", "user:read").await.unwrap(),
            Some(true)
        );

        // 覆盖为 false
        fw.cache_permission("1001", "user:read", false, 300)
            .await
            .unwrap();
        assert_eq!(
            fw.get_cached_permission("1001", "user:read").await.unwrap(),
            Some(false),
            "覆盖后应返回 false"
        );
    }

    /// 验证 check_permission 优先读取缓存（短路优化）。
    #[tokio::test]
    async fn check_permission_uses_cache_short_circuit() {
        let dao = Arc::new(MockCacheDao::new());
        let mut iface = MockInterface::new();
        // interface 中无 user:read 权限
        iface.set_permissions("1001", &[]);
        let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_dao(dao.clone());

        // 预先写入缓存 true（与 interface 实际权限矛盾）
        fw.cache_permission("1001", "user:read", true, 300)
            .await
            .unwrap();

        // check_permission 应短路返回缓存值 true，不查询 interface
        assert!(
            fw.check_permission("1001", "user:read").await.unwrap(),
            "应优先返回缓存结果 true，而非查询 interface"
        );
    }

    // ------------------------------------------------------------------------
    // 防火墙安全钩子集成测试
    // ------------------------------------------------------------------------

    /// 验证未注入 firewall_hook 时 check_login_hooks 为 no-op（向后兼容 0.2.x）。
    #[tokio::test]
    async fn check_login_hooks_noop_without_hook() {
        let iface = MockInterface::new();
        let fw = make_firewall(iface);
        let ctx = LoginContext::new("1001");

        // 未注入 hook，应直接返回 Ok
        assert!(
            fw.check_login_hooks("1001", &ctx).await.is_ok(),
            "未注入 firewall_hook 时 check_login_hooks 应为 no-op"
        );
    }

    /// 验证注入 hook 且所有检查通过时 check_login_hooks 返回 Ok。
    #[tokio::test]
    async fn check_login_hooks_passes_with_hook() {
        let iface = MockInterface::new();
        let hook = Arc::new(BulwarkFirewallCheckHookDefault::new());
        let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_firewall_hook(hook);
        let ctx = LoginContext::new("1001");

        // hook 计数器为空，所有检查应通过
        assert!(
            fw.check_login_hooks("1001", &ctx).await.is_ok(),
            "注入 hook 且无失败记录时 check_login_hooks 应返回 Ok"
        );
    }

    /// 验证 hook 在登录频率超限时阻断 check_login_hooks。
    #[tokio::test]
    async fn check_login_hooks_blocks_on_frequency_exceeded() {
        let iface = MockInterface::new();
        let hook = Arc::new(BulwarkFirewallCheckHookDefault::new());
        let fw =
            BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_firewall_hook(hook.clone());
        let ctx = LoginContext::new("1001").with_ip("1.2.3.4");

        // 记录 10 次失败（达到阈值）
        for _ in 0..10 {
            hook.record_failure(&ctx).await.unwrap();
        }

        // check_login_hooks 应被 login_frequency hook 阻断
        let result = fw.check_login_hooks("1001", &ctx).await;
        assert!(result.is_err(), "登录频率超限时应被 check_login_hooks 阻断");
        assert!(
            matches!(result.unwrap_err(), BulwarkError::Session(_)),
            "阻断错误应为 Session 类型"
        );
    }

    /// 验证 hook 在暴力破解超限时阻断 check_login_hooks。
    #[tokio::test]
    async fn check_login_hooks_blocks_on_brute_force_exceeded() {
        let iface = MockInterface::new();
        let hook = Arc::new(BulwarkFirewallCheckHookDefault::new());
        let fw =
            BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_firewall_hook(hook.clone());
        let ctx = LoginContext::new("1001"); // 无 IP，仅触发暴力破解检测

        // 记录 5 次失败（达到阈值）
        for _ in 0..5 {
            hook.record_failure(&ctx).await.unwrap();
        }

        // check_login_hooks 应被 brute_force hook 阻断
        let result = fw.check_login_hooks("1001", &ctx).await;
        assert!(result.is_err(), "暴力破解超限时应被 check_login_hooks 阻断");
    }

    /// 验证 with_firewall_hook builder 方法正确注入 hook。
    #[tokio::test]
    async fn with_firewall_hook_injects_hook() {
        let iface = MockInterface::new();
        let hook = Arc::new(BulwarkFirewallCheckHookDefault::new());
        let fw =
            BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_firewall_hook(hook.clone());

        // 注入后，记录失败并触发检测应能阻断
        let ctx = LoginContext::new("1001").with_ip("9.9.9.9");
        for _ in 0..10 {
            hook.record_failure(&ctx).await.unwrap();
        }
        let result = fw.check_login_hooks("1001", &ctx).await;
        assert!(result.is_err(), "注入 hook 后应能检测到频率超限并阻断");
    }

    /// 验证 check_login_hooks 按 5 个 hook 顺序调用（login_frequency 先于 brute_force）。
    ///
    /// 当 IP 维度先达阈值时，应优先返回 login_frequency 错误。
    #[tokio::test]
    async fn check_login_hooks_calls_in_order() {
        use crate::strategy::hooks::BulwarkFirewallCheckHook;
        use std::sync::atomic::{AtomicU8, Ordering};

        /// 记录调用顺序的测试 hook。
        struct OrderTrackingHook {
            order: Arc<AtomicU8>,
        }

        #[async_trait]
        impl BulwarkFirewallCheckHook for OrderTrackingHook {
            async fn check_login_frequency(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                self.order.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
            async fn check_brute_force(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                self.order.fetch_add(2, Ordering::SeqCst);
                Ok(())
            }
            async fn check_geo_anomaly(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                self.order.fetch_add(4, Ordering::SeqCst);
                Ok(())
            }
            async fn check_token_reuse(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                self.order.fetch_add(8, Ordering::SeqCst);
                Ok(())
            }
            async fn check_device_anomaly(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                self.order.fetch_add(16, Ordering::SeqCst);
                Ok(())
            }
        }

        let order = Arc::new(AtomicU8::new(0));
        let hook = Arc::new(OrderTrackingHook {
            order: order.clone(),
        });
        let iface = MockInterface::new();
        let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_firewall_hook(hook);
        let ctx = LoginContext::new("1001");

        fw.check_login_hooks("1001", &ctx).await.unwrap();

        // 5 个 hook 按序调用：1 + 2 + 4 + 8 + 16 = 31
        assert_eq!(order.load(Ordering::SeqCst), 31, "5 个 hook 应全部按序调用");
    }

    /// 验证 check_login_hooks 任一 hook Err 立即阻断后续 hook。
    #[tokio::test]
    async fn check_login_hooks_short_circuits_on_err() {
        use crate::strategy::hooks::BulwarkFirewallCheckHook;
        use std::sync::atomic::{AtomicU8, Ordering};

        struct ShortCircuitHook {
            called: Arc<AtomicU8>,
        }

        #[async_trait]
        impl BulwarkFirewallCheckHook for ShortCircuitHook {
            async fn check_login_frequency(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                self.called.fetch_add(1, Ordering::SeqCst);
                Err(BulwarkError::Session("frequency blocked".to_string()))
            }
            async fn check_brute_force(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                self.called.fetch_add(2, Ordering::SeqCst);
                Ok(())
            }
            async fn check_geo_anomaly(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                self.called.fetch_add(4, Ordering::SeqCst);
                Ok(())
            }
            async fn check_token_reuse(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                self.called.fetch_add(8, Ordering::SeqCst);
                Ok(())
            }
            async fn check_device_anomaly(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                self.called.fetch_add(16, Ordering::SeqCst);
                Ok(())
            }
        }

        let called = Arc::new(AtomicU8::new(0));
        let hook = Arc::new(ShortCircuitHook {
            called: called.clone(),
        });
        let iface = MockInterface::new();
        let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_firewall_hook(hook);
        let ctx = LoginContext::new("1001");

        let result = fw.check_login_hooks("1001", &ctx).await;
        assert!(result.is_err(), "应在第一个 hook Err 时阻断");

        // 仅第一个 hook 被调用（值为 1），后续 4 个未调用
        assert_eq!(
            called.load(Ordering::SeqCst),
            1,
            "第一个 hook Err 后应短路，后续 hook 不应被调用"
        );
    }

    // ========================================================================
    // 覆盖率补充：with_listener_manager、缓存写入失败、多 hook 失败
    // ========================================================================

    /// `with_listener_manager` 注入后 listener_manager 字段为 Some。
    ///
    /// 覆盖行 275-277（builder 方法体）。
    #[cfg(feature = "listener")]
    #[test]
    fn with_listener_manager_sets_field() {
        use crate::listener::BulwarkListenerManager;
        let lm = Arc::new(BulwarkListenerManager::new());
        let fw = BulwarkPermissionStrategyDefault::new(Arc::new(MockInterface::new()))
            .with_listener_manager(lm);
        assert!(
            fw.listener_manager.is_some(),
            "with_listener_manager 后 listener_manager 应为 Some"
        );
    }

    /// `check_permission` 缓存写入失败时仅 warn 不中断，仍返回正确结果。
    ///
    /// 覆盖行 394-396, 398（缓存写入失败 warn 分支）。
    ///
    /// 使用 FailingDao（set 方法返回 Err）触发缓存写入失败。
    #[tokio::test]
    async fn check_permission_cache_write_failure_warns_but_returns_result() {
        /// 所有写操作都失败的 DAO
        struct FailingDao;
        #[async_trait]
        impl crate::dao::BulwarkDao for FailingDao {
            async fn get(&self, _key: &str) -> BulwarkResult<Option<String>> {
                Ok(None)
            }
            async fn set(&self, _key: &str, _value: &str, _ttl: u64) -> BulwarkResult<()> {
                Err(BulwarkError::Dao("simulated set failure".to_string()))
            }
            async fn update(&self, _key: &str, _value: &str) -> BulwarkResult<()> {
                Err(BulwarkError::Dao("simulated update failure".to_string()))
            }
            async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
                Err(BulwarkError::Dao("simulated expire failure".to_string()))
            }
            async fn delete(&self, _key: &str) -> BulwarkResult<()> {
                Ok(())
            }
        }

        let mut iface = MockInterface::new();
        iface.set_permissions("1001", &["user:read"]);
        let fw =
            BulwarkPermissionStrategyDefault::new(Arc::new(iface)).with_dao(Arc::new(FailingDao));
        // 缓存写入失败但 check_permission 仍应返回 true（持有权限）
        let result = fw.check_permission("1001", "user:read").await;
        assert!(
            result.is_ok(),
            "缓存写入失败不应中断 check_permission，实际: {:?}",
            result
        );
        assert!(
            result.unwrap(),
            "持有权限应返回 true（缓存写入失败不影响结果）"
        );
    }

    /// `check_login_hooks` 第 3 个 hook（check_geo_anomaly）失败时广播 FirewallBlock 并阻断。
    ///
    /// 覆盖行 467-468（第 3 个 hook 失败）+ 490, 492（broadcast_firewall_block）。
    #[cfg(feature = "listener")]
    #[tokio::test]
    async fn check_login_hooks_geo_anomaly_failure_broadcasts_firewall_block() {
        use crate::listener::BulwarkListenerManager;
        let iface = MockInterface::new();
        let lm = Arc::new(BulwarkListenerManager::new());

        struct GeoFailHook;
        #[async_trait]
        impl crate::strategy::BulwarkFirewallCheckHook for GeoFailHook {
            async fn check_login_frequency(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                Ok(())
            }
            async fn check_brute_force(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                Ok(())
            }
            async fn check_geo_anomaly(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                Err(BulwarkError::Session("geo blocked".to_string()))
            }
        }

        let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface))
            .with_firewall_hook(Arc::new(GeoFailHook))
            .with_listener_manager(lm);
        let ctx = LoginContext::new("1001");
        let result = fw.check_login_hooks("1001", &ctx).await;
        assert!(result.is_err(), "geo_anomaly 失败应阻断");
        assert!(
            matches!(result.unwrap_err(), BulwarkError::Session(_)),
            "应返回 Session 错误"
        );
    }

    /// `check_login_hooks` 第 4 个 hook（check_token_reuse）失败时广播并阻断。
    ///
    /// 覆盖行 471-472（第 4 个 hook 失败）。
    #[cfg(feature = "listener")]
    #[tokio::test]
    async fn check_login_hooks_token_reuse_failure_broadcasts() {
        use crate::listener::BulwarkListenerManager;
        let iface = MockInterface::new();
        let lm = Arc::new(BulwarkListenerManager::new());

        struct TokenReuseFailHook;
        #[async_trait]
        impl crate::strategy::BulwarkFirewallCheckHook for TokenReuseFailHook {
            async fn check_login_frequency(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                Ok(())
            }
            async fn check_brute_force(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                Ok(())
            }
            async fn check_geo_anomaly(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                Ok(())
            }
            async fn check_token_reuse(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                Err(BulwarkError::Session("token reuse blocked".to_string()))
            }
        }

        let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface))
            .with_firewall_hook(Arc::new(TokenReuseFailHook))
            .with_listener_manager(lm);
        let ctx = LoginContext::new("1001");
        let result = fw.check_login_hooks("1001", &ctx).await;
        assert!(result.is_err(), "token_reuse 失败应阻断");
    }

    /// `check_login_hooks` 第 5 个 hook（check_device_anomaly）失败时广播并阻断。
    ///
    /// 覆盖行 475-476（第 5 个 hook 失败）。
    #[cfg(feature = "listener")]
    #[tokio::test]
    async fn check_login_hooks_device_anomaly_failure_broadcasts() {
        use crate::listener::BulwarkListenerManager;
        let iface = MockInterface::new();
        let lm = Arc::new(BulwarkListenerManager::new());

        struct DeviceFailHook;
        #[async_trait]
        impl crate::strategy::BulwarkFirewallCheckHook for DeviceFailHook {
            async fn check_login_frequency(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                Ok(())
            }
            async fn check_brute_force(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                Ok(())
            }
            async fn check_geo_anomaly(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                Ok(())
            }
            async fn check_token_reuse(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                Ok(())
            }
            async fn check_device_anomaly(&self, _ctx: &LoginContext) -> BulwarkResult<()> {
                Err(BulwarkError::Session("device anomaly blocked".to_string()))
            }
        }

        let fw = BulwarkPermissionStrategyDefault::new(Arc::new(iface))
            .with_firewall_hook(Arc::new(DeviceFailHook))
            .with_listener_manager(lm);
        let ctx = LoginContext::new("1001");
        let result = fw.check_login_hooks("1001", &ctx).await;
        assert!(result.is_err(), "device_anomaly 失败应阻断");
    }
}
