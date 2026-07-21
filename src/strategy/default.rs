//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `GarrisonPermissionStrategyDefault` 的实现块。
//!
//! 从 `mod.rs` 迁移而出（规则 25：mod.rs 接口隔离）。
//! 本模块持有构造器、builder 方法、`GarrisonPermissionStrategy` trait 实现，
//! 以及 `broadcast_firewall_block` 事件广播 helper。

use crate::core::permission::PermissionChecker;
use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
// GarrisonEvent 仅在 listener + firewall/oauth2 同时启用时需要（broadcast_firewall_block 内部使用）
#[cfg(all(
    feature = "listener",
    any(
        feature = "sms-rate-limit",
        feature = "firewall-ratelimit",
        feature = "firewall-bruteforce",
        feature = "firewall-ddos",
        feature = "firewall",
        feature = "oauth2-server"
    )
))]
use crate::listener::GarrisonEvent;
#[cfg(feature = "listener")]
use crate::listener::GarrisonListenerManager;
use crate::plugin::GarrisonPluginManager;
use crate::stp::GarrisonInterface;
#[cfg(any(
    feature = "sms-rate-limit",
    feature = "firewall-ratelimit",
    feature = "firewall-bruteforce",
    feature = "firewall-ddos",
    feature = "firewall",
    feature = "oauth2-server"
))]
use crate::strategy::hooks::{GarrisonFirewallCheckHook, LoginContext};
use async_trait::async_trait;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use super::{GarrisonPermissionStrategy, GarrisonPermissionStrategyDefault};

impl GarrisonPermissionStrategyDefault {
    /// 创建默认实现实例。
    ///
    /// # 参数
    /// - `interface`: 权限/角色数据回调（业务方实现）。
    ///
    /// # 返回
    /// 新建的 `GarrisonPermissionStrategyDefault` 实例（0.2.0 扩展字段均为 None/空，
    /// 行为与 0.1.0 完全一致）。
    pub fn new(interface: Arc<dyn GarrisonInterface>) -> Self {
        Self {
            interface,
            permission_checker: None,
            dao: None,
            role_hierarchy: HashMap::new(),
            plugin_manager: None,
            #[cfg(any(
                feature = "sms-rate-limit",
                feature = "firewall-ratelimit",
                feature = "firewall-bruteforce",
                feature = "firewall-ddos",
                feature = "firewall",
                feature = "oauth2-server"
            ))]
            firewall_hook: None,
            #[cfg(feature = "listener")]
            listener_manager: None,
        }
    }

    /// 注入 `PermissionChecker`，启用委托校验。
    ///
    /// 注入后 `check_permission` 将委托 `PermissionChecker::has_permission`，
    /// 而非直接调用 `GarrisonInterface::get_permission_list`。
    pub fn with_permission_checker(mut self, pc: Arc<dyn PermissionChecker>) -> Self {
        self.permission_checker = Some(pc);
        self
    }

    /// 注入 `GarrisonDao`，启用权限缓存。
    ///
    /// 注入后 `check_permission` 会优先读取缓存，未命中时查询并回填。
    pub fn with_dao(mut self, dao: Arc<dyn GarrisonDao>) -> Self {
        self.dao = Some(dao);
        self
    }

    /// 配置角色层级映射。
    ///
    /// # 参数
    /// - `hierarchy`: 角色层级映射，如 `{"admin": ["user"], "superadmin": ["admin"]}`，
    ///   表示 admin 隐含持有 user，superadmin 隐含持有 admin（多层传递）。
    pub fn with_role_hierarchy(mut self, hierarchy: HashMap<String, Vec<String>>) -> Self {
        self.role_hierarchy = hierarchy;
        self
    }

    /// 注入 `GarrisonPluginManager`，启用插件钩子。
    ///
    /// 注入后 `check_permission` 前后调用 `GarrisonPluginManager::on_permission_check`，
    /// 插件返回 Err 仅 `tracing::warn!` 不中断主流程。
    pub fn with_plugin_manager(mut self, pm: Arc<GarrisonPluginManager>) -> Self {
        self.plugin_manager = Some(pm);
        self
    }

    /// 注入 `GarrisonFirewallCheckHook`，启用登录前防火墙安全检查。
    ///
    /// 注入后 `check_login_hooks` 将按序调用 5 个 hook（登录频率 / 暴力破解 /
    /// 异地登录 / Token 复用 / 设备异常），任一返回 `Err` 阻断登录。
    #[cfg(any(
        feature = "sms-rate-limit",
        feature = "firewall-ratelimit",
        feature = "firewall-bruteforce",
        feature = "firewall-ddos",
        feature = "firewall",
        feature = "oauth2-server"
    ))]
    pub fn with_firewall_hook(mut self, hook: Arc<dyn GarrisonFirewallCheckHook>) -> Self {
        self.firewall_hook = Some(hook);
        self
    }

    /// 注入 `GarrisonListenerManager`，启用 FirewallBlock 事件广播
    ///
    ///
    /// 注入后 `check_login_hooks` 任一 hook 返回 `Err` 时广播 `GarrisonEvent::FirewallBlock`。
    /// 未注入时为 no-op（向后兼容 0.4.1）。需启用 `listener` feature。
    #[cfg(feature = "listener")]
    pub fn with_listener_manager(mut self, lm: Arc<GarrisonListenerManager>) -> Self {
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
    /// 将校验结果写入 `GarrisonDao`，key 格式 `garrison:perm:cache:<login_id>:<permission>`。
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
    /// - DAO 写入失败：透传 `GarrisonError`。
    pub async fn cache_permission(
        &self,
        login_id: &str,
        permission: &str,
        result: bool,
        ttl_seconds: u64,
    ) -> GarrisonResult<()> {
        if let Some(dao) = &self.dao {
            let key = format!("garrison:perm:cache:{}:{}", login_id, permission);
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
    /// - DAO 读取失败：透传 `GarrisonError`。
    pub async fn get_cached_permission(
        &self,
        login_id: &str,
        permission: &str,
    ) -> GarrisonResult<Option<bool>> {
        if let Some(dao) = &self.dao {
            let key = format!("garrison:perm:cache:{}:{}", login_id, permission);
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
impl GarrisonPermissionStrategy for GarrisonPermissionStrategyDefault {
    async fn get_permission_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        self.interface.get_permission_list(login_id).await
    }

    async fn get_role_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        self.interface.get_role_list(login_id).await
    }

    async fn check_permission(&self, login_id: &str, permission: &str) -> GarrisonResult<bool> {
        // spec scenario "权限为空字符串"：空字符串抛 InvalidParam
        if permission.is_empty() {
            return Err(GarrisonError::InvalidParam(
                "strategy-perm-empty".to_string(),
            ));
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

    async fn check_role(&self, login_id: &str, role: &str) -> GarrisonResult<bool> {
        if role.is_empty() {
            return Err(GarrisonError::InvalidParam(
                "strategy-role-empty".to_string(),
            ));
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

    async fn check_role_any(&self, login_id: &str, roles: &[&str]) -> GarrisonResult<bool> {
        let user_roles = self.get_role_list(login_id).await?;
        // 层级角色展开
        if !self.role_hierarchy.is_empty() {
            let expanded = self.expand_roles(&user_roles);
            Ok(roles.iter().any(|r| expanded.contains(*r)))
        } else {
            Ok(roles.iter().any(|r| user_roles.iter().any(|ur| ur == r)))
        }
    }

    async fn check_role_all(&self, login_id: &str, roles: &[&str]) -> GarrisonResult<bool> {
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
    /// 广播 `GarrisonEvent::FirewallBlock` 事件。
    #[cfg(any(
        feature = "sms-rate-limit",
        feature = "firewall-ratelimit",
        feature = "firewall-bruteforce",
        feature = "firewall-ddos",
        feature = "firewall",
        feature = "oauth2-server"
    ))]
    async fn check_login_hooks(&self, login_id: &str, ctx: &LoginContext) -> GarrisonResult<()> {
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

impl GarrisonPermissionStrategyDefault {
    /// 广播 FirewallBlock 事件。
    ///
    /// 仅在注入 `listener_manager` 且启用 `listener` feature 时广播，否则为 no-op。
    ///
    /// v0.5.0 改为 async：broadcast 改为 async 后此 helper 也需 async。
    #[cfg(any(
        feature = "sms-rate-limit",
        feature = "firewall-ratelimit",
        feature = "firewall-bruteforce",
        feature = "firewall-ddos",
        feature = "firewall",
        feature = "oauth2-server"
    ))]
    #[cfg_attr(not(feature = "listener"), allow(unused_variables))]
    async fn broadcast_firewall_block(&self, login_id: &str, e: &GarrisonError) {
        #[cfg(feature = "listener")]
        if let Some(lm) = &self.listener_manager {
            lm.broadcast(&GarrisonEvent::FirewallBlock {
                login_id: login_id.to_string(),
                reason: e.to_string(),
                request_context: None,
            })
            .await;
        }
    }
}
