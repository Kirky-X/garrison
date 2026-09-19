// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `GarrisonPermissionStrategyDefault` 的实现块。
//!
//! 从 `mod.rs` 迁移而出（mod.rs 接口隔离）。
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
    /// 新建的 `GarrisonPermissionStrategyDefault` 实例（扩展字段均为 None/空，
    /// 行为与基础构造一致）。
    pub fn new(interface: Arc<dyn GarrisonInterface>) -> Self {
        Self {
            interface,
            permission_checker: None,
            dao: None,
            tenant_id: None,
            login_type: "default".to_string(),
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

    /// 设置租户维度，启用权限缓存键租户隔离。
    ///
    /// 注入后权限缓存键形如 `garrison:perm:cache:<tenant_id>:<login_id>:<permission>`，
    /// 不同租户相同 `login_id` 的权限判定结果互不污染。
    /// 不注入（`None`）时缓存键使用占位符 `_`（未配置租户隔离，所有租户共享缓存键）。
    pub fn with_tenant_id(mut self, tenant_id: i64) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    /// 设置默认 `login_type`（多账号体系，接线 `_with_type` 回调）。
    ///
    /// 注入后 `get_permission_list` / `get_role_list`（及其上的
    /// `check_permission` / `check_role` 等校验）经
    /// `GarrisonInterface::get_*_list_with_type` 以该 `login_type` 查询数据，
    /// 业务方覆写 `_with_type` 实现的多账号隔离真正生效。
    /// 未设置时默认 `"default"`（与 `GarrisonLogicDefault::with_login_type` 默认值一致）。
    pub fn with_login_type(mut self, login_type: &str) -> Self {
        self.login_type = login_type.to_string();
        self
    }

    /// 构造权限缓存键（含租户维度）。
    ///
    /// `tenant_override` 用于请求级租户覆盖（`check_permission_in_tenant`），
    /// 避免未配置 builder 租户时回退路径的跨租户缓存污染。
    fn perm_cache_key_with(
        &self,
        tenant_override: Option<i64>,
        login_id: &str,
        permission: &str,
    ) -> String {
        let tenant = tenant_override
            .or(self.tenant_id)
            .map(|t| t.to_string())
            .unwrap_or_else(|| "_".to_string());
        format!("garrison:perm:cache:{}:{}:{}", tenant, login_id, permission)
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
    /// 注入后 `check_permission` 在**权限判定前**调用一次
    /// `GarrisonPluginManager::on_permission_check`（缓存命中路径亦如此，
    /// 无后置调用——与实现一致），
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
    /// 未注入时广播为 no-op（告警组件可选）。需启用 `listener` feature。
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
    /// 将校验结果写入 `GarrisonDao`，key 格式 `garrison:perm:cache:<tenant_id>:<login_id>:<permission>`。
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
        self.cache_permission_with(None, login_id, permission, result, ttl_seconds)
            .await
    }

    /// 写入权限缓存结果（带请求级租户覆盖）。
    ///
    /// `tenant_override` 为 `Some(t)` 时缓存键使用该租户（优先于 builder 配置），
    /// 供 `check_permission_in_tenant` 回退路径隔离不同租户的判定结果。
    pub async fn cache_permission_with(
        &self,
        tenant_override: Option<i64>,
        login_id: &str,
        permission: &str,
        result: bool,
        ttl_seconds: u64,
    ) -> GarrisonResult<()> {
        if let Some(dao) = &self.dao {
            let key = self.perm_cache_key_with(tenant_override, login_id, permission);
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
        self.get_cached_permission_with(None, login_id, permission)
            .await
    }

    /// 读取缓存的权限校验结果（带请求级租户覆盖）。
    pub async fn get_cached_permission_with(
        &self,
        tenant_override: Option<i64>,
        login_id: &str,
        permission: &str,
    ) -> GarrisonResult<Option<bool>> {
        if let Some(dao) = &self.dao {
            let key = self.perm_cache_key_with(tenant_override, login_id, permission);
            match dao.get(&key).await? {
                Some(v) => Ok(Some(v == "true")),
                None => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    /// 失效某 `login_id` 的全部权限缓存。
    ///
    /// 扫描 `garrison:perm:cache:<tenant>:<login_id>:*` 模式并逐一删除，
    /// 使权限回收 / 角色变更后下一次 `check_permission` 立即回源查询业务接口，
    /// 而非等待 300 秒 TTL 自然过期。
    ///
    /// 建议在 logout 流程与角色 / 权限变更监听器中调用本方法。
    /// 未注入 DAO 时不写缓存，本方法直接返回 `Ok(())`。
    pub async fn invalidate_permission_cache(&self, login_id: &str) -> GarrisonResult<()> {
        if let Some(dao) = &self.dao {
            let tenant = self
                .tenant_id
                .map(|t| t.to_string())
                .unwrap_or_else(|| "_".to_string());
            let pattern = format!("garrison:perm:cache:{}:{}:*", tenant, login_id);
            let keys = dao.keys(&pattern).await?;
            for k in keys {
                dao.delete(&k).await?;
            }
        }
        Ok(())
    }
}

#[async_trait]
impl GarrisonPermissionStrategy for GarrisonPermissionStrategyDefault {
    fn firewall_hook_injected(&self) -> bool {
        #[cfg(any(
            feature = "sms-rate-limit",
            feature = "firewall-ratelimit",
            feature = "firewall-bruteforce",
            feature = "firewall-ddos",
            feature = "firewall",
            feature = "oauth2-server"
        ))]
        {
            self.firewall_hook.is_some()
        }
        #[cfg(not(any(
            feature = "sms-rate-limit",
            feature = "firewall-ratelimit",
            feature = "firewall-bruteforce",
            feature = "firewall-ddos",
            feature = "firewall",
            feature = "oauth2-server"
        )))]
        {
            false
        }
    }

    async fn get_permission_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        // 接线：改调 `_with_type` 变体传入策略配置的
        // login_type（默认 "default"）。接口默认实现委托非 typed 方法，
        // 现有实现者行为不变；覆写了 `_with_type` 的多账号数据源自此生效。
        self.interface
            .get_permission_list_with_type(login_id, &self.login_type)
            .await
    }

    async fn get_role_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        // 接线：同 get_permission_list，传入 login_type。
        self.interface
            .get_role_list_with_type(login_id, &self.login_type)
            .await
    }

    async fn check_permission(&self, login_id: &str, permission: &str) -> GarrisonResult<bool> {
        self.check_permission_scoped(self.tenant_id, login_id, permission)
            .await
    }

    async fn check_permission_in_tenant(
        &self,
        tenant_id: i64,
        login_id: &str,
        permission: &str,
    ) -> GarrisonResult<bool> {
        // 请求级租户覆盖缓存键维度：firewall 回退路径传入的租户
        // 优先于 builder 配置，防止未配置 builder 租户时跨租户缓存污染。
        self.check_permission_scoped(Some(tenant_id), login_id, permission)
            .await
    }

    async fn check_role_in_tenant(
        &self,
        _tenant_id: i64,
        login_id: &str,
        role: &str,
    ) -> GarrisonResult<bool> {
        // 本策略的角色数据源（GarrisonInterface 回调）无租户维度：角色列表全局共享，
        // 请求级租户不参与角色判定。租户隔离的角色数据源请自定义实现本方法。
        self.check_role(login_id, role).await
    }

    async fn check_role(&self, login_id: &str, role: &str) -> GarrisonResult<bool> {
        if role.is_empty() {
            return Err(GarrisonError::InvalidParam(
                "strategy-role-empty::".to_string(),
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
    /// 未注入时为 no-op（纯权限校验场景）。
    ///
    /// 任一 hook 返回 Err 时，若注入了 `listener_manager`，
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
            // 回归护栏：firewall feature 启用却未注入 hook，说明 builder
            // 自动装配被意外移除——输出 error! 避免"编译通过但防火墙静默失效"。
            #[cfg(feature = "firewall")]
            tracing::error!(
                "firewall feature enabled but GarrisonFirewallCheckHook not injected \
                 (builder auto-wire may be broken)"
            );
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
    /// `check_permission` 的共享实现（缓存键租户维度可由请求级租户覆盖）。
    ///
    /// `cache_tenant` 为 `Some(t)` 时权限缓存键使用该租户（`check_permission_in_tenant`
    /// 传入的请求级租户），否则回退 builder 配置的 `self.tenant_id`。
    async fn check_permission_scoped(
        &self,
        cache_tenant: Option<i64>,
        login_id: &str,
        permission: &str,
    ) -> GarrisonResult<bool> {
        // 权限为空字符串时抛 InvalidParam
        if permission.is_empty() {
            return Err(GarrisonError::InvalidParam(
                "strategy-perm-empty::".to_string(),
            ));
        }

        // 插件钩子（before）— 内部已处理 Err 仅 warn 不中断
        if let Some(pm) = &self.plugin_manager {
            pm.on_permission_check(login_id, permission);
        }

        // 优先读取权限缓存
        if self.dao.is_some() {
            if let Ok(Some(cached)) = self
                .get_cached_permission_with(cache_tenant, login_id, permission)
                .await
            {
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
                .cache_permission_with(cache_tenant, login_id, permission, result, 300)
                .await
            {
                tracing::warn!(
                    "permission cache write failed (login_id={}, perm={}): {}",
                    login_id,
                    permission,
                    e
                );
            }
        }

        Ok(result)
    }

    /// 广播 FirewallBlock 事件。
    ///
    /// 仅在注入 `listener_manager` 且启用 `listener` feature 时广播，否则为 no-op。
    ///
    /// broadcast 为 async，此 helper 也需 async。
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
