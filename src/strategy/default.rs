// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `GarrisonPermissionStrategyDefault` 的实现块：构造器、builder 方法、`GarrisonPermissionStrategy` trait 实现，
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

/// 判定缓存 TTL（秒）：权限/角色判定结果缓存窗口（既有 300s 语义保持不变）。
const DECISION_CACHE_TTL_SECS: u64 = 300;

/// 失效纪元键 TTL（秒）：仅约束存储垃圾的存活窗口（过期后下次判定回退哨兵纪元 `v0`），**不承担失效安全性**——
/// 纪元标签为每次失效随机生成的 UUID，旧纪元键与新纪元标签结构性不可能匹配（见 `invalidate_permission_cache` 文档）。
const DECISION_VERSION_KEY_TTL_SECS: u64 = 2 * DECISION_CACHE_TTL_SECS;

/// 权限判定缓存键前缀。
const PERM_CACHE_KEY_PREFIX: &str = "garrison:perm:cache:";

/// 角色判定缓存键前缀。
const ROLE_CACHE_KEY_PREFIX: &str = "garrison:role:cache:";

/// 失效版本号键前缀（权限/角色判定缓存共用一个 per-login 版本号）。
const DECISION_VERSION_KEY_PREFIX: &str = "garrison:decision:ver:";

/// 哨兵失效纪元：纪元键缺失（从未失效/已过期/未注入 DAO）时的判定键标签；纪元键 TTL ≥ 2× 判定 TTL，
/// 该窗口内写入的判定键在纪元键过期重开前必然已过判定 TTL，无复活窗口（见 `invalidate_permission_cache`）。
const SENTINEL_DECISION_EPOCH: &str = "0";

/// 缓存键分量歧义消除编码：`%` → `%25`、`:` → `%3A`，编码后分量**不含裸 `:`**，使
/// `garrison:perm:cache:v{ver}:{tenant}:{enc(login)}:{enc(perm)}` 可按 `:` 唯一反解为定长段（旧版裸拼接下
/// (login="a:b", perm="c") 与 (login="a", perm="b:c") 同键，可投毒）。新键第 4 段恒为 `v<数字>`（版本段），
/// 旧键该段为租户（纯数字或 `_`），二者不相交——旧版残留键不会被新读取路径命中。
fn encode_key_component(component: &str) -> String {
    component.replace('%', "%25").replace(':', "%3A")
}

impl GarrisonPermissionStrategyDefault {
    /// 创建默认实现实例（扩展字段均为 None/空，行为与基础构造一致）。
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

    /// 注入 `PermissionChecker`，启用委托校验：`check_permission` 将委托 `PermissionChecker::has_permission`，而非直接调用 `GarrisonInterface::get_permission_list`。
    pub fn with_permission_checker(mut self, pc: Arc<dyn PermissionChecker>) -> Self {
        self.permission_checker = Some(pc);
        self
    }

    /// 注入 `GarrisonDao`，启用权限缓存：`check_permission` 优先读缓存，未命中时查询并回填。
    pub fn with_dao(mut self, dao: Arc<dyn GarrisonDao>) -> Self {
        self.dao = Some(dao);
        self
    }

    /// 设置租户维度，启用权限缓存键租户隔离（不注入时租户段用占位符 `_`，所有租户共享缓存键）。
    ///
    /// 注入后不同租户相同 `login_id` 的判定结果互不污染，键分量经 `encode_key_component` 歧义消除编码。
    pub fn with_tenant_id(mut self, tenant_id: i64) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    /// 设置默认 `login_type`（多账号体系，接线 `_with_type` 回调，未设置时默认 `"default"`）。
    ///
    /// 注入后 `get_permission_list` / `get_role_list`（及其上的 `check_permission` / `check_role` 等校验）经
    /// `GarrisonInterface::get_*_list_with_type` 以该 `login_type` 查询数据，业务方覆写 `_with_type` 实现的多账号隔离真正生效。
    pub fn with_login_type(mut self, login_type: &str) -> Self {
        self.login_type = login_type.to_string();
        self
    }

    /// 构造判定缓存键（含失效纪元段与租户维度，分量经歧义消除编码）。
    ///
    /// 键格式 `{prefix}v{epoch}:{tenant}:{enc(login_id)}:{enc(component)}`：`epoch` 为当前失效纪元标签（UUID 或哨兵 `"0"`），
    /// `tenant_override` 用于请求级租户覆盖（`check_permission_in_tenant`），未配置租户时用占位符 `_`。
    fn decision_cache_key(
        &self,
        prefix: &str,
        tenant_override: Option<i64>,
        epoch: &str,
        login_id: &str,
        component: &str,
    ) -> String {
        let tenant = tenant_override
            .or(self.tenant_id)
            .map(|t| t.to_string())
            .unwrap_or_else(|| "_".to_string());
        format!(
            "{}v{}:{}:{}:{}",
            prefix,
            epoch,
            tenant,
            encode_key_component(login_id),
            encode_key_component(component)
        )
    }

    /// 失效版本号键：`garrison:decision:ver:{enc(login_id)}`；权限与角色判定缓存共用同一 per-login 版本号，
    /// 失效点递增/换标签后新旧两套判定键同时失活。
    fn decision_version_key(&self, login_id: &str) -> String {
        format!(
            "{}{}",
            DECISION_VERSION_KEY_PREFIX,
            encode_key_component(login_id)
        )
    }

    /// 读取当前失效纪元标签（未失效过/未注入 DAO/键已过期时回退哨兵 `"0"`）；纪元标签是每次失效随机生成的
    /// UUID（见 `invalidate_permission_cache`），无需解析为数字。
    async fn current_decision_epoch(&self, login_id: &str) -> GarrisonResult<String> {
        match self.dao.as_ref() {
            Some(dao) => {
                let key = self.decision_version_key(login_id);
                match dao.get(&key).await? {
                    Some(v) if !v.is_empty() => Ok(v),
                    // 空值视为键缺失（防御 DAO 异常写入），回退哨兵纪元
                    _ => Ok(SENTINEL_DECISION_EPOCH.to_string()),
                }
            },
            None => Ok(SENTINEL_DECISION_EPOCH.to_string()),
        }
    }

    /// 配置角色层级映射，如 `{"admin": ["user"], "superadmin": ["admin"]}`，表示 admin 隐含持有 user，superadmin 隐含持有 admin（多层传递）。
    pub fn with_role_hierarchy(mut self, hierarchy: HashMap<String, Vec<String>>) -> Self {
        self.role_hierarchy = hierarchy;
        self
    }

    /// 注入 `GarrisonPluginManager`，启用插件钩子：`check_permission` 在**权限判定前**调用一次
    /// `GarrisonPluginManager::on_permission_check`（缓存命中路径亦如此，无后置调用），插件返回 Err 仅 `tracing::warn!` 不中断主流程。
    pub fn with_plugin_manager(mut self, pm: Arc<GarrisonPluginManager>) -> Self {
        self.plugin_manager = Some(pm);
        self
    }

    /// 注入 `GarrisonFirewallCheckHook`，启用登录前防火墙安全检查：`check_login_hooks` 按序调用 5 个 hook
    /// （登录频率 / 暴力破解 / 异地登录 / Token 复用 / 设备异常），任一返回 `Err` 阻断登录。
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

    /// 注入 `GarrisonListenerManager`，启用 FirewallBlock 事件广播：`check_login_hooks` 任一 hook 返回 `Err` 时
    /// 广播 `GarrisonEvent::FirewallBlock`，未注入时为 no-op（告警组件可选）。需启用 `listener` feature。
    #[cfg(feature = "listener")]
    pub fn with_listener_manager(mut self, lm: Arc<GarrisonListenerManager>) -> Self {
        self.listener_manager = Some(lm);
        self
    }

    /// 展开角色列表（含层级隐含角色）：DFS 遍历 `role_hierarchy` 收集直接与间接角色，`role_hierarchy` 为空时即原列表集合。
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

    /// 缓存权限校验结果：写入 `GarrisonDao`，key 格式 `garrison:perm:cache:v{ver}:{tenant}:{enc(login_id)}:{enc(permission)}`；
    /// 未注入 DAO 时为 no-op，写入失败透传 `GarrisonError`。
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

    /// 写入权限缓存结果（带请求级租户覆盖）：`tenant_override` 为 `Some(t)` 时缓存键使用该租户（优先于 builder 配置），
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
            let epoch = self.current_decision_epoch(login_id).await?;
            let key = self.decision_cache_key(
                PERM_CACHE_KEY_PREFIX,
                tenant_override,
                &epoch,
                login_id,
                permission,
            );
            dao.set(&key, if result { "true" } else { "false" }, ttl_seconds)
                .await?;
        }
        Ok(())
    }

    /// 读取缓存的权限校验结果：未命中或未注入 DAO 时返回 `None`，读取失败透传 `GarrisonError`。
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
            let epoch = self.current_decision_epoch(login_id).await?;
            let key = self.decision_cache_key(
                PERM_CACHE_KEY_PREFIX,
                tenant_override,
                &epoch,
                login_id,
                permission,
            );
            match dao.get(&key).await? {
                Some(v) => Ok(Some(v == "true")),
                None => Ok(None),
            }
        } else {
            Ok(None)
        }
    }

    /// 失效某 `login_id` 的全部权限/角色判定缓存（**跨租户**）。
    ///
    /// 每次失效向 `garrison:decision:ver:{login_id}` 写入随机 UUID 标签（`dao.set` 同时刷新 TTL，
    /// InMemoryDao / oxcache 两后端一致，不依赖 feature-gated 的 `keys()` 枚举）；判定缓存键内嵌纪元段
    /// `…:cache:v{epoch}:{tenant}:…`，失效后旧纪元键全部不可达、随 TTL（300s）自然过期，影响该 `login_id` 的
    /// **全部租户段**权限与角色判定缓存（两套缓存共用同一纪元键），其他主体不受影响。
    ///
    /// 用随机标签而非自增计数：计数方案依赖「版本键不过期或过期前旧键已亡」的时序论证，纪元键过期后计数回零重走，
    /// 与上一纪元同值的旧键仍存活时即可被再次命中（陈旧 Allow 复活窗口）；随机 UUID 标签使新旧纪元结构性不相等、
    /// 与 TTL 时序无关，哨兵纪元 `"0"`（键缺失窗口）的重开间隔 ≥ 纪元键 TTL（600s）> 判定 TTL（300s），同样无复活窗口。
    pub async fn invalidate_permission_cache(&self, login_id: &str) -> GarrisonResult<()> {
        if let Some(dao) = &self.dao {
            let key = self.decision_version_key(login_id);
            let epoch = uuid::Uuid::new_v4().simple().to_string();
            dao.set(&key, &epoch, DECISION_VERSION_KEY_TTL_SECS).await?;
        }
        Ok(())
    }
}

#[async_trait]
impl GarrisonPermissionStrategy for GarrisonPermissionStrategyDefault {
    async fn invalidate_login_cache(&self, login_id: &str) -> GarrisonResult<()> {
        if let Err(e) = self.invalidate_permission_cache(login_id).await {
            // 失效失败：warn 降级，缓存 TTL 兜底，不阻断登出主流程
            tracing::warn!(
                login_id = login_id,
                error = %e,
                "permission cache invalidation failed on logout (cache TTL will expire)"
            );
        }
        Ok(())
    }

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
        // 改调 `_with_type` 变体传入策略配置的 login_type（默认 "default"）：接口默认实现委托非 typed 方法，覆写 `_with_type` 的多账号数据源自此生效。
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
        // 全局路径：缓存键用 builder 租户，数据源保持全局回调（含 login_type 接线）；租户感知数据源仅在 check_permission_in_tenant 生效。
        self.check_permission_scoped(self.tenant_id, None, login_id, permission)
            .await
    }

    async fn check_permission_in_tenant(
        &self,
        tenant_id: i64,
        login_id: &str,
        permission: &str,
    ) -> GarrisonResult<bool> {
        // 请求级租户覆盖缓存键与数据源（优先于 builder 配置），防止未配置 builder 租户时跨租户缓存污染；数据源作用域见 `check_permission_scoped`。
        self.check_permission_scoped(Some(tenant_id), Some(tenant_id), login_id, permission)
            .await
    }

    async fn check_role_in_tenant(
        &self,
        tenant_id: i64,
        login_id: &str,
        role: &str,
    ) -> GarrisonResult<bool> {
        // 租户维度真实参与判定：数据源优先走 GarrisonInterface::get_role_list_in_tenant
        //（默认委托全局方法，覆写的业务方获得租户作用域角色数据），缓存键含租户段（编码与失效版本号机制与权限判定一致）。
        self.check_role_scoped(tenant_id, login_id, role).await
    }

    async fn check_role(&self, login_id: &str, role: &str) -> GarrisonResult<bool> {
        if role.is_empty() {
            return Err(GarrisonError::InvalidParam(
                "strategy-role-empty::".to_string(),
            ));
        }
        let roles = self.get_role_list(login_id).await?;
        if !self.role_hierarchy.is_empty() {
            let expanded = self.expand_roles(&roles);
            Ok(expanded.contains(role))
        } else {
            Ok(roles.iter().any(|r| r == role))
        }
    }

    async fn check_role_any(&self, login_id: &str, roles: &[&str]) -> GarrisonResult<bool> {
        let user_roles = self.get_role_list(login_id).await?;
        if !self.role_hierarchy.is_empty() {
            let expanded = self.expand_roles(&user_roles);
            Ok(roles.iter().any(|r| expanded.contains(*r)))
        } else {
            Ok(roles.iter().any(|r| user_roles.iter().any(|ur| ur == r)))
        }
    }

    async fn check_role_all(&self, login_id: &str, roles: &[&str]) -> GarrisonResult<bool> {
        let user_roles = self.get_role_list(login_id).await?;
        if !self.role_hierarchy.is_empty() {
            let expanded = self.expand_roles(&user_roles);
            Ok(roles.iter().all(|r| expanded.contains(*r)))
        } else {
            Ok(roles.iter().all(|r| user_roles.iter().any(|ur| ur == r)))
        }
    }

    /// 登录前防火墙安全钩子检查：注入 `firewall_hook` 后按序调用 5 个 hook，任一 Err 阻断登录，未注入时为 no-op；
    /// 任一 hook 返回 Err 时，若注入了 `listener_manager`，广播 `GarrisonEvent::FirewallBlock`。
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
            // 回归护栏：firewall feature 启用却未注入 hook，说明 builder 自动装配被意外移除——输出 error! 避免"编译通过但防火墙静默失效"。
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
    /// `check_permission` 的共享实现：`cache_tenant` 决定缓存键租户维度（`None` 回退 builder 配置的 `self.tenant_id`），
    /// `data_tenant` 决定数据源租户维度——`Some(t)` 时权限数据经 `GarrisonInterface::get_permission_list_in_tenant(t, …)`
    /// 查询（租户感知回调，默认委托全局方法），`None` 时保持全局回调 `get_permission_list`（含 `login_type` 接线）；
    /// builder 静态租户属部署拓扑而非请求作用域，不切换数据源。
    async fn check_permission_scoped(
        &self,
        cache_tenant: Option<i64>,
        data_tenant: Option<i64>,
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

        // 优先读取权限缓存（键内嵌失效版本段，见 invalidate_permission_cache）
        if self.dao.is_some() {
            if let Ok(Some(cached)) = self
                .get_cached_permission_with(cache_tenant, login_id, permission)
                .await
            {
                return Ok(cached);
            }
        }

        // 委托 PermissionChecker（若注入），否则回退到默认行为；data_tenant = Some 时权限数据按请求级租户作用域查询（租户感知回调）。
        let result = if let Some(pc) = &self.permission_checker {
            match data_tenant {
                Some(t) => pc.has_permission_in_tenant(t, login_id, permission).await?,
                None => pc.has_permission(login_id, permission).await?,
            }
        } else {
            let permissions = match data_tenant {
                Some(t) => {
                    self.interface
                        .get_permission_list_in_tenant(t, login_id)
                        .await?
                },
                None => self.get_permission_list(login_id).await?,
            };
            permissions.iter().any(|p| p == permission)
        };

        // 写入缓存（失败仅 warn 不中断）
        if let Some(_dao) = &self.dao {
            if let Err(e) = self
                .cache_permission_with(
                    cache_tenant,
                    login_id,
                    permission,
                    result,
                    DECISION_CACHE_TTL_SECS,
                )
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

    /// `check_role_in_tenant` 的共享实现：数据源经 `GarrisonInterface::get_role_list_in_tenant(tenant_id, …)`
    ///（默认委托全局方法，覆写的业务方获得租户隔离）；判定结果按 `garrison:role:cache:v{ver}:{tenant}:…` 缓存，
    /// 版本段与权限判定缓存共用（`invalidate_login_cache` 一次失效两套）。
    async fn check_role_scoped(
        &self,
        tenant_id: i64,
        login_id: &str,
        role: &str,
    ) -> GarrisonResult<bool> {
        if role.is_empty() {
            return Err(GarrisonError::InvalidParam(
                "strategy-role-empty::".to_string(),
            ));
        }

        // 失效纪元段与权限判定缓存共用（invalidate_login_cache 一次失效两套）；纪元读取失败跳过缓存读写回源，与权限路径的错误降级一致。
        let cached_epoch = match self.dao.as_ref() {
            Some(_) => self.current_decision_epoch(login_id).await.ok(),
            None => None,
        };

        if let (Some(dao), Some(epoch)) = (&self.dao, cached_epoch.clone()) {
            let key = self.decision_cache_key(
                ROLE_CACHE_KEY_PREFIX,
                Some(tenant_id),
                &epoch,
                login_id,
                role,
            );
            if let Ok(Some(cached)) = dao.get(&key).await {
                return Ok(cached == "true");
            }
        }

        // 回源：租户感知角色数据源（含 role_hierarchy 语义与 check_role 对齐）
        let roles = self
            .interface
            .get_role_list_in_tenant(tenant_id, login_id)
            .await?;
        let result = if !self.role_hierarchy.is_empty() {
            let expanded = self.expand_roles(&roles);
            expanded.contains(role)
        } else {
            roles.iter().any(|r| r == role)
        };

        // 写入缓存（失败仅 warn 不中断，与权限判定缓存一致）
        if let (Some(dao), Some(epoch)) = (&self.dao, cached_epoch) {
            let key = self.decision_cache_key(
                ROLE_CACHE_KEY_PREFIX,
                Some(tenant_id),
                &epoch,
                login_id,
                role,
            );
            if let Err(e) = dao
                .set(
                    &key,
                    if result { "true" } else { "false" },
                    DECISION_CACHE_TTL_SECS,
                )
                .await
            {
                tracing::warn!(
                    "role cache write failed (login_id={}, role={}): {}",
                    login_id,
                    role,
                    e
                );
            }
        }

        Ok(result)
    }

    /// 广播 FirewallBlock 事件：仅在注入 `listener_manager` 且启用 `listener` feature 时广播，否则为 no-op。
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
