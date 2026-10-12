// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 策略模块，提供鉴权策略与可插拔权限策略。
//!
//! `GarrisonPermissionStrategy` trait 定义权限/角色校验的可插拔契约；默认实现 `GarrisonPermissionStrategyDefault`
//! 持有 `GarrisonInterface` 回调获取权限/角色数据，做字符串匹配校验（权限数据不委托 dbnexus `PermissionProvider` trait，其 API 模型与 Garrison 不匹配）。

use crate::core::permission::PermissionChecker;
use crate::dao::GarrisonDao;
use crate::error::GarrisonResult;
// listener_manager 字段类型（feature-gated）
#[cfg(feature = "listener")]
use crate::listener::GarrisonListenerManager;
use crate::plugin::GarrisonPluginManager;
use crate::stp::GarrisonInterface;
// hooks 依赖 limiteron，cfg 门控与 lib.rs 的 limiteron 一致；类型用于 struct 字段与签名
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
use std::collections::HashMap;
use std::sync::Arc;

/// 安全告警系统模块（feature-gated: `security-alert`）。
#[cfg(feature = "security-extra")]
pub mod alert;
/// 设备绑定策略模块（feature-gated: `device-binding`，依赖 `security-alert`）。
#[cfg(feature = "device-binding")]
pub mod device_binding;
/// IP 级防火墙策略套件模块。
#[cfg(feature = "firewall")]
pub mod firewall;
/// 防火墙安全钩子模块（feature-gated：依赖 limiteron，匹配 lib.rs 的 limiteron cfg）。
#[cfg(any(
    feature = "sms-rate-limit",
    feature = "firewall-ratelimit",
    feature = "firewall-bruteforce",
    feature = "firewall-ddos",
    feature = "firewall",
    feature = "oauth2-server"
))]
pub mod hooks;
/// 限流后端配置 enum 模块（trait 始终可用，无 feature gate）。
pub mod rate_limiter_backend;
/// 策略注册表模块。
pub mod registry;

/// `GarrisonPermissionStrategyDefault` 的实现块。
mod default;

// Re-export 核心 trait 与类型以便外部使用
#[cfg(any(
    feature = "sms-rate-limit",
    feature = "firewall-ratelimit",
    feature = "firewall-bruteforce",
    feature = "firewall-ddos",
    feature = "firewall",
    feature = "oauth2-server"
))]
pub use hooks::{
    GarrisonFirewallCheckHookDefault, LoginContext as FirewallLoginContext, BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW, LOGIN_FREQUENCY_THRESHOLD, LOGIN_FREQUENCY_WINDOW,
};
// Re-export 策略注册表 trait 与默认实现（FirewallStrategy 与 GarrisonPermissionStrategy 名称不同，可共存）
pub use registry::{
    DefaultFirewallStrategy, DefaultLoginHandler, DefaultLogoutHandler, DefaultPermissionHandler,
    DefaultSessionCreator, DefaultTokenGenerator, FirewallStrategy, LoginHandler, LogoutHandler,
    PermissionHandler, SessionCreator, Strategy, TokenGenerator,
};

/// 权限策略 trait，定义权限/角色校验的可插拔契约。
///
/// 业务方可通过实现此 trait 替换默认的权限校验逻辑；默认实现
/// `GarrisonPermissionStrategyDefault` 经 `GarrisonInterface` 回调获取数据后做字符串匹配。
#[async_trait]
pub trait GarrisonPermissionStrategy: Send + Sync {
    /// 按主体失效权限判定缓存（登出/踢出联动调用；默认 no-op）。
    ///
    /// `DefaultPermissionStrategy` 覆写为递增该主体的失效版本号键，版本递增后**全部租户段**的旧 Allow 立即不可达
    /// （不依赖 `keys()` 枚举），旧键随缓存 TTL（当前 300s）自然过期；权限/角色**变更**点（不经过登出）仍需业务方
    /// 显式调用 `DefaultPermissionStrategy::invalidate_permission_cache`，未覆写时旧 Allow 最长存续一个缓存 TTL。
    async fn invalidate_login_cache(&self, _login_id: &str) -> GarrisonResult<()> {
        Ok(())
    }

    /// 获取主体的权限列表；数据回调失败时透传 `GarrisonError`。
    async fn get_permission_list(&self, login_id: &str) -> GarrisonResult<Vec<String>>;

    /// 获取主体的角色列表；数据回调失败时透传 `GarrisonError`。
    async fn get_role_list(&self, login_id: &str) -> GarrisonResult<Vec<String>>;

    /// 校验权限：检查主体是否持有指定权限；查询失败或权限字符串为空时返回 `Err`。
    async fn check_permission(&self, login_id: &str, permission: &str) -> GarrisonResult<bool>;

    /// 校验权限（带租户维度）：stp 层 firewall 回退路径经此方法传入请求级 `tenant_id`。
    ///
    /// 实现方**必须**将 `tenant_id` 纳入权限判定或缓存键；数据源与租户无关的策略应显式说明
    /// （而非静默丢弃参数，`tenant_id=0` 表示单租户/未隔离）。
    async fn check_permission_in_tenant(
        &self,
        tenant_id: i64,
        login_id: &str,
        permission: &str,
    ) -> GarrisonResult<bool>;

    /// 校验角色：检查主体是否持有指定角色；数据回调失败时透传 `GarrisonError`。
    async fn check_role(&self, login_id: &str, role: &str) -> GarrisonResult<bool>;

    /// 校验角色（带租户维度）：stp 层 firewall 回退路径经此方法传入请求级 `tenant_id`。
    ///
    /// 实现方**必须**将 `tenant_id` 纳入角色判定；默认实现经
    /// [`GarrisonInterface::get_role_list_in_tenant`] 查询（默认委托全局方法），缓存键纳入租户段；
    /// 数据源与租户无关的实现应显式说明（而非静默丢弃参数，`tenant_id=0` 表示单租户/未隔离）。
    async fn check_role_in_tenant(
        &self,
        tenant_id: i64,
        login_id: &str,
        role: &str,
    ) -> GarrisonResult<bool>;

    /// 校验角色（任一匹配）：主体持有 `roles` 中任意一个即通过。
    async fn check_role_any(&self, login_id: &str, roles: &[&str]) -> GarrisonResult<bool>;

    /// 校验角色（全部匹配）：主体需持有 `roles` 中所有角色（空列表平凡满足）。
    async fn check_role_all(&self, login_id: &str, roles: &[&str]) -> GarrisonResult<bool>;

    /// 获取用户基本信息（用于缓存），默认返回 `Ok(None)`，业务方可覆盖此方法。
    ///
    /// 启用 `three-tier-cache` feature 后，`UserCacheService` 通过此方法获取用户信息并缓存。
    ///
    /// # 安全警告
    ///
    /// 返回值会缓存到 L1（内存）和 L2（DAO），**不要**包含敏感信息（密码哈希、salt、
    /// session token 等），建议仅返回展示用信息（用户名、昵称、头像 URL 等）。
    async fn get_user_info(&self, _login_id: &str) -> GarrisonResult<Option<String>> {
        Ok(None)
    }

    /// 登录前防火墙安全钩子检查（IP / 设备指纹 / 地理位置经 `ctx` 传入）。
    ///
    /// 必须实现：注入防火墙 hook 的策略（如 `GarrisonPermissionStrategyDefault`）按序调用
    /// 5 个 hook，任一 Err 阻断登录；纯权限校验用途的策略可显式实现为 no-op。
    #[cfg(any(
        feature = "sms-rate-limit",
        feature = "firewall-ratelimit",
        feature = "firewall-bruteforce",
        feature = "firewall-ddos",
        feature = "firewall",
        feature = "oauth2-server"
    ))]
    async fn check_login_hooks(&self, login_id: &str, ctx: &LoginContext) -> GarrisonResult<()>;

    /// 诊断：防火墙 hook 是否已注入（用于 builder 自动装配自检）。
    ///
    /// 默认实现返回 `false`；`GarrisonPermissionStrategyDefault` 在注入
    /// `GarrisonFirewallCheckHook` 后返回 `true`。
    fn firewall_hook_injected(&self) -> bool {
        false
    }
}

/// `GarrisonPermissionStrategy` 的默认实现，持有 `GarrisonInterface` 回调获取权限/角色数据。
///
/// 框架不假定权限/角色数据来源（数据库 / YAML / 内存等），由业务方实现 `GarrisonInterface`
/// 提供数据，本结构做字符串匹配校验。
///
/// 扩展字段：`permission_checker` 注入后 `check_permission` 委托到 `PermissionChecker`；
/// `dao` 注入后启用权限缓存；`role_hierarchy` 为角色层级映射（如 `"admin" → ["user"]`），
/// 空时保持默认行为；`plugin_manager` 注入后 `check_permission` 在权限判定前调用一次插件钩子
/// （缓存命中路径亦如此，无后置调用；Err 仅 warn 不中断）。
pub struct GarrisonPermissionStrategyDefault {
    /// 权限/角色数据回调。
    interface: Arc<dyn GarrisonInterface>,
    /// 可选 PermissionChecker，注入后 check_permission 委托到它。
    permission_checker: Option<Arc<dyn PermissionChecker>>,
    /// 可选 DAO，用于权限缓存。
    dao: Option<Arc<dyn GarrisonDao>>,
    /// 可选租户维度，用于缓存键隔离：`Some(t)` 时缓存键租户段为 `<t>`（含失效版本段），
    /// `None` 时用占位符 `_`（未配置租户隔离，所有租户共享缓存键）。
    tenant_id: Option<i64>,
    /// 默认 login_type（多账号体系，接线 `_with_type` 回调）；未设置时 `"default"`。
    ///
    /// `get_permission_list` / `get_role_list` 经
    /// `GarrisonInterface::get_*_list_with_type` 把该值传给业务回调，
    /// 使覆写了 `_with_type` 的多账号数据源真正生效。
    login_type: String,
    /// 角色层级映射（如 "admin" → ["user"]），空时保持默认行为。
    role_hierarchy: HashMap<String, Vec<String>>,
    /// 可选插件管理器，注入后 check_permission 权限判定前调用一次钩子（无后置调用）。
    plugin_manager: Option<Arc<GarrisonPluginManager>>,
    /// 可选防火墙安全钩子，注入后 login 前按序调用 5 个 hook。
    #[cfg(any(
        feature = "sms-rate-limit",
        feature = "firewall-ratelimit",
        feature = "firewall-bruteforce",
        feature = "firewall-ddos",
        feature = "firewall",
        feature = "oauth2-server"
    ))]
    firewall_hook: Option<Arc<dyn GarrisonFirewallCheckHook>>,
    /// 可选监听器管理器，注入后 check_login_hooks 阻断时广播 FirewallBlock 事件
    #[cfg(feature = "listener")]
    listener_manager: Option<Arc<GarrisonListenerManager>>,
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
