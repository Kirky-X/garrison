//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 策略模块，提供鉴权策略与可插拔权限策略。
//!
//! 对应 策略模式设计，
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
use crate::error::BulwarkResult;
// listener_manager 字段类型（feature-gated）
#[cfg(feature = "listener")]
use crate::listener::BulwarkListenerManager;
use crate::plugin::BulwarkPluginManager;
use crate::stp::BulwarkInterface;
// hooks 模块依赖 limiteron，仅在 limiteron 启用时编译（匹配 lib.rs 的 limiteron cfg）
// BulwarkFirewallCheckHook / LoginContext 用于 struct 字段与 trait 方法签名
#[cfg(any(
    feature = "sms-rate-limit",
    feature = "firewall-ratelimit",
    feature = "firewall-bruteforce",
    feature = "firewall-ddos",
    feature = "firewall",
    feature = "oauth2-server"
))]
use crate::strategy::hooks::{BulwarkFirewallCheckHook, LoginContext};
use async_trait::async_trait;
use std::collections::HashMap;
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

/// `BulwarkPermissionStrategyDefault` 的实现块（规则 25：mod.rs 接口隔离）。
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
/// 对应 可插拔权限策略，
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

    /// 获取用户基本信息（用于缓存）。
    ///
    /// 默认返回 `Ok(None)`，业务方可覆盖此方法提供用户信息。
    /// 启用 `three-tier-cache` feature 后，`UserCacheService` 通过此方法获取用户信息并缓存。
    ///
    /// # 安全警告
    ///
    /// 返回的字符串将被缓存到 L1（内存）和 L2（DAO 持久化）。
    /// **不要**在返回值中包含敏感信息（密码哈希、salt、session token 等）。
    /// 建议仅返回展示用信息（用户名、昵称、头像 URL 等）。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    ///
    /// # 返回
    /// - `Ok(Some(user_info))`: 用户信息字符串（如 JSON 序列化的用户对象）。
    /// - `Ok(None)`: 用户不存在或未实现此方法。
    ///
    /// # 错误
    /// - 数据回调失败：透传 `BulwarkError`。
    async fn get_user_info(&self, _login_id: &str) -> BulwarkResult<Option<String>> {
        Ok(None)
    }

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
    #[cfg(any(
        feature = "sms-rate-limit",
        feature = "firewall-ratelimit",
        feature = "firewall-bruteforce",
        feature = "firewall-ddos",
        feature = "firewall",
        feature = "oauth2-server"
    ))]
    async fn check_login_hooks(&self, _login_id: &str, _ctx: &LoginContext) -> BulwarkResult<()> {
        Ok(())
    }
}

// ============================================================================
// BulwarkPermissionStrategyDefault：默认实现（委托 BulwarkInterface 回调）
// ============================================================================

/// `BulwarkPermissionStrategy` 的默认实现，持有 `BulwarkInterface` 回调获取权限/角色数据。
///
/// 对应 `StpInterface` 回调模式：
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
    #[cfg(any(
        feature = "sms-rate-limit",
        feature = "firewall-ratelimit",
        feature = "firewall-bruteforce",
        feature = "firewall-ddos",
        feature = "firewall",
        feature = "oauth2-server"
    ))]
    firewall_hook: Option<Arc<dyn BulwarkFirewallCheckHook>>,
    /// 可选监听器管理器，注入后 check_login_hooks 阻断时广播 FirewallBlock 事件
    #[cfg(feature = "listener")]
    listener_manager: Option<Arc<BulwarkListenerManager>>,
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
