//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! BulwarkLogicFactory：编译期注册的工厂子系统。
//!
//! 本文件从 `mod.rs` 迁移而来，遵循 mod-crate-hardening（规则 25）：
//! `mod.rs` 仅保留 trait 定义、pub struct/enum、pub type alias、pub use、mod 声明。
//!
//! 工厂上下文 [`BulwarkLogicFactoryContext`] 持有 init 阶段构造的 5 个 manager（用于 auto-wire）。
//! factory 函数通过此 context 获取 manager 引用，使用 builder 链式调用注入到
//! [`BulwarkLogicDefault`](crate::stp::BulwarkLogicDefault)。

use std::sync::Arc;

use crate::account::disable::DisableRepository;
use crate::config::BulwarkConfig;
use crate::core::auth::AuthLogic;
use crate::core::permission::PermissionChecker;
use crate::error::BulwarkResult;
#[cfg(feature = "listener")]
use crate::listener::BulwarkListenerManager;
use crate::plugin::BulwarkPluginManager;
use crate::session::BulwarkSession;
use crate::stp::BulwarkLogicDefault;
use crate::strategy::BulwarkPermissionStrategy;

/// 工厂上下文，持有 init 阶段构造的 5 个 manager（用于 auto-wire）。
///
/// factory 函数通过此 context 获取 manager 引用，使用 builder 链式调用注入到
/// `BulwarkLogicDefault`。所有字段为 `Option`，便于自定义 factory 选择性注入。
///
/// # 字段
/// - `plugin_manager`: 插件管理器（login/logout 触发 on_login/on_logout 钩子）
/// - `listener_manager`: 监听器管理器（需 `listener` feature，广播 Login/Logout/Kickout 事件）
/// - `auth_logic`: 认证逻辑（login_by_token 优先委托此实现）
/// - `permission_checker`: 权限校验器（check_permission/check_role 可委托此实现）
/// - `disable_repository`: 封禁库（check_disable 委托此实现查询封禁状态）
pub struct BulwarkLogicFactoryContext {
    /// 插件管理器（None 表示不注入，login/logout 不触发插件钩子）。
    pub plugin_manager: Option<Arc<BulwarkPluginManager>>,
    /// 监听器管理器（仅 `listener` feature 下存在；None 表示不注入）。
    #[cfg(feature = "listener")]
    pub listener_manager: Option<Arc<BulwarkListenerManager>>,
    /// 认证逻辑（None 表示不注入，login_by_token 使用 trait default）。
    pub auth_logic: Option<Arc<dyn AuthLogic>>,
    /// 权限校验器（None 表示不注入，check_permission 委托 firewall）。
    pub permission_checker: Option<Arc<dyn PermissionChecker>>,
    /// 封禁库（None 表示不注入，check_disable 返回 Ok 向后兼容 0.6.4 之前）。
    pub disable_repository: Option<Arc<dyn DisableRepository>>,
}

/// 工厂函数签名：接收 session/config/firewall + factory context，返回 `Arc<BulwarkLogicDefault>`。
///
/// 使用裸函数指针（`Fn` trait object 的简化形式）以便 `inventory::submit!` 静态注册。
///
/// # 0.2.1 变更
/// 签名新增第 4 个参数 `&BulwarkLogicFactoryContext`，用于 auto-wire 4 个 manager。
/// 自定义 factory 可选择忽略 context（保持旧行为）或使用 builder 链注入 manager。
pub type BulwarkLogicFactoryFn = fn(
    session: Arc<BulwarkSession>,
    config: Arc<BulwarkConfig>,
    firewall: Arc<dyn BulwarkPermissionStrategy>,
    ctx: &BulwarkLogicFactoryContext,
) -> BulwarkResult<Arc<BulwarkLogicDefault>>;

/// 工厂 entry：通过 `inventory::submit!` 注册的具体工厂实例。
///
/// # 注册方式
///
/// ```ignore
/// inventory::submit! {
///     BulwarkLogicFactoryEntry {
///         name: "default",
///         factory: bulwark_logic_factory_default,
///     }
/// }
/// ```
pub struct BulwarkLogicFactoryEntry {
    /// 工厂名称（用于诊断与优先级排序，0.1.0 不强制唯一）。
    pub name: &'static str,
    /// 工厂函数指针。
    pub factory: BulwarkLogicFactoryFn,
}

inventory::collect!(BulwarkLogicFactoryEntry);

/// 默认工厂函数：构造 `BulwarkLogicDefault`，使用 builder 链注入 context 中的 4 个 manager。
///
/// 此函数通过 `inventory::submit!` 在编译期注册到全局工厂列表，
/// `BulwarkManager::init()` 会找到它并调用以构造 `Arc<BulwarkLogicDefault>`。
///
/// # 参数
/// - `session`: 会话管理器。
/// - `config`: 全局配置。
/// - `firewall`: 权限策略。
/// - `ctx`: 工厂上下文（持有 4 个可选 manager 引用）。
///
/// # 返回
/// 新建的 `Arc<BulwarkLogicDefault>`（实际类型为 `BulwarkLogicDefault`，已注入 manager）。
///
/// # 错误
/// 当前实现始终返回 `Ok`，保留 `BulwarkResult` 以匹配工厂签名便于扩展。
pub fn bulwark_logic_factory_default(
    session: Arc<BulwarkSession>,
    config: Arc<BulwarkConfig>,
    firewall: Arc<dyn BulwarkPermissionStrategy>,
    ctx: &BulwarkLogicFactoryContext,
) -> BulwarkResult<Arc<BulwarkLogicDefault>> {
    let mut builder = BulwarkLogicDefault::new(session, config, firewall);
    if let Some(pm) = ctx.plugin_manager.clone() {
        builder = builder.with_plugin_manager(pm);
    }
    #[cfg(feature = "listener")]
    if let Some(lm) = ctx.listener_manager.clone() {
        builder = builder.with_listener_manager(lm);
    }
    if let Some(auth) = ctx.auth_logic.clone() {
        builder = builder.with_auth_logic(auth);
    }
    if let Some(pc) = ctx.permission_checker.clone() {
        builder = builder.with_permission_checker(pc);
    }
    if let Some(dr) = ctx.disable_repository.clone() {
        builder = builder.with_disable_repository(dr);
    }
    Ok(Arc::new(builder))
}

inventory::submit! {
    BulwarkLogicFactoryEntry {
        name: "default",
        factory: bulwark_logic_factory_default,
    }
}
