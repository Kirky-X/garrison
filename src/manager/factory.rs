// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! GarrisonLogicFactory：编译期注册的工厂子系统。
//!
//! 工厂上下文 [`GarrisonLogicFactoryContext`] 持有 init 阶段构造的各 manager（用于 auto-wire），
//! factory 函数通过此 context 获取 manager 引用，使用 builder 链式调用注入到
//! [`GarrisonLogicDefault`]。

use std::sync::Arc;

use crate::account::disable::{DefaultDisableRepository, DisableRepository};
use crate::config::GarrisonConfig;
use crate::core::auth::AuthLogic;
use crate::core::permission::PermissionChecker;
use crate::error::GarrisonResult;
#[cfg(feature = "listener")]
use crate::listener::GarrisonListenerManager;
use crate::plugin::GarrisonPluginManager;
use crate::session::GarrisonSession;
use crate::stp::GarrisonLogicDefault;
use crate::strategy::GarrisonPermissionStrategy;

/// 工厂上下文，持有 init 阶段构造的各 manager（用于 auto-wire）。
///
/// factory 函数通过此 context 获取 manager 引用，使用 builder 链式调用注入到
/// `GarrisonLogicDefault`。所有字段为 `Option`，便于自定义 factory 选择性注入。
pub struct GarrisonLogicFactoryContext {
    /// 插件管理器（None 表示不注入，login/logout 不触发插件钩子）。
    pub plugin_manager: Option<Arc<GarrisonPluginManager>>,
    /// 监听器管理器（仅 `listener` feature 下存在；None 表示不注入）。
    #[cfg(feature = "listener")]
    pub listener_manager: Option<Arc<GarrisonListenerManager>>,
    /// 认证逻辑（None 表示不注入，login_by_token 使用 trait default）。
    pub auth_logic: Option<Arc<dyn AuthLogic>>,
    /// 权限校验器（None 表示不注入，check_permission 委托 firewall）。
    pub permission_checker: Option<Arc<dyn PermissionChecker>>,
    /// 封禁库（None 表示未提供，factory 回退为基于 session DAO 的 `DefaultDisableRepository`）。
    pub disable_repository: Option<Arc<dyn DisableRepository>>,
    /// 三级缓存服务（仅 `three-tier-cache` feature 下存在；None 表示不注入）。
    #[cfg(feature = "three-tier-cache")]
    pub user_cache_service: Option<Arc<crate::cache::UserCacheService>>,
}

/// 工厂函数签名：接收 session/config/firewall + factory context，返回 `Arc<GarrisonLogicDefault>`。
///
/// 使用裸函数指针（`Fn` trait object 的简化形式）以便 `inventory::submit!` 静态注册。
pub type GarrisonLogicFactoryFn = fn(
    session: Arc<GarrisonSession>,
    config: Arc<GarrisonConfig>,
    firewall: Arc<dyn GarrisonPermissionStrategy>,
    ctx: &GarrisonLogicFactoryContext,
) -> GarrisonResult<Arc<GarrisonLogicDefault>>;

/// 工厂 entry：通过 `inventory::submit!` 注册的具体工厂实例。
///
/// # 注册方式
///
/// ```ignore
/// inventory::submit! {
/// GarrisonLogicFactoryEntry {
/// name: "default",
/// factory: garrison_logic_factory_default,
/// }
/// }
/// ```
pub struct GarrisonLogicFactoryEntry {
    /// 工厂名称（用于诊断与优先级排序）。
    pub name: &'static str,
    /// 工厂函数指针。
    pub factory: GarrisonLogicFactoryFn,
}

inventory::collect!(GarrisonLogicFactoryEntry);

/// 默认工厂函数：构造 `GarrisonLogicDefault`，使用 builder 链注入 context 中的 manager。
///
/// 此函数通过 `inventory::submit!` 在编译期注册到全局工厂列表，`GarrisonManager::builder()`
/// 会找到它并调用以构造 `Arc<GarrisonLogicDefault>`；当前实现始终返回 `Ok`，
/// 保留 `GarrisonResult` 以匹配工厂签名便于扩展。
pub fn garrison_logic_factory_default(
    session: Arc<GarrisonSession>,
    config: Arc<GarrisonConfig>,
    firewall: Arc<dyn GarrisonPermissionStrategy>,
    ctx: &GarrisonLogicFactoryContext,
) -> GarrisonResult<Arc<GarrisonLogicDefault>> {
    // ctx 未携带封禁库时，基于 session 的 DAO 构造默认实现（check_disable 始终生效）
    let disable_repository: Arc<dyn DisableRepository> = ctx
        .disable_repository
        .clone()
        .unwrap_or_else(|| Arc::new(DefaultDisableRepository::new(session.dao().clone())));
    let mut builder = GarrisonLogicDefault::new(session, config, firewall, disable_repository);
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
    #[cfg(feature = "three-tier-cache")]
    if let Some(ucs) = ctx.user_cache_service.clone() {
        builder = builder.with_user_cache_service(ucs);
    }
    Ok(Arc::new(builder))
}

inventory::submit! {
    GarrisonLogicFactoryEntry {
        name: "default",
        factory: garrison_logic_factory_default,
    }
}
