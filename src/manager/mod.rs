//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 管理器模块，提供全局管理器单例与编译期工厂注册。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `SaManager`，
//! 统筹 DAO、配置、策略等组件的全局生命周期。
//!
//! ## 设计
//!
//! - `BulwarkManager` 持有 `Arc<BulwarkLogicDefault>` 全局单例（基于 `parking_lot::RwLock` 支持重复 init）
//! - `BulwarkLogicFactory` trait 通过 `inventory::submit!` 编译期注册
//! - 业务方调用 `BulwarkManager::init(dao, config, interface)` 注入依赖
//! - `BulwarkUtil::login(id)` 等静态方法委托到 `BULWARK_MANAGER` 单例
//!
//! ## 初始化流程
//!
//! ```ignore
//! use std::sync::Arc;
//! use bulwark::prelude::*;
//!
//! // 1. 准备依赖
//! let dao: Arc<dyn BulwarkDao> = /* oxcache 或 dbnexus 实现 */;
//! let config = Arc::new(BulwarkConfig::default_config());
//! let interface: Arc<dyn BulwarkInterface> = Arc::new(MyInterface);
//!
//! // 2. 初始化全局管理器
//! BulwarkManager::init(dao, config, interface).unwrap();
//!
//! // 3. 使用静态 API（task_local 上下文由 middleware 设置）
//! let token = BulwarkUtil::login_simple("1001").await.unwrap();
//! ```

use crate::account::disable::{DefaultDisableRepository, DisableRepository};
use crate::config::BulwarkConfig;
use crate::core::auth::{AuthLogic, AuthLogicDefault};
use crate::core::permission::{PermissionChecker, PermissionCheckerDefault};
use crate::core::token::TokenStyleFactory;
use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
#[cfg(feature = "listener")]
use crate::listener::BulwarkListenerManager;
use crate::plugin::BulwarkPluginManager;
use crate::session::BulwarkSession;
use crate::stp::util::spawn_cleanup_task;
use crate::stp::{BulwarkInterface, BulwarkLogicDefault};
#[cfg(feature = "anomalous-detector-dual")]
use crate::strategy::firewall::{AnomalousAnalyzerConfig, AnomalousLoginAnalyzer};
use crate::strategy::{BulwarkPermissionStrategy, BulwarkPermissionStrategyDefault, Strategy};
use once_cell::sync::Lazy;
use parking_lot::RwLock;
use std::sync::Arc;
#[cfg(feature = "anomalous-detector-dual")]
use tokio::sync::watch;
use tokio::task::JoinHandle;

// 显式 Manager API
// 启用 manager-explicit feature 后提供不依赖全局单例的 Manager struct。
#[cfg(feature = "manager-explicit")]
pub mod explicit;

/// 全局管理器，统筹 `BulwarkLogicDefault` 的生命周期。
///
/// [借鉴 Sa-Token] 对应 `SaManager`，
/// 持有全局 `Arc<BulwarkLogicDefault>` 引用，提供静态方法入口。
///
/// # 初始化
///
/// 业务方启动时调用 `BulwarkManager::init(dao, config, interface)` 注入依赖。
/// 未初始化时调用 `BulwarkUtil::login(id)` 等返回 `BulwarkError::Session`。
pub struct BulwarkManager {
    /// 全局 `BulwarkLogicDefault` 引用（RwLock 支持测试时重复 init 与 reset）。
    logic: RwLock<Option<Arc<BulwarkLogicDefault>>>,
    /// 全局 Strategy 注册表引用。
    ///
    /// 外层 `RwLock` 管理 Option（初始化/重置），内层 `Arc<RwLock<Strategy>>`
    /// 允许运行时通过 `strategy.write().register_*()` 替换策略。
    strategy: RwLock<Option<Arc<RwLock<Strategy>>>>,
    /// 后台 cleanup task 的 JoinHandle（T030）。
    ///
    /// `init` 时若 `config.token_map_cleanup_interval_secs > 0` 则启动 task 并保存 handle。
    /// `reset_for_test` / `Drop` 时 abort task，避免后台线程在测试间或程序退出后残留。
    cleanup_task_handle: RwLock<Option<JoinHandle<()>>>,
    /// 异常登录分析器 task 的 JoinHandle（anomalous-detector-dual feature）。
    ///
    /// `init` 时若 `anomalous-detector-dual` feature 启用则启动 analyzer task 并保存 handle。
    /// `reset_for_test` / `Drop` 时 abort task，避免后台线程在测试间或程序退出后残留。
    #[cfg(feature = "anomalous-detector-dual")]
    anomalous_analyzer_handle: RwLock<Option<JoinHandle<()>>>,
    /// 异常登录分析器 shutdown 信号发送端（anomalous-detector-dual feature）。
    ///
    /// 保存 `shutdown_tx` 使其生命周期与 `BulwarkManager` 一致，
    /// 避免 `shutdown_rx` 因 sender drop 而误触发停止。
    /// `reset_for_test` / `Drop` 时 take 清空，触发 `shutdown_rx.changed()` 返回 Err 通知 task 退出。
    #[cfg(feature = "anomalous-detector-dual")]
    anomalous_analyzer_shutdown_tx: RwLock<Option<watch::Sender<bool>>>,
}

impl BulwarkManager {
    /// 创建空的管理器实例（仅用于 BULWARK_MANAGER 单例初始化）。
    fn new() -> Self {
        Self {
            logic: RwLock::new(None),
            strategy: RwLock::new(None),
            cleanup_task_handle: RwLock::new(None),
            #[cfg(feature = "anomalous-detector-dual")]
            anomalous_analyzer_handle: RwLock::new(None),
            #[cfg(feature = "anomalous-detector-dual")]
            anomalous_analyzer_shutdown_tx: RwLock::new(None),
        }
    }

    /// 初始化全局管理器：注入 dao/config/interface 依赖，构造默认 `BulwarkLogicDefault` 实例。
    ///
    /// # 参数
    /// - `dao`: DAO 引用（oxcache / dbnexus）
    /// - `config`: 全局配置
    /// - `interface`: 权限数据回调（由业务方实现）
    ///
    /// # 行为
    /// 1. 校验配置合法性
    /// 2. 构造 `BulwarkSession::new(dao, timeout, active_timeout)`
    /// 3. 构造 `BulwarkPermissionStrategyDefault::new(interface)`
    /// 4. 通过 `inventory::iter::<BulwarkLogicFactoryEntry>()` 找到注册的 factory
    /// 5. 调用 `factory.build(session, config, firewall)` 生成 `Arc<BulwarkLogicDefault>`
    /// 6. 若无 factory 注册，使用默认 `BulwarkLogicFactoryDefault` 构造 `BulwarkLogicDefault`
    /// 7. 覆盖式更新全局单例（允许重复 init，便于测试）
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    ///
    /// # 错误
    /// - 配置非法（timeout ≤ 0 等）：`BulwarkError::Config`
    /// - timeout/active_timeout 溢出 u64：`BulwarkError::Config`
    /// - factory 构造失败：透传 factory 返回的 `BulwarkError`
    pub fn init(
        dao: Arc<dyn BulwarkDao>,
        config: Arc<BulwarkConfig>,
        interface: Arc<dyn BulwarkInterface>,
    ) -> BulwarkResult<()> {
        Self::init_with_factory_selector(dao, config, interface, default_factory_selector)
    }

    /// 内部初始化方法，允许注入自定义 factory selector（便于测试 mock factory）。
    fn init_with_factory_selector(
        dao: Arc<dyn BulwarkDao>,
        config: Arc<BulwarkConfig>,
        interface: Arc<dyn BulwarkInterface>,
        factory_selector: fn() -> Option<&'static BulwarkLogicFactoryEntry>,
    ) -> BulwarkResult<()> {
        // 1. 校验配置
        config.validate()?;

        // 2. 构造 session（处理 active_timeout = -1 的兜底语义）
        let timeout = u64::try_from(config.timeout)
            .map_err(|_| BulwarkError::Config(format!("timeout 溢出 u64: {}", config.timeout)))?;
        let active_timeout = if config.active_timeout < 0 {
            // -1 表示不启用 activity 超时，使用 timeout 兜底（保留 Sa-Token 语义）
            timeout
        } else {
            u64::try_from(config.active_timeout).map_err(|_| {
                BulwarkError::Config(format!(
                    "active_timeout 溢出 u64: {}",
                    config.active_timeout
                ))
            })?
        };
        let session = Arc::new(BulwarkSession::new(dao.clone(), timeout, active_timeout));

        // T030: 先 abort 旧 cleanup task 再 spawn 新 task，避免短暂重叠窗口
        if let Some(old) = BULWARK_MANAGER.cleanup_task_handle.write().take() {
            old.abort();
        }

        // T030: 启动后台 cleanup task（interval_secs <= 0 时返回 None，不启动）
        let cleanup_handle =
            spawn_cleanup_task(session.clone(), config.token_map_cleanup_interval_secs);

        // 3. auto-wire: 构造 4 个 manager（gap）
        // 3.1 PermissionChecker（委托 interface 查询权限/角色数据）
        let permission_checker: Arc<dyn PermissionChecker> =
            Arc::new(PermissionCheckerDefault::new(interface.clone()));
        // 3.2 PluginManager（通过 inventory 收集编译期注册的插件）
        let plugin_manager = Arc::new(BulwarkPluginManager::new());
        // 3.3 ListenerManager（通过 inventory 收集编译期注册的监听器，需 listener feature）
        #[cfg(feature = "listener")]
        let listener_manager = Arc::new(BulwarkListenerManager::new());
        // 3.4 AuthLogic（委托 session + token_handler 实现登录/校验）
        //     token_handler 由 TokenStyleFactory 依据 config.token_style 创建
        let token_handler: Arc<dyn crate::core::token::Token> = Arc::from(TokenStyleFactory::new(
            &config.token_style,
            &config.jwt_secret,
        )?);
        let auth_logic: Arc<dyn AuthLogic> = Arc::new(AuthLogicDefault::new(
            session.clone(),
            token_handler,
            config.timeout,
        ));

        // 4. 构造 firewall，注入 permission_checker + plugin_manager
        let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(
            BulwarkPermissionStrategyDefault::new(interface)
                .with_permission_checker(permission_checker.clone())
                .with_plugin_manager(plugin_manager.clone()),
        );

        // 4.5 构造 disable_repository（T020）：委托同一 DAO 实例持久化封禁条目
        let disable_repo: Arc<dyn DisableRepository> =
            Arc::new(DefaultDisableRepository::new(dao.clone()));

        // 5. 构造 factory context（持有 5 个 manager 引用）
        #[cfg(feature = "listener")]
        let factory_ctx = BulwarkLogicFactoryContext {
            plugin_manager: Some(plugin_manager.clone()),
            listener_manager: Some(listener_manager.clone()),
            auth_logic: Some(auth_logic.clone()),
            permission_checker: Some(permission_checker.clone()),
            disable_repository: Some(disable_repo.clone()),
        };
        #[cfg(not(feature = "listener"))]
        let factory_ctx = BulwarkLogicFactoryContext {
            plugin_manager: Some(plugin_manager.clone()),
            auth_logic: Some(auth_logic.clone()),
            permission_checker: Some(permission_checker.clone()),
            disable_repository: Some(disable_repo.clone()),
        };

        // T023: clone listener_manager 和 dao 给 analyzer，读取 config 值（均在 move 之前）
        #[cfg(feature = "anomalous-detector-dual")]
        let (
            analyzer_listener_manager,
            analyzer_dao,
            analyzer_interval_secs,
            analyzer_burst_threshold,
        ) = (
            listener_manager.clone(),
            dao.clone(),
            config.anomalous_analyzer_interval_secs,
            config.anomalous_analyzer_burst_threshold,
        );

        // 6. 通过 factory 构造 logic（传递 context 以便 factory 使用 builder 链）
        // T014: three-tier-cache feature 启用时构造 UserCacheService（复用 dao + firewall）
        #[cfg(feature = "three-tier-cache")]
        let user_cache_service = Arc::new(crate::cache::UserCacheService::new(
            dao.clone(),
            firewall.clone(),
            config.l1_cache_ttl_secs,
            config.l2_cache_ttl_secs,
            config.l1_cache_capacity,
        )?);
        let logic: Arc<BulwarkLogicDefault> = match factory_selector() {
            Some(entry) => (entry.factory)(session, config, firewall, &factory_ctx)?,
            None => {
                // 兜底路径：直接通过 builder 链构造 BulwarkLogicDefault
                // `mut` 仅在 `listener`/`three-tier-cache` feature 启用时需要（下方 cfg 块会 reassign）
                #[cfg_attr(
                    not(any(feature = "listener", feature = "three-tier-cache")),
                    allow(unused_mut)
                )]
                let mut builder = BulwarkLogicDefault::new(session, config, firewall)
                    .with_plugin_manager(plugin_manager)
                    .with_auth_logic(auth_logic)
                    .with_permission_checker(permission_checker)
                    .with_disable_repository(disable_repo);
                #[cfg(feature = "listener")]
                {
                    builder = builder.with_listener_manager(listener_manager);
                }
                #[cfg(feature = "three-tier-cache")]
                {
                    builder = builder.with_user_cache_service(user_cache_service);
                }
                Arc::new(builder)
            },
        };

        // 7. 覆盖式更新全局单例（允许重复 init，便于测试）
        // 同时构造 Strategy 注册表
        let strategy = Arc::new(RwLock::new(Strategy::new(logic.clone())));
        *BULWARK_MANAGER.logic.write() = Some(logic);
        *BULWARK_MANAGER.strategy.write() = Some(strategy);

        // T030: 保存新 cleanup task handle（旧 task 已在上方 abort）
        *BULWARK_MANAGER.cleanup_task_handle.write() = cleanup_handle;

        // T023: 启动异常登录分析器 task（anomalous-detector-dual feature）
        #[cfg(feature = "anomalous-detector-dual")]
        {
            // 先 abort 旧 analyzer task
            if let Some(old) = BULWARK_MANAGER.anomalous_analyzer_handle.write().take() {
                old.abort();
            }
            // 清空旧 shutdown_tx（drop 后 shutdown_rx.changed() 返回 Err，task 退出）
            BULWARK_MANAGER
                .anomalous_analyzer_shutdown_tx
                .write()
                .take();

            // 创建 shutdown channel
            let (shutdown_tx, shutdown_rx) = watch::channel(false);

            // 从 BulwarkConfig 构造 analyzer config
            let analyzer_config = AnomalousAnalyzerConfig {
                interval_secs: analyzer_interval_secs,
                burst_threshold: analyzer_burst_threshold,
                ..AnomalousAnalyzerConfig::default()
            };

            // 构造 analyzer 并 spawn task
            let analyzer = AnomalousLoginAnalyzer::new(
                analyzer_dao,
                analyzer_config,
                shutdown_rx,
                Some(analyzer_listener_manager),
            );
            let analyzer_handle = analyzer.start();

            // 保存 handle 和 shutdown_tx
            *BULWARK_MANAGER.anomalous_analyzer_handle.write() = Some(analyzer_handle);
            *BULWARK_MANAGER.anomalous_analyzer_shutdown_tx.write() = Some(shutdown_tx);
        }

        Ok(())
    }

    /// 获取全局 `BulwarkLogicDefault` 引用。
    ///
    /// # 返回
    /// 已初始化时返回 `Arc<BulwarkLogicDefault>`。
    ///
    /// # 错误
    /// - 若未初始化，返回 `BulwarkError::Session("BulwarkManager 未初始化")`。
    pub fn logic() -> BulwarkResult<Arc<BulwarkLogicDefault>> {
        BULWARK_MANAGER
            .logic
            .read()
            .clone()
            .ok_or_else(|| BulwarkError::Session("BulwarkManager 未初始化".to_string()))
    }

    /// 获取全局 `Strategy` 注册表引用。
    ///
    /// 返回 `Arc<RwLock<Strategy>>`，业务方可通过 `strategy.write().register_*()`
    /// 运行时替换策略，替换后立即生效（下次调用使用新策略）。
    ///
    /// # 返回
    /// 已初始化时返回 `Arc<RwLock<Strategy>>`。
    ///
    /// # 错误
    /// - 若未初始化，返回 `BulwarkError::Session("BulwarkManager 未初始化")`。
    pub fn strategy() -> BulwarkResult<Arc<RwLock<Strategy>>> {
        BULWARK_MANAGER
            .strategy
            .read()
            .clone()
            .ok_or_else(|| BulwarkError::Session("BulwarkManager 未初始化".to_string()))
    }

    /// 获取全局 `DisableRepository` 引用（v0.6.5 T020）。
    ///
    /// `init` 时自动创建 `DefaultDisableRepository` 并注入到 `BulwarkLogicDefault`，
    /// 此方法从 logic 中读取封禁库实例，供业务方调用 `disable` / `untie_disable` /
    /// `is_disable` / `get_disable_time` / `get_disable_level`。
    ///
    /// # 返回
    /// - `Some(Arc<dyn DisableRepository>)`: 已 init 且 disable_repository 已注册。
    /// - `None`: 未 init 或未注册（向后兼容场景）。
    ///
    /// # 示例
    /// ```ignore
    /// use bulwark::prelude::*;
    ///
    /// if let Some(repo) = BulwarkManager::disable_repository() {
    ///     repo.disable("user-1", "default", None, 0, 0).await.unwrap();
    /// }
    /// ```
    pub fn disable_repository() -> Option<Arc<dyn DisableRepository>> {
        Self::logic()
            .ok()
            .and_then(|logic| logic.disable_repository.clone())
    }

    /// 替换全局 `Strategy` 注册表。
    ///
    /// 用于运行时或测试时整体替换 Strategy 实例（如注入预配置的自定义策略集合）。
    /// 替换后立即生效，旧 Strategy 被 drop。
    ///
    /// # 参数
    /// - `strategy`: 新的 `Arc<RwLock<Strategy>>` 实例。
    ///
    /// # 返回
    /// 成功返回 `Ok(())`。
    pub fn with_strategy(strategy: Arc<RwLock<Strategy>>) -> BulwarkResult<()> {
        *BULWARK_MANAGER.strategy.write() = Some(strategy);
        Ok(())
    }

    /// 检查管理器是否已初始化。
    ///
    /// # 返回
    /// - `true`: 已调用 `init` 且全局单例持有 `BulwarkLogicDefault`。
    /// - `false`: 未初始化或已 `reset_for_test`。
    pub fn is_initialized() -> bool {
        BULWARK_MANAGER.logic.read().is_some()
    }

    /// 重置管理器（仅供测试用，业务代码不应调用）。
    ///
    /// 清空全局 `BulwarkLogicDefault` 与 `Strategy` 引用，
    /// 使后续 `BulwarkUtil::login(id)` 等返回未初始化错误。
    #[cfg(test)]
    pub fn reset_for_test() {
        // T030: abort cleanup task 避免测试间残留后台线程
        if let Some(handle) = BULWARK_MANAGER.cleanup_task_handle.write().take() {
            handle.abort();
        }
        // T023: abort anomalous analyzer task + 清空 shutdown_tx
        #[cfg(feature = "anomalous-detector-dual")]
        {
            if let Some(handle) = BULWARK_MANAGER.anomalous_analyzer_handle.write().take() {
                handle.abort();
            }
            BULWARK_MANAGER
                .anomalous_analyzer_shutdown_tx
                .write()
                .take();
        }
        *BULWARK_MANAGER.logic.write() = None;
        *BULWARK_MANAGER.strategy.write() = None;
    }
}

impl Drop for BulwarkManager {
    fn drop(&mut self) {
        // T030: manager drop 时 abort cleanup task，避免后台线程残留
        if let Some(handle) = self.cleanup_task_handle.write().take() {
            handle.abort();
        }
        // T023: abort anomalous analyzer task + 清空 shutdown_tx
        #[cfg(feature = "anomalous-detector-dual")]
        {
            if let Some(handle) = self.anomalous_analyzer_handle.write().take() {
                handle.abort();
            }
            self.anomalous_analyzer_shutdown_tx.write().take();
        }
    }
}

/// 默认 factory selector：从 inventory 中找到第一个注册的 `BulwarkLogicFactoryEntry`。
///
/// 若无 entry 注册，返回 `None`，由 `init()` 兜底使用 `BulwarkLogicDefault`。
fn default_factory_selector() -> Option<&'static BulwarkLogicFactoryEntry> {
    use std::iter::Iterator;
    inventory::iter::<BulwarkLogicFactoryEntry>().next()
}

/// 全局管理器单例。
///
/// 通过 `once_cell::sync::Lazy` 实现懒加载，
/// 首次访问时调用 `BulwarkManager::new()`。
pub static BULWARK_MANAGER: Lazy<BulwarkManager> = Lazy::new(BulwarkManager::new);

// ============================================================================
// BulwarkLogicFactory：编译期注册的工厂 trait
// ============================================================================

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

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests {
    use super::mock::MockInterface;
    use super::*;
    use crate::dao::tests::MockDao;
    use crate::dao::BulwarkDao;
    use crate::stp::{BulwarkUtil, LoginParams, SessionLogic};
    use async_trait::async_trait;
    use serial_test::serial;

    // ------------------------------------------------------------------------
    // 辅助函数
    // ------------------------------------------------------------------------

    /// 创建默认测试配置（timeout=3600，throw_on_not_login=false 便于断言）。
    fn make_config() -> BulwarkConfig {
        let mut config = BulwarkConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = -1;
        config.throw_on_not_login = false;
        config
    }

    /// 在 task_local 上下文中执行 future（设置当前 token）。
    async fn with_token<R>(token: String, f: impl std::future::Future<Output = R>) -> R {
        crate::stp::with_current_token(token, f).await
    }

    // ------------------------------------------------------------------------
    // 未初始化场景测试（spec Scenario: 未初始化抛错）
    // ------------------------------------------------------------------------

    /// 验证未初始化时 `BulwarkManager::logic()` 返回 Session 错误。
    #[test]
    #[serial]
    fn logic_returns_error_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkManager::logic();
        assert!(result.is_err());
        match result {
            Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化") => {},
            other => panic!(
                "应返回 'BulwarkManager 未初始化'，实际: {:?}",
                other.map(|_| ())
            ),
        }
    }

    /// 验证未初始化时 `BulwarkManager::is_initialized()` 返回 false。
    #[test]
    #[serial]
    fn is_initialized_returns_false_when_not_initialized() {
        BulwarkManager::reset_for_test();
        assert!(!BulwarkManager::is_initialized());
    }

    // ------------------------------------------------------------------------
    // 初始化场景测试（spec Scenario: init 后即可用）
    // ------------------------------------------------------------------------

    /// 验证 init 后 `is_initialized()` 返回 true。
    #[tokio::test]
    #[serial]
    async fn init_sets_initialized_flag() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        let result = BulwarkManager::init(dao, config, interface);
        assert!(result.is_ok(), "init 应成功: {:?}", result.map(|_| ()));
        assert!(BulwarkManager::is_initialized());
        BulwarkManager::reset_for_test();
    }

    /// 验证 init 校验配置：timeout=0 抛 Config 错误。
    #[tokio::test]
    #[serial]
    async fn init_rejects_invalid_config() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mut config = BulwarkConfig::default_config();
        config.timeout = 0; // 非法
        let config = Arc::new(config);
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        let result = BulwarkManager::init(dao, config, interface);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BulwarkError::Config(ref msg) if msg.contains("timeout must be positive")
        ));
        assert!(!BulwarkManager::is_initialized());
        BulwarkManager::reset_for_test();
    }

    /// 验证 init 处理 active_timeout=-1 的兜底语义（使用 timeout 兜底）。
    #[tokio::test]
    #[serial]
    async fn init_handles_negative_active_timeout() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config()); // active_timeout = -1
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        let result = BulwarkManager::init(dao, config, interface);
        assert!(result.is_ok(), "active_timeout=-1 应使用 timeout 兜底");
        assert!(BulwarkManager::is_initialized());
        BulwarkManager::reset_for_test();
    }

    // ------------------------------------------------------------------------
    // 端到端流程测试（spec Scenario: login → check_login → check_permission → logout）
    // ------------------------------------------------------------------------

    /// 验证完整端到端流程：init → login → check_login → logout → check_login 失败。
    #[tokio::test]
    #[serial]
    async fn end_to_end_login_check_logout() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        BulwarkManager::init(dao, config, interface).unwrap();
        assert!(BulwarkManager::is_initialized());

        // login
        let token = BulwarkUtil::login_simple("1001").await.unwrap();
        assert!(!token.is_empty());

        // check_login
        let is_logged_in = with_token(token.clone(), async { BulwarkUtil::check_login().await })
            .await
            .unwrap();
        assert!(is_logged_in, "登录后 check_login 应返回 true");

        // logout
        let logout_result = with_token(token.clone(), async { BulwarkUtil::logout().await }).await;
        assert!(
            logout_result.is_ok(),
            "logout 应成功: {:?}",
            logout_result.map(|_| ())
        );

        // logout 后 check_login 应返回 false
        let is_still_logged_in =
            with_token(token.clone(), async { BulwarkUtil::check_login().await })
                .await
                .unwrap();
        assert!(!is_still_logged_in, "logout 后 check_login 应返回 false");

        BulwarkManager::reset_for_test();
    }

    /// 验证权限校验端到端流程：login → check_permission 持有/未持有。
    #[tokio::test]
    #[serial]
    async fn end_to_end_check_permission() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> =
            Arc::new(MockInterface::new().with_permission("1001", &["user:read", "user:write"]));
        BulwarkManager::init(dao, config, interface).unwrap();

        let token = BulwarkUtil::login_simple("1001").await.unwrap();

        // 持有权限
        let check_result = with_token(token.clone(), async {
            BulwarkUtil::check_permission("user:read").await
        })
        .await;
        assert!(
            check_result.is_ok(),
            "持有权限应通过: {:?}",
            check_result.map(|_| ())
        );

        // 未持有权限
        let check_result = with_token(token.clone(), async {
            BulwarkUtil::check_permission("user:delete").await
        })
        .await;
        assert!(check_result.is_err());
        assert!(matches!(
            check_result.unwrap_err(),
            BulwarkError::NotPermission(ref p) if p == "user:delete"
        ));

        BulwarkManager::reset_for_test();
    }

    /// 验证角色校验端到端流程：login → check_role 持有/未持有。
    #[tokio::test]
    #[serial]
    async fn end_to_end_check_role() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> =
            Arc::new(MockInterface::new().with_role("1001", &["admin"]));
        BulwarkManager::init(dao, config, interface).unwrap();

        let token = BulwarkUtil::login_simple("1001").await.unwrap();

        // 持有角色
        let check_result = with_token(token.clone(), async {
            BulwarkUtil::check_role("admin").await
        })
        .await;
        assert!(
            check_result.is_ok(),
            "持有角色应通过: {:?}",
            check_result.map(|_| ())
        );

        // 未持有角色
        let check_result = with_token(token.clone(), async {
            BulwarkUtil::check_role("superadmin").await
        })
        .await;
        assert!(check_result.is_err());
        assert!(matches!(
            check_result.unwrap_err(),
            BulwarkError::NotRole(ref r) if r == "superadmin"
        ));

        BulwarkManager::reset_for_test();
    }

    /// 验证 BulwarkUtil::login 未初始化时抛错。
    #[tokio::test]
    #[serial]
    async fn util_login_fails_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkUtil::login_simple("1001").await;
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            BulwarkError::Session(ref msg) if msg.contains("未初始化")
        ));
    }

    /// 验证重复 init 覆盖式更新（不抛错）。
    #[tokio::test]
    #[serial]
    async fn init_overwrites_existing() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        BulwarkManager::init(dao.clone(), config.clone(), interface.clone()).unwrap();
        assert!(BulwarkManager::is_initialized());

        // 重复 init 应覆盖式更新，不抛错
        let result = BulwarkManager::init(dao, config, interface);
        assert!(
            result.is_ok(),
            "重复 init 应覆盖式更新: {:?}",
            result.map(|_| ())
        );
        assert!(BulwarkManager::is_initialized());

        BulwarkManager::reset_for_test();
    }

    /// 验证 inventory 已注册 default factory。
    #[test]
    fn default_factory_registered_via_inventory() {
        use std::iter::Iterator;
        let found = inventory::iter::<BulwarkLogicFactoryEntry>()
            .filter(|e| e.name == "default")
            .count();
        assert!(
            found >= 1,
            "应至少注册一个 name='default' 的 factory，实际: {}",
            found
        );
    }

    /// 验证 default factory 构造的 logic 可正常 login。
    #[tokio::test]
    async fn default_factory_builds_working_logic() {
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());

        let timeout = u64::try_from(config.timeout).unwrap();
        let session = Arc::new(BulwarkSession::new(dao, timeout, timeout));
        let firewall: Arc<dyn BulwarkPermissionStrategy> =
            Arc::new(BulwarkPermissionStrategyDefault::new(interface));

        // factory 签名新增 ctx 参数，构造空 context 验证向后兼容
        #[cfg(feature = "listener")]
        let ctx = BulwarkLogicFactoryContext {
            plugin_manager: None,
            listener_manager: None,
            auth_logic: None,
            permission_checker: None,
            disable_repository: None,
        };
        #[cfg(not(feature = "listener"))]
        let ctx = BulwarkLogicFactoryContext {
            plugin_manager: None,
            auth_logic: None,
            permission_checker: None,
            disable_repository: None,
        };
        let logic = bulwark_logic_factory_default(session, config, firewall, &ctx).unwrap();
        let token = logic.login("1001", &LoginParams::default()).await.unwrap();
        assert!(!token.is_empty());
    }

    // ------------------------------------------------------------------------
    // init 配置分支补充测试
    // ------------------------------------------------------------------------

    /// 验证 init 处理 active_timeout > 0 的非负值（else 分支）。
    ///
    /// 覆盖 `init_with_factory_selector` 中 `else { u64::try_from(active_timeout)... }` 分支：
    /// 当 active_timeout >= 0 时，直接转换为 u64，不使用 timeout 兜底。
    #[tokio::test]
    #[serial]
    async fn init_with_positive_active_timeout() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mut config = BulwarkConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = 1800; // 正值，走 else 分支
        let config = Arc::new(config);
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());

        let result = BulwarkManager::init(dao, config, interface);
        assert!(
            result.is_ok(),
            "active_timeout=1800 应走 else 分支并成功: {:?}",
            result.map(|_| ())
        );
        assert!(BulwarkManager::is_initialized());

        // 验证 login 仍可正常工作
        let token = BulwarkUtil::login_simple("1001").await.unwrap();
        assert!(!token.is_empty());

        BulwarkManager::reset_for_test();
    }

    /// 验证 init 处理 active_timeout = 0 的边界值（else 分支）。
    ///
    /// 覆盖 `init_with_factory_selector` 中 `else` 分支的边界值 0。
    #[tokio::test]
    #[serial]
    async fn init_with_zero_active_timeout() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mut config = BulwarkConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = 0; // 边界值 0，走 else 分支
        let config = Arc::new(config);
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());

        let result = BulwarkManager::init(dao, config, interface);
        assert!(result.is_ok(), "active_timeout=0 应走 else 分支并成功");
        assert!(BulwarkManager::is_initialized());

        BulwarkManager::reset_for_test();
    }

    /// 验证 init 校验配置：非法 token_style 抛 Config 错误。
    ///
    /// 覆盖 `init_with_factory_selector` 中 `config.validate()?` 的另一种错误分支
    /// （非法 token_style，区别于 timeout 非法）。
    #[tokio::test]
    #[serial]
    async fn init_rejects_invalid_token_style() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mut config = BulwarkConfig::default_config();
        config.token_style = "unknown_style".to_string(); // 非法
        let config = Arc::new(config);
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());

        let result = BulwarkManager::init(dao, config, interface);
        assert!(result.is_err());
        assert!(
            matches!(result.unwrap_err(), BulwarkError::Config(ref msg) if msg.contains("unknown token_style")),
            "应返回 'unknown token_style' 错误"
        );
        assert!(!BulwarkManager::is_initialized());

        BulwarkManager::reset_for_test();
    }

    // ------------------------------------------------------------------------
    // init_with_factory_selector 兜底路径测试
    // ------------------------------------------------------------------------

    /// 验证 init_with_factory_selector 在无 factory 注册时走兜底路径。
    ///
    /// 覆盖 init_with_factory_selector 中 `match factory_selector() { None => { ... } }` 分支：
    /// 当 factory_selector 返回 None 时，直接通过 builder 链构造 BulwarkLogicDefault。
    #[tokio::test]
    #[serial]
    async fn init_fallback_when_no_factory_registered() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());

        // 使用返回 None 的 selector，触发兜底路径
        let result = BulwarkManager::init_with_factory_selector(
            dao,
            config,
            interface,
            || None, // selector 返回 None，跳过 inventory factory
        );
        assert!(result.is_ok(), "兜底路径应成功: {:?}", result.map(|_| ()));
        assert!(BulwarkManager::is_initialized());

        // 验证 login 仍可正常工作
        let token = BulwarkUtil::login_simple("1001").await.unwrap();
        assert!(!token.is_empty());

        BulwarkManager::reset_for_test();
    }

    // ------------------------------------------------------------------------
    // MockDao 方法覆盖测试
    // ------------------------------------------------------------------------

    /// 验证 MockDao::expire 和 delete 方法可正常调用。
    ///
    /// 覆盖 MockDao 的 expire 和 delete trait 方法（此前测试未直接调用）。
    #[tokio::test]
    async fn mock_dao_expire_and_delete_work() {
        let dao = MockDao::new();
        dao.set("key1", "value1", 3600).await.unwrap();

        // 测试 expire
        dao.expire("key1", 7200).await.unwrap();
        let got = dao.get("key1").await.unwrap();
        assert_eq!(got, Some("value1".to_string()));

        // 测试 expire 不存在的键
        let result = dao.expire("missing", 3600).await;
        assert!(result.is_err());

        // 测试 delete
        dao.delete("key1").await.unwrap();
        let got = dao.get("key1").await.unwrap();
        assert!(got.is_none());
    }

    // ------------------------------------------------------------------------
    // Strategy 注册表集成测试
    // ------------------------------------------------------------------------

    /// 验证未初始化时 `BulwarkManager::strategy()` 返回 Session 错误。
    #[tokio::test]
    #[serial]
    async fn strategy_returns_error_when_not_initialized() {
        BulwarkManager::reset_for_test();
        let result = BulwarkManager::strategy();
        match result {
            Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化") => {},
            other => panic!(
                "应返回 'BulwarkManager 未初始化'，实际: {:?}",
                other.map(|_| ())
            ),
        }
    }

    /// 验证 init 后 `strategy()` 返回 `Arc<RwLock<Strategy>>`。
    #[tokio::test]
    #[serial]
    async fn strategy_available_after_init() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        BulwarkManager::init(dao, config, interface).unwrap();

        let strategy = BulwarkManager::strategy();
        assert!(strategy.is_ok(), "init 后应能获取 strategy");

        BulwarkManager::reset_for_test();
    }

    /// 验证 `with_strategy()` 整体替换 Strategy 注册表。
    #[tokio::test]
    #[serial]
    async fn with_strategy_replaces_registry() {
        use crate::strategy::LoginHandler;

        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        BulwarkManager::init(dao, config, interface).unwrap();

        // 获取原 logic 并构造自定义 Strategy
        let logic = BulwarkManager::logic().unwrap();
        let custom_strategy = Arc::new(RwLock::new(Strategy::new(logic)));

        // 注入自定义 LoginHandler
        struct CustomLogin;
        #[async_trait]
        impl LoginHandler for CustomLogin {
            async fn handle_login(&self, id: &str) -> BulwarkResult<String> {
                Ok(format!("custom-{}", id))
            }
        }
        custom_strategy
            .write()
            .register_login_handler(Arc::new(CustomLogin));

        // with_strategy 替换
        BulwarkManager::with_strategy(custom_strategy).unwrap();

        // 验证替换后使用自定义策略
        let strategy = BulwarkManager::strategy().unwrap();
        let login_handler = strategy.read().login_handler().clone();
        let token = login_handler.handle_login("1001").await.unwrap();
        assert_eq!(token, "custom-1001", "with_strategy 后应使用自定义策略");

        BulwarkManager::reset_for_test();
    }

    /// 验证运行时通过 `strategy().write().register_*()` 替换策略立即生效。
    #[tokio::test]
    #[serial]
    async fn runtime_strategy_replacement_takes_effect_immediately() {
        use crate::strategy::LoginHandler;

        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        BulwarkManager::init(dao, config, interface).unwrap();

        // 替换前：默认策略生成 token（先 clone Arc 再 await，避免跨 await 持锁）
        let strategy = BulwarkManager::strategy().unwrap();
        let default_handler = strategy.read().login_handler().clone();
        let default_token = default_handler.handle_login("1001").await.unwrap();
        assert!(!default_token.is_empty());

        // 运行时替换
        struct CustomLogin;
        #[async_trait]
        impl LoginHandler for CustomLogin {
            async fn handle_login(&self, id: &str) -> BulwarkResult<String> {
                Ok(format!("runtime-{}", id))
            }
        }
        strategy
            .write()
            .register_login_handler(Arc::new(CustomLogin));

        // 替换后立即生效（先 clone Arc 再 await）
        let custom_handler = strategy.read().login_handler().clone();
        let token = custom_handler.handle_login("1001").await.unwrap();
        assert_eq!(token, "runtime-1001", "运行时替换策略后应立即生效");

        BulwarkManager::reset_for_test();
    }

    // ------------------------------------------------------------------------
    // T020: BulwarkManager 注册 DisableRepository 集成测试
    // ------------------------------------------------------------------------

    /// 验证 init 后 `BulwarkManager::disable_repository()` 返回 Some，
    /// 未注册时返回 None。
    ///
    /// 覆盖场景：
    /// - reset_for_test 后（未注册）返回 None
    /// - init 后（已注册）返回 Some
    #[tokio::test]
    #[serial]
    async fn test_manager_registers_disable_repository() {
        BulwarkManager::reset_for_test();

        // 未注册时返回 None
        assert!(
            BulwarkManager::disable_repository().is_none(),
            "未 init 时 disable_repository() 应返回 None"
        );

        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        BulwarkManager::init(dao, config, interface).unwrap();

        // init 后返回 Some
        let repo = BulwarkManager::disable_repository();
        assert!(repo.is_some(), "init 后 disable_repository() 应返回 Some");

        BulwarkManager::reset_for_test();
    }

    /// 验证通过 disable_repository 封禁用户后，check_disable 返回 DisableService 错误。
    #[tokio::test]
    #[serial]
    async fn test_disable_then_check_disable_errors() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        BulwarkManager::init(dao, config, interface).unwrap();

        // login 获取 token
        let token = BulwarkUtil::login_simple("1001").await.unwrap();

        // 通过 disable_repository 封禁用户
        let repo = BulwarkManager::disable_repository().expect("init 后应返回 Some");
        let until = chrono::Utc::now() + chrono::Duration::seconds(3600);
        repo.disable("1001", "default", Some(until), 0, 3600)
            .await
            .unwrap();

        // 在 token 上下文中调用 check_disable 应返回错误
        let result = with_token(token, async { BulwarkUtil::check_disable().await }).await;
        match result {
            Err(BulwarkError::DisableService { service, .. }) => {
                assert_eq!(service, "default");
            },
            other => panic!(
                "封禁后 check_disable 应返回 Err(DisableService)，实际: {:?}",
                other
            ),
        }

        BulwarkManager::reset_for_test();
    }

    /// 验证封禁后解封，check_disable 返回 Ok。
    #[tokio::test]
    #[serial]
    async fn test_untie_disable_then_check_disable_ok() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        BulwarkManager::init(dao, config, interface).unwrap();

        let token = BulwarkUtil::login_simple("1002").await.unwrap();

        // 封禁
        let repo = BulwarkManager::disable_repository().expect("init 后应返回 Some");
        repo.disable("1002", "default", None, 0, 0).await.unwrap();

        // 解封
        repo.untie_disable("1002", "default").await.unwrap();

        // check_disable 应返回 Ok
        let result = with_token(token, async { BulwarkUtil::check_disable().await }).await;
        assert!(
            result.is_ok(),
            "解封后 check_disable 应返回 Ok，实际: {:?}",
            result
        );

        BulwarkManager::reset_for_test();
    }

    /// 验证 disable_repository() 多次调用返回同一实例（Arc 指针相等）。
    #[tokio::test]
    #[serial]
    async fn test_manager_disable_repository_persists() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
        BulwarkManager::init(dao, config, interface).unwrap();

        let repo1 = BulwarkManager::disable_repository().expect("init 后应返回 Some");
        let repo2 = BulwarkManager::disable_repository().expect("init 后应返回 Some");

        assert!(
            Arc::ptr_eq(&repo1, &repo2),
            "disable_repository() 多次调用应返回同一实例（Arc 指针相等）"
        );

        BulwarkManager::reset_for_test();
    }

    // ------------------------------------------------------------------------
    // T030: spawn_cleanup_task 集成到 BulwarkManager::init
    // ------------------------------------------------------------------------

    /// 验证 interval > 0 时 init 后 cleanup task 启动。
    ///
    /// 覆盖场景：`config.token_map_cleanup_interval_secs = 1`（> 0），
    /// init 后 `BULWARK_MANAGER.cleanup_task_handle` 应为 `Some`。
    #[tokio::test]
    #[serial]
    async fn manager_init_positive_interval_starts_cleanup_task() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mut config = make_config();
        config.token_map_cleanup_interval_secs = 1;
        let config = Arc::new(config);
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());

        BulwarkManager::init(dao, config, interface).unwrap();

        assert!(
            BULWARK_MANAGER.cleanup_task_handle.read().is_some(),
            "interval > 0 时 init 后应启动 cleanup task"
        );

        BulwarkManager::reset_for_test();
    }

    /// 验证 interval = -1 时 init 不启动 cleanup task。
    ///
    /// 覆盖场景：`config.token_map_cleanup_interval_secs = -1`（< 0，禁用），
    /// init 后 `BULWARK_MANAGER.cleanup_task_handle` 应为 `None`。
    #[tokio::test]
    #[serial]
    async fn manager_init_negative_interval_no_cleanup_task() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mut config = make_config();
        config.token_map_cleanup_interval_secs = -1;
        let config = Arc::new(config);
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());

        BulwarkManager::init(dao, config, interface).unwrap();

        assert!(
            BULWARK_MANAGER.cleanup_task_handle.read().is_none(),
            "interval = -1 时 init 不应启动 cleanup task"
        );

        BulwarkManager::reset_for_test();
    }

    /// 验证 init 后 cleanup task 实际运行（token 被清理）。
    ///
    /// 策略：init with timeout=1（TTL=1 秒）+ interval=1（每秒清理），
    /// login 创建 token 后等待 3 秒，验证 token 已从 `login_token_map` 移除。
    #[tokio::test]
    #[serial]
    async fn manager_init_cleanup_task_runs_after_init() {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let mut config = make_config();
        config.timeout = 1; // TTL = 1 秒
        config.active_timeout = -1;
        config.token_map_cleanup_interval_secs = 1; // 每秒清理
        let config = Arc::new(config);
        let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());

        BulwarkManager::init(dao, config, interface).unwrap();

        // login 创建 token
        let token = BulwarkUtil::login_simple("1001").await.unwrap();
        assert!(!token.is_empty());

        // 验证 token 存在于 login_token_map
        let logic = BulwarkManager::logic().unwrap();
        assert!(
            logic.session.get_token_by_login_id("1001").is_some(),
            "清理前 token 应存在于 login_token_map"
        );

        // 等待 token TTL 过期 + 至少 2 次清理周期
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;

        // 验证 token 已被 cleanup task 清理
        assert!(
            logic.session.get_token_by_login_id("1001").is_none(),
            "清理后 token 应从 login_token_map 移除"
        );

        BulwarkManager::reset_for_test();
    }

    /// 验证 manager drop 时 cleanup task 被取消。
    ///
    /// 策略：创建局部 `BulwarkManager` 实例，存入 cleanup task handle，
    /// drop 后验证 task 停止运行（计数器不再显著增长）。
    #[tokio::test]
    async fn manager_drop_cancels_cleanup_task() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        // 计数 DAO：get 始终返回 Err，cleanup 每次循环都会调用 get 并计数
        struct CountingDao {
            counter: Arc<AtomicUsize>,
        }
        #[async_trait]
        impl BulwarkDao for CountingDao {
            async fn get(&self, _key: &str) -> BulwarkResult<Option<String>> {
                self.counter.fetch_add(1, Ordering::SeqCst);
                Err(BulwarkError::Dao("test counting".to_string()))
            }
            async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> BulwarkResult<()> {
                Ok(())
            }
            async fn update(&self, _key: &str, _value: &str) -> BulwarkResult<()> {
                Ok(())
            }
            async fn expire(&self, _key: &str, _seconds: u64) -> BulwarkResult<()> {
                Ok(())
            }
            async fn delete(&self, _key: &str) -> BulwarkResult<()> {
                Ok(())
            }
        }

        let counter = Arc::new(AtomicUsize::new(0));
        let dao: Arc<dyn BulwarkDao> = Arc::new(CountingDao {
            counter: counter.clone(),
        });
        let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
        // 添加 token 到 login_token_map，确保 cleanup 有内容可遍历
        session.add_login_token("user1", "token1");

        // 启动 cleanup task
        let handle = spawn_cleanup_task(session, 1).unwrap();

        // 创建局部 manager 并存入 handle
        let manager = BulwarkManager::new();
        *manager.cleanup_task_handle.write() = Some(handle);

        // 等待 2 个 cleanup 周期（tokio::time::interval 首次 tick 立即返回，第二次在 1 秒后）
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let count_before = counter.load(Ordering::SeqCst);
        assert!(
            count_before >= 2,
            "drop 前 cleanup task 应已运行至少 2 次，实际: {}",
            count_before
        );

        // drop manager — 应 abort cleanup task
        drop(manager);

        // 等待 2 个周期，验证 task 已停止（计数不应显著增长）
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let count_after = counter.load(Ordering::SeqCst);
        assert!(
            count_after <= count_before + 1,
            "drop 后 cleanup task 应已取消，计数不应显著增长。before={}, after={}",
            count_before,
            count_after
        );
    }
}
