//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `BulwarkManager` 的实现块（含 `Drop` impl）与 factory selector 辅助函数。
//!
//! 本文件从 `mod.rs` 迁移而来，遵循 mod-crate-hardening（规则 25）：
//! `mod.rs` 仅保留 trait 定义、pub struct/enum、pub type alias、pub use、mod 声明。

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
use parking_lot::RwLock;
use std::sync::Arc;
#[cfg(feature = "anomalous-detector-dual")]
use tokio::sync::watch;

use super::factory::{BulwarkLogicFactoryContext, BulwarkLogicFactoryEntry};
use super::{BulwarkManager, BULWARK_MANAGER};

impl BulwarkManager {
    /// 创建空的管理器实例（仅用于 BULWARK_MANAGER 单例初始化）。
    pub(super) fn new() -> Self {
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
    pub(super) fn init_with_factory_selector(
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
            // -1 表示不启用 activity 超时，使用 timeout 兜底（保留 既有语义）
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
            config.jwt_secret.as_str(),
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
    #[cfg(any(test, feature = "testing"))]
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
