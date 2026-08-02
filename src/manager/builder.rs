//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `GarrisonManagerBuilder`：可组合的初始化入口。
//!
//! 本模块将原 [`GarrisonManager::builder()`](crate::manager::GarrisonManager) 的 4 个职责
//!（构造 5 个内部 manager / 装配 `GarrisonLogicDefault` / 注入全局单例 / 启动后台 task）
//! 拆解为链式 setter + `build()` / `build_explicit()` 两个构造入口：
//!
//! - [`build`](GarrisonManagerBuilder::build)：构造 logic + 注入全局单例 + 启动后台 task
//!   （task handle 归单例，`GarrisonUtil` 静态 API 可用）。
//! - [`build_explicit`](GarrisonManagerBuilder::build_explicit)：构造 logic + 包装为
//!   [`Manager`](crate::manager::explicit::Manager) + 启动后台 task（task handle 归
//!   `Manager`，Drop 时 abort，不触碰全局单例）。
//!
//! 后台 task handle 由 [`TaskHandles`] 统一持有，归属构造方（`build` → 单例，
//! `build_explicit` → `Manager`），Drop 时自动 abort，无单例泄漏。

use crate::account::disable::{DefaultDisableRepository, DisableRepository};
use crate::config::GarrisonConfig;
use crate::core::auth::{AuthLogic, AuthLogicDefault};
use crate::core::permission::{PermissionChecker, PermissionCheckerDefault};
use crate::core::token::TokenStyleFactory;
use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
#[cfg(feature = "listener")]
use crate::listener::GarrisonListenerManager;
#[cfg(feature = "manager-explicit")]
use crate::manager::explicit::Manager;
use crate::manager::factory::{GarrisonLogicFactoryContext, GarrisonLogicFactoryEntry};
use crate::manager::{GarrisonManager, GARRISON_MANAGER};
use crate::plugin::GarrisonPluginManager;
use crate::session::GarrisonSession;
use crate::stp::util::spawn_cleanup_task;
use crate::stp::{GarrisonInterface, GarrisonLogicDefault};
#[cfg(feature = "anomalous-detector-dual")]
use crate::strategy::firewall::{AnomalousAnalyzerConfig, AnomalousLoginAnalyzer};
use crate::strategy::{GarrisonPermissionStrategy, GarrisonPermissionStrategyDefault, Strategy};
use parking_lot::RwLock;
use std::sync::Arc;
#[cfg(feature = "anomalous-detector-dual")]
use tokio::sync::watch;
use tokio::task::JoinHandle;

/// 后台任务句柄集合，由构造方持有（`build` → 单例，`build_explicit` → `Manager`）。
///
/// Drop 时由持有方 abort 对应 task，避免后台线程残留。
pub(crate) struct TaskHandles {
    /// 定期清理过期 token 的 task handle（interval <= 0 时为 None）。
    pub(crate) cleanup: Option<Arc<JoinHandle<()>>>,
    /// 异常登录分析器 task handle（`anomalous-detector-dual` feature 下存在）。
    #[cfg(feature = "anomalous-detector-dual")]
    pub(crate) anomalous: Option<Arc<JoinHandle<()>>>,
    /// 异常登录分析器 shutdown 信号发送端（`anomalous-detector-dual` feature 下存在）。
    ///
    /// 保存 `shutdown_tx` 使其生命周期与持有方一致，
    /// 避免 `shutdown_rx` 因 sender drop 而误触发停止。
    #[cfg(feature = "anomalous-detector-dual")]
    pub(crate) anomalous_shutdown: Option<watch::Sender<bool>>,
}

impl TaskHandles {
    /// 空句柄集合（`Manager::new` 路径使用，不启动任何 task）。
    #[cfg(feature = "manager-explicit")]
    pub(crate) fn empty() -> Self {
        Self {
            cleanup: None,
            #[cfg(feature = "anomalous-detector-dual")]
            anomalous: None,
            #[cfg(feature = "anomalous-detector-dual")]
            anomalous_shutdown: None,
        }
    }
}

/// 可组合的初始化 builder。
///
/// 通过 [`GarrisonManager::builder`] 获取新实例，链式注入必填字段
/// （`dao` / `config` / `interface`）与可选 manager，最后调用
/// [`build`](GarrisonManagerBuilder::build) 或
/// [`build_explicit`](GarrisonManagerBuilder::build_explicit) 完成构造。
pub struct GarrisonManagerBuilder {
    // 必填
    dao: Option<Arc<dyn GarrisonDao>>,
    config: Option<Arc<GarrisonConfig>>,
    interface: Option<Arc<dyn GarrisonInterface>>,
    // 可选（None 表示用默认实现）
    plugin_manager: Option<Arc<GarrisonPluginManager>>,
    #[cfg(feature = "listener")]
    listener_manager: Option<Arc<GarrisonListenerManager>>,
    auth_logic: Option<Arc<dyn AuthLogic>>,
    permission_checker: Option<Arc<dyn PermissionChecker>>,
    disable_repository: Option<Arc<dyn DisableRepository>>,
    // three-tier-cache feature 下的用户缓存服务（None 时若 feature 启用则自动构造）
    #[cfg(feature = "three-tier-cache")]
    user_cache_service: Option<Arc<crate::cache::UserCacheService>>,
    // 扩展点
    factory: Option<&'static GarrisonLogicFactoryEntry>,
}

impl Default for GarrisonManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl GarrisonManagerBuilder {
    /// 创建空的 builder 实例（所有字段为 None）。
    pub fn new() -> Self {
        Self {
            dao: None,
            config: None,
            interface: None,
            plugin_manager: None,
            #[cfg(feature = "listener")]
            listener_manager: None,
            auth_logic: None,
            permission_checker: None,
            disable_repository: None,
            #[cfg(feature = "three-tier-cache")]
            user_cache_service: None,
            factory: None,
        }
    }

    /// 注入 DAO 引用（必填）。
    pub fn dao(mut self, dao: Arc<dyn GarrisonDao>) -> Self {
        self.dao = Some(dao);
        self
    }

    /// 注入全局配置（必填）。
    pub fn config(mut self, config: Arc<GarrisonConfig>) -> Self {
        self.config = Some(config);
        self
    }

    /// 注入权限数据回调（必填）。
    pub fn interface(mut self, interface: Arc<dyn GarrisonInterface>) -> Self {
        self.interface = Some(interface);
        self
    }

    /// 注入插件管理器（可选；None 时使用 `GarrisonPluginManager::new()` 默认实现）。
    pub fn with_plugin_manager(mut self, pm: Arc<GarrisonPluginManager>) -> Self {
        self.plugin_manager = Some(pm);
        self
    }

    /// 注入监听器管理器（可选，需 `listener` feature；None 时使用 `GarrisonListenerManager::new()` 默认实现）。
    #[cfg(feature = "listener")]
    pub fn with_listener_manager(mut self, lm: Arc<GarrisonListenerManager>) -> Self {
        self.listener_manager = Some(lm);
        self
    }

    /// 注入认证逻辑（可选；None 时使用 `AuthLogicDefault` 默认实现）。
    pub fn with_auth_logic(mut self, al: Arc<dyn AuthLogic>) -> Self {
        self.auth_logic = Some(al);
        self
    }

    /// 注入权限校验器（可选；None 时使用 `PermissionCheckerDefault` 默认实现）。
    pub fn with_permission_checker(mut self, pc: Arc<dyn PermissionChecker>) -> Self {
        self.permission_checker = Some(pc);
        self
    }

    /// 注入封禁库（可选；None 时使用 `DefaultDisableRepository` 默认实现）。
    pub fn with_disable_repository(mut self, dr: Arc<dyn DisableRepository>) -> Self {
        self.disable_repository = Some(dr);
        self
    }

    /// 注入用户缓存服务（可选，需 `three-tier-cache` feature；None 时若 feature 启用则自动构造）。
    #[cfg(feature = "three-tier-cache")]
    pub fn with_user_cache_service(mut self, ucs: Arc<crate::cache::UserCacheService>) -> Self {
        self.user_cache_service = Some(ucs);
        self
    }

    /// 注入自定义 factory entry（可选扩展点）。
    ///
    /// 注入后 `build` / `build_explicit` 使用 `entry.factory` 构造 `GarrisonLogicDefault`；
    /// 否则使用 `inventory` 中注册的默认 factory，无 entry 时走 builder 链兜底。
    pub fn with_factory(mut self, entry: &'static GarrisonLogicFactoryEntry) -> Self {
        self.factory = Some(entry);
        self
    }

    /// 构造 logic + 注入全局单例 + 启动后台 task。
    ///
    /// task handle 归 `GARRISON_MANAGER` 单例，`GarrisonUtil` 静态 API 可用。
    ///
    /// # 错误
    /// - 必填字段缺失（dao/config/interface 任一为 None）：`GarrisonError::Config`
    /// - 配置非法：透传 `config.validate()` 的错误
    /// - factory 构造失败：透传 factory 返回的 `GarrisonError`
    pub async fn build(self) -> GarrisonResult<()> {
        let (logic, task_handles) = self.build_logic()?;

        // 覆盖式更新全局单例（允许重复 build，便于测试）
        let strategy = Arc::new(RwLock::new(Strategy::new(logic.clone())));
        GARRISON_MANAGER.logic.store(Some(logic));
        GARRISON_MANAGER.strategy.store(Some(strategy));

        // 先 abort 旧 cleanup task 再保存新 handle，避免短暂重叠窗口
        if let Some(old) = GARRISON_MANAGER.cleanup_task_handle.write().take() {
            old.abort();
        }
        *GARRISON_MANAGER.cleanup_task_handle.write() = task_handles.cleanup;

        #[cfg(feature = "anomalous-detector-dual")]
        {
            // 先 abort 旧 analyzer task
            if let Some(old) = GARRISON_MANAGER.anomalous_analyzer_handle.write().take() {
                old.abort();
            }
            // 清空旧 shutdown_tx（drop 后 shutdown_rx.changed() 返回 Err，task 退出）
            GARRISON_MANAGER
                .anomalous_analyzer_shutdown_tx
                .write()
                .take();
            *GARRISON_MANAGER.anomalous_analyzer_handle.write() = task_handles.anomalous;
            *GARRISON_MANAGER.anomalous_analyzer_shutdown_tx.write() =
                task_handles.anomalous_shutdown;
        }

        Ok(())
    }

    /// 构造 logic + 包装为 [`Manager`] + 启动后台 task。
    ///
    /// **不写入 `GARRISON_MANAGER` 全局单例**，task handle 归返回的 `Manager` 持有，
    /// `Manager` Drop 时 abort 所有后台 task。用于多实例 / 测试隔离场景。
    ///
    /// 与 [`Manager::new`](crate::manager::explicit::Manager::new) 的区别：
    /// `build_explicit` 完整构造 logic + 启动后台 task（task_handles 非空，Drop 时 abort）；
    /// `Manager::new` 仅包装已构造的 logic，不启动 task（task_handles 为空）。
    ///
    /// # GarrisonUtil 限制
    ///
    /// `build_explicit()` 不写入全局单例，因此 `GarrisonUtil` 静态 API
    /// （`login` / `logout` / `check_login` 等，委托 [`GarrisonManager::logic`]）
    /// 在此路径下返回 `GarrisonError::Session("manager-not-init")`。
    /// 调用方应通过返回的 `Manager` 实例方法（如 `manager.logic.login(...)`）操作，
    /// 而非 `GarrisonUtil` 静态 API。
    ///
    /// # 错误
    /// - 必填字段缺失（dao/config/interface 任一为 None）：`GarrisonError::Config`
    /// - 配置非法：透传 `config.validate()` 的错误
    /// - factory 构造失败：透传 factory 返回的 `GarrisonError`
    #[cfg(feature = "manager-explicit")]
    pub async fn build_explicit(self) -> GarrisonResult<Manager> {
        let (logic, task_handles) = self.build_logic()?;
        Ok(Manager::with_task_handles(logic, task_handles))
    }

    /// 构造 `GarrisonLogicDefault` + 启动后台 task，返回 logic 与 task handle 集合。
    ///
    /// 校验 config + 构造 session + 装配 5 个内部 manager + 通过 factory 或 builder 链
    /// 构造 logic + 启动 cleanup_task 与 anomalous_analyzer_task。
    /// 此方法不触碰全局单例，由 `build` / `build_explicit` 决定注入目标。
    fn build_logic(self) -> GarrisonResult<(Arc<GarrisonLogicDefault>, TaskHandles)> {
        // 1. fail-closed：必填字段缺失即返回，不构造任何 manager 或 task
        let dao = self
            .dao
            .ok_or_else(|| GarrisonError::Config("builder-dao-missing".to_string()))?;
        let config = self
            .config
            .ok_or_else(|| GarrisonError::Config("builder-config-missing".to_string()))?;
        let interface = self
            .interface
            .ok_or_else(|| GarrisonError::Config("builder-interface-missing".to_string()))?;

        // 2. 校验配置
        config.validate()?;

        // 3. 构造 session（处理 active_timeout = -1 的兜底语义）
        let timeout = u64::try_from(config.timeout).map_err(|_| {
            GarrisonError::Config(format!("manager-timeout-overflow::{}", config.timeout))
        })?;
        let active_timeout = if config.active_timeout < 0 {
            // -1 表示不启用 activity 超时，使用 timeout 兜底（保留既有语义）
            timeout
        } else {
            u64::try_from(config.active_timeout).map_err(|_| {
                GarrisonError::Config(format!(
                    "manager-active-timeout-overflow::{}",
                    config.active_timeout
                ))
            })?
        };
        let session = Arc::new(GarrisonSession::new(dao.clone(), timeout, active_timeout));

        // 4. auto-wire：构造 5 个 manager（builder 字段为 Some 用注入值，None 用默认实现）
        // 4.1 PermissionChecker（委托 interface 查询权限/角色数据）
        let permission_checker: Arc<dyn PermissionChecker> = match self.permission_checker {
            Some(pc) => pc,
            None => Arc::new(PermissionCheckerDefault::new(interface.clone())),
        };
        // 4.2 PluginManager（通过 inventory 收集编译期注册的插件）
        let plugin_manager = match self.plugin_manager {
            Some(pm) => pm,
            None => Arc::new(GarrisonPluginManager::new()),
        };
        // 4.3 ListenerManager（通过 inventory 收集编译期注册的监听器，需 listener feature）
        #[cfg(feature = "listener")]
        let listener_manager = match self.listener_manager {
            Some(lm) => lm,
            None => Arc::new(GarrisonListenerManager::new()),
        };
        // 4.4 AuthLogic（委托 session + token_handler 实现登录/校验）
        let token_handler: Arc<dyn crate::core::token::Token> = Arc::from(TokenStyleFactory::new(
            &config.token_style,
            config.jwt_secret.as_str(),
        )?);
        let auth_logic: Arc<dyn AuthLogic> = match self.auth_logic {
            Some(al) => al,
            None => Arc::new(AuthLogicDefault::new(
                session.clone(),
                token_handler,
                config.timeout,
            )),
        };

        // 5. 构造 firewall，注入 permission_checker + plugin_manager
        let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(
            GarrisonPermissionStrategyDefault::new(interface)
                .with_permission_checker(permission_checker.clone())
                .with_plugin_manager(plugin_manager.clone()),
        );

        // 6. 构造 disable_repository（委托同一 DAO 实例持久化封禁条目）
        let disable_repo = match self.disable_repository {
            Some(dr) => dr,
            None => Arc::new(DefaultDisableRepository::new(dao.clone())),
        };

        // 7. three-tier-cache feature 启用时构造 UserCacheService（复用 dao + firewall）
        #[cfg(feature = "three-tier-cache")]
        let user_cache_service = match self.user_cache_service {
            Some(ucs) => ucs,
            None => Arc::new(crate::cache::UserCacheService::new(
                dao.clone(),
                firewall.clone(),
                config.l1_cache_ttl_secs,
                config.l2_cache_ttl_secs,
                config.l1_cache_capacity,
            )?),
        };

        // 8. 构造 factory context（持有 5 个 manager 引用）
        #[cfg(feature = "listener")]
        let factory_ctx = GarrisonLogicFactoryContext {
            plugin_manager: Some(plugin_manager.clone()),
            listener_manager: Some(listener_manager.clone()),
            auth_logic: Some(auth_logic.clone()),
            permission_checker: Some(permission_checker.clone()),
            disable_repository: Some(disable_repo.clone()),
            #[cfg(feature = "three-tier-cache")]
            user_cache_service: Some(user_cache_service.clone()),
        };
        #[cfg(not(feature = "listener"))]
        let factory_ctx = GarrisonLogicFactoryContext {
            plugin_manager: Some(plugin_manager.clone()),
            auth_logic: Some(auth_logic.clone()),
            permission_checker: Some(permission_checker.clone()),
            disable_repository: Some(disable_repo.clone()),
            #[cfg(feature = "three-tier-cache")]
            user_cache_service: Some(user_cache_service.clone()),
        };

        // 9. clone listener_manager 和 dao 给 analyzer，读取 config 值（均在 move 之前）
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

        // 10. 通过 factory 构造 logic（builder 字段优先，否则 inventory 默认，最后 builder 链兜底）
        let factory_entry = self.factory.or_else(default_factory_selector);
        let logic: Arc<GarrisonLogicDefault> = match factory_entry {
            Some(entry) => (entry.factory)(
                session.clone(),
                config.clone(),
                firewall.clone(),
                &factory_ctx,
            )?,
            None => Self::build_logic_via_builder_chain(
                session.clone(),
                config.clone(),
                firewall.clone(),
                plugin_manager,
                auth_logic,
                permission_checker,
                disable_repo,
                #[cfg(feature = "listener")]
                listener_manager,
                #[cfg(feature = "three-tier-cache")]
                user_cache_service,
            ),
        };

        // 11. 启动后台 cleanup task（interval_secs <= 0 时返回 None，不启动）
        let cleanup_handle =
            spawn_cleanup_task(session, config.token_map_cleanup_interval_secs).map(Arc::new);

        // 12. 启动异常登录分析器 task（anomalous-detector-dual feature）
        #[cfg(feature = "anomalous-detector-dual")]
        let (anomalous_handle, anomalous_shutdown) = {
            // 创建 shutdown channel
            let (shutdown_tx, shutdown_rx) = watch::channel(false);

            // 从 GarrisonConfig 构造 analyzer config
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
            let analyzer_handle = Arc::new(analyzer.start());

            (analyzer_handle, shutdown_tx)
        };

        // 13. 装配 task handle 集合，交由构造方持有
        let task_handles = TaskHandles {
            cleanup: cleanup_handle,
            #[cfg(feature = "anomalous-detector-dual")]
            anomalous: Some(anomalous_handle),
            #[cfg(feature = "anomalous-detector-dual")]
            anomalous_shutdown: Some(anomalous_shutdown),
        };

        Ok((logic, task_handles))
    }

    /// 兜底路径：无 factory entry 时直接通过 builder 链构造 `GarrisonLogicDefault`。
    ///
    /// 提取为独立私有函数，便于 T035b 单元测试兜底逻辑本身（不依赖 inventory 全局状态）。
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(
        not(any(feature = "listener", feature = "three-tier-cache")),
        allow(unused_mut)
    )]
    fn build_logic_via_builder_chain(
        session: Arc<GarrisonSession>,
        config: Arc<GarrisonConfig>,
        firewall: Arc<dyn GarrisonPermissionStrategy>,
        plugin_manager: Arc<GarrisonPluginManager>,
        auth_logic: Arc<dyn AuthLogic>,
        permission_checker: Arc<dyn PermissionChecker>,
        disable_repo: Arc<dyn DisableRepository>,
        #[cfg(feature = "listener")] listener_manager: Arc<GarrisonListenerManager>,
        #[cfg(feature = "three-tier-cache")] user_cache_service: Arc<
            crate::cache::UserCacheService,
        >,
    ) -> Arc<GarrisonLogicDefault> {
        let mut builder = GarrisonLogicDefault::new(session, config, firewall)
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
    }
}

impl GarrisonManager {
    /// 获取可组合的初始化 builder。
    ///
    /// 返回所有字段为 None 的新 builder，通过链式 setter 注入依赖后调用
    /// [`build`](GarrisonManagerBuilder::build) 或
    /// [`build_explicit`](GarrisonManagerBuilder::build_explicit) 完成构造。
    pub fn builder() -> GarrisonManagerBuilder {
        GarrisonManagerBuilder::new()
    }
}

/// 默认 factory selector：从 inventory 中找到第一个注册的 `GarrisonLogicFactoryEntry`。
///
/// 若无 entry 注册，返回 `None`，由 `build_logic` 兜底使用 builder 链构造 `GarrisonLogicDefault`。
fn default_factory_selector() -> Option<&'static GarrisonLogicFactoryEntry> {
    use std::iter::Iterator;
    inventory::iter::<GarrisonLogicFactoryEntry>().next()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::GarrisonConfig;
    use crate::dao::tests::MockDao;
    use crate::dao::GarrisonDao;
    use crate::manager::mock::MockInterface;
    use crate::session::GarrisonSession;
    use crate::stp::GarrisonInterface;
    use async_trait::async_trait;
    use serial_test::serial;
    use std::sync::Arc;

    // ------------------------------------------------------------------------
    // 测试辅助
    // ------------------------------------------------------------------------

    fn make_config() -> GarrisonConfig {
        let mut config = GarrisonConfig::default_config();
        config.timeout = 3600;
        config.active_timeout = -1;
        config.throw_on_not_login = false;
        config
    }

    fn make_dao() -> Arc<dyn GarrisonDao> {
        Arc::new(MockDao::new())
    }

    fn make_interface() -> Arc<dyn GarrisonInterface> {
        Arc::new(MockInterface::new())
    }

    fn make_default_builder() -> GarrisonManagerBuilder {
        GarrisonManagerBuilder::new()
    }

    /// 构造带必填字段的 builder（用于 build/build_explicit 测试）。
    fn make_ready_builder() -> GarrisonManagerBuilder {
        GarrisonManagerBuilder::new()
            .dao(make_dao())
            .config(Arc::new(make_config()))
            .interface(make_interface())
    }

    /// 等待 task 被 abort 后 is_finished() 返回 true。
    #[cfg(feature = "manager-explicit")]
    async fn wait_finished(handle: &JoinHandle<()>) {
        for _ in 0..100 {
            if handle.is_finished() {
                return;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    // ------------------------------------------------------------------------
    // 测试用 mock（AuthLogic / PermissionChecker / DisableRepository）
    // ------------------------------------------------------------------------

    #[derive(Clone)]
    struct MockAuthLogic;

    #[async_trait]
    impl AuthLogic for MockAuthLogic {
        async fn login(&self, id: &str, _params: Option<&str>) -> GarrisonResult<String> {
            Ok(format!("mock-token-{}", id))
        }
        async fn logout(&self, _token: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn is_login(&self, _token: &str) -> GarrisonResult<bool> {
            Ok(true)
        }
        async fn get_login_id(&self, _token: &str) -> GarrisonResult<Option<String>> {
            Ok(Some("mock-user".to_string()))
        }
        async fn verify_token(&self, _token: &str) -> GarrisonResult<String> {
            Ok("mock-user".to_string())
        }
    }

    #[derive(Clone)]
    struct MockPermissionChecker;

    #[async_trait]
    impl PermissionChecker for MockPermissionChecker {
        async fn has_permission(&self, _login_id: &str, _permission: &str) -> GarrisonResult<bool> {
            Ok(true)
        }
        async fn has_role(&self, _login_id: &str, _role: &str) -> GarrisonResult<bool> {
            Ok(true)
        }
        async fn has_any_permission(&self, _login_id: &str, _perms: &[&str]) -> bool {
            true
        }
        async fn has_all_permissions(&self, _login_id: &str, _perms: &[&str]) -> bool {
            true
        }
    }

    #[derive(Clone)]
    struct MockDisableRepository;

    #[async_trait]
    impl DisableRepository for MockDisableRepository {
        async fn disable(
            &self,
            _login_id: &str,
            _service: &str,
            _until: Option<chrono::DateTime<chrono::Utc>>,
            _level: u32,
            _duration_secs: u64,
        ) -> GarrisonResult<()> {
            Ok(())
        }
        async fn untie_disable(&self, _login_id: &str, _service: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn is_disable(&self, _login_id: &str, _service: &str) -> GarrisonResult<bool> {
            Ok(false)
        }
        async fn get_disable_time(
            &self,
            _login_id: &str,
            _service: &str,
        ) -> GarrisonResult<Option<chrono::DateTime<chrono::Utc>>> {
            Ok(None)
        }
        async fn get_disable_level(
            &self,
            _login_id: &str,
            _service: &str,
        ) -> GarrisonResult<Option<u32>> {
            Ok(None)
        }
    }

    /// 计数 DAO：get 返回 Err 并计数，用于验证 cleanup task 是否仍在运行。
    #[cfg(feature = "manager-explicit")]
    struct CountingDao {
        counter: Arc<std::sync::atomic::AtomicUsize>,
    }

    #[cfg(feature = "manager-explicit")]
    #[async_trait]
    impl GarrisonDao for CountingDao {
        async fn get(&self, _key: &str) -> GarrisonResult<Option<String>> {
            self.counter
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(GarrisonError::Dao("test counting".to_string()))
        }
        async fn set(&self, _key: &str, _value: &str, _ttl_seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }
        async fn update(&self, _key: &str, _value: &str) -> GarrisonResult<()> {
            Ok(())
        }
        async fn expire(&self, _key: &str, _seconds: u64) -> GarrisonResult<()> {
            Ok(())
        }
        async fn delete(&self, _key: &str) -> GarrisonResult<()> {
            Ok(())
        }
    }

    // ------------------------------------------------------------------------
    // T002: new() 与 9 个链式 setter
    // ------------------------------------------------------------------------

    #[test]
    fn builder_new_all_fields_none() {
        let b = make_default_builder();
        assert!(b.dao.is_none());
        assert!(b.config.is_none());
        assert!(b.interface.is_none());
        assert!(b.plugin_manager.is_none());
        #[cfg(feature = "listener")]
        assert!(b.listener_manager.is_none());
        assert!(b.auth_logic.is_none());
        assert!(b.permission_checker.is_none());
        assert!(b.disable_repository.is_none());
        #[cfg(feature = "three-tier-cache")]
        assert!(b.user_cache_service.is_none());
        assert!(b.factory.is_none());
    }

    #[test]
    fn builder_setters_set_fields() {
        let dao = make_dao();
        let config = Arc::new(make_config());
        let interface = make_interface();
        let pm = Arc::new(crate::plugin::GarrisonPluginManager::new());
        #[cfg(feature = "listener")]
        let lm = Arc::new(crate::listener::GarrisonListenerManager::new());
        let auth: Arc<dyn AuthLogic> = Arc::new(MockAuthLogic);
        let pc: Arc<dyn PermissionChecker> = Arc::new(MockPermissionChecker);
        let dr: Arc<dyn DisableRepository> = Arc::new(MockDisableRepository);

        let mut b = make_default_builder();
        b = b
            .dao(dao)
            .config(config)
            .interface(interface)
            .with_plugin_manager(pm)
            .with_auth_logic(auth)
            .with_permission_checker(pc)
            .with_disable_repository(dr);
        #[cfg(feature = "listener")]
        {
            b = b.with_listener_manager(lm);
        }
        #[cfg(feature = "three-tier-cache")]
        {
            let dao2 = make_dao();
            let fw: Arc<dyn GarrisonPermissionStrategy> =
                Arc::new(GarrisonPermissionStrategyDefault::new(make_interface()));
            let ucs =
                Arc::new(crate::cache::UserCacheService::new(dao2, fw, 60, 3600, 10000).unwrap());
            b = b.with_user_cache_service(ucs);
        }

        assert!(b.dao.is_some());
        assert!(b.config.is_some());
        assert!(b.interface.is_some());
        assert!(b.plugin_manager.is_some());
        #[cfg(feature = "listener")]
        assert!(b.listener_manager.is_some());
        assert!(b.auth_logic.is_some());
        assert!(b.permission_checker.is_some());
        assert!(b.disable_repository.is_some());
        #[cfg(feature = "three-tier-cache")]
        assert!(b.user_cache_service.is_some());
        assert!(b.factory.is_none());
    }

    // ------------------------------------------------------------------------
    // T004: with_factory setter
    // ------------------------------------------------------------------------

    #[test]
    fn builder_with_factory_sets_field() {
        static TEST_ENTRY: GarrisonLogicFactoryEntry = GarrisonLogicFactoryEntry {
            name: "test-factory-setter",
            factory: crate::manager::factory::garrison_logic_factory_default,
        };
        let b = make_default_builder().with_factory(&TEST_ENTRY);
        assert!(b.factory.is_some());
        assert_eq!(b.factory.unwrap().name, "test-factory-setter");
    }

    // ------------------------------------------------------------------------
    // T005: build() 注入全局单例
    // ------------------------------------------------------------------------

    #[tokio::test]
    #[serial]
    async fn build_injects_global_singleton() {
        GarrisonManager::reset_for_test();
        let result = make_ready_builder().build().await;
        assert!(result.is_ok(), "build 应成功: {:?}", result.map(|_| ()));
        assert!(GarrisonManager::is_initialized());
        GarrisonManager::reset_for_test();
    }

    // ------------------------------------------------------------------------
    // T007 / T032: build_explicit() 返回独立 Manager，Drop 后 task 被 abort
    // ------------------------------------------------------------------------

    #[cfg(feature = "manager-explicit")]
    #[tokio::test]
    #[serial]
    async fn build_explicit_returns_independent_manager() {
        GarrisonManager::reset_for_test();
        let manager = make_ready_builder().build_explicit().await;
        assert!(
            manager.is_ok(),
            "build_explicit 应成功: {:?}",
            manager.err()
        );
        assert!(
            !GarrisonManager::is_initialized(),
            "build_explicit 不应触碰全局单例"
        );
        drop(manager);
        assert!(!GarrisonManager::is_initialized());
    }

    #[cfg(feature = "manager-explicit")]
    #[tokio::test]
    async fn build_explicit_drop_aborts_tasks() {
        let mut config = make_config();
        config.token_map_cleanup_interval_secs = 1;
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dao: Arc<dyn GarrisonDao> = Arc::new(CountingDao {
            counter: counter.clone(),
        });
        let builder = GarrisonManagerBuilder::new()
            .dao(dao)
            .config(Arc::new(config))
            .interface(make_interface());
        let (logic, task_handles) = builder.build_logic().unwrap();

        let cleanup_handle = task_handles.cleanup.clone().unwrap();
        #[cfg(feature = "anomalous-detector-dual")]
        let anomalous_handle = task_handles.anomalous.clone().unwrap();
        #[cfg(feature = "anomalous-detector-dual")]
        let anomalous_shutdown = task_handles.anomalous_shutdown.clone();

        let manager = Manager::with_task_handles(logic, task_handles);
        assert!(
            !cleanup_handle.is_finished(),
            "build 后 cleanup task 应运行中"
        );

        // 直接向 session 注入 token，使 cleanup 遍历 login_token_map 并调用 dao.get（计数）。
        // 不通过 login：CountingDao.get 返回 Err，login 会失败。
        manager.logic.session.add_login_token("1001", "token1");
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let count_before = counter.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            count_before >= 1,
            "drop 前 cleanup task 应已运行（计数>=1）"
        );

        // 保留 shutdown_tx 引用使 manager Drop 后能通过 abort 终止 analyzer
        drop(manager);

        wait_finished(&cleanup_handle).await;
        assert!(
            cleanup_handle.is_finished(),
            "Manager Drop 后 cleanup task 应被 abort"
        );
        #[cfg(feature = "anomalous-detector-dual")]
        {
            wait_finished(&anomalous_handle).await;
            assert!(
                anomalous_handle.is_finished(),
                "Manager Drop 后 anomalous task 应被 abort"
            );
            drop(anomalous_shutdown);
        }

        // 验证 cleanup task 已停止（计数不再增长）
        let count_mid = counter.load(std::sync::atomic::Ordering::SeqCst);
        tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
        let count_after = counter.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            count_after <= count_mid + 1,
            "abort 后 cleanup task 不应继续运行。mid={}, after={}",
            count_mid,
            count_after
        );
    }

    // ------------------------------------------------------------------------
    // T009: 5 个 with_* manager 注入
    // ------------------------------------------------------------------------

    #[tokio::test]
    #[serial]
    async fn build_injects_plugin_manager() {
        GarrisonManager::reset_for_test();
        let pm = Arc::new(crate::plugin::GarrisonPluginManager::new());
        make_ready_builder()
            .with_plugin_manager(pm.clone())
            .build()
            .await
            .unwrap();
        let logic = GarrisonManager::logic().unwrap();
        assert!(
            Arc::ptr_eq(logic.plugin_manager.as_ref().unwrap(), &pm),
            "build 后 plugin_manager 应为注入实例"
        );
        GarrisonManager::reset_for_test();
    }

    #[cfg(feature = "listener")]
    #[tokio::test]
    #[serial]
    async fn build_injects_listener_manager() {
        GarrisonManager::reset_for_test();
        let lm = Arc::new(crate::listener::GarrisonListenerManager::new());
        make_ready_builder()
            .with_listener_manager(lm.clone())
            .build()
            .await
            .unwrap();
        let logic = GarrisonManager::logic().unwrap();
        assert!(
            Arc::ptr_eq(logic.listener_manager.as_ref().unwrap(), &lm),
            "build 后 listener_manager 应为注入实例"
        );
        GarrisonManager::reset_for_test();
    }

    #[tokio::test]
    #[serial]
    async fn build_injects_auth_logic() {
        GarrisonManager::reset_for_test();
        let al: Arc<dyn AuthLogic> = Arc::new(MockAuthLogic);
        make_ready_builder()
            .with_auth_logic(al.clone())
            .build()
            .await
            .unwrap();
        let logic = GarrisonManager::logic().unwrap();
        assert!(
            Arc::ptr_eq(&logic.auth_logic.as_ref().unwrap().clone(), &al),
            "build 后 auth_logic 应为注入实例"
        );
        GarrisonManager::reset_for_test();
    }

    #[tokio::test]
    #[serial]
    async fn build_injects_permission_checker() {
        GarrisonManager::reset_for_test();
        let pc: Arc<dyn PermissionChecker> = Arc::new(MockPermissionChecker);
        make_ready_builder()
            .with_permission_checker(pc.clone())
            .build()
            .await
            .unwrap();
        let logic = GarrisonManager::logic().unwrap();
        assert!(
            Arc::ptr_eq(&logic.permission_checker.as_ref().unwrap().clone(), &pc),
            "build 后 permission_checker 应为注入实例"
        );
        GarrisonManager::reset_for_test();
    }

    #[tokio::test]
    #[serial]
    async fn build_injects_disable_repository() {
        GarrisonManager::reset_for_test();
        let dr: Arc<dyn DisableRepository> = Arc::new(MockDisableRepository);
        make_ready_builder()
            .with_disable_repository(dr.clone())
            .build()
            .await
            .unwrap();
        let logic = GarrisonManager::logic().unwrap();
        assert!(
            Arc::ptr_eq(&logic.disable_repository.as_ref().unwrap().clone(), &dr),
            "build 后 disable_repository 应为注入实例"
        );
        GarrisonManager::reset_for_test();
    }

    // ------------------------------------------------------------------------
    // T010b: build_explicit() 路径下 GarrisonUtil 契约
    // ------------------------------------------------------------------------

    #[cfg(feature = "manager-explicit")]
    #[tokio::test]
    #[serial]
    async fn build_explicit_garrison_util_returns_manager_not_init() {
        GarrisonManager::reset_for_test();
        let _manager = make_ready_builder().build_explicit().await.unwrap();
        let result = crate::stp::GarrisonUtil::login_simple("1001").await;
        assert!(
            matches!(
                result,
                Err(GarrisonError::Session(ref msg)) if msg.contains("manager-not-init")
            ),
            "build_explicit 路径下 GarrisonUtil 应返回 manager-not-init，实际: {:?}",
            result.map(|_| ())
        );
        drop(_manager);
        GarrisonManager::reset_for_test();
    }

    #[tokio::test]
    #[serial]
    async fn build_garrison_util_works_normally() {
        GarrisonManager::reset_for_test();
        make_ready_builder().build().await.unwrap();
        let token = crate::stp::GarrisonUtil::login_simple("1001").await;
        assert!(token.is_ok(), "build 路径下 GarrisonUtil 应正常工作");
        GarrisonManager::reset_for_test();
    }

    // ------------------------------------------------------------------------
    // T033: build() 后 cleanup_task_handle 状态
    // ------------------------------------------------------------------------

    #[tokio::test]
    #[serial]
    async fn build_sets_cleanup_task_handle() {
        GarrisonManager::reset_for_test();
        let mut config = make_config();
        config.token_map_cleanup_interval_secs = 1;
        let builder = GarrisonManagerBuilder::new()
            .dao(make_dao())
            .config(Arc::new(config))
            .interface(make_interface());
        builder.build().await.unwrap();
        assert!(
            GARRISON_MANAGER.cleanup_task_handle.read().is_some(),
            "interval > 0 时 build 后应持有 cleanup task handle"
        );
        GarrisonManager::reset_for_test();
        assert!(
            GARRISON_MANAGER.cleanup_task_handle.read().is_none(),
            "reset_for_test 后 cleanup task handle 应为 None"
        );
    }

    // ------------------------------------------------------------------------
    // T034: 必填字段缺失 fail-closed
    // ------------------------------------------------------------------------

    #[tokio::test]
    #[serial]
    async fn build_missing_dao_fails_closed() {
        GarrisonManager::reset_for_test();
        let builder = GarrisonManagerBuilder::new()
            .config(Arc::new(make_config()))
            .interface(make_interface());
        let result = builder.build().await;
        assert!(
            matches!(result, Err(GarrisonError::Config(ref m)) if m == "builder-dao-missing"),
            "dao=None 应返回 builder-dao-missing，实际: {:?}",
            result.map(|_| ())
        );
        assert!(!GarrisonManager::is_initialized(), "失败后单例不应被初始化");
        GarrisonManager::reset_for_test();
    }

    #[tokio::test]
    #[serial]
    async fn build_missing_config_fails_closed() {
        GarrisonManager::reset_for_test();
        let builder = GarrisonManagerBuilder::new()
            .dao(make_dao())
            .interface(make_interface());
        let result = builder.build().await;
        assert!(
            matches!(result, Err(GarrisonError::Config(ref m)) if m == "builder-config-missing"),
            "config=None 应返回 builder-config-missing，实际: {:?}",
            result.map(|_| ())
        );
        assert!(!GarrisonManager::is_initialized());
        GarrisonManager::reset_for_test();
    }

    #[tokio::test]
    #[serial]
    async fn build_missing_interface_fails_closed() {
        GarrisonManager::reset_for_test();
        let builder = GarrisonManagerBuilder::new()
            .dao(make_dao())
            .config(Arc::new(make_config()));
        let result = builder.build().await;
        assert!(
            matches!(result, Err(GarrisonError::Config(ref m)) if m == "builder-interface-missing"),
            "interface=None 应返回 builder-interface-missing，实际: {:?}",
            result.map(|_| ())
        );
        assert!(!GarrisonManager::is_initialized());
        GarrisonManager::reset_for_test();
    }

    // ------------------------------------------------------------------------
    // T035: with_factory 自定义 factory 构造 logic
    // ------------------------------------------------------------------------

    static TEST_MARKER_ENTRY: GarrisonLogicFactoryEntry = GarrisonLogicFactoryEntry {
        name: "test-marker",
        factory: test_marker_factory,
    };

    fn test_marker_factory(
        session: Arc<GarrisonSession>,
        config: Arc<GarrisonConfig>,
        firewall: Arc<dyn GarrisonPermissionStrategy>,
        ctx: &GarrisonLogicFactoryContext,
    ) -> GarrisonResult<Arc<GarrisonLogicDefault>> {
        let mut builder = GarrisonLogicDefault::new(session, config, firewall);
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
        Ok(Arc::new(builder.with_marker("custom-factory")))
    }

    #[tokio::test]
    #[serial]
    async fn build_with_factory_uses_custom_marker() {
        GarrisonManager::reset_for_test();
        make_ready_builder()
            .with_factory(&TEST_MARKER_ENTRY)
            .build()
            .await
            .unwrap();
        let logic = GarrisonManager::logic().unwrap();
        assert_eq!(
            logic.marker,
            Some("custom-factory"),
            "with_factory 应使用自定义 factory 构造 logic"
        );
        GarrisonManager::reset_for_test();
    }

    // ------------------------------------------------------------------------
    // T035a: three-tier-cache 注入与自动构造
    // ------------------------------------------------------------------------

    #[cfg(feature = "three-tier-cache")]
    #[tokio::test]
    #[serial]
    async fn build_injects_user_cache_service() {
        GarrisonManager::reset_for_test();
        let fw: Arc<dyn GarrisonPermissionStrategy> =
            Arc::new(GarrisonPermissionStrategyDefault::new(make_interface()));
        let custom_ucs =
            Arc::new(crate::cache::UserCacheService::new(make_dao(), fw, 60, 3600, 10000).unwrap());
        make_ready_builder()
            .with_user_cache_service(custom_ucs.clone())
            .build()
            .await
            .unwrap();
        let logic = GarrisonManager::logic().unwrap();
        assert!(
            Arc::ptr_eq(logic.user_cache_service.as_ref().unwrap(), &custom_ucs),
            "build 后 user_cache_service 应为注入实例"
        );
        GarrisonManager::reset_for_test();
    }

    #[cfg(feature = "three-tier-cache")]
    #[tokio::test]
    #[serial]
    async fn build_auto_constructs_user_cache_service() {
        GarrisonManager::reset_for_test();
        make_ready_builder().build().await.unwrap();
        let logic = GarrisonManager::logic().unwrap();
        assert!(
            logic.user_cache_service.is_some(),
            "three-tier-cache feature 下未注入时 build 应自动构造 user_cache_service"
        );
        GarrisonManager::reset_for_test();
    }

    // ------------------------------------------------------------------------
    // T035b: build_logic_via_builder_chain 兜底逻辑
    // ------------------------------------------------------------------------

    #[tokio::test]
    async fn build_logic_via_builder_chain_constructs_default_managers() {
        let dao = make_dao();
        let config = Arc::new(make_config());
        let interface = make_interface();
        let timeout = u64::try_from(config.timeout).unwrap();
        let session = Arc::new(GarrisonSession::new(dao, timeout, timeout));
        let firewall: Arc<dyn GarrisonPermissionStrategy> =
            Arc::new(GarrisonPermissionStrategyDefault::new(interface));
        let plugin_manager = Arc::new(crate::plugin::GarrisonPluginManager::new());
        #[cfg(feature = "listener")]
        let listener_manager = Arc::new(crate::listener::GarrisonListenerManager::new());
        let auth_logic: Arc<dyn AuthLogic> = Arc::new(MockAuthLogic);
        let permission_checker: Arc<dyn PermissionChecker> = Arc::new(MockPermissionChecker);
        let disable_repo: Arc<dyn DisableRepository> = Arc::new(MockDisableRepository);
        #[cfg(feature = "three-tier-cache")]
        let firewall_for_cache = firewall.clone();

        let logic = GarrisonManagerBuilder::build_logic_via_builder_chain(
            session,
            config,
            firewall,
            plugin_manager,
            auth_logic,
            permission_checker,
            disable_repo,
            #[cfg(feature = "listener")]
            listener_manager,
            #[cfg(feature = "three-tier-cache")]
            Arc::new(
                crate::cache::UserCacheService::new(
                    make_dao(),
                    firewall_for_cache,
                    60,
                    3600,
                    10000,
                )
                .unwrap(),
            ),
        );

        assert!(
            logic.plugin_manager.is_some(),
            "兜底 logic 应注入 plugin_manager"
        );
        #[cfg(feature = "listener")]
        assert!(
            logic.listener_manager.is_some(),
            "兜底 logic 应注入 listener_manager"
        );
        assert!(logic.auth_logic.is_some(), "兜底 logic 应注入 auth_logic");
        assert!(
            logic.permission_checker.is_some(),
            "兜底 logic 应注入 permission_checker"
        );
        assert!(
            logic.disable_repository.is_some(),
            "兜底 logic 应注入 disable_repository"
        );
    }
}
