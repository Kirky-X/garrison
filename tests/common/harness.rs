//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 统一集成测试基建（specmark change `acceptance-overhaul` / spec `test-harness`）。
//!
//! [`GarrisonTestHarness`] 一次 `init()` 完成 `GarrisonManager` 全局单例装配：
//! 默认 `InMemoryDao` + 可编程 [`MockInterface`]，可选注入 [`MockClock`]、
//! `GarrisonPluginManager`、`GarrisonListenerManager`。
//!
//! # 串行约束
//!
//! `GarrisonManager` 是进程级全局单例。使用 harness 的测试**必须**标注 `#[serial]`
//! （仓库既有惯例，见 `src/account/metrics.rs:242`）；漏标时并发 `init()` 会显性返回
//! `GarrisonError::Config`，而不是静默共享到别人的单例状态。

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use garrison::config::GarrisonConfig;
use garrison::context::tenant::{TenantContext, TenantSource, TENANT};
use garrison::dao::{GarrisonDao, InMemoryDao};
use garrison::error::{GarrisonError, GarrisonResult};
use garrison::manager::factory::{GarrisonLogicFactoryContext, GarrisonLogicFactoryEntry};
use garrison::manager::GarrisonManager;
use garrison::plugin::GarrisonPluginManager;
use garrison::session::GarrisonSession;
use garrison::stp::{Clock, GarrisonInterface, GarrisonLogicDefault, MockClock};
use garrison::strategy::GarrisonPermissionStrategy;
use parking_lot::Mutex;

#[cfg(feature = "listener")]
use garrison::listener::GarrisonListenerManager;

// ============================================================================
// MockInterface：可编程权限 / 角色数据源 + 错误注入
// ============================================================================

#[derive(Default)]
struct InterfaceState {
    permissions: HashMap<String, Vec<String>>,
    roles: HashMap<String, Vec<String>>,
    failure: Option<Arc<dyn Fn() -> GarrisonError + Send + Sync + 'static>>,
}

/// 可编程 `GarrisonInterface` 测试替身。
///
/// 产品侧不提供 `GarrisonInterface` 实现（该 trait 设计为业务方回调），`src/` 内的
/// 同名 mock 均为 `#[cfg(test)]` 私有且不支持编程式应答与错误注入，故 tests/ 自带一份。
pub struct MockInterface {
    state: Mutex<InterfaceState>,
}

impl MockInterface {
    /// 新建（无任何授权数据，两个列表查询均返回空列表）。
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(InterfaceState::default()),
        })
    }

    /// 为 `login_id` 声明权限与角色列表。
    pub fn allow(&self, login_id: &str, permissions: &[&str], roles: &[&str]) -> &Self {
        let mut state = self.state.lock();
        state.permissions.insert(
            login_id.to_string(),
            permissions.iter().map(|v| (*v).to_string()).collect(),
        );
        state.roles.insert(
            login_id.to_string(),
            roles.iter().map(|v| (*v).to_string()).collect(),
        );
        self
    }

    /// 收回全部授权（任意主体均无权限、无角色）。
    pub fn deny_all(&self) -> &Self {
        let mut state = self.state.lock();
        state.permissions.clear();
        state.roles.clear();
        self
    }

    /// 注入错误：此后两个列表查询均返回该闭包产生的 `Err`。
    ///
    /// 以闭包而非 `GarrisonError` 值注入，因为 `GarrisonError` 未实现 `Clone`，
    /// 而错误注入需要可重复触发。
    pub fn fail_with<F>(&self, factory: F) -> &Self
    where
        F: Fn() -> GarrisonError + Send + Sync + 'static,
    {
        self.state.lock().failure = Some(Arc::new(factory));
        self
    }

    /// 清除错误注入。
    pub fn clear_failure(&self) -> &Self {
        self.state.lock().failure = None;
        self
    }

    /// 先判错误注入，再查授权表；未命中的主体返回空列表。
    fn lookup(
        &self,
        pick: impl FnOnce(&InterfaceState) -> Option<&Vec<String>>,
    ) -> GarrisonResult<Vec<String>> {
        let failure = self.state.lock().failure.clone();
        if let Some(failure) = failure {
            return Err(failure());
        }
        let state = self.state.lock();
        Ok(pick(&state).cloned().unwrap_or_default())
    }
}

#[async_trait]
impl GarrisonInterface for MockInterface {
    async fn get_permission_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        self.lookup(|state| state.permissions.get(login_id))
    }

    async fn get_role_list(&self, login_id: &str) -> GarrisonResult<Vec<String>> {
        self.lookup(|state| state.roles.get(login_id))
    }
}

/// 在指定租户上下文中执行 future。
///
/// `tenant-isolation` feature 启用时，权限 / 角色查询路径是 fail-closed 的：
/// 未进入 `TENANT.scope` 会返回 `ctx-tenant-context-missing`（`src/context/tenant.rs:118`）。
/// 需要权限 / 角色断言的验收测试应把被测调用包进本函数。
pub async fn with_tenant<R>(tenant_id: i64, future: impl std::future::Future<Output = R>) -> R {
    TENANT
        .scope(
            TenantContext {
                tenant_id,
                resolved_from: TenantSource::Header,
            },
            future,
        )
        .await
}

// ============================================================================
// MockClock 注入通道
// ============================================================================

/// `GarrisonManagerBuilder` 没有 `.clock()` 透传口，注入时钟只能经 `with_factory`
/// 的裸函数指针工厂取回，故用进程级交接位把 builder 侧的时钟传给工厂函数。
/// 并发 `init()` 已被 [`LiveGuard`] 拦截，交接不会跨测试串扰。
static CLOCK_HANDOFF: Mutex<Option<Arc<dyn Clock>>> = Mutex::new(None);

/// 时钟交接位的 RAII 守卫：无论 `build()` 成功或失败都清空，避免污染下一次 init。
struct ClockHandoffGuard;

impl ClockHandoffGuard {
    fn install(clock: Arc<MockClock>) -> Self {
        *CLOCK_HANDOFF.lock() = Some(clock);
        Self
    }
}

impl Drop for ClockHandoffGuard {
    fn drop(&mut self) {
        *CLOCK_HANDOFF.lock() = None;
    }
}

static HARNESS_LOGIC_FACTORY: GarrisonLogicFactoryEntry = GarrisonLogicFactoryEntry {
    name: "harness-test",
    factory: harness_logic_factory,
};

/// 等价于 `src/manager/factory.rs` 的 `garrison_logic_factory_default`，额外注入时钟。
fn harness_logic_factory(
    session: Arc<GarrisonSession>,
    config: Arc<GarrisonConfig>,
    firewall: Arc<dyn GarrisonPermissionStrategy>,
    ctx: &GarrisonLogicFactoryContext,
) -> GarrisonResult<Arc<GarrisonLogicDefault>> {
    let clock = CLOCK_HANDOFF
        .lock()
        .clone()
        .ok_or_else(|| GarrisonError::Config("harness-clock-handoff-empty".to_string()))?;
    let mut builder = GarrisonLogicDefault::new(session, config, firewall).with_clock(clock);
    if let Some(plugin_manager) = ctx.plugin_manager.clone() {
        builder = builder.with_plugin_manager(plugin_manager);
    }
    #[cfg(feature = "listener")]
    if let Some(listener_manager) = ctx.listener_manager.clone() {
        builder = builder.with_listener_manager(listener_manager);
    }
    if let Some(auth_logic) = ctx.auth_logic.clone() {
        builder = builder.with_auth_logic(auth_logic);
    }
    if let Some(permission_checker) = ctx.permission_checker.clone() {
        builder = builder.with_permission_checker(permission_checker);
    }
    if let Some(disable_repository) = ctx.disable_repository.clone() {
        builder = builder.with_disable_repository(disable_repository);
    }
    #[cfg(feature = "three-tier-cache")]
    if let Some(user_cache_service) = ctx.user_cache_service.clone() {
        builder = builder.with_user_cache_service(user_cache_service);
    }
    Ok(Arc::new(builder))
}

// ============================================================================
// 单例占用守卫
// ============================================================================

static SINGLETON_IN_USE: AtomicBool = AtomicBool::new(false);

/// 标记全局单例已被某次 `init()` 占用；占用期间的第二次 `init()` 直接报错。
struct LiveGuard;

impl LiveGuard {
    fn acquire() -> GarrisonResult<Self> {
        if SINGLETON_IN_USE.swap(true, Ordering::AcqRel) {
            return Err(GarrisonError::Config(
                "harness-concurrent-init::全局单例已被占用，使用 harness 的测试须标注 #[serial]"
                    .to_string(),
            ));
        }
        Ok(Self)
    }
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        SINGLETON_IN_USE.store(false, Ordering::Release);
    }
}

// ============================================================================
// GarrisonTestHarness
// ============================================================================

/// 统一测试入口：`GarrisonTestHarness::builder().init().await`。
pub struct GarrisonTestHarness;

impl GarrisonTestHarness {
    /// 返回默认配置的构建器（`InMemoryDao` + 空授权 [`MockInterface`] + 系统时钟）。
    pub fn builder() -> HarnessBuilder {
        HarnessBuilder::default()
    }
}

/// harness 构建器。
#[derive(Default)]
pub struct HarnessBuilder {
    dao: Option<Arc<dyn GarrisonDao>>,
    config: Option<Arc<GarrisonConfig>>,
    interface: Option<Arc<MockInterface>>,
    clock: Option<Arc<MockClock>>,
    plugin_manager: Option<Arc<GarrisonPluginManager>>,
    #[cfg(feature = "listener")]
    listener_manager: Option<Arc<GarrisonListenerManager>>,
}

impl HarnessBuilder {
    /// 覆盖 DAO（默认 `InMemoryDao`）。
    pub fn dao(mut self, dao: Arc<dyn GarrisonDao>) -> Self {
        self.dao = Some(dao);
        self
    }

    /// 覆盖全局配置（默认 `GarrisonConfig::default_config()`）。
    pub fn config(mut self, config: Arc<GarrisonConfig>) -> Self {
        self.config = Some(config);
        self
    }

    /// 覆盖权限数据源替身。
    pub fn interface(mut self, interface: Arc<MockInterface>) -> Self {
        self.interface = Some(interface);
        self
    }

    /// 注入可控时钟。
    ///
    /// 注意：`GarrisonSession` 的 TTL 计算直调 `chrono::Utc::now()`
    /// （`src/session/impl.rs`），不受注入时钟影响；本注入只驱动 `GarrisonLogicDefault`
    /// 的 `clock` 路径（`session_hover_timeout` 等）。会话过期场景须用短 TTL + 真实等待，
    /// 或改写存储层时间戳。
    pub fn clock(mut self, clock: Arc<MockClock>) -> Self {
        self.clock = Some(clock);
        self
    }

    /// 注入插件管理器。
    pub fn plugin_manager(mut self, plugin_manager: Arc<GarrisonPluginManager>) -> Self {
        self.plugin_manager = Some(plugin_manager);
        self
    }

    /// 注入监听器管理器（需 `listener` feature）。
    #[cfg(feature = "listener")]
    pub fn listener_manager(mut self, listener_manager: Arc<GarrisonListenerManager>) -> Self {
        self.listener_manager = Some(listener_manager);
        self
    }

    /// 装配全局单例。
    ///
    /// # 错误
    /// - 单例已被占用（漏标 `#[serial]`）：`GarrisonError::Config`
    /// - 配置非法：透传 `GarrisonConfig::validate()` 的错误
    pub async fn init(self) -> GarrisonResult<Harness> {
        let live = LiveGuard::acquire()?;
        let dao: Arc<dyn GarrisonDao> = self
            .dao
            .unwrap_or_else(|| Arc::new(InMemoryDao::new()) as Arc<dyn GarrisonDao>);
        let interface = self.interface.unwrap_or_else(MockInterface::new);
        let config = self
            .config
            .unwrap_or_else(|| Arc::new(GarrisonConfig::default_config()));

        let mut builder = GarrisonManager::builder()
            .dao(dao.clone())
            .config(config)
            .interface(interface.clone());
        if let Some(plugin_manager) = self.plugin_manager {
            builder = builder.with_plugin_manager(plugin_manager);
        }
        #[cfg(feature = "listener")]
        if let Some(listener_manager) = self.listener_manager {
            builder = builder.with_listener_manager(listener_manager);
        }

        let clock = self.clock;
        let built = match &clock {
            Some(clock) => {
                let _handoff = ClockHandoffGuard::install(clock.clone());
                builder.with_factory(&HARNESS_LOGIC_FACTORY).build().await
            },
            None => builder.build().await,
        };
        built?;

        Ok(Harness {
            dao,
            interface,
            clock,
            _live: live,
        })
    }
}

/// 已完成 `init()` 的 harness 句柄。持有期间全局单例视为被占用。
pub struct Harness {
    dao: Arc<dyn GarrisonDao>,
    interface: Arc<MockInterface>,
    clock: Option<Arc<MockClock>>,
    _live: LiveGuard,
}

impl Harness {
    /// 本次 init 使用的 DAO（默认为 `InMemoryDao`，可用于直接断言存储状态）。
    pub fn dao(&self) -> &Arc<dyn GarrisonDao> {
        &self.dao
    }

    /// 本次 init 使用的权限数据源替身。
    pub fn interface(&self) -> &Arc<MockInterface> {
        &self.interface
    }

    /// 本次 init 注入的时钟（未注入时为 `None`）。
    pub fn clock(&self) -> Option<&Arc<MockClock>> {
        self.clock.as_ref()
    }

    /// 清空全局单例并释放占用。
    ///
    /// # 错误
    /// `testing` feature 未启用时返回 `GarrisonError::NotImplemented`：清空单例的
    /// `GarrisonManager::reset_for_test()` 是 `#[cfg(any(test, feature = "testing"))]`
    /// 可见，外部测试 crate 只能依赖 `build()` 的覆盖式写入（既见于
    /// `tests/acceptance_criteria.rs:97`）。此处显性失败而非静默不动作。
    pub fn reset(self) -> GarrisonResult<()> {
        #[cfg(feature = "testing")]
        GarrisonManager::reset_for_test();
        #[cfg(not(feature = "testing"))]
        return Err(GarrisonError::NotImplemented(
            "harness-reset-requires-testing-feature".to_string(),
        ));
        #[cfg(feature = "testing")]
        Ok(())
    }
}
