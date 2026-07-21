//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 管理器层集成测试模块。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod tests;` 声明），
//! 覆盖 `GarrisonManager` 的初始化、端到端流程、Strategy 注册表、
//! DisableRepository 集成、cleanup task 生命周期等场景。

use super::mock::MockInterface;
use super::*;
use crate::config::GarrisonConfig;
use crate::context::tenant::with_default_tenant;
use crate::dao::tests::MockDao;
use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use crate::session::GarrisonSession;
use crate::stp::util::spawn_cleanup_task;
use crate::stp::{GarrisonInterface, GarrisonUtil, LoginParams, SessionLogic};
use crate::strategy::{GarrisonPermissionStrategy, GarrisonPermissionStrategyDefault};
use async_trait::async_trait;
use serial_test::serial;

// ------------------------------------------------------------------------
// 辅助函数
// ------------------------------------------------------------------------

/// 创建默认测试配置（timeout=3600，throw_on_not_login=false 便于断言）。
fn make_config() -> GarrisonConfig {
    let mut config = GarrisonConfig::default_config();
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

/// 验证未初始化时 `GarrisonManager::logic()` 返回 Session 错误。
#[test]
#[serial]
fn logic_returns_error_when_not_initialized() {
    GarrisonManager::reset_for_test();
    let result = GarrisonManager::logic();
    assert!(result.is_err());
    match result {
        Err(GarrisonError::Session(ref msg)) if msg.contains("manager-not-init") => {},
        other => panic!("应返回 manager-not-init，实际: {:?}", other.map(|_| ())),
    }
}

/// 验证未初始化时 `GarrisonManager::is_initialized()` 返回 false。
#[test]
#[serial]
fn is_initialized_returns_false_when_not_initialized() {
    GarrisonManager::reset_for_test();
    assert!(!GarrisonManager::is_initialized());
}

// ------------------------------------------------------------------------
// 初始化场景测试（spec Scenario: init 后即可用）
// ------------------------------------------------------------------------

/// 验证 init 后 `is_initialized()` 返回 true。
#[tokio::test]
#[serial]
async fn init_sets_initialized_flag() {
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(make_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());
    let result = GarrisonManager::init(dao, config, interface);
    assert!(result.is_ok(), "init 应成功: {:?}", result.map(|_| ()));
    assert!(GarrisonManager::is_initialized());
    GarrisonManager::reset_for_test();
}

/// 验证 init 校验配置：timeout=0 抛 Config 错误。
#[tokio::test]
#[serial]
async fn init_rejects_invalid_config() {
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let mut config = GarrisonConfig::default_config();
    config.timeout = 0; // 非法
    let config = Arc::new(config);
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());
    let result = GarrisonManager::init(dao, config, interface);
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        GarrisonError::Config(ref msg) if msg.contains("timeout must be positive")
    ));
    assert!(!GarrisonManager::is_initialized());
    GarrisonManager::reset_for_test();
}

/// 验证 init 处理 active_timeout=-1 的兜底语义（使用 timeout 兜底）。
#[tokio::test]
#[serial]
async fn init_handles_negative_active_timeout() {
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(make_config()); // active_timeout = -1
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());
    let result = GarrisonManager::init(dao, config, interface);
    assert!(result.is_ok(), "active_timeout=-1 应使用 timeout 兜底");
    assert!(GarrisonManager::is_initialized());
    GarrisonManager::reset_for_test();
}

// ------------------------------------------------------------------------
// 端到端流程测试（spec Scenario: login → check_login → check_permission → logout）
// ------------------------------------------------------------------------

/// 验证完整端到端流程：init → login → check_login → logout → check_login 失败。
#[tokio::test]
#[serial]
async fn end_to_end_login_check_logout() {
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(make_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());
    GarrisonManager::init(dao, config, interface).unwrap();
    assert!(GarrisonManager::is_initialized());

    // login
    let token = GarrisonUtil::login_simple("1001").await.unwrap();
    assert!(!token.is_empty());

    // check_login
    let is_logged_in = with_token(token.clone(), async { GarrisonUtil::check_login().await })
        .await
        .unwrap();
    assert!(is_logged_in, "登录后 check_login 应返回 true");

    // logout
    let logout_result = with_token(token.clone(), async { GarrisonUtil::logout().await }).await;
    assert!(
        logout_result.is_ok(),
        "logout 应成功: {:?}",
        logout_result.map(|_| ())
    );

    // logout 后 check_login 应返回 false
    let is_still_logged_in = with_token(token.clone(), async { GarrisonUtil::check_login().await })
        .await
        .unwrap();
    assert!(!is_still_logged_in, "logout 后 check_login 应返回 false");

    GarrisonManager::reset_for_test();
}

/// 验证权限校验端到端流程：login → check_permission 持有/未持有。
#[tokio::test]
#[serial]
async fn end_to_end_check_permission() {
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(make_config());
    let interface: Arc<dyn GarrisonInterface> =
        Arc::new(MockInterface::new().with_permission("1001", &["user:read", "user:write"]));
    GarrisonManager::init(dao, config, interface).unwrap();

    let token = GarrisonUtil::login_simple("1001").await.unwrap();

    // 持有权限
    let check_result = with_token(token.clone(), async {
        with_default_tenant(async { GarrisonUtil::check_permission("user:read").await }).await
    })
    .await;
    assert!(
        check_result.is_ok(),
        "持有权限应通过: {:?}",
        check_result.map(|_| ())
    );

    // 未持有权限
    let check_result = with_token(token.clone(), async {
        with_default_tenant(async { GarrisonUtil::check_permission("user:delete").await }).await
    })
    .await;
    assert!(check_result.is_err());
    assert!(matches!(
        check_result.unwrap_err(),
        GarrisonError::NotPermission(ref p) if p == "user:delete"
    ));

    GarrisonManager::reset_for_test();
}

/// 验证角色校验端到端流程：login → check_role 持有/未持有。
#[tokio::test]
#[serial]
async fn end_to_end_check_role() {
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(make_config());
    let interface: Arc<dyn GarrisonInterface> =
        Arc::new(MockInterface::new().with_role("1001", &["admin"]));
    GarrisonManager::init(dao, config, interface).unwrap();

    let token = GarrisonUtil::login_simple("1001").await.unwrap();

    // 持有角色
    let check_result = with_token(token.clone(), async {
        GarrisonUtil::check_role("admin").await
    })
    .await;
    assert!(
        check_result.is_ok(),
        "持有角色应通过: {:?}",
        check_result.map(|_| ())
    );

    // 未持有角色
    let check_result = with_token(token.clone(), async {
        GarrisonUtil::check_role("superadmin").await
    })
    .await;
    assert!(check_result.is_err());
    assert!(matches!(
        check_result.unwrap_err(),
        GarrisonError::NotRole(ref r) if r == "superadmin"
    ));

    GarrisonManager::reset_for_test();
}

/// 验证 GarrisonUtil::login 未初始化时抛错。
#[tokio::test]
#[serial]
async fn util_login_fails_when_not_initialized() {
    GarrisonManager::reset_for_test();
    let result = GarrisonUtil::login_simple("1001").await;
    assert!(result.is_err());
    assert!(matches!(
        result.unwrap_err(),
        GarrisonError::Session(ref msg) if msg.contains("manager-not-init")
    ));
}

/// 验证重复 init 覆盖式更新（不抛错）。
#[tokio::test]
#[serial]
async fn init_overwrites_existing() {
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(make_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());
    GarrisonManager::init(dao.clone(), config.clone(), interface.clone()).unwrap();
    assert!(GarrisonManager::is_initialized());

    // 重复 init 应覆盖式更新，不抛错
    let result = GarrisonManager::init(dao, config, interface);
    assert!(
        result.is_ok(),
        "重复 init 应覆盖式更新: {:?}",
        result.map(|_| ())
    );
    assert!(GarrisonManager::is_initialized());

    GarrisonManager::reset_for_test();
}

/// 验证 inventory 已注册 default factory。
#[test]
fn default_factory_registered_via_inventory() {
    use std::iter::Iterator;
    let found = inventory::iter::<GarrisonLogicFactoryEntry>()
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
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(make_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());

    let timeout = u64::try_from(config.timeout).unwrap();
    let session = Arc::new(GarrisonSession::new(dao, timeout, timeout));
    let firewall: Arc<dyn GarrisonPermissionStrategy> =
        Arc::new(GarrisonPermissionStrategyDefault::new(interface));

    // factory 签名新增 ctx 参数，构造空 context 验证向后兼容
    #[cfg(feature = "listener")]
    let ctx = GarrisonLogicFactoryContext {
        plugin_manager: None,
        listener_manager: None,
        auth_logic: None,
        permission_checker: None,
        disable_repository: None,
    };
    #[cfg(not(feature = "listener"))]
    let ctx = GarrisonLogicFactoryContext {
        plugin_manager: None,
        auth_logic: None,
        permission_checker: None,
        disable_repository: None,
    };
    let logic = garrison_logic_factory_default(session, config, firewall, &ctx).unwrap();
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
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let mut config = GarrisonConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = 1800; // 正值，走 else 分支
    let config = Arc::new(config);
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());

    let result = GarrisonManager::init(dao, config, interface);
    assert!(
        result.is_ok(),
        "active_timeout=1800 应走 else 分支并成功: {:?}",
        result.map(|_| ())
    );
    assert!(GarrisonManager::is_initialized());

    // 验证 login 仍可正常工作
    let token = GarrisonUtil::login_simple("1001").await.unwrap();
    assert!(!token.is_empty());

    GarrisonManager::reset_for_test();
}

/// 验证 init 处理 active_timeout = 0 的边界值（else 分支）。
///
/// 覆盖 `init_with_factory_selector` 中 `else` 分支的边界值 0。
#[tokio::test]
#[serial]
async fn init_with_zero_active_timeout() {
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let mut config = GarrisonConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = 0; // 边界值 0，走 else 分支
    let config = Arc::new(config);
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());

    let result = GarrisonManager::init(dao, config, interface);
    assert!(result.is_ok(), "active_timeout=0 应走 else 分支并成功");
    assert!(GarrisonManager::is_initialized());

    GarrisonManager::reset_for_test();
}

/// 验证 init 校验配置：非法 token_style 抛 Config 错误。
///
/// 覆盖 `init_with_factory_selector` 中 `config.validate()?` 的另一种错误分支
/// （非法 token_style，区别于 timeout 非法）。
#[tokio::test]
#[serial]
async fn init_rejects_invalid_token_style() {
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let mut config = GarrisonConfig::default_config();
    config.token_style = "unknown_style".to_string(); // 非法
    let config = Arc::new(config);
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());

    let result = GarrisonManager::init(dao, config, interface);
    assert!(result.is_err());
    assert!(
        matches!(result.unwrap_err(), GarrisonError::Config(ref msg) if msg.contains("unknown token_style")),
        "应返回 'unknown token_style' 错误"
    );
    assert!(!GarrisonManager::is_initialized());

    GarrisonManager::reset_for_test();
}

// ------------------------------------------------------------------------
// init_with_factory_selector 兜底路径测试
// ------------------------------------------------------------------------

/// 验证 init_with_factory_selector 在无 factory 注册时走兜底路径。
///
/// 覆盖 init_with_factory_selector 中 `match factory_selector() { None => { ... } }` 分支：
/// 当 factory_selector 返回 None 时，直接通过 builder 链构造 GarrisonLogicDefault。
#[tokio::test]
#[serial]
async fn init_fallback_when_no_factory_registered() {
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(make_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());

    // 使用返回 None 的 selector，触发兜底路径
    let result = GarrisonManager::init_with_factory_selector(
        dao,
        config,
        interface,
        || None, // selector 返回 None，跳过 inventory factory
    );
    assert!(result.is_ok(), "兜底路径应成功: {:?}", result.map(|_| ()));
    assert!(GarrisonManager::is_initialized());

    // 验证 login 仍可正常工作
    let token = GarrisonUtil::login_simple("1001").await.unwrap();
    assert!(!token.is_empty());

    GarrisonManager::reset_for_test();
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

/// 验证未初始化时 `GarrisonManager::strategy()` 返回 Session 错误。
#[tokio::test]
#[serial]
async fn strategy_returns_error_when_not_initialized() {
    GarrisonManager::reset_for_test();
    let result = GarrisonManager::strategy();
    match result {
        Err(GarrisonError::Session(ref msg)) if msg.contains("manager-not-init") => {},
        other => panic!("应返回 manager-not-init，实际: {:?}", other.map(|_| ())),
    }
}

/// 验证 init 后 `strategy()` 返回 `Arc<RwLock<Strategy>>`。
#[tokio::test]
#[serial]
async fn strategy_available_after_init() {
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(make_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());
    GarrisonManager::init(dao, config, interface).unwrap();

    let strategy = GarrisonManager::strategy();
    assert!(strategy.is_ok(), "init 后应能获取 strategy");

    GarrisonManager::reset_for_test();
}

/// 验证 `with_strategy()` 整体替换 Strategy 注册表。
#[tokio::test]
#[serial]
async fn with_strategy_replaces_registry() {
    use crate::strategy::LoginHandler;

    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(make_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());
    GarrisonManager::init(dao, config, interface).unwrap();

    // 获取原 logic 并构造自定义 Strategy
    let logic = GarrisonManager::logic().unwrap();
    let custom_strategy = Arc::new(RwLock::new(Strategy::new(logic)));

    // 注入自定义 LoginHandler
    struct CustomLogin;
    #[async_trait]
    impl LoginHandler for CustomLogin {
        async fn handle_login(&self, id: &str) -> GarrisonResult<String> {
            Ok(format!("custom-{}", id))
        }
    }
    custom_strategy
        .write()
        .register_login_handler(Arc::new(CustomLogin));

    // with_strategy 替换
    GarrisonManager::with_strategy(custom_strategy).unwrap();

    // 验证替换后使用自定义策略
    let strategy = GarrisonManager::strategy().unwrap();
    let login_handler = strategy.read().login_handler().clone();
    let token = login_handler.handle_login("1001").await.unwrap();
    assert_eq!(token, "custom-1001", "with_strategy 后应使用自定义策略");

    GarrisonManager::reset_for_test();
}

/// 验证运行时通过 `strategy().write().register_*()` 替换策略立即生效。
#[tokio::test]
#[serial]
async fn runtime_strategy_replacement_takes_effect_immediately() {
    use crate::strategy::LoginHandler;

    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(make_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());
    GarrisonManager::init(dao, config, interface).unwrap();

    // 替换前：默认策略生成 token（先 clone Arc 再 await，避免跨 await 持锁）
    let strategy = GarrisonManager::strategy().unwrap();
    let default_handler = strategy.read().login_handler().clone();
    let default_token = default_handler.handle_login("1001").await.unwrap();
    assert!(!default_token.is_empty());

    // 运行时替换
    struct CustomLogin;
    #[async_trait]
    impl LoginHandler for CustomLogin {
        async fn handle_login(&self, id: &str) -> GarrisonResult<String> {
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

    GarrisonManager::reset_for_test();
}

// ------------------------------------------------------------------------
// T020: GarrisonManager 注册 DisableRepository 集成测试
// ------------------------------------------------------------------------

/// 验证 init 后 `GarrisonManager::disable_repository()` 返回 Some，
/// 未注册时返回 None。
///
/// 覆盖场景：
/// - reset_for_test 后（未注册）返回 None
/// - init 后（已注册）返回 Some
#[tokio::test]
#[serial]
async fn test_manager_registers_disable_repository() {
    GarrisonManager::reset_for_test();

    // 未注册时返回 None
    assert!(
        GarrisonManager::disable_repository().is_none(),
        "未 init 时 disable_repository() 应返回 None"
    );

    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(make_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());
    GarrisonManager::init(dao, config, interface).unwrap();

    // init 后返回 Some
    let repo = GarrisonManager::disable_repository();
    assert!(repo.is_some(), "init 后 disable_repository() 应返回 Some");

    GarrisonManager::reset_for_test();
}

/// 验证通过 disable_repository 封禁用户后，check_disable 返回 DisableService 错误。
#[tokio::test]
#[serial]
async fn test_disable_then_check_disable_errors() {
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(make_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());
    GarrisonManager::init(dao, config, interface).unwrap();

    // login 获取 token
    let token = GarrisonUtil::login_simple("1001").await.unwrap();

    // 通过 disable_repository 封禁用户
    let repo = GarrisonManager::disable_repository().expect("init 后应返回 Some");
    let until = chrono::Utc::now() + chrono::Duration::seconds(3600);
    repo.disable("1001", "default", Some(until), 0, 3600)
        .await
        .unwrap();

    // 在 token 上下文中调用 check_disable 应返回错误
    let result = with_token(token, async { GarrisonUtil::check_disable().await }).await;
    match result {
        Err(GarrisonError::DisableService { service, .. }) => {
            assert_eq!(service, "default");
        },
        other => panic!(
            "封禁后 check_disable 应返回 Err(DisableService)，实际: {:?}",
            other
        ),
    }

    GarrisonManager::reset_for_test();
}

/// 验证封禁后解封，check_disable 返回 Ok。
#[tokio::test]
#[serial]
async fn test_untie_disable_then_check_disable_ok() {
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(make_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());
    GarrisonManager::init(dao, config, interface).unwrap();

    let token = GarrisonUtil::login_simple("1002").await.unwrap();

    // 封禁
    let repo = GarrisonManager::disable_repository().expect("init 后应返回 Some");
    repo.disable("1002", "default", None, 0, 0).await.unwrap();

    // 解封
    repo.untie_disable("1002", "default").await.unwrap();

    // check_disable 应返回 Ok
    let result = with_token(token, async { GarrisonUtil::check_disable().await }).await;
    assert!(
        result.is_ok(),
        "解封后 check_disable 应返回 Ok，实际: {:?}",
        result
    );

    GarrisonManager::reset_for_test();
}

/// 验证 disable_repository() 多次调用返回同一实例（Arc 指针相等）。
#[tokio::test]
#[serial]
async fn test_manager_disable_repository_persists() {
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(make_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());
    GarrisonManager::init(dao, config, interface).unwrap();

    let repo1 = GarrisonManager::disable_repository().expect("init 后应返回 Some");
    let repo2 = GarrisonManager::disable_repository().expect("init 后应返回 Some");

    assert!(
        Arc::ptr_eq(&repo1, &repo2),
        "disable_repository() 多次调用应返回同一实例（Arc 指针相等）"
    );

    GarrisonManager::reset_for_test();
}

// ------------------------------------------------------------------------
// T030: spawn_cleanup_task 集成到 GarrisonManager::init
// ------------------------------------------------------------------------

/// 验证 interval > 0 时 init 后 cleanup task 启动。
///
/// 覆盖场景：`config.token_map_cleanup_interval_secs = 1`（> 0），
/// init 后 `GARRISON_MANAGER.cleanup_task_handle` 应为 `Some`。
#[tokio::test]
#[serial]
async fn manager_init_positive_interval_starts_cleanup_task() {
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let mut config = make_config();
    config.token_map_cleanup_interval_secs = 1;
    let config = Arc::new(config);
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());

    GarrisonManager::init(dao, config, interface).unwrap();

    assert!(
        GARRISON_MANAGER.cleanup_task_handle.read().is_some(),
        "interval > 0 时 init 后应启动 cleanup task"
    );

    GarrisonManager::reset_for_test();
}

/// 验证 interval = -1 时 init 不启动 cleanup task。
///
/// 覆盖场景：`config.token_map_cleanup_interval_secs = -1`（< 0，禁用），
/// init 后 `GARRISON_MANAGER.cleanup_task_handle` 应为 `None`。
#[tokio::test]
#[serial]
async fn manager_init_negative_interval_no_cleanup_task() {
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let mut config = make_config();
    config.token_map_cleanup_interval_secs = -1;
    let config = Arc::new(config);
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());

    GarrisonManager::init(dao, config, interface).unwrap();

    assert!(
        GARRISON_MANAGER.cleanup_task_handle.read().is_none(),
        "interval = -1 时 init 不应启动 cleanup task"
    );

    GarrisonManager::reset_for_test();
}

/// 验证 init 后 cleanup task 实际运行（token 被清理）。
///
/// 策略：init with timeout=1（TTL=1 秒）+ interval=1（每秒清理），
/// login 创建 token 后等待 3 秒，验证 token 已从 `login_token_map` 移除。
#[tokio::test]
#[serial]
async fn manager_init_cleanup_task_runs_after_init() {
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let mut config = make_config();
    config.timeout = 1; // TTL = 1 秒
    config.active_timeout = -1;
    config.token_map_cleanup_interval_secs = 1; // 每秒清理
    let config = Arc::new(config);
    let interface: Arc<dyn GarrisonInterface> = Arc::new(MockInterface::new());

    GarrisonManager::init(dao, config, interface).unwrap();

    // login 创建 token
    let token = GarrisonUtil::login_simple("1001").await.unwrap();
    assert!(!token.is_empty());

    // 验证 token 存在于 login_token_map
    let logic = GarrisonManager::logic().unwrap();
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

    GarrisonManager::reset_for_test();
}

/// 验证 manager drop 时 cleanup task 被取消。
///
/// 策略：创建局部 `GarrisonManager` 实例，存入 cleanup task handle，
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
    impl GarrisonDao for CountingDao {
        async fn get(&self, _key: &str) -> GarrisonResult<Option<String>> {
            self.counter.fetch_add(1, Ordering::SeqCst);
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

    let counter = Arc::new(AtomicUsize::new(0));
    let dao: Arc<dyn GarrisonDao> = Arc::new(CountingDao {
        counter: counter.clone(),
    });
    let session = Arc::new(GarrisonSession::new(dao, 3600, 86400));
    // 添加 token 到 login_token_map，确保 cleanup 有内容可遍历
    session.add_login_token("user1", "token1");

    // 启动 cleanup task
    let handle = spawn_cleanup_task(session, 1).unwrap();

    // 创建局部 manager 并存入 handle
    let manager = GarrisonManager::new();
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
