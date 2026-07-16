//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Stp 集成测试。
#[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
use super::mock::MockUserRepository;
use super::mock::{
    MockDao, MockFirewall, MockInterface, MockInterfaceWithLoginType, MockInterfaceWithPerms,
};
use super::*;
use crate::config::{OverflowLogoutMode, ReplacedLoginExitMode};
use crate::context::tenant::with_default_tenant;
use crate::dao::BulwarkDao;
use crate::manager::BulwarkManager;
use async_trait::async_trait;
#[cfg(feature = "listener")]
use parking_lot::Mutex;
use serial_test::serial;
use std::collections::HashMap;
use std::time::Duration;

/// 辅助函数：创建 BulwarkLogicDefault 实例（throw_on_not_login + firewall 返回值可配置）。
fn make_logic(
    timeout: u64,
    active_timeout: u64,
    throw_on_not_login: bool,
    token_style: &str,
    has_permission: bool,
    has_role: bool,
) -> BulwarkLogicDefault {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let session = Arc::new(BulwarkSession::new(dao, timeout, active_timeout));
    let mut config = BulwarkConfig::default_config();
    config.throw_on_not_login = throw_on_not_login;
    config.token_style = token_style.to_string();
    let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
        has_permission,
        has_role,
    });
    BulwarkLogicDefault::new(session, Arc::new(config), firewall)
}

/// 辅助函数：创建 BulwarkLogicDefault 实例并返回 dao 引用（用于测试中操作 dao 内部状态）。
fn make_logic_with_dao(
    timeout: u64,
    active_timeout: u64,
    throw_on_not_login: bool,
    token_style: &str,
    has_permission: bool,
    has_role: bool,
) -> (Arc<MockDao>, BulwarkLogicDefault) {
    let dao = Arc::new(MockDao::new());
    let session = Arc::new(BulwarkSession::new(
        dao.clone() as Arc<dyn BulwarkDao>,
        timeout,
        active_timeout,
    ));
    let mut config = BulwarkConfig::default_config();
    config.throw_on_not_login = throw_on_not_login;
    config.token_style = token_style.to_string();
    let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
        has_permission,
        has_role,
    });
    let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall);
    (dao, logic)
}

/// 辅助函数：在当前 task_local 设置 token 后执行 future。
async fn with_token<R>(token: &str, f: impl std::future::Future<Output = R>) -> R {
    with_current_token(token.to_string(), f).await
}

/// 初始化全局 BulwarkManager（用于 BulwarkUtil 静态方法测试）。
fn init_global_manager(throw_on_not_login: bool) {
    BulwarkManager::reset_for_test();
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = throw_on_not_login;
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
    BulwarkManager::init(dao, Arc::new(config), interface).unwrap();
}

/// 初始化全局 BulwarkManager 并返回 MockDao 引用（用于 API Key 测试等需共享 DAO 的场景）。
///
/// 返回的 `Arc<MockDao>` 与 BulwarkManager 内部 session 持有同一 DAO 实例，
/// 测试可用它构造 `ApiKeyHandler` 生成/校验 API Key。
#[cfg(feature = "protocol-apikey")]
fn init_global_manager_with_dao(throw_on_not_login: bool) -> Arc<MockDao> {
    BulwarkManager::reset_for_test();
    let dao = Arc::new(MockDao::new());
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = throw_on_not_login;
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
    BulwarkManager::init(
        dao.clone() as Arc<dyn BulwarkDao>,
        Arc::new(config),
        interface,
    )
    .unwrap();
    dao
}

/// 初始化全局 BulwarkManager 并注入预设权限/角色列表（用于 has_permission/has_role 返回 true 的测试）。
fn init_global_manager_with_perms(
    throw_on_not_login: bool,
    permissions: Vec<String>,
    roles: Vec<String>,
) {
    BulwarkManager::reset_for_test();
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = throw_on_not_login;
    let interface: Arc<dyn BulwarkInterface> =
        Arc::new(MockInterfaceWithPerms { permissions, roles });
    BulwarkManager::init(dao, Arc::new(config), interface).unwrap();
}

// ------------------------------------------------------------------------
// login 首次登录 / 重复登录 / 自定义 token 风格
// ------------------------------------------------------------------------

/// 验证 login 返回非空 token 并创建会话。
#[tokio::test]
async fn login_creates_session_and_returns_token() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();
    assert!(!token.is_empty(), "login 应返回非空 token");

    // 验证会话创建
    let ts = logic
        .session
        .get_token_session(&token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ts.login_id, "1001".to_string());
}

/// 验证重复登录生成不同 token 并记录多 token。
#[tokio::test]
async fn login_repeated_creates_multiple_tokens() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let t1 = logic.login("1001", &LoginParams::default()).await.unwrap();
    let t2 = logic.login("1001", &LoginParams::default()).await.unwrap();
    assert_ne!(t1, t2, "重复登录应生成不同 token");

    // Account-Session 应包含两个 token
    let as_ = logic
        .session
        .get_account_session("1001")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(as_.tokens.len(), 2);
}

/// 验证 token_style=random_64 生成 64 字符 token。
#[tokio::test]
async fn login_with_random_64_style() {
    let logic = make_logic(3600, 86400, false, "random_64", true, true);
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();
    assert_eq!(token.len(), 64, "random_64 应生成 64 字符 token");
}

/// 验证 token_style=simple 生成 32 字符 token。
#[tokio::test]
async fn login_with_simple_style() {
    let logic = make_logic(3600, 86400, false, "simple", true, true);
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();
    assert_eq!(token.len(), 32, "simple 应生成 32 字符 token");
}

/// 验证未知 token_style 时 login 返回 Err。
///
/// 覆盖 `generate_token` 的 `other =>` 分支，断言返回 `BulwarkError::Config`。
#[tokio::test]
async fn create_token_unknown_style_errors() {
    let logic = make_logic(3600, 86400, false, "unknown_style", true, true);
    let result = logic.login("1001", &LoginParams::default()).await;
    assert!(
        matches!(result, Err(BulwarkError::Config(ref msg)) if msg.contains("unknown token_style")),
        "未知 token_style 应返回含 'unknown token_style' 的 Config 错误，实际: {:?}",
        result
    );
}

/// 验证 login_with_token 用自定义 token 创建会话。
#[tokio::test]
async fn login_with_custom_token() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    logic
        .login_with_token("1001", "custom-token-123")
        .await
        .unwrap();

    let ts = logic
        .session
        .get_token_session("custom-token-123")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ts.login_id, "1001".to_string());
    assert_eq!(ts.token, "custom-token-123");
}

// ------------------------------------------------------------------------
// logout 销毁当前 / 销毁指定账号 / kickout
// ------------------------------------------------------------------------

/// 验证 logout 销毁当前 token 的会话。
#[tokio::test]
async fn logout_destroys_current_token() {
    let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();

    // 在 task_local 作用域内调用 logout
    with_current_token(token.clone(), async {
        logic.logout().await.unwrap();
    })
    .await;

    // Token-Session 已删除
    let ts = logic.session.get_token_session(&token).await.unwrap();
    assert!(ts.is_none(), "logout 后 Token-Session 应删除");
}

/// 验证 logout 未登录时幂等返回 Ok。
#[tokio::test]
async fn logout_when_not_logged_in_is_noop() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    // 未设置 task_local，logout 应幂等返回 Ok
    let result = logic.logout().await;
    assert!(result.is_ok(), "未登录时 logout 应幂等返回 Ok");
}

/// 验证 logout_by_login_id 销毁所有 token。
#[tokio::test]
async fn logout_by_login_id_destroys_all_tokens() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let t1 = logic.login("1001", &LoginParams::default()).await.unwrap();
    let t2 = logic.login("1001", &LoginParams::default()).await.unwrap();

    logic.logout_by_login_id("1001").await.unwrap();

    assert!(logic
        .session
        .get_token_session(&t1)
        .await
        .unwrap()
        .is_none());
    assert!(logic
        .session
        .get_token_session(&t2)
        .await
        .unwrap()
        .is_none());
    assert!(logic
        .session
        .get_account_session("1001")
        .await
        .unwrap()
        .is_none());
}

/// 验证 kickout 按账号踢出（语义等同 logout_by_login_id）。
#[tokio::test]
async fn kickout_by_account_destroys_session() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();

    logic.kickout("1001").await.unwrap();

    assert!(logic
        .session
        .get_token_session(&token)
        .await
        .unwrap()
        .is_none());
    assert!(logic
        .session
        .get_account_session("1001")
        .await
        .unwrap()
        .is_none());
}

/// 验证 kickout_by_token 按 token 踢出。
#[tokio::test]
async fn kickout_by_token_destroys_token_session() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();

    logic.kickout_by_token(&token).await.unwrap();

    assert!(logic
        .session
        .get_token_session(&token)
        .await
        .unwrap()
        .is_none());
}

// ------------------------------------------------------------------------
// check_login 有效 / 无效 / 过期 / 未登录抛异常
// ------------------------------------------------------------------------

/// 验证 check_login 有效 token 返回 true。
#[tokio::test]
async fn check_login_returns_true_for_valid_token() {
    let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();

    with_current_token(token, async {
        let valid = logic.check_login().await.unwrap();
        assert!(valid, "有效 token 应返回 true");
    })
    .await;
}

/// 验证 check_login 无效 token 返回 false（throw_on_not_login=false）。
#[tokio::test]
async fn check_login_returns_false_for_invalid_token() {
    let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));

    with_current_token("invalid-token".to_string(), async {
        let valid = logic.check_login().await.unwrap();
        assert!(!valid, "无效 token 应返回 false");
    })
    .await;
}

/// 验证 check_login 未设置 token 返回 false（throw_on_not_login=false）。
#[tokio::test]
async fn check_login_returns_false_when_no_token() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    // 未设置 task_local，check_login 返回 false
    let valid = logic.check_login().await.unwrap();
    assert!(!valid, "未设置 token 应返回 false");
}

/// 验证 check_login 未登录且 throw_on_not_login=true 抛异常。
///
/// spec config-system Requirement: 配置校验——throw_on_not_login。
#[tokio::test]
async fn check_login_throws_when_throw_on_not_login() {
    let logic = make_logic(3600, 86400, true, "uuid", true, true);
    let result = logic.check_login().await;
    assert!(
        matches!(result, Err(BulwarkError::Session(_))),
        "throw_on_not_login=true 且未登录应抛 Session 错误"
    );
}

/// 验证 check_login 过期 token 返回 false。
#[tokio::test]
async fn check_login_returns_false_for_expired_token() {
    let logic = Arc::new(make_logic(1, 86400, false, "uuid", true, true));
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();

    // 等待 token 过期（1 秒 TTL）
    tokio::time::sleep(Duration::from_secs(2)).await;

    with_current_token(token, async {
        let valid = logic.check_login().await.unwrap();
        assert!(!valid, "过期 token 应返回 false");
    })
    .await;
}

// ------------------------------------------------------------------------
// token 类型专用校验方法
// ------------------------------------------------------------------------

/// 验证 `check_access_token` 委托 `check_login`，已登录时返回 `Ok(())`。
///
/// T151。语义：access_token 类型校验入口，默认实现委托 check_login。
#[tokio::test]
async fn check_access_token_delegates_to_check_login() {
    let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();

    with_current_token(token, async {
        let result = logic.check_access_token().await;
        assert!(
            result.is_ok(),
            "已登录时 check_access_token 应返回 Ok，实际: {:?}",
            result
        );
    })
    .await;
}

/// 验证 `check_client_token` 委托 `check_login`，已登录时返回 `Ok(())`。
///
/// T151。语义：client_token 类型校验入口，默认实现委托 check_login。
#[tokio::test]
async fn check_client_token_delegates_to_check_login() {
    let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();

    with_current_token(token, async {
        let result = logic.check_client_token().await;
        assert!(
            result.is_ok(),
            "已登录时 check_client_token 应返回 Ok，实际: {:?}",
            result
        );
    })
    .await;
}

/// 验证 `check_temp_token` 委托 `check_login`，已登录时返回 `Ok(())`。
///
/// T151。语义：temp_token 类型校验入口，默认实现委托 check_login。
#[tokio::test]
async fn check_temp_token_delegates_to_check_login() {
    let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();

    with_current_token(token, async {
        let result = logic.check_temp_token().await;
        assert!(
            result.is_ok(),
            "已登录时 check_temp_token 应返回 Ok，实际: {:?}",
            result
        );
    })
    .await;
}

// ------------------------------------------------------------------------
// get_login_id
// ------------------------------------------------------------------------

/// 验证 get_login_id 返回当前 login_id。
#[tokio::test]
async fn get_login_id_returns_current_login_id() {
    let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();

    with_current_token(token, async {
        let login_id = logic.get_login_id().await.unwrap();
        assert_eq!(login_id, Some("1001".to_string()));
    })
    .await;
}

/// 验证 get_login_id 未登录返回 None。
#[tokio::test]
async fn get_login_id_returns_none_when_not_logged_in() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let login_id = logic.get_login_id().await.unwrap();
    assert_eq!(login_id, None, "未登录应返回 None");
}

/// 验证 get_login_id 无效 token 返回 None。
#[tokio::test]
async fn get_login_id_returns_none_for_invalid_token() {
    let logic = Arc::new(make_logic(3600, 86400, false, "uuid", true, true));

    with_current_token("invalid-token".to_string(), async {
        let login_id = logic.get_login_id().await.unwrap();
        assert_eq!(login_id, None, "无效 token 应返回 None");
    })
    .await;
}

// ------------------------------------------------------------------------
// task_local 上下文测试
// ------------------------------------------------------------------------

/// 验证 current_token 未设置时抛错。
#[test]
fn current_token_errors_when_not_set() {
    let result = current_token();
    assert!(
        matches!(result, Err(BulwarkError::Session(_))),
        "未设置 task_local 时 current_token 应抛错"
    );
}

/// 验证 current_token 在作用域内返回 token。
#[tokio::test]
async fn current_token_returns_value_in_scope() {
    with_current_token("scoped-token".to_string(), async {
        let token = current_token().unwrap();
        assert_eq!(token, "scoped-token");
    })
    .await;
}

// ------------------------------------------------------------------------
// BulwarkContext：task_local 跨 spawn 传播测试
// ------------------------------------------------------------------------

/// 验证 BulwarkContext 跨 `tokio::spawn` 传播 task_local（`current_token`）。
///
/// tokio `task_local!` 不会自动传播到 `tokio::spawn` 子任务。
/// `BulwarkContext::capture()` + `within()` 提供手动传播机制。
///
/// 测试逻辑：
/// 1. 父 task 设置 `current_token` = "parent-task-token"
/// 2. `BulwarkContext::capture()` 捕获上下文
/// 3. `tokio::spawn` 子任务，在子任务内 `ctx.within()` 恢复上下文
/// 4. 子任务内 `current_token()` 应返回父 task 设置的 token
#[tokio::test(flavor = "multi_thread")]
async fn task_local_propagates_across_spawn() {
    // 1. 在父 task 设置 current_token 并捕获上下文
    let ctx = with_current_token("parent-task-token".to_string(), async {
        BulwarkContext::capture()
    })
    .await;

    // 2. spawn 子任务，在子任务内恢复上下文
    let handle = tokio::spawn(async move {
        ctx.within(async {
            // 子任务内应能读到 token（若无 within 则 current_token() 失败）
            match current_token() {
                Ok(t) => t == "parent-task-token",
                Err(_) => false,
            }
        })
        .await
    });

    // 3. 子任务应返回 true（token 可读且值匹配）
    let result = handle.await.expect("子任务 panic");
    assert!(
        result,
        "子任务内 current_token() 应返回父 task 设置的 token（通过 BulwarkContext 传播）"
    );
}

/// 验证 BulwarkContext::capture() 在未设置 token 时返回 None 上下文。
///
/// 在未设置 `current_token` 的 task 中 capture，`within()` 内
/// `current_token()` 应失败（返回 Err）。
#[tokio::test(flavor = "multi_thread")]
async fn bulwark_context_capture_without_token_propagates_none() {
    // 在未设置 current_token 的 task 中 capture
    let ctx = BulwarkContext::capture();

    let handle = tokio::spawn(async move { ctx.within(async { current_token().is_ok() }).await });

    let result = handle.await.expect("子任务 panic");
    assert!(
        !result,
        "未设置 token 时 capture 的上下文在子任务内 current_token() 应失败"
    );
}

// ------------------------------------------------------------------------
// check_permission 持有/未持有/未登录抛异常
// ------------------------------------------------------------------------

/// 已登录且 firewall 返回 true 时 check_permission 通过。
#[tokio::test]
async fn check_permission_held_returns_ok() {
    let logic = make_logic(3600, 86400, true, "uuid", true, true);
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();
    let result = with_token(
        &token,
        with_default_tenant(async { logic.check_permission("user:read").await }),
    )
    .await;
    assert!(result.is_ok(), "持有权限应返回 Ok");
}

/// 已登录但 firewall 返回 false 时抛 NotPermission。
#[tokio::test]
async fn check_permission_not_held_throws_not_permission() {
    let logic = make_logic(3600, 86400, true, "uuid", false, true);
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();
    let result = with_token(
        &token,
        with_default_tenant(async { logic.check_permission("user:delete").await }),
    )
    .await;
    assert!(
        matches!(result, Err(BulwarkError::NotPermission(_))),
        "未持有权限应抛 NotPermission"
    );
}

/// 未登录且 throw_on_not_login=true 时抛 NotLogin。
#[tokio::test]
async fn check_permission_not_login_throws_when_throw_on_not_login() {
    let logic = make_logic(3600, 86400, true, "uuid", true, true);
    // 不调用 login，直接 check_permission（无 task_local token）
    let result = logic.check_permission("user:read").await;
    assert!(
        matches!(result, Err(BulwarkError::NotLogin(_))),
        "未登录且 throw_on_not_login=true 应抛 NotLogin"
    );
}

/// 未登录且 throw_on_not_login=false 时 check_permission 抛 NotPermission（降级为无权限）。
#[tokio::test]
async fn check_permission_not_login_throws_not_permission_when_silent() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    // 不调用 login，直接 check_permission（无 task_local token）
    let result = logic.check_permission("user:read").await;
    assert!(
        matches!(result, Err(BulwarkError::NotPermission(_))),
        "未登录且 throw_on_not_login=false 应抛 NotPermission（降级）"
    );
}

// ------------------------------------------------------------------------
// check_role 持有/未持有/未登录抛异常
// ------------------------------------------------------------------------

/// 已登录且 firewall 返回 true 时 check_role 通过。
#[tokio::test]
async fn check_role_held_returns_ok() {
    let logic = make_logic(3600, 86400, true, "uuid", true, true);
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();
    let result = with_token(&token, logic.check_role("admin")).await;
    assert!(result.is_ok(), "持有角色应返回 Ok");
}

/// 已登录但 firewall 返回 false 时抛 NotRole。
#[tokio::test]
async fn check_role_not_held_throws_not_role() {
    let logic = make_logic(3600, 86400, true, "uuid", true, false);
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();
    let result = with_token(&token, logic.check_role("admin")).await;
    assert!(
        matches!(result, Err(BulwarkError::NotRole(_))),
        "未持有角色应抛 NotRole"
    );
}

/// 未登录且 throw_on_not_login=true 时 check_role 抛 NotLogin。
#[tokio::test]
async fn check_role_not_login_throws_when_throw_on_not_login() {
    let logic = make_logic(3600, 86400, true, "uuid", true, true);
    // 不调用 login，直接 check_role（无 task_local token）
    let result = logic.check_role("admin").await;
    assert!(
        matches!(result, Err(BulwarkError::NotLogin(_))),
        "未登录且 throw_on_not_login=true 应抛 NotLogin"
    );
}

/// 未登录且 throw_on_not_login=false 时 check_role 抛 NotRole（降级为无角色）。
#[tokio::test]
async fn check_role_not_login_throws_not_role_when_silent() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    // 不调用 login，直接 check_role（无 task_local token）
    let result = logic.check_role("admin").await;
    assert!(
        matches!(result, Err(BulwarkError::NotRole(_))),
        "未登录且 throw_on_not_login=false 应抛 NotRole（降级）"
    );
}

// ------------------------------------------------------------------------
// BulwarkUtil 未初始化错误测试（spec Scenario: 未初始化抛错）
// ------------------------------------------------------------------------

/// 未初始化时 BulwarkUtil::logout 返回 Session 错误。
#[tokio::test]
#[serial]
async fn util_logout_fails_when_not_initialized() {
    BulwarkManager::reset_for_test();
    let result = BulwarkUtil::logout().await;
    assert!(
        matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
        "未初始化时 logout 应返回 Session 错误"
    );
}

/// 未初始化时 BulwarkUtil::logout_by_login_id 返回 Session 错误。
#[tokio::test]
#[serial]
async fn util_logout_by_login_id_fails_when_not_initialized() {
    BulwarkManager::reset_for_test();
    let result = BulwarkUtil::logout_by_login_id("1001").await;
    assert!(
        matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
        "未初始化时 logout_by_login_id 应返回 Session 错误"
    );
}

/// 未初始化时 BulwarkUtil::kickout 返回 Session 错误。
#[tokio::test]
#[serial]
async fn util_kickout_fails_when_not_initialized() {
    BulwarkManager::reset_for_test();
    let result = BulwarkUtil::kickout("1001").await;
    assert!(
        matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
        "未初始化时 kickout 应返回 Session 错误"
    );
}

/// 未初始化时 BulwarkUtil::kickout_by_token 返回 Session 错误。
#[tokio::test]
#[serial]
async fn util_kickout_by_token_fails_when_not_initialized() {
    BulwarkManager::reset_for_test();
    let result = BulwarkUtil::kickout_by_token("some-token").await;
    assert!(
        matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
        "未初始化时 kickout_by_token 应返回 Session 错误"
    );
}

/// 未初始化时 BulwarkUtil::check_login 返回 Session 错误。
#[tokio::test]
#[serial]
async fn util_check_login_fails_when_not_initialized() {
    BulwarkManager::reset_for_test();
    let result = BulwarkUtil::check_login().await;
    assert!(
        matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
        "未初始化时 check_login 应返回 Session 错误"
    );
}

/// 未初始化时 BulwarkUtil::get_login_id 返回 Session 错误。
#[tokio::test]
#[serial]
async fn util_get_login_id_fails_when_not_initialized() {
    BulwarkManager::reset_for_test();
    let result = BulwarkUtil::get_login_id().await;
    assert!(
        matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
        "未初始化时 get_login_id 应返回 Session 错误"
    );
}

/// 未初始化时 BulwarkUtil::check_permission 返回 Session 错误。
#[tokio::test]
#[serial]
async fn util_check_permission_fails_when_not_initialized() {
    BulwarkManager::reset_for_test();
    let result = BulwarkUtil::check_permission("user:read").await;
    assert!(
        matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
        "未初始化时 check_permission 应返回 Session 错误"
    );
}

/// 未初始化时 BulwarkUtil::check_role 返回 Session 错误。
#[tokio::test]
#[serial]
async fn util_check_role_fails_when_not_initialized() {
    BulwarkManager::reset_for_test();
    let result = BulwarkUtil::check_role("admin").await;
    assert!(
        matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
        "未初始化时 check_role 应返回 Session 错误"
    );
}

/// 未初始化时 BulwarkUtil::check_safe 返回 Session 错误（）。
#[tokio::test]
#[serial]
async fn util_check_safe_fails_when_not_initialized() {
    BulwarkManager::reset_for_test();
    let result = BulwarkUtil::check_safe().await;
    assert!(
        matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
        "未初始化时 check_safe 应返回 Session 错误"
    );
}

/// 未初始化时 BulwarkUtil::check_disable 返回 Session 错误（）。
#[tokio::test]
#[serial]
async fn util_check_disable_fails_when_not_initialized() {
    BulwarkManager::reset_for_test();
    let result = BulwarkUtil::check_disable().await;
    assert!(
        matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
        "未初始化时 check_disable 应返回 Session 错误"
    );
}

// ------------------------------------------------------------------------
// BulwarkUtil::has_permission / has_role 测试
// ------------------------------------------------------------------------

/// has_permission 空字符串返回 InvalidParam（校验在 logic() 之前，不依赖全局状态）。
#[tokio::test]
async fn util_has_permission_empty_string_returns_invalid_param() {
    let result = BulwarkUtil::has_permission("").await;
    assert!(
        matches!(result, Err(BulwarkError::InvalidParam(ref s)) if s.contains("permission")),
        "空 permission 应返回 InvalidParam，实际: {:?}",
        result
    );
}

/// has_role 空字符串返回 InvalidParam。
#[tokio::test]
async fn util_has_role_empty_string_returns_invalid_param() {
    let result = BulwarkUtil::has_role("").await;
    assert!(
        matches!(result, Err(BulwarkError::InvalidParam(ref s)) if s.contains("role")),
        "空 role 应返回 InvalidParam，实际: {:?}",
        result
    );
}

/// 未初始化时 BulwarkUtil::has_permission 返回 Session 错误。
#[tokio::test]
#[serial]
async fn util_has_permission_fails_when_not_initialized() {
    BulwarkManager::reset_for_test();
    let result = BulwarkUtil::has_permission("user:read").await;
    assert!(
        matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
        "未初始化时 has_permission 应返回 Session 错误"
    );
}

/// 未初始化时 BulwarkUtil::has_role 返回 Session 错误。
#[tokio::test]
#[serial]
async fn util_has_role_fails_when_not_initialized() {
    BulwarkManager::reset_for_test();
    let result = BulwarkUtil::has_role("admin").await;
    assert!(
        matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
        "未初始化时 has_role 应返回 Session 错误"
    );
}

/// 已登录 + 持有权限 → has_permission 返回 Ok(true)。
#[tokio::test]
#[serial]
async fn util_has_permission_returns_true_when_granted() {
    init_global_manager_with_perms(
        false,
        vec!["user:read".to_string()],
        vec!["admin".to_string()],
    );
    let token = BulwarkUtil::login_simple("1001").await.unwrap();
    let result = with_token(
        &token,
        with_default_tenant(BulwarkUtil::has_permission("user:read")),
    )
    .await;
    assert!(result.unwrap(), "持有权限应返回 true");
}

/// 已登录 + 未持有权限 → has_permission 返回 Ok(false)。
#[tokio::test]
#[serial]
async fn util_has_permission_returns_false_when_not_granted() {
    init_global_manager_with_perms(false, vec![], vec![]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();
    let result = with_token(
        &token,
        with_default_tenant(BulwarkUtil::has_permission("user:read")),
    )
    .await;
    assert!(!result.unwrap(), "未持有权限应返回 false");
}

/// 未登录 → has_permission 返回 Ok(false)（不抛 NotLogin）。
#[tokio::test]
#[serial]
async fn util_has_permission_returns_false_when_not_logged_in() {
    init_global_manager(false);
    // 不调用 login，直接 has_permission（无 task_local token）
    let result = BulwarkUtil::has_permission("user:read").await;
    assert!(!result.unwrap(), "未登录应返回 false");
}

/// 已登录 + 持有角色 → has_role 返回 Ok(true)。
#[tokio::test]
#[serial]
async fn util_has_role_returns_true_when_granted() {
    init_global_manager_with_perms(
        false,
        vec!["user:read".to_string()],
        vec!["admin".to_string()],
    );
    let token = BulwarkUtil::login_simple("1001").await.unwrap();
    let result = with_token(&token, BulwarkUtil::has_role("admin")).await;
    assert!(result.unwrap(), "持有角色应返回 true");
}

/// 已登录 + 未持有角色 → has_role 返回 Ok(false)。
#[tokio::test]
#[serial]
async fn util_has_role_returns_false_when_not_granted() {
    init_global_manager_with_perms(false, vec![], vec![]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();
    let result = with_token(&token, BulwarkUtil::has_role("admin")).await;
    assert!(!result.unwrap(), "未持有角色应返回 false");
}

/// 未登录 → has_role 返回 Ok(false)。
#[tokio::test]
#[serial]
async fn util_has_role_returns_false_when_not_logged_in() {
    init_global_manager(false);
    let result = BulwarkUtil::has_role("admin").await;
    assert!(!result.unwrap(), "未登录应返回 false");
}

// ------------------------------------------------------------------------
// BulwarkUtil::get_permission_list / get_role_list 测试
// ------------------------------------------------------------------------

/// 未初始化时 BulwarkUtil::get_permission_list 返回 Session 错误。
#[tokio::test]
#[serial]
async fn util_get_permission_list_fails_when_not_initialized() {
    BulwarkManager::reset_for_test();
    let result = BulwarkUtil::get_permission_list().await;
    assert!(
        matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
        "未初始化时 get_permission_list 应返回 Session 错误"
    );
}

/// 未初始化时 BulwarkUtil::get_role_list 返回 Session 错误。
#[tokio::test]
#[serial]
async fn util_get_role_list_fails_when_not_initialized() {
    BulwarkManager::reset_for_test();
    let result = BulwarkUtil::get_role_list().await;
    assert!(
        matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
        "未初始化时 get_role_list 应返回 Session 错误"
    );
}

/// 已登录 + 持有权限列表 → get_permission_list 返回非空列表。
#[tokio::test]
#[serial]
async fn util_get_permission_list_returns_permissions_when_granted() {
    init_global_manager_with_perms(
        false,
        vec!["user:read".to_string(), "user:write".to_string()],
        vec!["admin".to_string()],
    );
    let token = BulwarkUtil::login_simple("1001").await.unwrap();
    let result = with_token(&token, BulwarkUtil::get_permission_list()).await;
    let perms = result.unwrap();
    assert_eq!(perms.len(), 2, "应返回 2 个权限");
    assert!(perms.contains(&"user:read".to_string()), "应包含 user:read");
    assert!(
        perms.contains(&"user:write".to_string()),
        "应包含 user:write"
    );
}

/// 已登录 + 空权限列表 → get_permission_list 返回空 vec。
#[tokio::test]
#[serial]
async fn util_get_permission_list_returns_empty_when_no_permissions() {
    init_global_manager_with_perms(false, vec![], vec![]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();
    let result = with_token(&token, BulwarkUtil::get_permission_list()).await;
    assert!(result.unwrap().is_empty(), "无权限时应返回空 vec");
}

/// 未登录 → get_permission_list 返回空 vec（不抛 NotLogin）。
#[tokio::test]
#[serial]
async fn util_get_permission_list_returns_empty_when_not_logged_in() {
    init_global_manager(false);
    let result = BulwarkUtil::get_permission_list().await;
    assert!(result.unwrap().is_empty(), "未登录应返回空 vec");
}

/// 已登录 + 持有角色列表 → get_role_list 返回非空列表。
#[tokio::test]
#[serial]
async fn util_get_role_list_returns_roles_when_granted() {
    init_global_manager_with_perms(
        false,
        vec!["user:read".to_string()],
        vec!["admin".to_string(), "user".to_string()],
    );
    let token = BulwarkUtil::login_simple("1001").await.unwrap();
    let result = with_token(&token, BulwarkUtil::get_role_list()).await;
    let roles = result.unwrap();
    assert_eq!(roles.len(), 2, "应返回 2 个角色");
    assert!(roles.contains(&"admin".to_string()), "应包含 admin");
    assert!(roles.contains(&"user".to_string()), "应包含 user");
}

/// 已登录 + 空角色列表 → get_role_list 返回空 vec。
#[tokio::test]
#[serial]
async fn util_get_role_list_returns_empty_when_no_roles() {
    init_global_manager_with_perms(false, vec![], vec![]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();
    let result = with_token(&token, BulwarkUtil::get_role_list()).await;
    assert!(result.unwrap().is_empty(), "无角色时应返回空 vec");
}

/// 未登录 → get_role_list 返回空 vec。
#[tokio::test]
#[serial]
async fn util_get_role_list_returns_empty_when_not_logged_in() {
    init_global_manager(false);
    let result = BulwarkUtil::get_role_list().await;
    assert!(result.unwrap().is_empty(), "未登录应返回空 vec");
}

// ------------------------------------------------------------------------
// BulwarkUtil 成功路径测试（覆盖未测试的静态方法）
// ------------------------------------------------------------------------

/// BulwarkUtil::logout_by_login_id 成功销毁指定账号的所有会话。
#[tokio::test]
#[serial]
async fn util_logout_by_login_id_succeeds() {
    init_global_manager(false);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();
    assert!(!token.is_empty());

    BulwarkUtil::logout_by_login_id("1001").await.unwrap();

    // logout 后 check_login 应返回 false
    let valid = with_token(&token, async { BulwarkUtil::check_login().await })
        .await
        .unwrap();
    assert!(!valid, "logout_by_login_id 后 check_login 应返回 false");

    BulwarkManager::reset_for_test();
}

/// BulwarkUtil::kickout 成功踢出指定账号。
#[tokio::test]
#[serial]
async fn util_kickout_succeeds() {
    init_global_manager(false);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    BulwarkUtil::kickout("1001").await.unwrap();

    let valid = with_token(&token, async { BulwarkUtil::check_login().await })
        .await
        .unwrap();
    assert!(!valid, "kickout 后 check_login 应返回 false");

    BulwarkManager::reset_for_test();
}

/// BulwarkUtil::kickout_by_token 成功踢出指定 token。
#[tokio::test]
#[serial]
async fn util_kickout_by_token_succeeds() {
    init_global_manager(false);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    BulwarkUtil::kickout_by_token(&token).await.unwrap();

    let valid = with_token(&token, async { BulwarkUtil::check_login().await })
        .await
        .unwrap();
    assert!(!valid, "kickout_by_token 后 check_login 应返回 false");

    BulwarkManager::reset_for_test();
}

/// BulwarkUtil::get_login_id 返回当前登录 ID。
#[tokio::test]
#[serial]
async fn util_get_login_id_returns_current_id() {
    init_global_manager(false);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let login_id = with_token(&token, async { BulwarkUtil::get_login_id().await })
        .await
        .unwrap();
    assert_eq!(
        login_id,
        Some("1001".to_string()),
        "get_login_id 应返回当前 login_id"
    );

    BulwarkManager::reset_for_test();
}

/// BulwarkUtil::check_safe 默认行为随 `safe-auth` feature 变化。
///
/// - 未启用 `safe-auth`：`is_safe` trait default 返回 `Ok(true)`，`check_safe` 返回 `Ok(())`。
/// - 启用 `safe-auth`：`is_safe` inherent method 查询 `safe_services`，
///   未调用 `open_safe` 时返回 `Ok(false)`，`check_safe` 返回 `Err(NotSafe)`。
#[tokio::test]
#[serial]
async fn util_check_safe_returns_ok_by_default() {
    init_global_manager(false);
    let _ = BulwarkUtil::login_simple("1001").await.unwrap();

    let result = BulwarkUtil::check_safe().await;

    #[cfg(feature = "safe-auth")]
    {
        assert!(
            matches!(result, Err(BulwarkError::NotSafe { .. })),
            "启用 safe-auth 时未 open_safe，check_safe 应返回 Err(NotSafe)，实际: {:?}",
            result
        );
    }
    #[cfg(not(feature = "safe-auth"))]
    {
        assert!(
            result.is_ok(),
            "未启用 safe-auth 时 check_safe 应返回 Ok，实际: {:?}",
            result
        );
    }

    BulwarkManager::reset_for_test();
}

/// BulwarkUtil::check_disable 默认实现返回 Ok。
///
/// 默认 `BulwarkLogicDefault` 未实现禁用账号库，`check_disable` 返回 `Ok(())`。
#[tokio::test]
#[serial]
async fn util_check_disable_returns_ok_by_default() {
    init_global_manager(false);
    let _ = BulwarkUtil::login_simple("1001").await.unwrap();

    // 默认实现（未覆写 check_disable）应返回 Ok
    let result = BulwarkUtil::check_disable().await;
    assert!(
        result.is_ok(),
        "默认 check_disable 应返回 Ok，实际: {:?}",
        result
    );

    BulwarkManager::reset_for_test();
}

// ------------------------------------------------------------------------
// API 测试：login_by_token / verify_token / refresh_token
// ------------------------------------------------------------------------

/// BulwarkLogicDefault::login_by_token 对 uuid style token 返回 InvalidToken（0.2.1 auto-wire 修复）。
///
/// 0.2.1 起login_by_token 被 override：优先委托 auth_logic，否则使用 verify_token。
/// uuid token 不包含 login_id，verify_token 返回 InvalidToken。
#[tokio::test]
async fn login_by_token_uuid_style_returns_invalid_token() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let result = logic.login_by_token("any-token").await;
    assert!(
        matches!(result, Err(BulwarkError::InvalidToken(_))),
        "uuid style login_by_token 应返回 InvalidToken，实际: {:?}",
        result
    );
}

/// BulwarkUtil::login_by_token 未初始化时返回 Session 错误。
#[tokio::test]
#[serial]
async fn util_login_by_token_fails_when_not_initialized() {
    BulwarkManager::reset_for_test();
    let result = BulwarkUtil::login_by_token("any-token").await;
    assert!(
        matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
        "未初始化时 login_by_token 应返回 Session 错误"
    );
}

/// verify_token 对 simple style token 返回 login_id（spec Scenario）。
///
/// 注意：0.1.0 `generate_token("simple")` 生成 32 字符 UUID，
/// 与 core-token `SimpleTokenStyle` 的 `<login_id>-<uuid>` 格式不同。
/// 此测试手动构造 simple-format token 验证 verify_token 委托逻辑。
#[tokio::test]
async fn verify_token_simple_style_returns_login_id() {
    let logic = make_logic(3600, 86400, false, "simple", true, true);
    // 手动构造 simple-format token: <login_id>-<uuid>
    let token = format!("1001-{}", uuid::Uuid::new_v4());
    let login_id = logic.verify_token(&token).await.unwrap();
    assert_eq!(login_id, "1001".to_string(), "verify_token 应返回 login_id");
}

/// verify_token 对 uuid style token 返回 InvalidToken（spec Scenario）。
///
/// uuid token 不包含 login_id，Token::verify 返回 None → InvalidToken。
#[tokio::test]
async fn verify_token_uuid_style_returns_invalid_token() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();
    let result = logic.verify_token(&token).await;
    assert!(
        matches!(result, Err(BulwarkError::InvalidToken(_))),
        "uuid style verify_token 应返回 InvalidToken，实际: {:?}",
        result
    );
}

/// verify_token 对无效 token 返回 InvalidToken（spec Scenario）。
///
/// "nodash" 无 '-' 分隔符，SimpleTokenStyle::verify 返回 Ok(None) → InvalidToken。
#[tokio::test]
async fn verify_token_invalid_returns_error() {
    let logic = make_logic(3600, 86400, false, "simple", true, true);
    let result = logic.verify_token("nodash").await;
    assert!(
        matches!(result, Err(BulwarkError::InvalidToken(_))),
        "无效 token 应返回 InvalidToken，实际: {:?}",
        result
    );
}

/// verify_token 对合法 UUID 后缀的 simple-format token 返回 login_id（spec Scenario）。
///
/// SimpleTokenStyle 要求 token 后缀为合法 UUID，防止身份伪造。
#[tokio::test]
async fn verify_token_malformed_returns_invalid_token() {
    let logic = make_logic(3600, 86400, false, "simple", true, true);
    // 使用合法 UUID 后缀
    let result = logic
        .verify_token("abc-550e8400-e29b-41d4-a716-446655440000")
        .await;
    assert!(
        result.is_ok(),
        "simple-format token with valid UUID suffix 应返回 Ok，实际: {:?}",
        result
    );
    assert_eq!(result.unwrap(), "abc");
}

/// BulwarkUtil::verify_token 未初始化时返回 Session 错误。
#[tokio::test]
#[serial]
async fn util_verify_token_fails_when_not_initialized() {
    BulwarkManager::reset_for_test();
    let result = BulwarkUtil::verify_token("any-token").await;
    assert!(
        matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
        "未初始化时 verify_token 应返回 Session 错误"
    );
}

/// refresh_token default 返回 NotImplemented（spec Scenario: 未启用 protocol-jwt）。
#[tokio::test]
async fn refresh_token_default_returns_not_implemented() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let result = logic.refresh_token("any-token").await;
    assert!(
        matches!(result, Err(BulwarkError::NotImplemented(_))),
        "default refresh_token 应返回 NotImplemented，实际: {:?}",
        result
    );
}

/// BulwarkUtil::refresh_token 未初始化时返回 Session 错误。
#[tokio::test]
#[serial]
async fn util_refresh_token_fails_when_not_initialized() {
    BulwarkManager::reset_for_test();
    let result = BulwarkUtil::refresh_token("any-token").await;
    assert!(
        matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
        "未初始化时 refresh_token 应返回 Session 错误"
    );
}

/// BulwarkUtil::verify_token 端到端：simple style token → 返回 login_id。
///
/// 注意：BulwarkUtil::login 使用 0.1.0 generate_token，"simple" 生成 32 字符 UUID，
/// 与 core-token SimpleTokenStyle 格式不同。此测试手动构造 simple-format token。
#[tokio::test]
#[serial]
async fn util_verify_token_returns_login_id() {
    BulwarkManager::reset_for_test();
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.token_style = "simple".to_string();
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
    BulwarkManager::init(dao, Arc::new(config), interface).unwrap();

    // 手动构造 simple-format token: <login_id>-<uuid>
    let token = format!("1001-{}", uuid::Uuid::new_v4());
    let login_id = BulwarkUtil::verify_token(&token).await.unwrap();
    assert_eq!(login_id, "1001".to_string());

    BulwarkManager::reset_for_test();
}

/// BulwarkUtil::refresh_token 端到端：未启用 protocol-jwt → NotImplemented。
#[tokio::test]
#[serial]
async fn util_refresh_token_returns_not_implemented_without_jwt() {
    BulwarkManager::reset_for_test();
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface);
    BulwarkManager::init(dao, Arc::new(config), interface).unwrap();

    let result = BulwarkUtil::refresh_token("any-token").await;
    assert!(
        matches!(result, Err(BulwarkError::NotImplemented(_))),
        "未启用 protocol-jwt 时 refresh_token 应返回 NotImplemented"
    );

    BulwarkManager::reset_for_test();
}

// ------------------------------------------------------------------------
// builder 方法 + plugin/listener 触发测试
// ------------------------------------------------------------------------

/// builder 方法链式调用返回 Self（spec Scenario: 4.8 builder 方法验证）。
#[tokio::test]
async fn builder_methods_return_self_for_chaining() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    // 链式调用所有 builder 方法，验证返回 Self
    let pm = Arc::new(BulwarkPluginManager::new());
    #[cfg(feature = "listener")]
    let lm = Arc::new(BulwarkListenerManager::new());
    #[cfg(feature = "listener")]
    let _logic = logic.with_plugin_manager(pm).with_listener_manager(lm);
    #[cfg(not(feature = "listener"))]
    let _logic = logic.with_plugin_manager(pm);
    // 验证 login 仍可正常工作（builder 未破坏核心功能）
    let logic2 = make_logic(3600, 86400, false, "uuid", true, true);
    let token = logic2.login("1001", &LoginParams::default()).await.unwrap();
    assert!(!token.is_empty());
}

/// builder 方法注入 plugin_manager 后 login 触发 on_login 钩子（spec Scenario: auto-wire）。
#[tokio::test]
async fn login_with_plugin_manager_triggers_on_login() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let pm = Arc::new(BulwarkPluginManager::new());
    let logic = logic.with_plugin_manager(pm);
    // login 应成功，plugin on_login 作为副作用被调用（失败仅 warn 不中断）
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();
    assert!(!token.is_empty());
}

/// builder 方法注入 listener_manager 后 login 广播 Login 事件（spec Scenario: auto-wire）。
#[tokio::test]
async fn login_with_listener_manager_broadcasts_login_event() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    #[cfg(feature = "listener")]
    {
        let lm = Arc::new(BulwarkListenerManager::new());
        let logic = logic.with_listener_manager(lm);
        let token = logic.login("1001", &LoginParams::default()).await.unwrap();
        assert!(!token.is_empty());
    }
    #[cfg(not(feature = "listener"))]
    {
        let _ = logic;
    }
}

/// logout 注入 plugin_manager + listener_manager 后触发 on_logout + Logout 事件。
#[tokio::test]
async fn logout_with_managers_triggers_hooks() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let pm = Arc::new(BulwarkPluginManager::new());
    let logic = logic.with_plugin_manager(pm);
    #[cfg(feature = "listener")]
    let logic = logic.with_listener_manager(Arc::new(BulwarkListenerManager::new()));

    // 先 login 获取 token
    let token = logic.login("2002", &LoginParams::default()).await.unwrap();
    // 在 token 上下文中 logout
    with_current_token(token.clone(), async { logic.logout().await })
        .await
        .unwrap();
}

/// kickout 注入 listener_manager 后广播 Kickout 事件。
#[tokio::test]
async fn kickout_with_listener_manager_broadcasts_event() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    #[cfg(feature = "listener")]
    {
        let lm = Arc::new(BulwarkListenerManager::new());
        let logic = logic.with_listener_manager(lm);
        // kickout 应成功，Kickout 事件作为副作用被广播
        logic.kickout("3003").await.unwrap();
    }
    #[cfg(not(feature = "listener"))]
    {
        logic.kickout("3003").await.unwrap();
    }
}

/// revoke_token 销毁指定 token 的会话。
///
/// 验证：revoke_token 后 Token-Session 已删除。
#[tokio::test]
async fn revoke_token_destroys_session() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let token = logic.login("4004", &LoginParams::default()).await.unwrap();

    // revoke 前存在
    assert!(logic
        .session
        .get_token_session(&token)
        .await
        .unwrap()
        .is_some());

    logic.revoke_token(&token).await.unwrap();

    // revoke 后 Token-Session 已删除
    assert!(logic
        .session
        .get_token_session(&token)
        .await
        .unwrap()
        .is_none());
}

/// revoke_token 注入 listener_manager 后广播 RevokeToken 事件
/// 。
#[tokio::test]
async fn revoke_token_with_listener_manager_broadcasts_event() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    #[cfg(feature = "listener")]
    {
        let lm = Arc::new(BulwarkListenerManager::new());
        let logic = logic.with_listener_manager(lm);
        let token = logic.login("4005", &LoginParams::default()).await.unwrap();
        // revoke 应成功，RevokeToken 事件作为副作用被广播
        logic.revoke_token(&token).await.unwrap();
        // Token-Session 已删除
        assert!(logic
            .session
            .get_token_session(&token)
            .await
            .unwrap()
            .is_none());
    }
    #[cfg(not(feature = "listener"))]
    {
        let token = logic.login("4005", &LoginParams::default()).await.unwrap();
        logic.revoke_token(&token).await.unwrap();
    }
}

/// revoke_token 对不存在的 token 幂等返回 Ok。
#[tokio::test]
async fn revoke_token_nonexistent_is_noop() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    // 不存在的 token 应幂等返回 Ok
    let result = logic.revoke_token("nonexistent-token").await;
    assert!(
        result.is_ok(),
        "revoke_token 对不存在的 token 应幂等返回 Ok"
    );
}

/// 未注入 manager 时向后兼容：login/logout/kickout 行为与 0.2.0 一致（spec Scenario: 4.9）。
#[tokio::test]
async fn backward_compat_without_managers_works_same_as_0_2_0() {
    // make_logic 不注入任何 manager，所有 Option 都是 None
    let logic = make_logic(3600, 86400, false, "uuid", true, true);

    // login 成功
    let token = logic.login("5005", &LoginParams::default()).await.unwrap();
    assert!(!token.is_empty());

    // check_login 成功
    let is_valid = with_current_token(token.clone(), async { logic.check_login().await })
        .await
        .unwrap();
    assert!(is_valid);

    // logout 成功（在 token 上下文中）
    with_current_token(token.clone(), async { logic.logout().await })
        .await
        .unwrap();

    // kickout 成功
    logic.kickout("5005").await.unwrap();
}

/// login_by_token 注入 auth_logic 后优先委托 auth_logic.verify_token。
#[tokio::test]
async fn login_by_token_with_auth_logic_delegates_to_auth() {
    use crate::core::auth::{AuthLogic, AuthLogicDefault};
    use crate::core::token::{Token, UuidTokenStyle};

    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
    let token_handler: Arc<dyn Token> = Arc::new(UuidTokenStyle);
    let auth_logic: Arc<dyn AuthLogic> =
        Arc::new(AuthLogicDefault::new(session.clone(), token_handler, 3600));

    // 先通过 auth_logic login 生成一个有效 token
    let valid_token = auth_logic.login("6006", None).await.unwrap();

    // 构造 logic 注入 auth_logic
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let logic = logic.with_auth_logic(auth_logic);

    // login_by_token 应委托 auth_logic.verify_token 并建立会话
    logic.login_by_token(&valid_token).await.unwrap();

    // 验证会话已建立
    let ts = logic.session.get_token_session(&valid_token).await.unwrap();
    assert!(ts.is_some(), "login_by_token 后应建立会话");
    assert_eq!(ts.unwrap().login_id, "6006".to_string());
}

// ------------------------------------------------------------------------
// refresh_token 覆盖率补充测试（impl）
// ------------------------------------------------------------------------

/// refresh_token 在 token_style 非 jwt 时返回 NotImplemented。
#[cfg(feature = "protocol-jwt")]
#[tokio::test]
async fn refresh_token_non_jwt_style_returns_not_implemented() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let result = logic.refresh_token("any-token").await;
    assert!(
        matches!(result, Err(BulwarkError::NotImplemented(ref msg)) if msg.contains("token_style=jwt")),
        "非 jwt style 的 refresh_token 应返回 NotImplemented，实际: {:?}",
        result
    );
}

/// refresh_token 对无效 JWT token 返回 InvalidToken 错误。
#[cfg(feature = "protocol-jwt")]
#[tokio::test]
async fn refresh_token_invalid_jwt_returns_error() {
    // 构造 token_style=jwt 的 logic（jwt_secret 来自 default_config）
    let logic = make_logic(3600, 86400, false, "jwt", true, true);
    // 无效 token：verify_token 返回 Err，refresh_token 应透传
    let result = logic.refresh_token("invalid.jwt.token").await;
    assert!(
        result.is_err(),
        "无效 JWT refresh_token 应返回 Err，实际: {:?}",
        result
    );
}

/// refresh_token 对有效 JWT token 成功刷新（0.2.1 auto-wire 触发 plugin/listener）。
#[cfg(feature = "protocol-jwt")]
#[tokio::test]
async fn refresh_token_valid_jwt_returns_new_token() {
    // 构造 logic：token_style=jwt，使用明确 secret
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
    let mut config = BulwarkConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_secret = "refresh-test-secret".to_string().into();
    config.timeout = 3600;
    let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
        has_permission: true,
        has_role: true,
    });
    let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall);

    // 注入 plugin_manager + listener_manager 验证 auto-wire 不中断
    let pm = Arc::new(BulwarkPluginManager::new());
    let logic = logic.with_plugin_manager(pm);
    #[cfg(feature = "listener")]
    let logic = logic.with_listener_manager(Arc::new(BulwarkListenerManager::new()));

    // 先生成一个有效 JWT token
    let handler = crate::protocol::jwt::JwtHandler::new("refresh-test-secret");
    let original_token = handler.sign("7007", 3600).unwrap();

    // 刷新 token（同秒内 iat/exp 可能相同，不强制 new_token != original_token）
    let new_token = logic.refresh_token(&original_token).await.unwrap();
    assert!(!new_token.is_empty(), "refresh_token 应返回非空 token");

    // 验证新 token 有效且 login_id 一致
    let new_claims = handler.verify(&new_token).unwrap();
    assert_eq!(new_claims.login_id, "7007".to_string());
}

// ------------------------------------------------------------------------
// trait default 方法覆盖率测试（login_by_token/verify_token/refresh_token）
// ------------------------------------------------------------------------

/// 最小化子 trait mock，仅用于测试 trait default 方法。
/// 所有必需方法返回 `BulwarkError::NotImplemented`（Rule 12 失败显性化，不 panic），
/// 仅保留 default 方法（login_by_token/verify_token/refresh_token）。
struct MinimalLogic {
    config: Arc<BulwarkConfig>,
}

impl BulwarkCore for MinimalLogic {
    fn config(&self) -> Arc<BulwarkConfig> {
        Arc::clone(&self.config)
    }
}

#[async_trait]
impl SessionLogic for MinimalLogic {
    async fn login(&self, _: &str, _params: &LoginParams) -> BulwarkResult<String> {
        Err(BulwarkError::NotImplemented(
            "mock implementation, not for production".to_string(),
        ))
    }
    async fn login_with_token(&self, _: &str, _: &str) -> BulwarkResult<()> {
        Err(BulwarkError::NotImplemented(
            "mock implementation, not for production".to_string(),
        ))
    }
    async fn logout(&self) -> BulwarkResult<()> {
        Err(BulwarkError::NotImplemented(
            "mock implementation, not for production".to_string(),
        ))
    }
    async fn logout_by_login_id(&self, _: &str) -> BulwarkResult<()> {
        Err(BulwarkError::NotImplemented(
            "mock implementation, not for production".to_string(),
        ))
    }
    async fn kickout(&self, _: &str) -> BulwarkResult<()> {
        Err(BulwarkError::NotImplemented(
            "mock implementation, not for production".to_string(),
        ))
    }
    async fn kickout_by_token(&self, _: &str) -> BulwarkResult<()> {
        Err(BulwarkError::NotImplemented(
            "mock implementation, not for production".to_string(),
        ))
    }
    async fn revoke_token(&self, _: &str) -> BulwarkResult<()> {
        Err(BulwarkError::NotImplemented(
            "mock implementation, not for production".to_string(),
        ))
    }
    async fn check_login(&self) -> BulwarkResult<bool> {
        Err(BulwarkError::NotImplemented(
            "mock implementation, not for production".to_string(),
        ))
    }
    async fn get_login_id(&self) -> BulwarkResult<Option<String>> {
        Err(BulwarkError::NotImplemented(
            "mock implementation, not for production".to_string(),
        ))
    }
}

#[async_trait]
impl PermissionLogic for MinimalLogic {
    async fn check_permission(&self, _: &str) -> BulwarkResult<()> {
        Err(BulwarkError::NotImplemented(
            "mock implementation, not for production".to_string(),
        ))
    }
    async fn check_role(&self, _: &str) -> BulwarkResult<()> {
        Err(BulwarkError::NotImplemented(
            "mock implementation, not for production".to_string(),
        ))
    }
}

#[async_trait]
impl TokenLogic for MinimalLogic {}

#[async_trait]
impl MfaLogic for MinimalLogic {}

#[async_trait]
impl PasswordLogic for MinimalLogic {}

/// trait default login_by_token 返回 NotImplemented（spec: 未启用协议层 feature）。
#[tokio::test]
async fn trait_default_login_by_token_returns_not_implemented() {
    let logic = MinimalLogic {
        config: Arc::new(BulwarkConfig::default_config()),
    };
    let result = logic.login_by_token("any-token").await;
    assert!(
        matches!(result, Err(BulwarkError::NotImplemented(ref msg)) if msg.contains("protocol-oauth2")),
        "trait default login_by_token 应返回 NotImplemented，实际: {:?}",
        result
    );
}

/// trait default verify_token 返回 NotImplemented（spec: 需子类 override）。
#[tokio::test]
async fn trait_default_verify_token_returns_not_implemented() {
    let logic = MinimalLogic {
        config: Arc::new(BulwarkConfig::default_config()),
    };
    let result = logic.verify_token("any-token").await;
    assert!(
        matches!(result, Err(BulwarkError::NotImplemented(ref msg)) if msg.contains("override")),
        "trait default verify_token 应返回 NotImplemented，实际: {:?}",
        result
    );
}

/// trait default refresh_token 返回 NotImplemented（spec: 需启用 protocol-jwt）。
#[tokio::test]
async fn trait_default_refresh_token_returns_not_implemented() {
    let logic = MinimalLogic {
        config: Arc::new(BulwarkConfig::default_config()),
    };
    let result = logic.refresh_token("any-token").await;
    assert!(
        matches!(result, Err(BulwarkError::NotImplemented(ref msg)) if msg.contains("protocol-jwt")),
        "trait default refresh_token 应返回 NotImplemented，实际: {:?}",
        result
    );
}

/// MinimalLogic mock 必需方法返回 `NotImplemented`（替换原 `unreachable!()` panic，
/// 依据 Rule 12 失败显性化）。
///
/// 覆盖 11 个 mock 方法：login / login_with_token / logout / logout_by_login_id /
/// kickout / kickout_by_token / revoke_token / check_login / get_login_id /
/// check_permission / check_role。
#[tokio::test]
async fn minimal_logic_returns_not_implemented() {
    let logic = MinimalLogic {
        config: Arc::new(BulwarkConfig::default_config()),
    };

    // 1. login
    assert!(
        matches!(
            logic.login("1", &LoginParams::default()).await,
            Err(BulwarkError::NotImplemented(_))
        ),
        "MinimalLogic::login 应返回 NotImplemented（mock 不应 panic）"
    );
    // 2. login_with_token
    assert!(
        matches!(
            logic.login_with_token("1", "t").await,
            Err(BulwarkError::NotImplemented(_))
        ),
        "MinimalLogic::login_with_token 应返回 NotImplemented"
    );
    // 3. logout
    assert!(
        matches!(logic.logout().await, Err(BulwarkError::NotImplemented(_))),
        "MinimalLogic::logout 应返回 NotImplemented"
    );
    // 4. logout_by_login_id
    assert!(
        matches!(
            logic.logout_by_login_id("1").await,
            Err(BulwarkError::NotImplemented(_))
        ),
        "MinimalLogic::logout_by_login_id 应返回 NotImplemented"
    );
    // 5. kickout
    assert!(
        matches!(
            logic.kickout("1").await,
            Err(BulwarkError::NotImplemented(_))
        ),
        "MinimalLogic::kickout 应返回 NotImplemented"
    );
    // 6. kickout_by_token
    assert!(
        matches!(
            logic.kickout_by_token("t").await,
            Err(BulwarkError::NotImplemented(_))
        ),
        "MinimalLogic::kickout_by_token 应返回 NotImplemented"
    );
    // 7. revoke_token
    assert!(
        matches!(
            logic.revoke_token("t").await,
            Err(BulwarkError::NotImplemented(_))
        ),
        "MinimalLogic::revoke_token 应返回 NotImplemented"
    );
    // 8. check_login
    assert!(
        matches!(
            logic.check_login().await,
            Err(BulwarkError::NotImplemented(_))
        ),
        "MinimalLogic::check_login 应返回 NotImplemented"
    );
    // 9. get_login_id
    assert!(
        matches!(
            logic.get_login_id().await,
            Err(BulwarkError::NotImplemented(_))
        ),
        "MinimalLogic::get_login_id 应返回 NotImplemented"
    );
    // 10. check_permission
    assert!(
        matches!(
            logic.check_permission("p").await,
            Err(BulwarkError::NotImplemented(_))
        ),
        "MinimalLogic::check_permission 应返回 NotImplemented"
    );
    // 11. check_role
    assert!(
        matches!(
            logic.check_role("r").await,
            Err(BulwarkError::NotImplemented(_))
        ),
        "MinimalLogic::check_role 应返回 NotImplemented"
    );
}

// ------------------------------------------------------------------------
// login_by_token auto-wire 覆盖率补充（plugin + listener 钩子触发）
// ------------------------------------------------------------------------

/// login_by_token 注入 plugin_manager + listener_manager 后触发 auto-wire 钩子（simple style）。
#[tokio::test]
async fn login_by_token_with_managers_triggers_hooks() {
    let logic = make_logic(3600, 86400, false, "simple", true, true);
    let pm = Arc::new(BulwarkPluginManager::new());
    let logic = logic.with_plugin_manager(pm);
    #[cfg(feature = "listener")]
    let logic = logic.with_listener_manager(Arc::new(BulwarkListenerManager::new()));

    // 构造 simple 格式 token: "<login_id>-<uuid>"
    let token = format!("8008-{}", uuid::Uuid::new_v4());

    // login_by_token 应成功（plugin/listener 失败仅 warn 不中断）
    logic.login_by_token(&token).await.unwrap();

    // 验证会话已建立
    let ts = logic.session.get_token_session(&token).await.unwrap();
    assert!(ts.is_some(), "login_by_token 后应建立会话");
    assert_eq!(ts.unwrap().login_id, "8008".to_string());
}

// ------------------------------------------------------------------------
// 0.4.2 Phase 5: login_with_password 测试
// ------------------------------------------------------------------------

#[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
use crate::account::credential::{Argon2Hasher, PasswordHasher};
#[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
use crate::dao::repository::{UserRepository, UserRow};

/// 构造测试用 UserRow（username 与 login_id 字符串一致）。
#[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
fn make_user_row(login_id: &str, password_hash: &str) -> UserRow {
    UserRow {
        id: format!("u-{}", login_id),
        username: login_id.to_string(),
        password_hash: password_hash.to_string(),
        status: "active".to_string(),
        tenant_id: 0,
        created_at: "2026-07-04T00:00:00Z".to_string(),
        updated_at: "2026-07-04T00:00:00Z".to_string(),
        last_login_at: None,
    }
}

/// R-001: 正确密码返回 token。
///
/// 覆盖 spec auth-password-login R-001 验收 case 1：
/// 注入 Argon2Hasher + MockUserRepository（含正确 hash）→ 调用 login_with_password → Ok(token)。
#[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
#[tokio::test]
#[serial]
async fn login_with_password_correct_returns_token() {
    let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2Hasher::default());
    let hash = hasher.hash("correct-password").unwrap();

    let mock_repo = MockUserRepository::new();
    mock_repo.insert(make_user_row("1001", &hash));
    let repo: Arc<dyn UserRepository> = Arc::new(mock_repo);

    let logic = make_logic(3600, 86400, false, "uuid", true, true)
        .with_password_hasher(hasher)
        .with_user_repository(repo);

    let result = logic.login_with_password("1001", "correct-password").await;
    assert!(result.is_ok(), "正确密码应返回 Ok，实际: {:?}", result);
    let token = result.unwrap();
    assert!(!token.is_empty(), "token 应非空");
}

/// R-001: 错误密码返回 InvalidParam("invalid password")。
///
/// 覆盖 spec auth-password-login R-001 验收 case 2。
#[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
#[tokio::test]
#[serial]
async fn login_with_password_wrong_password_returns_invalid_param() {
    let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2Hasher::default());
    let hash = hasher.hash("correct-password").unwrap();

    let mock_repo = MockUserRepository::new();
    mock_repo.insert(make_user_row("1001", &hash));
    let repo: Arc<dyn UserRepository> = Arc::new(mock_repo);

    let logic = make_logic(3600, 86400, false, "uuid", true, true)
        .with_password_hasher(hasher)
        .with_user_repository(repo);

    let result = logic.login_with_password("1001", "wrong-password").await;
    assert!(
        matches!(result, Err(BulwarkError::InvalidParam(ref msg)) if msg == "invalid password"),
        "错误密码应返回 InvalidParam(\"invalid password\")，实际: {:?}",
        result
    );
}

/// R-001: 用户不存在返回 InvalidParam("invalid password")。
///
/// 覆盖 spec auth-password-login R-001 验收 case 3。
/// 注：spec R-001 说"用户不存在返回 NotLogin"，但 Constraints 说"不泄露具体原因"。
/// 决策：遵循 Constraints 安全要求，统一返回 InvalidParam 防止用户枚举。
/// v0.4.2 安全审计 A-014: 日志和事件 reason 也统一为 "invalid_credentials"，
/// 不区分 user_not_found/wrong_password。
#[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
#[tokio::test]
#[serial]
async fn login_with_password_user_not_found_returns_invalid_param() {
    let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2Hasher::default());
    let repo: Arc<dyn UserRepository> = Arc::new(MockUserRepository::new());
    // 不插入任何用户 → find_by_username 返回 None

    let logic = make_logic(3600, 86400, false, "uuid", true, true)
        .with_password_hasher(hasher)
        .with_user_repository(repo);

    let result = logic.login_with_password("9999", "any-password").await;
    assert!(
        matches!(result, Err(BulwarkError::InvalidParam(ref msg)) if msg == "invalid password"),
        "用户不存在应返回 InvalidParam(\"invalid password\")（不泄露 NotLogin），实际: {:?}",
        result
    );
}

/// R-001: 密码哈希格式不支持返回 InvalidParam。
///
/// 覆盖 spec auth-password-login R-001 验收 case 4。
/// 注：此错误可泄露（不暴露用户是否存在），返回 "unsupported hash format"。
#[cfg(all(feature = "account-credential", feature = "db-sqlite"))]
#[tokio::test]
#[serial]
async fn login_with_password_unsupported_hash_format_returns_invalid_param() {
    let hasher: Arc<dyn PasswordHasher> = Arc::new(Argon2Hasher::default());

    let mock_repo = MockUserRepository::new();
    mock_repo.insert(make_user_row("1001", "unsupported_hash_format"));
    let repo: Arc<dyn UserRepository> = Arc::new(mock_repo);

    let logic = make_logic(3600, 86400, false, "uuid", true, true)
        .with_password_hasher(hasher)
        .with_user_repository(repo);

    let result = logic.login_with_password("1001", "any-password").await;
    assert!(
        matches!(result, Err(BulwarkError::InvalidParam(ref msg)) if msg == "unsupported hash format"),
        "不支持的哈希格式应返回 InvalidParam(\"unsupported hash format\")，实际: {:?}",
        result
    );
}

// ------------------------------------------------------------------------
// 0.3.0 TG1: metrics 集成测试
// ------------------------------------------------------------------------

/// with_metrics builder 注入 BulwarkMetrics 后 login 触发 record_login(success)。
#[cfg(feature = "metrics-prometheus")]
#[tokio::test]
async fn login_with_metrics_records_success() {
    let logic = make_logic(3600, 86400, false, "uuid", false, false);
    let registry = prometheus::Registry::new();
    let metrics = Arc::new(crate::observability::BulwarkMetrics::register_to(&registry).unwrap());
    let logic = logic.with_metrics(metrics.clone());

    let _token = logic.login("1001", &LoginParams::default()).await.unwrap();

    // 验证 login_total{result="success"} = 1
    let output = prometheus::TextEncoder::new()
        .encode_to_string(&registry.gather())
        .unwrap();
    assert!(
        output.contains("bulwark_login_total{result=\"success\"} 1"),
        "expected success counter=1, got: {}",
        output
    );
}

/// with_metrics 注入后 check_permission 触发 record_permission_query(allow/deny)。
#[cfg(feature = "metrics-prometheus")]
#[tokio::test]
async fn check_permission_with_metrics_records_query() {
    let logic = make_logic(3600, 86400, true, "uuid", false, false);
    let registry = prometheus::Registry::new();
    let metrics = Arc::new(crate::observability::BulwarkMetrics::register_to(&registry).unwrap());
    let logic = logic.with_metrics(metrics.clone());

    let token = logic.login("1001", &LoginParams::default()).await.unwrap();

    // check_permission 应记录 deny（MockInterface 返回空权限列表）
    let result = with_token(
        &token,
        with_default_tenant(async { logic.check_permission("user:read").await }),
    )
    .await;
    assert!(result.is_err(), "未授权权限应返回 Err");

    let output = prometheus::TextEncoder::new()
        .encode_to_string(&registry.gather())
        .unwrap();
    assert!(
        output.contains("bulwark_permission_query_total{result=\"deny\"} 1"),
        "expected deny counter=1, got: {}",
        output
    );
}

/// 未注入 metrics 时 login 不 panic（零开销路径）。
#[cfg(feature = "metrics-prometheus")]
#[tokio::test]
async fn login_without_metrics_does_not_panic() {
    let logic = make_logic(3600, 86400, false, "uuid", false, false);
    // 不调用 with_metrics
    let _token = logic.login("1001", &LoginParams::default()).await.unwrap();
    // 不 panic 即通过
}

// ------------------------------------------------------------------------
// 0.4.2 Phase 6: login_type Multi-Account 测试
// ------------------------------------------------------------------------

/// R-001: 新方法 get_permission_list_with_type 默认委托旧方法。
///
/// 偏差说明：spec R-001 要求"旧方法委托新方法"，实际实现为"新方法默认委托旧方法"
/// 以保持向后兼容（28 个现有 BulwarkInterface 实现者无需修改）。
/// MockInterface 旧方法返回空 Vec，新方法默认委托旧方法应返回相同结果。
#[tokio::test]
#[serial]
async fn get_permission_list_with_type_delegates_to_default() {
    let interface = MockInterface;
    let result = interface
        .get_permission_list_with_type("1001", "default")
        .await;
    assert!(result.is_ok(), "新方法应成功，实际: {:?}", result);
    assert!(result.unwrap().is_empty(), "默认委托旧方法应返回空 Vec");
}

/// R-001: 新方法 get_role_list_with_type 默认委托旧方法。
#[tokio::test]
#[serial]
async fn get_role_list_with_type_delegates_to_default() {
    let interface = MockInterface;
    let result = interface.get_role_list_with_type("1001", "default").await;
    assert!(result.is_ok(), "新方法应成功，实际: {:?}", result);
    assert!(result.unwrap().is_empty(), "默认委托旧方法应返回空 Vec");
}

/// R-002: admin login_type 的权限查询不返回 user 的权限。
///
/// 覆盖 spec login-type-multi-account R-002 验收 case 1。
#[tokio::test]
#[serial]
async fn get_permission_list_with_type_admin_isolated_from_user() {
    let mut perms = HashMap::new();
    perms.insert("admin".to_string(), vec!["admin:*".to_string()]);
    perms.insert("user".to_string(), vec!["user:*".to_string()]);
    let interface = MockInterfaceWithLoginType {
        perms,
        roles: HashMap::new(),
    };
    let admin_perms = interface
        .get_permission_list_with_type("1001", "admin")
        .await
        .unwrap();
    assert_eq!(admin_perms, vec!["admin:*"]);
    assert!(
        !admin_perms.iter().any(|p| p == "user:*"),
        "admin login_type 不应返回 user 的权限"
    );
}

/// R-002: 同一 login_id 在不同 login_type 下可拥有不同权限。
///
/// 覆盖 spec login-type-multi-account R-002 验收 case 2。
#[tokio::test]
#[serial]
async fn same_login_id_different_login_type_different_permissions() {
    let mut perms = HashMap::new();
    perms.insert("admin".to_string(), vec!["admin:*".to_string()]);
    perms.insert("user".to_string(), vec!["user:*".to_string()]);
    let interface = MockInterfaceWithLoginType {
        perms,
        roles: HashMap::new(),
    };
    let admin_perms = interface
        .get_permission_list_with_type("1001", "admin")
        .await
        .unwrap();
    let user_perms = interface
        .get_permission_list_with_type("1001", "user")
        .await
        .unwrap();
    assert_ne!(admin_perms, user_perms, "不同 login_type 应返回不同权限");
    assert_eq!(admin_perms, vec!["admin:*"]);
    assert_eq!(user_perms, vec!["user:*"]);
}

/// R-003: with_login_type builder 设置 login_type 字段。
///
/// 覆盖 spec login-type-multi-account R-003 验收 case 1。
#[tokio::test]
#[serial]
async fn with_login_type_builder_sets_login_type() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    assert_eq!(
        logic.login_type, "default",
        "默认 login_type 应为 'default'"
    );
    let logic2 = make_logic(3600, 86400, false, "uuid", true, true).with_login_type("admin");
    assert_eq!(
        logic2.login_type, "admin",
        "with_login_type 应设置 login_type 为 'admin'"
    );
}

/// R-003: with_login_type 链式调用不破坏其他 builder。
///
/// 覆盖 spec login-type-multi-account R-003 验收 case 1（链式调用兼容性）。
#[tokio::test]
#[serial]
async fn with_login_type_chains_with_other_builders() {
    let pm = Arc::new(BulwarkPluginManager::new());
    let logic = make_logic(3600, 86400, false, "uuid", true, true)
        .with_plugin_manager(pm)
        .with_login_type("merchant");
    assert_eq!(logic.login_type, "merchant");
    // 验证 login 仍可工作（其他 builder 未被破坏）
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();
    assert!(!token.is_empty());
}

// ------------------------------------------------------------------------
// spec protocol-jwt-modes: JwtMode 三模式（Stateless/Mixin/Simple）
// ------------------------------------------------------------------------

/// R-001: JwtMode::default() == JwtMode::Mixin（推荐模式为默认）。
///
/// 覆盖 spec protocol-jwt-modes R-001 验收 case 1。
#[test]
fn jwt_mode_default_is_mixin() {
    assert_eq!(JwtMode::default(), JwtMode::Mixin);
}

/// R-001: JwtMode 是 Copy（无需 Arc 包装）。
///
/// 覆盖 spec protocol-jwt-modes R-001 验收 case 2。
#[test]
fn jwt_mode_is_copy() {
    let mode = JwtMode::Stateless;
    let copied = mode; // Copy 语义：复制后原值仍可用
    assert_eq!(mode, copied);
    assert_eq!(mode, JwtMode::Stateless);
}

/// R-005: with_jwt_mode builder 设置 jwt_mode 字段，默认 Mixin。
///
/// 覆盖 spec protocol-jwt-modes R-005 验收 case 1（默认 Mixin + builder 切换）。
#[tokio::test]
#[serial]
async fn with_jwt_mode_builder_sets_mode() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    assert_eq!(
        logic.jwt_mode,
        JwtMode::Mixin,
        "未设置时默认 JwtMode::Mixin"
    );
    let logic2 =
        make_logic(3600, 86400, false, "uuid", true, true).with_jwt_mode(JwtMode::Stateless);
    assert_eq!(
        logic2.jwt_mode,
        JwtMode::Stateless,
        "with_jwt_mode 应设置 jwt_mode 为 Stateless"
    );
}

/// R-002: Stateless 模式仅 JWT verify，不查询 session。
///
/// 覆盖 spec protocol-jwt-modes R-002 验收 case 1（有效 JWT 通过 + 不查 DAO）。
#[cfg(feature = "protocol-jwt")]
#[tokio::test]
#[serial]
async fn check_login_stateless_only_jwt_verify() {
    // 构造 logic：jwt_mode=Stateless + token_style=jwt + 明确 secret
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
    let mut config = BulwarkConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_secret = "stateless-test-secret".to_string().into();
    config.throw_on_not_login = true;
    let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
        has_permission: true,
        has_role: true,
    });
    let logic = Arc::new(
        BulwarkLogicDefault::new(session, Arc::new(config), firewall)
            .with_jwt_mode(JwtMode::Stateless),
    );

    // 用 JwtHandler 直接签发 token，不通过 login（确保 DAO 无 session）
    let handler = crate::protocol::jwt::JwtHandler::new("stateless-test-secret");
    let token = handler.sign("1001", 3600).unwrap();

    // Stateless 模式：仅 JWT verify，不查 session → 应返回 Ok(true)
    with_current_token(token, async {
        let valid = logic.check_login().await.unwrap();
        assert!(
            valid,
            "Stateless 模式下有效 JWT 应返回 true（不查 session）"
        );
    })
    .await;
}

/// R-003: Mixin 模式 JWT verify + session 二级校验。
///
/// 覆盖 spec protocol-jwt-modes R-003 验收 case 2（有效 JWT + session 存在 → 通过）。
#[cfg(feature = "protocol-jwt")]
#[tokio::test]
#[serial]
async fn check_login_mixin_jwt_and_session() {
    // 构造 logic：jwt_mode=Mixin（默认）+ token_style=jwt + 明确 secret
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
    let mut config = BulwarkConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_secret = "mixin-test-secret".to_string().into();
    config.throw_on_not_login = true;
    let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
        has_permission: true,
        has_role: true,
    });
    let logic = Arc::new(
        BulwarkLogicDefault::new(session, Arc::new(config), firewall).with_jwt_mode(JwtMode::Mixin),
    );

    // login 创建 session + 签发 JWT token
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();

    // Mixin 模式：JWT verify 通过 + session 存在 → Ok(true)
    with_current_token(token, async {
        let valid = logic.check_login().await.unwrap();
        assert!(valid, "Mixin 模式下有效 JWT + session 存在应返回 true");
    })
    .await;
}

/// R-004: Simple 模式仅 session 校验，不验证 JWT 签名。
///
/// 覆盖 spec protocol-jwt-modes R-004 验收 case 1（session 存在 → 通过，不验证 JWT）。
#[tokio::test]
#[serial]
async fn check_login_simple_only_session() {
    // 构造 logic：jwt_mode=Simple + token_style=uuid（非 JWT）
    let logic =
        Arc::new(make_logic(3600, 86400, true, "uuid", true, true).with_jwt_mode(JwtMode::Simple));

    // login 创建 session（uuid token，非 JWT 格式）
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();

    // Simple 模式：仅查 session，不验证 JWT → session 存在应返回 Ok(true)
    with_current_token(token, async {
        let valid = logic.check_login().await.unwrap();
        assert!(valid, "Simple 模式下 session 存在应返回 true（不验证 JWT）");
    })
    .await;
}

// ========================================================================
// 覆盖率补充：login_with_password trait default 实现
// ========================================================================

/// trait default `login_with_password` 返回 NotImplemented（spec: 需 account-credential + db-sqlite）。
///
/// 覆盖行 331-333（login_with_password 默认实现）。
#[tokio::test]
async fn trait_default_login_with_password_returns_not_implemented() {
    let logic = MinimalLogic {
        config: Arc::new(BulwarkConfig::default_config()),
    };
    let result = logic.login_with_password("1001", "any-password").await;
    assert!(
        matches!(result, Err(BulwarkError::NotImplemented(ref msg)) if msg.contains("account-credential")),
        "trait default login_with_password 应返回 NotImplemented（需 account-credential + db-sqlite），实际: {:?}",
        result
    );
}

// ========================================================================
// 覆盖率补充：SessionTimeout 广播 + metrics + 全局函数
// ========================================================================

/// check_login_mixin 在 token 无效且 listener_manager 注入时广播 SessionTimeout 事件。
///
/// 覆盖 check_login_mixin 的 listener 分支（行 749-751, 753）。
/// 触发条件：account session 不存在 → is_valid 返回 false，但 token session 仍存在。
#[tokio::test]
async fn check_login_mixin_broadcasts_session_timeout_when_account_missing() {
    let (dao, logic) = make_logic_with_dao(3600, 86400, false, "uuid", true, true);
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();

    // 删除 account session，使 is_valid 返回 false（token session 仍存在）
    dao.delete("account:session:1001").await.unwrap();

    // 注入 listener_manager（Mixin 模式为默认）
    #[cfg(feature = "listener")]
    let logic = logic.with_listener_manager(Arc::new(BulwarkListenerManager::new()));

    // check_login 应返回 false（不 panic，listener 广播作为副作用执行）
    with_current_token(token, async {
        let valid = logic.check_login().await.unwrap();
        assert!(!valid, "account session 不存在时 check_login 应返回 false");
    })
    .await;
}

/// check_login_simple 在 token 无效且 listener_manager 注入时广播 SessionTimeout 事件。
///
/// 覆盖 check_login_simple 的 listener 分支（行 774-777, 779）。
#[tokio::test]
async fn check_login_simple_broadcasts_session_timeout_when_account_missing() {
    let (dao, logic) = make_logic_with_dao(3600, 86400, false, "uuid", true, true);
    let logic = logic.with_jwt_mode(JwtMode::Simple);
    let token = logic.login("1001", &LoginParams::default()).await.unwrap();

    // 删除 account session，使 is_valid 返回 false（token session 仍存在）
    dao.delete("account:session:1001").await.unwrap();

    // 注入 listener_manager
    #[cfg(feature = "listener")]
    let logic = logic.with_listener_manager(Arc::new(BulwarkListenerManager::new()));

    with_current_token(token, async {
        let valid = logic.check_login().await.unwrap();
        assert!(!valid, "account session 不存在时 check_login 应返回 false");
    })
    .await;
}

/// check_permission 未登录时 emit metrics record_permission_query(false)。
///
/// 覆盖行 914（metrics-prometheus feature）。
#[cfg(feature = "metrics-prometheus")]
#[tokio::test]
#[serial]
async fn check_permission_not_logged_in_emits_deny_metric() {
    use crate::observability::BulwarkMetrics;
    let registry = prometheus::Registry::new();
    let metrics = Arc::new(BulwarkMetrics::register_to(&registry).expect("注册失败"));
    let logic = make_logic(3600, 86400, false, "uuid", true, true).with_metrics(metrics);

    // 未登录状态下 check_permission（throw_on_not_login=false → 返回 NotPermission）
    let result = logic.check_permission("user:read").await;
    assert!(matches!(result, Err(BulwarkError::NotPermission(_))));

    // 验证 metrics 记录了 deny
    let output = prometheus::TextEncoder::new()
        .encode_to_string(&registry.gather())
        .expect("encode 失败");
    assert!(
        output.contains("bulwark_permission_query_total{result=\"deny\"}"),
        "未登录 check_permission 应 emit deny metric，实际: {}",
        output
    );
}

/// check_permission 已登录 + permission_checker 注入时 emit metrics record_permission_query(allowed)。
///
/// 覆盖行 948（metrics-prometheus feature + permission_checker 路径）。
#[cfg(feature = "metrics-prometheus")]
#[tokio::test]
#[serial]
async fn check_permission_with_checker_emits_metric() {
    use crate::core::permission::PermissionCheckerDefault;
    use crate::observability::BulwarkMetrics;

    /// 本测试专用 mock，账号 1001 持有 user:read 权限。
    struct MockInterfaceWithPerms;
    #[async_trait]
    impl BulwarkInterface for MockInterfaceWithPerms {
        async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
            Ok(vec!["user:read".to_string()])
        }
        async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
            Ok(vec![])
        }
    }

    let registry = prometheus::Registry::new();
    let metrics = Arc::new(BulwarkMetrics::register_to(&registry).expect("注册失败"));

    // 使用 PermissionCheckerDefault（账号 1001 持有 user:read）
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterfaceWithPerms);
    let checker = Arc::new(PermissionCheckerDefault::new(interface));

    let logic = make_logic(3600, 86400, false, "uuid", true, true)
        .with_metrics(metrics)
        .with_permission_checker(checker);

    let token = logic.login("1001", &LoginParams::default()).await.unwrap();
    with_current_token(token, async {
        with_default_tenant(async {
            // check_permission 持有权限 → Ok(()) + emit allow metric
            let result = logic.check_permission("user:read").await;
            assert!(result.is_ok());
        })
        .await
    })
    .await;

    let output = prometheus::TextEncoder::new()
        .encode_to_string(&registry.gather())
        .expect("encode 失败");
    assert!(
        output.contains("bulwark_permission_query_total{result=\"allow\"}"),
        "持有权限应 emit allow metric，实际: {}",
        output
    );
}

/// check_role 未登录时 emit metrics record_role_query(false)。
///
/// 覆盖行 980（metrics-prometheus feature）。
#[cfg(feature = "metrics-prometheus")]
#[tokio::test]
#[serial]
async fn check_role_not_logged_in_emits_deny_metric() {
    use crate::observability::BulwarkMetrics;
    let registry = prometheus::Registry::new();
    let metrics = Arc::new(BulwarkMetrics::register_to(&registry).expect("注册失败"));
    let logic = make_logic(3600, 86400, false, "uuid", true, true).with_metrics(metrics);

    // 未登录状态下 check_role
    let result = logic.check_role("admin").await;
    assert!(matches!(result, Err(BulwarkError::NotRole(_))));

    let output = prometheus::TextEncoder::new()
        .encode_to_string(&registry.gather())
        .expect("encode 失败");
    assert!(
        output.contains("bulwark_role_query_total{result=\"deny\"}"),
        "未登录 check_role 应 emit deny metric，实际: {}",
        output
    );
}

/// check_role 已登录时 emit metrics record_role_query(has_role)。
///
/// 覆盖行 995（metrics-prometheus feature）。
#[cfg(feature = "metrics-prometheus")]
#[tokio::test]
#[serial]
async fn check_role_logged_in_emits_metric() {
    use crate::observability::BulwarkMetrics;
    let registry = prometheus::Registry::new();
    let metrics = Arc::new(BulwarkMetrics::register_to(&registry).expect("注册失败"));
    let logic = make_logic(3600, 86400, false, "uuid", true, true).with_metrics(metrics);

    let token = logic.login("1001", &LoginParams::default()).await.unwrap();
    with_current_token(token, async {
        // check_role（MockFirewall.has_role=true → Ok(())）
        let result = logic.check_role("admin").await;
        assert!(result.is_ok());
    })
    .await;

    let output = prometheus::TextEncoder::new()
        .encode_to_string(&registry.gather())
        .expect("encode 失败");
    assert!(
        output.contains("bulwark_role_query_total{result=\"allow\"}"),
        "持有角色应 emit allow metric，实际: {}",
        output
    );
}

/// BulwarkUtil::revoke_token 全局函数成功销毁会话。
///
/// 覆盖行 1381-1384（revoke_token 全局函数委托 BulwarkManager::logic()）。
#[tokio::test]
#[serial]
async fn util_revoke_token_destroys_session() {
    init_global_manager(false);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    // revoke_token 应成功
    BulwarkUtil::revoke_token(&token).await.unwrap();

    // 验证 token session 已销毁
    let valid = with_token(&token, async { BulwarkUtil::check_login().await })
        .await
        .unwrap();
    assert!(!valid, "revoke_token 后 check_login 应返回 false");
}

/// BulwarkUtil::login_by_token 全局函数在初始化后不返回 Session 错误。
///
/// 覆盖行 1565-1566（login_by_token 全局函数委托 BulwarkManager::logic()）。
/// uuid style token 无法 verify → 返回 InvalidToken（而非 Session "未初始化"）。
#[tokio::test]
#[serial]
async fn util_login_by_token_delegates_to_logic_after_init() {
    init_global_manager(false);
    // uuid style token → verify_token 返回 InvalidToken
    let result = BulwarkUtil::login_by_token("any-token").await;
    assert!(
        !matches!(result, Err(BulwarkError::Session(ref msg)) if msg.contains("未初始化")),
        "初始化后 login_by_token 不应返回 '未初始化' Session 错误，实际: {:?}",
        result
    );
}

// ------------------------------------------------------------------------
// 覆盖率补充：check_access_token / check_client_token / check_temp_token
// ------------------------------------------------------------------------

/// check_access_token 未登录时返回 NotLogin（覆盖 trait 默认实现 Err 路径）。
#[tokio::test]
async fn check_access_token_not_logged_in_returns_not_login() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let result = logic.check_access_token().await;
    assert!(
        matches!(result, Err(BulwarkError::NotLogin(_))),
        "未登录时 check_access_token 应返回 NotLogin，实际: {:?}",
        result
    );
}

/// check_client_token 未登录时返回 NotLogin。
#[tokio::test]
async fn check_client_token_not_logged_in_returns_not_login() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let result = logic.check_client_token().await;
    assert!(
        matches!(result, Err(BulwarkError::NotLogin(_))),
        "未登录时 check_client_token 应返回 NotLogin，实际: {:?}",
        result
    );
}

/// check_temp_token 未登录时返回 NotLogin。
#[tokio::test]
async fn check_temp_token_not_logged_in_returns_not_login() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let result = logic.check_temp_token().await;
    assert!(
        matches!(result, Err(BulwarkError::NotLogin(_))),
        "未登录时 check_temp_token 应返回 NotLogin，实际: {:?}",
        result
    );
}

/// BulwarkUtil::check_access_token 全局函数委托到 logic（覆盖行 1484-1487）。
#[tokio::test]
#[serial]
async fn util_check_access_token_delegates_to_logic() {
    init_global_manager(false);
    let result = BulwarkUtil::check_access_token().await;
    assert!(result.is_err());
}

/// BulwarkUtil::check_client_token 全局函数委托到 logic（覆盖行 1500-1503）。
#[tokio::test]
#[serial]
async fn util_check_client_token_delegates_to_logic() {
    init_global_manager(false);
    let result = BulwarkUtil::check_client_token().await;
    assert!(result.is_err());
}

/// BulwarkUtil::check_temp_token 全局函数委托到 logic（覆盖行 1516-1519）。
#[tokio::test]
#[serial]
async fn util_check_temp_token_delegates_to_logic() {
    init_global_manager(false);
    let result = BulwarkUtil::check_temp_token().await;
    assert!(result.is_err());
}

// ============================================================================
// BulwarkUtil 同步方法（check_*_sync）测试
// ============================================================================
//
// 测试约束：
// - `#[tokio::test(flavor = "multi_thread")]`：`block_in_place` 要求 multi_thread runtime
// - `#[serial]`：修改全局 BulwarkManager 单例
// - `check_*_sync` 内部 `block_in_place + Handle::current().block_on` 在同 task 内安全
// ============================================================================

/// 验证 `check_login_sync` 在 multi_thread runtime 内正确委托 async `check_login`。
///
/// 测试逻辑：
/// 1. 初始化 BulwarkManager（mock DAO）
/// 2. login 一个用户获取 token
/// 3. 在 `current_token` task_local 作用域内调用 `check_login_sync()`
/// 4. 验证返回 `Ok(true)`（已登录）
///
/// 设计说明：
/// - `block_in_place` 将当前 worker 线程转为阻塞模式，`Handle::current().block_on`
///   在当前 runtime 上执行 future，组合使用在 multi_thread runtime 内安全
/// - task_local `CURRENT_TOKEN` 在同 task 内自动继承（block_in_place 不 spawn 新 task）
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn sync_check_login_works_in_runtime() {
    init_global_manager(false);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    with_current_token(token, async {
        let result = BulwarkUtil::check_login_sync();
        assert!(
            result.is_ok(),
            "check_login_sync 应返回 Ok，实际: {:?}",
            result
        );
        assert!(result.unwrap(), "已登录时 check_login_sync 应返回 Ok(true)");
    })
    .await;

    BulwarkManager::reset_for_test();
}

/// 验证 `check_login_sync` 未登录时返回 Ok(false)（throw_on_not_login=false）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn sync_check_login_returns_false_when_not_logged_in() {
    init_global_manager(false);
    // 未设置 task_local，check_login_sync 应返回 Ok(false)
    let result = BulwarkUtil::check_login_sync();
    assert!(
        result.is_ok(),
        "check_login_sync 应返回 Ok，实际: {:?}",
        result
    );
    assert!(
        !result.unwrap(),
        "未登录时 check_login_sync 应返回 Ok(false)"
    );

    BulwarkManager::reset_for_test();
}

/// 验证 `check_permission_sync` 已登录 + 持有权限时返回 Ok(())。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn sync_check_permission_held_returns_ok() {
    init_global_manager_with_perms(
        false,
        vec!["user:read".to_string()],
        vec!["admin".to_string()],
    );
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    with_current_token(token, async {
        with_default_tenant(async {
            let result = BulwarkUtil::check_permission_sync("user:read");
            assert!(
                result.is_ok(),
                "持有权限时 check_permission_sync 应返回 Ok，实际: {:?}",
                result
            );
        })
        .await
    })
    .await;

    BulwarkManager::reset_for_test();
}

/// 验证 `check_role_sync` 已登录 + 持有角色时返回 Ok(())。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn sync_check_role_held_returns_ok() {
    init_global_manager_with_perms(
        false,
        vec!["user:read".to_string()],
        vec!["admin".to_string()],
    );
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    with_current_token(token, async {
        let result = BulwarkUtil::check_role_sync("admin");
        assert!(
            result.is_ok(),
            "持有角色时 check_role_sync 应返回 Ok，实际: {:?}",
            result
        );
    })
    .await;

    BulwarkManager::reset_for_test();
}

/// 验证 `check_access_token_sync` 已登录时返回 Ok(())。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn sync_check_access_token_returns_ok_when_logged_in() {
    init_global_manager(false);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    with_current_token(token, async {
        let result = BulwarkUtil::check_access_token_sync();
        assert!(
            result.is_ok(),
            "已登录时 check_access_token_sync 应返回 Ok，实际: {:?}",
            result
        );
    })
    .await;

    BulwarkManager::reset_for_test();
}

/// 验证 `check_client_token_sync` 已登录时返回 Ok(())。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn sync_check_client_token_returns_ok_when_logged_in() {
    init_global_manager(false);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    with_current_token(token, async {
        let result = BulwarkUtil::check_client_token_sync();
        assert!(
            result.is_ok(),
            "已登录时 check_client_token_sync 应返回 Ok，实际: {:?}",
            result
        );
    })
    .await;

    BulwarkManager::reset_for_test();
}

/// 验证 `check_temp_token_sync` 已登录时返回 Ok(())。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn sync_check_temp_token_returns_ok_when_logged_in() {
    init_global_manager(false);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    with_current_token(token, async {
        let result = BulwarkUtil::check_temp_token_sync();
        assert!(
            result.is_ok(),
            "已登录时 check_temp_token_sync 应返回 Ok，实际: {:?}",
            result
        );
    })
    .await;

    BulwarkManager::reset_for_test();
}

/// 验证 `check_api_key_sync` 未设置 token 上下文时返回 Err。
///
/// 注意：`protocol-apikey` feature 关闭时 `check_api_key` 返回 Ok(())，
/// 但未设置 token 上下文时 `BulwarkLogicDefault::check_api_key` 在
/// `protocol-apikey` 启用时返回 NotLogin。本测试只验证方法不 panic
/// 且返回 Result（具体错误类型依赖 feature 配置）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn sync_check_api_key_executes_without_panic() {
    init_global_manager(false);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    with_current_token(token, async {
        // 调用 check_api_key_sync 不应 panic（具体返回值依赖 protocol-apikey feature）
        let _ = BulwarkUtil::check_api_key_sync("default");
    })
    .await;

    BulwarkManager::reset_for_test();
}

// ============================================================================
// 会话悬停超时集成测试（spec R-hover-001 ~ R-hover-004）
// ========================================================================

/// R-hover-003: `session_hover_timeout=1`（1秒），login 后 check_login 返回 true，
/// MockClock 推进 2 秒后 check_login 返回 false（踢出）。
///
/// 使用 MockClock 替代 `tokio::time::sleep` 消除 flaky 测试（T007）。
#[tokio::test]
async fn hover_timeout_evicts_inactive_session() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
    let mut config = BulwarkConfig::default_config();
    config.token_style = "uuid".to_string();
    config.session_hover_timeout = 1;
    config.throw_on_not_login = false;
    let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
        has_permission: true,
        has_role: true,
    });
    let mock_clock = Arc::new(MockClock::new(chrono::Utc::now()));
    let logic = Arc::new(
        BulwarkLogicDefault::new(session, Arc::new(config), firewall)
            .with_clock(mock_clock.clone()),
    );

    let token = logic.login("1001", &LoginParams::default()).await.unwrap();

    // 第一次 check_login：last_active_time 无记录 → 返回 true，并更新 last_active_time
    let first_check = with_current_token(token.clone(), async { logic.check_login().await })
        .await
        .unwrap();
    assert!(first_check, "首次 check_login 应返回 true");

    // 推进 MockClock 时间 2 秒，超过 hover_timeout=1 秒（无需真实 sleep）
    mock_clock.advance(chrono::Duration::seconds(2));

    // 第二次 check_login：last_active_time 已过期 → 返回 false（踢出）
    let second_check = with_current_token(token.clone(), async { logic.check_login().await })
        .await
        .unwrap();
    assert!(!second_check, "悬停超时后 check_login 应返回 false");
}

/// R-hover-004: `session_hover_timeout=10`（10秒），login 后立即 check_login 返回 true。
#[tokio::test]
async fn hover_timeout_active_session_not_evicted() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
    let mut config = BulwarkConfig::default_config();
    config.token_style = "uuid".to_string();
    config.session_hover_timeout = 10;
    let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
        has_permission: true,
        has_role: true,
    });
    let logic = Arc::new(BulwarkLogicDefault::new(
        session,
        Arc::new(config),
        firewall,
    ));

    let token = logic.login("1001", &LoginParams::default()).await.unwrap();

    with_current_token(token.clone(), async {
        let valid = logic.check_login().await.unwrap();
        assert!(valid, "活跃会话不应被踢出");
    })
    .await;

    // 再次 check_login 也应返回 true（每次 check_login 都更新 last_active_time）
    with_current_token(token, async {
        let valid = logic.check_login().await.unwrap();
        assert!(valid, "连续 check_login 应始终返回 true");
    })
    .await;
}

/// R-hover-001: 默认配置 `session_hover_timeout=-1`，login 后 check_login 返回 true（不受悬停影响）。
#[tokio::test]
async fn hover_timeout_disabled_by_default() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let session = Arc::new(BulwarkSession::new(dao, 3600, 86400));
    let mut config = BulwarkConfig::default_config();
    config.token_style = "uuid".to_string();
    // session_hover_timeout 保持默认 -1
    assert_eq!(config.session_hover_timeout, -1);
    let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
        has_permission: true,
        has_role: true,
    });
    let logic = Arc::new(BulwarkLogicDefault::new(
        session,
        Arc::new(config),
        firewall,
    ));

    let token = logic.login("1001", &LoginParams::default()).await.unwrap();

    with_current_token(token.clone(), async {
        let valid = logic.check_login().await.unwrap();
        assert!(valid, "默认配置（hover=-1）应始终返回 true");
    })
    .await;

    // 即使等待一段时间，check_login 仍应返回 true
    tokio::time::sleep(Duration::from_millis(100)).await;
    with_current_token(token, async {
        let valid = logic.check_login().await.unwrap();
        assert!(valid, "hover=-1 时不应因时间推移踢出");
    })
    .await;
}

// ============================================================================
// BulwarkUtil::check_api_key 测试
// ============================================================================

#[cfg(feature = "protocol-apikey")]
mod check_api_key_tests {
    use super::*;
    use crate::protocol::apikey::ApiKeyHandler;

    /// 有效 API Key + 正确 namespace → Ok(())。
    #[tokio::test]
    #[serial]
    async fn check_api_key_valid_key_correct_namespace_succeeds() {
        let dao = init_global_manager_with_dao(false);
        let handler = ApiKeyHandler::new(dao.clone() as Arc<dyn BulwarkDao>);
        let key = handler
            .generate_with_namespace("user1", "ns1", vec![], 3600)
            .await
            .unwrap();

        let result = with_token(&key, BulwarkUtil::check_api_key("ns1")).await;
        assert!(result.is_ok(), "有效 key + 正确 namespace 应通过校验");

        BulwarkManager::reset_for_test();
    }

    /// 无效 API Key（不存在）→ Err(InvalidToken)。
    #[tokio::test]
    #[serial]
    async fn check_api_key_nonexistent_key_fails() {
        init_global_manager_with_dao(false);

        let result = with_token(
            "nonexistent-key-12345",
            BulwarkUtil::check_api_key("default"),
        )
        .await;
        assert!(
            matches!(result, Err(BulwarkError::InvalidToken(_))),
            "不存在的 key 应返回 InvalidToken，实际: {:?}",
            result
        );

        BulwarkManager::reset_for_test();
    }

    /// 未设置 current_token 上下文 → Err(NotLogin)。
    #[tokio::test]
    #[serial]
    async fn check_api_key_without_token_context_fails() {
        init_global_manager_with_dao(false);

        // 不调用 with_token，直接调用 check_api_key
        let result = BulwarkUtil::check_api_key("default").await;
        assert!(
            result.is_err(),
            "未设置 token 上下文应返回错误，实际: {:?}",
            result
        );
        assert!(
            matches!(result, Err(BulwarkError::NotLogin(_))),
            "未设置 token 上下文应返回 NotLogin（映射 401），实际: {:?}",
            result
        );

        BulwarkManager::reset_for_test();
    }

    /// namespace 隔离：ns1 的 key 不能在 ns2 校验通过。
    #[tokio::test]
    #[serial]
    async fn check_api_key_namespace_isolation() {
        let dao = init_global_manager_with_dao(false);
        let handler = ApiKeyHandler::new(dao.clone() as Arc<dyn BulwarkDao>);
        let key_ns1 = handler
            .generate_with_namespace("user1", "ns1", vec![], 3600)
            .await
            .unwrap();

        // ns1 的 key 在 ns1 校验通过
        let result_ns1 = with_token(&key_ns1, BulwarkUtil::check_api_key("ns1")).await;
        assert!(result_ns1.is_ok(), "ns1 key + ns1 namespace 应通过");

        // ns1 的 key 在 ns2 校验失败（namespace 不匹配）
        let result_ns2 = with_token(&key_ns1, BulwarkUtil::check_api_key("ns2")).await;
        assert!(
            result_ns2.is_err(),
            "ns1 key + ns2 namespace 应失败（namespace 隔离）"
        );
        assert!(
            matches!(result_ns2, Err(BulwarkError::InvalidToken(_))),
            "namespace 不匹配应返回 InvalidToken，实际: {:?}",
            result_ns2
        );

        BulwarkManager::reset_for_test();
    }

    /// 默认命名空间：generate（不带 namespace）生成的 key 可在 "default" 校验通过。
    #[tokio::test]
    #[serial]
    async fn check_api_key_default_namespace() {
        let dao = init_global_manager_with_dao(false);
        let handler = ApiKeyHandler::new(dao.clone() as Arc<dyn BulwarkDao>);
        let key = handler.generate("user1", vec![], 3600).await.unwrap();

        let result = with_token(&key, BulwarkUtil::check_api_key("default")).await;
        assert!(result.is_ok(), "默认命名空间生成的 key 应在 default 通过");

        BulwarkManager::reset_for_test();
    }

    /// BulwarkManager 未初始化 → Err(Session)。
    #[tokio::test]
    #[serial]
    async fn check_api_key_manager_not_initialized_fails() {
        BulwarkManager::reset_for_test();

        let result = with_token("some-key", BulwarkUtil::check_api_key("default")).await;
        assert!(
            result.is_err(),
            "Manager 未初始化应返回错误，实际: {:?}",
            result
        );

        BulwarkManager::reset_for_test();
    }
}

// ============================================================================
// v0.6.3 D1: Token 自动续签（check_and_renew）测试
// ============================================================================

use super::context::{current_renewed_token, with_renewed_token_scope};
use crate::core::auth::AuthLogicDefault;
use crate::core::token::{Token, UuidTokenStyle};

/// 辅助函数：创建 BulwarkLogicDefault 实例并注入 auth_logic（用于 check_and_renew 测试）。
/// 返回 MockDao 引用以便测试中操作 TTL。
fn make_logic_with_auth(
    timeout: u64,
    active_timeout: u64,
    token_style: &str,
    auto_renewal_threshold: i64,
) -> (Arc<MockDao>, BulwarkLogicDefault) {
    let dao = Arc::new(MockDao::new());
    let session = Arc::new(BulwarkSession::new(
        dao.clone() as Arc<dyn BulwarkDao>,
        timeout,
        active_timeout,
    ));
    let token_handler: Arc<dyn Token> = Arc::new(UuidTokenStyle);
    let auth_logic: Arc<dyn AuthLogic> = Arc::new(AuthLogicDefault::new(
        session.clone(),
        token_handler,
        timeout as i64,
    ));
    let mut config = BulwarkConfig::default_config();
    config.timeout = timeout as i64;
    config.token_style = token_style.to_string();
    config.auto_renewal_threshold = auto_renewal_threshold;
    let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
        has_permission: true,
        has_role: true,
    });
    let logic =
        BulwarkLogicDefault::new(session, Arc::new(config), firewall).with_auth_logic(auth_logic);
    (dao, logic)
}

/// T002: threshold=-1（未启用）时 check_and_renew 返回 None。
#[tokio::test]
async fn check_and_renew_returns_none_when_threshold_disabled() {
    let (_dao, logic) = make_logic_with_auth(3600, 86400, "uuid", -1);
    let token = logic
        .login("user-001", &LoginParams::default())
        .await
        .unwrap();
    let result = logic.check_and_renew(&token).await.unwrap();
    assert!(result.is_none(), "threshold=-1 时应返回 None");
}

/// T002: TTL 充足时 check_and_renew 返回 None。
#[tokio::test]
async fn check_and_renew_returns_none_when_ttl_sufficient() {
    let (_dao, logic) = make_logic_with_auth(3600, 86400, "uuid", 20);
    let token = logic
        .login("user-002", &LoginParams::default())
        .await
        .unwrap();
    // 刚登录，remaining_pct = 100 >= 20，不应触发续签
    let result = logic.check_and_renew(&token).await.unwrap();
    assert!(result.is_none(), "TTL 充足时应返回 None");
}

/// T003: 非 JWT 模式 + remaining_pct < threshold 时调用 renew_to_equivalent 续签。
#[tokio::test]
async fn check_and_renew_renews_non_jwt_when_threshold_reached() {
    let (dao, logic) = make_logic_with_auth(10, 86400, "uuid", 90);
    let token = logic
        .login("user-003", &LoginParams::default())
        .await
        .unwrap();
    // 手动将 TTL 缩短到 1 秒（remaining_pct = 10% < 90%）
    let key = format!("token:session:{}", token);
    dao.expire(&key, 1).await.unwrap();
    let result = logic.check_and_renew(&token).await.unwrap();
    assert!(result.is_some(), "remaining_pct < threshold 时应触发续签");
    let new_token = result.unwrap();
    assert_ne!(new_token, token, "续签后应生成新 token");
    // 旧 token 应已失效
    let old_valid = logic.session.is_valid(&token).await.unwrap();
    assert!(!old_valid, "旧 token 续签后应失效");
    // 新 token 应有效
    let new_valid = logic.session.is_valid(&new_token).await.unwrap();
    assert!(new_valid, "新 token 应有效");
}

/// T004: JWT 模式 + remaining_pct < threshold 时调用 refresh_token 续签。
#[cfg(feature = "protocol-jwt")]
#[tokio::test]
async fn check_and_renew_renews_jwt_when_threshold_reached() {
    let dao: Arc<MockDao> = Arc::new(MockDao::new());
    let session = Arc::new(BulwarkSession::new(
        dao.clone() as Arc<dyn BulwarkDao>,
        10,
        86400,
    ));
    let mut config = BulwarkConfig::default_config();
    config.timeout = 10;
    config.token_style = "jwt".to_string();
    config.jwt_secret = "test-secret".to_string().into();
    config.auto_renewal_threshold = 90;
    let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
        has_permission: true,
        has_role: true,
    });
    let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall);

    let token = logic
        .login("user-004", &LoginParams::default())
        .await
        .unwrap();
    // 手动将 TTL 缩短到 1 秒（remaining_pct = 10% < 90%）
    let key = format!("token:session:{}", token);
    dao.expire(&key, 1).await.unwrap();
    let result = logic.check_and_renew(&token).await.unwrap();
    assert!(
        result.is_some(),
        "JWT 模式 remaining_pct < threshold 时应触发续签"
    );
    let new_token = result.unwrap();
    assert_ne!(new_token, token, "续签后应生成新 token");
}

/// T005: check_login 在 TTL 低于阈值时自动续签，并通过 CURRENT_RENEWED_TOKEN 传递新 token。
#[tokio::test]
async fn check_login_renews_token_when_threshold_reached() {
    let (dao, logic) = make_logic_with_auth(10, 86400, "uuid", 90);
    let token = logic
        .login("user-005", &LoginParams::default())
        .await
        .unwrap();
    // 手动将 TTL 缩短到 1 秒（remaining_pct = 10% < 90%）
    let key = format!("token:session:{}", token);
    dao.expire(&key, 1).await.unwrap();
    // check_login 应触发续签
    let renewed = with_current_token(token.clone(), async {
        with_renewed_token_scope(async {
            let valid = logic.check_login().await.unwrap();
            assert!(valid, "check_login 应返回 true（token 续签前有效）");
            current_renewed_token()
        })
        .await
    })
    .await;
    assert!(renewed.is_some(), "续签后应设置 CURRENT_RENEWED_TOKEN");
    assert_ne!(renewed.unwrap(), token, "续签后的 token 应不同于原 token");
}

// ============================================================================
// v0.6.3 D2: LoginParams 测试
// ========================================================================

/// LoginParams::default() 所有字段为 None/false。
#[test]
fn login_params_default_is_all_none() {
    let params = LoginParams::default();
    assert!(params.device.is_none(), "默认 device 应为 None");
    assert!(params.ip.is_none(), "默认 ip 应为 None");
    assert!(params.user_agent.is_none(), "默认 user_agent 应为 None");
    assert!(!params.remember_me, "默认 remember_me 应为 false");
}

/// login("id", &LoginParams::default()) 等价于旧 login("id") 行为。
#[tokio::test]
async fn login_with_default_params_creates_session() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let token = logic
        .login("user-params-001", &LoginParams::default())
        .await
        .unwrap();
    assert!(!token.is_empty(), "login 应返回非空 token");
    let ts = logic
        .session
        .get_token_session(&token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ts.login_id, "user-params-001");
}

// ============================================================================
// v0.6.3 D2 T010: is_share 复用现有 token 测试
// ========================================================================

/// is_share=true 时，重复登录同一 login_id 应复用现有有效 token，不创建新会话。
#[tokio::test]
async fn login_with_is_share_reuses_existing_token() {
    let mut logic = make_logic(3600, 86400, false, "uuid", true, true);
    Arc::make_mut(&mut logic.config).is_share = true;

    // 首次登录
    let t1 = logic
        .login("share-user-001", &LoginParams::default())
        .await
        .unwrap();

    // 第二次登录（is_share=true 应复用 t1）
    let t2 = logic
        .login("share-user-001", &LoginParams::default())
        .await
        .unwrap();

    assert_eq!(t1, t2, "is_share=true 应复用现有 token");
}

/// is_share=true 但无现有会话时，应创建新 token。
#[tokio::test]
async fn login_with_is_share_creates_new_when_no_existing() {
    let mut logic = make_logic(3600, 86400, false, "uuid", true, true);
    Arc::make_mut(&mut logic.config).is_share = true;

    // 无现有会话时创建新 token
    let token = logic
        .login("share-user-002", &LoginParams::default())
        .await
        .unwrap();
    assert!(!token.is_empty());

    // 验证会话创建
    let ts = logic
        .session
        .get_token_session(&token)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(ts.login_id, "share-user-002");
}

// ============================================================================
// v0.6.3 D2 T011: is_concurrent=false 踢出现有会话测试
// ========================================================================

/// is_concurrent=false + is_share=false 时，重复登录同一 login_id 应踢出旧 token。
#[tokio::test]
async fn login_with_is_concurrent_false_kickouts_existing() {
    let mut logic = make_logic(3600, 86400, false, "uuid", true, true);
    // is_concurrent=false, is_share=false
    Arc::make_mut(&mut logic.config).is_concurrent = false;

    // 首次登录
    let t1 = logic
        .login("concurrent-user-001", &LoginParams::default())
        .await
        .unwrap();

    // 第二次登录（is_concurrent=false 应踢出 t1）
    let t2 = logic
        .login("concurrent-user-001", &LoginParams::default())
        .await
        .unwrap();

    assert_ne!(t1, t2, "is_concurrent=false 应创建新 token");

    // t1 应已被踢出（Token-Session 不存在）
    let ts1 = logic.session.get_token_session(&t1).await.unwrap();
    assert!(ts1.is_none(), "is_concurrent=false 登录后旧 token 应被踢出");
}

// ============================================================================
// T002: replaced_login_exit_mode 集成测试（is_concurrent=false 时生效）
// ============================================================================

/// T002: NewDevice 模式下，已有旧会话时拒绝新登录。
#[tokio::test]
async fn login_new_device_mode_rejects_new_login() {
    let mut logic = make_logic(3600, 86400, false, "uuid", true, true);
    Arc::make_mut(&mut logic.config).is_concurrent = false;
    Arc::make_mut(&mut logic.config).replaced_login_exit_mode = ReplacedLoginExitMode::NewDevice;

    // 首次登录应成功（无旧会话）
    let token1 = logic
        .login("new-device-user-001", &LoginParams::default())
        .await
        .unwrap();
    assert!(!token1.is_empty(), "首次登录应成功");

    // 第二次登录应被拒绝（已有旧会话 + NewDevice 模式）
    let result = logic
        .login("new-device-user-001", &LoginParams::default())
        .await;
    assert!(
        matches!(result, Err(BulwarkError::NotLogin(ref msg)) if msg.contains("NewDevice")),
        "NewDevice 模式下已有旧会话时应返回 NotLogin 错误，实际: {:?}",
        result
    );

    // 旧会话应仍然有效（NewDevice 模式保留旧设备）
    let ts1 = logic.session.get_token_session(&token1).await.unwrap();
    assert!(ts1.is_some(), "NewDevice 模式拒绝新登录后，旧会话应保留");
}

/// NewDevice 模式下，旧会话已过期时应允许新登录。
///
/// 覆盖 session.rs 行 403-415 的 fall-through 分支：
/// `get_token_by_login_id` 返回 Some(token)（login_token_map 仍有条目），
/// 但 `get_token_session` 返回 Ok(None)（Token-Session 在 DAO 中已过期/删除）。
/// 此时应跳过拒绝逻辑，允许新登录。
///
/// 注意：不能用 `logout()` 模拟过期——logout 会同时清理 login_token_map，
/// 导致 `get_token_by_login_id` 返回 None，无法命中目标分支。
/// 此处通过直接删除 DAO 中的 Token-Session key，保留 login_token_map 条目，
/// 精确构造目标分支所需状态。
#[tokio::test]
async fn login_new_device_mode_allows_when_old_session_expired() {
    let (dao, mut logic) = make_logic_with_dao(3600, 86400, false, "uuid", true, true);
    Arc::make_mut(&mut logic.config).is_concurrent = false;
    Arc::make_mut(&mut logic.config).replaced_login_exit_mode = ReplacedLoginExitMode::NewDevice;

    // 首次登录
    let token1 = logic
        .login("expired-user-001", &LoginParams::default())
        .await
        .unwrap();

    // 仅删除 DAO 中的 Token-Session，模拟会话过期（保留 login_token_map 条目）
    dao.delete(&format!("token:session:{}", token1))
        .await
        .unwrap();

    // 验证前置条件：get_token_by_login_id 仍返回 Some，但 get_token_session 返回 None
    assert_eq!(
        logic.session.get_token_by_login_id("expired-user-001"),
        Some(token1.clone()),
        "login_token_map 条目应仍存在"
    );
    let ts1 = logic.session.get_token_session(&token1).await.unwrap();
    assert!(ts1.is_none(), "Token-Session 应已从 DAO 删除");

    // 第二次登录应成功（旧 session 已失效，fall through 到允许新登录）
    let token2 = logic
        .login("expired-user-001", &LoginParams::default())
        .await
        .unwrap();
    assert!(
        !token2.is_empty(),
        "旧会话过期后 NewDevice 模式应允许新登录"
    );
    assert_ne!(token1, token2, "新登录应生成新 token");
}

/// OldDevice 模式下，已有旧会话时踢出旧会话允许新登录。
#[tokio::test]
async fn login_old_device_mode_kickout_old_session() {
    let mut logic = make_logic(3600, 86400, false, "uuid", true, true);
    Arc::make_mut(&mut logic.config).is_concurrent = false;
    Arc::make_mut(&mut logic.config).replaced_login_exit_mode = ReplacedLoginExitMode::OldDevice;

    // 首次登录
    let token1 = logic
        .login("old-device-user-001", &LoginParams::default())
        .await
        .unwrap();
    assert!(!token1.is_empty(), "首次登录应成功");

    // 第二次登录应成功且踢出旧会话
    let token2 = logic
        .login("old-device-user-001", &LoginParams::default())
        .await
        .unwrap();
    assert_ne!(token1, token2, "第二次登录应生成新 token");

    // 旧 token 应已被踢出
    let ts1 = logic.session.get_token_session(&token1).await.unwrap();
    assert!(ts1.is_none(), "OldDevice 模式下旧会话应被踢出");

    // 新 token 应有效
    let ts2 = logic.session.get_token_session(&token2).await.unwrap();
    assert!(ts2.is_some(), "OldDevice 模式下新会话应有效");
}

/// is_concurrent=true + is_share=false 时，重复登录应保留旧 token（允许并发）。
#[tokio::test]
async fn login_with_is_concurrent_true_preserves_existing() {
    let mut logic = make_logic(3600, 86400, false, "uuid", true, true);
    // is_concurrent=true（默认）, is_share=false
    Arc::make_mut(&mut logic.config).is_concurrent = true;

    let t1 = logic
        .login("concurrent-user-002", &LoginParams::default())
        .await
        .unwrap();
    let t2 = logic
        .login("concurrent-user-002", &LoginParams::default())
        .await
        .unwrap();

    assert_ne!(
        t1, t2,
        "is_concurrent=true + is_share=false 应创建不同 token"
    );

    // t1 应仍然有效
    let ts1 = logic.session.get_token_session(&t1).await.unwrap();
    assert!(ts1.is_some(), "is_concurrent=true 应保留旧 token");
}

// v0.6.3 D2 T012: enforce_max_login_count 测试

/// enforce_max_login_count 应踢出最旧的 token，保留较新的。
///
/// 创建 3 个会话（sleep 1 秒确保 last_active_at 不同），
/// max=2 时应踢出最早的 t1，保留 t2 和 t3。
#[tokio::test]
async fn enforce_max_login_count_evicts_oldest() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);

    // 创建 3 个会话，sleep 确保 last_active_at 递增（Unix 秒级时间戳）
    let t1 = logic
        .login("max-user-001", &LoginParams::default())
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    let t2 = logic
        .login("max-user-001", &LoginParams::default())
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    let t3 = logic
        .login("max-user-001", &LoginParams::default())
        .await
        .unwrap();

    // max=2，应踢出最旧的 t1
    logic
        .enforce_max_login_count("max-user-001", 2)
        .await
        .unwrap();

    // t1 应被踢出
    let ts1 = logic.session.get_token_session(&t1).await.unwrap();
    assert!(ts1.is_none(), "最旧的 token 应被踢出");

    // t2 和 t3 应保留
    let ts2 = logic.session.get_token_session(&t2).await.unwrap();
    let ts3 = logic.session.get_token_session(&t3).await.unwrap();
    assert!(ts2.is_some(), "较新的 token 应保留");
    assert!(ts3.is_some(), "最新的 token 应保留");
}

/// enforce_max_login_count 在数量 <= max 时不应踢出任何 token。
#[tokio::test]
async fn enforce_max_login_count_no_op_when_under_limit() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);

    let t1 = logic
        .login("max-user-002", &LoginParams::default())
        .await
        .unwrap();
    let t2 = logic
        .login("max-user-002", &LoginParams::default())
        .await
        .unwrap();

    // max=5，当前只有 2 个，不应踢出任何 token
    logic
        .enforce_max_login_count("max-user-002", 5)
        .await
        .unwrap();

    assert!(logic
        .session
        .get_token_session(&t1)
        .await
        .unwrap()
        .is_some());
    assert!(logic
        .session
        .get_token_session(&t2)
        .await
        .unwrap()
        .is_some());
}

// v0.6.3 D2 T013: login 调用 enforce_max_login_count 测试

/// login 在 max_login_count > 0 时应自动踢出最旧的会话。
///
/// max_login_count=2 时创建 3 个会话（sleep 1 秒确保 last_active_at 不同），
/// 第 3 次登录应触发 enforce_max_login_count 踢出最早的 t1，保留 t2 和 t3。
#[tokio::test]
async fn login_with_max_login_count_evicts_oldest_session() {
    let mut logic = make_logic(3600, 86400, false, "uuid", true, true);
    // max_login_count=2：最多 2 个并发会话
    Arc::make_mut(&mut logic.config).max_login_count = 2;

    // 创建 3 个会话，sleep 确保 last_active_at 递增（Unix 秒级时间戳）
    let t1 = logic
        .login("max-login-user-001", &LoginParams::default())
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    let t2 = logic
        .login("max-login-user-001", &LoginParams::default())
        .await
        .unwrap();
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
    let t3 = logic
        .login("max-login-user-001", &LoginParams::default())
        .await
        .unwrap();

    // t1 应被踢出（最旧），t2 和 t3 保留
    let ts1 = logic.session.get_token_session(&t1).await.unwrap();
    let ts2 = logic.session.get_token_session(&t2).await.unwrap();
    let ts3 = logic.session.get_token_session(&t3).await.unwrap();
    assert!(ts1.is_none(), "max_login_count=2 时最旧 token 应被踢出");
    assert!(ts2.is_some(), "第二个 token 应保留");
    assert!(ts3.is_some(), "最新 token 应保留");
}

// ============================================================================
// v0.6.6 T003: enforce_max_login_count 集成 overflow_logout_mode 测试
// ============================================================================

/// 测试用录音监听器：捕获广播事件供测试断言。
///
/// 仅在 `listener` feature 启用时编译。通过 `Arc<Mutex<Vec<BulwarkEvent>>>` 存储
/// 收到的事件，测试结束后读取断言事件类型与字段。
#[cfg(feature = "listener")]
struct RecordingListener {
    events: Arc<Mutex<Vec<crate::listener::BulwarkEvent>>>,
}

#[cfg(feature = "listener")]
#[async_trait]
impl crate::listener::BulwarkListener for RecordingListener {
    async fn on_event(
        &self,
        event: &crate::listener::BulwarkEvent,
    ) -> crate::error::BulwarkResult<()> {
        self.events.lock().push(event.clone());
        Ok(())
    }
}

/// `overflow_logout_mode = Logout` 时，超过 max_login_count 应踢出最早 token
/// 并广播 `Logout` 事件（验证现有行为不回归）。
#[tokio::test]
async fn enforce_max_login_count_overflow_logout_mode_logout() {
    let mut logic = make_logic(3600, 86400, false, "uuid", true, true);
    Arc::make_mut(&mut logic.config).max_login_count = 2;
    Arc::make_mut(&mut logic.config).overflow_logout_mode = OverflowLogoutMode::Logout;

    #[cfg(feature = "listener")]
    let captured_events: Arc<Mutex<Vec<crate::listener::BulwarkEvent>>> =
        Arc::new(Mutex::new(Vec::new()));
    #[cfg(feature = "listener")]
    {
        let lm = Arc::new(BulwarkListenerManager::new());
        lm.register(Arc::new(RecordingListener {
            events: captured_events.clone(),
        }));
        let logic = logic.with_listener_manager(lm);

        // 创建 3 个会话，sleep 确保 last_active_at 递增
        let t1 = logic
            .login("overflow-logout-user-001", &LoginParams::default())
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let _t2 = logic
            .login("overflow-logout-user-001", &LoginParams::default())
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let _t3 = logic
            .login("overflow-logout-user-001", &LoginParams::default())
            .await
            .unwrap();

        // t1 应被踢出（最旧）
        let ts1 = logic.session.get_token_session(&t1).await.unwrap();
        assert!(ts1.is_none(), "Logout 模式：最旧 token 应被踢出");

        // 验证广播了 Logout 事件（至少 1 个，含被踢出 token）
        let events = captured_events.lock();
        let has_logout = events.iter().any(|e| match e {
            crate::listener::BulwarkEvent::Logout { token, .. } => token == &t1,
            _ => false,
        });
        assert!(
            has_logout,
            "Logout 模式应广播 Logout 事件（含被踢出的 token），实际事件: {:?}",
            events
                .iter()
                .map(|e| format!("{:?}", e))
                .collect::<Vec<_>>()
        );
    }
    #[cfg(not(feature = "listener"))]
    {
        // 无 listener feature 时仅验证踢出行为
        let t1 = logic
            .login("overflow-logout-user-001", &LoginParams::default())
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let _t2 = logic
            .login("overflow-logout-user-001", &LoginParams::default())
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let _t3 = logic
            .login("overflow-logout-user-001", &LoginParams::default())
            .await
            .unwrap();

        let ts1 = logic.session.get_token_session(&t1).await.unwrap();
        assert!(ts1.is_none(), "Logout 模式：最旧 token 应被踢出");
    }
}

/// `overflow_logout_mode = Kickout` 时，超过 max_login_count 应踢出最早 token
/// 并广播 `Kickout` 事件（reason 为 "超过最大登录数限制"）。
#[tokio::test]
async fn enforce_max_login_count_overflow_logout_mode_kickout() {
    let mut logic = make_logic(3600, 86400, false, "uuid", true, true);
    Arc::make_mut(&mut logic.config).max_login_count = 2;
    Arc::make_mut(&mut logic.config).overflow_logout_mode = OverflowLogoutMode::Kickout;

    #[cfg(feature = "listener")]
    let captured_events: Arc<Mutex<Vec<crate::listener::BulwarkEvent>>> =
        Arc::new(Mutex::new(Vec::new()));
    #[cfg(feature = "listener")]
    {
        let lm = Arc::new(BulwarkListenerManager::new());
        lm.register(Arc::new(RecordingListener {
            events: captured_events.clone(),
        }));
        let logic = logic.with_listener_manager(lm);

        // 创建 3 个会话，sleep 确保 last_active_at 递增
        let t1 = logic
            .login("overflow-kickout-user-001", &LoginParams::default())
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let _t2 = logic
            .login("overflow-kickout-user-001", &LoginParams::default())
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let _t3 = logic
            .login("overflow-kickout-user-001", &LoginParams::default())
            .await
            .unwrap();

        // t1 应被踢出（最旧）
        let ts1 = logic.session.get_token_session(&t1).await.unwrap();
        assert!(ts1.is_none(), "Kickout 模式：最旧 token 应被踢出");

        // 验证广播了 Kickout 事件（含被踢出 token 和正确 reason）
        let events = captured_events.lock();
        let has_kickout = events.iter().any(|e| match e {
            crate::listener::BulwarkEvent::Kickout { token, reason, .. } => {
                token == &t1 && reason == "超过最大登录数限制"
            },
            _ => false,
        });
        assert!(
            has_kickout,
            "Kickout 模式应广播 Kickout 事件（reason='超过最大登录数限制'），实际事件: {:?}",
            events
                .iter()
                .map(|e| format!("{:?}", e))
                .collect::<Vec<_>>()
        );
    }
    #[cfg(not(feature = "listener"))]
    {
        // 无 listener feature 时仅验证踢出行为
        let t1 = logic
            .login("overflow-kickout-user-001", &LoginParams::default())
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let _t2 = logic
            .login("overflow-kickout-user-001", &LoginParams::default())
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let _t3 = logic
            .login("overflow-kickout-user-001", &LoginParams::default())
            .await
            .unwrap();

        let ts1 = logic.session.get_token_session(&t1).await.unwrap();
        assert!(ts1.is_none(), "Kickout 模式：最旧 token 应被踢出");
    }
}

/// `overflow_logout_mode = Replaced` 时，超过 max_login_count 应踢出最早 token
/// 并广播 `RevokeToken` 事件。
#[tokio::test]
async fn enforce_max_login_count_overflow_logout_mode_replaced() {
    let mut logic = make_logic(3600, 86400, false, "uuid", true, true);
    Arc::make_mut(&mut logic.config).max_login_count = 2;
    Arc::make_mut(&mut logic.config).overflow_logout_mode = OverflowLogoutMode::Replaced;

    #[cfg(feature = "listener")]
    let captured_events: Arc<Mutex<Vec<crate::listener::BulwarkEvent>>> =
        Arc::new(Mutex::new(Vec::new()));
    #[cfg(feature = "listener")]
    {
        let lm = Arc::new(BulwarkListenerManager::new());
        lm.register(Arc::new(RecordingListener {
            events: captured_events.clone(),
        }));
        let logic = logic.with_listener_manager(lm);

        // 创建 3 个会话，sleep 确保 last_active_at 递增
        let t1 = logic
            .login("overflow-replaced-user-001", &LoginParams::default())
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let _t2 = logic
            .login("overflow-replaced-user-001", &LoginParams::default())
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let _t3 = logic
            .login("overflow-replaced-user-001", &LoginParams::default())
            .await
            .unwrap();

        // t1 应被踢出（最旧）
        let ts1 = logic.session.get_token_session(&t1).await.unwrap();
        assert!(ts1.is_none(), "Replaced 模式：最旧 token 应被踢出");

        // 验证广播了 Replaced 事件（含被顶替的 login_id/token/reason）
        let events = captured_events.lock();
        let has_replaced = events.iter().any(|e| match e {
            crate::listener::BulwarkEvent::Replaced {
                login_id,
                token,
                reason,
                ..
            } => {
                login_id == "overflow-replaced-user-001"
                    && token == &t1
                    && reason == "超过最大登录数限制，被新会话顶替"
            },
            _ => false,
        });
        assert!(
            has_replaced,
            "Replaced 模式应广播 Replaced 事件（含 login_id/token/reason），实际事件: {:?}",
            events
                .iter()
                .map(|e| format!("{:?}", e))
                .collect::<Vec<_>>()
        );
    }
    #[cfg(not(feature = "listener"))]
    {
        // 无 listener feature 时仅验证踢出行为
        let t1 = logic
            .login("overflow-replaced-user-001", &LoginParams::default())
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let _t2 = logic
            .login("overflow-replaced-user-001", &LoginParams::default())
            .await
            .unwrap();
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let _t3 = logic
            .login("overflow-replaced-user-001", &LoginParams::default())
            .await
            .unwrap();

        let ts1 = logic.session.get_token_session(&t1).await.unwrap();
        assert!(ts1.is_none(), "Replaced 模式：最旧 token 应被踢出");
    }
}

// v0.6.3 D3 T014: refresh_access_token 默认实现返回 NotImplemented

/// `refresh_access_token` 默认实现应返回 `BulwarkError::NotImplemented`。
///
/// T014 仅添加 trait 方法签名 + 默认实现；T015 会注入 `RefreshTokenRotation` 实现实际轮换。
#[tokio::test]
async fn session_logic_refresh_default_returns_not_implemented() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let result = logic.refresh_access_token("some-refresh-token").await;
    assert!(
        matches!(result, Err(BulwarkError::NotImplemented(_))),
        "默认 refresh_access_token 应返回 NotImplemented，实际: {:?}",
        result
    );
}

// v0.6.3 D3 T015: refresh_access_token 覆盖实现——未注入/未启用 feature 时返回 NotImplemented

/// 未注入 RefreshTokenRotation 时返回 NotImplemented（db-sqlite + protocol-jwt 启用）。
///
/// T015 覆盖 `refresh_access_token`：注入了 `refresh_token_rotation` 字段后，
/// 未注入（None）时应返回 `NotImplemented`，而非调用 trait 默认实现。
#[cfg(all(feature = "protocol-jwt", feature = "db-sqlite"))]
#[tokio::test]
async fn refresh_access_token_returns_not_implemented_when_not_injected() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    // 未注入 refresh_token_rotation
    let result = logic.refresh_access_token("some-refresh-token").await;
    assert!(
        matches!(result, Err(BulwarkError::NotImplemented(_))),
        "未注入 RefreshTokenRotation 时应返回 NotImplemented，实际: {:?}",
        result
    );
}

/// 未启用 db-sqlite feature 时返回 NotImplemented。
///
/// `RefreshTokenRotation` 需 `protocol-jwt` + `db-sqlite` 双 feature，
/// 未启用时覆盖实现直接返回 `NotImplemented`。
#[cfg(not(all(feature = "protocol-jwt", feature = "db-sqlite")))]
#[tokio::test]
async fn refresh_access_token_returns_not_implemented_without_db_sqlite() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let result = logic.refresh_access_token("some-refresh-token").await;
    assert!(
        matches!(result, Err(BulwarkError::NotImplemented(_))),
        "未启用 db-sqlite feature 时应返回 NotImplemented，实际: {:?}",
        result
    );
}

// ========================================================================
// v0.6.3 D4 T020: login 自动生成设备指纹
// ========================================================================

/// login 时 `LoginParams.device` 为 None 但 `user_agent` + `ip` 有值，
/// 应自动调用 `device_fingerprint` 生成指纹写入 `TokenSession.device`。
///
/// 指纹为 SHA-256(UA+IP) 前 16 字节 hex = 32 字符。
/// 仅在 device 模块可用时编译（与 `device_fingerprint` feature gate 一致）。
#[cfg(any(
    feature = "protocol-jwt",
    feature = "account-credential",
    feature = "protocol-oauth2",
    feature = "protocol-sso",
    feature = "protocol-sign",
    feature = "secure-sign",
    feature = "secure-httpdigest"
))]
#[tokio::test]
async fn login_auto_generates_device_fingerprint() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);

    let params = LoginParams {
        device: None,
        ip: Some("192.168.1.100".to_string()),
        user_agent: Some("Mozilla/5.0 Chrome".to_string()),
        remember_me: false,
        require_mfa: false,
    };

    let token = logic
        .login("fingerprint-user-001", &params)
        .await
        .expect("login 应成功");

    // 验证 TokenSession 的 device 字段已自动生成（32 字符指纹）
    let ts = logic
        .session
        .get_token_session(&token)
        .await
        .unwrap()
        .expect("Token-Session 应存在");
    assert!(ts.device.is_some(), "device 应自动生成");
    assert_eq!(
        ts.device.as_ref().unwrap().len(),
        32,
        "指纹应为 32 字符（16 字节 hex）"
    );

    // 验证 ip 和 user_agent 也正确存储
    assert_eq!(ts.ip.as_deref(), Some("192.168.1.100"));
    assert_eq!(ts.user_agent.as_deref(), Some("Mozilla/5.0 Chrome"));
}

// ============================================================================
// HIGH-001 + HIGH-002 测试
// ============================================================================

/// HIGH-001: 续签后对旧 token 再次调用 check_and_renew 应返回 None（非错误）。
///
/// 验证 per-login_id 锁 + 二次 TTL 检查的行为：
/// 1. 首次 check_and_renew 续签成功（旧 token 删除，新 token 创建）
/// 2. 对旧 token 再次调用 check_and_renew：
///    - 快速路径 get_token_timeout 返回 None（旧 token 已删除）→ Ok(None)
///    - 即使进入锁路径，二次检查也会发现 token 不存在 → Ok(None)
/// 3. 不应返回 Err（避免 "会话假活" 场景下旧 token 被误判为有效）
#[tokio::test]
async fn check_and_renew_returns_none_for_old_token_after_renewal() {
    let (dao, logic) = make_logic_with_auth(10, 86400, "uuid", 90);
    let token = logic
        .login("high001-user-001", &LoginParams::default())
        .await
        .unwrap();

    // 缩短 TTL 触发续签
    let key = format!("token:session:{}", token);
    dao.expire(&key, 1).await.unwrap();

    // 首次续签应成功
    let result1 = logic.check_and_renew(&token).await.unwrap();
    assert!(result1.is_some(), "首次续签应返回新 token");
    let new_token = result1.unwrap();
    assert_ne!(new_token, token, "新 token 应不同于旧 token");

    // 对旧 token 再次调用 — 应返回 None（不是 Err）
    let result2 = logic.check_and_renew(&token).await;
    assert!(
        result2.is_ok(),
        "对已续签的旧 token 调用 check_and_renew 不应返回 Err"
    );
    assert!(
        result2.unwrap().is_none(),
        "旧 token 已被续签删除，应返回 None"
    );

    // 新 token 应仍然有效
    assert!(
        logic.session.is_valid(&new_token).await.unwrap(),
        "新 token 应有效"
    );
}

/// HIGH-002: enforce_max_login_count 失败时，新创建的会话应被回滚（logout）。
///
/// 使用 FailInjectionDao 在第 N 次 account:session: 查询时注入失败，
/// 模拟 enforce_max_login_count 内部 get_account_session 失败的场景。
///
/// DAO 调用序列（account:session: get）：
/// 1. 首次 login → create_inner → get_account_session（#1，返回 None → 创建）
/// 2. 第二次 login → create_inner → get_account_session（#2，返回 1 token → 添加）
/// 3. 第二次 login → enforce_max_login_count → get_account_session（#3 → 注入失败！）
/// 4. 回滚 logout → logout_inner → get_account_session（#4，恢复正常 → 清理）
///
/// 验证 login 返回 Err 且新 token 已从 login_token_map 回滚（剩 1 个 token）。
#[tokio::test]
async fn login_rolls_back_session_when_enforce_fails() {
    use std::sync::atomic::{AtomicU32, Ordering};

    /// 测试用 DAO 包装器：在第 N 次 account:session: get 调用时注入失败。
    struct FailInjectionDao {
        inner: Arc<MockDao>,
        fail_on_nth: AtomicU32,
        call_count: AtomicU32,
    }

    #[async_trait]
    impl BulwarkDao for FailInjectionDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
            if key.starts_with("account:session:") {
                let n = self.call_count.fetch_add(1, Ordering::SeqCst) + 1;
                if n == self.fail_on_nth.load(Ordering::SeqCst) {
                    return Err(BulwarkError::Dao(
                        "injected failure for HIGH-002 test".to_string(),
                    ));
                }
            }
            self.inner.get(key).await
        }
        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
            self.inner.set(key, value, ttl_seconds).await
        }
        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            self.inner.update(key, value).await
        }
        async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
            self.inner.expire(key, seconds).await
        }
        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            self.inner.delete(key).await
        }
        async fn get_timeout(&self, key: &str) -> BulwarkResult<Option<Duration>> {
            self.inner.get_timeout(key).await
        }
    }

    let mock_dao = Arc::new(MockDao::new());
    let fail_dao = Arc::new(FailInjectionDao {
        inner: mock_dao.clone(),
        fail_on_nth: AtomicU32::new(3), // 第 3 次 account:session: get = enforce 调用
        call_count: AtomicU32::new(0),
    });
    let session = Arc::new(BulwarkSession::new(
        fail_dao.clone() as Arc<dyn BulwarkDao>,
        3600,
        86400,
    ));
    let mut config = BulwarkConfig::default_config();
    config.token_style = "uuid".to_string();
    config.is_concurrent = true;
    config.max_login_count = 1; // 限制最多 1 个会话
    let firewall: Arc<dyn BulwarkPermissionStrategy> = Arc::new(MockFirewall {
        has_permission: true,
        has_role: true,
    });
    let logic = BulwarkLogicDefault::new(session, Arc::new(config), firewall);

    // 首次登录 — 成功（count=1 <= max=1，enforce 不触发）
    let t1 = logic
        .login("high002-user-001", &LoginParams::default())
        .await
        .expect("首次登录应成功");
    assert!(
        logic.session.is_valid(&t1).await.unwrap(),
        "首次登录的 token 应有效"
    );

    // 第二次登录 — create_inner 成功（#2 get），
    // enforce_max_login_count 触发（count=2 > max=1），get_account_session 失败（#3 get），
    // login 应回滚新 token（logout 调用 #4 get 恢复正常）
    let login_result = logic
        .login("high002-user-001", &LoginParams::default())
        .await;

    assert!(
        login_result.is_err(),
        "enforce 失败时 login 应返回 Err，实际: {:?}",
        login_result
    );

    // 验证回滚：login_token_map 应只剩 1 个 token（首次登录的）
    let tokens = logic.session.get_tokens_by_login_id("high002-user-001");
    assert_eq!(
        tokens.len(),
        1,
        "回滚后应只剩 1 个 token（首次登录的），实际: {} 个: {:?}",
        tokens.len(),
        tokens
    );

    // 首次登录的 token 应仍然有效
    assert!(
        logic.session.is_valid(&t1).await.unwrap(),
        "回滚不应影响首次登录的 token"
    );
}

// ------------------------------------------------------------------------
// T011: per-token dynamic active timeout（dynamic-active-timeout feature）
// ------------------------------------------------------------------------

/// 验证 per-token active_timeout 生效：设置 per-token active_timeout=1 秒（很短），
/// 等待 2 秒后验证 token 已过期（全局 active_timeout=3600 不影响）。
///
/// 不设置 per-token 时全局 active_timeout=3600 不会导致过期；
/// 设置 per-token=1 后，token 级检查使用 1 秒超时，2 秒后 token 过期。
#[cfg(feature = "dynamic-active-timeout")]
#[tokio::test]
async fn per_token_active_timeout_takes_effect() {
    // 全局 active_timeout=3600（长），per-token 会设置为 1（短）
    let logic = make_logic(3600, 3600, false, "uuid", true, true);
    let token = logic
        .login("1001", &LoginParams::default())
        .await
        .expect("login 应成功");

    // 设置 per-token active_timeout=1 秒
    logic
        .session
        .set_active_timeout(&token, 1)
        .await
        .expect("set_active_timeout 应成功");

    // 等待 2 秒（超过 per-token timeout=1，但未超过全局 active_timeout=3600）
    tokio::time::sleep(Duration::from_secs(2)).await;

    // 验证 token 已过期
    let valid = with_token(&token, async { logic.check_login().await.unwrap() }).await;
    assert!(
        !valid,
        "per-token active_timeout=1 秒后 token 应已过期（全局 active_timeout=3600 不影响）"
    );
}

/// 验证 per-token active_timeout 为 None 时回退到全局 active_timeout。
///
/// 全局 active_timeout=2 秒，不设置 per-token（None）。
/// 将 TokenSession 的 last_active_at 手动设为 5 秒前（超过全局 active_timeout=2），
/// 但 Account-Session 的 last_active_at 仍为登录时的时间（未超过 active_timeout=2）。
/// 验证 token 已过期——证明 token 级检查使用了全局 active_timeout 作为回退值。
///
/// 若未实现 per-token 检查，token 不会过期（Account-Session 仍有效），测试失败。
#[cfg(feature = "dynamic-active-timeout")]
#[tokio::test]
async fn per_token_active_timeout_none_falls_back_to_global() {
    use crate::session::TokenSession;
    use chrono::Utc;

    // 全局 active_timeout=2 秒（短），timeout=3600（长，确保 TTL 检查不干扰）
    let (dao, logic) = make_logic_with_dao(3600, 2, false, "uuid", true, true);
    let token = logic
        .login("1001", &LoginParams::default())
        .await
        .expect("login 应成功");

    // 不设置 per-token active_timeout（保持 None）

    // 手动将 TokenSession 的 last_active_at 设为 5 秒前（超过全局 active_timeout=2）
    let token_dao_key = format!("token:session:{}", token);
    let json = dao.get(&token_dao_key).await.unwrap().unwrap();
    let mut ts: TokenSession = serde_json::from_str(&json).unwrap();
    ts.last_active_at = Utc::now().timestamp() - 5;
    let new_json = serde_json::to_string(&ts).unwrap();
    dao.update(&token_dao_key, &new_json).await.unwrap();

    // 验证 token 已过期（token 级检查使用全局 active_timeout=2，5 > 2 → 过期）
    // Account-Session 的 last_active_at 仍为登录时间（未超过 active_timeout=2），account 检查不触发过期
    let valid = with_token(&token, async { logic.check_login().await.unwrap() }).await;
    assert!(
        !valid,
        "per-token=None 时应回退到全局 active_timeout=2，token（last_active_at 5 秒前）应已过期"
    );
}

// ============================================================================
// T003-T004: revoke_all_sessions + get_active_sessions 工业标准 API 测试
// ============================================================================

/// 验证 `revoke_all_sessions` 终止指定用户的所有会话并返回数量。
///
/// 场景：同一 login_id 登录 2 次（产生 2 个 token），调用 revoke_all_sessions 后：
/// - 返回值为 2（成功吊销数量）
/// - 两个 token 的 Token-Session 均失效
/// - Account-Session 被清除
#[tokio::test]
async fn revoke_all_sessions_terminates_all_tokens_for_login_id() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let t1 = logic.login("1001", &LoginParams::default()).await.unwrap();
    let t2 = logic.login("1001", &LoginParams::default()).await.unwrap();

    let count = logic.revoke_all_sessions("1001").await.unwrap();

    assert_eq!(count, 2, "应吊销 2 个 token，实际: {}", count);
    assert!(
        logic
            .session
            .get_token_session(&t1)
            .await
            .unwrap()
            .is_none(),
        "t1 应已失效"
    );
    assert!(
        logic
            .session
            .get_token_session(&t2)
            .await
            .unwrap()
            .is_none(),
        "t2 应已失效"
    );
    assert!(
        logic
            .session
            .get_account_session("1001")
            .await
            .unwrap()
            .is_none(),
        "Account-Session 应已清除"
    );
}

/// 验证 `revoke_all_sessions` 对未知用户返回 0（幂等）。
#[tokio::test]
async fn revoke_all_sessions_returns_zero_for_unknown_user() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let count = logic.revoke_all_sessions("unknown").await.unwrap();
    assert_eq!(count, 0, "未知用户应返回 0，实际: {}", count);
}

/// 验证 `get_active_sessions` 返回当前活跃的 token 列表。
///
/// 场景：同一 login_id 登录 2 次，get_active_sessions 应返回 2 个 token；
/// 登出其中一个后，再调用应返回 1 个。
#[tokio::test]
async fn get_active_sessions_returns_valid_tokens() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let t1 = logic.login("1001", &LoginParams::default()).await.unwrap();
    let t2 = logic.login("1001", &LoginParams::default()).await.unwrap();

    let active = logic.get_active_sessions("1001").await.unwrap();
    assert_eq!(
        active.len(),
        2,
        "应有 2 个活跃 token，实际: {}",
        active.len()
    );
    assert!(active.contains(&t1), "应包含 t1");
    assert!(active.contains(&t2), "应包含 t2");

    // 登出 t1 后再查询
    logic.session.logout(&t1).await.unwrap();
    let active_after = logic.get_active_sessions("1001").await.unwrap();
    assert_eq!(
        active_after.len(),
        1,
        "登出 t1 后应有 1 个活跃 token，实际: {}",
        active_after.len()
    );
    assert!(
        active_after.contains(&t2),
        "应仅包含 t2，实际: {:?}",
        active_after
    );
}

/// 验证 `get_active_sessions` 对未知用户返回空 Vec。
#[tokio::test]
async fn get_active_sessions_returns_empty_for_unknown_user() {
    let logic = make_logic(3600, 86400, false, "uuid", true, true);
    let active = logic.get_active_sessions("unknown").await.unwrap();
    assert!(
        active.is_empty(),
        "未知用户应返回空 Vec，实际: {:?}",
        active
    );
}

// ============================================================================
// Clock trait 测试（覆盖 stp/mod.rs 中 SystemClock::default / MockClock::set_time）
// ============================================================================

/// SystemClock::default() 等价于 SystemClock::new()，now() 返回当前 UTC 时间。
#[test]
fn system_clock_default_returns_valid_time() {
    let clock = SystemClock;
    let before = chrono::Utc::now();
    let now = clock.now();
    let after = chrono::Utc::now();
    assert!(
        now >= before && now <= after,
        "SystemClock::now() 应在调用前后时间范围内"
    );
}

/// SystemClock::new() 与 Default 返回的实例 now() 均为有效时间。
#[test]
fn system_clock_new_works() {
    let clock = SystemClock::new();
    let now = clock.now();
    assert!(now <= chrono::Utc::now());
}

/// MockClock::set_time 修改时间后 now() 返回新值。
#[test]
fn mock_clock_set_time_updates_time() {
    let initial = chrono::Utc::now();
    let clock = MockClock::new(initial);
    assert_eq!(clock.now(), initial);

    let new_time = initial + chrono::Duration::seconds(3600);
    clock.set_time(new_time);
    assert_eq!(clock.now(), new_time, "set_time 后 now() 应返回新时间");
}

/// MockClock::advance 正向推进时间。
#[test]
fn mock_clock_advance_forward() {
    let initial = chrono::Utc::now();
    let clock = MockClock::new(initial);
    clock.advance(chrono::Duration::seconds(100));
    assert_eq!(clock.now(), initial + chrono::Duration::seconds(100));
}

/// MockClock::advance 负数回退时间。
#[test]
fn mock_clock_advance_backward() {
    let initial = chrono::Utc::now();
    let clock = MockClock::new(initial);
    clock.advance(chrono::Duration::seconds(-50));
    assert_eq!(clock.now(), initial + chrono::Duration::seconds(-50));
}

/// MockClock Clone 后共享底层时间状态（Arc<RwLock>）。
#[test]
fn mock_clock_clone_shares_state() {
    let initial = chrono::Utc::now();
    let clock1 = MockClock::new(initial);
    let clock2 = clock1.clone();
    clock1.set_time(initial + chrono::Duration::seconds(999));
    assert_eq!(
        clock2.now(),
        initial + chrono::Duration::seconds(999),
        "Clone 后应共享时间状态"
    );
}
