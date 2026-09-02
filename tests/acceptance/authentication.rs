//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! authentication 域验收（spec `acceptance-matrix` R-acceptance-matrix-001，
//! 任务 T020）。登录 / 登出 / 切换 / 续期 / 顶替 / 踢出 / 过期 / 封禁 / 锁定，
//! 「正常 + 异常」成对覆盖，场景编号 `ACC-AUTH-NNN`。
//!
//! 会话级场景（001-009）经 `GarrisonTestHarness`（全局单例）+ `#[serial]`；
//! 密码场景（010）使用独立 `GarrisonLogicDefault` 实例 + 真实 SQLite 迁移
//! （镜像 integration/login_password.rs 的已知良好装配）；封禁（011）经
//! `DefaultDisableRepository`；锁定（012）经 `UserLockoutStrategy`。
//!
//! Phase 4 测试迁移（T040/T043）：
//! - ACC-AUTH-016/017/018 自 tests/e2e（safe+disable 默认值 / switch-to / refresh 链）移植；
//! - ACC-AUTH-019 自 tests/acceptance_criteria.rs **BW-AC-010** 移植（编号注释保留）；
//! - 去重注释：BW-AC-004 → ACC-RBAC-004（+ACC-RBAC-007 web 403 编码）、
//!   BW-AC-005 → ACC-RBAC-003（+ACC-RBAC-007）、BW-AC-006 →
//!   ACC-AUTH-001/002 + ACC-RBAC-001/002（组合覆盖）、BW-AC-009 →
//!   ACC-AUTH-002 + ACC-SESS-001（logout 失效 + Token-Session 删除）。

use crate::common::harness::GarrisonTestHarness;
use garrison::stp::context::{get_renewed_token, with_renewed_token_scope};
use garrison::stp::{with_current_token, GarrisonUtil};
use serial_test::serial;
use std::sync::Arc;

/// 统一的「token 已失效」断言：`check_login` 返回 `Ok(false)` 或显性错误
/// 均视为未登录（Ok(true) 才算有效）。
macro_rules! assert_token_invalid {
    ($check:expr, $msg:expr) => {
        assert!(
            !matches!($check, Ok(true)),
            "{}（实际: {:?}）",
            $msg,
            $check
        );
    };
}

/// 测试统一配置：`throw_on_not_login = false`（失效 token 断言走 `Ok(false)`
/// 路径，而非异常中断——与仓库集成测试 `make_config()` 惯例一致）。
fn test_config() -> Arc<garrison::config::GarrisonConfig> {
    let mut c = garrison::config::GarrisonConfig::default_config();
    c.throw_on_not_login = false;
    Arc::new(c)
}

// ------------------------------------------------------------------------
// ACC-AUTH-001..003：登录 / 登出 / 账号切换（正常）
// ------------------------------------------------------------------------

/// ACC-AUTH-001（正常）：登录成功签发非空 token，按 token 反查 login_id，
/// 且当前作用域内 check_login = true。
#[tokio::test]
#[serial]
async fn acc_auth_001_login_success_issued_token() {
    let _h = GarrisonTestHarness::builder().init().await.unwrap();

    let token = GarrisonUtil::login_simple("1001").await.unwrap();
    assert!(!token.is_empty(), "签发 token 不应为空");

    assert_eq!(
        GarrisonUtil::get_login_id_by_token(&token).await.unwrap(),
        Some("1001".to_string()),
        "按 token 应反查到登录主体 1001"
    );

    with_current_token(token.clone(), async {
        assert!(
            GarrisonUtil::check_login().await.unwrap(),
            "有效 token 作用域内 check_login 应为 true"
        );
        assert_eq!(
            GarrisonUtil::get_login_id().await.unwrap(),
            Some("1001".to_string()),
            "当前会话主体应为 1001"
        );
    })
    .await;
}

/// ACC-AUTH-002（正常→异常）：logout 后 token 立即失效（check_login 不再为
/// Ok(true)，按 token 反查为 None），重复 logout 不 panic（幂等）。
#[tokio::test]
#[serial]
async fn acc_auth_002_logout_invalidates_token() {
    let _h = GarrisonTestHarness::builder()
        .config(test_config())
        .init()
        .await
        .unwrap();
    let token = GarrisonUtil::login_simple("1001").await.unwrap();

    with_current_token(token.clone(), async {
        GarrisonUtil::logout().await.unwrap();
    })
    .await;

    let check =
        with_current_token(token.clone(), async { GarrisonUtil::check_login().await }).await;
    assert_token_invalid!(check, "logout 后 check_login 应失效");
    assert_eq!(
        GarrisonUtil::get_login_id_by_token(&token).await.unwrap(),
        None,
        "logout 后按 token 反查应返回 None"
    );
}

/// ACC-AUTH-003（正常）：切换账号——嵌套 `with_current_token` 作用域语义：
/// 外层 A → 内层 B → 回到外层仍为 A（token 上下文不串号）。
#[tokio::test]
#[serial]
async fn acc_auth_003_switch_account_context() {
    let _h = GarrisonTestHarness::builder().init().await.unwrap();
    let token_a = GarrisonUtil::login_simple("user-a").await.unwrap();
    let token_b = GarrisonUtil::login_simple("user-b").await.unwrap();

    with_current_token(token_a.clone(), async {
        assert_eq!(
            GarrisonUtil::get_login_id().await.unwrap(),
            Some("user-a".to_string())
        );
        // 切换到 B
        with_current_token(token_b.clone(), async {
            assert_eq!(
                GarrisonUtil::get_login_id().await.unwrap(),
                Some("user-b".to_string()),
                "切换后当前主体应为 user-b"
            );
        })
        .await;
        // 回到 A
        assert_eq!(
            GarrisonUtil::get_login_id().await.unwrap(),
            Some("user-a".to_string()),
            "退出内层作用域后应回到 user-a"
        );
    })
    .await;
}

// ------------------------------------------------------------------------
// ACC-AUTH-004..005：滑动续期 / 踢出（正常 + 异常）
// ------------------------------------------------------------------------

/// ACC-AUTH-004（正常+异常）：自动续期——`auto_renewal_threshold=80`（剩余
/// TTL 低于 80% 触发续签轮换）：`timeout=2s` 下活动 1.2s 后 check_login 触发
/// 续签，作用域内可读到新 token；旧 token 轮换后失效（异常侧）。
#[tokio::test]
#[serial]
async fn acc_auth_004_auto_renewal_rotates_token_below_threshold() {
    let config = {
        let mut c = garrison::config::GarrisonConfig::default_config();
        c.timeout = 2;
        c.auto_renewal_threshold = 80;
        c.throw_on_not_login = false;
        Arc::new(c)
    };
    let _h = GarrisonTestHarness::builder()
        .config(config)
        .init()
        .await
        .unwrap();
    let old_token = GarrisonUtil::login_simple("1001").await.unwrap();

    // 消耗 1.2s（剩余 ≈40% < 80% 阈值）→ check_login 触发续签。
    // `CURRENT_RENEWED_TOKEN` 的作用域由 `with_renewed_token_scope` 建立
    //（与 axum/actix/warp middleware 的包裹方式一致）。
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;

    let (logged, renewed) =
        with_renewed_token_scope(with_current_token(old_token.clone(), async {
            let logged = GarrisonUtil::check_login().await.unwrap();
            (logged, get_renewed_token())
        }))
        .await;
    assert!(logged, "续期阈值内活动会话应保持登录");
    assert!(renewed.is_some(), "低于阈值应触发续签并产出新 token");
    let new_token = renewed.unwrap();
    assert_ne!(new_token, old_token, "续签应轮换出新 token");
    assert_eq!(
        GarrisonUtil::get_login_id_by_token(&new_token)
            .await
            .unwrap(),
        Some("1001".to_string()),
        "新 token 应绑定同一登录主体"
    );

    // 异常侧：旧 token 轮换后失效
    let old_check =
        with_current_token(old_token, async { GarrisonUtil::check_login().await }).await;
    assert_token_invalid!(old_check, "旧 token 续签轮换后应失效");
}

/// ACC-AUTH-005（异常）：kickout 后该账号全部 token 失效，check_login 不为 Ok(true)。
#[tokio::test]
#[serial]
async fn acc_auth_005_kickout_invalidates_all_tokens() {
    let _h = GarrisonTestHarness::builder()
        .config(test_config())
        .init()
        .await
        .unwrap();
    let token1 = GarrisonUtil::login_simple("1001").await.unwrap();
    let token2 = GarrisonUtil::login_simple("1001").await.unwrap();

    GarrisonUtil::kickout("1001").await.unwrap();

    for (name, token) in [("token1", token1), ("token2", token2)] {
        let check = with_current_token(token, async { GarrisonUtil::check_login().await }).await;
        assert_token_invalid!(check, format!("{name} 在 kickout 后应失效"));
    }
}

// ------------------------------------------------------------------------
// ACC-AUTH-006..008：顶替 / 过期 / 吊销（异常）
// ------------------------------------------------------------------------

/// ACC-AUTH-006（异常）：并发登录溢出顶替——`max_login_count=2`（溢出策略
/// Logout）：第 3 次登录后最早的 token 被顶失效，最新 token 有效。
#[tokio::test]
#[serial]
async fn acc_auth_006_login_overflow_logs_out_oldest_token() {
    let config = {
        let mut c = garrison::config::GarrisonConfig::default_config();
        c.is_concurrent = true; // 允许多端
        c.is_share = false; // 每端独立 token
        c.max_login_count = 2; // 超限顶替最早会话
        c.throw_on_not_login = false;
        Arc::new(c)
    };
    let _h = GarrisonTestHarness::builder()
        .config(config)
        .init()
        .await
        .unwrap();

    let t1 = GarrisonUtil::login_simple("1001").await.unwrap();
    let t2 = GarrisonUtil::login_simple("1001").await.unwrap();
    let t3 = GarrisonUtil::login_simple("1001").await.unwrap();

    let logged = |t: String| async move {
        with_current_token(t, async { GarrisonUtil::check_login().await })
            .await
            .unwrap_or(true)
    };
    assert!(!logged(t1).await, "最早的 t1 应被第 3 次登录顶替失效");
    assert!(logged(t2).await, "t2 仍在并发上限内应有效");
    assert!(logged(t3).await, "最新 t3 应有效");
}

/// ACC-AUTH-007（异常）：绝对过期——`timeout=1s` 后 token 过期被拒绝。
#[tokio::test]
#[serial]
async fn acc_auth_007_expired_token_rejected() {
    let config = {
        let mut c = garrison::config::GarrisonConfig::default_config();
        c.timeout = 1;
        c.throw_on_not_login = false;
        Arc::new(c)
    };
    let _h = GarrisonTestHarness::builder()
        .config(config)
        .init()
        .await
        .unwrap();
    let token = GarrisonUtil::login_simple("1001").await.unwrap();

    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;

    let logged = with_current_token(token, async { GarrisonUtil::check_login().await })
        .await
        .unwrap_or(true);
    assert!(!logged, "超过 timeout 的 token 应过期被拒");
}

/// ACC-AUTH-008（异常）：token 粒度吊销——`revoke_token` 与 `kickout_by_token`
/// 仅失效目标 token，不影响同账号其他会话。
#[tokio::test]
#[serial]
async fn acc_auth_008_token_scoped_revocation() {
    let _h = GarrisonTestHarness::builder()
        .config(test_config())
        .init()
        .await
        .unwrap();
    let t1 = GarrisonUtil::login_simple("1001").await.unwrap();
    let t2 = GarrisonUtil::login_simple("1001").await.unwrap();

    GarrisonUtil::revoke_token(&t1).await.unwrap();
    let t1_check =
        with_current_token(t1.clone(), async { GarrisonUtil::check_login().await }).await;
    assert_token_invalid!(t1_check, "revoke_token 后 t1 应失效");
    let t2_alive = with_current_token(t2.clone(), async { GarrisonUtil::check_login().await })
        .await
        .unwrap_or(true);
    assert!(t2_alive, "t2 不应受 t1 吊销影响");

    GarrisonUtil::kickout_by_token(&t2).await.unwrap();
    let t2_check = with_current_token(t2, async { GarrisonUtil::check_login().await }).await;
    assert_token_invalid!(t2_check, "kickout_by_token 后 t2 应失效");
}

// ------------------------------------------------------------------------
// ACC-AUTH-009：任务隔离（异常侧：上下文不跨 task 泄漏）
// ------------------------------------------------------------------------

/// ACC-AUTH-009（异常）：task_local 上下文不跨 task 泄漏——子任务切换主体
/// 不影响父任务；未设置 token 的任务读取上下文显性报错（fail-loud）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[serial]
async fn acc_auth_009_token_context_not_leaked_across_tasks() {
    let _h = GarrisonTestHarness::builder().init().await.unwrap();
    let token_a = GarrisonUtil::login_simple("user-a").await.unwrap();
    let token_b = GarrisonUtil::login_simple("user-b").await.unwrap();

    with_current_token(token_a.clone(), async {
        let child = with_current_token(token_b, async {
            assert_eq!(
                GarrisonUtil::get_login_id().await.unwrap(),
                Some("user-b".to_string())
            );
        });
        let child = tokio::spawn(child);
        child.await.unwrap();

        // 子任务的 B 上下文不应泄漏回父任务
        assert_eq!(
            GarrisonUtil::get_login_id().await.unwrap(),
            Some("user-a".to_string()),
            "子任务切换不应污染父任务上下文"
        );
    })
    .await;

    // 未设置 token 的任务：读取上下文 fail-loud（Session 错误），而非静默当作 A
    let leaked = tokio::spawn(async { GarrisonUtil::get_login_id().await })
        .await
        .unwrap();
    assert!(
        leaked.is_err() || leaked.unwrap().is_none(),
        "无 token 上下文的任务不应读到任何主体"
    );
}

// ------------------------------------------------------------------------
// ACC-AUTH-010..012：密码登录（防枚举）/ 封禁 / 锁定（异常）
// ------------------------------------------------------------------------

/// ACC-AUTH-010（异常）：错误密码与用户不存在返回**完全相同**的统一错误
/// `InvalidParam("invalid password")`——不泄露账号是否存在（防枚举）。
#[cfg(all(
    feature = "account-credential",
    feature = "db-sqlite",
    feature = "cache-memory"
))]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn acc_auth_010_wrong_password_and_unknown_user_indistinguishable() {
    use garrison::account::credential::password::Argon2Hasher;
    use garrison::dao::repository::{sqlite::DbnexusUserRepository, NewUser, UserRepository};
    use garrison::dao::{init_dbnexus, GarrisonDao, GarrisonDaoOxcache};
    use garrison::error::GarrisonError;
    use garrison::session::GarrisonSession;
    use garrison::stp::{GarrisonInterface, GarrisonLogicDefault, PasswordLogic};
    use garrison::strategy::GarrisonPermissionStrategy;

    struct NoopInterface;
    #[async_trait::async_trait]
    impl GarrisonInterface for NoopInterface {
        async fn get_permission_list(
            &self,
            _login_id: &str,
        ) -> garrison::error::GarrisonResult<Vec<String>> {
            Ok(vec![])
        }
        async fn get_role_list(
            &self,
            _login_id: &str,
        ) -> garrison::error::GarrisonResult<Vec<String>> {
            Ok(vec![])
        }
    }

    let pool = init_dbnexus("sqlite::memory:").await.unwrap();
    let migration = garrison::dao::GarrisonMigration::with_base_dir(
        pool.clone(),
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations/sqlite"),
    );
    migration.migrate_core().await.unwrap();

    let user_repo = Arc::new(DbnexusUserRepository::new(pool.clone()));
    let hasher = Argon2Hasher::new();
    let password_hash =
        garrison::account::credential::password::PasswordHasher::hash(&hasher, "secret").unwrap();
    user_repo
        .create(
            0,
            NewUser {
                username: "1001".to_string(),
                password_hash,
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();

    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoOxcache::new().await.unwrap());
    let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
    let config = garrison::config::GarrisonConfig::default_config();
    let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(
        garrison::strategy::GarrisonPermissionStrategyDefault::new(Arc::new(NoopInterface)),
    );
    let logic = GarrisonLogicDefault::new(session, Arc::new(config), firewall)
        .with_password_hasher(Arc::new(hasher))
        .with_user_repository(user_repo);

    // 正常路径锚点：正确密码可登录
    let ok = logic.login_with_password("1001", "secret").await;
    assert!(ok.is_ok(), "正确密码应登录成功: {:?}", ok.err());

    // 防枚举：两种失败返回逐字相同的统一错误
    let wrong = logic
        .login_with_password("1001", "wrong")
        .await
        .unwrap_err();
    let unknown = logic
        .login_with_password("ghost-9999", "secret")
        .await
        .unwrap_err();
    let unified = |err: &GarrisonError| match err {
        GarrisonError::InvalidParam(m) => m.clone(),
        other => panic!("期望 InvalidParam，实际: {other:?}"),
    };
    assert_eq!(
        unified(&wrong),
        "invalid password",
        "密码错误应返回统一错误（不泄露真实原因）"
    );
    assert_eq!(
        unified(&wrong),
        unified(&unknown),
        "错误密码与用户不存在的错误必须逐字相同（防枚举）"
    );
}

/// ACC-AUTH-011（异常）：账号封禁——`DisableRepository.disable` 后已登录
/// 会话 `check_disable` 拒绝（DisableService 语义）；解封后恢复放行。
#[tokio::test]
#[serial]
async fn acc_auth_011_disable_rejects_then_untie_restores() {
    use garrison::account::disable::{DefaultDisableRepository, DisableRepository};

    let repo = Arc::new(DefaultDisableRepository::new(Arc::new(
        garrison::dao::InMemoryDao::new(),
    )));
    let _h = GarrisonTestHarness::builder()
        .disable_repository(repo.clone())
        .init()
        .await
        .unwrap();

    let token = GarrisonUtil::login_simple("1001").await.unwrap();

    // 封禁前：放行
    with_current_token(token.clone(), async {
        GarrisonUtil::check_disable()
            .await
            .expect("封禁前 check_disable 应放行");
    })
    .await;

    // 封禁（永久，service="default"）→ 已登录会话访问被拒
    repo.disable("1001", "default", None, 0, 0).await.unwrap();
    with_current_token(token.clone(), async {
        let result = GarrisonUtil::check_disable().await;
        assert!(
            result.is_err(),
            "封禁后 check_disable 应拒绝，实际: {:?}",
            result
        );
    })
    .await;

    // 解封 → 恢复放行
    repo.untie_disable("1001", "default").await.unwrap();
    with_current_token(token, async {
        GarrisonUtil::check_disable()
            .await
            .expect("解封后 check_disable 应放行");
    })
    .await;
}

/// ACC-AUTH-012（异常）：登录失败锁定——连续失败达阈值后 `check` 拒绝，
/// `unlock` 后恢复（`account-lockout` feature）。
#[cfg(feature = "account-lockout")]
#[tokio::test]
#[serial]
async fn acc_auth_012_lockout_blocks_after_repeated_failures() {
    use garrison::account::lockout::{UserLockoutConfig, UserLockoutStrategy};
    use garrison::dao::InMemoryDao;
    use garrison::error::GarrisonError;
    use garrison::strategy::firewall::{FirewallContext, GarrisonFirewallStrategy};

    let dao = Arc::new(InMemoryDao::new());
    let config = UserLockoutConfig {
        max_failure_factor: 3,
        ..Default::default()
    };
    let strategy = UserLockoutStrategy::new(config, dao.clone());
    let ctx = FirewallContext::new("203.0.113.9").with_login_id("victim-user");

    // 阈值内：放行
    strategy.record_failure("victim-user").await.unwrap();
    strategy.record_failure("victim-user").await.unwrap();
    strategy.check(&ctx).await.expect("阈值内不应锁定");

    // 达阈值：拒绝（异常侧）
    strategy.record_failure("victim-user").await.unwrap();
    strategy.record_failure("victim-user").await.unwrap();
    let blocked = strategy.check(&ctx).await;
    assert!(
        matches!(blocked, Err(GarrisonError::FirewallBlocked(_))),
        "连续失败达阈值应锁定（FirewallBlocked），实际: {:?}",
        blocked
    );

    // 管理员解锁：恢复
    strategy.unlock("victim-user").await.unwrap();
    strategy.check(&ctx).await.expect("解锁后应恢复放行");
}

// ------------------------------------------------------------------------
// ACC-AUTH-013..016：Phase 4 测试迁移（T040/T043，自 tests/e2e 移植）
// ------------------------------------------------------------------------

/// ACC-AUTH-017（异常）：switch-to 默认安全拒绝——未注入自定义
/// `SwitchToGuard` 时默认 `DenyAllSwitchToGuard` fail-closed 拒绝所有身份切换
/// （`NotPermission`），且被拒切换无副作用（token 仍绑定原主体并保持有效）。
///
/// # 迁移溯源（Phase 4 T040/T043）
/// 自 tests/e2e/session_flow.rs `test_e2e_switch_to_default_denies` 与
/// tests/e2e/api_happy.rs `test_api_happy_kickout_switch_renew`（T021）的
/// switch-to 部分移植。原版经 HTTP 断言 `error_code="NOT_PERMISSION"`；
/// 本场景在逻辑层直接断言 `BackendEmbedded::switch_to` 的 `NotPermission`
/// 错误并补充无副作用断言（不可弱化，语义等价）。
#[tokio::test]
#[serial]
async fn acc_auth_017_switch_to_default_deny_all_guard_rejects() {
    use garrison::backend::{AuthBackend, BackendEmbedded};
    use garrison::error::GarrisonError;

    let _h = GarrisonTestHarness::builder()
        .config(test_config())
        .init()
        .await
        .unwrap();
    let token = GarrisonUtil::login_simple("user-a").await.unwrap();
    let _token_b = GarrisonUtil::login_simple("user-b").await.unwrap();

    let backend = BackendEmbedded::new();
    let result = backend.switch_to(&token, "user-b").await;
    assert!(
        matches!(result, Err(GarrisonError::NotPermission(_))),
        "默认 DenyAllSwitchToGuard 应拒绝 switch-to，实际: {result:?}"
    );

    // 无副作用：token 仍绑定原主体且有效
    assert_eq!(
        GarrisonUtil::get_login_id_by_token(&token).await.unwrap(),
        Some("user-a".to_string()),
        "被拒的切换不应改变 token 绑定主体"
    );
    let logged = with_current_token(token, async { GarrisonUtil::check_login().await }).await;
    assert!(
        matches!(logged, Ok(true)),
        "被拒的切换后原 token 应仍有效，实际: {logged:?}"
    );
}

/// ACC-AUTH-018（正常）：refresh 链 50 次——连续 `renew_to_equivalent` 50 次
/// 每次产出新 token（新旧互异）、链路不中断，最终 token 有效且首 token 已失效。
///
/// # 迁移溯源（Phase 4 T040/T043）
/// 自 tests/e2e/api_boundary.rs `test_api_boundary_refresh_chain_50_times`（T027）
/// 移植。原版经 HTTP `/api/v1/auth/refresh` 断言 status 200 + 新 token；
/// 本场景在逻辑层直接调用 `BackendEmbedded::renew_to_equivalent`（refresh
/// 端点的同一下游实现，见 src/server/sdforge_routes.rs `auth_refresh`），
/// 保留「链不中断 / 新旧互异 / 终态有效」全部语义。
#[tokio::test]
#[serial]
async fn acc_auth_018_refresh_chain_50_times_keeps_valid() {
    use garrison::backend::{AuthBackend, BackendEmbedded};

    let _h = GarrisonTestHarness::builder()
        .config(test_config())
        .init()
        .await
        .unwrap();
    let backend = BackendEmbedded::new();

    let first_token = GarrisonUtil::login_simple("chain-refresh-user")
        .await
        .unwrap();
    let mut current = first_token.clone();
    for i in 1..=50 {
        let new_token = backend
            .renew_to_equivalent(&current)
            .await
            .unwrap_or_else(|e| panic!("第 {i} 次 refresh 应成功，实际: {e:?}"));
        assert_ne!(current, new_token, "第 {i} 次 refresh 应返回新 token");
        current = new_token;
    }

    // 终态：最终 token 有效
    let logged = with_current_token(current, async { GarrisonUtil::check_login().await }).await;
    assert!(
        matches!(logged, Ok(true)),
        "refresh 链 50 次后最终 token 应有效，实际: {logged:?}"
    );
    // 首 token 经轮换链已失效
    let first_check =
        with_current_token(first_token, async { GarrisonUtil::check_login().await }).await;
    assert_token_invalid!(first_check, "refresh 链后首个 token 应已失效");
}

/// ACC-AUTH-019（异常）：**BW-AC-010** 连续登录失败封禁——5 次失败触发锁定
/// （Linear 策略 base=1800s → 锁定时长 ≈ 30 分钟），LockoutState 字段正确
/// （failure_count=5、locked_until>0、锁定时长落在 ±60s 窗口），且可构造
/// `DisableService` 错误（until=Some(now+30min)，HTTP status=403）。
///
/// # 迁移溯源（Phase 4 T040/T043）
/// 自 tests/acceptance_criteria.rs `bw_ac_010_login_failure_locks_account`
///（FRD §8.1 **BW-AC-010**）原样移植，断言语义与编号注释保留。
#[tokio::test]
#[serial]
#[cfg(feature = "account-lockout")]
async fn acc_auth_019_bw_ac_010_login_failure_locks_account() {
    use garrison::account::lockout::{UserLockoutConfig, UserLockoutStrategy, WaitStrategy};
    use garrison::dao::InMemoryDao;

    let dao: Arc<dyn garrison::dao::GarrisonDao> = Arc::new(InMemoryDao::new());

    // 配置：5 次失败触发锁定，每次临时锁定 30min（Linear 策略 base=1800）
    let config = UserLockoutConfig {
        max_failure_factor: 5,
        permanent_lockout: false,
        max_temporary_lockouts: 3,
        wait_strategy: WaitStrategy::Linear { base_seconds: 1800 },
        failure_window_seconds: 300,
    };
    let strategy = UserLockoutStrategy::new(config, dao.clone());

    // Given: 用户连续 5 次登录失败
    for _ in 0..5 {
        strategy
            .record_failure("user-010")
            .await
            .expect("record_failure 应成功");
    }

    // Then: 读取 LockoutState 验证锁定状态
    let lockout_key = "lockout:user-010";
    let lockout_json = dao
        .get(lockout_key)
        .await
        .expect("DAO get 应成功")
        .expect("LockoutState 应存在");
    let state: garrison::account::lockout::LockoutState =
        serde_json::from_str(&lockout_json).expect("反序列化 LockoutState 应成功");

    assert_eq!(state.failure_count, 5, "失败次数应为 5");
    assert!(
        state.locked_until > 0,
        "locked_until 应已设置（账号已锁定）"
    );

    // 验证锁定时长 ≈ 30min（1800 秒，允许 ±60 秒误差）
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let lock_duration = state.locked_until - now;
    assert!(
        (1740..=1860).contains(&lock_duration),
        "锁定时长应接近 1800 秒（30min），实际: {} 秒",
        lock_duration
    );

    // Then: 构造 DisableService 错误（业务代码在捕获 FirewallBlocked 后调用）
    let until = chrono::Utc::now() + chrono::Duration::minutes(30);
    let disable_err = garrison::error::GarrisonError::DisableService {
        service: "default".to_string(),
        until: Some(until),
    };

    // 验证错误变体与字段
    match &disable_err {
        garrison::error::GarrisonError::DisableService { service, until } => {
            assert_eq!(service, "default");
            assert!(until.is_some(), "until 应为 Some");
        },
        other => panic!("期望 DisableService 变体，实际: {other:?}"),
    }

    // 验证 HTTP status = 403
    let (status, _, _, _) = disable_err.response_parts();
    assert_eq!(status, 403, "DisableService 的 HTTP status 应为 403");
}

/// ACC-AUTH-016（正常）：安全默认值——新登录 token 未经二级认证
/// `check_safe=false`、未被封禁 `check_disable=false`；未知 token 同样两项
/// 均为 false（不误报封禁/认证状态）。
///
/// # 迁移溯源（Phase 4 T040/T043）
/// 自 tests/e2e/permission_flow.rs `test_e2e_check_safe_default_returns_false` /
/// `test_e2e_check_disable_default_returns_false` 与 tests/e2e/api_authz_boundary.rs
/// `test_authz_boundary_disabled_token_rejected`（T030d）的 check-disable 部分
/// 移植。原版经 HTTP 断言 `data=false`；本场景经 `BackendEmbedded::check_safe` /
/// `check_disable`（端点同一下游）直接断言布尔值。
#[tokio::test]
#[serial]
async fn acc_auth_016_safe_disable_defaults_false() {
    use garrison::backend::{AuthBackend, BackendEmbedded};

    let _h = GarrisonTestHarness::builder()
        .config(test_config())
        .init()
        .await
        .unwrap();
    let token = GarrisonUtil::login_simple("user1").await.unwrap();

    let backend = BackendEmbedded::new();
    // 新 token 未开启二级认证 → check_safe=false
    assert!(
        !backend.check_safe(&token).await.unwrap(),
        "新 token 未开启二级认证，check_safe 应为 false"
    );
    // 新 token 未被封禁 → check_disable=false
    assert!(
        !backend.check_disable(&token).await.unwrap(),
        "新 token 未被封禁，check_disable 应为 false"
    );
    // 未知 token → 两者均为 false（不误报，T030d fallback 语义）
    assert!(
        !backend
            .check_safe("nonexistent-token-disabled-test-12345")
            .await
            .unwrap(),
        "未知 token check_safe 应为 false"
    );
    assert!(
        !backend
            .check_disable("nonexistent-token-disabled-test-12345")
            .await
            .unwrap(),
        "未知 token check_disable 应为 false（未标记封禁）"
    );
}

// ------------------------------------------------------------------------
// ACC-AUTH-020..022：密码凭据域（T041 迁移自 tests/integration/login_password.rs；
// ACC-AUTH-010 已覆盖的「防枚举统一错误」语义在 021 中标注去重）
// ------------------------------------------------------------------------

/// 测试用 listener：根据 login_id 区分 user_not_found (9999) 与 wrong_password
/// (1001)。v0.4.2 安全审计 A-014：实现层 reason 统一为 "invalid_credentials"，
/// listener 无法仅凭 reason 区分两类失败，需借助 login_id（测试场景固定）。
#[cfg(all(feature = "account-credential", feature = "listener"))]
struct PasswordLoginListener;

#[cfg(all(feature = "account-credential", feature = "listener"))]
#[async_trait::async_trait]
impl garrison::listener::GarrisonListener for PasswordLoginListener {
    async fn on_event(
        &self,
        event: &garrison::listener::GarrisonEvent,
    ) -> garrison::error::GarrisonResult<()> {
        if let garrison::listener::GarrisonEvent::LoginFailure {
            login_id, reason, ..
        } = event
        {
            if reason == "invalid_credentials" {
                if *login_id == "9999" {
                    LOGIN_FAILURE_NOT_FOUND.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                } else if *login_id == "1001" {
                    LOGIN_FAILURE_WRONG_PASSWORD.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }
        Ok(())
    }
}

#[cfg(all(feature = "account-credential", feature = "listener"))]
fn password_login_listener_factory() -> std::sync::Arc<dyn garrison::listener::GarrisonListener> {
    std::sync::Arc::new(PasswordLoginListener)
}

#[cfg(all(feature = "account-credential", feature = "listener"))]
inventory::submit! {
    garrison::listener::GarrisonListenerEntry { factory: password_login_listener_factory }
}

#[cfg(all(feature = "account-credential", feature = "listener"))]
static LOGIN_FAILURE_NOT_FOUND: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(all(feature = "account-credential", feature = "listener"))]
static LOGIN_FAILURE_WRONG_PASSWORD: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[cfg(all(feature = "account-credential", feature = "listener"))]
fn reset_listener_counters() {
    use std::sync::atomic::Ordering;
    LOGIN_FAILURE_NOT_FOUND.store(0, Ordering::SeqCst);
    LOGIN_FAILURE_WRONG_PASSWORD.store(0, Ordering::SeqCst);
}

/// ACC-AUTH-020（正常+异常）：`Argon2Hasher` / `BcryptHasher` hash → verify
/// roundtrip——相同密码匹配、不同密码不匹配、跨算法不互认、`PasswordVerifier`
/// 自动识别算法（原 argon2/bcrypt/cross_algorithm/password_verifier 四测试合并）。
#[cfg(all(
    feature = "account-credential",
    feature = "db-sqlite",
    feature = "cache-memory"
))]
#[tokio::test]
async fn acc_auth_020_password_hashers_roundtrip_and_auto_detect() {
    use garrison::account::credential::password::{
        Argon2Hasher, BcryptHasher, PasswordHasher, PasswordVerifier,
    };

    let argon2 = Argon2Hasher::new();
    let argon2_hash = argon2.hash("correct-password").expect("hash 应成功");
    assert!(
        argon2_hash.starts_with("$argon2"),
        "Argon2 哈希应以 $argon2 开头，实际: {}",
        &argon2_hash[..8.min(argon2_hash.len())]
    );
    assert!(
        argon2.verify("correct-password", &argon2_hash).unwrap(),
        "相同密码应匹配"
    );
    assert!(
        !argon2.verify("wrong-password", &argon2_hash).unwrap(),
        "不同密码应不匹配"
    );

    let bcrypt = BcryptHasher::with_cost(4); // 低 cost 加速测试
    let bcrypt_hash = bcrypt.hash("correct-password").expect("hash 应成功");
    assert!(
        bcrypt_hash.starts_with("$2"),
        "Bcrypt 哈希应以 $2 开头，实际: {}",
        &bcrypt_hash[..3.min(bcrypt_hash.len())]
    );
    assert!(
        bcrypt.verify("correct-password", &bcrypt_hash).unwrap(),
        "相同密码应匹配"
    );
    assert!(
        !bcrypt.verify("wrong-password", &bcrypt_hash).unwrap(),
        "不同密码应不匹配"
    );

    // 跨算法校验不得误判为 true
    assert!(
        !matches!(bcrypt.verify("password", &argon2_hash), Ok(true)),
        "Argon2 hash 不应被 Bcrypt 验证为 true"
    );
    assert!(
        !matches!(argon2.verify("password", &bcrypt_hash), Ok(true)),
        "Bcrypt hash 不应被 Argon2 验证为 true"
    );

    // PasswordVerifier 自动识别算法
    assert!(
        PasswordVerifier::verify("secret", &argon2.hash("secret").unwrap()).unwrap(),
        "PasswordVerifier 应识别 Argon2 hash 并校验通过"
    );
    assert!(
        PasswordVerifier::verify("secret", &bcrypt.hash("secret").unwrap()).unwrap(),
        "PasswordVerifier 应识别 Bcrypt hash 并校验通过"
    );
    assert!(
        !PasswordVerifier::verify("wrong", &argon2.hash("secret").unwrap()).unwrap(),
        "Argon2 hash 错误密码应不匹配"
    );
    assert!(
        !PasswordVerifier::verify("wrong", &bcrypt.hash("secret").unwrap()).unwrap(),
        "Bcrypt hash 错误密码应不匹配"
    );
}

/// 构造注入 Argon2Hasher + DbnexusUserRepository + ListenerManager 的
/// `GarrisonLogicDefault`（镜像 ACC-AUTH-010 的 SQLite 装配与旧 login_password.rs）。
#[cfg(all(
    feature = "account-credential",
    feature = "db-sqlite",
    feature = "cache-memory",
    feature = "listener"
))]
async fn make_logic_with_password() -> std::sync::Arc<garrison::stp::GarrisonLogicDefault> {
    use garrison::account::credential::password::{Argon2Hasher, PasswordHasher};
    use garrison::dao::repository::{sqlite::DbnexusUserRepository, NewUser, UserRepository};
    use garrison::dao::{init_dbnexus, GarrisonDao, GarrisonDaoOxcache, GarrisonMigration};
    use garrison::session::GarrisonSession;
    use garrison::strategy::{GarrisonPermissionStrategy, GarrisonPermissionStrategyDefault};

    struct NoopInterface;
    #[async_trait::async_trait]
    impl garrison::stp::GarrisonInterface for NoopInterface {
        async fn get_permission_list(
            &self,
            _login_id: &str,
        ) -> garrison::error::GarrisonResult<Vec<String>> {
            Ok(vec![])
        }
        async fn get_role_list(
            &self,
            _login_id: &str,
        ) -> garrison::error::GarrisonResult<Vec<String>> {
            Ok(vec![])
        }
    }

    let pool = init_dbnexus("sqlite::memory:").await.unwrap();
    let migration = GarrisonMigration::with_base_dir(
        pool.clone(),
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("migrations/sqlite"),
    );
    migration.migrate_core().await.unwrap();

    let user_repo = Arc::new(DbnexusUserRepository::new(pool.clone()));
    let hasher = Argon2Hasher::new();
    let password_hash = PasswordHasher::hash(&hasher, "secret").unwrap();
    user_repo
        .create(
            0,
            NewUser {
                username: "1001".to_string(),
                password_hash,
                status: "active".to_string(),
            },
        )
        .await
        .expect("预置用户应成功");

    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoOxcache::new().await.unwrap());
    let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
    let mut config = garrison::config::GarrisonConfig::default_config();
    config.token_style = "uuid".to_string();
    config.timeout = 3600;
    config.throw_on_not_login = true;
    let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(
        GarrisonPermissionStrategyDefault::new(Arc::new(NoopInterface)),
    );
    let lm = Arc::new(garrison::listener::GarrisonListenerManager::new());

    Arc::new(
        garrison::stp::GarrisonLogicDefault::new(session, Arc::new(config), firewall)
            .with_password_hasher(Arc::new(hasher))
            .with_user_repository(user_repo)
            .with_listener_manager(lm),
    )
}

#[cfg(all(
    feature = "account-credential",
    feature = "db-sqlite",
    feature = "cache-memory"
))]
fn test_password_config() -> garrison::config::GarrisonConfig {
    let mut config = garrison::config::GarrisonConfig::default_config();
    config.token_style = "uuid".to_string();
    config.timeout = 3600;
    config
}

/// ACC-AUTH-021（正常+异常）：`login_with_password` 端到端——用户存在 + 密码匹配
/// 签发非空 token（成功语义去重至 ACC-AUTH-010 的正确密码锚点）；用户不存在 /
/// 密码错误统一返回 `InvalidParam("invalid password")`（防枚举，去重至
/// ACC-AUTH-010）且 listener 广播 `LoginFailure` 事件各 1 次（本场景增量覆盖：
/// 原 login_password.rs 的 user_not_found / wrong_password 事件计数断言）。
#[cfg(all(
    feature = "account-credential",
    feature = "db-sqlite",
    feature = "cache-memory",
    feature = "listener"
))]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn acc_auth_021_password_login_success_and_failure_listener_events() {
    use garrison::error::GarrisonError;
    use garrison::stp::PasswordLogic;

    reset_listener_counters();
    let logic = make_logic_with_password().await;

    // 正常：用户存在 + 密码匹配 → 非空 token
    let token = logic.login_with_password("1001", "secret").await;
    assert!(
        token.is_ok(),
        "login_with_password 应成功: {:?}",
        token.err()
    );
    assert!(!token.unwrap().is_empty(), "返回 token 不应为空");

    // 异常：用户不存在 → 统一错误 + LoginFailure(login_id=9999) 事件
    let result = logic.login_with_password("9999", "secret").await;
    match result.unwrap_err() {
        GarrisonError::InvalidParam(msg) => assert_eq!(
            msg, "invalid password",
            "用户不存在应统一返回 'invalid password'，不泄露真实原因"
        ),
        other => panic!("期望 InvalidParam，实际: {:?}", other),
    }
    assert_eq!(
        LOGIN_FAILURE_NOT_FOUND.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "应广播 1 次 LoginFailure(login_id=9999) 事件"
    );

    // 异常：密码错误 → 统一错误 + LoginFailure(login_id=1001) 事件
    let result = logic.login_with_password("1001", "wrong-password").await;
    match result.unwrap_err() {
        GarrisonError::InvalidParam(msg) => assert_eq!(
            msg, "invalid password",
            "密码错误应统一返回 'invalid password'"
        ),
        other => panic!("期望 InvalidParam，实际: {:?}", other),
    }
    assert_eq!(
        LOGIN_FAILURE_WRONG_PASSWORD.load(std::sync::atomic::Ordering::SeqCst),
        1,
        "应广播 1 次 LoginFailure(login_id=1001) 事件"
    );
}

/// ACC-AUTH-022（异常）：`login_with_password` 装配缺失 fail-fast——未配置 hasher
/// 返回 `Config("password hasher not configured")`；未配置 user_repository 返回
/// `Config("user repository not configured")`（显性报错，不静默降级）。
#[cfg(all(
    feature = "account-credential",
    feature = "db-sqlite",
    feature = "cache-memory"
))]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn acc_auth_022_password_login_fails_without_hasher_or_repository() {
    use garrison::account::credential::password::Argon2Hasher;
    use garrison::dao::{GarrisonDao, GarrisonDaoOxcache};
    use garrison::error::GarrisonError;
    use garrison::session::GarrisonSession;
    use garrison::stp::{GarrisonInterface, GarrisonLogicDefault, PasswordLogic};
    use garrison::strategy::{GarrisonPermissionStrategy, GarrisonPermissionStrategyDefault};

    struct NoopInterface;
    #[async_trait::async_trait]
    impl GarrisonInterface for NoopInterface {
        async fn get_permission_list(
            &self,
            _login_id: &str,
        ) -> garrison::error::GarrisonResult<Vec<String>> {
            Ok(vec![])
        }
        async fn get_role_list(
            &self,
            _login_id: &str,
        ) -> garrison::error::GarrisonResult<Vec<String>> {
            Ok(vec![])
        }
    }

    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoOxcache::new().await.unwrap());
    let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
    let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(
        GarrisonPermissionStrategyDefault::new(Arc::new(NoopInterface)),
    );

    // 未配置 hasher → Config
    let logic_no_hasher = Arc::new(GarrisonLogicDefault::new(
        session.clone(),
        Arc::new(test_password_config()),
        firewall.clone(),
    ));
    let result = logic_no_hasher.login_with_password("1001", "secret").await;
    match result.unwrap_err() {
        GarrisonError::Config(msg) => assert!(
            msg.contains("password hasher not configured"),
            "错误消息应包含 'password hasher not configured'，实际: {}",
            msg
        ),
        other => panic!("期望 Config，实际: {:?}", other),
    }

    // 未配置 user_repository → Config
    let logic_no_repo = Arc::new(
        GarrisonLogicDefault::new(session, Arc::new(test_password_config()), firewall)
            .with_password_hasher(Arc::new(Argon2Hasher::new())),
    );
    let result = logic_no_repo.login_with_password("1001", "secret").await;
    match result.unwrap_err() {
        GarrisonError::Config(msg) => assert!(
            msg.contains("user repository not configured"),
            "错误消息应包含 'user repository not configured'，实际: {}",
            msg
        ),
        other => panic!("期望 Config，实际: {:?}", other),
    }
}
