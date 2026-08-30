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
    use garrison::dao::{init_dbnexus, GarrisonDao, GarrisonDaoOxcache, GarrisonMigration};
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
