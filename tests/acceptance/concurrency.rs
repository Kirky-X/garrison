//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! concurrency 域验收（spec `acceptance-matrix` R-acceptance-matrix-001，
//! 任务 T032）。`multi_thread` runtime 真实竞争场景，编号 `ACC-CONC-NNN`：
//! 50 并发登录同账号 / 并发 renew（session.renew 与 auto_renewal 竞争）/
//! 并发 refresh 同一 refresh token（轮换重用检测）/ kickout 与 login 竞态。
//!
//! `#[serial]` 约定（硬性要求 1）：所有经 `GarrisonTestHarness`（全局单例）
//! 的测试加 `#[serial]`；不经 `GarrisonManager` 的纯竞争测试（GarrisonSession
//! 独立实例、RefreshTokenRotation 直测）省略。
//!
//! 文件尾原样并入 3 个 `#[ignore]` 性能基线（tests/e2e/perf.rs 的
//! perf_login / perf_check_login / perf_check_permission，保留 `#[ignore]`
//! 与原文档注释；经 `--ignored` 显式触发）。

use garrison::dao::{GarrisonDao, InMemoryDao};
use garrison::protocol::jwt::JwtHandler;
use garrison::session::GarrisonSession;
use garrison::stp::context::{get_renewed_token, with_renewed_token_scope};
use garrison::stp::{with_current_token, GarrisonUtil};
use garrison::RefreshTokenRotation;
use serial_test::serial;
use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use crate::common::harness::GarrisonTestHarness;

/// 统一「token 已失效」断言：`check_login` 返回 `Ok(false)` 或显性错误
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
/// 路径，与仓库集成测试 `make_config()` 惯例一致）。
fn test_config() -> Arc<garrison::config::GarrisonConfig> {
    let mut c = garrison::config::GarrisonConfig::default_config();
    c.throw_on_not_login = false;
    Arc::new(c)
}

// ------------------------------------------------------------------------
// ACC-CONC-001：50 task 并发 login 同账号
// ------------------------------------------------------------------------

/// ACC-CONC-001（正常）：50 个并发 task 登录同一账号——全部成功、签发 50 个
/// 互不相同的 token、按 token 反查全部一致、`max_login_count=100` 足够大时
/// 不误伤（50 < 100，无任何 token 被顶替）。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn acc_conc_001_concurrent_login_same_account_all_valid() {
    let config = {
        let mut c = garrison::config::GarrisonConfig::default_config();
        c.is_concurrent = true; // 允许多端并发登录
        c.is_share = false; // 每端独立 token
        c.max_login_count = 100; // 足够大：50 次并发登录不应触发任何顶替
        c.throw_on_not_login = false;
        Arc::new(c)
    };
    let _h = GarrisonTestHarness::builder()
        .config(config)
        .init()
        .await
        .unwrap();

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..50 {
        set.spawn(async { GarrisonUtil::login_simple("conc-1001").await });
    }
    let mut tokens = Vec::with_capacity(50);
    while let Some(result) = set.join_next().await {
        let token = result
            .expect("并发登录 task 不应 panic")
            .unwrap_or_else(|e| panic!("50 个并发登录应全部成功，实际: {e:?}"));
        tokens.push(token);
    }
    assert_eq!(tokens.len(), 50, "50 个并发 task 应全部产出 token");

    let unique: HashSet<&String> = tokens.iter().collect();
    assert_eq!(unique.len(), 50, "50 次登录应签发 50 个互不相同的 token");

    // 全部反查一致：get_login_id_by_token 均命中同一主体
    for token in &tokens {
        assert_eq!(
            GarrisonUtil::get_login_id_by_token(token).await.unwrap(),
            Some("conc-1001".to_string()),
            "并发登录签发的 token 应全部反查到 conc-1001"
        );
    }

    // max_login_count=100 足够大时不误伤：全部 token 仍有效
    for token in &tokens {
        let logged =
            with_current_token(token.clone(), async { GarrisonUtil::check_login().await }).await;
        assert!(
            matches!(logged, Ok(true)),
            "max_login_count=100 时 50 个 token 不应被顶替（实际: {:?}）",
            logged
        );
    }
}

// ------------------------------------------------------------------------
// ACC-CONC-002..003：并发 renew（session.renew / auto_renewal 竞争）
// ------------------------------------------------------------------------

/// ACC-CONC-002（正常）：20 个并发 `GarrisonSession::renew` 同一 token——
/// 全部成功（renew 即 touch：重置 TTL + 更新活跃时间），token 保持有效，
/// 无 token 泄漏/重复（Account-Session 中仍只有 1 个 token，反查一致）。
///
/// 不经 `GarrisonManager`（独立 `GarrisonSession` + `InMemoryDao` 实例），
/// 省略 `#[serial]`。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acc_conc_002_concurrent_session_renew_no_token_duplication() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    let session = Arc::new(GarrisonSession::new(dao, 3600, 86400, 0));
    let token = "conc-renew-token-001";
    session.create("1001", token).await.unwrap();

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let session = session.clone();
        let token = token.to_string();
        set.spawn(async move { session.renew(&token).await });
    }
    while let Some(result) = set.join_next().await {
        result
            .expect("并发 renew task 不应 panic")
            .unwrap_or_else(|e| panic!("并发的 renew 调用应全部成功，实际: {e:?}"));
    }

    assert!(
        session.is_valid(token).await.unwrap(),
        "20 次并发 renew 后 token 应仍有效"
    );
    // 无 token 泄漏/重复：Account-Session 中 token 列表长度不变
    let account = session
        .get_account_session("1001")
        .await
        .unwrap()
        .expect("Account-Session 应存在");
    assert_eq!(account.tokens.len(), 1, "并发 renew 不应产生重复 token");
    assert_eq!(account.tokens[0].token, token);
    // 反查一致：Token-Session 仍绑定同一主体
    let ts = session
        .get_token_session(token)
        .await
        .unwrap()
        .expect("Token-Session 应存在");
    assert_eq!(ts.login_id, "1001", "renew 后反查主体应一致");
}

/// ACC-CONC-003（异常侧）：auto_renewal 并发竞争——10 个并发 `check_login`
/// 触发同一 token 的自动续签，per-login_id 续签锁 + 锁内二次 TTL 检查保证
/// **恰一次**续签（其余并发调用被吸收，无 token 泄漏/重复）：
/// - 恰 1 个 task 产出续签新 token，且与旧 token 不同；
/// - 新 token 有效且绑定同一主体；旧 token 轮换后失效；
/// - 产出续签的 task 自身保持登录（Ok(true)），其余 task 不报错。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn acc_conc_003_concurrent_auto_renewal_exactly_once() {
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

    // 消耗 1.3s（剩余 ≈35% < 80% 阈值）→ 后续 check_login 触发续签
    tokio::time::sleep(std::time::Duration::from_millis(1300)).await;

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..10 {
        let token = old_token.clone();
        set.spawn(async move {
            with_renewed_token_scope(with_current_token(token, async {
                let logged = GarrisonUtil::check_login().await;
                (logged, get_renewed_token())
            }))
            .await
        });
    }

    let mut renewed_tokens: Vec<String> = Vec::new();
    let mut renewer_logged_ok = None;
    let mut all_tasks_ok = true;
    while let Some(result) = set.join_next().await {
        let (logged, renewed) = result.expect("并发 check_login task 不应 panic");
        if let Err(e) = &logged {
            all_tasks_ok = false;
            eprintln!("check_login 意外失败: {e:?}");
        }
        match renewed {
            Some(new_token) => {
                renewer_logged_ok = Some(logged.is_ok() && matches!(logged, Ok(true)));
                renewed_tokens.push(new_token);
            },
            None => {},
        }
    }
    assert!(
        all_tasks_ok,
        "10 个并发 check_login 均不应报错（续签失败只告警）"
    );

    // 恰一次续签：per-login 续签锁内二次 TTL 检查吸收其余并发调用
    assert_eq!(
        renewed_tokens.len(),
        1,
        "10 个并发 check_login 应恰有一次续签产出新 token（无泄漏/重复）"
    );
    let renewer = renewer_logged_ok.expect("产出续签的 task 应存在");
    assert!(renewer, "产出续签的 task 自身应保持登录 Ok(true)");
    let new_token = renewed_tokens.into_iter().next().unwrap();
    assert_ne!(new_token, old_token, "续签应轮换出新 token");

    // 新 token 有效且绑定同一主体；旧 token 轮换后失效
    assert_eq!(
        GarrisonUtil::get_login_id_by_token(&new_token)
            .await
            .unwrap(),
        Some("1001".to_string()),
        "新 token 应绑定同一登录主体"
    );
    let new_logged =
        with_current_token(new_token, async { GarrisonUtil::check_login().await }).await;
    assert!(
        matches!(new_logged, Ok(true)),
        "续签新 token 应有效（实际: {:?}）",
        new_logged
    );
    let old_logged =
        with_current_token(old_token, async { GarrisonUtil::check_login().await }).await;
    assert_token_invalid!(old_logged, "旧 token 续签轮换后应失效");
}

// ------------------------------------------------------------------------
// ACC-CONC-004：kickout 与 login 竞态
// ------------------------------------------------------------------------

/// ACC-CONC-004（异常侧）：kickout 与并发 login 竞态——终态一致。
///
/// `GarrisonSession` 对同一 login_id 的 login 写入与 kickout 删除均在
/// per-login_id 锁（`with_login_lock`）临界区内串行化，故序关系可确定：
/// - 顺序锚点：kickout 之前签发的 token 全部失效（「kickout 前的 token 全失效」）；
/// - 顺序锚点：kickout 完成之后签发的 token 有效（「kickout 后登录的 token 有效」）；
/// - 竞态阶段：`JoinSet` 同时发起 kickout 与 20 个 login，断言确定性不变量：
///   - kickout 成功，无 task 失败；
///   - 观察到 kickout 已完成（AtomicBool）才返回的登录 token 必然有效；
///   - 终态一致：每个登录 token 要么有效（反查一致 + check_login=true）要么
///     已失效（反查 None + check_login 不为 Ok(true)），无中间态、无跨账号泄漏。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[serial]
async fn acc_conc_004_kickout_login_race_final_state_consistent() {
    let _h = GarrisonTestHarness::builder()
        .config(test_config())
        .init()
        .await
        .unwrap();

    // 顺序锚点 A：kickout 之前签发的 token 全部失效
    let pre_token = GarrisonUtil::login_simple("race-904").await.unwrap();

    // 竞态阶段：同时发起 kickout（tokio::spawn）与 20 个 login（JoinSet，
    // 两种返回类型经两条通道分别收集，等价于 join! 并发语义）。kickout 完成
    // 即置位 AtomicBool，作为「kickout 已完成」的同步点。
    let kickout_done = Arc::new(AtomicBool::new(false));
    let kickout_handle = {
        let flag = kickout_done.clone();
        tokio::spawn(async move {
            let result = GarrisonUtil::kickout("race-904").await;
            flag.store(true, Ordering::SeqCst);
            result
        })
    };
    let mut set = tokio::task::JoinSet::new();
    for _ in 0..20 {
        let flag = kickout_done.clone();
        set.spawn(async move {
            let result = GarrisonUtil::login_simple("race-904").await;
            let saw_kickout_done = flag.load(Ordering::SeqCst);
            (saw_kickout_done, result)
        });
    }

    // 先收 kickout（不等待 logins），其完成即触发 flag
    let kickout_result = kickout_handle.await.expect("kickout task 不应 panic");
    assert!(
        kickout_result.is_ok(),
        "kickout 应成功，实际: {:?}",
        kickout_result.err()
    );

    let mut login_entries: Vec<(bool, String)> = Vec::new();
    while let Some(result) = set.join_next().await {
        let (saw_kickout_done, login) = result.expect("login task 不应 panic");
        let token = login.unwrap_or_else(|e| panic!("竞态 login 不应失败，实际: {e:?}"));
        login_entries.push((saw_kickout_done, token));
    }
    assert_eq!(login_entries.len(), 20, "20 个并发 login 应全部成功");

    // 顺序锚点 A 断言：kickout 之前签发的 token 失效
    let pre_logged =
        with_current_token(pre_token, async { GarrisonUtil::check_login().await }).await;
    assert_token_invalid!(pre_logged, "kickout 之前签发的 token 应全部失效");

    // 竞态不变量 1：观察到 kickout 已完成才返回的登录 token 必然有效
    for (saw_kickout_done, token) in &login_entries {
        if *saw_kickout_done {
            let logged =
                with_current_token(token.clone(), async { GarrisonUtil::check_login().await })
                    .await;
            assert!(
                matches!(logged, Ok(true)),
                "kickout 完成后登录的 token 应有效（实际: {:?}）",
                logged
            );
        }
    }

    // 竞态不变量 2：终态一致——每个登录 token 要么有效（反查一致）要么失效
    //（无反查），不存在中间态；任何有效 token 都不跨账号泄漏。
    for (_, token) in &login_entries {
        let lookup = GarrisonUtil::get_login_id_by_token(token).await.unwrap();
        let logged =
            with_current_token(token.clone(), async { GarrisonUtil::check_login().await }).await;
        if lookup.is_some() {
            assert_eq!(
                lookup.as_deref(),
                Some("race-904"),
                "有效 token 反查不得跨账号泄漏"
            );
            assert!(
                matches!(logged, Ok(true)),
                "反查命中的 token 其 check_login 应一致为有效（实际: {:?}）",
                logged
            );
        } else {
            assert_token_invalid!(logged, "无反查的 token 不得处于半有效状态");
        }
    }

    // 顺序锚点 B：kickout 完成之后签到的新 token 有效
    let post_token = GarrisonUtil::login_simple("race-904").await.unwrap();
    let post_logged = with_current_token(post_token.clone(), async {
        GarrisonUtil::check_login().await
    })
    .await;
    assert!(
        matches!(post_logged, Ok(true)),
        "kickout 后登录的 token 应有效（实际: {:?}）",
        post_logged
    );
    assert_eq!(
        GarrisonUtil::get_login_id_by_token(&post_token)
            .await
            .unwrap(),
        Some("race-904".to_string()),
        "kickout 后登录的 token 应反查一致"
    );
}

// ------------------------------------------------------------------------
// ACC-CONC-005：并发 refresh 同一 refresh token（轮换重用检测）
// ------------------------------------------------------------------------

// 以下三个表直查辅助（INSERT / 查 revoked 列），镜像
// tests/integration/refresh_token.rs 的已知良好装配（dbnexus + sea-orm）。

async fn insert_refresh_token(
    pool: &dbnexus::DbPool,
    token_hash: &str,
    parent_token_hash: Option<&str>,
    login_id: i64,
    tenant_id: i64,
    key_version: u32,
    expires_at: i64,
    revoked: i64,
) {
    use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
    let session = pool.get_session("admin").await.expect("获取 admin session");
    let conn = session.connection().expect("获取连接");
    let stmt = Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "INSERT INTO refresh_tokens (token_hash, parent_token_hash, login_id, tenant_id, key_version, expires_at, revoked, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        vec![
            Value::String(Some(token_hash.to_string())),
            Value::String(parent_token_hash.map(|s| s.to_string())),
            Value::BigInt(Some(login_id)),
            Value::BigInt(Some(tenant_id)),
            Value::BigInt(Some(key_version as i64)),
            Value::BigInt(Some(expires_at)),
            Value::BigInt(Some(revoked)),
            Value::BigInt(Some(0)),
        ],
    );
    conn.execute_raw(stmt).await.expect("INSERT 应成功");
}

async fn query_revoked(pool: &dbnexus::DbPool, token_hash: &str) -> i64 {
    use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
    let session = pool.get_session("admin").await.expect("获取 admin session");
    let conn = session.connection().expect("获取连接");
    let stmt = Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "SELECT revoked FROM refresh_tokens WHERE token_hash = ?",
        vec![Value::String(Some(token_hash.to_string()))],
    );
    let row = conn
        .query_one_raw(stmt)
        .await
        .expect("查询应成功")
        .expect("record 应存在");
    row.try_get::<i64>("", "revoked").expect("读取 revoked 列")
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// ACC-CONC-005（异常侧）：8 个并发 task 对同一 refresh token 调用
/// `RefreshTokenRotation::rotate`——恰一次成功（轮换出新的 access+refresh
/// 对），其余调用全部被重用/已消费识别（`TokenRevoked` 或
/// `InvalidToken("refresh token not found or already consumed")`），整条链
/// 终态一致：旧 token revoked=1、新 token revoked=0，无重复签发。
///
/// # 池装配说明（API 偏差记录）
///
/// `rotate` 是**非事务性读-改-写**（detect_reuse → SELECT → INSERT → UPDATE，
/// 无内部锁）；且 dbnexus `sqlite::memory:` 多连接池下每个连接持有独立的
/// 内存库（并发 get_session 会看到空库）。因此本测试使用
/// `max_connections=1` 的单连接内存池：rotate 全程持有唯一连接，语句序列
/// 天然串行，`sqlite::memory:` 仅一份库（迁移/插入/轮换全部可见）。此装配
/// 使「恰一次成功」成为确定性不变量（非概率性断言），并保留 8 task 并发
/// 调度的真实竞争形态（连接获取互斥排队）。
///
/// 不经 `GarrisonManager`（直接构造 `RefreshTokenRotation` + SQLite 迁移，
/// 镜像 tests/integration/refresh_token.rs 装配），省略 `#[serial]`。
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn acc_conc_005_concurrent_refresh_same_token_exactly_once() {
    let pool = setup_single_connection_db().await;
    let jwt_handler = Arc::new(JwtHandler::new("test_secret_key_min_32_bytes!!!!"));
    let rotation = Arc::new(RefreshTokenRotation::new(
        pool.clone(),
        jwt_handler,
        Arc::new(std::sync::RwLock::new(1)),
    ));

    let t1 = "initial-refresh-token-t1";
    let t1_hash = crate::common::sha256_hex(t1);
    insert_refresh_token(
        &pool,
        &t1_hash,
        None,
        1001,
        0,
        1,
        now_unix() + 7 * 24 * 3600,
        0,
    )
    .await;

    let mut set = tokio::task::JoinSet::new();
    for _ in 0..8 {
        let rotation = rotation.clone();
        let token = t1.to_string();
        set.spawn(async move { rotation.rotate(&token).await });
    }

    let mut successes: Vec<(String, String)> = Vec::new();
    let mut reuse_detected = 0usize;
    while let Some(result) = set.join_next().await {
        match result.expect("并发 rotate task 不应 panic") {
            Ok((access, new_refresh)) => successes.push((access, new_refresh)),
            Err(err) => {
                // 重用检测的两种表达（依检测命中时机）：
                // - detect_reuse 命中已 revoked → TokenRevoked("reuse")
                // - SELECT...AND revoked=0 落空 → InvalidToken("already consumed")
                let msg = format!("{err}");
                let rejected = matches!(
                    err,
                    garrison::error::GarrisonError::TokenRevoked(_)
                        | garrison::error::GarrisonError::InvalidToken(_)
                ) && (msg.contains("reuse") || msg.contains("consumed"));
                assert!(
                    rejected,
                    "并发 rotate 失败方应被重用/已消费识别，实际: {msg}"
                );
                reuse_detected += 1;
            },
        }
    }

    // 恰一次成功：其余全部被重用/已消费识别（无重复签发、无泄漏）
    assert_eq!(
        successes.len(),
        1,
        "8 个并发 rotate 应恰一次成功（轮换链单次消费语义）"
    );
    assert_eq!(reuse_detected, 7, "其余 7 个并发 rotate 应被重用检测识别");

    let (access, new_refresh) = successes.into_iter().next().unwrap();
    assert!(!access.is_empty(), "新 access token 应非空");
    assert_ne!(t1, new_refresh, "新 refresh token 不应与旧 token 相同");

    // 终态一致：旧 token revoked=1，新 token revoked=0
    assert_eq!(
        query_revoked(&pool, &t1_hash).await,
        1,
        "旧 refresh token 应标记为 revoked"
    );
    let new_hash = crate::common::sha256_hex(&new_refresh);
    assert_eq!(
        query_revoked(&pool, &new_hash).await,
        0,
        "新 refresh token 应未 revoked"
    );
}

/// 单连接 SQLite 内存池（`max_connections=min_connections=1`）。
///
/// 见 ACC-CONC-005 的池装配说明：dbnexus 多连接 `sqlite::memory:` 池的每个
/// 连接持有独立内存库，并发会话会看到空库；单连接池保证迁移/写入/轮换的
/// 读-改-写序列串行可见。
async fn setup_single_connection_db() -> dbnexus::DbPool {
    let mut config = dbnexus::DbConfig::default();
    config.url = "sqlite::memory:".to_string();
    config.pool_config.max_connections = 1;
    config.pool_config.min_connections = 1;
    config.pool_config.acquire_timeout = 15_000;
    let pool = dbnexus::DbPool::with_config(config)
        .await
        .expect("初始化单连接 dbnexus 池应成功");
    let migration = garrison::dao::GarrisonMigration::with_base_dir(
        pool.clone(),
        crate::common::project_migrations_dir(),
    );
    let applied = migration.migrate_core().await.expect("migrate_core 应成功");
    assert!(applied >= 1, "migrate_core 应至少执行 1 个文件");
    pool
}

// ============================================================================
// 支持性性能基建（perf_util）：从 tests/e2e/（mod.rs + remote.rs + perf.rs）
// 原样下沉，供文件尾 3 个 #[ignore] 性能基线编译与运行。
// ============================================================================

mod perf_util {
    use once_cell::sync::OnceCell;
    use parking_lot::Mutex;
    use serde_json::json;
    use std::io::{BufRead, Write};
    use std::process::{Child, Command, Stdio};
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    /// 构造默认租户上下文所需的 HTTP headers（镜像 tests/e2e/mod.rs）。
    pub(super) fn default_tenant_headers() -> reqwest::header::HeaderMap {
        let mut headers = reqwest::header::HeaderMap::new();
        #[cfg(feature = "tenant-isolation")]
        {
            headers.insert(
                "X-Tenant-Id",
                reqwest::header::HeaderValue::from_static("0"),
            );
        }
        headers
    }

    /// 通用 env 变量 RAII Guard（镜像 tests/e2e/mod.rs）。
    pub(super) struct EnvGuard {
        key: String,
        original: Option<String>,
    }

    impl EnvGuard {
        pub(super) fn new(key: &str, val: &str) -> Self {
            let original = std::env::var(key).ok();
            std::env::set_var(key, val);
            Self {
                key: key.to_string(),
                original,
            }
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match self.original.take() {
                Some(orig) => std::env::set_var(&self.key, orig),
                None => std::env::remove_var(&self.key),
            }
        }
    }

    /// 远程 auth_server_serve 上下文（镜像 tests/e2e/remote.rs）。
    pub(super) struct RemoteContext {
        pub(super) external_url: String,
        pub(super) internal_url: String,
        pub(super) api_key: String,
        _child: Option<Child>,
    }

    impl Drop for RemoteContext {
        fn drop(&mut self) {
            if let Some(child) = self._child.as_mut() {
                if let Err(e) = child.kill() {
                    eprintln!("[RemoteContext::drop] kill 子进程失败: {}", e);
                }
                if let Err(e) = child.wait() {
                    eprintln!("[RemoteContext::drop] wait 子进程失败: {}", e);
                }
            }
        }
    }

    impl RemoteContext {
        pub(super) async fn connect_env() -> Option<Self> {
            let external_url = std::env::var("GARRISON_E2E_EXTERNAL_URL").ok()?;
            let internal_url = std::env::var("GARRISON_E2E_INTERNAL_URL").ok()?;
            let api_key = std::env::var("GARRISON_E2E_API_KEY").ok()?;

            let client = reqwest::Client::builder()
                .default_headers(default_tenant_headers())
                .build()
                .ok()?;

            for _ in 0..3 {
                if let Ok(resp) = client
                    .get(format!("{}/api/v1/auth/health", internal_url))
                    .header("x-api-key", &api_key)
                    .send()
                    .await
                {
                    if resp.status().is_success() {
                        return Some(Self {
                            external_url,
                            internal_url,
                            api_key,
                            _child: None,
                        });
                    }
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            None
        }

        pub(super) fn spawn_child() -> Self {
            let external_port = pick_free_port();
            let internal_port = pick_free_port();
            let api_key = std::env::var("EXAMPLE_INTERNAL_API_KEY")
                .unwrap_or_else(|_| "e2e-test-key-12345".to_string());

            let mut child = Command::new("cargo")
                .args([
                    "run",
                    "-p",
                    "garrison-examples",
                    "--bin",
                    "auth_server_serve",
                    "--features",
                    "full",
                ])
                .env("EXAMPLE_INTERNAL_API_KEY", &api_key)
                .env("GARRISON_EXTERNAL_PORT", external_port.to_string())
                .env("GARRISON_INTERNAL_PORT", internal_port.to_string())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn auth_server_serve 失败");

            let stderr = child.stderr.take().expect("stderr 不应为 None");
            let (tx, rx) = mpsc::channel::<String>();
            std::thread::spawn(move || {
                let reader = std::io::BufReader::new(stderr);
                for line in reader.lines().map_while(Result::ok) {
                    if tx.send(line).is_err() {
                        break;
                    }
                }
            });

            let deadline = Instant::now() + Duration::from_secs(180);
            let mut external_url: Option<String> = None;
            let mut internal_url: Option<String> = None;
            let mut stderr_dump = String::new();

            loop {
                if Instant::now() >= deadline {
                    panic!(
                        "auth_server_serve 180s 内未输出 listening 行，stderr dump:\n{}",
                        stderr_dump
                    );
                }
                match rx.recv_timeout(Duration::from_millis(100)) {
                    Ok(line) => {
                        stderr_dump.push_str(&line);
                        stderr_dump.push('\n');
                        if external_url.is_none() {
                            if let Some(port) = parse_port(&line, "external") {
                                external_url = Some(format!("http://127.0.0.1:{}", port));
                            }
                        }
                        if internal_url.is_none() {
                            if let Some(port) = parse_port(&line, "internal") {
                                internal_url = Some(format!("http://127.0.0.1:{}", port));
                            }
                        }
                        if external_url.is_some() && internal_url.is_some() {
                            break;
                        }
                    },
                    Err(mpsc::RecvTimeoutError::Timeout) => continue,
                    Err(mpsc::RecvTimeoutError::Disconnected) => {
                        panic!(
                            "auth_server_serve stderr 提前关闭，stderr dump:\n{}",
                            stderr_dump
                        );
                    },
                }
            }

            Self {
                external_url: external_url.expect("已校验 external_url 非 None"),
                internal_url: internal_url.expect("已校验 internal_url 非 None"),
                api_key,
                _child: Some(child),
            }
        }

        pub(super) async fn setup() -> Self {
            if let Some(ctx) = Self::connect_env().await {
                return ctx;
            }
            Self::spawn_child()
        }

        pub(super) fn plain_client(&self) -> reqwest::Client {
            reqwest::Client::builder()
                .default_headers(default_tenant_headers())
                .build()
                .expect("构造 reqwest 客户端失败")
        }
    }

    /// 从 stderr 行解析端口（镜像 tests/e2e/remote.rs）。
    fn parse_port(line: &str, key: &str) -> Option<u16> {
        let prefix = format!("{}=0.0.0.0:", key);
        let start = line.find(&prefix)? + prefix.len();
        let rest = &line[start..];
        let end = rest
            .find(|c: char| !c.is_ascii_digit())
            .unwrap_or(rest.len());
        rest[..end].parse().ok()
    }

    /// 挑选空闲端口（镜像 tests/e2e/remote.rs）。
    fn pick_free_port() -> u16 {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind 失败");
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        port
    }

    /// 性能报告 JSONL 共享单例（OnceCell，append 模式，镜像 tests/e2e/perf.rs）。
    static PERF_LOG: OnceCell<Arc<Mutex<std::io::BufWriter<std::fs::File>>>> = OnceCell::new();

    fn open_perf_log() -> Arc<Mutex<std::io::BufWriter<std::fs::File>>> {
        PERF_LOG
            .get_or_init(|| {
                std::fs::create_dir_all("logs").expect("创建 logs/ 目录失败");
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open("logs/perf.jsonl")
                    .expect("打开 logs/perf.jsonl 失败");
                Arc::new(Mutex::new(std::io::BufWriter::new(file)))
            })
            .clone()
    }

    pub(super) fn append_perf_report(report: &LoadReport, test_name: &str, endpoint: &str) {
        let entry = json!({
            "ts": chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            "test_name": test_name,
            "endpoint": endpoint,
            "total": report.total,
            "errors": report.errors,
            "rps": report.rps,
            "p50_ms": report.p50_ms,
            "p95_ms": report.p95_ms,
            "p99_ms": report.p99_ms,
        });
        let log = open_perf_log();
        let mut writer = log.lock();
        writeln!(writer, "{}", entry).expect("写入 perf.jsonl 失败");
        writer.flush().expect("flush perf.jsonl 失败");
    }

    /// 配置性能测试环境：设置高 rate_limit（spawn_child 模式下被子进程继承）。
    pub(super) fn setup_perf_env() -> EnvGuard {
        EnvGuard::new("GARRISON_RATE_LIMIT", "100000")
    }

    /// 性能基线断言：release 模式 HARD panic，debug 模式 SOFT 警告。
    pub(super) fn assert_perf_baseline(
        metric: &str,
        actual: u64,
        target: u64,
        op: &str,
        scenario: &str,
    ) {
        let (met, symbol) = match op {
            "lt" => (actual < target, "<"),
            "ge" => (actual >= target, ">="),
            _ => panic!("assert_perf_baseline: 未知 op {}", op),
        };
        if !met {
            if cfg!(debug_assertions) {
                eprintln!(
                    "⚠️  [debug SOFT] {}={} 未达标（{}{}，{} 性能基线），spec 预判 debug 模式不阻塞",
                    metric, actual, symbol, target, scenario
                );
            } else {
                panic!(
                    "{}={} 应 {}{}（{} 性能基线）",
                    metric, actual, symbol, target, scenario
                );
            }
        }
    }

    /// 负载测试报告（镜像 tests/e2e/perf.rs）。
    #[derive(Debug)]
    pub(super) struct LoadReport {
        pub(super) total: u64,
        pub(super) errors: u64,
        pub(super) rps: u64,
        pub(super) p50_ms: u64,
        pub(super) p95_ms: u64,
        pub(super) p99_ms: u64,
    }

    /// 自实现负载生成器（镜像 tests/e2e/perf.rs 的 LoadRunner）。
    pub(super) struct LoadRunner {
        client: reqwest::Client,
        url: String,
        method: reqwest::Method,
        body: Option<serde_json::Value>,
        headers: Vec<(String, String)>,
        concurrency: usize,
        duration: Duration,
        max_requests: Option<u64>,
    }

    impl LoadRunner {
        pub(super) fn new(
            client: reqwest::Client,
            url: impl Into<String>,
            method: reqwest::Method,
            body: Option<serde_json::Value>,
            concurrency: usize,
            duration: Duration,
        ) -> Self {
            Self {
                client,
                url: url.into(),
                method,
                body,
                headers: Vec::new(),
                concurrency,
                duration,
                max_requests: None,
            }
        }

        pub(super) fn with_header(mut self, key: &str, value: &str) -> Self {
            self.headers.push((key.to_string(), value.to_string()));
            self
        }

        /// 原样保留的公共 API（e2e/perf.rs 的 LoadRunner 亦有此方法；当前 3 个
        /// 基线未使用，保留以维持与原实现逐字一致）。
        #[allow(dead_code)]
        pub(super) fn with_max_requests(mut self, max: u64) -> Self {
            self.max_requests = Some(max);
            self
        }

        async fn worker(
            runner: Arc<LoadRunner>,
            stop: Arc<AtomicBool>,
            errors: Arc<AtomicU64>,
            total: Arc<AtomicU64>,
        ) -> Vec<u64> {
            let mut latencies: Vec<u64> = Vec::new();
            while !stop.load(Ordering::Relaxed) {
                if let Some(max) = runner.max_requests {
                    if total.load(Ordering::Relaxed) >= max {
                        break;
                    }
                }
                let mut req = runner
                    .client
                    .request(runner.method.clone(), runner.url.as_str());
                for (k, v) in &runner.headers {
                    req = req.header(k.as_str(), v.as_str());
                }
                if let Some(b) = &runner.body {
                    req = req.json(b);
                }
                let start = Instant::now();
                match req.send().await {
                    Ok(resp) => {
                        let latency = start.elapsed().as_millis() as u64;
                        let is_success = resp.status().is_success();
                        let _ = resp.bytes().await;
                        if is_success {
                            latencies.push(latency);
                        } else {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                        total.fetch_add(1, Ordering::Relaxed);
                    },
                    Err(_) => {
                        errors.fetch_add(1, Ordering::Relaxed);
                        total.fetch_add(1, Ordering::Relaxed);
                    },
                }
            }
            latencies
        }

        pub(super) async fn run(self) -> LoadReport {
            let runner = Arc::new(self);
            let stop = Arc::new(AtomicBool::new(false));
            let errors = Arc::new(AtomicU64::new(0));
            let total = Arc::new(AtomicU64::new(0));

            let mut handles = Vec::with_capacity(runner.concurrency);
            for _ in 0..runner.concurrency {
                let handle = tokio::spawn(Self::worker(
                    runner.clone(),
                    stop.clone(),
                    errors.clone(),
                    total.clone(),
                ));
                handles.push(handle);
            }

            tokio::time::sleep(runner.duration).await;
            stop.store(true, Ordering::Relaxed);

            let mut latencies_v: Vec<u64> = Vec::new();
            for handle in handles {
                match handle.await {
                    Ok(worker_latencies) => latencies_v.extend(worker_latencies),
                    Err(e) => eprintln!("worker join 失败: {}", e),
                }
            }

            latencies_v.sort_unstable();
            let count = latencies_v.len();
            let total_count = total.load(Ordering::Relaxed);
            let errors_count = errors.load(Ordering::Relaxed);
            let duration_secs = runner.duration.as_secs_f64().max(0.001);

            let percentile = |k: usize| -> u64 {
                if count == 0 {
                    return 0;
                }
                let idx = (count * k / 100).min(count - 1);
                latencies_v[idx]
            };

            LoadReport {
                total: total_count,
                errors: errors_count,
                rps: (total_count as f64 / duration_secs) as u64,
                p50_ms: percentile(50),
                p95_ms: percentile(95),
                p99_ms: percentile(99),
            }
        }
    }
}

// ============================================================================
// 文件尾：3 个 #[ignore] 性能基线（自 tests/e2e/perf.rs 原样并入，
// 保留 #[ignore] 与原文档注释；`--ignored` 显式触发）。
// ============================================================================

/// T034: login 性能基线——P99 < 200ms，RPS >= 1000，error_rate < 0.1%。
///
/// `RemoteContext::setup()` 启动服务后，对 `/api/v1/auth/login` 发起
/// concurrency=100、duration=10s 的负载测试，断言 P99/RPS/error_rate
/// 满足基线，并将报告追加到 `logs/perf.jsonl`。
///
/// # 基线依据
/// login 涉及 token 生成（含哈希计算）+ DAO 写入，是相对昂贵的操作，
/// 基线 P99 < 200ms / RPS >= 1000（比 check-login 宽松 4x）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[ignore]
async fn perf_login_p99_under_200ms_1000rps() {
    use garrison::backend::types::LoginParams;
    let _guard = perf_util::setup_perf_env();
    let ctx = perf_util::RemoteContext::setup().await;
    let runner = perf_util::LoadRunner::new(
        ctx.plain_client(),
        format!("{}/api/v1/auth/login", ctx.external_url),
        reqwest::Method::POST,
        Some(serde_json::json!({
            "login_id": "perf_user",
            "params": LoginParams::default()
        })),
        100,
        std::time::Duration::from_secs(10),
    );
    let report = runner.run().await;
    let error_rate = if report.total > 0 {
        report.errors as f64 / report.total as f64
    } else {
        1.0
    };
    println!(
        "perf_login report: {:?}, error_rate={:.4}",
        report, error_rate
    );
    perf_util::append_perf_report(
        &report,
        "perf_login_p99_under_200ms_1000rps",
        "/api/v1/auth/login",
    );
    perf_util::assert_perf_baseline("P99", report.p99_ms, 200, "lt", "login");
    perf_util::assert_perf_baseline("RPS", report.rps, 1000, "ge", "login");
    assert!(
        error_rate < 0.001,
        "error_rate={:.4} 应 < 0.1%（login 性能基线）",
        error_rate
    );
}

/// T035: check-login 性能基线——P99 < 50ms，RPS >= 5000。
///
/// 先 login 获取有效 token，再对 `/api/v1/auth/check-login`（internal 端点）
/// 发起 concurrency=200、duration=10s 的负载测试，断言 P99/RPS 满足基线。
///
/// # 基线依据
/// check-login 仅做 token 查找 + DAO 读取（oxcache 内存层），延迟应 < 50ms，
/// RPS >= 5000（比 login 严格 5x）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[ignore]
async fn perf_check_login_p99_under_50ms_5000rps() {
    use garrison::backend::types::LoginParams;
    let _guard = perf_util::setup_perf_env();
    let ctx = perf_util::RemoteContext::setup().await;
    let client = ctx.plain_client();

    // 先 login 拿一个有效 token（性能测试期间复用同一 token）
    let resp = client
        .post(format!("{}/api/v1/auth/login", ctx.external_url))
        .json(&serde_json::json!({
            "login_id": "perf_check_login",
            "params": LoginParams::default()
        }))
        .send()
        .await
        .expect("login 失败");
    assert_eq!(resp.status(), 200, "login 应返回 200");
    let body: serde_json::Value = resp.json().await.expect("login 响应非 JSON");
    let token = body["data"]
        .as_str()
        .unwrap_or_else(|| panic!("login 响应 data 字段非字符串: {:?}", body))
        .to_string();

    let runner = perf_util::LoadRunner::new(
        client,
        format!("{}/api/v1/auth/check-login", ctx.internal_url),
        reqwest::Method::POST,
        Some(serde_json::json!({ "token": token })),
        200,
        std::time::Duration::from_secs(10),
    )
    .with_header("x-api-key", &ctx.api_key);

    let report = runner.run().await;
    let error_rate = if report.total > 0 {
        report.errors as f64 / report.total as f64
    } else {
        1.0
    };
    println!(
        "perf_check_login report: {:?}, error_rate={:.4}",
        report, error_rate
    );
    perf_util::append_perf_report(
        &report,
        "perf_check_login_p99_under_50ms_5000rps",
        "/api/v1/auth/check-login",
    );
    perf_util::assert_perf_baseline("P99", report.p99_ms, 50, "lt", "check-login");
    perf_util::assert_perf_baseline("RPS", report.rps, 5000, "ge", "check-login");
}

/// T036: check-permission 性能基线——P99 < 50ms，RPS >= 5000。
///
/// 先 login 获取有效 token，再对 `/api/v1/auth/check-permission`（internal 端点）
/// body 含 `{"token": ..., "permission": "read"}` 发起 concurrency=200、
/// duration=10s 的负载测试，断言 P99/RPS 满足基线。
///
/// # 基线依据
/// check-permission 与 check-login 走相似代码路径（token 查找 + 权限校验），
/// MockInterface / SimpleInterface 返回空权限列表会返回 `NOT_PERMISSION`
/// 错误码（业务层拒绝，但响应成功 200），不影响 RPS/P99 测量。
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[ignore]
async fn perf_check_permission_p99_under_50ms_5000rps() {
    use garrison::backend::types::LoginParams;
    let _guard = perf_util::setup_perf_env();
    let ctx = perf_util::RemoteContext::setup().await;
    let client = ctx.plain_client();

    // 先 login 拿一个有效 token（性能测试期间复用同一 token）
    let resp = client
        .post(format!("{}/api/v1/auth/login", ctx.external_url))
        .json(&serde_json::json!({
            "login_id": "perf_check_permission",
            "params": LoginParams::default()
        }))
        .send()
        .await
        .expect("login 失败");
    assert_eq!(resp.status(), 200, "login 应返回 200");
    let body: serde_json::Value = resp.json().await.expect("login 响应非 JSON");
    let token = body["data"]
        .as_str()
        .unwrap_or_else(|| panic!("login 响应 data 字段非字符串: {:?}", body))
        .to_string();

    let runner = perf_util::LoadRunner::new(
        client,
        format!("{}/api/v1/auth/check-permission", ctx.internal_url),
        reqwest::Method::POST,
        Some(serde_json::json!({
            "token": token,
            "permission": "read"
        })),
        200,
        std::time::Duration::from_secs(10),
    )
    .with_header("x-api-key", &ctx.api_key);

    let report = runner.run().await;
    let error_rate = if report.total > 0 {
        report.errors as f64 / report.total as f64
    } else {
        1.0
    };
    println!(
        "perf_check_permission report: {:?}, error_rate={:.4}",
        report, error_rate
    );
    perf_util::append_perf_report(
        &report,
        "perf_check_permission_p99_under_50ms_5000rps",
        "/api/v1/auth/check-permission",
    );
    perf_util::assert_perf_baseline("P99", report.p99_ms, 50, "lt", "check-permission");
    perf_util::assert_perf_baseline("RPS", report.rps, 5000, "ge", "check-permission");
}
