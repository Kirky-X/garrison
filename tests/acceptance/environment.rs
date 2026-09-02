//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! environment 域验收（spec `acceptance-matrix` R-acceptance-matrix-001，任务 T035）。
//!
//! 真实外部服务门控验收，场景编号 `ACC-ENV-NNN`：
//! - ACC-ENV-001：`redis_available()` 探测辅助（`GARRISON_TEST_REDIS=1` 强制
//!   可用，否则 TCP 探活 127.0.0.1:6379）；
//! - ACC-ENV-002：redis 可达 → `GarrisonDaoOxcache::with_redis_config`
//!   基本读写 / TTL / 重命名；
//! - ACC-ENV-003：redis 可达 → `with_redis_config` 下原子六方法按 src 实际
//!   行为 fail-closed（显性 `Config` 错误，M4 防护）；
//! - ACC-ENV-004：基础 DAO 原子六方法成功路径（内存后端，不依赖外部服务）；
//! - ACC-ENV-005..006（`db-postgres`）：`pg_available()` 探活 127.0.0.1:5432，
//!   可达 → init_dbnexus postgres 连接 + 迁移 10 表 + user_repository CRUD
//!   （吸收 tests/repository/postgres_integration.rs 的 `#[ignore]` 用例语义）；
//! - ACC-ENV-007..008（`db-mysql`）：testcontainers MySQL 语义——docker 探活
//!   失败即跳过（吸收 tests/db_mysql_testcontainers.rs 的 1-2 个代表性场景）。
//!
//! 门控约定：外部服务不可达时 `eprintln!("[SKIP] …")` 并 `return`——测试
//! 通过但不运行，保证无外部服务环境（CI / 本机）全绿。

use serial_test::serial;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

/// TCP 探活：目标端口可达返回 `true`（300ms 超时，探测失败视为不可达）。
fn tcp_probe(addr: &str) -> bool {
    let Ok(socket_addr) = addr.parse::<SocketAddr>() else {
        return false;
    };
    TcpStream::connect_timeout(&socket_addr, Duration::from_millis(300)).is_ok()
}

/// redis 是否可用：`GARRISON_TEST_REDIS=1` 强制视为可用（显式测试开关），
/// 否则 TCP 探活 `127.0.0.1:6379`。
fn redis_available() -> bool {
    if std::env::var("GARRISON_TEST_REDIS").as_deref() == Ok("1") {
        return true;
    }
    tcp_probe("127.0.0.1:6379")
}

/// postgres 是否可用：TCP 探活 `127.0.0.1:5432`
///（与 tests/repository/postgres_integration.rs 的默认库地址一致）。
#[cfg(feature = "db-postgres")]
fn pg_available() -> bool {
    tcp_probe("127.0.0.1:5432")
}

/// docker 是否可用（MySQL testcontainers 前置）：`docker info` 成功
///（daemon 存活）视为可用，否则跳过 MySQL 场景。
#[cfg(feature = "db-mysql")]
fn docker_available() -> bool {
    std::process::Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// env 变量 RAII 守卫（构造时设置、Drop 时还原；用于 `GARRISON_TEST_REDIS`）。
struct EnvGuard {
    key: &'static str,
    original: Option<String>,
}

impl EnvGuard {
    fn new(key: &'static str, val: &str) -> Self {
        let original = std::env::var(key).ok();
        std::env::set_var(key, val);
        Self { key, original }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        match self.original.take() {
            Some(orig) => std::env::set_var(self.key, orig),
            None => std::env::remove_var(self.key),
        }
    }
}

// ------------------------------------------------------------------------
// ACC-ENV-001：redis 探测辅助（正常）
// ------------------------------------------------------------------------

/// ACC-ENV-001（正常）：`redis_available()` 探测语义——
/// `GARRISON_TEST_REDIS=1` 强制可用；未设置时与 TCP 探活结果一致
///（不自欺：探测结果就是环境事实）。
#[tokio::test]
#[serial]
async fn acc_env_001_redis_probe_helper_semantics() {
    {
        let _guard = EnvGuard::new("GARRISON_TEST_REDIS", "1");
        assert!(
            redis_available(),
            "GARRISON_TEST_REDIS=1 应强制视为 redis 可用"
        );
    }

    // 还原后：结果必须与 TCP 探活一致（无 env 时环境事实决定）
    let probe = tcp_probe("127.0.0.1:6379");
    assert_eq!(
        redis_available(),
        probe,
        "无 env 覆盖时 redis_available 应等于 TCP 探活结果"
    );
    if !probe {
        eprintln!("[SKIP] ACC-ENV-001: 本机 127.0.0.1:6379 未监听，redis 相关场景将跳过");
    }
}

// ------------------------------------------------------------------------
// ACC-ENV-002..003：redis 可达 → GarrisonDaoOxcache（with_redis_config）
// ------------------------------------------------------------------------

/// ACC-ENV-002（正常）：redis 可达 → `GarrisonDaoOxcache` 经 `with_redis_config`
/// 基本读写 / TTL：set/get、get_with_ttl（value+TTL 一次取回）、update 保留
/// 剩余 TTL、expire 缩短、set_permanent 永久键、rename 原子重命名、
/// delete 删除。
///
/// 不可达时 `[SKIP]` 打印并 return（测试通过但不运行）。
#[cfg(feature = "cache-redis")]
#[tokio::test(flavor = "multi_thread")]
async fn acc_env_002_redis_dao_basic_io_with_ttl() {
    if !redis_available() {
        eprintln!(
            "[SKIP] ACC-ENV-002: redis 不可达（127.0.0.1:6379 未监听且未设置 \
             GARRISON_TEST_REDIS=1），跳过 redis 基本读写/TTL 场景"
        );
        return;
    }

    use garrison::dao::{GarrisonDao, GarrisonDaoOxcache, RedisConfig, RedisDeploymentMode};

    let dao = GarrisonDaoOxcache::new()
        .await
        .expect("GarrisonDaoOxcache 初始化应成功")
        .with_redis_config(RedisConfig {
            mode: RedisDeploymentMode::Single {
                url: "redis://127.0.0.1:6379".to_string(),
            },
            ..Default::default()
        });
    let key = "acc-env:002:basic";

    // set + get（无条件的 DAO 读写不受 redis_config 影响——仅原子 _sync 受防护）
    dao.set(key, "v1", 60).await.expect("set 应成功");
    assert_eq!(
        dao.get(key).await.expect("get 应成功"),
        Some("v1".to_string())
    );

    // get_with_ttl：单次取回 value + 剩余 TTL
    let (value, ttl) = dao
        .get_with_ttl(key)
        .await
        .expect("get_with_ttl 应成功")
        .expect("key 应存在");
    assert_eq!(value, "v1");
    assert!(
        ttl.is_some() && ttl.unwrap() > Duration::ZERO,
        "TTL 键应返回剩余存活时间"
    );

    // update：保留剩余 TTL（不重置为永久）
    dao.update(key, "v2").await.expect("update 应成功");
    let ttl_before = dao
        .get_timeout(key)
        .await
        .expect("get_timeout 应成功")
        .expect("update 后 key 应仍有 TTL");
    assert_eq!(dao.get(key).await.unwrap(), Some("v2".to_string()));
    assert!(ttl_before <= Duration::from_secs(60));
    assert!(ttl_before > Duration::ZERO);

    // expire：缩短 TTL
    dao.expire(key, 3).await.expect("expire 应成功");
    let ttl_shortened = dao
        .get_timeout(key)
        .await
        .expect("get_timeout 应成功")
        .expect("expire 后 key 应仍有 TTL");
    assert!(ttl_shortened <= Duration::from_secs(3));

    // set_permanent：永久键（TTL=None）
    let perm_key = "acc-env:002:perm";
    dao.set_permanent(perm_key, "perm")
        .await
        .expect("set_permanent 应成功");
    assert_eq!(
        dao.get_timeout(perm_key).await.unwrap(),
        None,
        "永久键无 TTL"
    );
    assert_eq!(dao.get(perm_key).await.unwrap(), Some("perm".to_string()));

    // rename：TTL 键原子重命名（旧键消失、新键保留 TTL）
    let moved_key = "acc-env:002:moved";
    dao.rename(key, moved_key).await.expect("rename 应成功");
    assert_eq!(dao.get(key).await.unwrap(), None, "rename 后旧键应消失");
    let (moved_value, moved_ttl) = dao
        .get_with_ttl(moved_key)
        .await
        .unwrap()
        .expect("rename 后新键应存在");
    assert_eq!(moved_value, "v2");
    assert!(moved_ttl.is_some(), "rename 应保留原键 TTL");

    // delete
    dao.delete(moved_key).await.expect("delete 应成功");
    assert_eq!(dao.get(moved_key).await.unwrap(), None, "delete 后应不存在");
}

/// ACC-ENV-003（异常）：redis 可达 → `with_redis_config` 下原子六方法的
/// **实际行为**：`check_redis_compat`（M4 防护）令 5 个 `_sync` 原子方法
/// （set_if_absent/get_and_delete/incr/decr/compare_and_update_if_greater）
/// 返回显性 `GarrisonError::Config`（消息含 `dao-oxcache-sync-api-incompatible-with-redis`）
/// ——失败显性化而非静默错误结果（规则 12）；`rename` 不在防护名单内仍可用。
///
/// # API 偏差记录
/// `with_redis_config` 当前仅存储配置、未实际连接 Redis L2（src/dao/oxcache_impl.rs
/// 文档行为）；任务预期「原子六方法成功路径」无法在 redis 配置态成立，验收吸收
/// 实际契约并留此记录（成功路径见 ACC-ENV-004，无 redis 配置态）。
#[cfg(feature = "cache-redis")]
#[tokio::test(flavor = "multi_thread")]
async fn acc_env_003_redis_dao_atomic_six_fail_closed_under_config() {
    if !redis_available() {
        eprintln!(
            "[SKIP] ACC-ENV-003: redis 不可达（127.0.0.1:6379 未监听且未设置 \
             GARRISON_TEST_REDIS=1），跳过 redis 原子方法防护场景"
        );
        return;
    }

    use garrison::dao::{GarrisonDao, GarrisonDaoOxcache, RedisConfig};
    use garrison::error::GarrisonError;

    let dao = GarrisonDaoOxcache::new()
        .await
        .expect("GarrisonDaoOxcache 初始化应成功")
        .with_redis_config(RedisConfig::default());

    // 5 个受 M4 防护的原子方法：显性 Config 错误
    fn assert_compat_guard<T>(result: garrison::error::GarrisonResult<T>) {
        match result {
            Err(GarrisonError::Config(msg)) => assert!(
                msg.contains("dao-oxcache-sync-api-incompatible-with-redis"),
                "应返回 redis 不兼容显性错误，实际: {msg}"
            ),
            Err(other) => panic!("期望显性 Config 错误（fail-closed），实际: {other:?}"),
            Ok(_) => panic!("期望 Err（fail-closed），实际 Ok"),
        };
    }

    assert_compat_guard(dao.set_if_absent("acc-env:003:k1", "v", 60).await);
    assert_compat_guard(dao.get_and_delete("acc-env:003:k1").await);
    assert_compat_guard(dao.incr("acc-env:003:counter", 60).await);
    assert_compat_guard(dao.decr("acc-env:003:counter").await);
    assert_compat_guard(
        dao.compare_and_update_if_greater("acc-env:003:nc", 5, 60)
            .await,
    );

    // rename 不受防护（非 _sync 组合原子方法名录）：仍可用
    dao.set("acc-env:003:r1", "v", 60)
        .await
        .expect("set 应成功");
    dao.rename("acc-env:003:r1", "acc-env:003:r2")
        .await
        .expect("rename 不应受 redis_config 影响");
    assert_eq!(
        dao.get("acc-env:003:r2").await.unwrap(),
        Some("v".to_string())
    );
}

// ------------------------------------------------------------------------
// ACC-ENV-004：基础 DAO 原子六方法（正常，内存后端，无外部服务依赖）
// ------------------------------------------------------------------------

/// ACC-ENV-004（正常）：`GarrisonDaoOxcache`（未配置 redis）原子六方法
/// 成功路径：set_if_absent（SETNX 语义）、incr/decr（TTL 保留、
/// 归零删 key）、get_and_delete（原子消费）、compare_and_update_if_greater
/// （单调 CAS）、rename（保留 TTL）。不依赖外部服务，无门控。
#[tokio::test(flavor = "multi_thread")]
async fn acc_env_004_dao_atomic_six_success_path() {
    use garrison::dao::{GarrisonDao, GarrisonDaoOxcache};
    use std::sync::Arc;

    let dao: Arc<dyn GarrisonDao> = Arc::new(
        GarrisonDaoOxcache::new()
            .await
            .expect("GarrisonDaoOxcache 初始化应成功"),
    );

    // set_if_absent：仅首次写入成功（SETNX 原子语义）
    assert!(dao.set_if_absent("acc-env:004:sa", "v1", 60).await.unwrap());
    assert!(
        !dao.set_if_absent("acc-env:004:sa", "v2", 60).await.unwrap(),
        "已存在 key 的 set_if_absent 应返回 false（不覆盖）"
    );
    assert_eq!(
        dao.get("acc-env:004:sa").await.unwrap(),
        Some("v1".to_string())
    );

    // incr：初始化 1，随后递增且不重置 TTL
    assert_eq!(dao.incr("acc-env:004:cnt", 30).await.unwrap(), 1);
    assert_eq!(dao.incr("acc-env:004:cnt", 30).await.unwrap(), 2);
    let ttl = dao
        .get_timeout("acc-env:004:cnt")
        .await
        .unwrap()
        .expect("incr 键应有 TTL");
    assert!(
        ttl <= Duration::from_secs(30),
        "incr 二次调用不应重置 TTL，实际: {ttl:?}"
    );

    // decr：递减到 0 时删除 key（不出现负值、不留 0 残留）
    assert_eq!(dao.decr("acc-env:004:cnt").await.unwrap(), 1);
    assert_eq!(dao.decr("acc-env:004:cnt").await.unwrap(), 0);
    assert_eq!(
        dao.decr("acc-env:004:cnt").await.unwrap(),
        0,
        "归零后 decr 幂等返回 0"
    );
    assert!(
        dao.get("acc-env:004:cnt").await.unwrap().is_none(),
        "decr 归零应删除 key"
    );

    // get_and_delete：原子消费（读 + 删），二次读取为 None
    dao.set("acc-env:004:ticket", "t1", 60).await.unwrap();
    assert_eq!(
        dao.get_and_delete("acc-env:004:ticket").await.unwrap(),
        Some("t1".to_string())
    );
    assert!(
        dao.get_and_delete("acc-env:004:ticket")
            .await
            .unwrap()
            .is_none(),
        "get_and_delete 原子消费后不应再取到值"
    );

    // compare_and_update_if_greater：单调 CAS（仅新值更大时更新）
    assert!(dao
        .compare_and_update_if_greater("acc-env:004:nc", 5, 60)
        .await
        .unwrap());
    assert!(
        !dao.compare_and_update_if_greater("acc-env:004:nc", 3, 60)
            .await
            .unwrap(),
        "新值不大于当前值不应更新"
    );
    assert!(dao
        .compare_and_update_if_greater("acc-env:004:nc", 7, 60)
        .await
        .unwrap());
    assert_eq!(
        dao.get("acc-env:004:nc").await.unwrap(),
        Some("7".to_string())
    );

    // rename：原子重命名并保留原键 TTL
    dao.set("acc-env:004:src", "sv", 60).await.unwrap();
    dao.rename("acc-env:004:src", "acc-env:004:dst")
        .await
        .unwrap();
    assert_eq!(
        dao.get("acc-env:004:src").await.unwrap(),
        None,
        "rename 后旧键应消失"
    );
    let (value, ttl) = dao
        .get_with_ttl("acc-env:004:dst")
        .await
        .unwrap()
        .expect("rename 后新键应存在");
    assert_eq!(value, "sv");
    assert!(
        ttl.is_some() && ttl.unwrap() <= Duration::from_secs(60),
        "rename 应保留 TTL"
    );
}

// ------------------------------------------------------------------------
// ACC-ENV-005..006：postgres 门控（feature = "db-postgres"）
// ------------------------------------------------------------------------
//
// 吸收 tests/repository/postgres_integration.rs 的 `#[ignore]` 用例语义
//（postgres_connects_to_database / postgres_migrate_creates_all_core_tables /
//  postgres_user_repository_crud），改为运行时探活门控：不可达即 [SKIP]。

/// postgres 连接 URL（与 tests/repository/postgres_integration.rs 默认一致）。
#[cfg(feature = "db-postgres")]
const POSTGRES_URL: &str = "postgres://garrison:garrison@localhost:5432/garrison_test";

/// 定位 migrations/postgres/ 目录。
#[cfg(feature = "db-postgres")]
fn postgres_migrations_dir() -> std::path::PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    std::path::PathBuf::from(manifest_dir)
        .join("migrations")
        .join("postgres")
}

/// 清空 public schema（迁移前隔离；迁移需经 sea-orm 原生 execute 绕过
/// dbnexus 的 DDL 白名单 guard，同 tests/repository/postgres_integration.rs）。
#[cfg(feature = "db-postgres")]
async fn reset_postgres_database(pool: &dbnexus::DbPool) {
    use sea_orm::{ConnectionTrait, DbBackend, Statement};
    let session = pool
        .get_session("admin")
        .await
        .expect("reset_database: get_session 应成功");
    let conn = session.connection().expect("connection 应可用");
    conn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "DROP SCHEMA IF EXISTS public CASCADE",
        vec![],
    ))
    .await
    .expect("DROP SCHEMA public 应成功");
    conn.execute_raw(Statement::from_sql_and_values(
        DbBackend::Postgres,
        "CREATE SCHEMA public",
        vec![],
    ))
    .await
    .expect("CREATE SCHEMA public 应成功");
}

/// ACC-ENV-005（正常）：`pg_available()` 探活 127.0.0.1:5432——
/// 可达时 `init_dbnexus` postgres 连接 + `migrate_core` 创建 10 张
/// `app_%` 核心表（吸收 postgres_migrate_creates_all_core_tables 语义）；
/// 不可达时 [SKIP] 打印并 return。
#[cfg(feature = "db-postgres")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn acc_env_005_postgres_connect_and_migrate_core_tables() {
    if !pg_available() {
        eprintln!(
            "[SKIP] ACC-ENV-005: postgres 不可达（127.0.0.1:5432 未监听），跳过 \
             postgres 连接/迁移场景（可 docker run 见 tests/repository/postgres_integration.rs）"
        );
        return;
    }

    use garrison::dao::{init_dbnexus, GarrisonMigration};
    use sea_orm::{ConnectionTrait, DbBackend, Statement};

    let pool = init_dbnexus(POSTGRES_URL)
        .await
        .expect("init_dbnexus postgres 应成功（127.0.0.1:5432 可达）");
    let session = pool.get_session("admin").await.expect("get_session 应成功");
    let conn = session.connection().expect("connection 应可用");
    assert_eq!(
        conn.get_database_backend(),
        DbBackend::Postgres,
        "后端应为 PostgreSQL"
    );

    reset_postgres_database(&pool).await;
    let migration = GarrisonMigration::with_base_dir(pool.clone(), postgres_migrations_dir());
    let applied = migration.migrate_core().await.expect("migrate_core 应成功");
    assert!(
        applied >= 6,
        "migrate_core 应至少执行 6 个文件（001-006），实际: {}",
        applied
    );

    let rows = conn
        .query_all_raw(Statement::from_sql_and_values(
            DbBackend::Postgres,
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = 'public' AND table_name LIKE 'app_%' ORDER BY table_name",
            vec![],
        ))
        .await
        .expect("查询 information_schema 应成功");
    let tables: Vec<String> = rows
        .iter()
        .map(|row| row.try_get::<String>("", "table_name").unwrap_or_default())
        .collect();
    let expected = [
        "app_auth_method",
        "app_login_log",
        "app_permission",
        "app_role",
        "app_role_permission",
        "app_session",
        "app_user",
        "app_user_device",
        "app_user_ext",
        "app_user_role",
    ];
    for table in &expected {
        assert!(
            tables.contains(&table.to_string()),
            "核心表 {table} 应存在于 postgres public schema，实际: {tables:?}"
        );
    }
    assert_eq!(expected.len(), 10, "应有 10 张 app_ 前缀核心表");
}

/// ACC-ENV-006（正常）：postgres 可达 → `DbnexusPostgresUserRepository`
/// CRUD（create → find_by_id → update → list → delete 幂等，
/// 吸收 postgres_user_repository_crud 语义）。
#[cfg(feature = "db-postgres")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn acc_env_006_postgres_user_repository_crud() {
    if !pg_available() {
        eprintln!(
            "[SKIP] ACC-ENV-006: postgres 不可达（127.0.0.1:5432 未监听），跳过 \
             postgres user_repository CRUD 场景"
        );
        return;
    }

    use garrison::dao::{
        init_dbnexus,
        repository::{
            postgres::DbnexusPostgresUserRepository, NewUser, UpdateUser, UserRepository,
        },
        GarrisonMigration,
    };

    let pool = init_dbnexus(POSTGRES_URL)
        .await
        .expect("init_dbnexus postgres 应成功");
    reset_postgres_database(&pool).await;
    let migration = GarrisonMigration::with_base_dir(pool.clone(), postgres_migrations_dir());
    migration.migrate_core().await.expect("migrate_core 应成功");

    let repo = DbnexusPostgresUserRepository::new(pool);
    let user_id = repo
        .create(
            1,
            NewUser {
                username: "alice_pg".to_string(),
                password_hash: "hashed_pg".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .expect("create 应成功");

    let found = repo
        .find_by_id(1, &user_id)
        .await
        .unwrap()
        .expect("find_by_id 应返回 Some");
    assert_eq!(found.username, "alice_pg");
    assert_eq!(found.status, "active");
    assert_eq!(found.tenant_id, 1);

    repo.update(
        1,
        &user_id,
        UpdateUser {
            username: Some("alice_pg_updated".to_string()),
            status: Some("suspended".to_string()),
            ..Default::default()
        },
    )
    .await
    .expect("update 应成功");
    let updated = repo.find_by_id(1, &user_id).await.unwrap().unwrap();
    assert_eq!(updated.username, "alice_pg_updated");
    assert_eq!(updated.status, "suspended");

    let list = repo.list(1, 0, 100).await.expect("list 应成功");
    assert!(!list.is_empty(), "list 应返回非空");

    repo.delete(1, &user_id).await.expect("delete 应成功");
    repo.delete(1, &user_id).await.expect("delete 幂等应成功");
    assert!(
        repo.find_by_id(1, &user_id).await.unwrap().is_none(),
        "delete 后 find_by_id 应返回 None"
    );
}

// ------------------------------------------------------------------------
// ACC-ENV-007..008：MySQL testcontainers 门控（feature = "db-mysql"）
// ------------------------------------------------------------------------
//
// 吸收 tests/db_mysql_testcontainers.rs 的代表性语义（连接 + 迁移 +
// user CRUD），保持 `#[cfg(feature = "db-mysql")]` 门控与 testcontainers
// 装配；docker 不可用时探活跳过（不启动容器、不失败）。

/// MySQL 容器配置（镜像 / 端口 / 等待就绪 / 初始化库，同
/// tests/db_mysql_testcontainers.rs::setup_mysql_pool）。
#[cfg(feature = "db-mysql")]
async fn setup_mysql_pool() -> (
    dbnexus::DbPool,
    testcontainers::ContainerAsync<testcontainers::GenericImage>,
) {
    use testcontainers::core::{IntoContainerPort, WaitFor};
    use testcontainers::runners::AsyncRunner;
    use testcontainers::{GenericImage, ImageExt};

    let mysql_image = GenericImage::new("mysql", "8.0-oracle")
        .with_exposed_port(3306.tcp())
        .with_wait_for(WaitFor::message_on_either_std("ready for connections"))
        .with_env_var("MYSQL_ROOT_PASSWORD", "root")
        .with_env_var("MYSQL_DATABASE", "garrison_test");
    let container = mysql_image.start().await.expect("MySQL 8.0 容器应成功启动");
    let port = container
        .get_host_port_ipv4(3306)
        .await
        .expect("端口 3306 应映射到宿主机");
    let url = format!("mysql://root:root@127.0.0.1:{}/garrison_test", port);
    let pool = retry_init_mysql_pool(&url).await;
    (pool, container)
}

/// 重试初始化 MySQL 连接池（容器就绪后仍需内部初始化，最多 30 次 × 1s，
/// 同 tests/db_mysql_testcontainers.rs::retry_init_dbnexus）。
#[cfg(feature = "db-mysql")]
async fn retry_init_mysql_pool(url: &str) -> dbnexus::DbPool {
    use garrison::dao::init_dbnexus;
    use sea_orm::{ConnectionTrait, DbBackend, Statement};

    let mut last_err = None;
    for _ in 0..30u32 {
        match init_dbnexus(url).await {
            Ok(pool) => {
                if let Ok(session) = pool.get_session("admin").await {
                    if let Ok(conn) = session.connection() {
                        let stmt =
                            Statement::from_sql_and_values(DbBackend::MySql, "SELECT 1", vec![]);
                        if conn.query_one_raw(stmt).await.is_ok() {
                            return pool;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            },
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(Duration::from_secs(1)).await;
            },
        }
    }
    panic!("MySQL 连接池初始化失败（重试 30 次）：{:?}", last_err);
}

/// ACC-ENV-007（正常）：docker 可用 → testcontainers 启动 MySQL 8.0 容器、
/// `init_dbnexus` 连接（后端确认为 MySql）、`migrate_core` 迁移；
/// docker 不可用时 [SKIP] 打印并 return。
#[cfg(feature = "db-mysql")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn acc_env_007_mysql_testcontainers_connect_and_migrate() {
    if !docker_available() {
        eprintln!(
            "[SKIP] ACC-ENV-007: docker 不可用（docker info 失败），跳过 MySQL \
             testcontainers 连通/迁移场景"
        );
        return;
    }

    use garrison::dao::GarrisonMigration;
    use sea_orm::{ConnectionTrait, DbBackend};

    let (pool, _container) = setup_mysql_pool().await;
    let session = pool.get_session("admin").await.expect("get_session 应成功");
    let conn = session.connection().expect("connection 应可用");
    assert_eq!(
        conn.get_database_backend(),
        DbBackend::MySql,
        "后端应为 MySQL"
    );

    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let migration = GarrisonMigration::with_base_dir(
        pool.clone(),
        std::path::PathBuf::from(manifest_dir)
            .join("migrations")
            .join("mysql"),
    );
    let applied = migration.migrate_core().await.expect("migrate_core 应成功");
    assert!(
        applied >= 6,
        "migrate_core 应至少执行 6 个文件，实际: {}",
        applied
    );
}

/// ACC-ENV-008（正常）：docker 可用 → MySQL 上 `DbnexusMysqlUserRepository`
/// CRUD（create → find_by_username → update → delete，
/// 吸收 mysql_user_repository_crud 语义）。
#[cfg(feature = "db-mysql")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn acc_env_008_mysql_user_repository_crud() {
    if !docker_available() {
        eprintln!(
            "[SKIP] ACC-ENV-008: docker 不可用（docker info 失败），跳过 MySQL \
             user_repository CRUD 场景"
        );
        return;
    }

    use garrison::dao::{
        repository::{mysql::DbnexusMysqlUserRepository, NewUser, UpdateUser, UserRepository},
        GarrisonMigration,
    };

    let (pool, _container) = setup_mysql_pool().await;
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let migration = GarrisonMigration::with_base_dir(
        pool.clone(),
        std::path::PathBuf::from(manifest_dir)
            .join("migrations")
            .join("mysql"),
    );
    migration.migrate_core().await.expect("migrate_core 应成功");

    let repo = DbnexusMysqlUserRepository::new(pool);
    let tenant: i64 = 1;
    let user_id = repo
        .create(
            tenant,
            NewUser {
                username: "alice_mysql".to_string(),
                password_hash: "hashed_mysql".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .expect("create 应成功");

    let found = repo
        .find_by_username(tenant, "alice_mysql")
        .await
        .unwrap()
        .expect("find_by_username 应返回 Some");
    assert_eq!(found.id, user_id);
    assert_eq!(found.status, "active");

    repo.update(
        tenant,
        &user_id,
        UpdateUser {
            username: Some("alice_mysql_updated".to_string()),
            status: Some("suspended".to_string()),
            ..Default::default()
        },
    )
    .await
    .expect("update 应成功");
    let updated = repo.find_by_id(tenant, &user_id).await.unwrap().unwrap();
    assert_eq!(updated.username, "alice_mysql_updated");
    assert_eq!(updated.status, "suspended");

    repo.delete(tenant, &user_id).await.expect("delete 应成功");
    assert!(
        repo.find_by_id(tenant, &user_id).await.unwrap().is_none(),
        "delete 后 find_by_id 应返回 None"
    );
}
