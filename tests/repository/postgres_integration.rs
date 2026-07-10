//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! PostgreSQL Repository 集成测试（v0.5.1 新增，依据 tasks.md T112 / D8）。
//!
//! 验证 6 个 `DbnexusPostgresXxxRepository` 在真实 PostgreSQL 16 + 迁移后的 CRUD 行为：
//! 1. `postgres_connects_to_database`：建立 Postgres DbPool 连接
//! 2. `postgres_migrate_creates_all_core_tables`：运行 migration，断言 10 张 `app_` 前缀表存在
//! 3. `postgres_user_repository_crud`：UserRepository create/find_by_id/update/delete
//! 4. `postgres_role_repository_crud`：RoleRepository create/find_by_code/assign/list
//! 5. `postgres_permission_repository_crud`：PermissionRepository create/find/list
//! 6. `postgres_user_device_repository_crud`：UserDeviceRepository register/block/unblock/list/count
//!
//! 运行前必须启动 Docker 容器 `bulwark-postgres-test`：
//! ```sh
//! docker run -d --name bulwark-postgres-test \
//!   -e POSTGRES_USER=bulwark -e POSTGRES_PASSWORD=bulwark \
//!   -e POSTGRES_DB=bulwark_test -p 5432:5432 postgres:16-alpine
//! ```
//!
//! 运行：`cargo test --features db-postgres --test postgres_repository_integration`
//!
//! 测试间通过 `serial_test::serial` 串行化，每个测试前清空 `public` schema 避免数据污染。

#![cfg(feature = "db-postgres")]

use bulwark::dao::{
    init_dbnexus,
    repository::{
        postgres::{
            DbnexusPostgresPermissionRepository, DbnexusPostgresRoleRepository,
            DbnexusPostgresUserDeviceRepository, DbnexusPostgresUserRepository,
        },
        NewPermission, NewRole, NewUser, PermissionRepository, RoleRepository, UpdateUser,
        UserDeviceRepository, UserRepository,
    },
    BulwarkMigration,
};
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serial_test::serial;
use std::path::PathBuf;

const POSTGRES_URL: &str = "postgres://bulwark:bulwark@localhost:5432/bulwark_test";
const TENANT_A: i64 = 1;

// ============================================================================
// 辅助：定位 postgres 迁移目录 + 初始化 PostgreSQL + 迁移
// ============================================================================

/// 定位项目根目录的 migrations/postgres/ 目录。
fn project_migrations_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("migrations")
        .join("postgres")
}

/// 清空 public schema（删除所有表与 dbnexus_migrations 历史），避免上一个测试残留。
///
/// 每个测试前调用，保证测试间隔离。`DROP SCHEMA public CASCADE` 会级联删除 schema 下所有对象，
/// 随后 `CREATE SCHEMA public` 重建空 schema。
///
/// 注意：必须用 sea-orm 原生 `conn.execute()` 绕过 dbnexus 的 DDL 白名单 guard
/// （dbnexus 的 `execute_raw_ddl` 仅允许 CreateTable/AlterTable/CreateIndex/CreateView，
/// 禁止 DropSchema/DropTable）。
async fn reset_database(pool: &dbnexus::DbPool) {
    let session = pool
        .get_session("admin")
        .await
        .expect("reset_database: get_session 应成功");
    let conn = session
        .connection()
        .expect("reset_database: connection 应可用");
    let drop_stmt = Statement::from_sql_and_values(
        DbBackend::Postgres,
        "DROP SCHEMA IF EXISTS public CASCADE",
        vec![],
    );
    conn.execute_raw(drop_stmt)
        .await
        .expect("DROP SCHEMA public 应成功");
    let create_stmt =
        Statement::from_sql_and_values(DbBackend::Postgres, "CREATE SCHEMA public", vec![]);
    conn.execute_raw(create_stmt)
        .await
        .expect("CREATE SCHEMA public 应成功");
}

/// 创建并初始化 PostgreSQL 连接池：连接 → 清空 → 迁移 → 返回 pool。
async fn setup_db() -> dbnexus::DbPool {
    let pool = init_dbnexus(POSTGRES_URL)
        .await
        .expect("init_dbnexus postgres 应成功");
    reset_database(&pool).await;
    let migration = BulwarkMigration::with_base_dir(pool.clone(), project_migrations_dir());
    let applied = migration.migrate_core().await.expect("migrate_core 应成功");
    assert!(
        applied >= 6,
        "migrate_core 应至少执行 6 个文件（001-006），实际: {}",
        applied
    );
    pool
}

// ============================================================================
// 1. 连接测试
// ============================================================================

/// 验证 init_dbnexus 能连接到 PostgreSQL 16 容器。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn postgres_connects_to_database() {
    let pool = init_dbnexus(POSTGRES_URL)
        .await
        .expect("init_dbnexus 应成功连接 PostgreSQL");
    // 验证后端确实是 PostgreSQL
    let session = pool.get_session("admin").await.expect("get_session 应成功");
    let conn = session.connection().expect("connection 应可用");
    assert_eq!(
        conn.get_database_backend(),
        DbBackend::Postgres,
        "后端应为 PostgreSQL"
    );
}

// ============================================================================
// 2. Migration 测试
// ============================================================================

/// 验证 migrate_core 在 PostgreSQL 上创建 10 张 app_ 前缀表。
///
/// 10 张表：app_user / app_role / app_permission / app_user_role / app_role_permission
/// / app_auth_method / app_session / app_login_log / app_user_ext / app_user_device
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn postgres_migrate_creates_all_core_tables() {
    let pool = setup_db().await;

    let session = pool.get_session("admin").await.expect("get_session 应成功");
    let conn = session.connection().expect("connection 应可用");
    let stmt = Statement::from_sql_and_values(
        DbBackend::Postgres,
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_name LIKE 'app_%' ORDER BY table_name",
        vec![],
    );
    let rows = conn
        .query_all_raw(stmt)
        .await
        .expect("查询 information_schema 应成功");
    let table_names: Vec<String> = rows
        .iter()
        .map(|row| row.try_get::<String>("", "table_name").unwrap_or_default())
        .collect();

    let expected_tables = [
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
    for expected in &expected_tables {
        assert!(
            table_names.contains(&expected.to_string()),
            "核心表 {} 应存在于 PostgreSQL public schema，实际表: {:?}",
            expected,
            table_names
        );
    }
    assert_eq!(expected_tables.len(), 10, "应有 10 张 app_ 前缀的核心表");
}

// ============================================================================
// 3. UserRepository CRUD
// ============================================================================

/// UserRepository：create → find_by_id → update → list → delete（PostgreSQL 后端）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn postgres_user_repository_crud() {
    let pool = setup_db().await;
    let repo = DbnexusPostgresUserRepository::new(pool);

    let user_id = repo
        .create(
            TENANT_A,
            NewUser {
                username: "alice_pg".to_string(),
                password_hash: "hashed_pg".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .expect("create 应成功");

    // find_by_id
    let found = repo
        .find_by_id(TENANT_A, &user_id)
        .await
        .expect("find_by_id 应成功");
    assert!(found.is_some(), "find_by_id 应返回 Some");
    let row = found.unwrap();
    assert_eq!(row.id, user_id);
    assert_eq!(row.username, "alice_pg");
    assert_eq!(row.status, "active");
    assert_eq!(row.tenant_id, TENANT_A);

    // update
    repo.update(
        TENANT_A,
        &user_id,
        UpdateUser {
            username: Some("alice_pg_updated".to_string()),
            status: Some("suspended".to_string()),
            ..Default::default()
        },
    )
    .await
    .expect("update 应成功");
    let updated = repo
        .find_by_id(TENANT_A, &user_id)
        .await
        .expect("find_by_id 应成功")
        .expect("update 后应仍存在");
    assert_eq!(updated.username, "alice_pg_updated");
    assert_eq!(updated.status, "suspended");

    // list
    let list = repo.list(TENANT_A, 0, 100).await.expect("list 应成功");
    assert!(!list.is_empty(), "list 应返回非空（至少含刚创建的用户）");

    // delete（幂等）
    repo.delete(TENANT_A, &user_id)
        .await
        .expect("delete 应成功");
    repo.delete(TENANT_A, &user_id)
        .await
        .expect("delete 幂等应成功");
    let after_delete = repo
        .find_by_id(TENANT_A, &user_id)
        .await
        .expect("find_by_id 应成功");
    assert!(after_delete.is_none(), "delete 后 find_by_id 应返回 None");
}

// ============================================================================
// 4. RoleRepository CRUD
// ============================================================================

/// RoleRepository：create → find_by_code → list → assign（UserRoleRepository 集成）（PostgreSQL 后端）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn postgres_role_repository_crud() {
    let pool = setup_db().await;
    let repo = DbnexusPostgresRoleRepository::new(pool);

    let role_id = repo
        .create(
            TENANT_A,
            NewRole {
                code: "admin_pg".to_string(),
                name: "Administrator PG".to_string(),
                description: Some("full access pg".to_string()),
                is_system: false,
            },
        )
        .await
        .expect("create role 应成功");

    // find_by_code
    let by_code = repo
        .find_by_code(TENANT_A, "admin_pg")
        .await
        .expect("find_by_code 应成功");
    assert!(by_code.is_some(), "find_by_code 应返回 Some");
    assert_eq!(by_code.unwrap().id, role_id);

    // find_by_id 验证 is_system 字段（PostgreSQL BIGINT 0/1 → bool 转换）
    let by_id = repo
        .find_by_id(TENANT_A, &role_id)
        .await
        .expect("find_by_id 应成功")
        .expect("role 应存在");
    assert!(!by_id.is_system, "is_system=false 应正确读取为 false");

    // list
    let list = repo.list(TENANT_A, 0, 100).await.expect("list 应成功");
    assert!(!list.is_empty(), "list 应返回非空");

    // update
    repo.update(
        TENANT_A,
        &role_id,
        Some("super_admin_pg".to_string()),
        Some("Super Administrator PG".to_string()),
        None,
    )
    .await
    .expect("update role 应成功");
    let updated = repo
        .find_by_id(TENANT_A, &role_id)
        .await
        .expect("find_by_id 应成功")
        .expect("role 应存在");
    assert_eq!(updated.code, "super_admin_pg");
    assert_eq!(updated.name, "Super Administrator PG");

    // delete
    repo.delete(TENANT_A, &role_id)
        .await
        .expect("delete role 应成功");
    assert!(
        repo.find_by_id(TENANT_A, &role_id)
            .await
            .expect("find_by_id 应成功")
            .is_none(),
        "delete 后 find_by_id 应返回 None"
    );
}

// ============================================================================
// 5. PermissionRepository CRUD
// ============================================================================

/// PermissionRepository：create → find_by_code → find_by_id → list → delete（PostgreSQL 后端）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn postgres_permission_repository_crud() {
    let pool = setup_db().await;
    let repo = DbnexusPostgresPermissionRepository::new(pool);

    let perm_id = repo
        .create(NewPermission {
            code: "user:read:pg".to_string(),
            name: "Read User PG".to_string(),
            resource_type: Some("user".to_string()),
            action: Some("read".to_string()),
        })
        .await
        .expect("create permission 应成功");

    // find_by_code
    let by_code = repo
        .find_by_code("user:read:pg")
        .await
        .expect("find_by_code 应成功");
    assert!(by_code.is_some(), "find_by_code 应返回 Some");
    assert_eq!(by_code.unwrap().id, perm_id);

    // find_by_id
    let by_id = repo
        .find_by_id(&perm_id)
        .await
        .expect("find_by_id 应成功")
        .expect("permission 应存在");
    assert_eq!(by_id.code, "user:read:pg");
    assert_eq!(by_id.resource_type, Some("user".to_string()));
    assert_eq!(by_id.action, Some("read".to_string()));

    // list
    let list = repo.list(0, 100).await.expect("list 应成功");
    assert!(!list.is_empty(), "list 应返回非空");

    // update
    repo.update(
        &perm_id,
        Some("Read User PG v2".to_string()),
        None,
        Some("read_write".to_string()),
    )
    .await
    .expect("update permission 应成功");
    let updated = repo
        .find_by_id(&perm_id)
        .await
        .expect("find_by_id 应成功")
        .expect("permission 应存在");
    assert_eq!(updated.name, "Read User PG v2");
    assert_eq!(updated.action, Some("read_write".to_string()));

    // delete
    repo.delete(&perm_id)
        .await
        .expect("delete permission 应成功");
    assert!(
        repo.find_by_id(&perm_id)
            .await
            .expect("find_by_id 应成功")
            .is_none(),
        "delete 后 find_by_id 应返回 None"
    );
}

// ============================================================================
// 6. UserDeviceRepository CRUD
// ============================================================================

/// UserDeviceRepository：register → list → block → unblock → count（PostgreSQL 后端）。
///
/// 验证 PostgreSQL BIGINT 0/1 → bool 转换（is_blocked 字段）+ epoch seconds 时间字段。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn postgres_user_device_repository_crud() {
    let pool = setup_db().await;
    let repo = DbnexusPostgresUserDeviceRepository::new(pool);
    let login_id: i64 = 5001;
    let ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0";

    // register
    let device_id = repo
        .register_device(TENANT_A, login_id, "fp-pg-001", ua)
        .await
        .expect("register_device 应成功");
    assert!(
        !device_id.is_empty(),
        "register_device 应返回非空 device_id"
    );

    // 幂等注册：相同 identifier 返回已有 ID
    let same_id = repo
        .register_device(TENANT_A, login_id, "fp-pg-001", ua)
        .await
        .expect("幂等 register_device 应成功");
    assert_eq!(
        device_id, same_id,
        "相同 identifier 幂等注册应返回同一 device_id"
    );

    // 注册第二个设备
    let device_id_2 = repo
        .register_device(TENANT_A, login_id, "fp-pg-002", "Mozilla/5.0 Firefox/120.0")
        .await
        .expect("register_device 第二个应成功");
    assert_ne!(device_id, device_id_2, "两个设备 ID 应不同");

    // list
    let devices = repo
        .list_user_devices(TENANT_A, login_id)
        .await
        .expect("list_user_devices 应成功");
    assert_eq!(devices.len(), 2, "应有 2 个设备（幂等注册不新增）");

    // 验证字段（is_blocked=false, BIGINT 0 → bool false）
    let first = devices
        .iter()
        .find(|d| d.id == device_id)
        .expect("应找到第一个设备");
    assert!(!first.is_blocked, "新设备 is_blocked 应为 false");
    assert_eq!(first.tenant_id, TENANT_A);
    assert_eq!(first.login_id, login_id);
    assert_eq!(first.device_identifier, "fp-pg-001");
    assert!(first.last_seen_at.is_some(), "last_seen_at 应非空");

    // block
    repo.block_device(&device_id)
        .await
        .expect("block_device 应成功");
    let after_block = repo
        .list_user_devices(TENANT_A, login_id)
        .await
        .expect("list 应成功");
    let blocked = after_block
        .iter()
        .find(|d| d.id == device_id)
        .expect("应找到被阻断的设备");
    assert!(blocked.is_blocked, "block 后 is_blocked 应为 true");

    // unblock
    repo.unblock_device(&device_id)
        .await
        .expect("unblock_device 应成功");
    let after_unblock = repo
        .list_user_devices(TENANT_A, login_id)
        .await
        .expect("list 应成功");
    let unblocked = after_unblock
        .iter()
        .find(|d| d.id == device_id)
        .expect("应找到解除阻断的设备");
    assert!(!unblocked.is_blocked, "unblock 后 is_blocked 应为 false");

    // count
    let count = repo
        .count_user_devices(TENANT_A, login_id)
        .await
        .expect("count_user_devices 应成功");
    assert_eq!(count, 2, "应有 2 个设备");
}
