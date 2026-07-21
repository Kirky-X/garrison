//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! MySQL Repository 集成测试（v0.5.3 新增，依据 tasks.md T028-T043 + T076）。
//!
//! 使用 testcontainers 自动启动 MySQL 8.0 Docker 容器，验证 10 个
//! `DbnexusMysqlXxxRepository` 在真实 MySQL 上的 CRUD 行为：
//!
//! 1. `mysql_dbpool_init`：验证 `init_dbnexus` 能初始化 MySQL 连接池
//! 2. `mysql_auto_migrate`：验证 `GarrisonMigration::migrate_core()` 创建全部核心表
//! 3. `mysql_user_repository_crud`：UserRepository create/find_by_username/update/delete
//! 4. `mysql_role_repository_crud`：RoleRepository create/find_by_code/list/delete
//! 5. `mysql_permission_repository_crud`：PermissionRepository create/find_by_code/list/delete
//! 6. `mysql_user_role_repository`：UserRoleRepository assign/revoke/find_by_user_id
//! 7. `mysql_role_permission_repository`：RolePermissionRepository assign/revoke/find_by_role_id
//! 8. `mysql_auth_method_repository`：AuthMethodRepository create/find_by_user_id/delete
//! 9. `mysql_session_repository`：SessionRepository create/find_by_session_id/delete
//! 10. `mysql_login_log_repository`：LoginLogRepository create/find_by_user_id
//! 11. `mysql_user_ext_repository`：UserExtRepository upsert/find_by_user_id/delete
//! 12. `mysql_sql_dialect_placeholders`：MySQL `?` 占位符参数化查询（spec R-mysql-backend-003）
//!
//! 运行：`cargo test --features "db-mysql" --test db_mysql_testcontainers`
//!
//! 需要 Docker 运行。每个测试启动独立的 MySQL 容器，通过 `serial_test::serial` 串行化。

#![cfg(feature = "db-mysql")]

use garrison::dao::{
    init_dbnexus,
    repository::{
        mysql::{
            DbnexusMysqlAuthMethodRepository, DbnexusMysqlLoginLogRepository,
            DbnexusMysqlPermissionRepository, DbnexusMysqlRolePermissionRepository,
            DbnexusMysqlRoleRepository, DbnexusMysqlSessionRepository,
            DbnexusMysqlUserExtRepository, DbnexusMysqlUserRepository,
            DbnexusMysqlUserRoleRepository,
        },
        AuthMethodRepository, LoginLogRepository, NewAuthMethod, NewLoginLog, NewPermission,
        NewRole, NewSession, NewUser, PermissionRepository, RolePermissionRepository,
        RoleRepository, SessionRepository, UpdateUser, UserExtRepository, UserRepository,
        UserRoleRepository,
    },
    GarrisonMigration,
};
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serial_test::serial;
use std::path::PathBuf;
use testcontainers::{
    core::{IntoContainerPort, WaitFor},
    runners::AsyncRunner,
    ContainerAsync, GenericImage, ImageExt,
};

const TENANT_A: i64 = 1;

// ============================================================================
// 辅助：启动 MySQL 容器 + 初始化连接池
// ============================================================================

/// 启动 MySQL 8.0 容器并初始化 dbnexus 连接池。
///
/// 返回 `(DbPool, ContainerAsync<GenericImage>)`——container 必须在测试期间保持存活，
/// 否则容器会被回收（Docker container stopped & removed on drop）。
///
/// MySQL 容器配置：
/// - 镜像：mysql:8.0-oracle（Oracle 官方构建的 MySQL 8.0 镜像）
/// - root 密码：root
/// - 自动创建数据库：garrison_test
/// - 端口映射：宿主机随机端口 → 容器 3306
async fn setup_mysql_pool() -> (dbnexus::DbPool, ContainerAsync<GenericImage>) {
    let mysql_image = GenericImage::new("mysql", "8.0-oracle")
        .with_exposed_port(3306.tcp())
        .with_wait_for(WaitFor::message_on_either_std("ready for connections"))
        .with_env_var("MYSQL_ROOT_PASSWORD", "root")
        .with_env_var("MYSQL_DATABASE", "garrison_test");

    let container = mysql_image.start().await.expect("MySQL 8.0 容器应成功启动");

    let port = container
        .get_host_port_ipv4(3306)
        .await
        .expect("端口 3306 应被映射到宿主机");

    let url = format!("mysql://root:root@127.0.0.1:{}/garrison_test", port);

    // MySQL 容器就绪后仍需等待内部初始化完成，重试连接
    let pool = retry_init_dbnexus(&url).await;

    (pool, container)
}

/// 重试初始化 dbnexus 连接池（最多 30 次，每次间隔 1 秒）。
///
/// MySQL Docker 容器在输出 "ready for connections" 后仍需数秒完成内部初始化，
/// 首次连接可能失败。重试机制确保测试不会因时序问题 flaky。
async fn retry_init_dbnexus(url: &str) -> dbnexus::DbPool {
    let mut last_err = None;
    for i in 0..30u32 {
        match init_dbnexus(url).await {
            Ok(pool) => {
                // 验证连接可用：执行简单查询
                if let Ok(session) = pool.get_session("admin").await {
                    if let Ok(conn) = session.connection() {
                        let stmt =
                            Statement::from_sql_and_values(DbBackend::MySql, "SELECT 1", vec![]);
                        if conn.query_one_raw(stmt).await.is_ok() {
                            return pool;
                        }
                    }
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            },
            Err(e) => {
                last_err = Some(e);
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            },
        }
        let _ = i; // suppress unused warning
    }
    panic!("MySQL 连接池初始化失败（重试 30 次）：{:?}", last_err);
}

/// 定位项目根目录的 migrations/mysql/ 目录。
fn project_migrations_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir).join("migrations").join("mysql")
}

/// 创建并初始化 MySQL 连接池 + 迁移：连接 → 迁移 → 返回 pool + container。
async fn setup_db_with_migrations() -> (dbnexus::DbPool, ContainerAsync<GenericImage>) {
    let (pool, container) = setup_mysql_pool().await;

    let migration = GarrisonMigration::with_base_dir(pool.clone(), project_migrations_dir());
    let applied = migration.migrate_core().await.expect("migrate_core 应成功");
    assert!(
        applied >= 6,
        "migrate_core 应至少执行 6 个文件（001-006），实际: {}",
        applied
    );

    (pool, container)
}

// ============================================================================
// 1. 连接测试
// ============================================================================

/// 验证 `init_dbnexus` 能连接到 MySQL 8.0 容器并初始化连接池。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn mysql_dbpool_init() {
    let (pool, _container) = setup_mysql_pool().await;

    // 验证后端确实是 MySQL
    let session = pool.get_session("admin").await.expect("get_session 应成功");
    let conn = session.connection().expect("connection 应可用");
    assert_eq!(
        conn.get_database_backend(),
        DbBackend::MySql,
        "后端应为 MySQL"
    );
}

// ============================================================================
// 2. Migration 测试
// ============================================================================

/// 验证 `migrate_core` 在 MySQL 上创建全部核心表。
///
/// 9 张表：app_user / app_role / app_permission / app_user_role / app_role_permission
/// / app_auth_method / app_session / app_login_log / app_user_ext
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn mysql_auto_migrate() {
    let (pool, _container) = setup_db_with_migrations().await;

    let session = pool.get_session("admin").await.expect("get_session 应成功");
    let conn = session.connection().expect("connection 应可用");
    let stmt = Statement::from_sql_and_values(
        DbBackend::MySql,
        "SELECT table_name AS table_name FROM information_schema.tables \
         WHERE table_schema = 'garrison_test' AND table_name LIKE 'app_%' ORDER BY table_name",
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
        "app_user_ext",
        "app_user_role",
    ];
    for expected in &expected_tables {
        assert!(
            table_names.contains(&expected.to_string()),
            "核心表 {} 应存在于 MySQL garrison_test 数据库，实际表: {:?}",
            expected,
            table_names
        );
    }
    assert_eq!(expected_tables.len(), 9, "应有 9 张 app_ 前缀的核心表");
}

// ============================================================================
// 3. UserRepository CRUD
// ============================================================================

/// UserRepository：create → find_by_username → update → delete（MySQL 后端）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn mysql_user_repository_crud() {
    let (pool, _container) = setup_db_with_migrations().await;
    let repo = DbnexusMysqlUserRepository::new(pool);

    let user_id = repo
        .create(
            TENANT_A,
            NewUser {
                username: "alice_mysql".to_string(),
                password_hash: "hashed_mysql".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .expect("create 应成功");

    // find_by_username
    let found = repo
        .find_by_username(TENANT_A, "alice_mysql")
        .await
        .expect("find_by_username 应成功");
    assert!(found.is_some(), "find_by_username 应返回 Some");
    let row = found.unwrap();
    assert_eq!(row.id, user_id);
    assert_eq!(row.username, "alice_mysql");
    assert_eq!(row.status, "active");
    assert_eq!(row.tenant_id, TENANT_A);

    // update
    repo.update(
        TENANT_A,
        &user_id,
        UpdateUser {
            username: Some("alice_mysql_updated".to_string()),
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
    assert_eq!(updated.username, "alice_mysql_updated");
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

/// RoleRepository：create → find_by_code → list → delete（MySQL 后端）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn mysql_role_repository_crud() {
    let (pool, _container) = setup_db_with_migrations().await;
    let repo = DbnexusMysqlRoleRepository::new(pool);

    let role_id = repo
        .create(
            TENANT_A,
            NewRole {
                code: "admin_mysql".to_string(),
                name: "Administrator MySQL".to_string(),
                description: Some("full access mysql".to_string()),
                is_system: false,
            },
        )
        .await
        .expect("create role 应成功");

    // find_by_code
    let by_code = repo
        .find_by_code(TENANT_A, "admin_mysql")
        .await
        .expect("find_by_code 应成功");
    assert!(by_code.is_some(), "find_by_code 应返回 Some");
    assert_eq!(by_code.unwrap().id, role_id);

    // find_by_id 验证 is_system 字段（MySQL BIGINT 0/1 → bool 转换）
    let by_id = repo
        .find_by_id(TENANT_A, &role_id)
        .await
        .expect("find_by_id 应成功")
        .expect("role 应存在");
    assert!(!by_id.is_system, "is_system=false 应正确读取为 false");

    // list
    let list = repo.list(TENANT_A, 0, 100).await.expect("list 应成功");
    assert!(!list.is_empty(), "list 应返回非空");

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

/// PermissionRepository：create → find_by_code → list → delete（MySQL 后端）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn mysql_permission_repository_crud() {
    let (pool, _container) = setup_db_with_migrations().await;
    let repo = DbnexusMysqlPermissionRepository::new(pool);

    let perm_id = repo
        .create(NewPermission {
            code: "user:read:mysql".to_string(),
            name: "Read User MySQL".to_string(),
            resource_type: Some("user".to_string()),
            action: Some("read".to_string()),
        })
        .await
        .expect("create permission 应成功");

    // find_by_code
    let by_code = repo
        .find_by_code("user:read:mysql")
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
    assert_eq!(by_id.code, "user:read:mysql");
    assert_eq!(by_id.resource_type, Some("user".to_string()));
    assert_eq!(by_id.action, Some("read".to_string()));

    // list
    let list = repo.list(0, 100).await.expect("list 应成功");
    assert!(!list.is_empty(), "list 应返回非空");

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
// 6. UserRoleRepository
// ============================================================================

/// UserRoleRepository：assign → find_by_user_id → revoke（MySQL 后端）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn mysql_user_role_repository() {
    let (pool, _container) = setup_db_with_migrations().await;

    // 先创建用户和角色（外键依赖）
    let user_repo = DbnexusMysqlUserRepository::new(pool.clone());
    let role_repo = DbnexusMysqlRoleRepository::new(pool.clone());
    let user_role_repo = DbnexusMysqlUserRoleRepository::new(pool);

    let user_id = user_repo
        .create(
            TENANT_A,
            NewUser {
                username: "ur_user".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .expect("create user 应成功");

    let role_id = role_repo
        .create(
            TENANT_A,
            NewRole {
                code: "ur_role".to_string(),
                name: "UR Role".to_string(),
                description: None,
                is_system: false,
            },
        )
        .await
        .expect("create role 应成功");

    // assign
    user_role_repo
        .assign(TENANT_A, &user_id, &role_id, Some("all".to_string()))
        .await
        .expect("assign 应成功");

    // find_by_user_id（list_roles_for_user）
    let roles = user_role_repo
        .find_by_user_id(TENANT_A, &user_id)
        .await
        .expect("find_by_user_id 应成功");
    assert_eq!(roles.len(), 1, "用户应有 1 个角色");
    assert_eq!(roles[0].role_id, role_id);
    assert_eq!(roles[0].user_id, user_id);

    // revoke
    user_role_repo
        .revoke(TENANT_A, &user_id, &role_id)
        .await
        .expect("revoke 应成功");
    let after_revoke = user_role_repo
        .find_by_user_id(TENANT_A, &user_id)
        .await
        .expect("find_by_user_id 应成功");
    assert!(after_revoke.is_empty(), "revoke 后用户不应有角色");
}

// ============================================================================
// 7. RolePermissionRepository
// ============================================================================

/// RolePermissionRepository：assign → find_by_role_id → revoke（MySQL 后端）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn mysql_role_permission_repository() {
    let (pool, _container) = setup_db_with_migrations().await;

    // 先创建角色和权限（外键依赖）
    let role_repo = DbnexusMysqlRoleRepository::new(pool.clone());
    let perm_repo = DbnexusMysqlPermissionRepository::new(pool.clone());
    let rp_repo = DbnexusMysqlRolePermissionRepository::new(pool);

    let role_id = role_repo
        .create(
            TENANT_A,
            NewRole {
                code: "rp_role".to_string(),
                name: "RP Role".to_string(),
                description: None,
                is_system: false,
            },
        )
        .await
        .expect("create role 应成功");

    let perm_id = perm_repo
        .create(NewPermission {
            code: "rp:perm".to_string(),
            name: "RP Permission".to_string(),
            resource_type: None,
            action: None,
        })
        .await
        .expect("create permission 应成功");

    // assign
    rp_repo
        .assign(TENANT_A, &role_id, &perm_id)
        .await
        .expect("assign 应成功");

    // find_by_role_id（list_permissions_for_role）
    let perms = rp_repo
        .find_by_role_id(TENANT_A, &role_id)
        .await
        .expect("find_by_role_id 应成功");
    assert_eq!(perms.len(), 1, "角色应有 1 个权限");
    assert_eq!(perms[0].permission_id, perm_id);

    // revoke
    rp_repo
        .revoke(TENANT_A, &role_id, &perm_id)
        .await
        .expect("revoke 应成功");
    let after_revoke = rp_repo
        .find_by_role_id(TENANT_A, &role_id)
        .await
        .expect("find_by_role_id 应成功");
    assert!(after_revoke.is_empty(), "revoke 后角色不应有权限");
}

// ============================================================================
// 8. AuthMethodRepository
// ============================================================================

/// AuthMethodRepository：create → find_by_user_id → find_by_id → delete（MySQL 后端）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn mysql_auth_method_repository() {
    let (pool, _container) = setup_db_with_migrations().await;

    // 先创建用户（外键依赖）
    let user_repo = DbnexusMysqlUserRepository::new(pool.clone());
    let auth_repo = DbnexusMysqlAuthMethodRepository::new(pool);

    let user_id = user_repo
        .create(
            TENANT_A,
            NewUser {
                username: "am_user".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .expect("create user 应成功");

    // create
    let am_id = auth_repo
        .create(
            TENANT_A,
            NewAuthMethod {
                user_id: user_id.clone(),
                method_type: "password".to_string(),
                external_id: Some("ext-001".to_string()),
                metadata: Some(r#"{"k":"v"}"#.to_string()),
            },
        )
        .await
        .expect("create auth_method 应成功");

    // find_by_user_id
    let methods = auth_repo
        .find_by_user_id(TENANT_A, &user_id)
        .await
        .expect("find_by_user_id 应成功");
    assert_eq!(methods.len(), 1, "用户应有 1 个认证方式");
    assert_eq!(methods[0].id, am_id);
    assert_eq!(methods[0].method_type, "password");

    // find_by_id
    let by_id = auth_repo
        .find_by_id(TENANT_A, &am_id)
        .await
        .expect("find_by_id 应成功")
        .expect("auth_method 应存在");
    assert_eq!(by_id.method_type, "password");
    assert_eq!(by_id.external_id, Some("ext-001".to_string()));

    // delete
    auth_repo
        .delete(TENANT_A, &am_id)
        .await
        .expect("delete 应成功");
    assert!(
        auth_repo
            .find_by_id(TENANT_A, &am_id)
            .await
            .expect("find_by_id 应成功")
            .is_none(),
        "delete 后 find_by_id 应返回 None"
    );
}

// ============================================================================
// 9. SessionRepository
// ============================================================================

/// SessionRepository：create → find_by_session_id → delete（MySQL 后端）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn mysql_session_repository() {
    let (pool, _container) = setup_db_with_migrations().await;

    // 先创建用户（外键依赖）
    let user_repo = DbnexusMysqlUserRepository::new(pool.clone());
    let session_repo = DbnexusMysqlSessionRepository::new(pool);

    let user_id = user_repo
        .create(
            TENANT_A,
            NewUser {
                username: "sess_user".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .expect("create user 应成功");

    let session_token = "sess-token-mysql-001";

    // create
    session_repo
        .create(
            TENANT_A,
            NewSession {
                session_id: session_token.to_string(),
                user_id: user_id.clone(),
                device_id: Some("web".to_string()),
                ip: Some("127.0.0.1".to_string()),
                user_agent: Some("Mozilla/5.0".to_string()),
                expire_time: Some("2025-12-31 23:59:59".to_string()),
            },
        )
        .await
        .expect("create session 应成功");

    // find_by_session_id（find_by_token）
    let found = session_repo
        .find_by_session_id(TENANT_A, session_token)
        .await
        .expect("find_by_session_id 应成功");
    assert!(found.is_some(), "find_by_session_id 应返回 Some");
    let row = found.unwrap();
    assert_eq!(row.session_id, session_token);
    assert_eq!(row.user_id, user_id);
    assert_eq!(row.device_id, Some("web".to_string()));

    // delete
    session_repo
        .delete(TENANT_A, session_token)
        .await
        .expect("delete session 应成功");
    let after_delete = session_repo
        .find_by_session_id(TENANT_A, session_token)
        .await
        .expect("find_by_session_id 应成功");
    assert!(
        after_delete.is_none(),
        "delete 后 find_by_session_id 应返回 None"
    );
}

// ============================================================================
// 10. LoginLogRepository
// ============================================================================

/// LoginLogRepository：create → find_by_user_id（MySQL 后端）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn mysql_login_log_repository() {
    let (pool, _container) = setup_db_with_migrations().await;

    // 先创建用户（外键依赖）
    let user_repo = DbnexusMysqlUserRepository::new(pool.clone());
    let log_repo = DbnexusMysqlLoginLogRepository::new(pool);

    let user_id = user_repo
        .create(
            TENANT_A,
            NewUser {
                username: "log_user".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .expect("create user 应成功");

    // create（成功登录日志）
    let log_id = log_repo
        .create(
            TENANT_A,
            NewLoginLog {
                user_id: Some(user_id.clone()),
                action: "login".to_string(),
                ip: Some("192.168.1.1".to_string()),
                device_id: None,
                success: true,
                fail_reason: None,
            },
        )
        .await
        .expect("create login_log 应成功");

    // find_by_user_id
    let logs = log_repo
        .find_by_user_id(TENANT_A, &user_id, 0, 100)
        .await
        .expect("find_by_user_id 应成功");
    assert_eq!(logs.len(), 1, "用户应有 1 条登录日志");
    assert_eq!(logs[0].id, log_id);
    assert_eq!(logs[0].action, "login");
    assert!(
        logs[0].success,
        "success 应为 true（MySQL BIGINT 1 → bool）"
    );

    // find_by_id
    let by_id = log_repo
        .find_by_id(TENANT_A, &log_id)
        .await
        .expect("find_by_id 应成功")
        .expect("login_log 应存在");
    assert_eq!(by_id.action, "login");
    assert_eq!(by_id.ip, Some("192.168.1.1".to_string()));
}

// ============================================================================
// 11. UserExtRepository
// ============================================================================

/// UserExtRepository：upsert → find_by_user_id → find_by_user_and_key → delete（MySQL 后端）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn mysql_user_ext_repository() {
    let (pool, _container) = setup_db_with_migrations().await;

    // 先创建用户（外键依赖）
    let user_repo = DbnexusMysqlUserRepository::new(pool.clone());
    let ext_repo = DbnexusMysqlUserExtRepository::new(pool);

    let user_id = user_repo
        .create(
            TENANT_A,
            NewUser {
                username: "ext_user".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .expect("create user 应成功");

    // upsert（插入 email 扩展字段）
    ext_repo
        .upsert(
            TENANT_A,
            &user_id,
            "email",
            Some("alice@example.com".to_string()),
            "string",
        )
        .await
        .expect("upsert email 应成功");

    // upsert（插入 avatar 扩展字段）
    ext_repo
        .upsert(
            TENANT_A,
            &user_id,
            "avatar",
            Some("https://example.com/a.png".to_string()),
            "string",
        )
        .await
        .expect("upsert avatar 应成功");

    // find_by_user_id
    let exts = ext_repo
        .find_by_user_id(TENANT_A, &user_id)
        .await
        .expect("find_by_user_id 应成功");
    assert_eq!(exts.len(), 2, "用户应有 2 个扩展字段");

    // find_by_user_and_key
    let email = ext_repo
        .find_by_user_and_key(TENANT_A, &user_id, "email")
        .await
        .expect("find_by_user_and_key 应成功")
        .expect("email 字段应存在");
    assert_eq!(email.field_value, Some("alice@example.com".to_string()));

    // upsert（更新已有 email 字段——验证 UK(user_id, field_key) upsert 语义）
    ext_repo
        .upsert(
            TENANT_A,
            &user_id,
            "email",
            Some("bob@example.com".to_string()),
            "string",
        )
        .await
        .expect("upsert email 更新应成功");
    let updated_email = ext_repo
        .find_by_user_and_key(TENANT_A, &user_id, "email")
        .await
        .expect("find_by_user_and_key 应成功")
        .expect("email 字段应存在");
    assert_eq!(
        updated_email.field_value,
        Some("bob@example.com".to_string()),
        "upsert 后 email 应已更新"
    );

    // upsert 后仍应只有 2 个字段（不是 3 个）
    let exts_after_upsert = ext_repo
        .find_by_user_id(TENANT_A, &user_id)
        .await
        .expect("find_by_user_id 应成功");
    assert_eq!(exts_after_upsert.len(), 2, "upsert 不应新增记录（UK 约束）");

    // delete
    ext_repo
        .delete(TENANT_A, &user_id, "avatar")
        .await
        .expect("delete ext 应成功");
    let after_delete = ext_repo
        .find_by_user_id(TENANT_A, &user_id)
        .await
        .expect("find_by_user_id 应成功");
    assert_eq!(after_delete.len(), 1, "删除后应剩 1 个扩展字段");
}

// ============================================================================
// 12. SQL 方言占位符测试（spec R-mysql-backend-003，converge T076）
// ============================================================================

/// 验证 MySQL `?` 占位符参数化查询正确工作（spec R-mysql-backend-003）。
///
/// MySQL 使用 `?` 作为参数占位符（PostgreSQL 用 `$1, $2`）。本测试显式验证
/// sea-orm `Statement::from_sql_and_values` 在 MySQL 后端正确绑定 `?` 参数，
/// 与 9 个 Repository CRUD 测试互补——后者隐式使用占位符但未显式验证方言层。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn mysql_sql_dialect_placeholders() {
    let (pool, _container) = setup_mysql_pool().await;

    let session = pool.get_session("admin").await.expect("get_session 应成功");
    let conn = session.connection().expect("connection 应可用");

    // 单参数：SELECT ? AS val → 验证 ? 占位符被正确替换为参数值
    let stmt =
        Statement::from_sql_and_values(DbBackend::MySql, "SELECT ? AS val", vec![42i64.into()]);
    let row = conn
        .query_one_raw(stmt)
        .await
        .expect("参数化查询应成功")
        .expect("应返回一行");
    let val: i64 = row.try_get_by_index(0).expect("应能读取整数值");
    assert_eq!(val, 42, "? 占位符单参数绑定应正确");

    // 多参数：SELECT ? AS a, ? AS b → 验证多个 ? 占位符按序绑定
    let stmt_multi = Statement::from_sql_and_values(
        DbBackend::MySql,
        "SELECT ? AS a, ? AS b",
        vec![1i64.into(), 2i64.into()],
    );
    let row_multi = conn
        .query_one_raw(stmt_multi)
        .await
        .expect("多参数查询应成功")
        .expect("应返回一行");
    let a: i64 = row_multi.try_get_by_index(0).expect("应能读取 a");
    let b: i64 = row_multi.try_get_by_index(1).expect("应能读取 b");
    assert_eq!(a, 1, "第一个 ? 占位符应绑定 1");
    assert_eq!(b, 2, "第二个 ? 占位符应绑定 2");

    // 字符串参数：SELECT ? AS s → 验证字符串类型参数绑定
    let stmt_str =
        Statement::from_sql_and_values(DbBackend::MySql, "SELECT ? AS s", vec!["hello".into()]);
    let row_str = conn
        .query_one_raw(stmt_str)
        .await
        .expect("字符串参数查询应成功")
        .expect("应返回一行");
    let s: String = row_str.try_get_by_index(0).expect("应能读取字符串");
    assert_eq!(s, "hello", "? 占位符字符串参数绑定应正确");
}
