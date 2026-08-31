//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! repository 域验收（spec `acceptance-matrix` R-acceptance-matrix-001，任务 T034）。
//!
//! 场景编号 `ACC-REPO-NNN`，`#[cfg(feature = "db-sqlite")]` 门控：
//! - ACC-REPO-001..010：10 张核心表 CRUD（User/Role/Permission/UserRole/
//!   RolePermission/AuthMethod/Session/LoginLog/UserExt/UserDevice），
//!   从 `tests/repository.rs` / `tests/repository/` 吸收（每个场景标注
//!   「迁自 tests/repository/…」，Phase 4 迁移追溯）；
//! - ACC-REPO-011：迁移幂等（`migrate_core` 二次执行不报错、不重复建表）；
//! - ACC-REPO-012：级联删除（用户删除后 user_role/auth_method/session/user_ext
//!   级联清除、login_log SET NULL——以实际外键行为为准，sqlx-sqlite 默认
//!   `PRAGMA foreign_keys=ON`，migrations/sqlite/core/001_init.sql 定义级联）；
//! - ACC-REPO-013..022：缺表错误路径（吸收 `tests/repository/error_paths.rs`
//!   42 例核心语义，按表分组合并同构用例，每表至少 1 个缺表断言：
//!   未迁移库上操作返回 `GarrisonError::Dao` 而非 panic）。
//! - ACC-REPO-023..030：dbnexus 层语义与未吸收用例（迁移产物精确断言 /
//!   多租户隔离 / RBAC 全链 / 设备多量隔离 / 空 update 短路 / 唯一约束 /
//!   CHECK 约束 / 事务回滚，吸收 `tests/repository/dbnexus_integration.rs`
//!   与 `tests/repository/integration.rs` / `error_paths.rs` 未覆盖用例）。
//!
//! 每个场景独立 `sqlite::memory:` 连接池（in-memory 互不污染），无全局单例，
//! 不需要 `#[serial]`；与 `tests/repository/*.rs` 装配一致。

use garrison::dao::{
    init_dbnexus,
    repository::{
        sqlite::{
            DbnexusAuthMethodRepository, DbnexusLoginLogRepository, DbnexusPermissionRepository,
            DbnexusRolePermissionRepository, DbnexusRoleRepository, DbnexusSessionRepository,
            DbnexusUserDeviceRepository, DbnexusUserExtRepository, DbnexusUserRepository,
            DbnexusUserRoleRepository,
        },
        AuthMethodRepository, LoginLogRepository, NewAuthMethod, NewLoginLog, NewPermission,
        NewRole, NewSession, NewUser, PermissionRepository, RolePermissionRepository,
        RoleRepository, SessionRepository, UpdateUser, UserDeviceRepository, UserExtRepository,
        UserRepository, UserRoleRepository, MAX_DEVICES,
    },
    GarrisonMigration,
};
use garrison::error::GarrisonError;
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use std::path::PathBuf;

const TENANT_A: i64 = 1;

/// 第二租户（多租户隔离场景，迁自 tests/repository/integration.rs）。
const TENANT_B: i64 = 2;

/// 测试用 UA 字符串（Chrome on Windows，迁自 tests/repository/integration.rs）。
const UA_CHROME_WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
    AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";

/// 测试用 UA 字符串（Safari on Mac，迁自 tests/repository/integration.rs）。
const UA_SAFARI_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) \
    AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Safari/605.1.15";

// ============================================================================
// 辅助：迁移目录 + SQLite in-memory 装配（迁自 tests/repository/integration.rs）
// ============================================================================

fn project_migrations_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("migrations")
        .join("sqlite")
}

async fn setup_db() -> dbnexus::DbPool {
    let pool = init_dbnexus("sqlite::memory:")
        .await
        .expect("init_dbnexus 应成功");
    let migration = GarrisonMigration::with_base_dir(pool.clone(), project_migrations_dir());
    let applied = migration.migrate_core().await.expect("migrate_core 应成功");
    assert!(applied >= 1, "migrate_core 应至少执行 1 个文件");
    pool
}

/// 创建**未迁移**的 DbPool（所有表不存在），触发 `map_err` 缺表分支
///（迁自 tests/repository/error_paths.rs::setup_unmigrated_db）。
async fn setup_unmigrated_db() -> dbnexus::DbPool {
    init_dbnexus("sqlite::memory:")
        .await
        .expect("init_dbnexus 应成功（即使不迁移）")
}

/// 缺表断言：结果为 `Err(GarrisonError::Dao)` 且消息含方法/表名前缀，
/// 绝不 panic（迁自 tests/repository/error_paths.rs::assert_dao_error）。
fn assert_dao_error<T>(result: garrison::error::GarrisonResult<T>, method_name: &str) {
    match result {
        Err(GarrisonError::Dao(msg)) => {
            assert!(
                msg.contains(method_name),
                "错误信息应包含方法/表名 '{}'，实际: {}",
                method_name,
                msg
            );
        },
        Err(other) => panic!("期望 GarrisonError::Dao，实际: {:?}", other),
        Ok(_) => panic!("期望 Err，实际 Ok（DB 未迁移应失败）"),
    }
}

/// 查询 count(*) 结果（迁自 tests/repository/dbnexus_integration.rs::query_count）。
async fn query_count(session: &dbnexus::Session, sql: &str) -> i64 {
    let conn = session
        .connection()
        .expect("connection should be available");
    let stmt = Statement::from_sql_and_values(DbBackend::Sqlite, sql, vec![]);
    let row = conn
        .query_one_raw(stmt)
        .await
        .expect("query should succeed")
        .expect("row should exist");
    row.try_get::<i64>("", "cnt").expect("column 'cnt' 应存在")
}

/// 查询多行单列字符串值（迁自 tests/repository/dbnexus_integration.rs::query_all_strings）。
async fn query_all_strings(session: &dbnexus::Session, sql: &str) -> Vec<String> {
    let conn = session
        .connection()
        .expect("connection should be available");
    let stmt = Statement::from_sql_and_values(DbBackend::Sqlite, sql, vec![]);
    let rows = conn
        .query_all_raw(stmt)
        .await
        .expect("query should succeed");
    rows.into_iter()
        .filter_map(|r| r.try_get::<String>("", "val").ok())
        .collect()
}

// ------------------------------------------------------------------------
// ACC-REPO-001..010：10 表 CRUD（正常）
// ------------------------------------------------------------------------

/// ACC-REPO-001（正常）：User CRUD——create → find_by_id → find_by_username →
/// update → list → delete（幂等）。
/// 迁自 tests/repository/integration.rs::user_repository_full_crud
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_001_user_repository_full_crud() {
    let pool = setup_db().await;
    let repo = DbnexusUserRepository::new(pool);

    let user_id = repo
        .create(
            TENANT_A,
            NewUser {
                username: "alice".to_string(),
                password_hash: "hashed".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .expect("create 应成功");

    let found = repo.find_by_id(TENANT_A, &user_id).await.unwrap();
    assert!(found.is_some(), "find_by_id 应返回 Some");
    let row = found.unwrap();
    assert_eq!(row.id, user_id);
    assert_eq!(row.username, "alice");
    assert_eq!(row.status, "active");
    assert_eq!(row.tenant_id, TENANT_A);

    let by_name = repo.find_by_username(TENANT_A, "alice").await.unwrap();
    assert!(by_name.is_some(), "find_by_username 应返回 Some");
    assert_eq!(by_name.unwrap().id, user_id);

    repo.update(
        TENANT_A,
        &user_id,
        UpdateUser {
            username: Some("alice_updated".to_string()),
            status: Some("suspended".to_string()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let updated = repo.find_by_id(TENANT_A, &user_id).await.unwrap().unwrap();
    assert_eq!(updated.username, "alice_updated");
    assert_eq!(updated.status, "suspended");

    let list = repo.list(TENANT_A, 0, 100).await.unwrap();
    assert!(!list.is_empty(), "list 应返回非空");

    repo.delete(TENANT_A, &user_id).await.unwrap();
    repo.delete(TENANT_A, &user_id).await.unwrap(); // 幂等
    assert!(
        repo.find_by_id(TENANT_A, &user_id).await.unwrap().is_none(),
        "delete 后 find_by_id 应返回 None"
    );
}

/// ACC-REPO-002（正常）：Role CRUD——create → find_by_id → find_by_code →
/// update → delete。
/// 迁自 tests/repository/integration.rs::role_repository_full_crud
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_002_role_repository_full_crud() {
    let pool = setup_db().await;
    let repo = DbnexusRoleRepository::new(pool);

    let role_id = repo
        .create(
            TENANT_A,
            NewRole {
                code: "admin".to_string(),
                name: "Administrator".to_string(),
                description: Some("full access".to_string()),
                is_system: false,
            },
        )
        .await
        .unwrap();

    let by_id = repo.find_by_id(TENANT_A, &role_id).await.unwrap();
    assert!(by_id.is_some());
    assert_eq!(by_id.unwrap().code, "admin");

    let by_code = repo.find_by_code(TENANT_A, "admin").await.unwrap();
    assert!(by_code.is_some());
    assert_eq!(by_code.unwrap().id, role_id);

    repo.update(
        TENANT_A,
        &role_id,
        Some("super_admin".to_string()),
        Some("Super Administrator".to_string()),
        None,
    )
    .await
    .unwrap();
    let updated = repo.find_by_id(TENANT_A, &role_id).await.unwrap().unwrap();
    assert_eq!(updated.code, "super_admin");
    assert_eq!(updated.name, "Super Administrator");

    repo.delete(TENANT_A, &role_id).await.unwrap();
    assert!(repo.find_by_id(TENANT_A, &role_id).await.unwrap().is_none());
}

/// ACC-REPO-003（正常）：Permission CRUD——create → find_by_id → find_by_code →
/// update → delete（Permission 无 tenant_id 维度）。
/// 迁自 tests/repository/integration.rs::permission_repository_full_crud
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_003_permission_repository_full_crud() {
    let pool = setup_db().await;
    let repo = DbnexusPermissionRepository::new(pool);

    let perm_id = repo
        .create(NewPermission {
            code: "user:read".to_string(),
            name: "Read User".to_string(),
            resource_type: Some("user".to_string()),
            action: Some("read".to_string()),
        })
        .await
        .unwrap();

    let by_id = repo.find_by_id(&perm_id).await.unwrap();
    assert!(by_id.is_some());
    assert_eq!(by_id.unwrap().code, "user:read");

    let by_code = repo.find_by_code("user:read").await.unwrap();
    assert!(by_code.is_some());
    assert_eq!(by_code.unwrap().id, perm_id);

    repo.update(&perm_id, Some("Read All Users".to_string()), None, None)
        .await
        .unwrap();
    let updated = repo.find_by_id(&perm_id).await.unwrap().unwrap();
    assert_eq!(updated.name, "Read All Users");

    repo.delete(&perm_id).await.unwrap();
    assert!(repo.find_by_id(&perm_id).await.unwrap().is_none());
}

/// ACC-REPO-004（正常）：UserRole 关联——assign → find_by_user_id →
/// find_by_role_id → revoke（幂等）。
/// 迁自 tests/repository/integration.rs::user_role_repository_assign_find_revoke
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_004_user_role_assign_find_revoke() {
    let pool = setup_db().await;
    let user_repo = DbnexusUserRepository::new(pool.clone());
    let role_repo = DbnexusRoleRepository::new(pool.clone());
    let user_role_repo = DbnexusUserRoleRepository::new(pool);

    let user_id = user_repo
        .create(
            TENANT_A,
            NewUser {
                username: "bob".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();
    let role_id = role_repo
        .create(
            TENANT_A,
            NewRole {
                code: "editor".to_string(),
                name: "Editor".to_string(),
                description: None,
                is_system: false,
            },
        )
        .await
        .unwrap();

    user_role_repo
        .assign(TENANT_A, &user_id, &role_id, Some("scope1".to_string()))
        .await
        .unwrap();

    let by_user = user_role_repo
        .find_by_user_id(TENANT_A, &user_id)
        .await
        .unwrap();
    assert_eq!(by_user.len(), 1);
    assert_eq!(by_user[0].role_id, role_id);
    assert_eq!(by_user[0].scope.as_deref(), Some("scope1"));

    let by_role = user_role_repo
        .find_by_role_id(TENANT_A, &role_id)
        .await
        .unwrap();
    assert_eq!(by_role.len(), 1);
    assert_eq!(by_role[0].user_id, user_id);

    user_role_repo
        .revoke(TENANT_A, &user_id, &role_id)
        .await
        .unwrap();
    user_role_repo
        .revoke(TENANT_A, &user_id, &role_id)
        .await
        .unwrap();
    assert!(
        user_role_repo
            .find_by_user_id(TENANT_A, &user_id)
            .await
            .unwrap()
            .is_empty(),
        "revoke 后应无关联"
    );
}

/// ACC-REPO-005（正常）：RolePermission 关联——assign → find_by_role_id →
/// find_by_permission_id → revoke（幂等）。
/// 迁自 tests/repository/integration.rs::role_permission_repository_assign_find_revoke
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_005_role_permission_assign_find_revoke() {
    let pool = setup_db().await;
    let role_repo = DbnexusRoleRepository::new(pool.clone());
    let perm_repo = DbnexusPermissionRepository::new(pool.clone());
    let rp_repo = DbnexusRolePermissionRepository::new(pool);

    let role_id = role_repo
        .create(
            TENANT_A,
            NewRole {
                code: "viewer".to_string(),
                name: "Viewer".to_string(),
                description: None,
                is_system: false,
            },
        )
        .await
        .unwrap();
    let perm_id = perm_repo
        .create(NewPermission {
            code: "doc:read".to_string(),
            name: "Read Doc".to_string(),
            resource_type: Some("doc".to_string()),
            action: Some("read".to_string()),
        })
        .await
        .unwrap();

    rp_repo.assign(TENANT_A, &role_id, &perm_id).await.unwrap();

    let by_role = rp_repo.find_by_role_id(TENANT_A, &role_id).await.unwrap();
    assert_eq!(by_role.len(), 1);
    assert_eq!(by_role[0].permission_id, perm_id);

    let by_perm = rp_repo
        .find_by_permission_id(TENANT_A, &perm_id)
        .await
        .unwrap();
    assert_eq!(by_perm.len(), 1);
    assert_eq!(by_perm[0].role_id, role_id);

    rp_repo.revoke(TENANT_A, &role_id, &perm_id).await.unwrap();
    rp_repo.revoke(TENANT_A, &role_id, &perm_id).await.unwrap();
    assert!(
        rp_repo
            .find_by_role_id(TENANT_A, &role_id)
            .await
            .unwrap()
            .is_empty(),
        "revoke 后应无关联"
    );
}

/// ACC-REPO-006（正常）：AuthMethod CRUD——create → find_by_user_id →
/// find_by_id → delete（幂等）。
/// 迁自 tests/repository/integration.rs::auth_method_repository_create_find_delete
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_006_auth_method_create_find_delete() {
    let pool = setup_db().await;
    let user_repo = DbnexusUserRepository::new(pool.clone());
    let auth_repo = DbnexusAuthMethodRepository::new(pool);

    let user_id = user_repo
        .create(
            TENANT_A,
            NewUser {
                username: "charlie".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();

    let method_id = auth_repo
        .create(
            TENANT_A,
            NewAuthMethod {
                user_id: user_id.clone(),
                method_type: "password".to_string(),
                external_id: None,
                metadata: Some(r#"{"v":1}"#.to_string()),
            },
        )
        .await
        .unwrap();

    let by_user = auth_repo.find_by_user_id(TENANT_A, &user_id).await.unwrap();
    assert_eq!(by_user.len(), 1);
    assert_eq!(by_user[0].method_type, "password");

    let by_id = auth_repo.find_by_id(TENANT_A, &method_id).await.unwrap();
    assert!(by_id.is_some());

    auth_repo.delete(TENANT_A, &method_id).await.unwrap();
    auth_repo.delete(TENANT_A, &method_id).await.unwrap();
    assert!(
        auth_repo
            .find_by_user_id(TENANT_A, &user_id)
            .await
            .unwrap()
            .is_empty(),
        "delete 后应无认证方式"
    );
}

/// ACC-REPO-007（正常）：Session CRUD——create → find_by_session_id →
/// find_by_user_id → update_last_active → delete（幂等）。
/// 迁自 tests/repository/integration.rs::session_repository_create_find_update_delete
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_007_session_create_find_update_delete() {
    let pool = setup_db().await;
    let user_repo = DbnexusUserRepository::new(pool.clone());
    let session_repo = DbnexusSessionRepository::new(pool);

    let user_id = user_repo
        .create(
            TENANT_A,
            NewUser {
                username: "dave".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();

    let session_id = "session-token-xyz".to_string();
    session_repo
        .create(
            TENANT_A,
            NewSession {
                session_id: session_id.clone(),
                user_id: user_id.clone(),
                device_id: Some("web".to_string()),
                ip: Some("127.0.0.1".to_string()),
                user_agent: None,
                expire_time: None,
            },
        )
        .await
        .unwrap();

    let by_sid = session_repo
        .find_by_session_id(TENANT_A, &session_id)
        .await
        .unwrap();
    assert!(by_sid.is_some());
    assert_eq!(by_sid.unwrap().user_id, user_id);

    let by_user = session_repo
        .find_by_user_id(TENANT_A, &user_id)
        .await
        .unwrap();
    assert_eq!(by_user.len(), 1);

    session_repo
        .update_last_active(TENANT_A, &session_id)
        .await
        .unwrap();

    session_repo.delete(TENANT_A, &session_id).await.unwrap();
    session_repo.delete(TENANT_A, &session_id).await.unwrap();
    assert!(
        session_repo
            .find_by_session_id(TENANT_A, &session_id)
            .await
            .unwrap()
            .is_none(),
        "delete 后会话应不存在"
    );
}

/// ACC-REPO-008（正常）：LoginLog CRUD——create → find_by_id → find_by_user_id。
/// 迁自 tests/repository/integration.rs::login_log_repository_create_find
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_008_login_log_create_find() {
    let pool = setup_db().await;
    let user_repo = DbnexusUserRepository::new(pool.clone());
    let log_repo = DbnexusLoginLogRepository::new(pool);

    let user_id = user_repo
        .create(
            TENANT_A,
            NewUser {
                username: "eve".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();

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
        .unwrap();

    let by_id = log_repo.find_by_id(TENANT_A, &log_id).await.unwrap();
    assert!(by_id.is_some());
    assert_eq!(by_id.unwrap().action, "login");

    let by_user = log_repo
        .find_by_user_id(TENANT_A, &user_id, 0, 100)
        .await
        .unwrap();
    assert!(!by_user.is_empty(), "find_by_user_id 应返回日志");
}

/// ACC-REPO-009（正常）：UserExt upsert——插入 / 同 key 更新 / 多字段查询。
/// 迁自 tests/repository/integration.rs::user_ext_repository_upsert_find
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_009_user_ext_upsert_find() {
    let pool = setup_db().await;
    let user_repo = DbnexusUserRepository::new(pool.clone());
    let ext_repo = DbnexusUserExtRepository::new(pool);

    let user_id = user_repo
        .create(
            TENANT_A,
            NewUser {
                username: "frank".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();

    ext_repo
        .upsert(
            TENANT_A,
            &user_id,
            "email",
            Some("frank@example.com".to_string()),
            "string",
        )
        .await
        .unwrap();

    let by_key = ext_repo
        .find_by_user_and_key(TENANT_A, &user_id, "email")
        .await
        .unwrap();
    assert!(by_key.is_some());
    assert_eq!(
        by_key.unwrap().field_value.as_deref(),
        Some("frank@example.com")
    );

    // upsert 更新同一 key
    ext_repo
        .upsert(
            TENANT_A,
            &user_id,
            "email",
            Some("frank@new.com".to_string()),
            "string",
        )
        .await
        .unwrap();
    let after_update = ext_repo
        .find_by_user_and_key(TENANT_A, &user_id, "email")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after_update.field_value.as_deref(), Some("frank@new.com"));

    ext_repo
        .upsert(
            TENANT_A,
            &user_id,
            "phone",
            Some("+86-10086".to_string()),
            "string",
        )
        .await
        .unwrap();
    let all = ext_repo.find_by_user_id(TENANT_A, &user_id).await.unwrap();
    assert_eq!(all.len(), 2, "应有 2 个扩展字段（email + phone）");
}

/// ACC-REPO-010（正常）：UserDevice——register（幂等）/ list / block /
/// unblock / count / MAX_DEVICES 拒绝。
/// 迁自 tests/repository/integration.rs::register_device_creates_new_device、
/// register_device_idempotent_on_duplicate、block_device_sets_is_blocked、
/// unblock_device_clears_is_blocked、count_user_devices_returns_count、
/// register_device_rejects_when_max_exceeded
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_010_user_device_register_list_block_unblock_count() {
    let pool = setup_db().await;
    let repo = DbnexusUserDeviceRepository::new(pool);
    let login_id = "4004";

    // 注册 + 幂等
    let device_id = repo
        .register_device(TENANT_A, login_id, "block-fp", UA_CHROME_WIN)
        .await
        .expect("register_device 应成功");
    assert!(!device_id.is_empty(), "设备 ID 不应为空");
    uuid::Uuid::parse_str(&device_id).expect("设备 ID 应为合法 UUID");
    let id_dup = repo
        .register_device(TENANT_A, login_id, "block-fp", UA_CHROME_WIN)
        .await
        .expect("重复注册应幂等");
    assert_eq!(device_id, id_dup, "重复注册同一 identifier 应返回相同 ID");

    // list + 初始未阻断
    let devices = repo.list_user_devices(TENANT_A, login_id).await.unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(devices[0].device_identifier, "block-fp");
    assert!(!devices[0].is_blocked, "新设备默认未阻断");

    // block → unblock
    repo.block_device(&device_id).await.expect("block 应成功");
    let devices = repo.list_user_devices(TENANT_A, login_id).await.unwrap();
    assert!(devices[0].is_blocked, "block 后 is_blocked 应为 true");
    repo.unblock_device(&device_id)
        .await
        .expect("unblock 应成功");
    let devices = repo.list_user_devices(TENANT_A, login_id).await.unwrap();
    assert!(!devices[0].is_blocked, "unblock 后 is_blocked 应为 false");

    // count
    let count = repo.count_user_devices(TENANT_A, login_id).await.unwrap();
    assert_eq!(count, 1);

    // MAX_DEVICES 拒绝（异常侧）
    let overflow_login = "2002";
    for i in 0..MAX_DEVICES {
        repo.register_device(
            TENANT_A,
            overflow_login,
            &format!("fp-max-{:03}", i),
            UA_CHROME_WIN,
        )
        .await
        .unwrap_or_else(|_| panic!("注册第 {} 个设备应成功", i + 1));
    }
    let result = repo
        .register_device(TENANT_A, overflow_login, "fp-overflow", UA_CHROME_WIN)
        .await;
    assert!(
        matches!(result, Err(GarrisonError::InvalidParam(_))),
        "超过 MAX_DEVICES 应返回 InvalidParam，实际: {:?}",
        result
    );
    assert_eq!(
        repo.count_user_devices(TENANT_A, overflow_login)
            .await
            .unwrap(),
        MAX_DEVICES,
        "拒绝后 count 应保持 MAX_DEVICES"
    );
}

// ------------------------------------------------------------------------
// ACC-REPO-011..012：迁移幂等 / 级联删除（正常）
// ------------------------------------------------------------------------

/// ACC-REPO-011（正常）：迁移幂等——`migrate_core` 二次执行不报错，
/// 且 `app_%` 表数量不重复增长（迁移历史已记录，无重建）。
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_011_migrate_core_idempotent() {
    let pool = init_dbnexus("sqlite::memory:")
        .await
        .expect("init_dbnexus 应成功");
    let migration = GarrisonMigration::with_base_dir(pool.clone(), project_migrations_dir());

    let first = migration.migrate_core().await.expect("首次迁移应成功");
    assert!(first >= 1, "首次 migrate_core 应至少执行 1 个文件");

    let tables_before = count_app_tables(&pool).await;
    assert!(
        tables_before >= 10,
        "核心表应至少 10 张，实际: {tables_before}"
    );

    // 二次执行：不报错、不重复
    migration
        .migrate_core()
        .await
        .expect("migrate_core 二次执行不应报错（幂等）");
    let tables_after = count_app_tables(&pool).await;
    assert_eq!(
        tables_before, tables_after,
        "二次迁移不应重复建表（{tables_before} → {tables_after}）"
    );

    // 迁移后表可用
    let repo = DbnexusUserRepository::new(pool);
    repo.create(
        TENANT_A,
        NewUser {
            username: "idempotent-user".to_string(),
            password_hash: "h".to_string(),
            status: "active".to_string(),
        },
    )
    .await
    .expect("迁移后 CRUD 应可用");
}

/// 统计 `app_%` 前缀表数量（sqlite_master，幂等断言用）。
async fn count_app_tables(pool: &dbnexus::DbPool) -> usize {
    let session = pool
        .get_session("admin")
        .await
        .expect("count_app_tables: get_session 应成功");
    let conn = session.connection().expect("connection 应可用");
    let stmt = Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name LIKE 'app_%'",
        vec![],
    );
    let rows = conn
        .query_all_raw(stmt)
        .await
        .expect("查询 sqlite_master 应成功");
    rows.len()
}

/// ACC-REPO-012（正常）：级联删除——删除用户后 `user_role` / `auth_method` /
/// `session` / `user_ext` 关联级联清除；`login_log` 外键为 SET NULL
///（记录保留、user_id 置空）。以实际外键行为为准：
/// migrations/sqlite/core/001_init.sql 定义各表 ON DELETE 动作，
/// sqlx-sqlite 默认 `PRAGMA foreign_keys=ON`。
/// 迁自 tests/repository/integration.rs 诸 CRUD 用例的组合语义
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_012_user_delete_cascades_relations() {
    let pool = setup_db().await;
    let user_repo = DbnexusUserRepository::new(pool.clone());
    let role_repo = DbnexusRoleRepository::new(pool.clone());
    let ur_repo = DbnexusUserRoleRepository::new(pool.clone());
    let auth_repo = DbnexusAuthMethodRepository::new(pool.clone());
    let session_repo = DbnexusSessionRepository::new(pool.clone());
    let log_repo = DbnexusLoginLogRepository::new(pool.clone());
    let ext_repo = DbnexusUserExtRepository::new(pool);

    // 准备用户 + 各关联
    let user_id = user_repo
        .create(
            TENANT_A,
            NewUser {
                username: "cascade-target".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();
    let role_id = role_repo
        .create(
            TENANT_A,
            NewRole {
                code: "cascade-role".to_string(),
                name: "Cascade Role".to_string(),
                description: None,
                is_system: false,
            },
        )
        .await
        .unwrap();
    ur_repo
        .assign(TENANT_A, &user_id, &role_id, None)
        .await
        .unwrap();
    auth_repo
        .create(
            TENANT_A,
            NewAuthMethod {
                user_id: user_id.clone(),
                method_type: "password".to_string(),
                external_id: None,
                metadata: None,
            },
        )
        .await
        .unwrap();
    session_repo
        .create(
            TENANT_A,
            NewSession {
                session_id: "cascade-session".to_string(),
                user_id: user_id.clone(),
                device_id: None,
                ip: None,
                user_agent: None,
                expire_time: None,
            },
        )
        .await
        .unwrap();
    let log_id = log_repo
        .create(
            TENANT_A,
            NewLoginLog {
                user_id: Some(user_id.clone()),
                action: "login".to_string(),
                ip: None,
                device_id: None,
                success: true,
                fail_reason: None,
            },
        )
        .await
        .unwrap();
    ext_repo
        .upsert(
            TENANT_A,
            &user_id,
            "email",
            Some("c@example.com".to_string()),
            "string",
        )
        .await
        .unwrap();

    // 删除用户
    user_repo.delete(TENANT_A, &user_id).await.unwrap();

    // CASCADE：user_role / auth_method / session / user_ext 关联清除
    assert!(
        ur_repo
            .find_by_user_id(TENANT_A, &user_id)
            .await
            .unwrap()
            .is_empty(),
        "用户删除后 user_role 关联应被级联清除"
    );
    assert!(
        auth_repo
            .find_by_user_id(TENANT_A, &user_id)
            .await
            .unwrap()
            .is_empty(),
        "用户删除后 auth_method 应被级联清除"
    );
    assert!(
        session_repo
            .find_by_session_id(TENANT_A, "cascade-session")
            .await
            .unwrap()
            .is_none(),
        "用户删除后 session 应被级联清除"
    );
    assert!(
        ext_repo
            .find_by_user_id(TENANT_A, &user_id)
            .await
            .unwrap()
            .is_empty(),
        "用户删除后 user_ext 应被级联清除"
    );

    // SET NULL：login_log 保留、user_id 置空（FK ON DELETE SET NULL）
    let log_after = log_repo
        .find_by_id(TENANT_A, &log_id)
        .await
        .unwrap()
        .expect("login_log 应保留（SET NULL 而非删除）");
    assert!(
        log_after.user_id.is_none(),
        "用户删除后 login_log.user_id 应被置空，实际: {:?}",
        log_after.user_id
    );

    // 角色本身不受用户删除影响（CASCADE 只沿 FK 方向）
    assert!(
        role_repo
            .find_by_id(TENANT_A, &role_id)
            .await
            .unwrap()
            .is_some(),
        "角色不应随用户删除"
    );
}

// ------------------------------------------------------------------------
// ACC-REPO-013..022：缺表错误路径（异常）
// ------------------------------------------------------------------------
//
// 吸收 tests/repository/error_paths.rs 42 例的核心语义：未迁移库上调用
// repository 方法返回 `GarrisonError::Dao`（含方法/表名前缀）而非 panic。
// 按表分组合并同构用例，每表至少 1 个缺表断言（任务约束允许合并）。

/// ACC-REPO-013（异常）：UserRepository 缺表——create/find_by_id/
/// find_by_username/update/delete/list 全部返回 Dao 错误而非 panic。
/// 迁自 tests/repository/error_paths.rs::user_repo_*（6 例合并）
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_013_user_repo_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserRepository::new(pool);
    assert_dao_error(
        repo.find_by_id(TENANT_A, "u-1").await,
        "app-user-find-by-id",
    );
    assert_dao_error(
        repo.find_by_username(TENANT_A, "alice").await,
        "app-user-find-by-username",
    );
    assert_dao_error(
        repo.create(
            TENANT_A,
            NewUser {
                username: "alice".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await,
        "app-user-create",
    );
    assert_dao_error(
        repo.update(
            TENANT_A,
            "u-1",
            UpdateUser {
                username: Some("alice2".to_string()),
                ..Default::default()
            },
        )
        .await,
        "app-user-update",
    );
    assert_dao_error(repo.delete(TENANT_A, "u-1").await, "app-user-delete");
    assert_dao_error(repo.list(TENANT_A, 0, 100).await, "app-user-list");
}

/// ACC-REPO-014（异常）：RoleRepository 缺表——create/find_by_id/
/// find_by_code/update/delete/list 全部返回 Dao 错误而非 panic。
/// 迁自 tests/repository/error_paths.rs::role_repo_*（6 例合并）
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_014_role_repo_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusRoleRepository::new(pool);
    assert_dao_error(
        repo.find_by_id(TENANT_A, "r-1").await,
        "app-role-find-by-id",
    );
    assert_dao_error(
        repo.find_by_code(TENANT_A, "admin").await,
        "app-role-find-by-code",
    );
    assert_dao_error(
        repo.create(
            TENANT_A,
            NewRole {
                code: "admin".to_string(),
                name: "Admin".to_string(),
                description: None,
                is_system: false,
            },
        )
        .await,
        "app-role-create",
    );
    assert_dao_error(
        repo.update(TENANT_A, "r-1", Some("c".to_string()), None, None)
            .await,
        "app-role-update",
    );
    assert_dao_error(repo.delete(TENANT_A, "r-1").await, "app-role-delete");
    assert_dao_error(repo.list(TENANT_A, 0, 100).await, "app-role-list");
}

/// ACC-REPO-015（异常）：PermissionRepository 缺表——create/find_by_id/
/// find_by_code/update/delete/list 全部返回 Dao 错误而非 panic。
/// 迁自 tests/repository/error_paths.rs::perm_repo_*（6 例合并）
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_015_permission_repo_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusPermissionRepository::new(pool);
    assert_dao_error(repo.find_by_id("p-1").await, "app-permission-find-by-id");
    assert_dao_error(
        repo.find_by_code("user:read").await,
        "app-permission-find-by-code",
    );
    assert_dao_error(
        repo.create(NewPermission {
            code: "user:read".to_string(),
            name: "Read".to_string(),
            resource_type: None,
            action: None,
        })
        .await,
        "app-permission-create",
    );
    assert_dao_error(
        repo.update("p-1", Some("n".to_string()), None, None).await,
        "app-permission-update",
    );
    assert_dao_error(repo.delete("p-1").await, "app-permission-delete");
    assert_dao_error(repo.list(0, 100).await, "app-permission-list");
}

/// ACC-REPO-016（异常）：UserRoleRepository 缺表——assign/find_by_user_id/
/// find_by_role_id/revoke 全部返回 Dao 错误而非 panic。
/// 迁自 tests/repository/error_paths.rs::user_role_repo_*（4 例合并）
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_016_user_role_repo_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserRoleRepository::new(pool);
    assert_dao_error(
        repo.assign(TENANT_A, "u-1", "r-1", None).await,
        "app-user-role-assign",
    );
    assert_dao_error(
        repo.find_by_user_id(TENANT_A, "u-1").await,
        "app-user-role-find-by-user-id",
    );
    assert_dao_error(
        repo.find_by_role_id(TENANT_A, "r-1").await,
        "app-user-role-find-by-role-id",
    );
    assert_dao_error(
        repo.revoke(TENANT_A, "u-1", "r-1").await,
        "app-user-role-revoke",
    );
}

/// ACC-REPO-017（异常）：RolePermissionRepository 缺表——assign/find_by_role_id/
/// find_by_permission_id/revoke 全部返回 Dao 错误而非 panic。
/// 迁自 tests/repository/error_paths.rs::role_perm_repo_*（4 例合并）
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_017_role_permission_repo_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusRolePermissionRepository::new(pool);
    assert_dao_error(
        repo.assign(TENANT_A, "r-1", "p-1").await,
        "app-role-permission-assign",
    );
    assert_dao_error(
        repo.find_by_role_id(TENANT_A, "r-1").await,
        "app-role-permission-find-by-role-id",
    );
    assert_dao_error(
        repo.find_by_permission_id(TENANT_A, "p-1").await,
        "app-role-permission-find-by-permission-id",
    );
    assert_dao_error(
        repo.revoke(TENANT_A, "r-1", "p-1").await,
        "app-role-permission-revoke",
    );
}

/// ACC-REPO-018（异常）：AuthMethodRepository 缺表——create/find_by_user_id/
/// find_by_id/delete 全部返回 Dao 错误而非 panic。
/// 迁自 tests/repository/error_paths.rs::auth_method_repo_*（4 例合并）
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_018_auth_method_repo_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusAuthMethodRepository::new(pool);
    assert_dao_error(
        repo.create(
            TENANT_A,
            NewAuthMethod {
                user_id: "u-1".to_string(),
                method_type: "password".to_string(),
                external_id: None,
                metadata: None,
            },
        )
        .await,
        "app-auth-method-create",
    );
    assert_dao_error(
        repo.find_by_user_id(TENANT_A, "u-1").await,
        "app-auth-method-find-by-user-id",
    );
    assert_dao_error(
        repo.find_by_id(TENANT_A, "m-1").await,
        "app-auth-method-find-by-id",
    );
    assert_dao_error(repo.delete(TENANT_A, "m-1").await, "app-auth-method-delete");
}

/// ACC-REPO-019（异常）：SessionRepository 缺表——create/find_by_session_id/
/// find_by_user_id/update_last_active/delete 全部返回 Dao 错误而非 panic。
/// 迁自 tests/repository/error_paths.rs::session_repo_*（5 例合并）
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_019_session_repo_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusSessionRepository::new(pool);
    assert_dao_error(
        repo.create(
            TENANT_A,
            NewSession {
                session_id: "s-1".to_string(),
                user_id: "u-1".to_string(),
                device_id: None,
                ip: None,
                user_agent: None,
                expire_time: None,
            },
        )
        .await,
        "app-session-create",
    );
    assert_dao_error(
        repo.find_by_session_id(TENANT_A, "s-1").await,
        "app-session-find-by-session-id",
    );
    assert_dao_error(
        repo.find_by_user_id(TENANT_A, "u-1").await,
        "app-session-find-by-user-id",
    );
    assert_dao_error(
        repo.update_last_active(TENANT_A, "s-1").await,
        "app-session-update-last-active",
    );
    assert_dao_error(repo.delete(TENANT_A, "s-1").await, "app-session-delete");
}

/// ACC-REPO-020（异常）：LoginLogRepository 缺表——create/find_by_id/
/// find_by_user_id 全部返回 Dao 错误而非 panic。
/// 迁自 tests/repository/error_paths.rs::login_log_repo_*（3 例合并）
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_020_login_log_repo_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusLoginLogRepository::new(pool);
    assert_dao_error(
        repo.create(
            TENANT_A,
            NewLoginLog {
                user_id: Some("u-1".to_string()),
                action: "login".to_string(),
                ip: None,
                device_id: None,
                success: true,
                fail_reason: None,
            },
        )
        .await,
        "app-login-log-create",
    );
    assert_dao_error(
        repo.find_by_id(TENANT_A, "log-1").await,
        "app-login-log-find-by-id",
    );
    assert_dao_error(
        repo.find_by_user_id(TENANT_A, "u-1", 0, 100).await,
        "app-login-log-find-by-user-id",
    );
}

/// ACC-REPO-021（异常）：UserExtRepository 缺表——upsert/find_by_user_and_key/
/// find_by_user_id 全部返回 Dao 错误而非 panic。
/// 迁自 tests/repository/error_paths.rs::user_ext_repo_*（3 例合并）
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_021_user_ext_repo_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserExtRepository::new(pool);
    assert_dao_error(
        repo.upsert(TENANT_A, "u-1", "email", Some("v".to_string()), "string")
            .await,
        "app-user-ext-upsert",
    );
    assert_dao_error(
        repo.find_by_user_and_key(TENANT_A, "u-1", "email").await,
        "app-user-ext-find-by-user-and-key",
    );
    assert_dao_error(
        repo.find_by_user_id(TENANT_A, "u-1").await,
        "app-user-ext-find-by-user-id",
    );
}

/// ACC-REPO-022（异常）：UserDeviceRepository 缺表——register_device /
/// list_user_devices / count_user_devices / block_device 全部返回 Dao 错误
/// 而非 panic（errors 消息含 `app-user-device` 前缀）。
/// 语义同 tests/repository/error_paths.rs（该文件未含 device 表，此处补齐）
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_022_user_device_repo_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserDeviceRepository::new(pool);
    assert_dao_error(
        repo.register_device(TENANT_A, "1001", "fingerprint-001", UA_CHROME_WIN)
            .await,
        "app-user-device",
    );
    assert_dao_error(
        repo.list_user_devices(TENANT_A, "1001").await,
        "app-user-device",
    );
    assert_dao_error(
        repo.count_user_devices(TENANT_A, "1001").await,
        "app-user-device",
    );
    assert_dao_error(repo.block_device("d-1").await, "app-user-device");
}

// ------------------------------------------------------------------------
// ACC-REPO-023..030：dbnexus 层语义与未吸收用例
// （迁自 tests/repository/dbnexus_integration.rs 与
//   tests/repository/integration.rs / error_paths.rs 的未覆盖用例，
//   Phase 4 迁移追溯）
// ------------------------------------------------------------------------

/// ACC-REPO-023（正常）：迁移产物精确断言——`migrate_core` 后 sqlite_master
/// 恰含 10 张 `app_%` 核心表（全名单）且索引 ≥ 15 个
///（`idx_app_%` / `uk_app_%` 前缀）。
/// 迁自 tests/repository/dbnexus_integration.rs::integration_migrate_creates_all_tables
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_023_migrate_creates_all_ten_core_tables() {
    let pool = setup_db().await;
    let session = pool.get_session("admin").await.expect("get_session 应成功");

    let tables = query_all_strings(
        &session,
        "SELECT name AS val FROM sqlite_master WHERE type='table' AND name LIKE 'app_%' ORDER BY name",
    )
    .await;
    assert_eq!(
        tables,
        vec![
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
        ],
        "应创建 10 张 app_ 前缀核心表，实际: {:?}",
        tables
    );

    let index_count = query_count(
        &session,
        "SELECT count(*) AS cnt FROM sqlite_master WHERE type='index' AND name LIKE 'idx_app_%' OR name LIKE 'uk_app_%'",
    )
    .await;
    assert!(
        index_count >= 15,
        "应至少创建 15 个索引，实际: {}",
        index_count
    );
}

/// ACC-REPO-024（正常）：多租户隔离——跨租户 `find_by_id` 互不可见、list 按
/// 租户过滤、同名 username 可在不同租户共存（DB 级唯一为 (tenant_id, username)）、
/// UserRole 关联按租户隔离（A 的角色列表不含 B 的角色）。
/// 迁自 tests/repository/integration.rs::user_repository_tenant_isolation、
/// user_role_repository_tenant_isolation 与
/// tests/repository/dbnexus_integration.rs::integration_multi_tenant_isolation（3 例合并）
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_024_multi_tenant_isolation() {
    let pool = setup_db().await;
    let user_repo = DbnexusUserRepository::new(pool.clone());
    let role_repo = DbnexusRoleRepository::new(pool.clone());
    let ur_repo = DbnexusUserRoleRepository::new(pool);

    // 1. 跨租户不可见 + list 隔离
    let user_a = user_repo
        .create(
            TENANT_A,
            NewUser {
                username: "tenant-a-user".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();
    let user_b = user_repo
        .create(
            TENANT_B,
            NewUser {
                username: "tenant-b-user".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();

    assert!(
        user_repo
            .find_by_id(TENANT_A, &user_b)
            .await
            .unwrap()
            .is_none(),
        "tenant A 不应查到 tenant B 的用户"
    );
    assert!(
        user_repo
            .find_by_id(TENANT_B, &user_a)
            .await
            .unwrap()
            .is_none(),
        "tenant B 不应查到 tenant A 的用户"
    );

    let list_a = user_repo.list(TENANT_A, 0, 100).await.unwrap();
    let list_b = user_repo.list(TENANT_B, 0, 100).await.unwrap();
    let a_ids: Vec<_> = list_a.iter().map(|u| u.id.clone()).collect();
    let b_ids: Vec<_> = list_b.iter().map(|u| u.id.clone()).collect();
    assert!(
        a_ids.contains(&user_a) && !a_ids.contains(&user_b),
        "list_A 应只含 A 用户"
    );
    assert!(
        b_ids.contains(&user_b) && !b_ids.contains(&user_a),
        "list_B 应只含 B 用户"
    );

    // 2. 同名 username 跨租户共存（镜 dbnexus_integration::integration_multi_tenant_isolation）
    let dup_a = user_repo
        .create(
            TENANT_A,
            NewUser {
                username: "alice".to_string(),
                password_hash: "h1".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();
    let dup_b = user_repo
        .create(
            TENANT_B,
            NewUser {
                username: "alice".to_string(),
                password_hash: "h2".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        user_repo
            .find_by_username(TENANT_A, "alice")
            .await
            .unwrap()
            .unwrap()
            .id,
        dup_a,
        "tenant A 的 alice 应可见"
    );
    assert_eq!(
        user_repo
            .find_by_username(TENANT_B, "alice")
            .await
            .unwrap()
            .unwrap()
            .id,
        dup_b,
        "tenant B 的同名 alice 也应可见（多租户共存）"
    );

    // 3. UserRole 关联按租户隔离
    let role_a = role_repo
        .create(
            TENANT_A,
            NewRole {
                code: "r-a".to_string(),
                name: "R-A".to_string(),
                description: None,
                is_system: false,
            },
        )
        .await
        .unwrap();
    let role_b = role_repo
        .create(
            TENANT_B,
            NewRole {
                code: "r-b".to_string(),
                name: "R-B".to_string(),
                description: None,
                is_system: false,
            },
        )
        .await
        .unwrap();
    ur_repo
        .assign(TENANT_A, &user_a, &role_a, None)
        .await
        .unwrap();
    ur_repo
        .assign(TENANT_B, &user_b, &role_b, None)
        .await
        .unwrap();

    let a_roles = ur_repo.find_by_user_id(TENANT_A, &user_a).await.unwrap();
    assert_eq!(a_roles.len(), 1);
    assert_eq!(
        a_roles[0].role_id, role_a,
        "tenant A 不应包含 tenant B 的角色"
    );
    let b_roles = ur_repo.find_by_user_id(TENANT_B, &user_b).await.unwrap();
    assert_eq!(b_roles.len(), 1);
    assert_eq!(
        b_roles[0].role_id, role_b,
        "tenant B 不应包含 tenant A 的角色"
    );
}

/// ACC-REPO-025（正常）：RBAC 全链——user → role → permission 链式查询
/// 返回用户全部权限编码（精确集合相等，排序后比对）。
/// 迁自 tests/repository/integration.rs::rbac_full_chain_user_to_permissions 与
/// tests/repository/dbnexus_integration.rs::integration_rbac_full_flow（2 例合并）
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_025_rbac_full_chain_user_to_permissions() {
    let pool = setup_db().await;
    let user_repo = DbnexusUserRepository::new(pool.clone());
    let role_repo = DbnexusRoleRepository::new(pool.clone());
    let perm_repo = DbnexusPermissionRepository::new(pool.clone());
    let ur_repo = DbnexusUserRoleRepository::new(pool.clone());
    let rp_repo = DbnexusRolePermissionRepository::new(pool);

    let user_id = user_repo
        .create(
            TENANT_A,
            NewUser {
                username: "grace".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();
    let role_id = role_repo
        .create(
            TENANT_A,
            NewRole {
                code: "manager".to_string(),
                name: "Manager".to_string(),
                description: None,
                is_system: false,
            },
        )
        .await
        .unwrap();
    let perm1_id = perm_repo
        .create(NewPermission {
            code: "report:read".to_string(),
            name: "Read Report".to_string(),
            resource_type: Some("report".to_string()),
            action: Some("read".to_string()),
        })
        .await
        .unwrap();
    let perm2_id = perm_repo
        .create(NewPermission {
            code: "report:export".to_string(),
            name: "Export Report".to_string(),
            resource_type: Some("report".to_string()),
            action: Some("export".to_string()),
        })
        .await
        .unwrap();

    ur_repo
        .assign(TENANT_A, &user_id, &role_id, None)
        .await
        .unwrap();
    rp_repo.assign(TENANT_A, &role_id, &perm1_id).await.unwrap();
    rp_repo.assign(TENANT_A, &role_id, &perm2_id).await.unwrap();

    // user → role → permission 链式查询，收集全部权限编码
    let user_roles = ur_repo.find_by_user_id(TENANT_A, &user_id).await.unwrap();
    assert_eq!(user_roles.len(), 1, "用户应恰有 1 个角色");
    let mut user_perms: Vec<String> = Vec::new();
    for ur in &user_roles {
        let rps = rp_repo
            .find_by_role_id(TENANT_A, &ur.role_id)
            .await
            .unwrap();
        for rp in rps {
            if let Some(p) = perm_repo.find_by_id(&rp.permission_id).await.unwrap() {
                user_perms.push(p.code);
            }
        }
    }

    // 精确集合相等（排序后比对，等价于 dbnexus JOIN 查询的精确断言）
    user_perms.sort();
    assert_eq!(
        user_perms,
        vec!["report:export".to_string(), "report:read".to_string()],
        "用户应持有 report:read + report:export（且无多余权限）"
    );
}

/// ACC-REPO-026（正常+异常）：UserDevice 多设备与租户隔离——多 UA 注册 3 设备
/// 全量列表返回、count 初始 0 后随注册增长、跨租户设备互不可见（list/count
/// 均隔离）。
/// 迁自 tests/repository/integration.rs::list_user_devices_returns_all、
/// count_user_devices_returns_count、list_user_devices_tenant_isolation（3 例合并）
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_026_user_device_multi_and_tenant_isolation() {
    let pool = setup_db().await;
    let repo = DbnexusUserDeviceRepository::new(pool);

    // 1. count 初始为 0
    assert_eq!(
        repo.count_user_devices(TENANT_A, "7007").await.unwrap(),
        0,
        "初始 count 应为 0"
    );

    // 2. 多 UA 注册 3 设备，list 全量返回且租户/主体字段正确
    for i in 0..3 {
        let identifier = format!("list-fp-{i}");
        let ua = if i % 2 == 0 {
            UA_CHROME_WIN
        } else {
            UA_SAFARI_MAC
        };
        repo.register_device(TENANT_A, "6006", &identifier, ua)
            .await
            .expect("注册应成功");
    }
    let devices = repo.list_user_devices(TENANT_A, "6006").await.unwrap();
    assert_eq!(devices.len(), 3, "应返回 3 个设备");
    for d in &devices {
        assert_eq!(d.tenant_id, TENANT_A);
        assert_eq!(d.login_id, "6006".to_string());
    }

    // 3. count 随注册增长
    repo.register_device(TENANT_A, "7007", "cnt-fp-1", UA_CHROME_WIN)
        .await
        .unwrap();
    repo.register_device(TENANT_A, "7007", "cnt-fp-2", UA_SAFARI_MAC)
        .await
        .unwrap();
    assert_eq!(
        repo.count_user_devices(TENANT_A, "7007").await.unwrap(),
        2,
        "注册 2 个后 count 应为 2"
    );

    // 4. 租户隔离：tenant A 2 个 + tenant B 1 个（相同 login_id）
    repo.register_device(TENANT_A, "8008", "tenant-a-fp-1", UA_CHROME_WIN)
        .await
        .unwrap();
    repo.register_device(TENANT_A, "8008", "tenant-a-fp-2", UA_SAFARI_MAC)
        .await
        .unwrap();
    repo.register_device(TENANT_B, "8008", "tenant-b-fp-1", UA_CHROME_WIN)
        .await
        .unwrap();

    let list_a = repo.list_user_devices(TENANT_A, "8008").await.unwrap();
    assert_eq!(list_a.len(), 2, "tenant A 应只见 2 个设备");
    for d in &list_a {
        assert_eq!(d.tenant_id, TENANT_A, "tenant A 列表不应包含其他租户设备");
    }
    let list_b = repo.list_user_devices(TENANT_B, "8008").await.unwrap();
    assert_eq!(list_b.len(), 1, "tenant B 应只见 1 个设备");
    assert_eq!(list_b[0].tenant_id, TENANT_B);

    let count_a = repo.count_user_devices(TENANT_A, "8008").await.unwrap();
    let count_b = repo.count_user_devices(TENANT_B, "8008").await.unwrap();
    assert_eq!(count_a, 2);
    assert_eq!(count_b, 1);
}

/// ACC-REPO-027（正常）：空字段 `update` 返回 Ok 且不触达 DB（`sets.is_empty()`
/// 短路分支）——在**未迁移**库上同样 Ok（不因缺表失败），覆盖
/// error_paths 42 例中唯一非缺表断言分支。
/// 迁自 tests/repository/error_paths.rs::user_repo_update_empty_fields_returns_ok
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_027_empty_update_fields_returns_ok() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserRepository::new(pool);
    let result = repo.update(TENANT_A, "u-1", UpdateUser::default()).await;
    assert!(
        result.is_ok(),
        "空 update 应返回 Ok 而不调 DB（未迁移库上也不报缺表错误）"
    );
}

/// ACC-REPO-028（异常）：`app_user_ext` 唯一约束——重复 `(user_id, field_key)`
/// 插入被数据库唯一索引拒绝（显性 Err 而非静默覆盖）；KV 读写语义已由
/// ACC-REPO-009 覆盖（此处仅移植唯一约束部分）。
/// 迁自 tests/repository/dbnexus_integration.rs::integration_user_ext_kv_crud
///（唯一约束断言部分）
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_028_user_ext_unique_constraint_rejects_duplicate() {
    let pool = setup_db().await;
    let session = pool.get_session("admin").await.expect("get_session 应成功");

    session
        .execute_raw(
            "INSERT INTO app_user (id, username, password_hash, status, tenant_id) \
             VALUES ('ue1', 'kv_user', 'hash', 'active', 1)",
        )
        .await
        .expect("INSERT user 应成功");
    session
        .execute_raw(
            "INSERT INTO app_user_ext (id, user_id, field_key, field_value, field_type, tenant_id) \
             VALUES ('e1', 'ue1', 'email', 'alice@example.com', 'string', 1)",
        )
        .await
        .expect("INSERT ext 应成功");

    // 重复 (user_id, field_key) → 唯一约束拒绝
    let dup_result = session
        .execute_raw(
            "INSERT INTO app_user_ext (id, user_id, field_key, field_value, field_type, tenant_id) \
             VALUES ('e3', 'ue1', 'email', 'dup@example.com', 'string', 1)",
        )
        .await;
    assert!(
        dup_result.is_err(),
        "重复 (user_id, field_key) 应被唯一约束拒绝"
    );
}

/// ACC-REPO-029（异常+正常）：CHECK 约束——`app_user.status` 非法值被拒、
/// 5 个合法值（pending/active/suspended/inactive/deleted）通过；
/// `app_auth_method.method_type` 非法值被拒、4 个合法值通过。
/// 迁自 tests/repository/dbnexus_integration.rs::integration_check_constraint_status
/// 与 integration_check_constraint_auth_method（2 例合并）
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_029_check_constraints_reject_invalid_values() {
    let pool = setup_db().await;
    let session = pool.get_session("admin").await.expect("get_session 应成功");

    // status CHECK：非法值拒绝
    let invalid = session
        .execute_raw(
            "INSERT INTO app_user (id, username, password_hash, status, tenant_id) \
             VALUES ('ck1', 'check_user', 'h', 'invalid_status', 1)",
        )
        .await;
    assert!(invalid.is_err(), "非法 status 应被 CHECK 约束拒绝");

    // status CHECK：5 个合法值全部通过
    for status in ["pending", "active", "suspended", "inactive", "deleted"] {
        let result = session
            .execute_raw(&format!(
                "INSERT INTO app_user (id, username, password_hash, status, tenant_id) \
                 VALUES ('ck_{status}', 'ck_{status}', 'h', '{status}', 1)"
            ))
            .await;
        assert!(
            result.is_ok(),
            "合法 status '{status}' 应被接受: {:?}",
            result.err()
        );
    }

    // auth_method CHECK：先建用户（外键依赖），合法值通过、非法值拒绝
    session
        .execute_raw(
            "INSERT INTO app_user (id, username, password_hash, status, tenant_id) \
             VALUES ('am1', 'am_user', 'h', 'active', 1)",
        )
        .await
        .expect("INSERT user 应成功");
    for mt in ["passkey", "password", "oauth", "did"] {
        let result = session
            .execute_raw(&format!(
                "INSERT INTO app_auth_method (id, user_id, method_type, tenant_id) \
                 VALUES ('am_{mt}', 'am1', '{mt}', 1)"
            ))
            .await;
        assert!(result.is_ok(), "合法 method_type '{mt}' 应被接受");
    }
    let invalid = session
        .execute_raw(
            "INSERT INTO app_auth_method (id, user_id, method_type, tenant_id) \
             VALUES ('am_bad', 'am1', 'unknown_method', 1)",
        )
        .await;
    assert!(invalid.is_err(), "非法 method_type 应被 CHECK 约束拒绝");
}

/// ACC-REPO-030（正常）：业务级事务回滚——begin → 跨表 INSERT
///（user/role/user_role）→ rollback 后全部不可见（原子性）。
/// 迁自 tests/repository/dbnexus_integration.rs::integration_multi_table_transaction_rollback
#[tokio::test(flavor = "multi_thread")]
async fn acc_repo_030_transaction_rollback_hides_writes() {
    let pool = setup_db().await;
    let session = pool.get_session("admin").await.expect("get_session 应成功");

    session.begin_transaction().await.expect("begin 应成功");
    session
        .execute_raw(
            "INSERT INTO app_user (id, username, password_hash, status, tenant_id) \
             VALUES ('tu1', 'txn_user', 'h', 'active', 1)",
        )
        .await
        .expect("事务内 INSERT user 应成功");
    session
        .execute_raw(
            "INSERT INTO app_role (id, code, name, tenant_id, is_system) \
             VALUES ('tr1', 'txn_role', 'TR', 1, 0)",
        )
        .await
        .expect("事务内 INSERT role 应成功");
    session
        .execute_raw(
            "INSERT INTO app_user_role (user_id, role_id, tenant_id) VALUES ('tu1', 'tr1', 1)",
        )
        .await
        .expect("事务内 INSERT user_role 应成功");

    session.rollback().await.expect("rollback 应成功");

    assert_eq!(
        query_count(
            &session,
            "SELECT count(*) AS cnt FROM app_user WHERE id = 'tu1'"
        )
        .await,
        0,
        "回滚后 user 应不存在"
    );
    assert_eq!(
        query_count(
            &session,
            "SELECT count(*) AS cnt FROM app_role WHERE id = 'tr1'"
        )
        .await,
        0,
        "回滚后 role 应不存在"
    );
    assert_eq!(
        query_count(
            &session,
            "SELECT count(*) AS cnt FROM app_user_role WHERE user_id = 'tu1'"
        )
        .await,
        0,
        "回滚后 user_role 应不存在"
    );
}
