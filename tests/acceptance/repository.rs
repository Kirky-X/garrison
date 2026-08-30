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

/// 测试用 UA 字符串（Chrome on Windows，迁自 tests/repository/integration.rs）。
const UA_CHROME_WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
    AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36";

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
