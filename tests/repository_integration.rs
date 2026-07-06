//! Repository 层 9 trait 端到端集成测试（v0.4.2 新增，依据 spec repository-layer）。
//!
//! 验证 9 个 `SqliteXxxRepository` 在真实 SQLite in-memory + 迁移后的 CRUD 行为：
//! 1. `UserRepository`：create / find_by_id / find_by_username / update / delete / list
//! 2. `RoleRepository`：create / find_by_id / find_by_code / update / delete
//! 3. `PermissionRepository`：create / find_by_id / find_by_code / update / delete
//! 4. `UserRoleRepository`：assign / find_by_user_id / find_by_role_id / revoke
//! 5. `RolePermissionRepository`：assign / find_by_role_id / revoke
//! 6. `AuthMethodRepository`：create / find_by_user_id / delete
//! 7. `SessionRepository`：create / find_by_session_id / find_by_user_id / update_last_active / delete
//! 8. `LoginLogRepository`：create / find_by_user_id / find_by_id
//! 9. `UserExtRepository`：upsert / find_by_user_and_key / find_by_user_id
//! 10. 多租户隔离：不同 tenant_id 数据互不可见
//!
//! 运行：`cargo test --features "db-sqlite" --test repository_integration`

#![cfg(feature = "db-sqlite")]

use bulwark::dao::{
    init_dbnexus,
    repository::{
        sqlite::{
            DbnexusAuthMethodRepository, DbnexusLoginLogRepository, DbnexusPermissionRepository,
            DbnexusRolePermissionRepository, DbnexusRoleRepository, DbnexusSessionRepository,
            DbnexusUserExtRepository, DbnexusUserRepository, DbnexusUserRoleRepository,
        },
        AuthMethodRepository, LoginLogRepository, NewAuthMethod, NewLoginLog, NewPermission,
        NewRole, NewSession, NewUser, PermissionRepository, RolePermissionRepository,
        RoleRepository, SessionRepository, UpdateUser, UserExtRepository, UserRepository,
        UserRoleRepository,
    },
    BulwarkMigration,
};
use std::path::PathBuf;

const TENANT_A: i64 = 1;
const TENANT_B: i64 = 2;

// ============================================================================
// 辅助：定位迁移目录 + 初始化 SQLite in-memory + 迁移
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
    let migration = BulwarkMigration::with_base_dir(pool.clone(), project_migrations_dir());
    let applied = migration.migrate_core().await.expect("migrate_core 应成功");
    assert!(applied >= 1, "migrate_core 应至少执行 1 个文件");
    pool
}

fn uuid_str() -> String {
    uuid::Uuid::new_v4().to_string()
}

// ============================================================================
// 1. UserRepository CRUD
// ============================================================================

/// UserRepository：create → find_by_id → find_by_username → update → list → delete。
#[tokio::test(flavor = "multi_thread")]
async fn user_repository_full_crud() {
    let pool = setup_db().await;
    let repo = DbnexusUserRepository::new(pool);

    let user_id = uuid_str();
    repo.create(
        TENANT_A,
        NewUser {
            id: user_id.clone(),
            username: "alice".to_string(),
            password_hash: "hashed".to_string(),
            status: "active".to_string(),
        },
    )
    .await
    .expect("create 应成功");

    // find_by_id
    let found = repo.find_by_id(TENANT_A, &user_id).await.unwrap();
    assert!(found.is_some(), "find_by_id 应返回 Some");
    let row = found.unwrap();
    assert_eq!(row.id, user_id);
    assert_eq!(row.username, "alice");
    assert_eq!(row.status, "active");
    assert_eq!(row.tenant_id, TENANT_A);

    // find_by_username
    let by_name = repo.find_by_username(TENANT_A, "alice").await.unwrap();
    assert!(by_name.is_some(), "find_by_username 应返回 Some");
    assert_eq!(by_name.unwrap().id, user_id);

    // update
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

    // list
    let list = repo.list(TENANT_A, 0, 100).await.unwrap();
    assert!(!list.is_empty(), "list 应返回非空");

    // delete（幂等）
    repo.delete(TENANT_A, &user_id).await.unwrap();
    repo.delete(TENANT_A, &user_id).await.unwrap(); // 幂等
    let after_delete = repo.find_by_id(TENANT_A, &user_id).await.unwrap();
    assert!(after_delete.is_none(), "delete 后 find_by_id 应返回 None");
}

// ============================================================================
// 2. RoleRepository CRUD
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn role_repository_full_crud() {
    let pool = setup_db().await;
    let repo = DbnexusRoleRepository::new(pool);

    let role_id = uuid_str();
    repo.create(
        TENANT_A,
        NewRole {
            id: role_id.clone(),
            code: "admin".to_string(),
            name: "Administrator".to_string(),
            description: Some("full access".to_string()),
            is_system: false,
        },
    )
    .await
    .unwrap();

    // find_by_id
    let by_id = repo.find_by_id(TENANT_A, &role_id).await.unwrap();
    assert!(by_id.is_some());
    assert_eq!(by_id.unwrap().code, "admin");

    // find_by_code
    let by_code = repo.find_by_code(TENANT_A, "admin").await.unwrap();
    assert!(by_code.is_some());
    assert_eq!(by_code.unwrap().id, role_id);

    // update
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

    // delete
    repo.delete(TENANT_A, &role_id).await.unwrap();
    assert!(repo.find_by_id(TENANT_A, &role_id).await.unwrap().is_none());
}

// ============================================================================
// 3. PermissionRepository CRUD
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn permission_repository_full_crud() {
    let pool = setup_db().await;
    let repo = DbnexusPermissionRepository::new(pool);

    let perm_id = uuid_str();
    repo.create(NewPermission {
        id: perm_id.clone(),
        code: "user:read".to_string(),
        name: "Read User".to_string(),
        resource_type: Some("user".to_string()),
        action: Some("read".to_string()),
    })
    .await
    .unwrap();

    // find_by_id
    let by_id = repo.find_by_id(&perm_id).await.unwrap();
    assert!(by_id.is_some());
    assert_eq!(by_id.unwrap().code, "user:read");

    // find_by_code
    let by_code = repo.find_by_code("user:read").await.unwrap();
    assert!(by_code.is_some());
    assert_eq!(by_code.unwrap().id, perm_id);

    // update
    repo.update(&perm_id, Some("Read All Users".to_string()), None, None)
        .await
        .unwrap();
    let updated = repo.find_by_id(&perm_id).await.unwrap().unwrap();
    assert_eq!(updated.name, "Read All Users");

    // delete
    repo.delete(&perm_id).await.unwrap();
    assert!(repo.find_by_id(&perm_id).await.unwrap().is_none());
}

// ============================================================================
// 4. UserRoleRepository 关联
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn user_role_repository_assign_find_revoke() {
    let pool = setup_db().await;
    let user_repo = DbnexusUserRepository::new(pool.clone());
    let role_repo = DbnexusRoleRepository::new(pool.clone());
    let user_role_repo = DbnexusUserRoleRepository::new(pool);

    let user_id = uuid_str();
    let role_id = uuid_str();
    user_repo
        .create(
            TENANT_A,
            NewUser {
                id: user_id.clone(),
                username: "bob".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();
    role_repo
        .create(
            TENANT_A,
            NewRole {
                id: role_id.clone(),
                code: "editor".to_string(),
                name: "Editor".to_string(),
                description: None,
                is_system: false,
            },
        )
        .await
        .unwrap();

    // assign
    user_role_repo
        .assign(TENANT_A, &user_id, &role_id, Some("scope1".to_string()))
        .await
        .unwrap();

    // find_by_user_id
    let by_user = user_role_repo
        .find_by_user_id(TENANT_A, &user_id)
        .await
        .unwrap();
    assert_eq!(by_user.len(), 1);
    assert_eq!(by_user[0].role_id, role_id);
    assert_eq!(by_user[0].scope.as_deref(), Some("scope1"));

    // find_by_role_id
    let by_role = user_role_repo
        .find_by_role_id(TENANT_A, &role_id)
        .await
        .unwrap();
    assert_eq!(by_role.len(), 1);
    assert_eq!(by_role[0].user_id, user_id);

    // revoke（幂等）
    user_role_repo
        .revoke(TENANT_A, &user_id, &role_id)
        .await
        .unwrap();
    user_role_repo
        .revoke(TENANT_A, &user_id, &role_id)
        .await
        .unwrap();
    let after_revoke = user_role_repo
        .find_by_user_id(TENANT_A, &user_id)
        .await
        .unwrap();
    assert!(after_revoke.is_empty(), "revoke 后应无关联");
}

// ============================================================================
// 5. RolePermissionRepository 关联
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn role_permission_repository_assign_find_revoke() {
    let pool = setup_db().await;
    let role_repo = DbnexusRoleRepository::new(pool.clone());
    let perm_repo = DbnexusPermissionRepository::new(pool.clone());
    let rp_repo = DbnexusRolePermissionRepository::new(pool);

    let role_id = uuid_str();
    let perm_id = uuid_str();
    role_repo
        .create(
            TENANT_A,
            NewRole {
                id: role_id.clone(),
                code: "viewer".to_string(),
                name: "Viewer".to_string(),
                description: None,
                is_system: false,
            },
        )
        .await
        .unwrap();
    perm_repo
        .create(NewPermission {
            id: perm_id.clone(),
            code: "doc:read".to_string(),
            name: "Read Doc".to_string(),
            resource_type: Some("doc".to_string()),
            action: Some("read".to_string()),
        })
        .await
        .unwrap();

    // assign
    rp_repo.assign(TENANT_A, &role_id, &perm_id).await.unwrap();

    // find_by_role_id
    let by_role = rp_repo.find_by_role_id(TENANT_A, &role_id).await.unwrap();
    assert_eq!(by_role.len(), 1);
    assert_eq!(by_role[0].permission_id, perm_id);

    // find_by_permission_id
    let by_perm = rp_repo
        .find_by_permission_id(TENANT_A, &perm_id)
        .await
        .unwrap();
    assert_eq!(by_perm.len(), 1);
    assert_eq!(by_perm[0].role_id, role_id);

    // revoke（幂等）
    rp_repo.revoke(TENANT_A, &role_id, &perm_id).await.unwrap();
    rp_repo.revoke(TENANT_A, &role_id, &perm_id).await.unwrap();
    let after = rp_repo.find_by_role_id(TENANT_A, &role_id).await.unwrap();
    assert!(after.is_empty(), "revoke 后应无关联");
}

// ============================================================================
// 6. AuthMethodRepository
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn auth_method_repository_create_find_delete() {
    let pool = setup_db().await;
    let user_repo = DbnexusUserRepository::new(pool.clone());
    let auth_repo = DbnexusAuthMethodRepository::new(pool);

    let user_id = uuid_str();
    user_repo
        .create(
            TENANT_A,
            NewUser {
                id: user_id.clone(),
                username: "charlie".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();

    let method_id = uuid_str();
    auth_repo
        .create(
            TENANT_A,
            NewAuthMethod {
                id: method_id.clone(),
                user_id: user_id.clone(),
                method_type: "password".to_string(),
                external_id: None,
                metadata: Some(r#"{"v":1}"#.to_string()),
            },
        )
        .await
        .unwrap();

    // find_by_user_id
    let by_user = auth_repo.find_by_user_id(TENANT_A, &user_id).await.unwrap();
    assert_eq!(by_user.len(), 1);
    assert_eq!(by_user[0].method_type, "password");

    // find_by_id
    let by_id = auth_repo.find_by_id(TENANT_A, &method_id).await.unwrap();
    assert!(by_id.is_some());

    // delete（幂等）
    auth_repo.delete(TENANT_A, &method_id).await.unwrap();
    auth_repo.delete(TENANT_A, &method_id).await.unwrap();
    let after = auth_repo.find_by_user_id(TENANT_A, &user_id).await.unwrap();
    assert!(after.is_empty());
}

// ============================================================================
// 7. SessionRepository
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn session_repository_create_find_update_delete() {
    let pool = setup_db().await;
    let user_repo = DbnexusUserRepository::new(pool.clone());
    let session_repo = DbnexusSessionRepository::new(pool);

    let user_id = uuid_str();
    user_repo
        .create(
            TENANT_A,
            NewUser {
                id: user_id.clone(),
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

    // find_by_session_id
    let by_sid = session_repo
        .find_by_session_id(TENANT_A, &session_id)
        .await
        .unwrap();
    assert!(by_sid.is_some());
    assert_eq!(by_sid.unwrap().user_id, user_id);

    // find_by_user_id
    let by_user = session_repo
        .find_by_user_id(TENANT_A, &user_id)
        .await
        .unwrap();
    assert_eq!(by_user.len(), 1);

    // update_last_active
    session_repo
        .update_last_active(TENANT_A, &session_id)
        .await
        .unwrap();

    // delete（幂等）
    session_repo.delete(TENANT_A, &session_id).await.unwrap();
    session_repo.delete(TENANT_A, &session_id).await.unwrap();
    let after = session_repo
        .find_by_session_id(TENANT_A, &session_id)
        .await
        .unwrap();
    assert!(after.is_none());
}

// ============================================================================
// 8. LoginLogRepository
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn login_log_repository_create_find() {
    let pool = setup_db().await;
    let user_repo = DbnexusUserRepository::new(pool.clone());
    let log_repo = DbnexusLoginLogRepository::new(pool);

    let user_id = uuid_str();
    user_repo
        .create(
            TENANT_A,
            NewUser {
                id: user_id.clone(),
                username: "eve".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();

    let log_id = uuid_str();
    log_repo
        .create(
            TENANT_A,
            NewLoginLog {
                id: log_id.clone(),
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

    // find_by_id
    let by_id = log_repo.find_by_id(TENANT_A, &log_id).await.unwrap();
    assert!(by_id.is_some());
    assert_eq!(by_id.unwrap().action, "login");

    // find_by_user_id
    let by_user = log_repo
        .find_by_user_id(TENANT_A, &user_id, 0, 100)
        .await
        .unwrap();
    assert!(!by_user.is_empty());
}

// ============================================================================
// 9. UserExtRepository
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn user_ext_repository_upsert_find() {
    let pool = setup_db().await;
    let user_repo = DbnexusUserRepository::new(pool.clone());
    let ext_repo = DbnexusUserExtRepository::new(pool);

    let user_id = uuid_str();
    user_repo
        .create(
            TENANT_A,
            NewUser {
                id: user_id.clone(),
                username: "frank".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();

    // upsert（insert）
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

    // find_by_user_and_key
    let by_key = ext_repo
        .find_by_user_and_key(TENANT_A, &user_id, "email")
        .await
        .unwrap();
    assert!(by_key.is_some());
    assert_eq!(
        by_key.unwrap().field_value.as_deref(),
        Some("frank@example.com")
    );

    // upsert（update 同一 key）
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

    // find_by_user_id（多个 ext 字段）
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

// ============================================================================
// 10. 多租户隔离
// ============================================================================

/// 不同 tenant_id 的用户互不可见（spec R-004 多租户过滤）。
#[tokio::test(flavor = "multi_thread")]
async fn user_repository_tenant_isolation() {
    let pool = setup_db().await;
    let repo = DbnexusUserRepository::new(pool);

    let user_a = uuid_str();
    let user_b = uuid_str();
    repo.create(
        TENANT_A,
        NewUser {
            id: user_a.clone(),
            username: "tenant-a-user".to_string(),
            password_hash: "h".to_string(),
            status: "active".to_string(),
        },
    )
    .await
    .unwrap();
    repo.create(
        TENANT_B,
        NewUser {
            id: user_b.clone(),
            username: "tenant-b-user".to_string(),
            password_hash: "h".to_string(),
            status: "active".to_string(),
        },
    )
    .await
    .unwrap();

    // tenant A 查不到 tenant B 的用户
    let cross = repo.find_by_id(TENANT_A, &user_b).await.unwrap();
    assert!(cross.is_none(), "tenant A 不应查到 tenant B 的用户");

    // tenant B 查不到 tenant A 的用户
    let cross = repo.find_by_id(TENANT_B, &user_a).await.unwrap();
    assert!(cross.is_none(), "tenant B 不应查到 tenant A 的用户");

    // list 按 tenant 隔离
    let list_a = repo.list(TENANT_A, 0, 100).await.unwrap();
    let list_b = repo.list(TENANT_B, 0, 100).await.unwrap();
    let a_ids: Vec<_> = list_a.iter().map(|u| u.id.clone()).collect();
    let b_ids: Vec<_> = list_b.iter().map(|u| u.id.clone()).collect();
    assert!(a_ids.contains(&user_a) && !a_ids.contains(&user_b));
    assert!(b_ids.contains(&user_b) && !b_ids.contains(&user_a));
}

/// UserRole 关联按 tenant 隔离。
#[tokio::test(flavor = "multi_thread")]
async fn user_role_repository_tenant_isolation() {
    let pool = setup_db().await;
    let user_repo = DbnexusUserRepository::new(pool.clone());
    let role_repo = DbnexusRoleRepository::new(pool.clone());
    let ur_repo = DbnexusUserRoleRepository::new(pool);

    let user_a = uuid_str();
    let user_b = uuid_str();
    let role_a = uuid_str();
    let role_b = uuid_str();
    user_repo
        .create(
            TENANT_A,
            NewUser {
                id: user_a.clone(),
                username: "u-a".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();
    user_repo
        .create(
            TENANT_B,
            NewUser {
                id: user_b.clone(),
                username: "u-b".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();
    role_repo
        .create(
            TENANT_A,
            NewRole {
                id: role_a.clone(),
                code: "r-a".to_string(),
                name: "R-A".to_string(),
                description: None,
                is_system: false,
            },
        )
        .await
        .unwrap();
    role_repo
        .create(
            TENANT_B,
            NewRole {
                id: role_b.clone(),
                code: "r-b".to_string(),
                name: "R-B".to_string(),
                description: None,
                is_system: false,
            },
        )
        .await
        .unwrap();

    // tenant A 用户分配 tenant A 角色
    ur_repo
        .assign(TENANT_A, &user_a, &role_a, None)
        .await
        .unwrap();
    // tenant B 用户分配 tenant B 角色
    ur_repo
        .assign(TENANT_B, &user_b, &role_b, None)
        .await
        .unwrap();

    // tenant A 用户的角色列表不应包含 tenant B 的角色
    let a_roles = ur_repo.find_by_user_id(TENANT_A, &user_a).await.unwrap();
    assert_eq!(a_roles.len(), 1);
    assert_eq!(a_roles[0].role_id, role_a);

    // tenant B 用户的角色列表不应包含 tenant A 的角色
    let b_roles = ur_repo.find_by_user_id(TENANT_B, &user_b).await.unwrap();
    assert_eq!(b_roles.len(), 1);
    assert_eq!(b_roles[0].role_id, role_b);
}

// ============================================================================
// 11. 跨表关联：User → Role → Permission 链式查询
// ============================================================================

/// 端到端 RBAC 链路：创建 user/role/permission → 分配 user-role / role-permission → 查询用户所有权限。
#[tokio::test(flavor = "multi_thread")]
async fn rbac_full_chain_user_to_permissions() {
    let pool = setup_db().await;
    let user_repo = DbnexusUserRepository::new(pool.clone());
    let role_repo = DbnexusRoleRepository::new(pool.clone());
    let perm_repo = DbnexusPermissionRepository::new(pool.clone());
    let ur_repo = DbnexusUserRoleRepository::new(pool.clone());
    let rp_repo = DbnexusRolePermissionRepository::new(pool);

    let user_id = uuid_str();
    let role_id = uuid_str();
    let perm1_id = uuid_str();
    let perm2_id = uuid_str();

    // 1. 创建基础数据
    user_repo
        .create(
            TENANT_A,
            NewUser {
                id: user_id.clone(),
                username: "grace".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .unwrap();
    role_repo
        .create(
            TENANT_A,
            NewRole {
                id: role_id.clone(),
                code: "manager".to_string(),
                name: "Manager".to_string(),
                description: None,
                is_system: false,
            },
        )
        .await
        .unwrap();
    perm_repo
        .create(NewPermission {
            id: perm1_id.clone(),
            code: "report:read".to_string(),
            name: "Read Report".to_string(),
            resource_type: Some("report".to_string()),
            action: Some("read".to_string()),
        })
        .await
        .unwrap();
    perm_repo
        .create(NewPermission {
            id: perm2_id.clone(),
            code: "report:export".to_string(),
            name: "Export Report".to_string(),
            resource_type: Some("report".to_string()),
            action: Some("export".to_string()),
        })
        .await
        .unwrap();

    // 2. 分配角色给用户
    ur_repo
        .assign(TENANT_A, &user_id, &role_id, None)
        .await
        .unwrap();

    // 3. 分配权限给角色
    rp_repo.assign(TENANT_A, &role_id, &perm1_id).await.unwrap();
    rp_repo.assign(TENANT_A, &role_id, &perm2_id).await.unwrap();

    // 4. 查询用户所有角色
    let user_roles = ur_repo.find_by_user_id(TENANT_A, &user_id).await.unwrap();
    assert_eq!(user_roles.len(), 1);

    // 5. 对每个角色查询其权限
    let mut user_perms: Vec<String> = Vec::new();
    for ur in &user_roles {
        let rps = rp_repo
            .find_by_role_id(TENANT_A, &ur.role_id)
            .await
            .unwrap();
        for rp in rps {
            let perm = perm_repo.find_by_id(&rp.permission_id).await.unwrap();
            if let Some(p) = perm {
                user_perms.push(p.code);
            }
        }
    }

    // 6. 验证用户最终持有 report:read + report:export
    assert!(user_perms.contains(&"report:read".to_string()));
    assert!(user_perms.contains(&"report:export".to_string()));
    assert_eq!(user_perms.len(), 2);
}
