//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Repository 层错误路径测试（v0.4.2 新增，T095 覆盖率提升）。
//!
//! 使用未迁移的 SQLite in-memory DbPool 触发所有 repository 方法的
//! `map_err` 错误处理分支（表不存在 → query/execute 失败）。
//!
//! 覆盖目标：`src/dao/repository/sqlite/mod.rs` 中所有 `map_err` 闭包体
//!（session/connection 失败 + query/execute/parse 失败）。
//!
//! 运行：`cargo test --features "db-sqlite" --test repository_error_paths`

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
};
use bulwark::error::BulwarkError;

const TENANT: i64 = 1;

/// 创建**未迁移**的 DbPool（不执行 migrate_core），所有表不存在，
/// repository 方法调用因 SQL 表不存在而失败，触发 `map_err` 分支。
async fn setup_unmigrated_db() -> dbnexus::DbPool {
    init_dbnexus("sqlite::memory:")
        .await
        .expect("init_dbnexus 应成功（即使不迁移）")
}

fn assert_dao_error<T>(result: bulwark::error::BulwarkResult<T>, method_name: &str) {
    match result {
        Err(BulwarkError::Dao(msg)) => {
            assert!(
                msg.contains(method_name),
                "错误信息应包含方法/表名 '{}'，实际: {}",
                method_name,
                msg
            );
        },
        Err(other) => panic!("期望 BulwarkError::Dao，实际: {:?}", other),
        Ok(_) => panic!("期望 Err，实际 Ok（DB 未迁移应失败）"),
    }
}

// ============================================================================
// 1. UserRepository 错误路径
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn user_repo_find_by_id_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserRepository::new(pool);
    let result = repo.find_by_id(TENANT, "u-1").await;
    assert_dao_error(result, "app-user-find-by-id");
}

#[tokio::test(flavor = "multi_thread")]
async fn user_repo_find_by_username_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserRepository::new(pool);
    let result = repo.find_by_username(TENANT, "alice").await;
    assert_dao_error(result, "app-user-find-by-username");
}

#[tokio::test(flavor = "multi_thread")]
async fn user_repo_create_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserRepository::new(pool);
    let result = repo
        .create(
            TENANT,
            NewUser {
                username: "alice".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await;
    assert_dao_error(result, "app-user-create");
}

#[tokio::test(flavor = "multi_thread")]
async fn user_repo_update_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserRepository::new(pool);
    let result = repo
        .update(
            TENANT,
            "u-1",
            UpdateUser {
                username: Some("alice2".to_string()),
                ..Default::default()
            },
        )
        .await;
    assert_dao_error(result, "app-user-update");
}

#[tokio::test(flavor = "multi_thread")]
async fn user_repo_update_empty_fields_returns_ok() {
    // 覆盖 update 中 sets.is_empty() 分支（返回 Ok(()) 不调 DB）
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserRepository::new(pool);
    let result = repo.update(TENANT, "u-1", UpdateUser::default()).await;
    assert!(result.is_ok(), "空 update 应返回 Ok 而不调 DB");
}

#[tokio::test(flavor = "multi_thread")]
async fn user_repo_delete_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserRepository::new(pool);
    let result = repo.delete(TENANT, "u-1").await;
    assert_dao_error(result, "app-user-delete");
}

#[tokio::test(flavor = "multi_thread")]
async fn user_repo_list_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserRepository::new(pool);
    let result = repo.list(TENANT, 0, 100).await;
    assert_dao_error(result, "app-user-list");
}

// ============================================================================
// 2. RoleRepository 错误路径
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn role_repo_find_by_id_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusRoleRepository::new(pool);
    let result = repo.find_by_id(TENANT, "r-1").await;
    assert_dao_error(result, "app-role-find-by-id");
}

#[tokio::test(flavor = "multi_thread")]
async fn role_repo_find_by_code_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusRoleRepository::new(pool);
    let result = repo.find_by_code(TENANT, "admin").await;
    assert_dao_error(result, "app-role-find-by-code");
}

#[tokio::test(flavor = "multi_thread")]
async fn role_repo_create_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusRoleRepository::new(pool);
    let result = repo
        .create(
            TENANT,
            NewRole {
                code: "admin".to_string(),
                name: "Admin".to_string(),
                description: None,
                is_system: false,
            },
        )
        .await;
    assert_dao_error(result, "app-role-create");
}

#[tokio::test(flavor = "multi_thread")]
async fn role_repo_update_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusRoleRepository::new(pool);
    let result = repo
        .update(TENANT, "r-1", Some("c".to_string()), None, None)
        .await;
    assert_dao_error(result, "app-role-update");
}

#[tokio::test(flavor = "multi_thread")]
async fn role_repo_delete_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusRoleRepository::new(pool);
    let result = repo.delete(TENANT, "r-1").await;
    assert_dao_error(result, "app-role-delete");
}

#[tokio::test(flavor = "multi_thread")]
async fn role_repo_list_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusRoleRepository::new(pool);
    let result = repo.list(TENANT, 0, 100).await;
    assert_dao_error(result, "app-role-list");
}

// ============================================================================
// 3. PermissionRepository 错误路径（无 tenant_id）
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn perm_repo_find_by_id_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusPermissionRepository::new(pool);
    let result = repo.find_by_id("p-1").await;
    assert_dao_error(result, "app-permission-find-by-id");
}

#[tokio::test(flavor = "multi_thread")]
async fn perm_repo_find_by_code_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusPermissionRepository::new(pool);
    let result = repo.find_by_code("user:read").await;
    assert_dao_error(result, "app-permission-find-by-code");
}

#[tokio::test(flavor = "multi_thread")]
async fn perm_repo_create_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusPermissionRepository::new(pool);
    let result = repo
        .create(NewPermission {
            code: "user:read".to_string(),
            name: "Read".to_string(),
            resource_type: None,
            action: None,
        })
        .await;
    assert_dao_error(result, "app-permission-create");
}

#[tokio::test(flavor = "multi_thread")]
async fn perm_repo_update_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusPermissionRepository::new(pool);
    let result = repo.update("p-1", Some("n".to_string()), None, None).await;
    assert_dao_error(result, "app-permission-update");
}

#[tokio::test(flavor = "multi_thread")]
async fn perm_repo_delete_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusPermissionRepository::new(pool);
    let result = repo.delete("p-1").await;
    assert_dao_error(result, "app-permission-delete");
}

#[tokio::test(flavor = "multi_thread")]
async fn perm_repo_list_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusPermissionRepository::new(pool);
    let result = repo.list(0, 100).await;
    assert_dao_error(result, "app-permission-list");
}

// ============================================================================
// 4. UserRoleRepository 错误路径
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn user_role_repo_assign_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserRoleRepository::new(pool);
    let result = repo.assign(TENANT, "u-1", "r-1", None).await;
    assert_dao_error(result, "app-user-role-assign");
}

#[tokio::test(flavor = "multi_thread")]
async fn user_role_repo_find_by_user_id_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserRoleRepository::new(pool);
    let result = repo.find_by_user_id(TENANT, "u-1").await;
    assert_dao_error(result, "app-user-role-find-by-user-id");
}

#[tokio::test(flavor = "multi_thread")]
async fn user_role_repo_find_by_role_id_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserRoleRepository::new(pool);
    let result = repo.find_by_role_id(TENANT, "r-1").await;
    assert_dao_error(result, "app-user-role-find-by-role-id");
}

#[tokio::test(flavor = "multi_thread")]
async fn user_role_repo_revoke_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserRoleRepository::new(pool);
    let result = repo.revoke(TENANT, "u-1", "r-1").await;
    assert_dao_error(result, "app-user-role-revoke");
}

// ============================================================================
// 5. RolePermissionRepository 错误路径
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn role_perm_repo_assign_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusRolePermissionRepository::new(pool);
    let result = repo.assign(TENANT, "r-1", "p-1").await;
    assert_dao_error(result, "app-role-permission-assign");
}

#[tokio::test(flavor = "multi_thread")]
async fn role_perm_repo_find_by_role_id_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusRolePermissionRepository::new(pool);
    let result = repo.find_by_role_id(TENANT, "r-1").await;
    assert_dao_error(result, "app-role-permission-find-by-role-id");
}

#[tokio::test(flavor = "multi_thread")]
async fn role_perm_repo_find_by_permission_id_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusRolePermissionRepository::new(pool);
    let result = repo.find_by_permission_id(TENANT, "p-1").await;
    assert_dao_error(result, "app-role-permission-find-by-permission-id");
}

#[tokio::test(flavor = "multi_thread")]
async fn role_perm_repo_revoke_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusRolePermissionRepository::new(pool);
    let result = repo.revoke(TENANT, "r-1", "p-1").await;
    assert_dao_error(result, "app-role-permission-revoke");
}

// ============================================================================
// 6. AuthMethodRepository 错误路径
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn auth_method_repo_create_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusAuthMethodRepository::new(pool);
    let result = repo
        .create(
            TENANT,
            NewAuthMethod {
                user_id: "u-1".to_string(),
                method_type: "password".to_string(),
                external_id: None,
                metadata: None,
            },
        )
        .await;
    assert_dao_error(result, "app-auth-method-create");
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_method_repo_find_by_user_id_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusAuthMethodRepository::new(pool);
    let result = repo.find_by_user_id(TENANT, "u-1").await;
    assert_dao_error(result, "app-auth-method-find-by-user-id");
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_method_repo_find_by_id_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusAuthMethodRepository::new(pool);
    let result = repo.find_by_id(TENANT, "m-1").await;
    assert_dao_error(result, "app-auth-method-find-by-id");
}

#[tokio::test(flavor = "multi_thread")]
async fn auth_method_repo_delete_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusAuthMethodRepository::new(pool);
    let result = repo.delete(TENANT, "m-1").await;
    assert_dao_error(result, "app-auth-method-delete");
}

// ============================================================================
// 7. SessionRepository 错误路径
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn session_repo_create_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusSessionRepository::new(pool);
    let result = repo
        .create(
            TENANT,
            NewSession {
                session_id: "s-1".to_string(),
                user_id: "u-1".to_string(),
                device_id: None,
                ip: None,
                user_agent: None,
                expire_time: None,
            },
        )
        .await;
    assert_dao_error(result, "app-session-create");
}

#[tokio::test(flavor = "multi_thread")]
async fn session_repo_find_by_session_id_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusSessionRepository::new(pool);
    let result = repo.find_by_session_id(TENANT, "s-1").await;
    assert_dao_error(result, "app-session-find-by-session-id");
}

#[tokio::test(flavor = "multi_thread")]
async fn session_repo_find_by_user_id_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusSessionRepository::new(pool);
    let result = repo.find_by_user_id(TENANT, "u-1").await;
    assert_dao_error(result, "app-session-find-by-user-id");
}

#[tokio::test(flavor = "multi_thread")]
async fn session_repo_update_last_active_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusSessionRepository::new(pool);
    let result = repo.update_last_active(TENANT, "s-1").await;
    assert_dao_error(result, "app-session-update-last-active");
}

#[tokio::test(flavor = "multi_thread")]
async fn session_repo_delete_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusSessionRepository::new(pool);
    let result = repo.delete(TENANT, "s-1").await;
    assert_dao_error(result, "app-session-delete");
}

// ============================================================================
// 8. LoginLogRepository 错误路径
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn login_log_repo_create_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusLoginLogRepository::new(pool);
    let result = repo
        .create(
            TENANT,
            NewLoginLog {
                user_id: Some("u-1".to_string()),
                action: "login".to_string(),
                ip: None,
                device_id: None,
                success: true,
                fail_reason: None,
            },
        )
        .await;
    assert_dao_error(result, "app-login-log-create");
}

#[tokio::test(flavor = "multi_thread")]
async fn login_log_repo_find_by_id_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusLoginLogRepository::new(pool);
    let result = repo.find_by_id(TENANT, "log-1").await;
    assert_dao_error(result, "app-login-log-find-by-id");
}

#[tokio::test(flavor = "multi_thread")]
async fn login_log_repo_find_by_user_id_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusLoginLogRepository::new(pool);
    let result = repo.find_by_user_id(TENANT, "u-1", 0, 100).await;
    assert_dao_error(result, "app-login-log-find-by-user-id");
}

// ============================================================================
// 9. UserExtRepository 错误路径
// ============================================================================

#[tokio::test(flavor = "multi_thread")]
async fn user_ext_repo_upsert_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserExtRepository::new(pool);
    let result = repo
        .upsert(TENANT, "u-1", "email", Some("v".to_string()), "string")
        .await;
    assert_dao_error(result, "app-user-ext-upsert");
}

#[tokio::test(flavor = "multi_thread")]
async fn user_ext_repo_find_by_user_and_key_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserExtRepository::new(pool);
    let result = repo.find_by_user_and_key(TENANT, "u-1", "email").await;
    assert_dao_error(result, "app-user-ext-find-by-user-and-key");
}

#[tokio::test(flavor = "multi_thread")]
async fn user_ext_repo_find_by_user_id_table_missing() {
    let pool = setup_unmigrated_db().await;
    let repo = DbnexusUserExtRepository::new(pool);
    let result = repo.find_by_user_id(TENANT, "u-1").await;
    assert_dao_error(result, "app-user-ext-find-by-user-id");
}
