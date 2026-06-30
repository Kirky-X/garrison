//! dbnexus 集成测试。
//!
//! 端到端验证 Bulwark + dbnexus 0.2 + sea-orm 2.0 的协作：
//! - 用项目根目录的 migrations/sqlite/core/001_init.sql 执行真实迁移
//! - 跨多表关联场景（用户-角色-权限 RBAC）
//! - 扩展表 KV 操作（app_user_ext）
//! - 多租户隔离
//! - 外键级联删除
//! - CHECK 约束生效
//!
//! 运行：`cargo test --features db-sqlite --test dbnexus_integration`

use bulwark::dao::{init_dbnexus, BulwarkMigration};
use sea_orm::{ConnectionTrait, DbBackend, Statement};
use std::path::PathBuf;

// ============================================================================
// 辅助函数
// ============================================================================

/// 定位项目根目录的 migrations/sqlite/ 目录。
///
/// 集成测试由 cargo 在项目根目录执行，CARGO_MANIFEST_DIR 指向项目根。
fn project_migrations_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("migrations")
        .join("sqlite")
}

/// 查询单行单列字符串值。
async fn query_one_string(session: &dbnexus::Session, sql: &str) -> Option<String> {
    let conn = session
        .connection()
        .expect("connection should be available");
    let stmt = Statement::from_sql_and_values(DbBackend::Sqlite, sql, vec![]);
    let row = conn
        .query_one_raw(stmt)
        .await
        .expect("query should succeed")?;
    row.try_get::<String>("", "val").ok()
}

/// 查询 count(*) 结果。
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
    row.try_get::<i64>("", "cnt")
        .expect("column 'cnt' should be present")
}

/// 查询多行单列字符串值。
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

/// 创建并初始化数据库（迁移 + 返回 pool）。
async fn setup_db() -> dbnexus::DbPool {
    let pool = init_dbnexus("sqlite::memory:")
        .await
        .expect("init_dbnexus 应成功");
    let migration = BulwarkMigration::with_base_dir(pool.clone(), project_migrations_dir());
    let applied = migration.migrate_core().await.expect("migrate_core 应成功");
    assert!(
        applied >= 1,
        "migrate_core 应至少执行 1 个文件，实际: {}",
        applied
    );
    pool
}

// ============================================================================
// 1. 端到端迁移：验证 9 张表全部创建
// ============================================================================

/// Scenario: migrate_core 在项目真实迁移文件上创建全部表。
/// WHEN BulwarkMigration::migrate_core() 执行 001_init.sql
/// THEN sqlite_master 中应包含 9 张表 + 全部索引
#[tokio::test]
async fn integration_migrate_creates_all_tables() {
    let pool = setup_db().await;
    let session = pool.get_session("admin").await.expect("get_session 应成功");

    // 查询所有 app_ 前缀的表
    let tables = query_all_strings(
        &session,
        "SELECT name AS val FROM sqlite_master WHERE type='table' AND name LIKE 'app_%' ORDER BY name",
    )
    .await;

    let expected = vec![
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
    assert_eq!(
        tables, expected,
        "应创建 9 张 app_ 前缀表，实际: {:?}",
        tables
    );

    // 验证索引数量（应 ≥ 15 个）
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

// ============================================================================
// 2. RBAC 多表关联：用户-角色-权限
// ============================================================================

/// Scenario: RBAC 完整流程：创建用户/角色/权限，建立关联，查询用户权限。
/// WHEN 插入 user → role → permission → user_role → role_permission
/// THEN 通过 JOIN 查询能拿到用户的所有权限编码
#[tokio::test]
async fn integration_rbac_full_flow() {
    let pool = setup_db().await;
    let session = pool.get_session("admin").await.expect("get_session 应成功");

    // 插入用户
    session
        .execute_raw(
            "INSERT INTO app_user (id, username, password_hash, status, tenant_id) \
             VALUES ('u1', 'alice', 'hash1', 'active', 't1')",
        )
        .await
        .expect("INSERT user 应成功");

    // 插入角色
    session
        .execute_raw(
            "INSERT INTO app_role (id, code, name, tenant_id, is_system) \
             VALUES ('r1', 'admin', '管理员', 't1', 0)",
        )
        .await
        .expect("INSERT role 应成功");

    // 插入权限（app_permission 无 tenant_id）
    session
        .execute_raw(
            "INSERT INTO app_permission (id, code, name, resource_type, action) \
             VALUES ('p1', 'user:read', '查看用户', 'user', 'read'), \
                    ('p2', 'user:write', '编辑用户', 'user', 'write')",
        )
        .await
        .expect("INSERT permission 应成功");

    // 建立用户-角色关联
    session
        .execute_raw(
            "INSERT INTO app_user_role (user_id, role_id, tenant_id) VALUES ('u1', 'r1', 't1')",
        )
        .await
        .expect("INSERT user_role 应成功");

    // 建立角色-权限关联
    session
        .execute_raw(
            "INSERT INTO app_role_permission (role_id, permission_id, tenant_id) \
             VALUES ('r1', 'p1', 't1'), ('r1', 'p2', 't1')",
        )
        .await
        .expect("INSERT role_permission 应成功");

    // 通过 JOIN 查询用户的所有权限编码
    let perms = query_all_strings(
        &session,
        "SELECT p.code AS val \
         FROM app_user_role ur \
         JOIN app_role_permission rp ON ur.role_id = rp.role_id \
         JOIN app_permission p ON rp.permission_id = p.id \
         WHERE ur.user_id = 'u1' ORDER BY p.code",
    )
    .await;

    assert_eq!(perms, vec!["user:read", "user:write"], "用户应有 2 个权限");
}

// ============================================================================
// 3. 扩展表 KV 操作
// ============================================================================

/// Scenario: app_user_ext 表的 KV 增删改查。
/// WHEN 插入扩展字段 → 查询 → 更新 → 查询 → 删除
/// THEN 各步骤返回正确结果
#[tokio::test]
async fn integration_user_ext_kv_crud() {
    let pool = setup_db().await;
    let session = pool.get_session("admin").await.expect("get_session 应成功");

    // 先插入用户（外键约束）
    session
        .execute_raw(
            "INSERT INTO app_user (id, username, password_hash, status, tenant_id) \
             VALUES ('ue1', 'kv_user', 'hash', 'active', 't1')",
        )
        .await
        .expect("INSERT user 应成功");

    // 插入扩展字段（email）
    session
        .execute_raw(
            "INSERT INTO app_user_ext (id, user_id, field_key, field_value, field_type, tenant_id) \
             VALUES ('e1', 'ue1', 'email', 'alice@example.com', 'string', 't1')",
        )
        .await
        .expect("INSERT ext 应成功");

    // 插入扩展字段（avatar）
    session
        .execute_raw(
            "INSERT INTO app_user_ext (id, user_id, field_key, field_value, field_type, tenant_id) \
             VALUES ('e2', 'ue1', 'avatar', 'https://example.com/a.png', 'string', 't1')",
        )
        .await
        .expect("INSERT ext 应成功");

    // 查询：用户的全部扩展字段
    let count = query_count(
        &session,
        "SELECT count(*) AS cnt FROM app_user_ext WHERE user_id = 'ue1'",
    )
    .await;
    assert_eq!(count, 2, "应有 2 个扩展字段");

    // 更新 email 值
    session
        .execute_raw("UPDATE app_user_ext SET field_value = 'bob@example.com' WHERE user_id = 'ue1' AND field_key = 'email'")
        .await
        .expect("UPDATE ext 应成功");

    let email = query_one_string(
        &session,
        "SELECT field_value AS val FROM app_user_ext WHERE user_id = 'ue1' AND field_key = 'email'",
    )
    .await
    .expect("email 应存在");
    assert_eq!(email, "bob@example.com", "email 应已更新");

    // 删除 avatar 字段
    session
        .execute_raw("DELETE FROM app_user_ext WHERE user_id = 'ue1' AND field_key = 'avatar'")
        .await
        .expect("DELETE ext 应成功");

    let count = query_count(
        &session,
        "SELECT count(*) AS cnt FROM app_user_ext WHERE user_id = 'ue1'",
    )
    .await;
    assert_eq!(count, 1, "删除后应剩 1 个扩展字段");

    // 验证唯一约束：(user_id, field_key) 不能重复
    let dup_result = session
        .execute_raw(
            "INSERT INTO app_user_ext (id, user_id, field_key, field_value, field_type, tenant_id) \
             VALUES ('e3', 'ue1', 'email', 'dup@example.com', 'string', 't1')",
        )
        .await;
    assert!(
        dup_result.is_err(),
        "重复 (user_id, field_key) 应被唯一约束拒绝"
    );
}

// ============================================================================
// 4. 多租户隔离
// ============================================================================

/// Scenario: 不同租户下相同 username 可以共存。
/// WHEN 在 tenant_id='t1' 和 tenant_id='t2' 下都创建 username='alice'
/// THEN 两条记录均存在，按 tenant_id 过滤互不影响
#[tokio::test]
async fn integration_multi_tenant_isolation() {
    let pool = setup_db().await;
    let session = pool.get_session("admin").await.expect("get_session 应成功");

    // 租户 t1 的 alice
    session
        .execute_raw(
            "INSERT INTO app_user (id, username, password_hash, status, tenant_id) \
             VALUES ('t1-alice', 'alice', 'h1', 'active', 't1')",
        )
        .await
        .expect("INSERT t1 alice 应成功");

    // 租户 t2 的同名 alice
    session
        .execute_raw(
            "INSERT INTO app_user (id, username, password_hash, status, tenant_id) \
             VALUES ('t2-alice', 'alice', 'h2', 'active', 't2')",
        )
        .await
        .expect("INSERT t2 alice 应成功（多租户允许相同 username）");

    // 按 tenant 查询
    let t1_count = query_count(
        &session,
        "SELECT count(*) AS cnt FROM app_user WHERE tenant_id = 't1' AND username = 'alice'",
    )
    .await;
    assert_eq!(t1_count, 1, "t1 下应有 1 个 alice");

    let t2_count = query_count(
        &session,
        "SELECT count(*) AS cnt FROM app_user WHERE tenant_id = 't2' AND username = 'alice'",
    )
    .await;
    assert_eq!(t2_count, 1, "t2 下应有 1 个 alice");

    let total_alice = query_count(
        &session,
        "SELECT count(*) AS cnt FROM app_user WHERE username = 'alice'",
    )
    .await;
    assert_eq!(total_alice, 2, "全局应有 2 个 alice（跨租户）");
}

// ============================================================================
// 5. 外键级联删除
// ============================================================================

/// Scenario: 删除用户后，user_role 与 user_ext 应被自动级联删除。
/// WHEN INSERT user → INSERT user_role → INSERT user_ext → DELETE user
/// THEN user_role 与 user_ext 中对应记录应被 CASCADE 删除
#[tokio::test]
async fn integration_cascade_delete_user() {
    let pool = setup_db().await;
    let session = pool.get_session("admin").await.expect("get_session 应成功");

    // 创建用户
    session
        .execute_raw(
            "INSERT INTO app_user (id, username, password_hash, status, tenant_id) \
             VALUES ('cu1', 'cascade_user', 'h', 'active', 't1')",
        )
        .await
        .expect("INSERT user 应成功");

    // 创建角色
    session
        .execute_raw(
            "INSERT INTO app_role (id, code, name, tenant_id, is_system) \
             VALUES ('cr1', 'user_role_c', 'CR', 't1', 0)",
        )
        .await
        .expect("INSERT role 应成功");

    // 关联用户-角色
    session
        .execute_raw(
            "INSERT INTO app_user_role (user_id, role_id, tenant_id) \
             VALUES ('cu1', 'cr1', 't1')",
        )
        .await
        .expect("INSERT user_role 应成功");

    // 添加扩展字段
    session
        .execute_raw(
            "INSERT INTO app_user_ext (id, user_id, field_key, field_value, field_type, tenant_id) \
             VALUES ('ce1', 'cu1', 'phone', '1234567890', 'string', 't1')",
        )
        .await
        .expect("INSERT user_ext 应成功");

    // 验证关联记录存在
    let ur_count = query_count(
        &session,
        "SELECT count(*) AS cnt FROM app_user_role WHERE user_id = 'cu1'",
    )
    .await;
    assert_eq!(ur_count, 1, "删除前应有 1 条 user_role");

    let ext_count = query_count(
        &session,
        "SELECT count(*) AS cnt FROM app_user_ext WHERE user_id = 'cu1'",
    )
    .await;
    assert_eq!(ext_count, 1, "删除前应有 1 条 user_ext");

    // 删除用户（应触发 CASCADE）
    session
        .execute_raw("DELETE FROM app_user WHERE id = 'cu1'")
        .await
        .expect("DELETE user 应成功");

    // 验证级联删除
    let ur_after = query_count(
        &session,
        "SELECT count(*) AS cnt FROM app_user_role WHERE user_id = 'cu1'",
    )
    .await;
    assert_eq!(ur_after, 0, "CASCADE 删除后 user_role 应为空");

    let ext_after = query_count(
        &session,
        "SELECT count(*) AS cnt FROM app_user_ext WHERE user_id = 'cu1'",
    )
    .await;
    assert_eq!(ext_after, 0, "CASCADE 删除后 user_ext 应为空");

    // 验证角色仍然存在（只删用户，不删角色）
    let role_exists = query_count(
        &session,
        "SELECT count(*) AS cnt FROM app_role WHERE id = 'cr1'",
    )
    .await;
    assert_eq!(role_exists, 1, "角色不应被级联删除");
}

// ============================================================================
// 6. CHECK 约束生效
// ============================================================================

/// Scenario: app_user.status 的 CHECK 约束拒绝非法状态值。
/// WHEN INSERT 用 status='invalid_status'
/// THEN 数据库应拒绝（返回错误）
#[tokio::test]
async fn integration_check_constraint_status() {
    let pool = setup_db().await;
    let session = pool.get_session("admin").await.expect("get_session 应成功");

    // 非法 status 应被 CHECK 拒绝
    let invalid = session
        .execute_raw(
            "INSERT INTO app_user (id, username, password_hash, status, tenant_id) \
             VALUES ('ck1', 'check_user', 'h', 'invalid_status', 't1')",
        )
        .await;
    assert!(invalid.is_err(), "非法 status 应被 CHECK 约束拒绝");

    // 合法 status 应成功（验证 5 个合法值）
    for status in ["pending", "active", "suspended", "inactive", "deleted"] {
        let username = format!("ck_{}", status);
        let result = session
            .execute_raw(&format!(
                "INSERT INTO app_user (id, username, password_hash, status, tenant_id) \
                 VALUES ('ck_{}', '{}', 'h', '{}', 't1')",
                status, username, status
            ))
            .await;
        assert!(
            result.is_ok(),
            "合法 status '{}' 应被接受: {:?}",
            status,
            result.err()
        );
    }
}

/// Scenario: app_auth_method.method_type CHECK 约束。
#[tokio::test]
async fn integration_check_constraint_auth_method() {
    let pool = setup_db().await;
    let session = pool.get_session("admin").await.expect("get_session 应成功");

    // 先创建用户
    session
        .execute_raw(
            "INSERT INTO app_user (id, username, password_hash, status, tenant_id) \
             VALUES ('am1', 'am_user', 'h', 'active', 't1')",
        )
        .await
        .expect("INSERT user 应成功");

    // 合法 method_type 应成功
    for mt in ["passkey", "password", "oauth", "did"] {
        let result = session
            .execute_raw(&format!(
                "INSERT INTO app_auth_method (id, user_id, method_type, tenant_id) \
                 VALUES ('am_{}', 'am1', '{}', 't1')",
                mt, mt
            ))
            .await;
        assert!(result.is_ok(), "合法 method_type '{}' 应被接受", mt);
    }

    // 非法 method_type 应被拒绝
    let invalid = session
        .execute_raw(
            "INSERT INTO app_auth_method (id, user_id, method_type, tenant_id) \
             VALUES ('am_bad', 'am1', 'unknown_method', 't1')",
        )
        .await;
    assert!(invalid.is_err(), "非法 method_type 应被 CHECK 约束拒绝");
}

// ============================================================================
// 7. 事务隔离：业务级事务
// ============================================================================

/// Scenario: 跨多表事务，rollback 后所有更改都不可见。
/// WHEN begin → INSERT user → INSERT user_role → rollback
/// THEN user 与 user_role 均应为空
#[tokio::test]
async fn integration_multi_table_transaction_rollback() {
    let pool = setup_db().await;
    let session = pool.get_session("admin").await.expect("get_session 应成功");

    session.begin_transaction().await.expect("begin 应成功");

    // 在事务中创建用户和角色关联
    session
        .execute_raw(
            "INSERT INTO app_user (id, username, password_hash, status, tenant_id) \
             VALUES ('tu1', 'txn_user', 'h', 'active', 't1')",
        )
        .await
        .expect("事务内 INSERT user 应成功");

    session
        .execute_raw(
            "INSERT INTO app_role (id, code, name, tenant_id, is_system) \
             VALUES ('tr1', 'txn_role', 'TR', 't1', 0)",
        )
        .await
        .expect("事务内 INSERT role 应成功");

    session
        .execute_raw(
            "INSERT INTO app_user_role (user_id, role_id, tenant_id) \
             VALUES ('tu1', 'tr1', 't1')",
        )
        .await
        .expect("事务内 INSERT user_role 应成功");

    // 回滚
    session.rollback().await.expect("rollback 应成功");

    // 验证所有插入都被回滚
    let user_count = query_count(
        &session,
        "SELECT count(*) AS cnt FROM app_user WHERE id = 'tu1'",
    )
    .await;
    assert_eq!(user_count, 0, "回滚后 user 应不存在");

    let role_count = query_count(
        &session,
        "SELECT count(*) AS cnt FROM app_role WHERE id = 'tr1'",
    )
    .await;
    assert_eq!(role_count, 0, "回滚后 role 应不存在");

    let ur_count = query_count(
        &session,
        "SELECT count(*) AS cnt FROM app_user_role WHERE user_id = 'tu1'",
    )
    .await;
    assert_eq!(ur_count, 0, "回滚后 user_role 应不存在");
}

// ============================================================================
// 8. 迁移幂等性：连续执行 migrate_core 两次
// ============================================================================

/// Scenario: 连续两次 migrate_core 第二次返回 0（幂等性）。
/// WHEN 第一次 migrate_core → 第二次 migrate_core
/// THEN 第二次应返回 0（版本号已被记录，不重复执行）
#[tokio::test]
async fn integration_migrate_idempotent() {
    let pool = init_dbnexus("sqlite::memory:")
        .await
        .expect("init_dbnexus 应成功");
    let migration = BulwarkMigration::with_base_dir(pool.clone(), project_migrations_dir());

    // 第一次执行：应执行 1 个迁移文件
    let first = migration
        .migrate_core()
        .await
        .expect("第一次 migrate_core 应成功");
    assert_eq!(first, 1, "第一次应执行 1 个文件，实际: {}", first);

    // 第二次执行：应返回 0（dbnexus_migrations 已记录 version=1）
    let second = migration
        .migrate_core()
        .await
        .expect("第二次 migrate_core 应成功");
    assert_eq!(second, 0, "第二次应返回 0（幂等），实际: {}", second);

    // 验证表仍然存在
    let session = pool.get_session("admin").await.expect("get_session 应成功");
    let count = query_count(
        &session,
        "SELECT count(*) AS cnt FROM sqlite_master WHERE type='table' AND name LIKE 'app_%'",
    )
    .await;
    assert_eq!(count, 9, "二次迁移后表数仍应为 9");
}

// ============================================================================
// 9. Session 会话表 CRUD
// ============================================================================

/// Scenario: app_session 表的会话 CRUD（模拟 token 持久化场景）。
/// WHEN INSERT session → SELECT → UPDATE last_active → DELETE
/// THEN 各步骤返回正确结果
#[tokio::test]
async fn integration_session_table_crud() {
    let pool = setup_db().await;
    let session = pool.get_session("admin").await.expect("get_session 应成功");

    // 创建用户
    session
        .execute_raw(
            "INSERT INTO app_user (id, username, password_hash, status, tenant_id) \
             VALUES ('su1', 'session_user', 'h', 'active', 't1')",
        )
        .await
        .expect("INSERT user 应成功");

    // 创建会话
    session
        .execute_raw(
            "INSERT INTO app_session (session_id, user_id, ip, login_time, last_active, tenant_id) \
             VALUES ('sess1', 'su1', '127.0.0.1', '2026-01-01 10:00:00', '2026-01-01 10:00:00', 't1')",
        )
        .await
        .expect("INSERT session 应成功");

    // 查询会话
    let user_id = query_one_string(
        &session,
        "SELECT user_id AS val FROM app_session WHERE session_id = 'sess1'",
    )
    .await
    .expect("session 应存在");
    assert_eq!(user_id, "su1", "session 应关联到 su1");

    // 更新 last_active
    session
        .execute_raw(
            "UPDATE app_session SET last_active = '2026-01-01 11:00:00' WHERE session_id = 'sess1'",
        )
        .await
        .expect("UPDATE session 应成功");

    let last_active = query_one_string(
        &session,
        "SELECT last_active AS val FROM app_session WHERE session_id = 'sess1'",
    )
    .await
    .expect("last_active 应存在");
    assert_eq!(last_active, "2026-01-01 11:00:00", "last_active 应已更新");

    // 删除会话
    session
        .execute_raw("DELETE FROM app_session WHERE session_id = 'sess1'")
        .await
        .expect("DELETE session 应成功");

    let count = query_count(
        &session,
        "SELECT count(*) AS cnt FROM app_session WHERE session_id = 'sess1'",
    )
    .await;
    assert_eq!(count, 0, "删除后会话应为空");
}
