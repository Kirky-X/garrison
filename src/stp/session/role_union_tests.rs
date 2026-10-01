// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 登录时角色层级 TC 预计算 + 权限并集缓存 接线测试（db-sqlite）。
//!
//! 对应文档意图（mdbook/src/permission-rbac.md「角色层级 hierarchy」）：
//! 「0.5.0 新增 `role_hierarchy` 表（`child_role`/`parent_role`/`tenant_id`
//! + TC 预计算），登录时缓存权限并集」。
//!
//! 验证 `login_inner` → `cache_role_union_on_login` 端到端：
//! - 登录触发 `RoleHierarchyService::get_ancestors`（TC 闭包写入
//!   `tenant:{tid}:role_closure`）
//! - 并集（直接角色 ∪ 间接祖先）写入 `role:cache:{login_id}`
//! - 租户上下文（`TENANT` task_local）参与闭包隔离
//! - 无 SQL 后端 / 无角色 / 角色查询失败时 fail-open（登录不受影响）

use crate::account::disable::DefaultDisableRepository;
use crate::config::GarrisonConfig;
use crate::constants::DaoKeyPrefix;
use crate::context::tenant::{TenantContext, TenantSource, TENANT};
use crate::dao::{init_dbnexus, GarrisonDao, GarrisonDaoDbnexus, GarrisonMigration};
use crate::stp::mock::{MockDao, MockInterfaceWithPerms};
use crate::stp::{GarrisonInterface, GarrisonLogicDefault, LoginParams, SessionLogic};
use crate::strategy::{GarrisonPermissionStrategy, GarrisonPermissionStrategyDefault};
use async_trait::async_trait;
use dbnexus::sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
use dbnexus::DbPool;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;

// ============================================================================
// 测试装配
// ============================================================================

/// 定位项目根目录的 migrations/sqlite/ 目录。
fn project_migrations_dir() -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("migrations")
        .join("sqlite")
}

/// 创建并初始化 SQLite in-memory 数据库（迁移 + 返回 pool）。
async fn setup_pool() -> DbPool {
    let pool = init_dbnexus("sqlite::memory:")
        .await
        .expect("init_dbnexus 应成功");
    let migration = GarrisonMigration::with_base_dir(pool.clone(), project_migrations_dir());
    let applied = migration.migrate_core().await.expect("migrate_core 应成功");
    assert!(applied >= 1, "migrate_core 应至少执行 1 个文件");
    pool
}

/// 向 role_hierarchy 表插入一条边。
async fn insert_edge(pool: &DbPool, tenant_id: i64, child_role: &str, parent_role: &str) {
    let session = pool.get_session("admin").await.unwrap();
    let conn = session.connection().unwrap();
    let stmt = Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "INSERT OR IGNORE INTO role_hierarchy (tenant_id, child_role, parent_role) VALUES (?, ?, ?)",
        vec![
            Value::BigInt(Some(tenant_id)),
            Value::String(Some(child_role.to_string())),
            Value::String(Some(parent_role.to_string())),
        ],
    );
    conn.execute_raw(stmt).await.expect("INSERT 应成功");
}

/// 构造待测 `GarrisonLogicDefault`：SQL(KV=MockDao) DAO + 固定角色列表的 interface。
fn make_logic(dao: Arc<dyn GarrisonDao>, roles: Vec<String>) -> GarrisonLogicDefault {
    let session = Arc::new(crate::session::GarrisonSession::new(
        dao.clone(),
        3600,
        86400,
        0,
    ));
    let mut config = GarrisonConfig::default_config();
    config.throw_on_not_login = false;
    config.token_style = "uuid".to_string();
    let interface = Arc::new(MockInterfaceWithPerms {
        permissions: vec![],
        roles,
    });
    let firewall: Arc<dyn GarrisonPermissionStrategy> =
        Arc::new(GarrisonPermissionStrategyDefault::new(interface));
    GarrisonLogicDefault::new(
        session,
        Arc::new(config),
        firewall,
        Arc::new(DefaultDisableRepository::new(dao.clone())),
    )
}

/// `get_role_list` 恒返回 Err 的 interface（验证 fail-open）。
struct FailingRoleInterface;

#[async_trait]
impl GarrisonInterface for FailingRoleInterface {
    async fn get_permission_list(
        &self,
        _login_id: &str,
    ) -> crate::error::GarrisonResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: &str) -> crate::error::GarrisonResult<Vec<String>> {
        Err(crate::error::GarrisonError::Internal(
            "test-role-source-down::".to_string(),
        ))
    }
}

/// 构造带故障角色源的 logic（其余同 `make_logic`）。
fn make_logic_with_failing_roles(dao: Arc<dyn GarrisonDao>) -> GarrisonLogicDefault {
    let session = Arc::new(crate::session::GarrisonSession::new(
        dao.clone(),
        3600,
        86400,
        0,
    ));
    let mut config = GarrisonConfig::default_config();
    config.throw_on_not_login = false;
    config.token_style = "uuid".to_string();
    let firewall: Arc<dyn GarrisonPermissionStrategy> = Arc::new(
        GarrisonPermissionStrategyDefault::new(Arc::new(FailingRoleInterface)),
    );
    GarrisonLogicDefault::new(
        session,
        Arc::new(config),
        firewall,
        Arc::new(DefaultDisableRepository::new(dao.clone())),
    )
}

/// 读取并解析 `role:cache:{login_id}` 并集缓存。
async fn read_union(dao: &Arc<dyn GarrisonDao>, login_id: &str) -> Option<HashSet<String>> {
    let raw = dao
        .get(&DaoKeyPrefix::RoleCache.build_key(login_id))
        .await
        .expect("dao.get 应成功")?;
    Some(serde_json::from_str(&raw).expect("并集缓存应为 JSON 集合"))
}

// ============================================================================
// 正向：登录触发 TC 预计算 + 并集缓存
// ============================================================================

/// 登录应触发 TC 闭包缓存（`tenant:0:role_closure`）并集缓存（`role:cache:*`），
/// 并集 = 直接角色 ∪ 直接祖先 ∪ 间接祖先。
#[tokio::test(flavor = "multi_thread")]
async fn login_warms_tc_closure_and_union_cache() {
    let pool = setup_pool().await;
    // user -> admin -> super_admin（user 有间接祖先）
    insert_edge(&pool, 0, "user", "admin").await;
    insert_edge(&pool, 0, "admin", "super_admin").await;

    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoDbnexus::new(
        pool,
        Arc::new(MockDao::new()) as Arc<dyn GarrisonDao>,
    ));
    let logic = make_logic(dao.clone(), vec!["user".to_string()]);

    let _token = logic
        .login("alice-ru1", &LoginParams::default())
        .await
        .expect("login 应成功");

    // TC 预计算缓存已写入（RoleHierarchyService::get_ancestors 的租户闭包缓存）
    let closure = dao
        .get("tenant:0:role_closure")
        .await
        .expect("dao.get 应成功");
    assert!(closure.is_some(), "登录应触发租户 TC 闭包缓存写入");

    // 权限并集缓存：直接角色 ∪ 间接祖先
    let union = read_union(&dao, "alice-ru1")
        .await
        .expect("登录应写入权限并集缓存");
    assert!(union.contains("user"), "并集应含直接角色 user");
    assert!(union.contains("admin"), "并集应含直接祖先 admin");
    assert!(
        union.contains("super_admin"),
        "并集应含间接祖先 super_admin"
    );
    assert_eq!(union.len(), 3, "并集应恰为 {{user, admin, super_admin}}");
}

/// 并集缓存按租户上下文隔离：`TENANT` 租户 1 登录时仅展开租户 1 的边。
#[tokio::test(flavor = "multi_thread")]
async fn login_union_cache_respects_tenant_context() {
    let pool = setup_pool().await;
    // 仅 tenant 0 有边：user -> admin；tenant 1 空
    insert_edge(&pool, 0, "user", "admin").await;

    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoDbnexus::new(
        pool,
        Arc::new(MockDao::new()) as Arc<dyn GarrisonDao>,
    ));
    let logic = make_logic(dao.clone(), vec!["user".to_string()]);

    let ctx = TenantContext {
        tenant_id: 1,
        resolved_from: TenantSource::Header,
    };
    let _token = TENANT
        .scope(ctx, logic.login("bob-ru2", &LoginParams::default()))
        .await
        .expect("租户上下文内 login 应成功");

    // TC 闭包按租户 1 计算并缓存
    let closure = dao
        .get("tenant:1:role_closure")
        .await
        .expect("dao.get 应成功");
    assert!(closure.is_some(), "登录应在租户 1 维度写 TC 闭包缓存");

    // 并集只含直接角色 user（租户 1 无继承边，不混入租户 0 的 admin）
    let union = read_union(&dao, "bob-ru2")
        .await
        .expect("登录应写入权限并集缓存");
    let expected: HashSet<String> = ["user".to_string()].into_iter().collect();
    assert_eq!(union, expected, "租户 1 无继承边，并集应仅含直接角色 user");
}

// ============================================================================
// fail-open：异常路径不阻断登录
// ============================================================================

/// DAO 无 SQL 后端（纯 KV MockDao）时：`query_role_hierarchy_edges` 默认
/// NotImplemented → 跳过预热，登录仍成功。
#[tokio::test(flavor = "multi_thread")]
async fn login_without_sql_backend_fails_open() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let logic = make_logic(dao.clone(), vec!["user".to_string()]);

    let _token = logic
        .login("carol-ru3", &LoginParams::default())
        .await
        .expect("无 SQL 后端时 login 仍应成功（fail-open）");

    let cached = read_union(&dao, "carol-ru3").await;
    assert!(cached.is_none(), "无 SQL 后端时不应写入并集缓存");
}

/// 角色列表为空时：不触发 TC 查询、不写并集缓存，登录仍成功。
#[tokio::test(flavor = "multi_thread")]
async fn login_without_roles_skips_union_cache() {
    let pool = setup_pool().await;
    insert_edge(&pool, 0, "user", "admin").await;

    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoDbnexus::new(
        pool,
        Arc::new(MockDao::new()) as Arc<dyn GarrisonDao>,
    ));
    let logic = make_logic(dao.clone(), vec![]);

    let _token = logic
        .login("dave-ru4", &LoginParams::default())
        .await
        .expect("无角色时 login 仍应成功");

    let union = read_union(&dao, "dave-ru4").await;
    assert!(union.is_none(), "无角色时不应写入并集缓存");
    let closure = dao
        .get("tenant:0:role_closure")
        .await
        .expect("dao.get 应成功");
    assert!(closure.is_none(), "无角色时不应触发 TC 闭包查询");
}

/// 角色数据源故障（`get_role_list` 返回 Err）时：warn 跳过，登录仍成功。
#[tokio::test(flavor = "multi_thread")]
async fn login_with_failing_role_source_fails_open() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let logic = make_logic_with_failing_roles(dao.clone());

    let _token = logic
        .login("eve-ru5", &LoginParams::default())
        .await
        .expect("角色源故障时 login 仍应成功（fail-open）");

    let cached = read_union(&dao, "eve-ru5").await;
    assert!(cached.is_none(), "角色源故障时不应写入并集缓存");
}
