//! 角色层级 Repository 模块（v0.5.0 新增，依据 proposal H6）。
//!
//! 提供 `role_hierarchy` 表的 CRUD 与 TC（传递闭包）预计算能力。
//! 依据 cedar 工程思想：登录时预计算角色层级的间接祖先并缓存到 oxcache，
//! 避免每次权限校验都做 DFS。
//!
//! ## 核心抽象
//!
//! - [`RoleHierarchyRecord`]：`role_hierarchy` 表行结构（child_role → parent_role + tenant_id）
//! - [`RoleHierarchyService`]：TC 预计算 + 缓存 + 增量失效（T045-T050 实现）
//!
//! ## 表结构
//!
//! ```sql
//! CREATE TABLE role_hierarchy (
//!     tenant_id INTEGER NOT NULL DEFAULT 0,
//!     child_role TEXT NOT NULL,
//!     parent_role TEXT NOT NULL,
//!     PRIMARY KEY (tenant_id, child_role, parent_role)
//! );
//! ```

// ============================================================================
// Row struct 定义（依据 proposal H6 + tasks T042）
// ============================================================================

/// `role_hierarchy` 表行结构（T042 Green）。
///
/// 表示一条 `child_role → parent_role` 的继承边（在同一 `tenant_id` 下）。
///
/// # 字段命名
///
/// 使用 `child_role` / `parent_role`（对称清晰，与 SQL schema 一致），
/// 而非 `role` / `parent_role`（避免 `role` 单字段歧义）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoleHierarchyRecord {
    /// 子角色编码（继承方）。
    pub child_role: String,
    /// 父角色编码（被继承方）。
    pub parent_role: String,
    /// 租户 ID。
    pub tenant_id: i64,
}

// ============================================================================
// RoleHierarchyService（T045-T050 将实现完整能力）
// ============================================================================

/// 角色层级服务（TC 预计算 + 缓存 + 增量失效）。
///
/// 完整实现在 T045-T050 逐步构建：
/// - T045-T046: `compute_closure` DFS 遍历计算传递闭包（届时改为 `pub struct RoleHierarchyService { dao: Arc<dyn BulwarkDao> }`）
/// - T047-T048: `get_ancestors` 先查 oxcache 未命中则 `compute_closure` 并缓存
/// - T049-T050: `add_edge` + `invalidate_cache` 增量失效
///
/// 当前为占位 unit struct，T045 重构为带字段 struct 后再加 `new(dao)` 构造器。
pub struct RoleHierarchyService;

// ============================================================================
// 测试模块
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // T041: RoleHierarchyRecord 构造测试
    // ========================================================================

    /// T041 Red→Green：`RoleHierarchyRecord` 可构造且字段可读。
    ///
    /// 断言 `RoleHierarchyRecord { child_role, parent_role, tenant_id }`
    /// 三字段可正确初始化与读取。
    ///
    /// # 命名说明（Rule 7 冲突暴露）
    ///
    /// tasks.md T041 原描述用 `role` 字段，T043 SQL 用 `child_role`。
    /// 决策：统一用 `child_role` / `parent_role`（对称清晰，与 SQL 一致），
    /// 避免 `role` 单字段在 Rust 中与 `RoleRow` 混淆。
    #[test]
    fn role_hierarchy_record_constructs_with_role_parent_tenant() {
        let record = RoleHierarchyRecord {
            child_role: "user".to_string(),
            parent_role: "admin".to_string(),
            tenant_id: 0,
        };
        assert_eq!(record.child_role, "user");
        assert_eq!(record.parent_role, "admin");
        assert_eq!(record.tenant_id, 0);
    }

    /// RoleHierarchyRecord 支持 Clone / Debug / PartialEq / Serialize / Deserialize。
    #[test]
    fn role_hierarchy_record_derives_clone_debug_eq_serde() {
        let r1 = RoleHierarchyRecord {
            child_role: "user".to_string(),
            parent_role: "admin".to_string(),
            tenant_id: 0,
        };
        let r2 = r1.clone();
        assert_eq!(r1, r2);
        let json = serde_json::to_string(&r1).unwrap();
        let r3: RoleHierarchyRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(r1, r3);
        // Debug 可格式化
        let _debug = format!("{:?}", r1);
    }

    /// RoleHierarchyService 可构造（占位 unit struct，T045+ 重构为带字段 struct）。
    #[test]
    fn role_hierarchy_service_constructs() {
        let _svc = RoleHierarchyService;
    }
}

// ============================================================================
// db-sqlite 集成测试（T043-T044: role_hierarchy 表迁移验证）
// ============================================================================

#[cfg(all(test, feature = "db-sqlite"))]
mod db_sqlite_tests {
    use crate::dao::{init_dbnexus, BulwarkMigration};
    use dbnexus::DbPool;
    use sea_orm::{ConnectionTrait, DbBackend, Statement};
    use std::path::PathBuf;

    /// 定位项目根目录的 migrations/sqlite/ 目录。
    fn project_migrations_dir() -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir)
            .join("migrations")
            .join("sqlite")
    }

    /// 创建并初始化 SQLite in-memory 数据库（迁移 + 返回 pool）。
    async fn setup_db() -> DbPool {
        let pool = init_dbnexus("sqlite::memory:")
            .await
            .expect("init_dbnexus 应成功");
        let migration = BulwarkMigration::with_base_dir(pool.clone(), project_migrations_dir());
        let applied = migration.migrate_core().await.expect("migrate_core 应成功");
        assert!(applied >= 1, "migrate_core 应至少执行 1 个文件");
        pool
    }

    /// T044 Green: 验证 SQLite 迁移加载 `002_role_hierarchy.sql` 后 `role_hierarchy` 表存在。
    ///
    /// Rule 11（惯例优先）：SQL 文件放 `migrations/sqlite/core/002_role_hierarchy.sql`，
    /// 复用现有 `migrate_core()` 自动加载机制，无需修改 sqlite/mod.rs 的 migration 段。
    ///
    /// Rule 7（冲突暴露）：tasks.md T043 原描述路径 `src/dao/repository/sqlite/role_hierarchy.sql`
    /// 不符合现有 migration 目录结构（`migrations/sqlite/core/`），改为符合惯例的路径。
    #[tokio::test(flavor = "multi_thread")]
    async fn role_hierarchy_table_exists_after_migration() {
        let pool = setup_db().await;
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT name FROM sqlite_master WHERE type='table' AND name='role_hierarchy'",
            vec![],
        );
        let rows = conn.query_all_raw(stmt).await.expect("query_all 应成功");
        assert_eq!(
            rows.len(),
            1,
            "role_hierarchy 表应存在（迁移后 sqlite_master 应有 1 行记录）"
        );
    }
}
