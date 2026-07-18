//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 角色层级 Repository 模块。
//!
//! 提供 `role_hierarchy` 表的 CRUD 与 TC（传递闭包）预计算能力。
//! 依据 cedar 工程思想：登录时预计算角色层级的间接祖先并缓存到 oxcache，
//! 避免每次权限校验都做 DFS。
//!
//! ## 核心抽象
//!
//! - [`RoleHierarchyRecord`](crate::dao::repository::role_hierarchy::RoleHierarchyRecord)：`role_hierarchy` 表行结构（child_role → parent_role + tenant_id）
//! - [`RoleHierarchyService`](crate::dao::repository::role_hierarchy::RoleHierarchyService)：TC 预计算 + 缓存 + 增量失效（T045-T050 实现，db-sqlite gated）
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
// Row struct 定义
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
// RoleHierarchyService（T045-db-sqlite gated，需 DbPool 查 SQL）
// ============================================================================

#[cfg(feature = "db-sqlite")]
mod service {
    use super::RoleHierarchyRecord;
    use crate::constants::DaoKeyPrefix;
    use crate::dao::BulwarkDao;
    use crate::error::{BulwarkError, BulwarkResult};
    use dbnexus::DbPool;
    use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    /// 角色层级服务（TC 预计算 + 缓存 + 增量失效）。
    ///
    /// 完整实现在 T045-T050 逐步构建：
    /// - T045-`compute_closure` DFS 遍历计算传递闭包（当前已实现）
    /// - T047-`get_ancestors` 先查 oxcache 未命中则 `compute_closure` 并缓存
    /// - T049-`add_edge` + `invalidate_cache` 增量失效
    ///
    /// # 字段
    ///
    /// - `pool`: SQLite 连接池（查 `role_hierarchy` 表）
    /// - `dao`: 缓存层抽象（T047+ 用于 oxcache 缓存闭包结果）
    ///
    /// # Rule 7 冲突暴露
    ///
    /// tasks.md T046 原描述 `pub dao: Arc<dyn BulwarkDao>` 不够——
    /// `compute_closure` 需查 SQL，BulwarkDao trait 是缓存层抽象不支持 SQL 查询。
    /// 决策：struct 同时持有 `pool: DbPool`（查 SQL）+ `dao: Arc<dyn BulwarkDao>`（查缓存）。
    pub struct RoleHierarchyService {
        /// SQLite 连接池（查 `role_hierarchy` 表）。
        pub pool: DbPool,
        /// 缓存层抽象（T047+ 用于 oxcache 缓存闭包结果）。
        pub dao: Arc<dyn BulwarkDao>,
    }

    impl RoleHierarchyService {
        /// 创建 RoleHierarchyService 实例。
        ///
        /// # 参数
        /// - `pool`: SQLite 连接池（用于查 `role_hierarchy` 表）
        /// - `dao`: 缓存层抽象（T047+ 用于 oxcache 缓存闭包结果）
        pub fn new(pool: DbPool, dao: Arc<dyn BulwarkDao>) -> Self {
            Self { pool, dao }
        }

        /// 查询指定租户的所有 role_hierarchy 记录。
        ///
        /// 返回 `Vec<RoleHierarchyRecord>`（child_role → parent_role 边集合）。
        async fn query_all_edges(&self, tenant_id: i64) -> BulwarkResult<Vec<RoleHierarchyRecord>> {
            let session = self
                .pool
                .get_session("admin")
                .await
                .map_err(|e| BulwarkError::Dao(format!("dao-role-hierarchy-session::{}", e)))?;
            let conn = session
                .connection()
                .map_err(|e| BulwarkError::Dao(format!("dao-role-hierarchy-connection::{}", e)))?;
            let stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT child_role, parent_role FROM role_hierarchy WHERE tenant_id = ?",
                vec![Value::BigInt(Some(tenant_id))],
            );
            let rows = conn
                .query_all_raw(stmt)
                .await
                .map_err(|e| BulwarkError::Dao(format!("dao-role-hierarchy-query::{}", e)))?;
            let records = rows
                .into_iter()
                .map(|row| {
                    let child_role = row
                        .try_get::<String>("", "child_role")
                        .map_err(|e| BulwarkError::Dao(format!("dao-child-role-read::{}", e)))?;
                    let parent_role = row
                        .try_get::<String>("", "parent_role")
                        .map_err(|e| BulwarkError::Dao(format!("dao-parent-role-read::{}", e)))?;
                    Ok::<_, BulwarkError>(RoleHierarchyRecord {
                        child_role,
                        parent_role,
                        tenant_id,
                    })
                })
                .collect::<Result<_, _>>()?;
            Ok(records)
        }

        /// 计算指定租户的角色层级传递闭包（T045-T046）。
        ///
        /// DFS 遍历 `role_hierarchy` 表，对每个 `child_role` 收集所有祖先
        ///（含直接父角色与间接祖先）。
        ///
        /// # 参数
        /// - `tenant_id`: 租户 ID（0=默认租户）。
        ///
        /// # 返回
        /// `HashMap<String, HashSet<String>>`：key=child_role，value=所有祖先集合。
        ///
        /// # 算法
        /// 1. 查询所有 `role_hierarchy` 记录，构建 `child → parents` 邻接表
        /// 2. 对每个 child，DFS 遍历收集所有祖先（避免环：用 visited 集合）
        /// 3. 返回闭包表
        ///
        /// # 错误
        /// - `BulwarkError::Dao`：SQL 查询失败。
        pub async fn compute_closure(
            &self,
            tenant_id: i64,
        ) -> BulwarkResult<HashMap<String, HashSet<String>>> {
            let edges = self.query_all_edges(tenant_id).await?;

            // 构建 child → parents 邻接表
            let mut adj: HashMap<String, Vec<String>> = HashMap::new();
            for edge in &edges {
                adj.entry(edge.child_role.clone())
                    .or_default()
                    .push(edge.parent_role.clone());
            }

            // 对每个 child DFS 收集所有祖先
            let mut closure: HashMap<String, HashSet<String>> = HashMap::new();
            for child in adj.keys() {
                let ancestors = Self::dfs_ancestors(child, &adj, &mut HashSet::new());
                closure.insert(child.clone(), ancestors);
            }

            Ok(closure)
        }

        /// DFS 递归收集 `role` 的所有祖先（含间接祖先）。
        ///
        /// # 参数
        /// - `role`: 起始角色
        /// - `adj`: child → parents 邻接表
        /// - `visited`: 已访问角色集合（防止环）
        ///
        /// # 返回
        /// `role` 的所有祖先集合（不含 `role` 自身）。
        fn dfs_ancestors(
            role: &str,
            adj: &HashMap<String, Vec<String>>,
            visited: &mut HashSet<String>,
        ) -> HashSet<String> {
            let mut ancestors = HashSet::new();
            if visited.contains(role) {
                return ancestors; // 防止环
            }
            visited.insert(role.to_string());

            if let Some(parents) = adj.get(role) {
                for parent in parents {
                    ancestors.insert(parent.clone());
                    // 递归收集 parent 的祖先
                    let indirect = Self::dfs_ancestors(parent, adj, visited);
                    ancestors.extend(indirect);
                }
            }

            visited.remove(role); // 回溯（允许不同路径访问同一节点）
            ancestors
        }

        /// T048 Green: 获取指定角色的所有祖先（先查 oxcache，未命中则 `compute_closure` 并缓存 1 小时）。
        ///
        /// 缓存策略：
        /// - key: `tenant:{tenant_id}:role_closure`，存储整个租户的闭包 JSON
        /// - TTL: 3600 秒（1 小时）
        /// - 反序列化失败时降级重新计算（不阻断主流程，记录在错误返回中）
        ///
        /// # 参数
        /// - `role`: 起始角色
        /// - `tenant_id`: 租户 ID（0=默认租户）
        ///
        /// # 返回
        /// `role` 的所有祖先集合（不含 `role` 自身）。若 `role` 不在闭包中，返回空集合。
        ///
        /// # 错误
        /// - `BulwarkError::Dao`：SQL 查询或缓存读写失败。
        pub async fn get_ancestors(
            &self,
            role: &str,
            tenant_id: i64,
        ) -> BulwarkResult<HashSet<String>> {
            let cache_key = format!("{}{}:role_closure", DaoKeyPrefix::Tenant, tenant_id);

            // 先查 oxcache
            if let Some(cached) = self.dao.get(&cache_key).await? {
                if let Ok(closure) =
                    serde_json::from_str::<HashMap<String, HashSet<String>>>(&cached)
                {
                    return Ok(closure.get(role).cloned().unwrap_or_default());
                }
                // 反序列化失败：降级重新计算（缓存损坏，不阻断）
            }

            // 未命中或反序列化失败：重新计算并缓存
            let closure = self.compute_closure(tenant_id).await?;
            let json = serde_json::to_string(&closure)
                .map_err(|e| BulwarkError::Dao(format!("dao-role-closure-serialize::{}", e)))?;
            self.dao.set(&cache_key, &json, 3600).await?;

            Ok(closure.get(role).cloned().unwrap_or_default())
        }

        /// T050 Green: 添加角色继承边（`INSERT OR IGNORE`）并失效该租户的闭包缓存。
        ///
        /// 幂等：若 `(tenant_id, child, parent)` 已存在，`INSERT OR IGNORE` 不报错。
        /// 缓存失效：插入成功后立即删除 `tenant:{tenant_id}:role_closure`，
        /// 下次 `get_ancestors` 会重新计算闭包并写入缓存。
        ///
        /// # 参数
        /// - `child`: 子角色编码（继承方）
        /// - `parent`: 父角色编码（被继承方）
        /// - `tenant_id`: 租户 ID
        ///
        /// # 错误
        /// - `BulwarkError::Dao`：SQL 执行或缓存删除失败。
        pub async fn add_edge(
            &self,
            child: &str,
            parent: &str,
            tenant_id: i64,
        ) -> BulwarkResult<()> {
            let session = self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("dao-role-hierarchy-add-edge-session::{}", e))
            })?;
            let conn = session.connection().map_err(|e| {
                BulwarkError::Dao(format!(
                    "role_hierarchy add_edge 获取 connection 失败: {}",
                    e
                ))
            })?;
            let stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "INSERT OR IGNORE INTO role_hierarchy (tenant_id, child_role, parent_role) VALUES (?, ?, ?)",
                vec![
                    Value::BigInt(Some(tenant_id)),
                    Value::String(Some(child.to_string())),
                    Value::String(Some(parent.to_string())),
                ],
            );
            conn.execute_raw(stmt).await.map_err(|e| {
                BulwarkError::Dao(format!("dao-role-hierarchy-add-edge-insert::{}", e))
            })?;

            self.invalidate_cache(tenant_id).await
        }

        /// T050 Green: 失效指定租户的闭包缓存。
        ///
        /// 删除 oxcache key `tenant:{tenant_id}:role_closure`。
        /// 幂等：若 key 不存在，`dao.delete` 不报错。
        ///
        /// # 参数
        /// - `tenant_id`: 租户 ID
        ///
        /// # 错误
        /// - `BulwarkError::Dao`：缓存删除失败。
        pub async fn invalidate_cache(&self, tenant_id: i64) -> BulwarkResult<()> {
            let cache_key = format!("{}{}:role_closure", DaoKeyPrefix::Tenant, tenant_id);
            self.dao.delete(&cache_key).await
        }

        /// 获取指定角色的所有后代（子角色集合）。
        ///
        /// 与 `get_ancestors` 反向：遍历 `parent → children` 邻接表，
        /// DFS 收集 `role` 的所有后代（含间接后代）。
        ///
        /// # 参数
        /// - `role`: 起始角色（父角色）
        /// - `tenant_id`: 租户 ID（0=默认租户）
        ///
        /// # 返回
        /// `role` 的所有后代集合（不含 `role` 自身）。若 `role` 无后代，返回空集合。
        ///
        /// # 错误
        /// - `BulwarkError::Dao`：SQL 查询失败。
        pub async fn get_descendants(
            &self,
            role: &str,
            tenant_id: i64,
        ) -> BulwarkResult<HashSet<String>> {
            let edges = self.query_all_edges(tenant_id).await?;

            // 构建 parent → children 邻接表（反向）
            let mut reverse_adj: HashMap<String, Vec<String>> = HashMap::new();
            for edge in &edges {
                reverse_adj
                    .entry(edge.parent_role.clone())
                    .or_default()
                    .push(edge.child_role.clone());
            }

            // DFS 收集所有后代
            let descendants = Self::dfs_descendants(role, &reverse_adj, &mut HashSet::new());
            Ok(descendants)
        }

        /// DFS 递归收集 `role` 的所有后代（含间接后代）。
        ///
        /// # 参数
        /// - `role`: 起始角色
        /// - `reverse_adj`: parent → children 邻接表
        /// - `visited`: 已访问角色集合（防止环）
        ///
        /// # 返回
        /// `role` 的所有后代集合（不含 `role` 自身）。
        fn dfs_descendants(
            role: &str,
            reverse_adj: &HashMap<String, Vec<String>>,
            visited: &mut HashSet<String>,
        ) -> HashSet<String> {
            let mut descendants = HashSet::new();
            if visited.contains(role) {
                return descendants;
            }
            visited.insert(role.to_string());

            if let Some(children) = reverse_adj.get(role) {
                for child in children {
                    descendants.insert(child.clone());
                    let indirect = Self::dfs_descendants(child, reverse_adj, visited);
                    descendants.extend(indirect);
                }
            }

            visited.remove(role);
            descendants
        }
    }
}

#[cfg(feature = "db-sqlite")]
pub use service::RoleHierarchyService;

// ============================================================================
// 测试模块（always compiled：RoleHierarchyRecord 构造测试）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // RoleHierarchyRecord 构造测试
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
}

// ============================================================================
// db-sqlite 集成测试（T043-role_hierarchy 表迁移 + compute_closure）
// ============================================================================

#[cfg(all(test, feature = "db-sqlite"))]
mod db_sqlite_tests {
    use super::*;
    use crate::dao::{init_dbnexus, BulwarkDao, BulwarkMigration};
    use dbnexus::DbPool;
    use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
    use std::path::PathBuf;
    use std::sync::Arc;

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

    /// 构造 MockDao 作为 BulwarkDao 实现（T047+ 用于 oxcache 缓存测试）。
    fn mock_dao() -> Arc<dyn BulwarkDao> {
        Arc::new(crate::dao::tests::MockDao::new())
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

    // ========================================================================
    // role_hierarchy 表迁移验证
    // ========================================================================

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

    // ========================================================================
    // T045-compute_closure 传递闭包测试
    // ========================================================================

    /// T045 Green: `compute_closure` 返回间接祖先。
    ///
    /// 构造 role_hierarchy 数据 `user -> admin -> super_admin`，
    /// 调用 `compute_closure(tenant_id=0)`，
    /// 断言返回的 HashMap 中 `"user"` 的 ancestors 集合含 `"admin"` 和 `"super_admin"`。
    #[tokio::test(flavor = "multi_thread")]
    async fn compute_closure_returns_indirect_ancestors() {
        let pool = setup_db().await;

        // 插入 role_hierarchy 数据：user -> admin -> super_admin
        insert_edge(&pool, 0, "user", "admin").await;
        insert_edge(&pool, 0, "admin", "super_admin").await;

        let svc = RoleHierarchyService::new(pool, mock_dao());
        let closure = svc
            .compute_closure(0)
            .await
            .expect("compute_closure 应成功");

        let user_ancestors = closure.get("user").expect("closure 应包含 user 的祖先集合");
        assert!(
            user_ancestors.contains("admin"),
            "user 的祖先应含 admin（直接父角色）"
        );
        assert!(
            user_ancestors.contains("super_admin"),
            "user 的祖先应含 super_admin（间接祖先）"
        );

        let admin_ancestors = closure
            .get("admin")
            .expect("closure 应包含 admin 的祖先集合");
        assert!(
            admin_ancestors.contains("super_admin"),
            "admin 的祖先应含 super_admin（直接父角色）"
        );
    }

    /// `compute_closure` 处理空表（无 role_hierarchy 记录）。
    #[tokio::test(flavor = "multi_thread")]
    async fn compute_closure_empty_table_returns_empty_map() {
        let pool = setup_db().await;
        let svc = RoleHierarchyService::new(pool, mock_dao());
        let closure = svc
            .compute_closure(0)
            .await
            .expect("compute_closure 应成功");
        assert!(closure.is_empty(), "空表应返回空 HashMap");
    }

    /// `compute_closure` 按租户隔离（tenant_id 过滤）。
    #[tokio::test(flavor = "multi_thread")]
    async fn compute_closure_filters_by_tenant_id() {
        let pool = setup_db().await;

        // tenant 0: user -> admin
        insert_edge(&pool, 0, "user", "admin").await;
        // tenant 1: user -> super_admin
        insert_edge(&pool, 1, "user", "super_admin").await;

        let svc = RoleHierarchyService::new(pool, mock_dao());

        // 查 tenant 0：user 的祖先应含 admin，不含 super_admin
        let closure_0 = svc
            .compute_closure(0)
            .await
            .expect("compute_closure(0) 应成功");
        let user_ancestors_0 = closure_0.get("user").expect("tenant 0 应有 user");
        assert!(user_ancestors_0.contains("admin"));
        assert!(!user_ancestors_0.contains("super_admin"));

        // 查 tenant 1：user 的祖先应含 super_admin，不含 admin
        let closure_1 = svc
            .compute_closure(1)
            .await
            .expect("compute_closure(1) 应成功");
        let user_ancestors_1 = closure_1.get("user").expect("tenant 1 应有 user");
        assert!(user_ancestors_1.contains("super_admin"));
        assert!(!user_ancestors_1.contains("admin"));
    }

    /// `compute_closure` 处理环（A -> B -> A 自环不应无限递归）。
    #[tokio::test(flavor = "multi_thread")]
    async fn compute_closure_handles_cycle_without_infinite_recursion() {
        let pool = setup_db().await;

        // 构造环：A -> B -> A
        insert_edge(&pool, 0, "A", "B").await;
        insert_edge(&pool, 0, "B", "A").await;

        let svc = RoleHierarchyService::new(pool, mock_dao());
        // 不应 stack overflow 或 hang
        let closure = svc
            .compute_closure(0)
            .await
            .expect("compute_closure 应成功");

        // A 的祖先应含 B（但不应含 A 自身，因 visited 防止环）
        let a_ancestors = closure.get("A").expect("closure 应包含 A");
        assert!(a_ancestors.contains("B"));
        // B 的祖先应含 A
        let b_ancestors = closure.get("B").expect("closure 应包含 B");
        assert!(b_ancestors.contains("A"));
    }

    // ========================================================================
    // T047-get_ancestors 缓存测试
    // ========================================================================

    /// T047 Red: `get_ancestors` 首次调用触发 `compute_closure` 并缓存到 oxcache。
    ///
    /// 构造 `user -> admin -> super_admin`，调用 `get_ancestors("user", 0)`，
    /// 断言返回集合含 `"admin"` 和 `"super_admin"`，并验证 oxcache 已写入
    /// key `tenant:0:role_closure`（TTL 1 小时）。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_ancestors_returns_cached_closure() {
        let pool = setup_db().await;
        let dao = mock_dao();

        // 先 insert_edge（pool 在 move 到 svc 之前完成借用）
        insert_edge(&pool, 0, "user", "admin").await;
        insert_edge(&pool, 0, "admin", "super_admin").await;

        let svc = RoleHierarchyService::new(pool, dao.clone());

        // 首次调用：触发 compute_closure + 缓存写入
        let ancestors = svc
            .get_ancestors("user", 0)
            .await
            .expect("get_ancestors 应成功");
        assert!(ancestors.contains("admin"), "应含 admin（直接父角色）");
        assert!(
            ancestors.contains("super_admin"),
            "应含 super_admin（间接祖先）"
        );

        // 验证 oxcache 已缓存完整闭包（key 格式 tenant:{tid}:role_closure）
        let cached = dao
            .get("tenant:0:role_closure")
            .await
            .expect("dao.get 应成功");
        assert!(cached.is_some(), "oxcache 应已缓存 role_closure");
    }

    // ========================================================================
    // T049-add_edge + invalidate_cache 测试
    // ========================================================================

    /// T049 Red: `add_edge` 插入新边后应失效该租户的闭包缓存。
    ///
    /// 流程：
    /// 1. `get_ancestors` 触发 `compute_closure` + 缓存写入
    /// 2. `add_edge("user", "super_admin", 0)` 插入新边
    /// 3. 断言 oxcache 中 `tenant:0:role_closure` 已被删除
    #[tokio::test(flavor = "multi_thread")]
    async fn add_edge_invalidates_cache() {
        let pool = setup_db().await;
        let dao = mock_dao();

        // 先插入初始边并触发缓存写入
        insert_edge(&pool, 0, "user", "admin").await;
        let svc = RoleHierarchyService::new(pool, dao.clone());
        let _ = svc
            .get_ancestors("user", 0)
            .await
            .expect("get_ancestors 应成功");

        let cached_before = dao
            .get("tenant:0:role_closure")
            .await
            .expect("dao.get 应成功");
        assert!(cached_before.is_some(), "前置条件：缓存应已写入");

        // add_edge 应失效缓存
        svc.add_edge("user", "super_admin", 0)
            .await
            .expect("add_edge 应成功");

        let cached_after = dao
            .get("tenant:0:role_closure")
            .await
            .expect("dao.get 应成功");
        assert!(cached_after.is_none(), "add_edge 后缓存应已失效");
    }

    /// T050 额外验证：`add_edge` 后再次 `get_ancestors` 应反映新边。
    ///
    /// 流程：
    /// 1. `user -> admin`，`get_ancestors("user")` 返回 {admin}
    /// 2. `add_edge("user", "super_admin", 0)`
    /// 3. `get_ancestors("user")` 重新计算，返回 {admin, super_admin}
    #[tokio::test(flavor = "multi_thread")]
    async fn add_edge_reflects_in_subsequent_get_ancestors() {
        let pool = setup_db().await;
        let dao = mock_dao();

        insert_edge(&pool, 0, "user", "admin").await;
        let svc = RoleHierarchyService::new(pool, dao.clone());

        // 首次：ancestors = {admin}
        let ancestors1 = svc
            .get_ancestors("user", 0)
            .await
            .expect("get_ancestors 应成功");
        assert!(ancestors1.contains("admin"));
        assert!(!ancestors1.contains("super_admin"));

        // 添加新边 user -> super_admin
        svc.add_edge("user", "super_admin", 0)
            .await
            .expect("add_edge 应成功");

        // 再次：ancestors = {admin, super_admin}
        let ancestors2 = svc
            .get_ancestors("user", 0)
            .await
            .expect("get_ancestors 应成功");
        assert!(ancestors2.contains("admin"));
        assert!(ancestors2.contains("super_admin"));
    }

    // ========================================================================
    // 补充测试：get_ancestors 缓存命中 / 损坏降级 / 不存在角色
    // ========================================================================

    /// `get_ancestors` 缓存命中时不查询 SQL。
    ///
    /// 流程：
    /// 1. 首次调用 get_ancestors 触发 compute_closure + 缓存写入
    /// 2. 删除 role_hierarchy 表所有数据
    /// 3. 再次调用 get_ancestors，缓存命中应返回与首次相同的结果（不查 SQL）
    #[tokio::test(flavor = "multi_thread")]
    async fn get_ancestors_cache_hit_does_not_query_db() {
        let pool = setup_db().await;
        let dao = mock_dao();

        insert_edge(&pool, 0, "user", "admin").await;
        let svc = RoleHierarchyService::new(pool.clone(), dao.clone());

        // 首次调用：触发 compute_closure + 缓存写入
        let ancestors1 = svc
            .get_ancestors("user", 0)
            .await
            .expect("get_ancestors 应成功");
        assert!(ancestors1.contains("admin"));

        // 删除 role_hierarchy 表所有数据
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        conn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "DELETE FROM role_hierarchy",
            vec![],
        ))
        .await
        .expect("DELETE 应成功");

        // 再次调用：缓存命中，不查 SQL，返回与首次相同的结果
        let ancestors2 = svc
            .get_ancestors("user", 0)
            .await
            .expect("缓存命中时 get_ancestors 应成功");
        assert!(
            ancestors2.contains("admin"),
            "缓存命中应返回与首次相同的结果"
        );
    }

    /// `get_ancestors` 缓存损坏时降级重新计算。
    ///
    /// 向 oxcache 注入损坏的闭包 JSON，验证 get_ancestors 降级走
    /// compute_closure 并重新写入有效缓存。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_ancestors_corrupt_cache_falls_back_to_recompute() {
        let pool = setup_db().await;
        let dao = mock_dao();

        insert_edge(&pool, 0, "user", "admin").await;
        let svc = RoleHierarchyService::new(pool, dao.clone());

        // 向 oxcache 注入损坏的闭包 JSON
        dao.set("tenant:0:role_closure", "{invalid json", 3600)
            .await
            .expect("注入损坏缓存应成功");

        // 调用 get_ancestors：缓存损坏 → 降级重新计算
        let ancestors = svc
            .get_ancestors("user", 0)
            .await
            .expect("降级重新计算应成功");
        assert!(ancestors.contains("admin"), "降级重新计算后应返回正确结果");

        // 验证缓存已被更新（覆盖损坏数据）
        let cached = dao
            .get("tenant:0:role_closure")
            .await
            .expect("dao.get 应成功");
        assert!(cached.is_some(), "缓存应已被重新写入");
        // 验证缓存内容是有效的 JSON
        let closure: std::collections::HashMap<String, std::collections::HashSet<String>> =
            serde_json::from_str(&cached.unwrap()).expect("缓存应为有效 JSON");
        assert!(closure.contains_key("user"), "闭包应包含 user");
    }

    /// `get_ancestors` 对不在闭包中的角色返回空集合。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_ancestors_for_nonexistent_role_returns_empty() {
        let pool = setup_db().await;
        let dao = mock_dao();

        insert_edge(&pool, 0, "user", "admin").await;
        let svc = RoleHierarchyService::new(pool, dao);

        // 查询不存在的角色
        let ancestors = svc
            .get_ancestors("nonexistent_role", 0)
            .await
            .expect("get_ancestors 应成功");
        assert!(ancestors.is_empty(), "不存在的角色应返回空祖先集合");
    }

    /// `invalidate_cache` 单独调用是幂等的。
    #[tokio::test(flavor = "multi_thread")]
    async fn invalidate_cache_is_idempotent() {
        let pool = setup_db().await;
        let dao = mock_dao();

        let svc = RoleHierarchyService::new(pool, dao);

        // 对从未缓存过的租户调用 invalidate_cache
        let result = svc.invalidate_cache(999).await;
        assert!(result.is_ok(), "invalidate_cache 不存在的缓存应幂等返回 Ok");

        // 再次调用也不报错
        let result2 = svc.invalidate_cache(999).await;
        assert!(result2.is_ok(), "多次调用 invalidate_cache 应幂等");
    }

    // ========================================================================
    // 补充测试：get_descendants（完全未覆盖的方法）
    // ========================================================================

    /// `get_descendants` 返回间接后代。
    ///
    /// 构造层级 user -> admin -> super_admin（user 继承 admin，admin 继承 super_admin），
    /// 验证 super_admin 的后代含 admin（直接）和 user（间接）。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_descendants_returns_indirect_descendants() {
        let pool = setup_db().await;

        // user -> admin -> super_admin
        insert_edge(&pool, 0, "user", "admin").await;
        insert_edge(&pool, 0, "admin", "super_admin").await;

        let svc = RoleHierarchyService::new(pool, mock_dao());

        // super_admin 的后代应含 admin（直接子角色）和 user（间接后代）
        let descendants = svc
            .get_descendants("super_admin", 0)
            .await
            .expect("get_descendants 应成功");
        assert!(
            descendants.contains("admin"),
            "super_admin 的后代应含 admin（直接子角色）"
        );
        assert!(
            descendants.contains("user"),
            "super_admin 的后代应含 user（间接后代）"
        );

        // admin 的后代应含 user，不含 super_admin
        let admin_descendants = svc
            .get_descendants("admin", 0)
            .await
            .expect("get_descendants 应成功");
        assert!(admin_descendants.contains("user"), "admin 的后代应含 user");
        assert!(
            !admin_descendants.contains("super_admin"),
            "admin 的后代不应含 super_admin（方向相反）"
        );

        // user 的后代应为空（user 是最底层）
        let user_descendants = svc
            .get_descendants("user", 0)
            .await
            .expect("get_descendants 应成功");
        assert!(
            user_descendants.is_empty(),
            "user 无后代（user 是最底层角色）"
        );
    }

    /// `get_descendants` 空表返回空集合。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_descendants_empty_table_returns_empty() {
        let pool = setup_db().await;
        let svc = RoleHierarchyService::new(pool, mock_dao());

        let descendants = svc
            .get_descendants("any_role", 0)
            .await
            .expect("get_descendants 应成功");
        assert!(descendants.is_empty(), "空表应返回空后代集合");
    }

    /// `get_descendants` 处理环（A -> B -> A 不应无限递归）。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_descendants_handles_cycle_without_infinite_recursion() {
        let pool = setup_db().await;

        // 构造环：A -> B -> A（A 继承 B，B 继承 A）
        insert_edge(&pool, 0, "A", "B").await;
        insert_edge(&pool, 0, "B", "A").await;

        let svc = RoleHierarchyService::new(pool, mock_dao());

        // 不应 stack overflow 或 hang
        let descendants_a = svc
            .get_descendants("A", 0)
            .await
            .expect("get_descendants 应成功");
        // A 的后代应含 B（A 继承 B，所以 B 的后代包含 A，A 的后代包含 B）
        assert!(descendants_a.contains("B"), "A 的后代应含 B");

        let descendants_b = svc
            .get_descendants("B", 0)
            .await
            .expect("get_descendants 应成功");
        assert!(descendants_b.contains("A"), "B 的后代应含 A");
    }

    /// `get_descendants` 按租户隔离。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_descendants_filters_by_tenant_id() {
        let pool = setup_db().await;

        // tenant 0: user -> admin
        insert_edge(&pool, 0, "user", "admin").await;
        // tenant 1: user -> super_admin
        insert_edge(&pool, 1, "user", "super_admin").await;

        let svc = RoleHierarchyService::new(pool, mock_dao());

        // tenant 0：admin 的后代应含 user，不含 super_admin
        let desc_0 = svc
            .get_descendants("admin", 0)
            .await
            .expect("get_descendants(0) 应成功");
        assert!(desc_0.contains("user"), "tenant 0: admin 的后代应含 user");
        assert!(
            !desc_0.contains("super_admin"),
            "tenant 0: admin 的后代不应含 super_admin"
        );

        // tenant 1：super_admin 的后代应含 user，不含 admin
        let desc_1 = svc
            .get_descendants("super_admin", 1)
            .await
            .expect("get_descendants(1) 应成功");
        assert!(
            desc_1.contains("user"),
            "tenant 1: super_admin 的后代应含 user"
        );
        assert!(
            !desc_1.contains("admin"),
            "tenant 1: super_admin 的后代不应含 admin"
        );
    }

    /// `get_descendants` 对不存在的角色返回空集合。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_descendants_for_nonexistent_role_returns_empty() {
        let pool = setup_db().await;

        insert_edge(&pool, 0, "user", "admin").await;
        let svc = RoleHierarchyService::new(pool, mock_dao());

        let descendants = svc
            .get_descendants("nonexistent_role", 0)
            .await
            .expect("get_descendants 应成功");
        assert!(descendants.is_empty(), "不存在的角色应返回空后代集合");
    }

    /// `get_descendants` 处理多分支（菱形继承）。
    ///
    /// 构造：D -> B -> A, D -> C -> A
    /// A 的后代应含 B, C, D。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_descendants_handles_diamond_inheritance() {
        let pool = setup_db().await;

        // D 继承 B, B 继承 A
        insert_edge(&pool, 0, "D", "B").await;
        insert_edge(&pool, 0, "B", "A").await;
        // D 继承 C, C 继承 A
        insert_edge(&pool, 0, "D", "C").await;
        insert_edge(&pool, 0, "C", "A").await;

        let svc = RoleHierarchyService::new(pool, mock_dao());

        // A 的后代应含 B, C, D
        let descendants = svc
            .get_descendants("A", 0)
            .await
            .expect("get_descendants 应成功");
        assert!(descendants.contains("B"), "A 的后代应含 B");
        assert!(descendants.contains("C"), "A 的后代应含 C");
        assert!(descendants.contains("D"), "A 的后代应含 D");

        // B 的后代应含 D，不含 C/A
        let b_descendants = svc
            .get_descendants("B", 0)
            .await
            .expect("get_descendants 应成功");
        assert!(b_descendants.contains("D"), "B 的后代应含 D");
        assert!(!b_descendants.contains("A"), "B 的后代不应含 A");
    }

    // ========================================================================
    // 补充测试：add_edge 幂等性
    // ========================================================================

    /// `add_edge` 重复插入相同边是幂等的（INSERT OR IGNORE）。
    #[tokio::test(flavor = "multi_thread")]
    async fn add_edge_is_idempotent() {
        let pool = setup_db().await;
        let dao = mock_dao();

        let svc = RoleHierarchyService::new(pool.clone(), dao);

        // 第一次插入
        svc.add_edge("user", "admin", 0)
            .await
            .expect("第一次 add_edge 应成功");

        // 第二次插入相同边（应幂等不报错）
        let result = svc.add_edge("user", "admin", 0).await;
        assert!(result.is_ok(), "重复插入相同边应幂等返回 Ok");

        // 验证只有一条记录
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT COUNT(*) as cnt FROM role_hierarchy WHERE tenant_id = 0 AND child_role = 'user' AND parent_role = 'admin'",
            vec![],
        );
        let rows = conn.query_all_raw(stmt).await.expect("COUNT 查询应成功");
        let count: i64 = rows[0].try_get::<i64>("", "cnt").expect("读取 cnt 应成功");
        assert_eq!(count, 1, "重复插入后应只有 1 条记录（INSERT OR IGNORE）");
    }

    // ========================================================================
    // 补充测试：compute_closure 菱形继承 / 自环 / 多分量 / 多层链
    // ========================================================================

    /// `compute_closure` 处理菱形继承（ancestors 方向）。
    ///
    /// 构造 D -> B -> A, D -> C -> A：
    /// D 的祖先应含 B, C, A（通过两条路径都能到达 A，但集合去重）。
    /// 覆盖 `dfs_ancestors` 的 backtracking 逻辑（`visited.remove(role)`）——
    /// 若不回溯，C -> A 路径会因 A 已被 B -> A 访问而漏掉。
    #[tokio::test(flavor = "multi_thread")]
    async fn compute_closure_diamond_inheritance_collects_all_ancestors() {
        let pool = setup_db().await;

        // D 继承 B, B 继承 A
        insert_edge(&pool, 0, "D", "B").await;
        insert_edge(&pool, 0, "B", "A").await;
        // D 继承 C, C 继承 A
        insert_edge(&pool, 0, "D", "C").await;
        insert_edge(&pool, 0, "C", "A").await;

        let svc = RoleHierarchyService::new(pool, mock_dao());
        let closure = svc
            .compute_closure(0)
            .await
            .expect("compute_closure 应成功");

        let d_ancestors = closure.get("D").expect("closure 应包含 D");
        assert!(d_ancestors.contains("B"), "D 的祖先应含 B");
        assert!(d_ancestors.contains("C"), "D 的祖先应含 C");
        assert!(
            d_ancestors.contains("A"),
            "D 的祖先应含 A（菱形继承的顶点）"
        );
        assert_eq!(
            d_ancestors.len(),
            3,
            "D 的祖先应为 {{B, C, A}}（去重后 3 个）"
        );

        // B 的祖先应含 A，不含 C/D
        let b_ancestors = closure.get("B").expect("closure 应包含 B");
        assert!(b_ancestors.contains("A"), "B 的祖先应含 A");
        assert!(!b_ancestors.contains("C"), "B 的祖先不应含 C");
        assert!(!b_ancestors.contains("D"), "B 的祖先不应含 D");
    }

    /// `compute_closure` 处理自环（A -> A）。
    ///
    /// 自环 A -> A 时，A 被插入为自身的祖先（`ancestors.insert(parent)` 先于
    /// 递归调用执行），但 `visited` 防止无限递归。
    /// 此测试验证自环不会 stack overflow，并记录实际行为。
    #[tokio::test(flavor = "multi_thread")]
    async fn compute_closure_self_loop_does_not_infinite_recurse() {
        let pool = setup_db().await;

        // 自环：A -> A
        insert_edge(&pool, 0, "A", "A").await;

        let svc = RoleHierarchyService::new(pool, mock_dao());
        let closure = svc
            .compute_closure(0)
            .await
            .expect("compute_closure 应成功");

        // A 在邻接表中（有自环边），所以 closure 应包含 A
        let a_ancestors = closure
            .get("A")
            .expect("closure 应包含 A（自环边使 A 在 adj 中）");
        // 自环导致 A 被插入为自身的祖先（当前实现行为）
        assert!(
            a_ancestors.contains("A"),
            "自环 A->A 时 A 出现在自身祖先集合中（实现行为）"
        );
    }

    /// `compute_closure` 处理多个不连通分量。
    ///
    /// 构造两组独立的层级：A -> B 和 C -> D，
    /// 验证两组都出现在闭包中且互不干扰。
    #[tokio::test(flavor = "multi_thread")]
    async fn compute_closure_multiple_disconnected_components() {
        let pool = setup_db().await;

        // 分量 1: A -> B
        insert_edge(&pool, 0, "A", "B").await;
        // 分量 2: C -> D
        insert_edge(&pool, 0, "C", "D").await;

        let svc = RoleHierarchyService::new(pool, mock_dao());
        let closure = svc
            .compute_closure(0)
            .await
            .expect("compute_closure 应成功");

        assert_eq!(closure.len(), 2, "应有两个不连通分量（A 和 C）");

        let a_ancestors = closure.get("A").expect("closure 应包含 A");
        assert!(a_ancestors.contains("B"), "A 的祖先应含 B");
        assert!(!a_ancestors.contains("D"), "A 的祖先不应含 D（不连通）");

        let c_ancestors = closure.get("C").expect("closure 应包含 C");
        assert!(c_ancestors.contains("D"), "C 的祖先应含 D");
        assert!(!c_ancestors.contains("B"), "C 的祖先不应含 B（不连通）");
    }

    /// `compute_closure` 处理多层链（5 层深度）。
    ///
    /// 构造 L0 -> L1 -> L2 -> L3 -> L4，
    /// 验证 L0 的祖先含 L1~L4 全部，L4 的祖先为空。
    #[tokio::test(flavor = "multi_thread")]
    async fn compute_closure_multi_level_chain_collects_all_ancestors() {
        let pool = setup_db().await;

        // 5 层链: L0 -> L1 -> L2 -> L3 -> L4
        insert_edge(&pool, 0, "L0", "L1").await;
        insert_edge(&pool, 0, "L1", "L2").await;
        insert_edge(&pool, 0, "L2", "L3").await;
        insert_edge(&pool, 0, "L3", "L4").await;

        let svc = RoleHierarchyService::new(pool, mock_dao());
        let closure = svc
            .compute_closure(0)
            .await
            .expect("compute_closure 应成功");

        let l0_ancestors = closure.get("L0").expect("closure 应包含 L0");
        assert_eq!(
            l0_ancestors.len(),
            4,
            "L0 的祖先应含 L1, L2, L3, L4（共 4 个）"
        );
        assert!(l0_ancestors.contains("L1"));
        assert!(l0_ancestors.contains("L2"));
        assert!(l0_ancestors.contains("L3"));
        assert!(l0_ancestors.contains("L4"));

        let l3_ancestors = closure.get("L3").expect("closure 应包含 L3");
        assert!(
            l3_ancestors.contains("L4"),
            "L3 的祖先应含 L4（直接父角色）"
        );
        assert_eq!(l3_ancestors.len(), 1, "L3 的祖先应只有 L4");
    }

    // ========================================================================
    // 补充测试：get_ancestors 缓存复用（同一租户不同角色共享缓存）
    // ========================================================================

    /// `get_ancestors` 首次调用缓存整个租户闭包后，第二次调用不同角色应命中缓存。
    ///
    /// 流程：
    /// 1. 构造 user -> admin, reader -> viewer
    /// 2. 首次 get_ancestors("user") 触发 compute_closure + 缓存写入
    /// 3. 删除 role_hierarchy 所有数据
    /// 4. get_ancestors("reader") 应从缓存返回 viewer（而非空集合）
    ///
    /// 覆盖 `closure.get(role).cloned().unwrap_or_default()` 在缓存命中时的路径。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_ancestors_second_role_hits_cached_closure() {
        let pool = setup_db().await;
        let dao = mock_dao();

        insert_edge(&pool, 0, "user", "admin").await;
        insert_edge(&pool, 0, "reader", "viewer").await;

        let svc = RoleHierarchyService::new(pool.clone(), dao.clone());

        // 首次调用 user：触发 compute_closure + 缓存写入
        let user_ancestors = svc
            .get_ancestors("user", 0)
            .await
            .expect("首次 get_ancestors(user) 应成功");
        assert!(user_ancestors.contains("admin"));

        // 删除所有数据
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        conn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "DELETE FROM role_hierarchy",
            vec![],
        ))
        .await
        .expect("DELETE 应成功");

        // 第二次调用 reader：应从缓存返回 viewer（而非重新计算返回空）
        let reader_ancestors = svc
            .get_ancestors("reader", 0)
            .await
            .expect("缓存命中时 get_ancestors(reader) 应成功");
        assert!(
            reader_ancestors.contains("viewer"),
            "缓存命中时应返回 reader 的祖先 viewer"
        );
    }

    // ========================================================================
    // 补充测试：add_edge 跨租户缓存隔离
    // ========================================================================

    /// `add_edge` 在 tenant 1 添加边只失效 tenant 1 的缓存，不影响 tenant 0。
    ///
    /// 流程：
    /// 1. tenant 0 和 tenant 1 各自 get_ancestors 触发缓存写入
    /// 2. tenant 1 add_edge 失效 tenant 1 缓存
    /// 3. tenant 0 缓存应仍存在
    #[tokio::test(flavor = "multi_thread")]
    async fn add_edge_invalidates_only_same_tenant_cache() {
        let pool = setup_db().await;
        let dao = mock_dao();

        insert_edge(&pool, 0, "user0", "admin0").await;
        insert_edge(&pool, 1, "user1", "admin1").await;

        let svc = RoleHierarchyService::new(pool, dao.clone());

        // 两个租户各自触发缓存写入
        svc.get_ancestors("user0", 0)
            .await
            .expect("tenant 0 首次查询应成功");
        svc.get_ancestors("user1", 1)
            .await
            .expect("tenant 1 首次查询应成功");

        // 两个缓存都应存在
        assert!(
            dao.get("tenant:0:role_closure").await.unwrap().is_some(),
            "tenant 0 缓存应已写入"
        );
        assert!(
            dao.get("tenant:1:role_closure").await.unwrap().is_some(),
            "tenant 1 缓存应已写入"
        );

        // tenant 1 add_edge 只失效 tenant 1 缓存
        svc.add_edge("user1", "super_admin1", 1)
            .await
            .expect("add_edge(tenant 1) 应成功");

        assert!(
            dao.get("tenant:0:role_closure").await.unwrap().is_some(),
            "tenant 0 缓存应仍存在（跨租户隔离）"
        );
        assert!(
            dao.get("tenant:1:role_closure").await.unwrap().is_none(),
            "tenant 1 缓存应已失效"
        );
    }

    // ========================================================================
    // 补充测试：get_descendants 自环 / 多父节点
    // ========================================================================

    /// `get_descendants` 处理自环（A -> A）。
    ///
    /// 自环 A -> A 时，A 被插入为自身的后代（`descendants.insert(child)` 先于
    /// 递归调用执行），但 `visited` 防止无限递归。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_descendants_self_loop_does_not_infinite_recurse() {
        let pool = setup_db().await;

        // 自环：A -> A（A 继承 A）
        insert_edge(&pool, 0, "A", "A").await;

        let svc = RoleHierarchyService::new(pool, mock_dao());
        // 不应 stack overflow 或 hang
        let descendants = svc
            .get_descendants("A", 0)
            .await
            .expect("get_descendants 应成功");

        // 自环导致 A 出现在自身的后代集合中（当前实现行为）
        assert!(
            descendants.contains("A"),
            "自环 A->A 时 A 出现在自身后代集合中（实现行为）"
        );
    }

    /// `get_descendants` 处理多父节点（一个 child 继承多个 parent）。
    ///
    /// 构造：user -> admin, user -> manager
    ///（user 同时继承 admin 和 manager）
    /// admin 的后代应含 user，manager 的后代也应含 user。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_descendants_multi_parent_child_appears_under_all_parents() {
        let pool = setup_db().await;

        // user 同时继承 admin 和 manager
        insert_edge(&pool, 0, "user", "admin").await;
        insert_edge(&pool, 0, "user", "manager").await;

        let svc = RoleHierarchyService::new(pool, mock_dao());

        // admin 的后代应含 user
        let admin_desc = svc
            .get_descendants("admin", 0)
            .await
            .expect("get_descendants(admin) 应成功");
        assert!(
            admin_desc.contains("user"),
            "admin 的后代应含 user（user 继承 admin）"
        );

        // manager 的后代应含 user
        let mgr_desc = svc
            .get_descendants("manager", 0)
            .await
            .expect("get_descendants(manager) 应成功");
        assert!(
            mgr_desc.contains("user"),
            "manager 的后代应含 user（user 继承 manager）"
        );

        // user 的后代应为空
        let user_desc = svc
            .get_descendants("user", 0)
            .await
            .expect("get_descendants(user) 应成功");
        assert!(user_desc.is_empty(), "user 无后代");
    }

    /// `compute_closure` 处理多父节点（一个 child 继承多个 parent）。
    ///
    /// 构造：user -> admin, user -> super_admin
    /// user 的祖先应含 admin 和 super_admin（两个都在集合中）。
    #[tokio::test(flavor = "multi_thread")]
    async fn compute_closure_multi_parent_collects_all_parents() {
        let pool = setup_db().await;

        // user 同时继承 admin 和 super_admin
        insert_edge(&pool, 0, "user", "admin").await;
        insert_edge(&pool, 0, "user", "super_admin").await;

        let svc = RoleHierarchyService::new(pool, mock_dao());
        let closure = svc
            .compute_closure(0)
            .await
            .expect("compute_closure 应成功");

        let user_ancestors = closure.get("user").expect("closure 应包含 user");
        assert!(user_ancestors.contains("admin"), "user 的祖先应含 admin");
        assert!(
            user_ancestors.contains("super_admin"),
            "user 的祖先应含 super_admin"
        );
        assert_eq!(
            user_ancestors.len(),
            2,
            "user 的祖先应为 {{admin, super_admin}}（共 2 个）"
        );
    }
}
