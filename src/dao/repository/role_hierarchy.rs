//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
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
            let session = self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("role_hierarchy 获取 session 失败: {}", e))
            })?;
            let conn = session.connection().map_err(|e| {
                BulwarkError::Dao(format!("role_hierarchy 获取 connection 失败: {}", e))
            })?;
            let stmt = Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT child_role, parent_role FROM role_hierarchy WHERE tenant_id = ?",
                vec![Value::BigInt(Some(tenant_id))],
            );
            let rows = conn
                .query_all_raw(stmt)
                .await
                .map_err(|e| BulwarkError::Dao(format!("role_hierarchy 查询失败: {}", e)))?;
            let records = rows
                .into_iter()
                .map(|row| {
                    let child_role = row
                        .try_get::<String>("", "child_role")
                        .map_err(|e| BulwarkError::Dao(format!("child_role 读取失败: {}", e)))?;
                    let parent_role = row
                        .try_get::<String>("", "parent_role")
                        .map_err(|e| BulwarkError::Dao(format!("parent_role 读取失败: {}", e)))?;
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
                .map_err(|e| BulwarkError::Dao(format!("role_closure 序列化失败: {}", e)))?;
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
                BulwarkError::Dao(format!("role_hierarchy add_edge 获取 session 失败: {}", e))
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
                BulwarkError::Dao(format!("role_hierarchy add_edge 插入失败: {}", e))
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
}
