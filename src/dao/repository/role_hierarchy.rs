// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 角色层级 Repository 模块：`role_hierarchy` 表的 CRUD 与 TC（传递闭包）预计算——
//! 登录时预计算间接祖先并缓存 oxcache，避免每次权限校验做 DFS（cedar 工程思想）。
//!
//! 核心抽象：[`RoleHierarchyRecord`](crate::dao::repository::role_hierarchy::RoleHierarchyRecord)（表行结构）
//! + `RoleHierarchyService`（TC 预计算 + 缓存 + 增量失效，any(db-sqlite, db-postgres, db-mysql) gated）。
//!
//! ## 表结构
//!
//! ```sql
//! CREATE TABLE role_hierarchy (
//! tenant_id INTEGER NOT NULL DEFAULT 0,
//! child_role TEXT NOT NULL,
//! parent_role TEXT NOT NULL,
//! PRIMARY KEY (tenant_id, child_role, parent_role)
//! );
//! ```

// Row struct 定义

/// `role_hierarchy` 表行：一条 `child_role → parent_role` 继承边（同 `tenant_id` 下）。
/// 字段用 `child_role` / `parent_role`（与 SQL schema 一致，避免 `role` 单字段歧义）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RoleHierarchyRecord {
    /// 子角色编码（继承方）。
    pub child_role: String,
    /// 父角色编码（被继承方）。
    pub parent_role: String,
    /// 租户 ID。
    pub tenant_id: i64,
}

// RoleHierarchyService（any(db-sqlite, db-postgres, db-mysql) gated，需 DbPool 查 SQL）

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
mod service {
    use super::RoleHierarchyRecord;
    use crate::constants::DaoKeyPrefix;
    use crate::dao::GarrisonDao;
    use crate::error::{GarrisonError, GarrisonResult};
    use std::collections::{HashMap, HashSet};
    use std::sync::Arc;

    /// 角色层级服务：TC 预计算（DFS 传递闭包，含环 / 自环防护）+ oxcache 缓存（TTL 1h）+ 增量失效；
    /// 支持全部 db 后端（SQL 方言按连接后端自适应）。
    ///
    /// 仅持有 `dao`（统一数据访问层，应传 `GarrisonDaoDbnexus`）：SQL 经 `dao.query_role_hierarchy_edges()` 等方法，
    /// KV 缓存经 `dao.get()` / `dao.set()` / `dao.delete()`。
    pub struct RoleHierarchyService {
        /// 统一数据访问层（KV 缓存 + SQL 方法）。
        pub dao: Arc<dyn GarrisonDao>,
    }

    impl RoleHierarchyService {
        /// 创建实例；`dao` 应传 `GarrisonDaoDbnexus`（KV + SQL 统一实现）。
        pub fn new(dao: Arc<dyn GarrisonDao>) -> Self {
            Self { dao }
        }

        /// 查询租户的全部 role_hierarchy 记录（委托 `dao.query_role_hierarchy_edges()`）。
        async fn query_all_edges(
            &self,
            tenant_id: i64,
        ) -> GarrisonResult<Vec<RoleHierarchyRecord>> {
            let edges = self.dao.query_role_hierarchy_edges(tenant_id).await?;
            Ok(edges
                .into_iter()
                .map(|(child_role, parent_role)| RoleHierarchyRecord {
                    child_role,
                    parent_role,
                    tenant_id,
                })
                .collect())
        }

        /// 计算指定租户的角色层级传递闭包（key=child_role，value=所有祖先集合，**不含角色自身**）。
        ///
        /// DFS 构建 `child → parents` 邻接表后逐 child 收集祖先（visited 防环；未受环截断的完整
        /// 结果进备忘录复用，线性链从 O(n²) 降为 O(n+e)）；自环 A→A 与环路均不写入自身祖先集。
        ///
        /// 错误：SQL 查询失败返回 `GarrisonError::Dao`。
        pub async fn compute_closure(
            &self,
            tenant_id: i64,
        ) -> GarrisonResult<HashMap<String, HashSet<String>>> {
            let edges = self.query_all_edges(tenant_id).await?;

            // 构建 child → parents 邻接表
            let mut adj: HashMap<String, Vec<String>> = HashMap::new();
            for edge in &edges {
                adj.entry(edge.child_role.clone())
                    .or_default()
                    .push(edge.parent_role.clone());
            }

            // 对每个 child DFS 收集所有祖先（备忘录在同一闭包计算内跨 child 复用：
            // 仅缓存未因环截断的完整祖先集合，含环节点的结果不缓存）
            let mut closure: HashMap<String, HashSet<String>> = HashMap::new();
            let mut memo: HashMap<String, HashSet<String>> = HashMap::new();
            for child in adj.keys() {
                let (ancestors, _complete) =
                    Self::dfs_ancestors(child, &adj, &mut HashSet::new(), &mut memo);
                closure.insert(child.clone(), ancestors);
            }

            Ok(closure)
        }

        /// DFS 收集 `role` 的全部祖先（含间接，**不含 `role` 自身**）。
        /// 返回 `(ancestors, complete)`；`complete == false` 表示因环截断，仅 `true` 的结果可写入 `memo` 复用。
        fn dfs_ancestors(
            role: &str,
            adj: &HashMap<String, Vec<String>>,
            visited: &mut HashSet<String>,
            memo: &mut HashMap<String, HashSet<String>>,
        ) -> (HashSet<String>, bool) {
            let mut ancestors = HashSet::new();
            if visited.contains(role) {
                return (ancestors, false); // 防止环（截断，结果不完整）
            }
            if let Some(cached) = memo.get(role) {
                // 备忘录条目均为完整祖先集合（与当前 DFS 路径无关），可直接复用
                return (cached.clone(), true);
            }
            visited.insert(role.to_string());

            let mut complete = true;
            if let Some(parents) = adj.get(role) {
                for parent in parents {
                    if visited.contains(parent) {
                        // 环 / 自环：先检查 visited 再决定是否插入，保证「祖先集合不含 role 自身」契约
                        complete = false;
                        continue;
                    }
                    ancestors.insert(parent.clone());
                    // 递归收集 parent 的祖先
                    let (indirect, sub_complete) = Self::dfs_ancestors(parent, adj, visited, memo);
                    complete &= sub_complete;
                    ancestors.extend(indirect);
                }
            }

            visited.remove(role); // 回溯（允许不同路径访问同一节点）
            if complete {
                memo.insert(role.to_string(), ancestors.clone());
            }
            (ancestors, complete)
        }

        /// 获取 `role` 的所有祖先（先查 oxcache，未命中或反序列化失败则 `compute_closure` 重算回写）。
        ///
        /// 缓存 key `tenant:{tenant_id}:role_closure`（整租户闭包 JSON），TTL 3600s；
        /// 返回不含 `role` 自身，角色不在闭包中返回空集合。
        pub async fn get_ancestors(
            &self,
            role: &str,
            tenant_id: i64,
        ) -> GarrisonResult<HashSet<String>> {
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
                .map_err(|e| GarrisonError::Dao(format!("dao-role-closure-serialize::{}", e)))?;
            self.dao.set(&cache_key, &json, 3600).await?;

            Ok(closure.get(role).cloned().unwrap_or_default())
        }

        /// 幂等添加继承边（child → parent）并失效该租户闭包缓存；自环（child == parent）返回 `InvalidParam` 不入库。
        ///
        /// # 并发窗口（已知限制）
        ///
        /// 「写库 + 失效缓存」非原子：并发读者可在窗口内未命中并回写**不含新边**的陈旧闭包，
        /// 存活至缓存 TTL（3600s）到期；强一致调用方应在写入后再调一次幂等的 `invalidate_cache`，或接受最长一个 TTL 的陈旧读。
        pub async fn add_edge(
            &self,
            child: &str,
            parent: &str,
            tenant_id: i64,
        ) -> GarrisonResult<()> {
            if child == parent {
                return Err(GarrisonError::InvalidParam(format!(
                    "dao-role-hierarchy-self-loop::{}",
                    child
                )));
            }
            self.dao
                .insert_role_hierarchy_edge(tenant_id, child, parent)
                .await?;
            self.invalidate_cache(tenant_id).await
        }

        /// 删除 `tenant:{tenant_id}:role_closure` 缓存 key（幂等：key 不存在不报错）。
        ///
        /// # 并发窗口（已知限制）
        ///
        /// 与并发读者无同步：未命中回写（TOCTOU）可能覆盖本次失效，详见 [`RoleHierarchyService::add_edge`]。
        pub async fn invalidate_cache(&self, tenant_id: i64) -> GarrisonResult<()> {
            let cache_key = format!("{}{}:role_closure", DaoKeyPrefix::Tenant, tenant_id);
            self.dao.delete(&cache_key).await
        }

        /// 获取 `role` 的所有后代（反向：遍历 parent → children 邻接表 DFS；不含 `role` 自身，无后代返回空集合）。
        pub async fn get_descendants(
            &self,
            role: &str,
            tenant_id: i64,
        ) -> GarrisonResult<HashSet<String>> {
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

        /// DFS 收集 `role` 的所有后代（含间接，**不含 `role` 自身**——自环 A→A 与环路均不写入）。
        fn dfs_descendants(
            role: &str,
            reverse_adj: &HashMap<String, Vec<String>>,
            visited: &mut HashSet<String>,
        ) -> HashSet<String> {
            let mut descendants = HashSet::new();
            if visited.contains(role) {
                return descendants; // 防止环
            }
            visited.insert(role.to_string());

            if let Some(children) = reverse_adj.get(role) {
                for child in children {
                    if visited.contains(child) {
                        // 环 / 自环：先检查 visited 再决定是否插入，保证「后代集合不含 role 自身」契约
                        continue;
                    }
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

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub use service::RoleHierarchyService;

// 测试模块（always compiled：RoleHierarchyRecord 构造测试）

#[cfg(test)]
mod tests {
    use super::*;

    // RoleHierarchyRecord 构造测试

    /// `RoleHierarchyRecord` 三字段可构造且可读（字段名与 SQL schema 一致，避免 `role` 与 `RoleRow` 混淆）。
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

    // 编译期守卫：RoleHierarchyService 对全部 db 后端 feature 可见

    /// 编译期守卫：任一非 sqlite db feature（`db-postgres` / `db-mysql`）启用时 `RoleHierarchyService` 必须可解析。
    #[cfg(all(test, any(feature = "db-postgres", feature = "db-mysql")))]
    #[test]
    fn role_hierarchy_service_compiles_under_postgres_and_mysql() {
        let _: Option<RoleHierarchyService> = None;
    }
}

// db-sqlite 集成测试（_hierarchy 表迁移 + compute_closure）

#[cfg(all(test, feature = "db-sqlite"))]
mod db_sqlite_tests {
    use super::*;
    use crate::dao::{init_dbnexus, GarrisonDao, GarrisonDaoDbnexus, GarrisonMigration};
    use dbnexus::sea_orm::{ConnectionTrait, DbBackend, Statement, Value};
    use dbnexus::DbPool;
    use std::path::PathBuf;
    use std::sync::Arc;

    /// 项目根 `migrations/sqlite/` 目录。
    fn project_migrations_dir() -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir)
            .join("migrations")
            .join("sqlite")
    }

    /// 初始化 SQLite 内存库（迁移 + 返回 pool）：用唯一命名的共享缓存内存库而非裸 `sqlite::memory:`——
    /// 后者连接池可能分配互不相通的内存实例（迁移在连接 A、查询在连接 B 时报 "no such table"），
    /// 共享缓存保证池内所有连接看到同一实例，序号隔离不同用例。
    async fn setup_db() -> DbPool {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let db_id = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let pool = init_dbnexus(&format!(
            "sqlite://garrison_role_hierarchy_{db_id}?mode=memory&cache=shared"
        ))
        .await
        .expect("init_dbnexus 应成功");
        let migration = GarrisonMigration::with_base_dir(pool.clone(), project_migrations_dir());
        let applied = migration.migrate_core().await.expect("migrate_core 应成功");
        assert!(applied >= 1, "migrate_core 应至少执行 1 个文件");
        pool
    }

    /// 构造 MockDao 作为 KV 层（用于 oxcache 缓存测试）。
    fn mock_dao() -> Arc<dyn GarrisonDao> {
        Arc::new(crate::dao::tests::MockDao::new())
    }

    /// 构造 GarrisonDaoDbnexus（KV + SQL 统一 DAO）：MockDao 为 KV 层 + pool 为 SQL 层，SQL 方法经 dao 委托到 pool。
    async fn setup_dao(pool: DbPool) -> Arc<dyn GarrisonDao> {
        let kv = mock_dao();
        Arc::new(GarrisonDaoDbnexus::new(pool, kv))
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

    // role_hierarchy 表迁移验证

    /// 验证迁移加载 `002_role_hierarchy.sql` 后 `role_hierarchy` 表存在（SQL 文件按惯例放 `migrations/sqlite/core/`，复用 `migrate_core()`）。
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

    // _closure 传递闭包测试

    /// `compute_closure` 返回间接祖先。
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

        let svc = RoleHierarchyService::new(setup_dao(pool).await);
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
        let svc = RoleHierarchyService::new(setup_dao(pool).await);
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

        let svc = RoleHierarchyService::new(setup_dao(pool).await);

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

        let svc = RoleHierarchyService::new(setup_dao(pool).await);
        // 不应 stack overflow 或 hang
        let closure = svc
            .compute_closure(0)
            .await
            .expect("compute_closure 应成功");

        // A 的祖先应含 B（但不应含 A 自身，因 visited 防止环）
        let a_ancestors = closure.get("A").expect("closure 应包含 A");
        assert!(a_ancestors.contains("B"));
        let b_ancestors = closure.get("B").expect("closure 应包含 B");
        assert!(b_ancestors.contains("A"));
    }

    // _ancestors 缓存测试

    /// `get_ancestors` 首次调用触发 `compute_closure` 并写入 oxcache（key `tenant:0:role_closure`，TTL 1h；返回含间接祖先）。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_ancestors_returns_cached_closure() {
        let pool = setup_db().await;
        let dao = setup_dao(pool.clone()).await;

        // 先 insert_edge（pool 在 move 到 svc 之前完成借用）
        insert_edge(&pool, 0, "user", "admin").await;
        insert_edge(&pool, 0, "admin", "super_admin").await;

        let svc = RoleHierarchyService::new(dao.clone());

        let ancestors = svc
            .get_ancestors("user", 0)
            .await
            .expect("get_ancestors 应成功");
        assert!(ancestors.contains("admin"), "应含 admin（直接父角色）");
        assert!(
            ancestors.contains("super_admin"),
            "应含 super_admin（间接祖先）"
        );

        // 验证 oxcache 已缓存完整闭包
        let cached = dao
            .get("tenant:0:role_closure")
            .await
            .expect("dao.get 应成功");
        assert!(cached.is_some(), "oxcache 应已缓存 role_closure");
    }

    // _edge + invalidate_cache 测试

    /// `add_edge` 插入新边后删除该租户的闭包缓存。
    #[tokio::test(flavor = "multi_thread")]
    async fn add_edge_invalidates_cache() {
        let pool = setup_db().await;
        let dao = setup_dao(pool.clone()).await;

        insert_edge(&pool, 0, "user", "admin").await;
        let svc = RoleHierarchyService::new(dao.clone());
        let _ = svc
            .get_ancestors("user", 0)
            .await
            .expect("get_ancestors 应成功");

        let cached_before = dao
            .get("tenant:0:role_closure")
            .await
            .expect("dao.get 应成功");
        assert!(cached_before.is_some(), "前置条件：缓存应已写入");

        svc.add_edge("user", "super_admin", 0)
            .await
            .expect("add_edge 应成功");

        let cached_after = dao
            .get("tenant:0:role_closure")
            .await
            .expect("dao.get 应成功");
        assert!(cached_after.is_none(), "add_edge 后缓存应已失效");
    }

    /// `add_edge` 后再次 `get_ancestors` 重新计算并返回新边。
    #[tokio::test(flavor = "multi_thread")]
    async fn add_edge_reflects_in_subsequent_get_ancestors() {
        let pool = setup_db().await;
        let dao = setup_dao(pool.clone()).await;

        insert_edge(&pool, 0, "user", "admin").await;
        let svc = RoleHierarchyService::new(dao.clone());

        let ancestors1 = svc
            .get_ancestors("user", 0)
            .await
            .expect("get_ancestors 应成功");
        assert!(ancestors1.contains("admin"));
        assert!(!ancestors1.contains("super_admin"));

        svc.add_edge("user", "super_admin", 0)
            .await
            .expect("add_edge 应成功");

        let ancestors2 = svc
            .get_ancestors("user", 0)
            .await
            .expect("get_ancestors 应成功");
        assert!(ancestors2.contains("admin"));
        assert!(ancestors2.contains("super_admin"));
    }

    // 补充测试：get_ancestors 缓存命中 / 损坏降级 / 不存在角色

    /// `get_ancestors` 缓存命中时不查 SQL（删除表内数据后仍返回首次结果）。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_ancestors_cache_hit_does_not_query_db() {
        let pool = setup_db().await;
        let dao = setup_dao(pool.clone()).await;

        insert_edge(&pool, 0, "user", "admin").await;
        let svc = RoleHierarchyService::new(dao.clone());

        let ancestors1 = svc
            .get_ancestors("user", 0)
            .await
            .expect("get_ancestors 应成功");
        assert!(ancestors1.contains("admin"));

        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        conn.execute_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "DELETE FROM role_hierarchy",
            vec![],
        ))
        .await
        .expect("DELETE 应成功");

        // 再次调用：缓存命中，不查 SQL
        let ancestors2 = svc
            .get_ancestors("user", 0)
            .await
            .expect("缓存命中时 get_ancestors 应成功");
        assert!(
            ancestors2.contains("admin"),
            "缓存命中应返回与首次相同的结果"
        );
    }

    /// `get_ancestors` 遇损坏的闭包 JSON 时降级 `compute_closure` 并回写有效缓存。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_ancestors_corrupt_cache_falls_back_to_recompute() {
        let pool = setup_db().await;
        let dao = setup_dao(pool.clone()).await;

        insert_edge(&pool, 0, "user", "admin").await;
        let svc = RoleHierarchyService::new(dao.clone());

        dao.set("tenant:0:role_closure", "{invalid json", 3600)
            .await
            .expect("注入损坏缓存应成功");

        let ancestors = svc
            .get_ancestors("user", 0)
            .await
            .expect("降级重新计算应成功");
        assert!(ancestors.contains("admin"), "降级重新计算后应返回正确结果");

        let cached = dao
            .get("tenant:0:role_closure")
            .await
            .expect("dao.get 应成功");
        assert!(cached.is_some(), "缓存应已被重新写入");
        let closure: std::collections::HashMap<String, std::collections::HashSet<String>> =
            serde_json::from_str(&cached.unwrap()).expect("缓存应为有效 JSON");
        assert!(closure.contains_key("user"), "闭包应包含 user");
    }

    /// `get_ancestors` 对不在闭包中的角色返回空集合。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_ancestors_for_nonexistent_role_returns_empty() {
        let pool = setup_db().await;
        let dao = setup_dao(pool.clone()).await;

        insert_edge(&pool, 0, "user", "admin").await;
        let svc = RoleHierarchyService::new(dao.clone());

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
        let dao = setup_dao(pool.clone()).await;

        let svc = RoleHierarchyService::new(dao.clone());

        let result = svc.invalidate_cache(999).await;
        assert!(result.is_ok(), "invalidate_cache 不存在的缓存应幂等返回 Ok");

        let result2 = svc.invalidate_cache(999).await;
        assert!(result2.is_ok(), "多次调用 invalidate_cache 应幂等");
    }

    // 补充测试：get_descendants（完全未覆盖的方法）

    /// `get_descendants` 返回间接后代（user → admin → super_admin 层级）。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_descendants_returns_indirect_descendants() {
        let pool = setup_db().await;

        // user -> admin -> super_admin
        insert_edge(&pool, 0, "user", "admin").await;
        insert_edge(&pool, 0, "admin", "super_admin").await;

        let svc = RoleHierarchyService::new(setup_dao(pool).await);

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
        let svc = RoleHierarchyService::new(setup_dao(pool).await);

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

        let svc = RoleHierarchyService::new(setup_dao(pool).await);

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

        let svc = RoleHierarchyService::new(setup_dao(pool).await);

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
        let svc = RoleHierarchyService::new(setup_dao(pool).await);

        let descendants = svc
            .get_descendants("nonexistent_role", 0)
            .await
            .expect("get_descendants 应成功");
        assert!(descendants.is_empty(), "不存在的角色应返回空后代集合");
    }

    /// `get_descendants` 处理菱形继承（D→B→A、D→C→A：A 的后代含 B/C/D）。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_descendants_handles_diamond_inheritance() {
        let pool = setup_db().await;

        // D 继承 B, B 继承 A
        insert_edge(&pool, 0, "D", "B").await;
        insert_edge(&pool, 0, "B", "A").await;
        // D 继承 C, C 继承 A
        insert_edge(&pool, 0, "D", "C").await;
        insert_edge(&pool, 0, "C", "A").await;

        let svc = RoleHierarchyService::new(setup_dao(pool).await);

        let descendants = svc
            .get_descendants("A", 0)
            .await
            .expect("get_descendants 应成功");
        assert!(descendants.contains("B"), "A 的后代应含 B");
        assert!(descendants.contains("C"), "A 的后代应含 C");
        assert!(descendants.contains("D"), "A 的后代应含 D");

        let b_descendants = svc
            .get_descendants("B", 0)
            .await
            .expect("get_descendants 应成功");
        assert!(b_descendants.contains("D"), "B 的后代应含 D");
        assert!(!b_descendants.contains("A"), "B 的后代不应含 A");
    }

    // 补充测试：add_edge 幂等性

    /// `add_edge` 重复插入相同边是幂等的（INSERT OR IGNORE）。
    #[tokio::test(flavor = "multi_thread")]
    async fn add_edge_is_idempotent() {
        let pool = setup_db().await;
        let dao = setup_dao(pool.clone()).await;

        let svc = RoleHierarchyService::new(dao);

        svc.add_edge("user", "admin", 0)
            .await
            .expect("第一次 add_edge 应成功");

        let result = svc.add_edge("user", "admin", 0).await;
        assert!(result.is_ok(), "重复插入相同边应幂等返回 Ok");

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

    /// `add_edge` 拒绝自环边：child == parent 返回 InvalidParam 且不入库。
    #[tokio::test(flavor = "multi_thread")]
    async fn add_edge_rejects_self_loop() {
        let pool = setup_db().await;
        let dao = setup_dao(pool.clone()).await;

        let svc = RoleHierarchyService::new(dao);
        let result = svc.add_edge("A", "A", 0).await;
        assert!(
            matches!(
                result,
                Err(crate::error::GarrisonError::InvalidParam(ref msg))
                    if msg.contains("dao-role-hierarchy-self-loop")
            ),
            "自环边应返回含 'dao-role-hierarchy-self-loop' 的 InvalidParam 错误，实际: {:?}",
            result
        );

        // 自环边不应入库
        let session = pool.get_session("admin").await.unwrap();
        let conn = session.connection().unwrap();
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT COUNT(*) as cnt FROM role_hierarchy WHERE child_role = 'A' AND parent_role = 'A'",
            vec![],
        );
        let rows = conn.query_all_raw(stmt).await.expect("COUNT 查询应成功");
        let count: i64 = rows[0].try_get::<i64>("", "cnt").expect("读取 cnt 应成功");
        assert_eq!(count, 0, "自环边不应入库");
    }

    // 补充测试：compute_closure 菱形继承 / 自环 / 多分量 / 多层链

    /// `compute_closure` 处理菱形继承 D→B→A、D→C→A：D 的祖先含 B/C/A（覆盖 `dfs_ancestors` 回溯——不回溯会漏 C→A 路径）。
    #[tokio::test(flavor = "multi_thread")]
    async fn compute_closure_diamond_inheritance_collects_all_ancestors() {
        let pool = setup_db().await;

        // D 继承 B, B 继承 A
        insert_edge(&pool, 0, "D", "B").await;
        insert_edge(&pool, 0, "B", "A").await;
        // D 继承 C, C 继承 A
        insert_edge(&pool, 0, "D", "C").await;
        insert_edge(&pool, 0, "C", "A").await;

        let svc = RoleHierarchyService::new(setup_dao(pool).await);
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

        let b_ancestors = closure.get("B").expect("closure 应包含 B");
        assert!(b_ancestors.contains("A"), "B 的祖先应含 A");
        assert!(!b_ancestors.contains("C"), "B 的祖先不应含 C");
        assert!(!b_ancestors.contains("D"), "B 的祖先不应含 D");
    }

    /// `compute_closure` 处理自环（A→A）：不把 A 加入自身祖先集合，也不无限递归。
    #[tokio::test(flavor = "multi_thread")]
    async fn compute_closure_self_loop_does_not_infinite_recurse() {
        let pool = setup_db().await;

        // 自环：A -> A
        insert_edge(&pool, 0, "A", "A").await;

        let svc = RoleHierarchyService::new(setup_dao(pool).await);
        let closure = svc
            .compute_closure(0)
            .await
            .expect("compute_closure 应成功");

        // A 在邻接表中（有自环边），所以 closure 应包含 A 的条目
        let a_ancestors = closure
            .get("A")
            .expect("closure 应包含 A（自环边使 A 在 adj 中）");
        // 自环不会把 A 加入自身祖先集合（「不含 role 自身」契约）
        assert!(
            !a_ancestors.contains("A"),
            "自环 A->A 时 A 不应出现在自身祖先集合中"
        );
        assert!(a_ancestors.is_empty(), "自环 A 的祖先集合应为空");
    }

    /// `compute_closure` 处理多个不连通分量（A→B 与 C→D 互不干扰）。
    #[tokio::test(flavor = "multi_thread")]
    async fn compute_closure_multiple_disconnected_components() {
        let pool = setup_db().await;

        // 分量 1: A -> B
        insert_edge(&pool, 0, "A", "B").await;
        // 分量 2: C -> D
        insert_edge(&pool, 0, "C", "D").await;

        let svc = RoleHierarchyService::new(setup_dao(pool).await);
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

    /// `compute_closure` 多层链 L0→L1→L2→L3→L4：L0 祖先含 L1~L4，L4 祖先为空。
    #[tokio::test(flavor = "multi_thread")]
    async fn compute_closure_multi_level_chain_collects_all_ancestors() {
        let pool = setup_db().await;

        // 5 层链: L0 -> L1 -> L2 -> L3 -> L4
        insert_edge(&pool, 0, "L0", "L1").await;
        insert_edge(&pool, 0, "L1", "L2").await;
        insert_edge(&pool, 0, "L2", "L3").await;
        insert_edge(&pool, 0, "L3", "L4").await;

        let svc = RoleHierarchyService::new(setup_dao(pool).await);
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

    // 补充测试：get_ancestors 缓存复用（同一租户不同角色共享缓存）

    /// 同一租户不同角色共享缓存：首次 `get_ancestors("user")` 缓存整租户闭包，删表后 `get_ancestors("reader")` 仍从缓存返回 viewer。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_ancestors_second_role_hits_cached_closure() {
        let pool = setup_db().await;
        let dao = setup_dao(pool.clone()).await;

        insert_edge(&pool, 0, "user", "admin").await;
        insert_edge(&pool, 0, "reader", "viewer").await;

        let svc = RoleHierarchyService::new(dao.clone());

        // 首次调用 user：触发 compute_closure + 缓存写入
        let user_ancestors = svc
            .get_ancestors("user", 0)
            .await
            .expect("首次 get_ancestors(user) 应成功");
        assert!(user_ancestors.contains("admin"));

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

    // 补充测试：add_edge 跨租户缓存隔离

    /// `add_edge` 只失效目标租户缓存：tenant 1 加边后 tenant 0 缓存仍在。
    #[tokio::test(flavor = "multi_thread")]
    async fn add_edge_invalidates_only_same_tenant_cache() {
        let pool = setup_db().await;
        let dao = setup_dao(pool.clone()).await;

        insert_edge(&pool, 0, "user0", "admin0").await;
        insert_edge(&pool, 1, "user1", "admin1").await;

        let svc = RoleHierarchyService::new(dao.clone());

        // 两个租户各自触发缓存写入
        svc.get_ancestors("user0", 0)
            .await
            .expect("tenant 0 首次查询应成功");
        svc.get_ancestors("user1", 1)
            .await
            .expect("tenant 1 首次查询应成功");

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

    // 补充测试：get_descendants 自环 / 多父节点

    /// `get_descendants` 处理自环（A→A）：不把 A 加入自身后代集合，也不无限递归。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_descendants_self_loop_does_not_infinite_recurse() {
        let pool = setup_db().await;

        // 自环：A -> A（A 继承 A）
        insert_edge(&pool, 0, "A", "A").await;

        let svc = RoleHierarchyService::new(setup_dao(pool).await);
        // 不应 stack overflow 或 hang
        let descendants = svc
            .get_descendants("A", 0)
            .await
            .expect("get_descendants 应成功");

        // 自环不会把 A 加入自身后代集合（「不含 role 自身」契约）
        assert!(
            !descendants.contains("A"),
            "自环 A->A 时 A 不应出现在自身后代集合中"
        );
        assert!(descendants.is_empty(), "自环 A 的后代集合应为空");
    }

    /// `get_descendants` 多父节点：user 同时继承 admin 与 manager，二者的后代都应含 user。
    #[tokio::test(flavor = "multi_thread")]
    async fn get_descendants_multi_parent_child_appears_under_all_parents() {
        let pool = setup_db().await;

        // user 同时继承 admin 和 manager
        insert_edge(&pool, 0, "user", "admin").await;
        insert_edge(&pool, 0, "user", "manager").await;

        let svc = RoleHierarchyService::new(setup_dao(pool).await);

        let admin_desc = svc
            .get_descendants("admin", 0)
            .await
            .expect("get_descendants(admin) 应成功");
        assert!(
            admin_desc.contains("user"),
            "admin 的后代应含 user（user 继承 admin）"
        );

        let mgr_desc = svc
            .get_descendants("manager", 0)
            .await
            .expect("get_descendants(manager) 应成功");
        assert!(
            mgr_desc.contains("user"),
            "manager 的后代应含 user（user 继承 manager）"
        );

        let user_desc = svc
            .get_descendants("user", 0)
            .await
            .expect("get_descendants(user) 应成功");
        assert!(user_desc.is_empty(), "user 无后代");
    }

    /// `compute_closure` 多父节点：user 同时继承 admin 与 super_admin，祖先集合含两者。
    #[tokio::test(flavor = "multi_thread")]
    async fn compute_closure_multi_parent_collects_all_parents() {
        let pool = setup_db().await;

        // user 同时继承 admin 和 super_admin
        insert_edge(&pool, 0, "user", "admin").await;
        insert_edge(&pool, 0, "user", "super_admin").await;

        let svc = RoleHierarchyService::new(setup_dao(pool).await);
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
