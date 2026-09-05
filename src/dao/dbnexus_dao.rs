//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `GarrisonDaoDbnexus` — 统一 KV + SQL 的 `GarrisonDao` 实现。
//!
//! 包装 `DbPool`（SQL 操作）+ `Arc<dyn GarrisonDao>`（KV 委托），
//! 将 `role_hierarchy` / `social_bindings` 等 SQL 表操作统一在 `GarrisonDao` trait 下，
//! 消除业务层直接持有 `DbPool` 的需要。
//!
//! # 架构
//!
//! ```text
//! GarrisonDaoDbnexus
//! ├── kv: Arc<dyn GarrisonDao>  → 委托所有 KV 方法（get/set/incr/...）
//! └── pool: DbPool              → 实现 SQL 方法（role_hierarchy/social_bindings）
//! ```
//!
//! # Feature gate
//!
//! `#[cfg(any(db-sqlite, db-postgres, db-mysql))]`：仅在启用数据库后端时编译。

use super::GarrisonDao;
use crate::dao::repository::make_statement;
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, DbBackend, Value};
use std::sync::Arc;
use std::time::Duration;

/// 统一 KV + SQL 的 `GarrisonDao` 实现。
///
/// KV 方法委托内部 `kv` 实现（通常为 `GarrisonDaoOxcache`），
/// SQL 方法通过 `pool` 直接查询数据库。
pub struct GarrisonDaoDbnexus {
    /// KV 缓存委托（get/set/incr 等方法转发）。
    kv: Arc<dyn GarrisonDao>,
    /// 数据库连接池（role_hierarchy / social_bindings 等 SQL 表操作）。
    pool: DbPool,
}

impl GarrisonDaoDbnexus {
    /// 创建 `GarrisonDaoDbnexus` 实例。
    ///
    /// # 参数
    /// - `pool`: 数据库连接池。
    /// - `kv`: KV 缓存层委托（通常为 `GarrisonDaoOxcache`）。
    pub fn new(pool: DbPool, kv: Arc<dyn GarrisonDao>) -> Self {
        Self { kv, pool }
    }

    /// 获取内部数据库连接池引用（测试/诊断用）。
    pub fn pool(&self) -> &DbPool {
        &self.pool
    }

    /// 获取内部 KV 委托引用。
    pub fn kv(&self) -> &Arc<dyn GarrisonDao> {
        &self.kv
    }
}

// ============================================================================
// GarrisonDao trait 实现
// ============================================================================

#[async_trait]
impl GarrisonDao for GarrisonDaoDbnexus {
    // ------------------------------------------------------------------------
    // KV 方法：全部委托 self.kv
    // ------------------------------------------------------------------------

    async fn get(&self, key: &str) -> GarrisonResult<Option<String>> {
        self.kv.get(key).await
    }

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> GarrisonResult<()> {
        self.kv.set(key, value, ttl_seconds).await
    }

    async fn update(&self, key: &str, value: &str) -> GarrisonResult<()> {
        self.kv.update(key, value).await
    }

    async fn expire(&self, key: &str, seconds: u64) -> GarrisonResult<()> {
        self.kv.expire(key, seconds).await
    }

    async fn delete(&self, key: &str) -> GarrisonResult<()> {
        self.kv.delete(key).await
    }

    async fn set_permanent(&self, key: &str, value: &str) -> GarrisonResult<()> {
        self.kv.set_permanent(key, value).await
    }

    async fn set_if_absent(
        &self,
        key: &str,
        value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        self.kv.set_if_absent(key, value, ttl_seconds).await
    }

    async fn get_timeout(&self, key: &str) -> GarrisonResult<Option<Duration>> {
        self.kv.get_timeout(key).await
    }

    async fn get_with_ttl(&self, key: &str) -> GarrisonResult<Option<(String, Option<Duration>)>> {
        self.kv.get_with_ttl(key).await
    }

    #[cfg(feature = "dao-key-index")]
    async fn keys(&self, pattern: &str) -> GarrisonResult<Vec<String>> {
        self.kv.keys(pattern).await
    }

    async fn rename(&self, old_key: &str, new_key: &str) -> GarrisonResult<()> {
        self.kv.rename(old_key, new_key).await
    }

    async fn get_and_delete(&self, key: &str) -> GarrisonResult<Option<String>> {
        self.kv.get_and_delete(key).await
    }

    async fn incr(&self, key: &str, ttl_seconds: u64) -> GarrisonResult<u64> {
        self.kv.incr(key, ttl_seconds).await
    }

    async fn decr(&self, key: &str) -> GarrisonResult<u64> {
        self.kv.decr(key).await
    }

    async fn compare_and_update_if_greater(
        &self,
        key: &str,
        new_value: u64,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        self.kv
            .compare_and_update_if_greater(key, new_value, ttl_seconds)
            .await
    }

    async fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&str>,
        new_value: &str,
        ttl_seconds: u64,
    ) -> GarrisonResult<bool> {
        self.kv
            .compare_and_swap(key, expected, new_value, ttl_seconds)
            .await
    }

    async fn eval_lua(
        &self,
        script: &str,
        keys: Vec<String>,
        args: Vec<String>,
    ) -> GarrisonResult<Vec<String>> {
        self.kv.eval_lua(script, keys, args).await
    }

    // ------------------------------------------------------------------------
    // SQL 方法：通过 self.pool 实现
    // ------------------------------------------------------------------------

    /// 查询指定租户的所有角色层级边。
    ///
    /// 从 `role_hierarchy` 表查询 `tenant_id` 匹配的所有 `(child_role, parent_role)` 记录。
    async fn query_role_hierarchy_edges(
        &self,
        tenant_id: i64,
    ) -> GarrisonResult<Vec<(String, String)>> {
        let session = self
            .pool
            .get_session("admin")
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-role-hierarchy-session::{}", e)))?;
        let conn = session
            .connection()
            .map_err(|e| GarrisonError::Dao(format!("dao-role-hierarchy-connection::{}", e)))?;
        let stmt = make_statement(
            conn,
            "SELECT child_role, parent_role FROM role_hierarchy WHERE tenant_id = ?",
            vec![Value::BigInt(Some(tenant_id))],
        );
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-role-hierarchy-query::{}", e)))?;
        rows.into_iter()
            .map(|row| {
                let child_role = row
                    .try_get::<String>("", "child_role")
                    .map_err(|e| GarrisonError::Dao(format!("dao-child-role-read::{}", e)))?;
                let parent_role = row
                    .try_get::<String>("", "parent_role")
                    .map_err(|e| GarrisonError::Dao(format!("dao-parent-role-read::{}", e)))?;
                Ok((child_role, parent_role))
            })
            .collect()
    }

    /// 插入角色层级边（幂等，后端自适应）。
    ///
    /// SQLite: `INSERT OR IGNORE`，PostgreSQL: `ON CONFLICT DO NOTHING`，MySQL: `INSERT IGNORE`。
    async fn insert_role_hierarchy_edge(
        &self,
        tenant_id: i64,
        child_role: &str,
        parent_role: &str,
    ) -> GarrisonResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            GarrisonError::Dao(format!("dao-role-hierarchy-add-edge-session::{}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            GarrisonError::Dao(format!("dao-role-hierarchy-add-edge-connection::{}", e))
        })?;
        let backend = conn.get_database_backend();
        let insert_sql = match backend {
            DbBackend::Postgres => {
                "INSERT INTO role_hierarchy (tenant_id, child_role, parent_role) \
                 VALUES (?, ?, ?) \
                 ON CONFLICT (tenant_id, child_role, parent_role) DO NOTHING"
            },
            DbBackend::MySql => {
                "INSERT IGNORE INTO role_hierarchy (tenant_id, child_role, parent_role) \
                 VALUES (?, ?, ?)"
            },
            _ => {
                "INSERT OR IGNORE INTO role_hierarchy (tenant_id, child_role, parent_role) \
                 VALUES (?, ?, ?)"
            },
        };
        let stmt = make_statement(
            conn,
            insert_sql,
            vec![
                Value::BigInt(Some(tenant_id)),
                Value::String(Some(child_role.to_string())),
                Value::String(Some(parent_role.to_string())),
            ],
        );
        conn.execute_raw(stmt).await.map_err(|e| {
            GarrisonError::Dao(format!("dao-role-hierarchy-add-edge-insert::{}", e))
        })?;
        Ok(())
    }

    /// 删除角色层级边（幂等）。
    async fn delete_role_hierarchy_edge(
        &self,
        tenant_id: i64,
        child_role: &str,
        parent_role: &str,
    ) -> GarrisonResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            GarrisonError::Dao(format!("dao-role-hierarchy-delete-edge-session::{}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            GarrisonError::Dao(format!("dao-role-hierarchy-delete-edge-connection::{}", e))
        })?;
        let stmt = make_statement(
            conn,
            "DELETE FROM role_hierarchy WHERE tenant_id = ? AND child_role = ? AND parent_role = ?",
            vec![
                Value::BigInt(Some(tenant_id)),
                Value::String(Some(child_role.to_string())),
                Value::String(Some(parent_role.to_string())),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-role-hierarchy-delete-edge::{}", e)))?;
        Ok(())
    }

    /// 查询社交账号绑定关系。
    ///
    /// 按 `(tenant_id, provider, provider_user_id)` 查询 `social_bindings` 表，
    /// 返回关联的 `login_id`（String，UUID）。
    async fn find_social_binding(
        &self,
        tenant_id: i64,
        provider: &str,
        provider_user_id: &str,
    ) -> GarrisonResult<Option<String>> {
        let session = self
            .pool
            .get_session("admin")
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-social-binding-session::{}", e)))?;
        let conn = session
            .connection()
            .map_err(|e| GarrisonError::Dao(format!("dao-social-binding-conn::{}", e)))?;
        let stmt = make_statement(
            conn,
            "SELECT login_id FROM social_bindings \
             WHERE tenant_id = ? AND provider = ? AND provider_user_id = ?",
            vec![
                Value::BigInt(Some(tenant_id)),
                Value::String(Some(provider.to_string())),
                Value::String(Some(provider_user_id.to_string())),
            ],
        );
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-social-binding-query::{}", e)))?;
        match rows.into_iter().next() {
            Some(row) => {
                let login_id = row.try_get::<String>("", "login_id").map_err(|e| {
                    GarrisonError::Dao(format!("dao-social-binding-login-id-read::{}", e))
                })?;
                Ok(Some(login_id))
            },
            None => Ok(None),
        }
    }

    /// 插入社交账号绑定关系。
    ///
    /// 将 `(tenant_id, login_id, provider, provider_user_id, union_id, created_at)`
    /// 写入 `social_bindings` 表。
    async fn insert_social_binding(
        &self,
        tenant_id: i64,
        login_id: &str,
        provider: &str,
        provider_user_id: &str,
        union_id: Option<&str>,
        created_at: i64,
    ) -> GarrisonResult<()> {
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                GarrisonError::Dao(format!("dao-social-binding-insert-session::{}", e))
            })?;
        let conn = session
            .connection()
            .map_err(|e| GarrisonError::Dao(format!("dao-social-binding-insert-conn::{}", e)))?;
        let stmt = make_statement(
            conn,
            "INSERT INTO social_bindings \
             (tenant_id, login_id, provider, provider_user_id, union_id, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
            vec![
                Value::BigInt(Some(tenant_id)),
                Value::String(Some(login_id.to_string())),
                Value::String(Some(provider.to_string())),
                Value::String(Some(provider_user_id.to_string())),
                match union_id {
                    Some(s) => Value::String(Some(s.to_string())),
                    None => Value::String(None),
                },
                Value::BigInt(Some(created_at)),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-social-binding-insert::{}", e)))?;
        Ok(())
    }
}

// ============================================================================
// 单元测试（GarrisonDaoDbnexus 生产后端实现层）
// ============================================================================
//
// 覆盖两条主线：
// 1. KV 方法委托正确性（以 `InMemoryDao` 为委托，断言转发与错误透传）；
// 2. role_hierarchy / social_bindings 的 SQL 读写（sqlite 内存池 + 项目
//    migrations/sqlite/core 迁移建表，与 tests/common/mod.rs `setup_db` 语义一致）。

#[cfg(all(test, feature = "db-sqlite"))]
mod tests {
    use super::*;
    use crate::dao::{init_dbnexus, GarrisonMigration, InMemoryDao};
    use sea_orm::Statement;
    use std::path::PathBuf;

    /// 创建已执行 core 迁移的 sqlite 内存 DAO，KV 委托为 `InMemoryDao`。
    ///
    /// 返回 `(dbnexus DAO, kv Arc)` 供委托断言（`Arc::ptr_eq` 等）。
    /// 迁移目录用 `CARGO_MANIFEST_DIR` 定位项目根 `migrations/sqlite`，
    /// 与 `tests/common/mod.rs::setup_db` 装配语义一致。
    async fn setup_dao() -> (GarrisonDaoDbnexus, Arc<InMemoryDao>) {
        let pool = init_dbnexus("sqlite::memory:")
            .await
            .expect("init_dbnexus 应成功");
        let migrations_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("migrations")
            .join("sqlite");
        let migration = GarrisonMigration::with_base_dir(pool.clone(), migrations_dir);
        migration.migrate_core().await.expect("migrate_core 应成功");
        let kv = Arc::new(InMemoryDao::new());
        (GarrisonDaoDbnexus::new(pool, kv.clone()), kv)
    }

    // ------------------------------------------------------------------------
    // 访问器：pool() / kv()
    // ------------------------------------------------------------------------

    /// `kv()` 返回注入的同一委托实例（Arc 指针相等）。
    #[tokio::test]
    async fn kv_accessor_returns_injected_delegate() {
        let (dao, kv) = setup_dao().await;
        let kv_dyn: Arc<dyn GarrisonDao> = kv.clone();
        assert!(
            Arc::ptr_eq(dao.kv(), &kv_dyn),
            "kv() 应返回注入的同一 Arc 实例"
        );
    }

    /// `pool()` 返回可用连接池：执行 `SELECT 1` 验证连通性。
    #[tokio::test]
    async fn pool_accessor_returns_usable_pool() {
        let (dao, _kv) = setup_dao().await;
        let session = dao
            .pool()
            .get_session("admin")
            .await
            .expect("get_session 应成功");
        let conn = session.connection().expect("connection 应可用");
        let stmt = Statement::from_sql_and_values(DbBackend::Sqlite, "SELECT 1 AS val", vec![]);
        let row = conn
            .query_one_raw(stmt)
            .await
            .expect("SELECT 1 应成功")
            .expect("应返回一行");
        let val: i64 = row.try_get("", "val").expect("val 列应存在");
        assert_eq!(val, 1);
    }

    // ------------------------------------------------------------------------
    // KV 方法委托
    // ------------------------------------------------------------------------

    /// set / get / update / delete 委托转发；update 缺失 key 错误透传。
    #[tokio::test]
    async fn kv_set_get_update_delete_delegate() {
        let (dao, kv) = setup_dao().await;
        dao.set("dn_k", "v1", 60).await.unwrap();
        assert_eq!(dao.get("dn_k").await.unwrap().as_deref(), Some("v1"));
        // 值写入的是注入的 kv（转发到同一实例）
        assert_eq!(kv.get("dn_k").await.unwrap().as_deref(), Some("v1"));

        dao.update("dn_k", "v2").await.unwrap();
        assert_eq!(dao.get("dn_k").await.unwrap().as_deref(), Some("v2"));

        let r = dao.update("dn_missing", "v").await;
        assert!(
            matches!(r, Err(GarrisonError::Dao(_))),
            "update 缺失 key 错误应透传"
        );

        dao.delete("dn_k").await.unwrap();
        assert!(dao.get("dn_k").await.unwrap().is_none());
    }

    /// expire 委托转发：重置 TTL 生效、缺失 key 错误透传。
    #[tokio::test]
    async fn kv_expire_delegates() {
        let (dao, _kv) = setup_dao().await;
        dao.set("dn_e", "v", 1).await.unwrap();
        dao.expire("dn_e", 3600).await.unwrap();
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert_eq!(
            dao.get("dn_e").await.unwrap().as_deref(),
            Some("v"),
            "expire(3600) 重置 TTL 后原 1s 窗口不应过期"
        );
        let r = dao.expire("dn_missing", 3600).await;
        assert!(
            matches!(r, Err(GarrisonError::Dao(_))),
            "expire 缺失 key 错误应透传"
        );
    }

    /// set_permanent / set_if_absent 委托转发（SETNX 两次调用 true→false）。
    #[tokio::test]
    async fn kv_set_permanent_and_set_if_absent_delegate() {
        let (dao, _kv) = setup_dao().await;
        dao.set_permanent("dn_p", "pv").await.unwrap();
        assert_eq!(dao.get("dn_p").await.unwrap().as_deref(), Some("pv"));
        assert!(
            dao.get_timeout("dn_p").await.unwrap().is_none(),
            "set_permanent 委托后应为永久键"
        );

        assert!(
            dao.set_if_absent("dn_sia", "a", 60).await.unwrap(),
            "首次 SETNX 应成功"
        );
        assert!(
            !dao.set_if_absent("dn_sia", "b", 60).await.unwrap(),
            "已存在应返回 false"
        );
        assert_eq!(
            dao.get("dn_sia").await.unwrap().as_deref(),
            Some("a"),
            "值不应被覆盖"
        );
    }

    /// get_timeout / get_with_ttl 委托转发（含缺失 key 返回 None）。
    #[tokio::test]
    async fn kv_get_timeout_and_get_with_ttl_delegate() {
        let (dao, _kv) = setup_dao().await;
        dao.set("dn_t", "v", 60).await.unwrap();
        let timeout = dao.get_timeout("dn_t").await.unwrap();
        assert!(timeout.is_some(), "TTL 键 get_timeout 应返回 Some");
        assert!(timeout.unwrap() <= Duration::from_secs(60));

        let (value, ttl) = dao
            .get_with_ttl("dn_t")
            .await
            .unwrap()
            .expect("get_with_ttl 应返回 Some");
        assert_eq!(value, "v");
        assert!(ttl.is_some());

        assert!(dao.get_with_ttl("dn_missing").await.unwrap().is_none());
    }

    /// rename / get_and_delete 委托转发（含 rename 缺失 key 错误透传）。
    #[tokio::test]
    async fn kv_rename_and_get_and_delete_delegate() {
        let (dao, _kv) = setup_dao().await;
        dao.set("dn_r", "v", 60).await.unwrap();
        dao.rename("dn_r", "dn_r2").await.unwrap();
        assert!(
            dao.get("dn_r").await.unwrap().is_none(),
            "rename 后 old key 应不存在"
        );
        assert_eq!(dao.get("dn_r2").await.unwrap().as_deref(), Some("v"));

        let r = dao.rename("dn_missing", "dn_any").await;
        assert!(r.is_err(), "rename 缺失 key 错误应透传");

        let got = dao.get_and_delete("dn_r2").await.unwrap();
        assert_eq!(got.as_deref(), Some("v"));
        assert!(
            dao.get("dn_r2").await.unwrap().is_none(),
            "get_and_delete 后 key 应删除"
        );
        assert!(dao.get_and_delete("dn_missing").await.unwrap().is_none());
    }

    /// incr / decr 委托转发（计数、归零删除、缺失 key 返回 0）。
    #[tokio::test]
    async fn kv_incr_decr_delegate() {
        let (dao, _kv) = setup_dao().await;
        assert_eq!(
            dao.incr("dn_c", 60).await.unwrap(),
            1,
            "新键 incr 应初始化为 1"
        );
        assert_eq!(dao.incr("dn_c", 60).await.unwrap(), 2);
        assert_eq!(dao.decr("dn_c").await.unwrap(), 1);
        assert_eq!(dao.decr("dn_c").await.unwrap(), 0);
        assert!(
            dao.get("dn_c").await.unwrap().is_none(),
            "decr 到 0 后 key 应被删除（转发保留该语义）"
        );
        assert_eq!(dao.decr("dn_c").await.unwrap(), 0, "缺失 key decr 应返回 0");
    }

    /// compare_and_swap / compare_and_update_if_greater 委托转发。
    #[tokio::test]
    async fn kv_atomic_compare_methods_delegate() {
        let (dao, _kv) = setup_dao().await;
        dao.set("dn_cas", "old", 60).await.unwrap();

        let ok = dao
            .compare_and_swap("dn_cas", Some("mismatch"), "new", 60)
            .await
            .unwrap();
        assert!(!ok, "期望值不匹配时 CAS 应返回 false");
        // 新值写数字，便于后续 compare_and_update_if_greater 解析
        let ok = dao
            .compare_and_swap("dn_cas", Some("old"), "5", 60)
            .await
            .unwrap();
        assert!(ok, "期望值匹配时 CAS 应返回 true");
        assert_eq!(dao.get("dn_cas").await.unwrap().as_deref(), Some("5"));

        let ok = dao
            .compare_and_update_if_greater("dn_cas", 10, 60)
            .await
            .unwrap();
        assert!(ok, "10 > 5 应更新");
        let ok = dao
            .compare_and_update_if_greater("dn_cas", 5, 60)
            .await
            .unwrap();
        assert!(!ok, "5 <= 10 不应更新");
        assert_eq!(dao.get("dn_cas").await.unwrap().as_deref(), Some("10"));
    }

    /// eval_lua 委托转发：不支持的脚本错误从 kv 透传（含原错误标识）。
    #[tokio::test]
    async fn kv_eval_lua_delegates() {
        let (dao, _kv) = setup_dao().await;
        let r = dao
            .eval_lua("unsupported-script", vec!["k".to_string()], vec![])
            .await;
        assert!(
            matches!(r, Err(GarrisonError::NotImplemented(ref msg)) if msg.contains("dao-eval-lua-unsupported-script")),
            "eval_lua 应透传 kv 的 NotImplemented 错误，实际: {:?}",
            r
        );
    }

    /// keys() 委托转发（dao-key-index 启用时编译）。
    #[cfg(feature = "dao-key-index")]
    #[tokio::test]
    async fn kv_keys_delegate() {
        let (dao, _kv) = setup_dao().await;
        dao.set("dn_a1", "v", 60).await.unwrap();
        dao.set("dn_a2", "v", 60).await.unwrap();
        dao.set("zz", "v", 60).await.unwrap();
        let mut keys = dao.keys("dn_a*").await.unwrap();
        keys.sort();
        assert_eq!(
            keys,
            vec!["dn_a1".to_string(), "dn_a2".to_string()],
            "keys() 应委托 kv 并按 pattern 过滤"
        );
    }

    // ------------------------------------------------------------------------
    // SQL 方法：role_hierarchy
    // ------------------------------------------------------------------------

    /// role_hierarchy 写读 roundtrip：多租户隔离 + 空结果路径。
    #[tokio::test]
    async fn role_hierarchy_insert_and_query_roundtrip() {
        let (dao, _kv) = setup_dao().await;
        // 空结果路径：迁移后空表查询返回空 Vec
        assert!(dao.query_role_hierarchy_edges(1).await.unwrap().is_empty());

        dao.insert_role_hierarchy_edge(1, "admin", "owner")
            .await
            .unwrap();
        dao.insert_role_hierarchy_edge(1, "manager", "admin")
            .await
            .unwrap();
        dao.insert_role_hierarchy_edge(2, "admin", "owner")
            .await
            .unwrap();

        let mut edges = dao.query_role_hierarchy_edges(1).await.unwrap();
        edges.sort();
        assert_eq!(
            edges,
            vec![
                ("admin".to_string(), "owner".to_string()),
                ("manager".to_string(), "admin".to_string()),
            ],
            "tenant 1 应查到 2 条层级边"
        );
        assert_eq!(
            dao.query_role_hierarchy_edges(2).await.unwrap().len(),
            1,
            "tenant 2 应只查到自己的 1 条（租户隔离）"
        );
        assert!(
            dao.query_role_hierarchy_edges(99).await.unwrap().is_empty(),
            "无数据租户应返回空 Vec"
        );
    }

    /// role_hierarchy 插入幂等：重复插入同一边不报错且不产生重复行。
    #[tokio::test]
    async fn role_hierarchy_insert_is_idempotent() {
        let (dao, _kv) = setup_dao().await;
        dao.insert_role_hierarchy_edge(0, "admin", "owner")
            .await
            .unwrap();
        dao.insert_role_hierarchy_edge(0, "admin", "owner")
            .await
            .unwrap();
        let edges = dao.query_role_hierarchy_edges(0).await.unwrap();
        assert_eq!(edges.len(), 1, "重复插入应被 INSERT OR IGNORE 去重");
    }

    /// role_hierarchy 删除：删除既有边生效；重复删除（不存在的边）幂等不报错。
    #[tokio::test]
    async fn role_hierarchy_delete_edge_is_idempotent() {
        let (dao, _kv) = setup_dao().await;
        dao.insert_role_hierarchy_edge(1, "admin", "owner")
            .await
            .unwrap();
        dao.insert_role_hierarchy_edge(1, "manager", "admin")
            .await
            .unwrap();

        dao.delete_role_hierarchy_edge(1, "admin", "owner")
            .await
            .unwrap();
        let edges = dao.query_role_hierarchy_edges(1).await.unwrap();
        assert_eq!(edges, vec![("manager".to_string(), "admin".to_string())]);

        // 幂等：删除不存在的边不报错
        dao.delete_role_hierarchy_edge(1, "admin", "owner")
            .await
            .unwrap();
        dao.delete_role_hierarchy_edge(42, "admin", "owner")
            .await
            .unwrap();
        assert_eq!(dao.query_role_hierarchy_edges(1).await.unwrap().len(), 1);
    }

    // ------------------------------------------------------------------------
    // SQL 方法：social_bindings
    // ------------------------------------------------------------------------

    /// social_bindings 写读 roundtrip：三元组精确匹配（租户 / 平台 / 平台用户）。
    #[tokio::test]
    async fn social_binding_insert_and_find_roundtrip() {
        let (dao, _kv) = setup_dao().await;
        // 空结果路径：首次登录（无绑定）返回 None
        let none = dao
            .find_social_binding(0, "wechat", "openid-1")
            .await
            .unwrap();
        assert!(none.is_none(), "无绑定时应返回 None");

        dao.insert_social_binding(
            0,
            "login-1",
            "wechat",
            "openid-1",
            Some("union-1"),
            1700000000,
        )
        .await
        .unwrap();

        let found = dao
            .find_social_binding(0, "wechat", "openid-1")
            .await
            .unwrap();
        assert_eq!(found.as_deref(), Some("login-1"));

        // 不存在的 provider_user_id / 错误平台 / 错误租户 → None（三元组精确匹配）
        assert!(dao
            .find_social_binding(0, "wechat", "openid-other")
            .await
            .unwrap()
            .is_none());
        assert!(dao
            .find_social_binding(0, "alipay", "openid-1")
            .await
            .unwrap()
            .is_none());
        assert!(dao
            .find_social_binding(1, "wechat", "openid-1")
            .await
            .unwrap()
            .is_none());
    }

    /// social_bindings：union_id 为 NULL 可正常插入查询；重复绑定触发 UNIQUE 约束报 Dao 错误。
    #[tokio::test]
    async fn social_binding_null_union_id_and_duplicate_insert_errors() {
        let (dao, _kv) = setup_dao().await;
        dao.insert_social_binding(0, "login-1", "wechat", "openid-1", None, 1700000000)
            .await
            .unwrap();
        let found = dao
            .find_social_binding(0, "wechat", "openid-1")
            .await
            .unwrap();
        assert_eq!(
            found.as_deref(),
            Some("login-1"),
            "union_id 为 NULL 不影响绑定查询"
        );

        // UNIQUE(tenant_id, provider, provider_user_id)：重复绑定应返回 Dao 错误而非 panic
        let r = dao
            .insert_social_binding(0, "login-2", "wechat", "openid-1", None, 1700000001)
            .await;
        assert!(
            matches!(r, Err(GarrisonError::Dao(ref msg)) if msg.contains("dao-social-binding-insert::")),
            "重复绑定应返回含 'dao-social-binding-insert::' 的 Dao 错误，实际: {:?}",
            r
        );
        // 原绑定不被破坏
        assert_eq!(
            dao.find_social_binding(0, "wechat", "openid-1")
                .await
                .unwrap()
                .as_deref(),
            Some("login-1")
        );
    }
}
