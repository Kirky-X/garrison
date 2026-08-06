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
