//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusUserExtRepository 实现（app_user_ext 表）。

use super::{v_i64, v_opt_str, v_str, DbnexusUserExtRepository};
use crate::dao::repository::{make_statement, UserExtRepository, UserExtRow};
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, QueryResult};

impl DbnexusUserExtRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserExtRepository for DbnexusUserExtRepository {
    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
    ) -> BulwarkResult<Vec<UserExtRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_ext find_by_user_id 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_ext find_by_user_id 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT id, user_id, field_key, field_value, field_type, created_at, updated_at, tenant_id \
                   FROM app_user_ext WHERE tenant_id = ? AND user_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(user_id)]);
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_ext find_by_user_id 查询失败: {}", e))
        })?;
        rows.iter().map(parse_user_ext_row).collect()
    }

    async fn find_by_user_and_key(
        &self,
        tenant_id: i64,
        user_id: &str,
        field_key: &str,
    ) -> BulwarkResult<Option<UserExtRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_ext find_by_user_and_key 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_ext find_by_user_and_key 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT id, user_id, field_key, field_value, field_type, created_at, updated_at, tenant_id \
                   FROM app_user_ext WHERE tenant_id = ? AND user_id = ? AND field_key = ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_str(user_id), v_str(field_key)],
        );
        let row = conn.query_one_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_ext find_by_user_and_key 查询失败: {}", e))
        })?;
        row.map(|r| parse_user_ext_row(&r)).transpose()
    }

    async fn upsert(
        &self,
        tenant_id: i64,
        user_id: &str,
        field_key: &str,
        field_value: Option<String>,
        field_type: &str,
    ) -> BulwarkResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_ext upsert 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_user_ext upsert 获取 connection 失败: {}", e))
        })?;
        // UPSERT，依赖 UK(user_id, field_key)。
        // 插入时生成新 UUID；冲突时更新 field_value/field_type/updated_at（保留原 id/created_at）。
        // SQLite/Postgres 使用 ON CONFLICT ... DO UPDATE SET ... = excluded.field；
        // MySQL 使用 ON DUPLICATE KEY UPDATE ... = VALUES(field)（MySQL 不支持 ON CONFLICT 语法）。
        let new_id = uuid::Uuid::new_v4().to_string();
        let sql = if conn.get_database_backend() == sea_orm::DbBackend::MySql {
            "INSERT INTO app_user_ext (id, user_id, field_key, field_value, field_type, tenant_id) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE \
             field_value = VALUES(field_value), \
             field_type = VALUES(field_type), \
             updated_at = CURRENT_TIMESTAMP"
        } else {
            "INSERT INTO app_user_ext (id, user_id, field_key, field_value, field_type, tenant_id) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT(user_id, field_key) DO UPDATE SET \
             field_value = excluded.field_value, \
             field_type = excluded.field_type, \
             updated_at = CURRENT_TIMESTAMP"
        };
        let stmt = make_statement(
            conn,
            sql,
            vec![
                v_str(&new_id),
                v_str(user_id),
                v_str(field_key),
                v_opt_str(&field_value),
                v_str(field_type),
                v_i64(tenant_id),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_ext upsert 失败: {}", e)))?;
        Ok(())
    }

    async fn delete(&self, tenant_id: i64, user_id: &str, field_key: &str) -> BulwarkResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_ext delete 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_user_ext delete 获取 connection 失败: {}", e))
        })?;
        let sql = "DELETE FROM app_user_ext \
                   WHERE tenant_id = ? AND user_id = ? AND field_key = ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_str(user_id), v_str(field_key)],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_ext delete 删除失败: {}", e)))?;
        Ok(())
    }

    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> BulwarkResult<Vec<UserExtRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_ext list 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_user_ext list 获取 connection 失败: {}", e))
        })?;
        let sql = "SELECT id, user_id, field_key, field_value, field_type, created_at, updated_at, tenant_id \
                   FROM app_user_ext WHERE tenant_id = ? LIMIT ? OFFSET ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_i64(limit), v_i64(offset)],
        );
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_ext list 查询失败: {}", e)))?;
        rows.iter().map(parse_user_ext_row).collect()
    }
}

/// 解析 app_user_ext 行。
fn parse_user_ext_row(row: &QueryResult) -> BulwarkResult<UserExtRow> {
    Ok(UserExtRow {
        id: row
            .try_get("", "id")
            .map_err(|e| BulwarkError::Dao(format!("app_user_ext 行解析失败 (id): {}", e)))?,
        user_id: row
            .try_get("", "user_id")
            .map_err(|e| BulwarkError::Dao(format!("app_user_ext 行解析失败 (user_id): {}", e)))?,
        field_key: row.try_get("", "field_key").map_err(|e| {
            BulwarkError::Dao(format!("app_user_ext 行解析失败 (field_key): {}", e))
        })?,
        field_value: row.try_get("", "field_value").map_err(|e| {
            BulwarkError::Dao(format!("app_user_ext 行解析失败 (field_value): {}", e))
        })?,
        field_type: row.try_get("", "field_type").map_err(|e| {
            BulwarkError::Dao(format!("app_user_ext 行解析失败 (field_type): {}", e))
        })?,
        created_at: row.try_get("", "created_at").map_err(|e| {
            BulwarkError::Dao(format!("app_user_ext 行解析失败 (created_at): {}", e))
        })?,
        updated_at: row.try_get("", "updated_at").map_err(|e| {
            BulwarkError::Dao(format!("app_user_ext 行解析失败 (updated_at): {}", e))
        })?,
        tenant_id: row.try_get("", "tenant_id").map_err(|e| {
            BulwarkError::Dao(format!("app_user_ext 行解析失败 (tenant_id): {}", e))
        })?,
    })
}
