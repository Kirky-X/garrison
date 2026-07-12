//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusAuthMethodRepository 实现（app_auth_method 表）。

use super::{v_i64, v_opt_str, v_str, DbnexusAuthMethodRepository};
use crate::dao::repository::{make_statement, AuthMethodRepository, AuthMethodRow, NewAuthMethod};
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, QueryResult};

impl DbnexusAuthMethodRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuthMethodRepository for DbnexusAuthMethodRepository {
    async fn find_by_id(&self, tenant_id: i64, id: &str) -> BulwarkResult<Option<AuthMethodRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_auth_method find_by_id 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_auth_method find_by_id 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT id, user_id, method_type, external_id, metadata, create_time, tenant_id \
                   FROM app_auth_method WHERE tenant_id = ? AND id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(id)]);
        let row = conn.query_one_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("app_auth_method find_by_id 查询失败: {}", e))
        })?;
        row.map(|r| parse_auth_method_row(&r)).transpose()
    }

    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
    ) -> BulwarkResult<Vec<AuthMethodRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_auth_method find_by_user_id 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_auth_method find_by_user_id 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT id, user_id, method_type, external_id, metadata, create_time, tenant_id \
                   FROM app_auth_method WHERE tenant_id = ? AND user_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(user_id)]);
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("app_auth_method find_by_user_id 查询失败: {}", e))
        })?;
        rows.iter().map(parse_auth_method_row).collect()
    }

    async fn create(&self, tenant_id: i64, method: NewAuthMethod) -> BulwarkResult<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_auth_method create 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_auth_method create 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "INSERT INTO app_auth_method (id, user_id, method_type, external_id, metadata, tenant_id) \
                   VALUES (?, ?, ?, ?, ?, ?)";
        let stmt = make_statement(
            conn,
            sql,
            vec![
                v_str(&id),
                v_str(&method.user_id),
                v_str(&method.method_type),
                v_opt_str(&method.external_id),
                v_opt_str(&method.metadata),
                v_i64(tenant_id),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_auth_method create 插入失败: {}", e)))?;
        Ok(id)
    }

    async fn delete(&self, tenant_id: i64, id: &str) -> BulwarkResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_auth_method delete 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_auth_method delete 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "DELETE FROM app_auth_method WHERE tenant_id = ? AND id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(id)]);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_auth_method delete 删除失败: {}", e)))?;
        Ok(())
    }

    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> BulwarkResult<Vec<AuthMethodRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_auth_method list 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_auth_method list 获取 connection 失败: {}", e))
        })?;
        let sql = "SELECT id, user_id, method_type, external_id, metadata, create_time, tenant_id \
                   FROM app_auth_method WHERE tenant_id = ? LIMIT ? OFFSET ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_i64(limit), v_i64(offset)],
        );
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_auth_method list 查询失败: {}", e)))?;
        rows.iter().map(parse_auth_method_row).collect()
    }
}

/// 解析 app_auth_method 行。
fn parse_auth_method_row(row: &QueryResult) -> BulwarkResult<AuthMethodRow> {
    Ok(AuthMethodRow {
        id: row
            .try_get("", "id")
            .map_err(|e| BulwarkError::Dao(format!("app_auth_method 行解析失败 (id): {}", e)))?,
        user_id: row.try_get("", "user_id").map_err(|e| {
            BulwarkError::Dao(format!("app_auth_method 行解析失败 (user_id): {}", e))
        })?,
        method_type: row.try_get("", "method_type").map_err(|e| {
            BulwarkError::Dao(format!("app_auth_method 行解析失败 (method_type): {}", e))
        })?,
        external_id: row.try_get("", "external_id").map_err(|e| {
            BulwarkError::Dao(format!("app_auth_method 行解析失败 (external_id): {}", e))
        })?,
        metadata: row.try_get("", "metadata").map_err(|e| {
            BulwarkError::Dao(format!("app_auth_method 行解析失败 (metadata): {}", e))
        })?,
        create_time: row.try_get("", "create_time").map_err(|e| {
            BulwarkError::Dao(format!("app_auth_method 行解析失败 (create_time): {}", e))
        })?,
        tenant_id: row.try_get("", "tenant_id").map_err(|e| {
            BulwarkError::Dao(format!("app_auth_method 行解析失败 (tenant_id): {}", e))
        })?,
    })
}
