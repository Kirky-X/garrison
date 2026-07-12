//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusUserRoleRepository 实现（app_user_role 表）。

use super::{v_i64, v_opt_str, v_str, DbnexusUserRoleRepository};
use crate::dao::repository::{make_statement, UserRoleRepository, UserRoleRow};
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, QueryResult};

impl DbnexusUserRoleRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRoleRepository for DbnexusUserRoleRepository {
    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
    ) -> BulwarkResult<Vec<UserRoleRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_role find_by_user_id 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_role find_by_user_id 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT user_id, role_id, scope, grant_time, tenant_id \
                   FROM app_user_role WHERE tenant_id = ? AND user_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(user_id)]);
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_role find_by_user_id 查询失败: {}", e))
        })?;
        rows.iter().map(parse_user_role_row).collect()
    }

    async fn find_by_role_id(
        &self,
        tenant_id: i64,
        role_id: &str,
    ) -> BulwarkResult<Vec<UserRoleRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_role find_by_role_id 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_role find_by_role_id 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT user_id, role_id, scope, grant_time, tenant_id \
                   FROM app_user_role WHERE tenant_id = ? AND role_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(role_id)]);
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_role find_by_role_id 查询失败: {}", e))
        })?;
        rows.iter().map(parse_user_role_row).collect()
    }

    async fn assign(
        &self,
        tenant_id: i64,
        user_id: &str,
        role_id: &str,
        scope: Option<String>,
    ) -> BulwarkResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_role assign 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_user_role assign 获取 connection 失败: {}", e))
        })?;
        let sql = "INSERT INTO app_user_role (user_id, role_id, scope, tenant_id) \
                   VALUES (?, ?, ?, ?)";
        let stmt = make_statement(
            conn,
            sql,
            vec![
                v_str(user_id),
                v_str(role_id),
                v_opt_str(&scope),
                v_i64(tenant_id),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_role assign 插入失败: {}", e)))?;
        Ok(())
    }

    async fn revoke(&self, tenant_id: i64, user_id: &str, role_id: &str) -> BulwarkResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_role revoke 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_user_role revoke 获取 connection 失败: {}", e))
        })?;
        let sql = "DELETE FROM app_user_role WHERE tenant_id = ? AND user_id = ? AND role_id = ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_str(user_id), v_str(role_id)],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_role revoke 删除失败: {}", e)))?;
        Ok(())
    }

    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> BulwarkResult<Vec<UserRoleRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_role list 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_user_role list 获取 connection 失败: {}", e))
        })?;
        let sql = "SELECT user_id, role_id, scope, grant_time, tenant_id \
                   FROM app_user_role WHERE tenant_id = ? LIMIT ? OFFSET ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_i64(limit), v_i64(offset)],
        );
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_role list 查询失败: {}", e)))?;
        rows.iter().map(parse_user_role_row).collect()
    }
}

/// 解析 app_user_role 行。
fn parse_user_role_row(row: &QueryResult) -> BulwarkResult<UserRoleRow> {
    Ok(UserRoleRow {
        user_id: row
            .try_get("", "user_id")
            .map_err(|e| BulwarkError::Dao(format!("app_user_role 行解析失败 (user_id): {}", e)))?,
        role_id: row
            .try_get("", "role_id")
            .map_err(|e| BulwarkError::Dao(format!("app_user_role 行解析失败 (role_id): {}", e)))?,
        scope: row
            .try_get("", "scope")
            .map_err(|e| BulwarkError::Dao(format!("app_user_role 行解析失败 (scope): {}", e)))?,
        grant_time: row.try_get("", "grant_time").map_err(|e| {
            BulwarkError::Dao(format!("app_user_role 行解析失败 (grant_time): {}", e))
        })?,
        tenant_id: row.try_get("", "tenant_id").map_err(|e| {
            BulwarkError::Dao(format!("app_user_role 行解析失败 (tenant_id): {}", e))
        })?,
    })
}
