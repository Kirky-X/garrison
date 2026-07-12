//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusRolePermissionRepository 实现（app_role_permission 表）。

use super::{v_i64, v_str, DbnexusRolePermissionRepository};
use crate::dao::repository::{make_statement, RolePermissionRepository, RolePermissionRow};
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, QueryResult};

impl DbnexusRolePermissionRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RolePermissionRepository for DbnexusRolePermissionRepository {
    async fn find_by_role_id(
        &self,
        tenant_id: i64,
        role_id: &str,
    ) -> BulwarkResult<Vec<RolePermissionRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission find_by_role_id 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission find_by_role_id 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT role_id, permission_id, tenant_id \
                   FROM app_role_permission WHERE tenant_id = ? AND role_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(role_id)]);
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission find_by_role_id 查询失败: {}",
                e
            ))
        })?;
        rows.iter().map(parse_role_permission_row).collect()
    }

    async fn find_by_permission_id(
        &self,
        tenant_id: i64,
        permission_id: &str,
    ) -> BulwarkResult<Vec<RolePermissionRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission find_by_permission_id 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission find_by_permission_id 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT role_id, permission_id, tenant_id \
                   FROM app_role_permission WHERE tenant_id = ? AND permission_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(permission_id)]);
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission find_by_permission_id 查询失败: {}",
                e
            ))
        })?;
        rows.iter().map(parse_role_permission_row).collect()
    }

    async fn assign(
        &self,
        tenant_id: i64,
        role_id: &str,
        permission_id: &str,
    ) -> BulwarkResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission assign 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission assign 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "INSERT INTO app_role_permission (role_id, permission_id, tenant_id) \
                   VALUES (?, ?, ?)";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_str(role_id), v_str(permission_id), v_i64(tenant_id)],
        );
        conn.execute_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("app_role_permission assign 插入失败: {}", e))
        })?;
        Ok(())
    }

    async fn revoke(
        &self,
        tenant_id: i64,
        role_id: &str,
        permission_id: &str,
    ) -> BulwarkResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission revoke 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission revoke 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "DELETE FROM app_role_permission \
                   WHERE tenant_id = ? AND role_id = ? AND permission_id = ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_str(role_id), v_str(permission_id)],
        );
        conn.execute_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("app_role_permission revoke 删除失败: {}", e))
        })?;
        Ok(())
    }

    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> BulwarkResult<Vec<RolePermissionRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_role_permission list 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission list 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT role_id, permission_id, tenant_id \
                   FROM app_role_permission WHERE tenant_id = ? LIMIT ? OFFSET ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_i64(limit), v_i64(offset)],
        );
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_role_permission list 查询失败: {}", e)))?;
        rows.iter().map(parse_role_permission_row).collect()
    }
}

/// 解析 app_role_permission 行。
fn parse_role_permission_row(row: &QueryResult) -> BulwarkResult<RolePermissionRow> {
    Ok(RolePermissionRow {
        role_id: row.try_get("", "role_id").map_err(|e| {
            BulwarkError::Dao(format!("app_role_permission 行解析失败 (role_id): {}", e))
        })?,
        permission_id: row.try_get("", "permission_id").map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission 行解析失败 (permission_id): {}",
                e
            ))
        })?,
        tenant_id: row.try_get("", "tenant_id").map_err(|e| {
            BulwarkError::Dao(format!("app_role_permission 行解析失败 (tenant_id): {}", e))
        })?,
    })
}
