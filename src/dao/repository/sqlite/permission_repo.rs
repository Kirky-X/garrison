//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusPermissionRepository 实现（app_permission 表，全局表无 tenant_id）。

use super::{v_i64, v_opt_str, v_str, DbnexusPermissionRepository};
use crate::dao::repository::{make_statement, NewPermission, PermissionRepository, PermissionRow};
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, QueryResult};

impl DbnexusPermissionRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PermissionRepository for DbnexusPermissionRepository {
    async fn find_by_id(&self, id: &str) -> BulwarkResult<Option<PermissionRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_permission find_by_id 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_permission find_by_id 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT id, code, name, resource_type, action, created_at, updated_at \
                   FROM app_permission WHERE id = ?";
        let stmt = make_statement(conn, sql, vec![v_str(id)]);
        let row = conn
            .query_one_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_permission find_by_id 查询失败: {}", e)))?;
        row.map(|r| parse_permission_row(&r)).transpose()
    }

    async fn find_by_code(&self, code: &str) -> BulwarkResult<Option<PermissionRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_permission find_by_code 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_permission find_by_code 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT id, code, name, resource_type, action, created_at, updated_at \
                   FROM app_permission WHERE code = ?";
        let stmt = make_statement(conn, sql, vec![v_str(code)]);
        let row = conn.query_one_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("app_permission find_by_code 查询失败: {}", e))
        })?;
        row.map(|r| parse_permission_row(&r)).transpose()
    }

    async fn create(&self, permission: NewPermission) -> BulwarkResult<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_permission create 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_permission create 获取 connection 失败: {}", e))
        })?;
        let sql = "INSERT INTO app_permission (id, code, name, resource_type, action) \
                   VALUES (?, ?, ?, ?, ?)";
        let stmt = make_statement(
            conn,
            sql,
            vec![
                v_str(&id),
                v_str(&permission.code),
                v_str(&permission.name),
                v_opt_str(&permission.resource_type),
                v_opt_str(&permission.action),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_permission create 插入失败: {}", e)))?;
        Ok(id)
    }

    async fn update(
        &self,
        id: &str,
        name: Option<String>,
        resource_type: Option<String>,
        action: Option<String>,
    ) -> BulwarkResult<()> {
        let mut sets = Vec::new();
        let mut params = Vec::new();
        if let Some(name) = name {
            sets.push("name = ?");
            params.push(v_str(&name));
        }
        if let Some(resource_type) = resource_type {
            sets.push("resource_type = ?");
            params.push(v_str(&resource_type));
        }
        if let Some(action) = action {
            sets.push("action = ?");
            params.push(v_str(&action));
        }
        if sets.is_empty() {
            return Ok(());
        }
        params.push(v_str(id));
        let sql = format!("UPDATE app_permission SET {} WHERE id = ?", sets.join(", "));
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_permission update 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_permission update 获取 connection 失败: {}", e))
        })?;
        let stmt = make_statement(conn, &sql, params);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_permission update 更新失败: {}", e)))?;
        Ok(())
    }

    async fn delete(&self, id: &str) -> BulwarkResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_permission delete 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_permission delete 获取 connection 失败: {}", e))
        })?;
        let sql = "DELETE FROM app_permission WHERE id = ?";
        let stmt = make_statement(conn, sql, vec![v_str(id)]);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_permission delete 删除失败: {}", e)))?;
        Ok(())
    }

    async fn list(&self, offset: i64, limit: i64) -> BulwarkResult<Vec<PermissionRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_permission list 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_permission list 获取 connection 失败: {}", e))
        })?;
        let sql = "SELECT id, code, name, resource_type, action, created_at, updated_at \
                   FROM app_permission LIMIT ? OFFSET ?";
        let stmt = make_statement(conn, sql, vec![v_i64(limit), v_i64(offset)]);
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_permission list 查询失败: {}", e)))?;
        rows.iter().map(parse_permission_row).collect()
    }
}

/// 解析 app_permission 行。
fn parse_permission_row(row: &QueryResult) -> BulwarkResult<PermissionRow> {
    Ok(PermissionRow {
        id: row
            .try_get("", "id")
            .map_err(|e| BulwarkError::Dao(format!("app_permission 行解析失败 (id): {}", e)))?,
        code: row
            .try_get("", "code")
            .map_err(|e| BulwarkError::Dao(format!("app_permission 行解析失败 (code): {}", e)))?,
        name: row
            .try_get("", "name")
            .map_err(|e| BulwarkError::Dao(format!("app_permission 行解析失败 (name): {}", e)))?,
        resource_type: row.try_get("", "resource_type").map_err(|e| {
            BulwarkError::Dao(format!("app_permission 行解析失败 (resource_type): {}", e))
        })?,
        action: row
            .try_get("", "action")
            .map_err(|e| BulwarkError::Dao(format!("app_permission 行解析失败 (action): {}", e)))?,
        created_at: row.try_get("", "created_at").map_err(|e| {
            BulwarkError::Dao(format!("app_permission 行解析失败 (created_at): {}", e))
        })?,
        updated_at: row.try_get("", "updated_at").map_err(|e| {
            BulwarkError::Dao(format!("app_permission 行解析失败 (updated_at): {}", e))
        })?,
    })
}
