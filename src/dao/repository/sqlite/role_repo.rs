//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusRoleRepository 实现（app_role 表）。

use super::{read_bool, v_bool, v_i64, v_opt_str, v_str, DbnexusRoleRepository};
use crate::dao::repository::{make_statement, NewRole, RoleRepository, RoleRow};
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, QueryResult};

impl DbnexusRoleRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RoleRepository for DbnexusRoleRepository {
    async fn find_by_id(&self, tenant_id: i64, id: &str) -> BulwarkResult<Option<RoleRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_role find_by_id 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_role find_by_id 获取 connection 失败: {}", e))
        })?;
        let sql =
            "SELECT id, code, name, description, tenant_id, is_system, created_at, updated_at \
                   FROM app_role WHERE tenant_id = ? AND id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(id)]);
        let row = conn
            .query_one_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_role find_by_id 查询失败: {}", e)))?;
        row.map(|r| parse_role_row(&r)).transpose()
    }

    async fn find_by_code(&self, tenant_id: i64, code: &str) -> BulwarkResult<Option<RoleRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_role find_by_code 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_role find_by_code 获取 connection 失败: {}", e))
        })?;
        let sql =
            "SELECT id, code, name, description, tenant_id, is_system, created_at, updated_at \
                   FROM app_role WHERE tenant_id = ? AND code = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(code)]);
        let row = conn
            .query_one_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_role find_by_code 查询失败: {}", e)))?;
        row.map(|r| parse_role_row(&r)).transpose()
    }

    async fn create(&self, tenant_id: i64, role: NewRole) -> BulwarkResult<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("app_role create 获取 session 失败: {}", e))
            })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_role create 获取 connection 失败: {}", e))
        })?;
        let sql = "INSERT INTO app_role (id, code, name, description, tenant_id, is_system) \
                   VALUES (?, ?, ?, ?, ?, ?)";
        let stmt = make_statement(
            conn,
            sql,
            vec![
                v_str(&id),
                v_str(&role.code),
                v_str(&role.name),
                v_opt_str(&role.description),
                v_i64(tenant_id),
                v_bool(role.is_system),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_role create 插入失败: {}", e)))?;
        Ok(id)
    }

    async fn update(
        &self,
        tenant_id: i64,
        id: &str,
        code: Option<String>,
        name: Option<String>,
        description: Option<String>,
    ) -> BulwarkResult<()> {
        let mut sets = Vec::new();
        let mut params = Vec::new();
        if let Some(code) = code {
            sets.push("code = ?");
            params.push(v_str(&code));
        }
        if let Some(name) = name {
            sets.push("name = ?");
            params.push(v_str(&name));
        }
        if let Some(description) = description {
            sets.push("description = ?");
            params.push(v_str(&description));
        }
        if sets.is_empty() {
            return Ok(());
        }
        params.push(v_i64(tenant_id));
        params.push(v_str(id));
        let sql = format!(
            "UPDATE app_role SET {} WHERE tenant_id = ? AND id = ?",
            sets.join(", ")
        );
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("app_role update 获取 session 失败: {}", e))
            })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_role update 获取 connection 失败: {}", e))
        })?;
        let stmt = make_statement(conn, &sql, params);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_role update 更新失败: {}", e)))?;
        Ok(())
    }

    async fn delete(&self, tenant_id: i64, id: &str) -> BulwarkResult<()> {
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("app_role delete 获取 session 失败: {}", e))
            })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_role delete 获取 connection 失败: {}", e))
        })?;
        let sql = "DELETE FROM app_role WHERE tenant_id = ? AND id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(id)]);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_role delete 删除失败: {}", e)))?;
        Ok(())
    }

    async fn list(&self, tenant_id: i64, offset: i64, limit: i64) -> BulwarkResult<Vec<RoleRow>> {
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("app_role list 获取 session 失败: {}", e))
            })?;
        let conn = session
            .connection()
            .map_err(|e| BulwarkError::Dao(format!("app_role list 获取 connection 失败: {}", e)))?;
        let sql =
            "SELECT id, code, name, description, tenant_id, is_system, created_at, updated_at \
                   FROM app_role WHERE tenant_id = ? LIMIT ? OFFSET ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_i64(limit), v_i64(offset)],
        );
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_role list 查询失败: {}", e)))?;
        rows.iter().map(parse_role_row).collect()
    }
}

/// 解析 app_role 行。
fn parse_role_row(row: &QueryResult) -> BulwarkResult<RoleRow> {
    Ok(RoleRow {
        id: row
            .try_get("", "id")
            .map_err(|e| BulwarkError::Dao(format!("app_role 行解析失败 (id): {}", e)))?,
        code: row
            .try_get("", "code")
            .map_err(|e| BulwarkError::Dao(format!("app_role 行解析失败 (code): {}", e)))?,
        name: row
            .try_get("", "name")
            .map_err(|e| BulwarkError::Dao(format!("app_role 行解析失败 (name): {}", e)))?,
        description: row
            .try_get("", "description")
            .map_err(|e| BulwarkError::Dao(format!("app_role 行解析失败 (description): {}", e)))?,
        tenant_id: row
            .try_get("", "tenant_id")
            .map_err(|e| BulwarkError::Dao(format!("app_role 行解析失败 (tenant_id): {}", e)))?,
        is_system: read_bool(row, "is_system"),
        created_at: row
            .try_get("", "created_at")
            .map_err(|e| BulwarkError::Dao(format!("app_role 行解析失败 (created_at): {}", e)))?,
        updated_at: row
            .try_get("", "updated_at")
            .map_err(|e| BulwarkError::Dao(format!("app_role 行解析失败 (updated_at): {}", e)))?,
    })
}
