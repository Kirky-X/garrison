//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusUserRepository 实现（app_user 表）。

use super::{v_i64, v_str, DbnexusUserRepository};
use crate::dao::repository::{make_statement, NewUser, UpdateUser, UserRepository, UserRow};
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, QueryResult};

impl DbnexusUserRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRepository for DbnexusUserRepository {
    async fn find_by_id(&self, tenant_id: i64, id: &str) -> BulwarkResult<Option<UserRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_user find_by_id 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_user find_by_id 获取 connection 失败: {}", e))
        })?;
        let sql = "SELECT id, username, password_hash, status, tenant_id, created_at, updated_at, last_login_at \
                   FROM app_user WHERE tenant_id = ? AND id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(id)]);
        let row = conn
            .query_one_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user find_by_id 查询失败: {}", e)))?;
        row.map(|r| parse_user_row(&r)).transpose()
    }

    async fn find_by_username(
        &self,
        tenant_id: i64,
        username: &str,
    ) -> BulwarkResult<Option<UserRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user find_by_username 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user find_by_username 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT id, username, password_hash, status, tenant_id, created_at, updated_at, last_login_at \
                   FROM app_user WHERE tenant_id = ? AND username = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(username)]);
        let row = conn
            .query_one_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user find_by_username 查询失败: {}", e)))?;
        row.map(|r| parse_user_row(&r)).transpose()
    }

    async fn create(&self, tenant_id: i64, user: NewUser) -> BulwarkResult<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("app_user create 获取 session 失败: {}", e))
            })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_user create 获取 connection 失败: {}", e))
        })?;
        let sql = "INSERT INTO app_user (id, username, password_hash, status, tenant_id) \
                   VALUES (?, ?, ?, ?, ?)";
        let stmt = make_statement(
            conn,
            sql,
            vec![
                v_str(&id),
                v_str(&user.username),
                v_str(&user.password_hash),
                v_str(&user.status),
                v_i64(tenant_id),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user create 插入失败: {}", e)))?;
        Ok(id)
    }

    async fn update(&self, tenant_id: i64, id: &str, user: UpdateUser) -> BulwarkResult<()> {
        let mut sets = Vec::new();
        let mut params = Vec::new();
        if let Some(username) = user.username {
            sets.push("username = ?");
            params.push(v_str(&username));
        }
        if let Some(password_hash) = user.password_hash {
            sets.push("password_hash = ?");
            params.push(v_str(&password_hash));
        }
        if let Some(status) = user.status {
            sets.push("status = ?");
            params.push(v_str(&status));
        }
        if let Some(last_login_at) = user.last_login_at {
            sets.push("last_login_at = ?");
            params.push(v_str(&last_login_at));
        }
        if sets.is_empty() {
            return Ok(());
        }
        params.push(v_i64(tenant_id));
        params.push(v_str(id));
        let sql = format!(
            "UPDATE app_user SET {} WHERE tenant_id = ? AND id = ?",
            sets.join(", ")
        );
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("app_user update 获取 session 失败: {}", e))
            })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_user update 获取 connection 失败: {}", e))
        })?;
        let stmt = make_statement(conn, &sql, params);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user update 更新失败: {}", e)))?;
        Ok(())
    }

    async fn delete(&self, tenant_id: i64, id: &str) -> BulwarkResult<()> {
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("app_user delete 获取 session 失败: {}", e))
            })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_user delete 获取 connection 失败: {}", e))
        })?;
        let sql = "DELETE FROM app_user WHERE tenant_id = ? AND id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(id)]);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user delete 删除失败: {}", e)))?;
        Ok(())
    }

    async fn list(&self, tenant_id: i64, offset: i64, limit: i64) -> BulwarkResult<Vec<UserRow>> {
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("app_user list 获取 session 失败: {}", e))
            })?;
        let conn = session
            .connection()
            .map_err(|e| BulwarkError::Dao(format!("app_user list 获取 connection 失败: {}", e)))?;
        let sql = "SELECT id, username, password_hash, status, tenant_id, created_at, updated_at, last_login_at \
                   FROM app_user WHERE tenant_id = ? LIMIT ? OFFSET ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_i64(limit), v_i64(offset)],
        );
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user list 查询失败: {}", e)))?;
        rows.iter().map(parse_user_row).collect()
    }
}

/// 解析 app_user 行。
fn parse_user_row(row: &QueryResult) -> BulwarkResult<UserRow> {
    Ok(UserRow {
        id: row
            .try_get("", "id")
            .map_err(|e| BulwarkError::Dao(format!("app_user 行解析失败 (id): {}", e)))?,
        username: row
            .try_get("", "username")
            .map_err(|e| BulwarkError::Dao(format!("app_user 行解析失败 (username): {}", e)))?,
        password_hash: row.try_get("", "password_hash").map_err(|e| {
            BulwarkError::Dao(format!("app_user 行解析失败 (password_hash): {}", e))
        })?,
        status: row
            .try_get("", "status")
            .map_err(|e| BulwarkError::Dao(format!("app_user 行解析失败 (status): {}", e)))?,
        tenant_id: row
            .try_get("", "tenant_id")
            .map_err(|e| BulwarkError::Dao(format!("app_user 行解析失败 (tenant_id): {}", e)))?,
        created_at: row
            .try_get("", "created_at")
            .map_err(|e| BulwarkError::Dao(format!("app_user 行解析失败 (created_at): {}", e)))?,
        updated_at: row
            .try_get("", "updated_at")
            .map_err(|e| BulwarkError::Dao(format!("app_user 行解析失败 (updated_at): {}", e)))?,
        last_login_at: row.try_get("", "last_login_at").map_err(|e| {
            BulwarkError::Dao(format!("app_user 行解析失败 (last_login_at): {}", e))
        })?,
    })
}
