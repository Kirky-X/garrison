//! Dbnexus Repository 实现（依据 spec repository-layer R-003）。
//!
//! 基于 dbnexus DbPool + sea-orm Statement 参数化查询。
//! 通过 [`make_statement`] 实现 backend-agnostic：传入 `?` 占位符的 SQL，
//! PostgreSQL 后端运行时自动转换为 `$1`, `$2`, ...
//!
//! ## 设计要点
//!
//! - **参数化查询**：所有 WHERE 条件用 `?` 占位符，防 SQL 注入。
//! - **多租户过滤**（R-004）：有 tenant_id 的表自动注入 `WHERE tenant_id = ?`；
//!   `app_permission` 表无 tenant_id（全局表）。
//! - **find_by_\*** 返回 `Option<Row>`，不存在返回 `Ok(None)`。
//! - **create** 返回 `NewXxx.id`（调用方生成的 UUID），不依赖数据库自增 ID。
//! - **delete** 幂等，不存在返回 `Ok(())`。
//! - **bool 字段**：SQLite 用 INTEGER 0/1 存储，Row struct 用 bool，读取时 i64→bool 转换。
//! - **时间字段**：SQLite 用 CURRENT_TIMESTAMP 默认生成，读取为 String。

use crate::dao::repository::*;
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, QueryResult, Value};

// ============================================================================
// 内部辅助函数
// ============================================================================

/// 构造字符串 Value 参数。
fn v_str(s: &str) -> Value {
    Value::String(Some(s.to_string()))
}

/// 构造可选字符串 Value 参数（None → SQL NULL）。
fn v_opt_str(s: &Option<String>) -> Value {
    Value::String(s.clone())
}

/// 构造 i64 Value 参数（用于 offset/limit 等）。
fn v_i64(n: i64) -> Value {
    Value::BigInt(Some(n))
}

/// 构造布尔 Value 参数（SQLite 用 0/1 存储）。
fn v_bool(b: bool) -> Value {
    Value::BigInt(Some(if b { 1 } else { 0 }))
}

/// 读取 bool 列（SQLite INTEGER 0/1 → bool）。
fn read_bool(row: &QueryResult, col: &str) -> bool {
    row.try_get::<i64>("", col).map(|v| v != 0).unwrap_or(false)
}

// ============================================================================
// 1. DbnexusUserRepository（app_user 表）
// ============================================================================

/// SQLite 用户表 Repository 实现。
pub struct DbnexusUserRepository {
    pool: DbPool,
}

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

// ============================================================================
// 2. DbnexusRoleRepository（app_role 表）
// ============================================================================

/// SQLite 角色表 Repository 实现。
pub struct DbnexusRoleRepository {
    pool: DbPool,
}

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

// ============================================================================
// 3. DbnexusPermissionRepository（app_permission 表，全局表无 tenant_id）
// ============================================================================

/// SQLite 权限表 Repository 实现（全局表，无 tenant_id）。
pub struct DbnexusPermissionRepository {
    pool: DbPool,
}

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

// ============================================================================
// 4. DbnexusUserRoleRepository（app_user_role 表）
// ============================================================================

/// SQLite 用户-角色关联表 Repository 实现。
pub struct DbnexusUserRoleRepository {
    pool: DbPool,
}

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

// ============================================================================
// 5. DbnexusRolePermissionRepository（app_role_permission 表）
// ============================================================================

/// SQLite 角色-权限关联表 Repository 实现。
pub struct DbnexusRolePermissionRepository {
    pool: DbPool,
}

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

// ============================================================================
// 6. DbnexusAuthMethodRepository（app_auth_method 表）
// ============================================================================

/// SQLite 认证方式表 Repository 实现。
pub struct DbnexusAuthMethodRepository {
    pool: DbPool,
}

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

// ============================================================================
// 7. DbnexusSessionRepository（app_session 表）
// ============================================================================

/// SQLite 会话表 Repository 实现。
pub struct DbnexusSessionRepository {
    pool: DbPool,
}

impl DbnexusSessionRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SessionRepository for DbnexusSessionRepository {
    async fn find_by_session_id(
        &self,
        tenant_id: i64,
        session_id: &str,
    ) -> BulwarkResult<Option<SessionRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_session find_by_session_id 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_session find_by_session_id 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql =
            "SELECT session_id, user_id, device_id, ip, user_agent, login_time, last_active, \
                   expire_time, tenant_id \
                   FROM app_session WHERE tenant_id = ? AND session_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(session_id)]);
        let row = conn.query_one_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("app_session find_by_session_id 查询失败: {}", e))
        })?;
        row.map(|r| parse_session_row(&r)).transpose()
    }

    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
    ) -> BulwarkResult<Vec<SessionRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_session find_by_user_id 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_session find_by_user_id 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql =
            "SELECT session_id, user_id, device_id, ip, user_agent, login_time, last_active, \
                   expire_time, tenant_id \
                   FROM app_session WHERE tenant_id = ? AND user_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(user_id)]);
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("app_session find_by_user_id 查询失败: {}", e))
        })?;
        rows.iter().map(parse_session_row).collect()
    }

    async fn create(&self, tenant_id: i64, session: NewSession) -> BulwarkResult<String> {
        let db_session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_session create 获取 session 失败: {}", e))
        })?;
        let conn = db_session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_session create 获取 connection 失败: {}", e))
        })?;
        let sql = "INSERT INTO app_session \
                   (session_id, user_id, device_id, ip, user_agent, expire_time, tenant_id) \
                   VALUES (?, ?, ?, ?, ?, ?, ?)";
        let stmt = make_statement(
            conn,
            sql,
            vec![
                v_str(&session.session_id),
                v_str(&session.user_id),
                v_opt_str(&session.device_id),
                v_opt_str(&session.ip),
                v_opt_str(&session.user_agent),
                v_opt_str(&session.expire_time),
                v_i64(tenant_id),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_session create 插入失败: {}", e)))?;
        Ok(session.session_id)
    }

    async fn update_last_active(&self, tenant_id: i64, session_id: &str) -> BulwarkResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_session update_last_active 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_session update_last_active 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "UPDATE app_session SET last_active = CURRENT_TIMESTAMP \
                   WHERE tenant_id = ? AND session_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(session_id)]);
        conn.execute_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("app_session update_last_active 更新失败: {}", e))
        })?;
        Ok(())
    }

    async fn delete(&self, tenant_id: i64, session_id: &str) -> BulwarkResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_session delete 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_session delete 获取 connection 失败: {}", e))
        })?;
        let sql = "DELETE FROM app_session WHERE tenant_id = ? AND session_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(session_id)]);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_session delete 删除失败: {}", e)))?;
        Ok(())
    }

    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> BulwarkResult<Vec<SessionRow>> {
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("app_session list 获取 session 失败: {}", e))
            })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_session list 获取 connection 失败: {}", e))
        })?;
        let sql =
            "SELECT session_id, user_id, device_id, ip, user_agent, login_time, last_active, \
                   expire_time, tenant_id \
                   FROM app_session WHERE tenant_id = ? LIMIT ? OFFSET ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_i64(limit), v_i64(offset)],
        );
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_session list 查询失败: {}", e)))?;
        rows.iter().map(parse_session_row).collect()
    }
}

/// 解析 app_session 行。
fn parse_session_row(row: &QueryResult) -> BulwarkResult<SessionRow> {
    Ok(SessionRow {
        session_id: row.try_get("", "session_id").map_err(|e| {
            BulwarkError::Dao(format!("app_session 行解析失败 (session_id): {}", e))
        })?,
        user_id: row
            .try_get("", "user_id")
            .map_err(|e| BulwarkError::Dao(format!("app_session 行解析失败 (user_id): {}", e)))?,
        device_id: row
            .try_get("", "device_id")
            .map_err(|e| BulwarkError::Dao(format!("app_session 行解析失败 (device_id): {}", e)))?,
        ip: row
            .try_get("", "ip")
            .map_err(|e| BulwarkError::Dao(format!("app_session 行解析失败 (ip): {}", e)))?,
        user_agent: row.try_get("", "user_agent").map_err(|e| {
            BulwarkError::Dao(format!("app_session 行解析失败 (user_agent): {}", e))
        })?,
        login_time: row.try_get("", "login_time").map_err(|e| {
            BulwarkError::Dao(format!("app_session 行解析失败 (login_time): {}", e))
        })?,
        last_active: row.try_get("", "last_active").map_err(|e| {
            BulwarkError::Dao(format!("app_session 行解析失败 (last_active): {}", e))
        })?,
        expire_time: row.try_get("", "expire_time").map_err(|e| {
            BulwarkError::Dao(format!("app_session 行解析失败 (expire_time): {}", e))
        })?,
        tenant_id: row
            .try_get("", "tenant_id")
            .map_err(|e| BulwarkError::Dao(format!("app_session 行解析失败 (tenant_id): {}", e)))?,
    })
}

// ============================================================================
// 8. DbnexusLoginLogRepository（app_login_log 表）
// ============================================================================

/// SQLite 登录日志表 Repository 实现。
pub struct DbnexusLoginLogRepository {
    pool: DbPool,
}

impl DbnexusLoginLogRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl LoginLogRepository for DbnexusLoginLogRepository {
    async fn find_by_id(&self, tenant_id: i64, id: &str) -> BulwarkResult<Option<LoginLogRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_login_log find_by_id 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_login_log find_by_id 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT id, user_id, action, ip, device_id, success, fail_reason, create_time, tenant_id \
                   FROM app_login_log WHERE tenant_id = ? AND id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(id)]);
        let row = conn
            .query_one_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_login_log find_by_id 查询失败: {}", e)))?;
        row.map(|r| parse_login_log_row(&r)).transpose()
    }

    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
        offset: i64,
        limit: i64,
    ) -> BulwarkResult<Vec<LoginLogRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_login_log find_by_user_id 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_login_log find_by_user_id 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT id, user_id, action, ip, device_id, success, fail_reason, create_time, tenant_id \
                   FROM app_login_log WHERE tenant_id = ? AND user_id = ? \
                   ORDER BY create_time DESC LIMIT ? OFFSET ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![
                v_i64(tenant_id),
                v_str(user_id),
                v_i64(limit),
                v_i64(offset),
            ],
        );
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("app_login_log find_by_user_id 查询失败: {}", e))
        })?;
        rows.iter().map(parse_login_log_row).collect()
    }

    async fn create(&self, tenant_id: i64, log: NewLoginLog) -> BulwarkResult<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_login_log create 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_login_log create 获取 connection 失败: {}", e))
        })?;
        let sql = "INSERT INTO app_login_log \
                   (id, user_id, action, ip, device_id, success, fail_reason, tenant_id) \
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
        let stmt = make_statement(
            conn,
            sql,
            vec![
                v_str(&id),
                v_opt_str(&log.user_id),
                v_str(&log.action),
                v_opt_str(&log.ip),
                v_opt_str(&log.device_id),
                v_bool(log.success),
                v_opt_str(&log.fail_reason),
                v_i64(tenant_id),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_login_log create 插入失败: {}", e)))?;
        Ok(id)
    }

    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> BulwarkResult<Vec<LoginLogRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_login_log list 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_login_log list 获取 connection 失败: {}", e))
        })?;
        let sql = "SELECT id, user_id, action, ip, device_id, success, fail_reason, create_time, tenant_id \
                   FROM app_login_log WHERE tenant_id = ? ORDER BY create_time DESC LIMIT ? OFFSET ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_i64(limit), v_i64(offset)],
        );
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_login_log list 查询失败: {}", e)))?;
        rows.iter().map(parse_login_log_row).collect()
    }
}

/// 解析 app_login_log 行。
fn parse_login_log_row(row: &QueryResult) -> BulwarkResult<LoginLogRow> {
    Ok(LoginLogRow {
        id: row
            .try_get("", "id")
            .map_err(|e| BulwarkError::Dao(format!("app_login_log 行解析失败 (id): {}", e)))?,
        user_id: row
            .try_get("", "user_id")
            .map_err(|e| BulwarkError::Dao(format!("app_login_log 行解析失败 (user_id): {}", e)))?,
        action: row
            .try_get("", "action")
            .map_err(|e| BulwarkError::Dao(format!("app_login_log 行解析失败 (action): {}", e)))?,
        ip: row
            .try_get("", "ip")
            .map_err(|e| BulwarkError::Dao(format!("app_login_log 行解析失败 (ip): {}", e)))?,
        device_id: row.try_get("", "device_id").map_err(|e| {
            BulwarkError::Dao(format!("app_login_log 行解析失败 (device_id): {}", e))
        })?,
        success: read_bool(row, "success"),
        fail_reason: row.try_get("", "fail_reason").map_err(|e| {
            BulwarkError::Dao(format!("app_login_log 行解析失败 (fail_reason): {}", e))
        })?,
        create_time: row.try_get("", "create_time").map_err(|e| {
            BulwarkError::Dao(format!("app_login_log 行解析失败 (create_time): {}", e))
        })?,
        tenant_id: row.try_get("", "tenant_id").map_err(|e| {
            BulwarkError::Dao(format!("app_login_log 行解析失败 (tenant_id): {}", e))
        })?,
    })
}

// ============================================================================
// 9. DbnexusUserExtRepository（app_user_ext 表）
// ============================================================================

/// SQLite 用户扩展字段表 Repository 实现。
pub struct DbnexusUserExtRepository {
    pool: DbPool,
}

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
        // SQLite UPSERT（ON CONFLICT ... DO UPDATE），依赖 UK(user_id, field_key)。
        // 插入时生成新 UUID；冲突时更新 field_value/field_type/updated_at（保留原 id/created_at）。
        let new_id = uuid::Uuid::new_v4().to_string();
        let sql = "INSERT INTO app_user_ext (id, user_id, field_key, field_value, field_type, tenant_id) \
                   VALUES (?, ?, ?, ?, ?, ?) \
                   ON CONFLICT(user_id, field_key) DO UPDATE SET \
                   field_value = excluded.field_value, \
                   field_type = excluded.field_type, \
                   updated_at = CURRENT_TIMESTAMP";
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

// ============================================================================
// 10. DbnexusUserDeviceRepository（app_user_device 表，v0.5.1 新增，依据 design.md D4 / M2）
// ============================================================================

/// SQLite 用户设备表 Repository 实现。
///
/// UA 解析当前用简单字符串启发式（提取 Browser/OS 关键字）。
/// 完整 `ua-parser` regex 集需启用 `ua-parser-precompiled` feature（设计 A4 决策延后）。
pub struct DbnexusUserDeviceRepository {
    pool: DbPool,
}

impl DbnexusUserDeviceRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserDeviceRepository for DbnexusUserDeviceRepository {
    async fn register_device(
        &self,
        tenant_id: i64,
        login_id: &str,
        identifier: &str,
        ua: &str,
    ) -> BulwarkResult<String> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_device register_device 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_device register_device 获取 connection 失败: {}",
                e
            ))
        })?;

        // 1. 检查是否已存在（幂等：相同 tenant_id + login_id + identifier 返回已有 ID）
        let find_sql = "SELECT id FROM app_user_device \
                        WHERE tenant_id = ? AND login_id = ? AND device_identifier = ?";
        let stmt = make_statement(
            conn,
            find_sql,
            vec![v_i64(tenant_id), v_str(login_id), v_str(identifier)],
        );
        let existing = conn
            .query_one_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_device 查询已存在失败: {}", e)))?;

        if let Some(row) = existing {
            let existing_id: String = row.try_get("", "id").map_err(|e| {
                BulwarkError::Dao(format!("app_user_device 解析已存在 id 失败: {}", e))
            })?;
            // 更新 last_seen_at（幂等注册视为一次活跃）
            let now = chrono::Utc::now().timestamp();
            let update_sql = "UPDATE app_user_device SET last_seen_at = ? WHERE id = ?";
            let stmt = make_statement(conn, update_sql, vec![v_i64(now), v_str(&existing_id)]);
            conn.execute_raw(stmt).await.map_err(|e| {
                BulwarkError::Dao(format!("app_user_device 更新 last_seen_at 失败: {}", e))
            })?;
            return Ok(existing_id);
        }

        // 2. 检查是否超过 MAX_DEVICES
        let count_sql =
            "SELECT COUNT(*) AS cnt FROM app_user_device WHERE tenant_id = ? AND login_id = ?";
        let stmt = make_statement(conn, count_sql, vec![v_i64(tenant_id), v_str(login_id)]);
        let count_row = conn
            .query_one_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_device count 查询失败: {}", e)))?
            .ok_or_else(|| BulwarkError::Dao("app_user_device COUNT(*) 未返回行".into()))?;
        let current_count: i64 = count_row
            .try_get("", "cnt")
            .map_err(|e| BulwarkError::Dao(format!("app_user_device 解析 count 失败: {}", e)))?;
        if (current_count as usize) >= MAX_DEVICES {
            return Err(BulwarkError::InvalidParam(format!(
                "用户 (tenant_id={}, login_id={}) 设备数已达上限 {}，无法注册新设备",
                tenant_id, login_id, MAX_DEVICES
            )));
        }

        // 3. 插入新设备
        let device_id = uuid::Uuid::new_v4().to_string();
        let now = chrono::Utc::now().timestamp();
        let device_name = parse_device_name(ua);
        let insert_sql = "INSERT INTO app_user_device \
                          (id, tenant_id, login_id, device_identifier, device_name, user_agent, is_blocked, last_seen_at, created_at) \
                          VALUES (?, ?, ?, ?, ?, ?, 0, ?, ?)";
        let stmt = make_statement(
            conn,
            insert_sql,
            vec![
                v_str(&device_id),
                v_i64(tenant_id),
                v_str(login_id),
                v_str(identifier),
                v_opt_str(&device_name),
                v_opt_str(&Some(ua.to_string())),
                v_i64(now),
                v_i64(now),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_device 插入失败: {}", e)))?;
        Ok(device_id)
    }

    async fn block_device(&self, device_id: &str) -> BulwarkResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_device block_device 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_device block_device 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "UPDATE app_user_device SET is_blocked = 1 WHERE id = ?";
        let stmt = make_statement(conn, sql, vec![v_str(device_id)]);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_device block 更新失败: {}", e)))?;
        Ok(())
    }

    async fn unblock_device(&self, device_id: &str) -> BulwarkResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_device unblock_device 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_device unblock_device 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "UPDATE app_user_device SET is_blocked = 0 WHERE id = ?";
        let stmt = make_statement(conn, sql, vec![v_str(device_id)]);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_device unblock 更新失败: {}", e)))?;
        Ok(())
    }

    async fn list_user_devices(
        &self,
        tenant_id: i64,
        login_id: &str,
    ) -> BulwarkResult<Vec<UserDeviceRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_device list 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_user_device list 获取 connection 失败: {}", e))
        })?;
        let sql = "SELECT id, tenant_id, login_id, device_identifier, device_name, user_agent, \
                  is_blocked, last_seen_at, created_at \
                  FROM app_user_device WHERE tenant_id = ? AND login_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(login_id)]);
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_device list 查询失败: {}", e)))?;
        rows.iter().map(parse_user_device_row).collect()
    }

    async fn count_user_devices(&self, tenant_id: i64, login_id: &str) -> BulwarkResult<usize> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_device count 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_user_device count 获取 connection 失败: {}", e))
        })?;
        let sql =
            "SELECT COUNT(*) AS cnt FROM app_user_device WHERE tenant_id = ? AND login_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(login_id)]);
        let row = conn
            .query_one_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_device count 查询失败: {}", e)))?
            .ok_or_else(|| BulwarkError::Dao("app_user_device COUNT(*) 未返回行".into()))?;
        let count: i64 = row
            .try_get("", "cnt")
            .map_err(|e| BulwarkError::Dao(format!("app_user_device 解析 count 失败: {}", e)))?;
        Ok(count as usize)
    }
}

/// 解析 app_user_device 行。
fn parse_user_device_row(row: &QueryResult) -> BulwarkResult<UserDeviceRow> {
    Ok(UserDeviceRow {
        id: row
            .try_get("", "id")
            .map_err(|e| BulwarkError::Dao(format!("app_user_device 行解析失败 (id): {}", e)))?,
        tenant_id: row.try_get("", "tenant_id").map_err(|e| {
            BulwarkError::Dao(format!("app_user_device 行解析失败 (tenant_id): {}", e))
        })?,
        login_id: row.try_get("", "login_id").map_err(|e| {
            BulwarkError::Dao(format!("app_user_device 行解析失败 (login_id): {}", e))
        })?,
        device_identifier: row.try_get("", "device_identifier").map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_device 行解析失败 (device_identifier): {}",
                e
            ))
        })?,
        device_name: row.try_get("", "device_name").map_err(|e| {
            BulwarkError::Dao(format!("app_user_device 行解析失败 (device_name): {}", e))
        })?,
        user_agent: row.try_get("", "user_agent").map_err(|e| {
            BulwarkError::Dao(format!("app_user_device 行解析失败 (user_agent): {}", e))
        })?,
        is_blocked: read_bool(row, "is_blocked"),
        last_seen_at: row.try_get("", "last_seen_at").map_err(|e| {
            BulwarkError::Dao(format!("app_user_device 行解析失败 (last_seen_at): {}", e))
        })?,
        created_at: row.try_get("", "created_at").map_err(|e| {
            BulwarkError::Dao(format!("app_user_device 行解析失败 (created_at): {}", e))
        })?,
    })
}

/// 从 User-Agent 字符串解析设备名（简单字符串启发式）。
///
/// 完整 `ua-parser` regex 集需启用 `ua-parser-precompiled` feature（设计 A4 决策延后），
/// 当前用关键字匹配提取 Browser + OS 信息。
fn parse_device_name(ua: &str) -> Option<String> {
    if ua.is_empty() {
        return None;
    }
    let browser = detect_browser(ua);
    let os = detect_os(ua);
    match (browser, os) {
        (Some(b), Some(o)) => Some(format!("{} on {}", b, o)),
        (Some(b), None) => Some(b),
        (None, Some(o)) => Some(o),
        (None, None) => None,
    }
}

/// 从 UA 检测浏览器名。
fn detect_browser(ua: &str) -> Option<String> {
    // 注意：检测顺序重要——Edg 必须在 Chrome 之前（Edge UA 包含 Chrome）
    if ua.contains("Edg/") {
        Some("Edge".into())
    } else if ua.contains("Firefox/") {
        Some("Firefox".into())
    } else if ua.contains("Chrome/") {
        Some("Chrome".into())
    } else if ua.contains("Safari/") {
        Some("Safari".into())
    } else if ua.contains("OPR/") || ua.contains("Opera/") {
        Some("Opera".into())
    } else {
        None
    }
}

/// 从 UA 检测操作系统名。
fn detect_os(ua: &str) -> Option<String> {
    if ua.contains("Windows NT") {
        Some("Windows".into())
    } else if ua.contains("iPhone") || ua.contains("iPad") {
        Some("iOS".into())
    } else if ua.contains("Mac OS X") || ua.contains("Macintosh") {
        Some("macOS".into())
    } else if ua.contains("Android") {
        Some("Android".into())
    } else if ua.contains("Linux") {
        Some("Linux".into())
    } else {
        None
    }
}

// ============================================================================
// 测试模块（依据 spec tenant-isolation R-004）
// ============================================================================

#[cfg(all(test, feature = "db-sqlite"))]
mod tests {
    use super::*;
    use crate::dao::{init_dbnexus, BulwarkMigration};
    use std::path::PathBuf;

    /// 定位项目根目录的 migrations/sqlite/ 目录。
    fn project_migrations_dir() -> PathBuf {
        let manifest_dir = env!("CARGO_MANIFEST_DIR");
        PathBuf::from(manifest_dir)
            .join("migrations")
            .join("sqlite")
    }

    /// 创建并初始化 SQLite in-memory 数据库（迁移 + 返回 pool）。
    async fn setup_db() -> DbPool {
        let pool = init_dbnexus("sqlite::memory:")
            .await
            .expect("init_dbnexus 应成功");
        let migration = BulwarkMigration::with_base_dir(pool.clone(), project_migrations_dir());
        let applied = migration.migrate_core().await.expect("migrate_core 应成功");
        assert!(applied >= 1, "migrate_core 应至少执行 1 个文件");
        pool
    }

    /// R-tenant-isolation-004: Repository SQL 强制 tenant_id 过滤。
    ///
    /// 验证 v0.4.2 已无条件实现的 `WHERE tenant_id = ?` 过滤行为：
    /// - 构造 tenant_id=42 与 tenant_id=1 的用户
    /// - 跨租户查询应返回 None（SQL 含 `WHERE tenant_id = ?` 过滤）
    /// - list 按 tenant 隔离
    ///
    /// 注：v0.5.0 决策（Rule 7 暴露冲突后用户选择"保留 v0.4.2 无条件过滤"）：
    /// SQL 过滤不门控 `tenant-isolation` feature，始终生效——因 tenant_id 已是所有表必需字段，
    /// 不过滤会导致跨租户数据泄露（安全优先）。
    #[tokio::test(flavor = "multi_thread")]
    async fn repository_filters_by_tenant_id_when_tenant_isolation_enabled() {
        let pool = setup_db().await;
        let repo = DbnexusUserRepository::new(pool);

        // 在 tenant 42 创建用户
        let user_42 = repo
            .create(
                42,
                NewUser {
                    username: "tenant-42-user".to_string(),
                    password_hash: "h".to_string(),
                    status: "active".to_string(),
                },
            )
            .await
            .expect("create tenant 42 用户应成功");

        // 在 tenant 1 创建用户
        let user_1 = repo
            .create(
                1,
                NewUser {
                    username: "tenant-1-user".to_string(),
                    password_hash: "h".to_string(),
                    status: "active".to_string(),
                },
            )
            .await
            .expect("create tenant 1 用户应成功");

        // 跨租户 find_by_id：tenant 42 查不到 tenant 1 的用户（SQL 含 WHERE tenant_id = ?）
        let cross = repo.find_by_id(42, &user_1).await.unwrap();
        assert!(
            cross.is_none(),
            "tenant 42 不应查到 tenant 1 的用户（SQL 过滤生效）"
        );

        // 跨租户 find_by_id：tenant 1 查不到 tenant 42 的用户
        let cross = repo.find_by_id(1, &user_42).await.unwrap();
        assert!(
            cross.is_none(),
            "tenant 1 不应查到 tenant 42 的用户（SQL 过滤生效）"
        );

        // 跨租户 find_by_username：tenant 42 查不到 tenant 1 的 username
        let cross = repo.find_by_username(42, "tenant-1-user").await.unwrap();
        assert!(
            cross.is_none(),
            "tenant 42 不应查到 tenant 1 的 username（SQL 过滤生效）"
        );

        // list 按 tenant 隔离
        let list_42 = repo.list(42, 0, 100).await.unwrap();
        let list_1 = repo.list(1, 0, 100).await.unwrap();
        let ids_42: Vec<_> = list_42.iter().map(|u| u.id.clone()).collect();
        let ids_1: Vec<_> = list_1.iter().map(|u| u.id.clone()).collect();
        assert!(
            ids_42.contains(&user_42) && !ids_42.contains(&user_1),
            "tenant 42 list 应仅含本租户用户"
        );
        assert!(
            ids_1.contains(&user_1) && !ids_1.contains(&user_42),
            "tenant 1 list 应仅含本租户用户"
        );

        // 验证返回行的 tenant_id 字段正确
        let row_42 = repo.find_by_id(42, &user_42).await.unwrap().unwrap();
        assert_eq!(row_42.tenant_id, 42, "返回行 tenant_id 应为 42");
    }

    /// create 内部生成合法 UUID v4。
    ///
    /// 验证 Repository 内部生成 UUID v4 的行为：
    /// - 调用 create 不传 id
    /// - 返回值应为合法 UUID v4（parse_str 成功 + version == Random）
    #[tokio::test(flavor = "multi_thread")]
    async fn create_generates_valid_uuid_v4() {
        let pool = setup_db().await;
        let repo = DbnexusUserRepository::new(pool);

        let id = repo
            .create(
                42,
                NewUser {
                    username: "uuid-test".to_string(),
                    password_hash: "h".to_string(),
                    status: "active".to_string(),
                },
            )
            .await
            .expect("create 应成功并返回 UUID v4");

        let parsed = uuid::Uuid::parse_str(&id).expect("返回的 id 应为合法 UUID");
        assert_eq!(
            parsed.get_version(),
            Some(uuid::Version::Random),
            "返回的 id 应为 UUID v4，实际: {}",
            id
        );
    }
}
