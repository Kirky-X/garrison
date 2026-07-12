//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusSessionRepository 实现（app_session 表）。

use super::{v_i64, v_opt_str, v_str, DbnexusSessionRepository};
use crate::dao::repository::{make_statement, NewSession, SessionRepository, SessionRow};
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, QueryResult};

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
