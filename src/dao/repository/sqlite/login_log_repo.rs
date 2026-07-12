//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusLoginLogRepository 实现（app_login_log 表）。

use super::{read_bool, v_bool, v_i64, v_opt_str, v_str, DbnexusLoginLogRepository};
use crate::dao::repository::{make_statement, LoginLogRepository, LoginLogRow, NewLoginLog};
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, QueryResult};

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
