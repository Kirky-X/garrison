// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! DbnexusPasswordHistoryRepository 实现（app_password_history 表）。

use super::{v_i64, v_str, DbnexusPasswordHistoryRepository};
use crate::dao::dao_session;
use crate::dao::repository::{make_statement, PasswordHistoryRepository};
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use dbnexus::sea_orm::ConnectionTrait;
use dbnexus::DbPool;

impl DbnexusPasswordHistoryRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PasswordHistoryRepository for DbnexusPasswordHistoryRepository {
    async fn append(
        &self,
        tenant_id: i64,
        user_id: &str,
        password_hash: &str,
    ) -> GarrisonResult<()> {
        dao_session!(self.pool, "dao-app-password-history-append", session, conn);
        let sql =
            "INSERT INTO app_password_history (id, tenant_id, user_id, password_hash, created_at) \
                   VALUES (?, ?, ?, ?, ?)";
        let now = chrono::Utc::now().timestamp();
        let stmt = make_statement(
            conn,
            sql,
            vec![
                v_str(&uuid::Uuid::new_v4().to_string()),
                v_i64(tenant_id),
                v_str(user_id),
                v_str(password_hash),
                v_i64(now),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-password-history-append::{}", e)))?;
        Ok(())
    }

    async fn recent(
        &self,
        tenant_id: i64,
        user_id: &str,
        limit: u32,
    ) -> GarrisonResult<Vec<String>> {
        dao_session!(self.pool, "dao-app-password-history-recent", session, conn);
        let sql = "SELECT password_hash FROM app_password_history \
                   WHERE tenant_id = ? AND user_id = ? \
                   ORDER BY created_at DESC LIMIT ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_str(user_id), v_i64(limit as i64)],
        );
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-password-history-recent::{}", e)))?;
        Ok(rows
            .iter()
            .filter_map(|r| r.try_get::<String>("", "password_hash").ok())
            .collect())
    }
}
