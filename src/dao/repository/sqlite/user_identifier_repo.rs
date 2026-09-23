// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! DbnexusUserIdentifierRepository 实现（app_user_identifier 表）。

use super::{v_i64, v_str, DbnexusUserIdentifierRepository};
use crate::dao::dao_session;
use crate::dao::repository::{make_statement, RegisterOutcome, UserIdentifierRepository};
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use dbnexus::sea_orm::ConnectionTrait;
use dbnexus::DbPool;

impl DbnexusUserIdentifierRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserIdentifierRepository for DbnexusUserIdentifierRepository {
    async fn register(
        &self,
        tenant_id: i64,
        id_type: &str,
        id_value: &str,
        user_id: &str,
    ) -> GarrisonResult<RegisterOutcome> {
        dao_session!(self.pool, "dao-app-user-identifier-register", session, conn);
        let sql = "INSERT INTO app_user_identifier (id_type, id_value, tenant_id, user_id) \
                   VALUES (?, ?, ?, ?)";
        let stmt = make_statement(
            conn,
            sql,
            vec![
                v_str(id_type),
                v_str(id_value),
                v_i64(tenant_id),
                v_str(user_id),
            ],
        );
        match conn.execute_raw(stmt).await {
            Ok(_) => Ok(RegisterOutcome::Registered),
            Err(e) => {
                // 唯一约束冲突（主键 id_type+id_value）：回查归属返回 Taken；
                // 无法识别冲突时 fail-loud 透传，不静默吞错
                let msg = format!("{}", e);
                if msg.contains("UNIQUE") || msg.contains("unique") || msg.contains("Duplicate") {
                    self.find_owner(id_type, id_value)
                        .await?
                        .map(|by_user_id| RegisterOutcome::Taken { by_user_id })
                        .ok_or_else(|| {
                            GarrisonError::Dao(format!(
                                "dao-app-user-identifier-register-conflict-gone::{}",
                                e
                            ))
                        })
                } else {
                    Err(GarrisonError::Dao(format!(
                        "dao-app-user-identifier-register::{}",
                        e
                    )))
                }
            },
        }
    }

    async fn find_owner(&self, id_type: &str, id_value: &str) -> GarrisonResult<Option<String>> {
        dao_session!(
            self.pool,
            "dao-app-user-identifier-find-owner",
            session,
            conn
        );
        let sql = "SELECT user_id FROM app_user_identifier \
                   WHERE id_type = ? AND id_value = ?";
        let stmt = make_statement(conn, sql, vec![v_str(id_type), v_str(id_value)]);
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-identifier-find-owner::{}", e))
        })?;
        Ok(rows
            .first()
            .and_then(|r| r.try_get::<String>("", "user_id").ok()))
    }
}
