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
                // 唯一约束冲突（全局主键 id_type+id_value）：按租户作用域回查归属——
                // 同租户冲突返回 Taken；他租户占用（或冲突行并发消失）返回中性
                // Registered（不向他租户泄露 by_user_id，渗透-租户隔离-标识符注册表-1）。
                // 无法识别冲突时 fail-loud 透传，不静默吞错
                let msg = format!("{}", e);
                if msg.contains("UNIQUE") || msg.contains("unique") || msg.contains("Duplicate") {
                    match self
                        .find_owner_in_tenant(tenant_id, id_type, id_value)
                        .await?
                    {
                        Some(by_user_id) => Ok(RegisterOutcome::Taken { by_user_id }),
                        None => {
                            // UNIQUE 命中但回查为空：冲突行并发消失，INSERT 实际未落库。
                            // 显性告警而非静默假成功（规则11）；中性 Registered 的
                            // 防跨租户泄露语义不变（渗透-租户隔离-标识符注册表-1）。
                            tracing::warn!(
                                id_type = %id_type,
                                "identifier register: unique conflict row vanished before tenant-scoped recheck, returning neutral Registered"
                            );
                            Ok(RegisterOutcome::Registered)
                        },
                    }
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

    async fn find_owner_in_tenant(
        &self,
        tenant_id: i64,
        id_type: &str,
        id_value: &str,
    ) -> GarrisonResult<Option<String>> {
        dao_session!(
            self.pool,
            "dao-app-user-identifier-find-owner-in-tenant",
            session,
            conn
        );
        // 租户谓词强制：跨租户命中一律 None（不泄露他租户归属）
        let sql = "SELECT user_id FROM app_user_identifier \
                   WHERE tenant_id = ? AND id_type = ? AND id_value = ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_str(id_type), v_str(id_value)],
        );
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            GarrisonError::Dao(format!(
                "dao-app-user-identifier-find-owner-in-tenant::{}",
                e
            ))
        })?;
        Ok(rows
            .first()
            .and_then(|r| r.try_get::<String>("", "user_id").ok()))
    }
}

#[cfg(all(test, feature = "db-sqlite"))]
mod tests {
    use super::*;
    use crate::dao::repository::sqlite::test_support::setup_db;

    /// 同租户冲突返回 Taken{by_user_id}（原语义保持，租户内归属可回显）。
    #[tokio::test(flavor = "multi_thread")]
    async fn register_same_tenant_conflict_returns_taken() {
        let pool = setup_db().await;
        let repo = DbnexusUserIdentifierRepository::new(pool);

        let first = repo
            .register(1, "email", "same@x.com", "user-a")
            .await
            .expect("首次注册应成功");
        assert_eq!(first, RegisterOutcome::Registered);

        let second = repo
            .register(1, "email", "same@x.com", "user-b")
            .await
            .expect("同租户冲突应走回查路径");
        assert_eq!(
            second,
            RegisterOutcome::Taken {
                by_user_id: "user-a".to_string()
            },
            "同租户冲突应携带同信任域内的占用者 user_id"
        );
    }

    /// 跨租户注册同名标识返回中性 Registered，不泄露他租户 user_id
    /// （渗透-租户隔离-标识符注册表-1 回归）。
    #[tokio::test(flavor = "multi_thread")]
    async fn register_cross_tenant_conflict_is_neutral_without_owner_leak() {
        let pool = setup_db().await;
        let repo = DbnexusUserIdentifierRepository::new(pool);

        // 租户 1 占用标识
        let first = repo
            .register(1, "email", "victim@mail.com", "user-tenant-A")
            .await
            .expect("租户 1 注册应成功");
        assert_eq!(first, RegisterOutcome::Registered);

        // 租户 2 注册同一标识：全局主键冲突 → 中性 Registered，不带 by_user_id
        let second = repo
            .register(2, "email", "victim@mail.com", "user-tenant-B")
            .await
            .expect("跨租户冲突应走中性路径而非错误");
        assert_eq!(
            second,
            RegisterOutcome::Registered,
            "跨租户命中必须返回中性「已注册」，不得回显他租户 user_id"
        );

        // 租户作用域回查：各自只见本租户归属
        let owner_t1 = repo
            .find_owner_in_tenant(1, "email", "victim@mail.com")
            .await
            .expect("租户 1 回查应成功");
        assert_eq!(owner_t1.as_deref(), Some("user-tenant-A"));
        let owner_t2 = repo
            .find_owner_in_tenant(2, "email", "victim@mail.com")
            .await
            .expect("租户 2 回查应成功");
        assert_eq!(
            owner_t2, None,
            "租户 2 的租户作用域回查不得看到租户 1 的归属"
        );
    }
}
