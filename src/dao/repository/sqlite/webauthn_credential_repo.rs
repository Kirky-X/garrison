// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! DbnexusWebauthnCredentialRepository 实现（app_webauthn_credential 表）。

use super::{read_bool, v_bool, v_i64, v_opt_str, v_str, DbnexusWebauthnCredentialRepository};
use crate::dao::dao_session;
use crate::dao::repository::{
    make_statement, WebauthnBindOutcome, WebauthnCredentialRepository, WebauthnCredentialRow,
};
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use dbnexus::sea_orm::{ConnectionTrait, QueryResult};
use dbnexus::DbPool;

impl DbnexusWebauthnCredentialRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }

    /// 行结构解析：列缺失/类型不符显性报错，不静默吞错。
    fn parse_row(row: &QueryResult) -> GarrisonResult<WebauthnCredentialRow> {
        Ok(WebauthnCredentialRow {
            tenant_id: row.try_get::<i64>("", "tenant_id").map_err(|e| {
                GarrisonError::Dao(format!("dao-webauthn-credential-parse-tenant::{e}"))
            })?,
            user_id: row.try_get::<String>("", "user_id").map_err(|e| {
                GarrisonError::Dao(format!("dao-webauthn-credential-parse-user::{e}"))
            })?,
            credential_id: row.try_get::<String>("", "credential_id").map_err(|e| {
                GarrisonError::Dao(format!("dao-webauthn-credential-parse-cred-id::{e}"))
            })?,
            public_key: row.try_get::<String>("", "public_key").map_err(|e| {
                GarrisonError::Dao(format!("dao-webauthn-credential-parse-pk::{e}"))
            })?,
            sign_count: row
                .try_get::<i64>("", "sign_count")
                .map_err(|e| {
                    GarrisonError::Dao(format!("dao-webauthn-credential-parse-sign-count::{e}"))
                })
                .and_then(|v| {
                    u32::try_from(v).map_err(|e| {
                        GarrisonError::Dao(format!("dao-webauthn-credential-sign-count-range::{e}"))
                    })
                })?,
            backup_eligible: read_bool(row, "backup_eligible")?,
            backup_state: read_bool(row, "backup_state")?,
            attestation: row
                .try_get::<Option<String>>("", "attestation")
                .map_err(|e| {
                    GarrisonError::Dao(format!("dao-webauthn-credential-parse-attestation::{e}"))
                })?,
            created_at: row.try_get::<i64>("", "created_at").map_err(|e| {
                GarrisonError::Dao(format!("dao-webauthn-credential-parse-created::{e}"))
            })?,
            updated_at: row.try_get::<i64>("", "updated_at").map_err(|e| {
                GarrisonError::Dao(format!("dao-webauthn-credential-parse-updated::{e}"))
            })?,
        })
    }
}

#[async_trait]
impl WebauthnCredentialRepository for DbnexusWebauthnCredentialRepository {
    async fn create(&self, row: &WebauthnCredentialRow) -> GarrisonResult<WebauthnBindOutcome> {
        dao_session!(
            self.pool,
            "dao-app-webauthn-credential-create",
            session,
            conn
        );
        let sql = "INSERT INTO app_webauthn_credential \
                   (tenant_id, user_id, credential_id, public_key, sign_count, backup_eligible, backup_state, attestation, created_at, updated_at) \
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
        let stmt = make_statement(
            conn,
            sql,
            vec![
                v_i64(row.tenant_id),
                v_str(&row.user_id),
                v_str(&row.credential_id),
                v_str(&row.public_key),
                v_i64(row.sign_count as i64),
                v_bool(row.backup_eligible),
                v_bool(row.backup_state),
                v_opt_str(&row.attestation),
                v_i64(row.created_at),
                v_i64(row.updated_at),
            ],
        );
        match conn.execute_raw(stmt).await {
            Ok(_) => Ok(WebauthnBindOutcome::Bound),
            Err(e) => {
                // 唯一约束冲突（主键 tenant_id+credential_id）：回查归属返回
                // AlreadyBound（同登录标识注册语义）；无法识别冲突 fail-loud 透传。
                // 回查必须复用本调用已持有的连接——再取一条会话在并发/内存库
                // 场景下可能拿到另一连接（看不到本事务上下文）或加剧池占用
                let msg = format!("{}", e);
                if msg.contains("UNIQUE") || msg.contains("unique") || msg.contains("Duplicate") {
                    let lookup_sql = "SELECT tenant_id, user_id, credential_id, public_key, \
                                      sign_count, backup_eligible, backup_state, attestation, \
                                      created_at, updated_at \
                                      FROM app_webauthn_credential \
                                      WHERE tenant_id = ? AND credential_id = ?";
                    let stmt = make_statement(
                        conn,
                        lookup_sql,
                        vec![v_i64(row.tenant_id), v_str(&row.credential_id)],
                    );
                    let existing = conn
                        .query_one_raw(stmt)
                        .await
                        .map_err(|e| {
                            GarrisonError::Dao(format!(
                                "dao-app-webauthn-credential-conflict-lookup::{e}"
                            ))
                        })?
                        .map(|r| Self::parse_row(&r))
                        .transpose()?;
                    match existing {
                        Some(existing) => Ok(WebauthnBindOutcome::AlreadyBound {
                            by_user_id: existing.user_id,
                        }),
                        None => Err(GarrisonError::Dao(format!(
                            "dao-app-webauthn-credential-conflict-without-owner::{e}"
                        ))),
                    }
                } else {
                    Err(GarrisonError::Dao(format!(
                        "dao-app-webauthn-credential-insert::{e}"
                    )))
                }
            },
        }
    }

    async fn find_by_credential_id(
        &self,
        tenant_id: i64,
        credential_id: &str,
    ) -> GarrisonResult<Option<WebauthnCredentialRow>> {
        dao_session!(
            self.pool,
            "dao-app-webauthn-credential-find-by-id",
            session,
            conn
        );
        let sql = "SELECT tenant_id, user_id, credential_id, public_key, sign_count, backup_eligible, backup_state, attestation, created_at, updated_at \
                   FROM app_webauthn_credential WHERE tenant_id = ? AND credential_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(credential_id)]);
        let row = conn
            .query_one_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-webauthn-credential-query::{e}")))?;
        row.map(|r| Self::parse_row(&r)).transpose()
    }

    async fn list_by_user(
        &self,
        tenant_id: i64,
        user_id: &str,
    ) -> GarrisonResult<Vec<WebauthnCredentialRow>> {
        dao_session!(
            self.pool,
            "dao-app-webauthn-credential-list-by-user",
            session,
            conn
        );
        let sql = "SELECT tenant_id, user_id, credential_id, public_key, sign_count, backup_eligible, backup_state, attestation, created_at, updated_at \
                   FROM app_webauthn_credential WHERE tenant_id = ? AND user_id = ? ORDER BY created_at ASC";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(user_id)]);
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-webauthn-credential-list::{e}")))?;
        rows.iter().map(Self::parse_row).collect()
    }

    async fn update_authenticator_state(
        &self,
        tenant_id: i64,
        credential_id: &str,
        sign_count: u32,
        backup_eligible: bool,
        backup_state: bool,
    ) -> GarrisonResult<()> {
        dao_session!(
            self.pool,
            "dao-app-webauthn-credential-update-state",
            session,
            conn
        );
        let now = chrono::Utc::now().timestamp();
        // 单调 CAS（sign_count 只进不退）：并发 finish 读到相同落库值时，
        // 后写者不得把计数器回写倒退（克隆检测的落库基准不被倒退破坏）。
        // `OR ? = 0` 豁免计数器不支持型认证器（恒 0，只刷新 backup flags）。
        let sql = "UPDATE app_webauthn_credential \
                   SET sign_count = ?, backup_eligible = ?, backup_state = ?, updated_at = ? \
                   WHERE tenant_id = ? AND credential_id = ? \
                     AND (sign_count < ? OR ? = 0)";
        let stmt = make_statement(
            conn,
            sql,
            vec![
                v_i64(sign_count as i64),
                v_bool(backup_eligible),
                v_bool(backup_state),
                v_i64(now),
                v_i64(tenant_id),
                v_str(credential_id),
                v_i64(sign_count as i64),
                v_i64(sign_count as i64),
            ],
        );
        let result = conn
            .execute_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-webauthn-credential-update::{e}")))?;
        if result.rows_affected() == 0 {
            // 区分：行不存在（InvalidParam 既有语义） vs 计数回退（显性 Dao）。
            // 存在性探测复用本调用已持有的连接（嵌套会话在内存库多连接下
            // 会读到空库，见 create 冲突回查同款约束）
            let probe_sql = "SELECT COUNT(*) AS cnt FROM app_webauthn_credential \
                              WHERE tenant_id = ? AND credential_id = ?";
            let probe = make_statement(
                conn,
                probe_sql,
                vec![v_i64(tenant_id), v_str(credential_id)],
            );
            let row = conn
                .query_one_raw(probe)
                .await
                .map_err(|e| {
                    GarrisonError::Dao(format!("dao-app-webauthn-credential-update-probe::{e}"))
                })?
                .ok_or_else(|| {
                    GarrisonError::Dao(
                        "dao-app-webauthn-credential-update-probe-empty::".to_string(),
                    )
                })?;
            let exists: i64 = row.try_get("", "cnt").map_err(|e| {
                GarrisonError::Dao(format!(
                    "dao-app-webauthn-credential-update-probe-parse::{e}"
                ))
            })?;
            if exists == 0 {
                return Err(GarrisonError::InvalidParam(format!(
                    "dao-app-webauthn-credential-not-found::tenant_id={tenant_id}, credential_id={credential_id}"
                )));
            }
            return Err(GarrisonError::Dao(format!(
                "dao-app-webauthn-credential-sign-count-regression::refusing-to-move-counter-backwards::credential_id={credential_id}"
            )));
        }
        Ok(())
    }

    async fn delete(&self, tenant_id: i64, credential_id: &str) -> GarrisonResult<()> {
        dao_session!(
            self.pool,
            "dao-app-webauthn-credential-delete",
            session,
            conn
        );
        let sql = "DELETE FROM app_webauthn_credential WHERE tenant_id = ? AND credential_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(credential_id)]);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-webauthn-credential-delete::{e}")))?;
        Ok(())
    }
}

#[cfg(all(test, feature = "db-sqlite"))]
mod tests {
    use super::super::test_support::setup_db;
    use super::*;
    use crate::dao::repository::WebauthnBindOutcome;

    /// 构造凭据行。
    fn credential_row(
        tenant_id: i64,
        user_id: &str,
        credential_id: &str,
        sign_count: u32,
    ) -> WebauthnCredentialRow {
        WebauthnCredentialRow {
            tenant_id,
            user_id: user_id.to_string(),
            credential_id: credential_id.to_string(),
            public_key: r#"{"type_":"ES256","key":{}}"#.to_string(),
            sign_count,
            backup_eligible: false,
            backup_state: false,
            attestation: Some("none".to_string()),
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
        }
    }

    /// 绑定后按凭据 ID 可查回全字段（roundtrip）。
    #[tokio::test]
    async fn webauthn_bind_then_find_roundtrip() {
        let pool = setup_db().await;
        let repo = DbnexusWebauthnCredentialRepository::new(pool);
        let row = credential_row(1, "user-1", "cred-aaa", 0);

        let outcome = repo.create(&row).await.expect("首次绑定应成功");
        assert_eq!(outcome, WebauthnBindOutcome::Bound);

        let found = repo
            .find_by_credential_id(1, "cred-aaa")
            .await
            .expect("查询应成功")
            .expect("绑定后应可查回");
        assert_eq!(found, row, "查回行应与写入行全字段一致");
    }

    /// 同 credential_id 二次绑定（换 user）→ AlreadyBound{by_user_id}：
    /// 数据库唯一约束兜底 ExcludeCredentials 之外的并发窗口。
    #[tokio::test]
    async fn webauthn_duplicate_credential_id_reports_owner() {
        let pool = setup_db().await;
        let repo = DbnexusWebauthnCredentialRepository::new(pool);

        repo.create(&credential_row(1, "user-1", "cred-dup", 0))
            .await
            .expect("首次绑定应成功");

        let second = repo
            .create(&credential_row(1, "user-2", "cred-dup", 0))
            .await
            .expect("冲突查询不应报错");
        assert_eq!(
            second,
            WebauthnBindOutcome::AlreadyBound {
                by_user_id: "user-1".to_string()
            },
            "同凭据二次绑定应回查归属"
        );
    }

    /// list_by_user 租户隔离：同 user_id 跨 tenant 不串。
    #[tokio::test]
    async fn webauthn_list_by_user_tenant_isolated() {
        let pool = setup_db().await;
        let repo = DbnexusWebauthnCredentialRepository::new(pool);

        repo.create(&credential_row(1, "user-1", "cred-t1", 0))
            .await
            .expect("tenant 1 绑定应成功");
        repo.create(&credential_row(2, "user-1", "cred-t2", 0))
            .await
            .expect("tenant 2 绑定应成功");

        let t1 = repo
            .list_by_user(1, "user-1")
            .await
            .expect("tenant 1 列举应成功");
        let t2 = repo
            .list_by_user(2, "user-1")
            .await
            .expect("tenant 2 列举应成功");
        let ids_t1: Vec<_> = t1.iter().map(|r| r.credential_id.clone()).collect();
        let ids_t2: Vec<_> = t2.iter().map(|r| r.credential_id.clone()).collect();
        assert_eq!(
            ids_t1,
            vec!["cred-t1".to_string()],
            "tenant 1 仅见本租户凭据"
        );
        assert_eq!(
            ids_t2,
            vec!["cred-t2".to_string()],
            "tenant 2 仅见本租户凭据"
        );
    }

    /// update_authenticator_state 落库 sign_count 与 backup flags；
    /// 不存在的凭据显性报错（不静默）。
    #[tokio::test]
    async fn webauthn_update_authenticator_state_reflects_and_missing_is_explicit() {
        let pool = setup_db().await;
        let repo = DbnexusWebauthnCredentialRepository::new(pool);

        repo.create(&credential_row(1, "user-1", "cred-upd", 0))
            .await
            .expect("绑定应成功");

        repo.update_authenticator_state(1, "cred-upd", 7, true, true)
            .await
            .expect("更新应成功");

        let found = repo
            .find_by_credential_id(1, "cred-upd")
            .await
            .expect("查询应成功")
            .expect("更新后凭据应存在");
        assert_eq!(found.sign_count, 7, "sign_count 应更新为 7");
        assert!(found.backup_eligible, "backup_eligible 应更新为 true");
        assert!(found.backup_state, "backup_state 应更新为 true");

        let missing = repo
            .update_authenticator_state(1, "cred-nope", 1, false, false)
            .await;
        assert!(
            matches!(missing, Err(GarrisonError::InvalidParam(_))),
            "更新不存在的凭据必须显性报错，实际: {:?}",
            missing
        );
    }

    /// delete 幂等：删除后查不到；二次删除 Ok(())。
    #[tokio::test]
    async fn webauthn_delete_is_idempotent() {
        let pool = setup_db().await;
        let repo = DbnexusWebauthnCredentialRepository::new(pool);

        repo.create(&credential_row(1, "user-1", "cred-del", 0))
            .await
            .expect("绑定应成功");
        repo.delete(1, "cred-del").await.expect("首次删除应成功");

        let after = repo
            .find_by_credential_id(1, "cred-del")
            .await
            .expect("查询应成功");
        assert!(after.is_none(), "删除后凭据应不存在");

        repo.delete(1, "cred-del")
            .await
            .expect("二次删除应幂等成功");
    }
}
