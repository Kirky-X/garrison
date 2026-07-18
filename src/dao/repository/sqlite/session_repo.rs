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
            BulwarkError::Dao(format!("dao-app-session-find-by-session-id-query::{}", e))
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
            BulwarkError::Dao(format!("dao-app-session-find-by-user-id-query::{}", e))
        })?;
        rows.iter().map(parse_session_row).collect()
    }

    async fn create(&self, tenant_id: i64, session: NewSession) -> BulwarkResult<String> {
        let db_session = self
            .pool
            .get_session("admin")
            .await
            .map_err(|e| BulwarkError::Dao(format!("dao-app-session-create-session::{}", e)))?;
        let conn = db_session
            .connection()
            .map_err(|e| BulwarkError::Dao(format!("dao-app-session-create-connection::{}", e)))?;
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
            .map_err(|e| BulwarkError::Dao(format!("dao-app-session-create-insert::{}", e)))?;
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
            BulwarkError::Dao(format!("dao-app-session-update-last-active-update::{}", e))
        })?;
        Ok(())
    }

    async fn delete(&self, tenant_id: i64, session_id: &str) -> BulwarkResult<()> {
        let session = self
            .pool
            .get_session("admin")
            .await
            .map_err(|e| BulwarkError::Dao(format!("dao-app-session-delete-session::{}", e)))?;
        let conn = session
            .connection()
            .map_err(|e| BulwarkError::Dao(format!("dao-app-session-delete-connection::{}", e)))?;
        let sql = "DELETE FROM app_session WHERE tenant_id = ? AND session_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(session_id)]);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("dao-app-session-delete-delete::{}", e)))?;
        Ok(())
    }

    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> BulwarkResult<Vec<SessionRow>> {
        let session = self
            .pool
            .get_session("admin")
            .await
            .map_err(|e| BulwarkError::Dao(format!("dao-app-session-list-session::{}", e)))?;
        let conn = session
            .connection()
            .map_err(|e| BulwarkError::Dao(format!("dao-app-session-list-connection::{}", e)))?;
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
            .map_err(|e| BulwarkError::Dao(format!("dao-app-session-list-query::{}", e)))?;
        rows.iter().map(parse_session_row).collect()
    }
}

/// 解析 app_session 行。
fn parse_session_row(row: &QueryResult) -> BulwarkResult<SessionRow> {
    Ok(SessionRow {
        session_id: row.try_get("", "session_id").map_err(|e| {
            BulwarkError::Dao(format!("dao-app-session-row-parse-session-id::{}", e))
        })?,
        user_id: row
            .try_get("", "user_id")
            .map_err(|e| BulwarkError::Dao(format!("dao-app-session-row-parse-user-id::{}", e)))?,
        device_id: row.try_get("", "device_id").map_err(|e| {
            BulwarkError::Dao(format!("dao-app-session-row-parse-device-id::{}", e))
        })?,
        ip: row
            .try_get("", "ip")
            .map_err(|e| BulwarkError::Dao(format!("dao-app-session-row-parse-ip::{}", e)))?,
        user_agent: row.try_get("", "user_agent").map_err(|e| {
            BulwarkError::Dao(format!("dao-app-session-row-parse-user-agent::{}", e))
        })?,
        login_time: row.try_get("", "login_time").map_err(|e| {
            BulwarkError::Dao(format!("dao-app-session-row-parse-login-time::{}", e))
        })?,
        last_active: row.try_get("", "last_active").map_err(|e| {
            BulwarkError::Dao(format!("dao-app-session-row-parse-last-active::{}", e))
        })?,
        expire_time: row.try_get("", "expire_time").map_err(|e| {
            BulwarkError::Dao(format!("dao-app-session-row-parse-expire-time::{}", e))
        })?,
        tenant_id: row.try_get("", "tenant_id").map_err(|e| {
            BulwarkError::Dao(format!("dao-app-session-row-parse-tenant-id::{}", e))
        })?,
    })
}

#[cfg(all(test, feature = "db-sqlite"))]
mod tests {
    use super::super::DbnexusUserRepository;
    use super::*;
    use crate::dao::repository::sqlite::test_support::setup_db;
    use crate::dao::repository::{NewUser, UserRepository};

    /// 在指定 tenant 创建 1 个 user，返回 user_id。
    async fn setup_user(pool: &DbPool, tenant_id: i64) -> String {
        let user_repo = DbnexusUserRepository::new(pool.clone());
        user_repo
            .create(
                tenant_id,
                NewUser {
                    username: format!("sess-user-{}", tenant_id),
                    password_hash: "h".to_string(),
                    status: "active".to_string(),
                },
            )
            .await
            .expect("创建 user 应成功")
    }

    /// create 插入会话后 find_by_session_id 应返回相同字段（含可选字段）。
    #[tokio::test(flavor = "multi_thread")]
    async fn create_and_find_by_session_id_roundtrip() {
        let pool = setup_db().await;
        let repo = DbnexusSessionRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        let session_id = repo
            .create(
                1,
                NewSession {
                    session_id: "sess-001".to_string(),
                    user_id: user_id.clone(),
                    device_id: Some("web".to_string()),
                    ip: Some("127.0.0.1".to_string()),
                    user_agent: Some("Mozilla/5.0".to_string()),
                    expire_time: Some("2026-12-31T00:00:00Z".to_string()),
                },
            )
            .await
            .expect("create 应成功");

        let row = repo
            .find_by_session_id(1, &session_id)
            .await
            .expect("find_by_session_id 应成功")
            .expect("会话应存在");
        assert_eq!(row.session_id, "sess-001");
        assert_eq!(row.user_id, user_id);
        assert_eq!(row.device_id.as_deref(), Some("web"));
        assert_eq!(row.ip.as_deref(), Some("127.0.0.1"));
        assert_eq!(row.user_agent.as_deref(), Some("Mozilla/5.0"));
        assert_eq!(row.expire_time.as_deref(), Some("2026-12-31T00:00:00Z"));
        assert_eq!(row.tenant_id, 1);
    }

    /// find_by_session_id 查询不存在的 session_id 应返回 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_session_id_returns_none_for_nonexistent() {
        let pool = setup_db().await;
        let repo = DbnexusSessionRepository::new(pool);

        let result = repo
            .find_by_session_id(1, "nonexistent-session")
            .await
            .expect("find_by_session_id 应成功");
        assert!(result.is_none(), "不存在的 session_id 应返回 None");
    }

    /// create 时可选字段全为 None 也能正确插入和查询。
    #[tokio::test(flavor = "multi_thread")]
    async fn create_with_all_optional_fields_none() {
        let pool = setup_db().await;
        let repo = DbnexusSessionRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        let session_id = repo
            .create(
                1,
                NewSession {
                    session_id: "sess-minimal".to_string(),
                    user_id: user_id.clone(),
                    device_id: None,
                    ip: None,
                    user_agent: None,
                    expire_time: None,
                },
            )
            .await
            .expect("create 应成功");

        let row = repo
            .find_by_session_id(1, &session_id)
            .await
            .expect("find_by_session_id 应成功")
            .expect("会话应存在");
        assert!(row.device_id.is_none());
        assert!(row.ip.is_none());
        assert!(row.user_agent.is_none());
        assert!(row.expire_time.is_none());
    }

    /// find_by_user_id 返回同一用户的所有会话。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_user_id_returns_all_sessions() {
        let pool = setup_db().await;
        let repo = DbnexusSessionRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        // 为同一用户创建 3 个会话
        for i in 0..3 {
            repo.create(
                1,
                NewSession {
                    session_id: format!("sess-{}", i),
                    user_id: user_id.clone(),
                    device_id: None,
                    ip: None,
                    user_agent: None,
                    expire_time: None,
                },
            )
            .await
            .expect("create 应成功");
        }

        let rows = repo
            .find_by_user_id(1, &user_id)
            .await
            .expect("find_by_user_id 应成功");
        assert_eq!(rows.len(), 3, "应有 3 个会话");
        assert!(rows.iter().all(|r| r.user_id == user_id));
    }

    /// find_by_user_id 查询无会话的用户应返回空列表。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_user_id_returns_empty_for_no_sessions() {
        let pool = setup_db().await;
        let repo = DbnexusSessionRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        let rows = repo
            .find_by_user_id(1, &user_id)
            .await
            .expect("find_by_user_id 应成功");
        assert!(rows.is_empty(), "无会话的用户应返回空列表");
    }

    /// update_last_active 更新最后活跃时间后 last_active 字段应变化。
    #[tokio::test(flavor = "multi_thread")]
    async fn update_last_active_changes_timestamp() {
        let pool = setup_db().await;
        let repo = DbnexusSessionRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        let session_id = repo
            .create(
                1,
                NewSession {
                    session_id: "sess-active".to_string(),
                    user_id,
                    device_id: None,
                    ip: None,
                    user_agent: None,
                    expire_time: None,
                },
            )
            .await
            .expect("create 应成功");

        let before = repo
            .find_by_session_id(1, &session_id)
            .await
            .expect("find 应成功")
            .expect("会话应存在");

        // 等待 1 秒确保时间戳不同
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        repo.update_last_active(1, &session_id)
            .await
            .expect("update_last_active 应成功");

        let after = repo
            .find_by_session_id(1, &session_id)
            .await
            .expect("find 应成功")
            .expect("会话应存在");

        assert_ne!(
            before.last_active, after.last_active,
            "update_last_active 后 last_active 应变化"
        );
    }

    /// update_last_active 对不存在的 session_id 不报错（幂等）。
    #[tokio::test(flavor = "multi_thread")]
    async fn update_last_active_nonexistent_is_noop() {
        let pool = setup_db().await;
        let repo = DbnexusSessionRepository::new(pool);

        repo.update_last_active(1, "nonexistent-session")
            .await
            .expect("对不存在的 session update_last_active 应为 no-op");
    }

    /// delete 删除后 find_by_session_id 返回 None；重复删除不报错（幂等）。
    #[tokio::test(flavor = "multi_thread")]
    async fn delete_is_idempotent() {
        let pool = setup_db().await;
        let repo = DbnexusSessionRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        let session_id = repo
            .create(
                1,
                NewSession {
                    session_id: "sess-del".to_string(),
                    user_id,
                    device_id: None,
                    ip: None,
                    user_agent: None,
                    expire_time: None,
                },
            )
            .await
            .expect("create 应成功");

        repo.delete(1, &session_id)
            .await
            .expect("首次 delete 应成功");
        let after = repo
            .find_by_session_id(1, &session_id)
            .await
            .expect("find 应成功");
        assert!(after.is_none(), "删除后应查不到");

        // 幂等：再次删除
        repo.delete(1, &session_id)
            .await
            .expect("幂等 delete 应成功");
    }

    /// list 分页查询：插入 3 条记录后 offset/limit 正确分页。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_paginates_correctly() {
        let pool = setup_db().await;
        let repo = DbnexusSessionRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        for i in 0..3 {
            repo.create(
                1,
                NewSession {
                    session_id: format!("sess-page-{}", i),
                    user_id: user_id.clone(),
                    device_id: None,
                    ip: None,
                    user_agent: None,
                    expire_time: None,
                },
            )
            .await
            .expect("create 应成功");
        }

        let all = repo.list(1, 0, 100).await.expect("list 应成功");
        assert_eq!(all.len(), 3, "应有 3 条记录");

        let page = repo.list(1, 1, 1).await.expect("list 分页应成功");
        assert_eq!(page.len(), 1, "分页应返回 1 条");

        let empty = repo.list(1, 100, 10).await.expect("list 超范围应成功");
        assert!(empty.is_empty(), "超出范围的 offset 应返回空");
    }

    /// list 按 tenant_id 隔离：不同租户的会话互不干扰。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_filters_by_tenant_id() {
        let pool = setup_db().await;
        let repo = DbnexusSessionRepository::new(pool.clone());

        let user_1 = setup_user(&pool, 1).await;
        repo.create(
            1,
            NewSession {
                session_id: "sess-t1".to_string(),
                user_id: user_1,
                device_id: None,
                ip: None,
                user_agent: None,
                expire_time: None,
            },
        )
        .await
        .expect("create tenant 1 应成功");

        let user_2 = setup_user(&pool, 2).await;
        repo.create(
            2,
            NewSession {
                session_id: "sess-t2".to_string(),
                user_id: user_2,
                device_id: None,
                ip: None,
                user_agent: None,
                expire_time: None,
            },
        )
        .await
        .expect("create tenant 2 应成功");

        let list_1 = repo.list(1, 0, 100).await.expect("list tenant 1 应成功");
        let list_2 = repo.list(2, 0, 100).await.expect("list tenant 2 应成功");
        assert_eq!(list_1.len(), 1, "tenant 1 应有 1 条");
        assert_eq!(list_2.len(), 1, "tenant 2 应有 1 条");
        assert_eq!(list_1[0].tenant_id, 1);
        assert_eq!(list_2[0].tenant_id, 2);
    }

    /// find_by_session_id 跨租户查询应返回 None（tenant_id 过滤生效）。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_session_id_cross_tenant_returns_none() {
        let pool = setup_db().await;
        let repo = DbnexusSessionRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        let session_id = repo
            .create(
                1,
                NewSession {
                    session_id: "sess-cross".to_string(),
                    user_id,
                    device_id: None,
                    ip: None,
                    user_agent: None,
                    expire_time: None,
                },
            )
            .await
            .expect("create 应成功");

        // 用 tenant 2 查询 tenant 1 的会话应返回 None
        let cross = repo
            .find_by_session_id(2, &session_id)
            .await
            .expect("find_by_session_id 应成功");
        assert!(cross.is_none(), "跨租户查询应返回 None");
    }
}
