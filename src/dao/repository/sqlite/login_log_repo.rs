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

// ============================================================================
// 单元测试
// ============================================================================

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
                    username: format!("ll-user-{}", tenant_id),
                    password_hash: "h".to_string(),
                    status: "active".to_string(),
                },
            )
            .await
            .expect("创建 user 应成功")
    }

    /// create 成功登录日志后 find_by_id 应返回完整字段（含 success=true 的 bool 转换）。
    #[tokio::test(flavor = "multi_thread")]
    async fn create_success_log_and_find_by_id() {
        let pool = setup_db().await;
        let repo = DbnexusLoginLogRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        let id = repo
            .create(
                1,
                NewLoginLog {
                    user_id: Some(user_id.clone()),
                    action: "login".to_string(),
                    ip: Some("192.168.1.1".to_string()),
                    device_id: Some("dev-001".to_string()),
                    success: true,
                    fail_reason: None,
                },
            )
            .await
            .expect("create 应成功");

        let row = repo
            .find_by_id(1, &id)
            .await
            .expect("find_by_id 应成功")
            .expect("日志应存在");
        assert_eq!(row.id, id);
        assert_eq!(row.user_id.as_deref(), Some(user_id.as_str()));
        assert_eq!(row.action, "login");
        assert_eq!(row.ip.as_deref(), Some("192.168.1.1"));
        assert_eq!(row.device_id.as_deref(), Some("dev-001"));
        assert!(row.success, "success=true 应正确转换为 bool");
        assert!(row.fail_reason.is_none());
        assert_eq!(row.tenant_id, 1);
    }

    /// create 失败日志（user_id=None, success=false, fail_reason 有值）验证可空字段和 bool 转换。
    #[tokio::test(flavor = "multi_thread")]
    async fn create_failure_log_with_null_user() {
        let pool = setup_db().await;
        let repo = DbnexusLoginLogRepository::new(pool);

        let id = repo
            .create(
                1,
                NewLoginLog {
                    user_id: None,
                    action: "login".to_string(),
                    ip: Some("10.0.0.1".to_string()),
                    device_id: None,
                    success: false,
                    fail_reason: Some("密码错误".to_string()),
                },
            )
            .await
            .expect("create 应成功");

        let row = repo
            .find_by_id(1, &id)
            .await
            .expect("find_by_id 应成功")
            .expect("日志应存在");
        assert!(row.user_id.is_none(), "user_id 应为 None");
        assert!(!row.success, "success=false 应正确转换为 bool");
        assert_eq!(row.fail_reason.as_deref(), Some("密码错误"));
        assert!(row.device_id.is_none());
    }

    /// find_by_user_id 分页查询：插入 3 条日志后 offset/limit 正确分页。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_user_id_paginates() {
        let pool = setup_db().await;
        let repo = DbnexusLoginLogRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        for i in 0..3 {
            repo.create(
                1,
                NewLoginLog {
                    user_id: Some(user_id.clone()),
                    action: "login".to_string(),
                    ip: Some(format!("10.0.0.{}", i)),
                    device_id: None,
                    success: true,
                    fail_reason: None,
                },
            )
            .await
            .expect("create 应成功");
        }

        // 查询全部
        let all = repo
            .find_by_user_id(1, &user_id, 0, 100)
            .await
            .expect("find_by_user_id 应成功");
        assert_eq!(all.len(), 3, "应有 3 条日志");

        // 分页：limit=2, offset=0 返回前 2 条
        let first_page = repo
            .find_by_user_id(1, &user_id, 0, 2)
            .await
            .expect("find_by_user_id 分页应成功");
        assert_eq!(first_page.len(), 2, "第一页应返回 2 条");

        // 分页：limit=2, offset=2 返回第 3 条
        let second_page = repo
            .find_by_user_id(1, &user_id, 2, 2)
            .await
            .expect("find_by_user_id 分页应成功");
        assert_eq!(second_page.len(), 1, "第二页应返回 1 条");
    }

    /// list 按 tenant_id 隔离。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_filters_by_tenant_id() {
        let pool = setup_db().await;
        let repo = DbnexusLoginLogRepository::new(pool.clone());

        // tenant 1
        let user_1 = setup_user(&pool, 1).await;
        repo.create(
            1,
            NewLoginLog {
                user_id: Some(user_1),
                action: "login".to_string(),
                ip: None,
                device_id: None,
                success: true,
                fail_reason: None,
            },
        )
        .await
        .expect("create tenant 1 应成功");

        // tenant 2
        let user_2 = setup_user(&pool, 2).await;
        repo.create(
            2,
            NewLoginLog {
                user_id: Some(user_2),
                action: "login".to_string(),
                ip: None,
                device_id: None,
                success: true,
                fail_reason: None,
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
}
