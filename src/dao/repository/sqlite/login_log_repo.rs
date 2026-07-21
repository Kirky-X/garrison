//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusLoginLogRepository 实现（app_login_log 表）。

use super::{read_bool, v_bool, v_i64, v_opt_str, v_str, DbnexusLoginLogRepository};
use crate::dao::repository::{make_statement, LoginLogRepository, LoginLogRow, NewLoginLog};
use crate::error::{GarrisonError, GarrisonResult};
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
    async fn find_by_id(&self, tenant_id: i64, id: &str) -> GarrisonResult<Option<LoginLogRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            GarrisonError::Dao(format!("dao-app-login-log-find-by-id-session::{}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            GarrisonError::Dao(format!("dao-app-login-log-find-by-id-connection::{}", e))
        })?;
        let sql = "SELECT id, user_id, action, ip, device_id, success, fail_reason, create_time, tenant_id \
                   FROM app_login_log WHERE tenant_id = ? AND id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(id)]);
        let row = conn.query_one_raw(stmt).await.map_err(|e| {
            GarrisonError::Dao(format!("dao-app-login-log-find-by-id-query::{}", e))
        })?;
        row.map(|r| parse_login_log_row(&r)).transpose()
    }

    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
        offset: i64,
        limit: i64,
    ) -> GarrisonResult<Vec<LoginLogRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            GarrisonError::Dao(format!("dao-app-login-log-find-by-user-id-session::{}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            GarrisonError::Dao(format!(
                "dao-app-login-log-find-by-user-id-connection::{}",
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
            GarrisonError::Dao(format!("dao-app-login-log-find-by-user-id-query::{}", e))
        })?;
        rows.iter().map(parse_login_log_row).collect()
    }

    async fn create(&self, tenant_id: i64, log: NewLoginLog) -> GarrisonResult<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                GarrisonError::Dao(format!("dao-app-login-log-create-session::{}", e))
            })?;
        let conn = session.connection().map_err(|e| {
            GarrisonError::Dao(format!("dao-app-login-log-create-connection::{}", e))
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
            .map_err(|e| GarrisonError::Dao(format!("dao-app-login-log-create-insert::{}", e)))?;
        Ok(id)
    }

    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> GarrisonResult<Vec<LoginLogRow>> {
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                GarrisonError::Dao(format!("dao-app-login-log-list-session::{}", e))
            })?;
        let conn = session
            .connection()
            .map_err(|e| GarrisonError::Dao(format!("dao-app-login-log-list-connection::{}", e)))?;
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
            .map_err(|e| GarrisonError::Dao(format!("dao-app-login-log-list-query::{}", e)))?;
        rows.iter().map(parse_login_log_row).collect()
    }
}

/// 解析 app_login_log 行。
fn parse_login_log_row(row: &QueryResult) -> GarrisonResult<LoginLogRow> {
    Ok(LoginLogRow {
        id: row
            .try_get("", "id")
            .map_err(|e| GarrisonError::Dao(format!("dao-app-login-log-row-parse-id::{}", e)))?,
        user_id: row.try_get("", "user_id").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-login-log-row-parse-user-id::{}", e))
        })?,
        action: row.try_get("", "action").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-login-log-row-parse-action::{}", e))
        })?,
        ip: row
            .try_get("", "ip")
            .map_err(|e| GarrisonError::Dao(format!("dao-app-login-log-row-parse-ip::{}", e)))?,
        device_id: row.try_get("", "device_id").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-login-log-row-parse-device-id::{}", e))
        })?,
        success: read_bool(row, "success"),
        fail_reason: row.try_get("", "fail_reason").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-login-log-row-parse-fail-reason::{}", e))
        })?,
        create_time: row.try_get("", "create_time").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-login-log-row-parse-create-time::{}", e))
        })?,
        tenant_id: row.try_get("", "tenant_id").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-login-log-row-parse-tenant-id::{}", e))
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

    // ========================================================================
    // 错误路径测试：DROP TABLE 后查询/插入触发 SQL 错误，覆盖 map_err 闭包
    // ========================================================================

    /// 删除 app_login_log 表后 find_by_id 应返回 Dao 错误。
    ///
    /// 覆盖 find_by_id 中 query_one_raw 的 map_err 闭包（line 38）。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_id_returns_error_when_table_dropped() {
        let pool = setup_db().await;
        let repo = DbnexusLoginLogRepository::new(pool.clone());

        // 先删除表
        {
            let session = pool.get_session("admin").await.expect("获取 session 失败");
            let conn = session.connection().expect("获取 connection 失败");
            conn.execute_unprepared("DROP TABLE IF EXISTS app_login_log")
                .await
                .expect("DROP TABLE 失败");
        }

        let result = repo.find_by_id(1, "nonexistent").await;
        assert!(result.is_err(), "表删除后 find_by_id 应返回错误");
        match result {
            Err(GarrisonError::Dao(msg)) => {
                assert!(
                    msg.contains("dao-app-login-log-find-by-id-query"),
                    "错误消息应包含 'find_by_id 查询失败'，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 Dao 错误，实际: {:?}", other),
            Ok(_) => panic!("期望错误，实际返回 Ok"),
        }
    }

    /// 删除 app_login_log 表后 find_by_user_id 应返回 Dao 错误。
    ///
    /// 覆盖 find_by_user_id 中 query_all_raw 的 map_err 闭包（line 76）。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_user_id_returns_error_when_table_dropped() {
        let pool = setup_db().await;
        let repo = DbnexusLoginLogRepository::new(pool.clone());

        {
            let session = pool.get_session("admin").await.expect("获取 session 失败");
            let conn = session.connection().expect("获取 connection 失败");
            conn.execute_unprepared("DROP TABLE IF EXISTS app_login_log")
                .await
                .expect("DROP TABLE 失败");
        }

        let result = repo.find_by_user_id(1, "user-1", 0, 10).await;
        assert!(result.is_err(), "表删除后 find_by_user_id 应返回错误");
        match result {
            Err(GarrisonError::Dao(msg)) => {
                assert!(
                    msg.contains("dao-app-login-log-find-by-user-id-query"),
                    "错误消息应包含 'find_by_user_id 查询失败'，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 Dao 错误，实际: {:?}", other),
            Ok(_) => panic!("期望错误，实际返回 Ok"),
        }
    }

    /// 删除 app_login_log 表后 create 应返回 Dao 错误。
    ///
    /// 覆盖 create 中 execute_raw 的 map_err 闭包（line 107）。
    #[tokio::test(flavor = "multi_thread")]
    async fn create_returns_error_when_table_dropped() {
        let pool = setup_db().await;
        let repo = DbnexusLoginLogRepository::new(pool.clone());

        {
            let session = pool.get_session("admin").await.expect("获取 session 失败");
            let conn = session.connection().expect("获取 connection 失败");
            conn.execute_unprepared("DROP TABLE IF EXISTS app_login_log")
                .await
                .expect("DROP TABLE 失败");
        }

        let result = repo
            .create(
                1,
                NewLoginLog {
                    user_id: Some("u-1".to_string()),
                    action: "login".to_string(),
                    ip: None,
                    device_id: None,
                    success: true,
                    fail_reason: None,
                },
            )
            .await;
        assert!(result.is_err(), "表删除后 create 应返回错误");
        match result {
            Err(GarrisonError::Dao(msg)) => {
                assert!(
                    msg.contains("dao-app-login-log-create-insert"),
                    "错误消息应包含 'create 插入失败'，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 Dao 错误，实际: {:?}", other),
            Ok(_) => panic!("期望错误，实际返回 Ok"),
        }
    }

    /// 删除 app_login_log 表后 list 应返回 Dao 错误。
    ///
    /// 覆盖 list 中 query_all_raw 的 map_err 闭包（line 133）。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_returns_error_when_table_dropped() {
        let pool = setup_db().await;
        let repo = DbnexusLoginLogRepository::new(pool.clone());

        {
            let session = pool.get_session("admin").await.expect("获取 session 失败");
            let conn = session.connection().expect("获取 connection 失败");
            conn.execute_unprepared("DROP TABLE IF EXISTS app_login_log")
                .await
                .expect("DROP TABLE 失败");
        }

        let result = repo.list(1, 0, 10).await;
        assert!(result.is_err(), "表删除后 list 应返回错误");
        match result {
            Err(GarrisonError::Dao(msg)) => {
                assert!(
                    msg.contains("dao-app-login-log-list-query"),
                    "错误消息应包含 'list 查询失败'，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 Dao 错误，实际: {:?}", other),
            Ok(_) => panic!("期望错误，实际返回 Ok"),
        }
    }

    // ========================================================================
    // parse_login_log_row 错误路径测试：重建表缺少列触发 try_get 解析失败
    // ========================================================================

    /// 重建 app_login_log 表（action 列插入 NULL）后 find_by_id 应返回 Dao 解析错误。
    ///
    /// 覆盖 parse_login_log_row 中 try_get("action") 的 map_err 闭包：
    /// SQL 查询成功返回行，但 action 字段为 NULL 无法解析为 String（非 Option），触发 parse 错误路径。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_id_returns_error_when_column_missing() {
        let pool = setup_db().await;
        let repo = DbnexusLoginLogRepository::new(pool.clone());

        // 删除原表，重建包含所有列的表，但插入 action=NULL 触发 parse 错误
        {
            let session = pool.get_session("admin").await.expect("获取 session 失败");
            let conn = session.connection().expect("获取 connection 失败");
            conn.execute_unprepared("DROP TABLE IF EXISTS app_login_log")
                .await
                .expect("DROP TABLE 失败");
            // 重建包含所有 9 列的表（与原 schema 一致）
            conn.execute_unprepared(
                "CREATE TABLE app_login_log (\
                 id TEXT, user_id TEXT, action TEXT, ip TEXT, device_id TEXT, \
                 success INTEGER, fail_reason TEXT, create_time TEXT, tenant_id INTEGER)",
            )
            .await
            .expect("CREATE TABLE 失败");
            // 插入 action=NULL：WHERE tenant_id=1 AND id='test-id' 匹配，
            // 但 try_get::<String>("", "action") 在 NULL 上返回 Err，触发 parse 错误路径
            conn.execute_unprepared(
                "INSERT INTO app_login_log \
                 (id, user_id, action, ip, device_id, success, fail_reason, create_time, tenant_id) \
                 VALUES ('test-id', 'u-1', NULL, '127.0.0.1', 'dev-1', 1, NULL, '2026-07-14', 1)",
            )
            .await
            .expect("INSERT 失败");
        }

        let result = repo.find_by_id(1, "test-id").await;
        assert!(
            result.is_err(),
            "action=NULL 时 find_by_id 应返回解析错误，实际: {:?}",
            result
        );
        match result {
            Err(GarrisonError::Dao(msg)) => {
                // 应包含 action 字段解析失败的描述
                assert!(
                    msg.contains("dao-app-login-log-row-parse-action"),
                    "错误消息应包含 'app_login_log 行解析失败'，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 Dao 错误，实际: {:?}", other),
            Ok(_) => panic!("期望错误，实际返回 Ok"),
        }
    }

    /// find_by_id 查询不存在的 ID 返回 Ok(None)。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_id_returns_none_for_nonexistent() {
        let pool = setup_db().await;
        let repo = DbnexusLoginLogRepository::new(pool);

        let result = repo
            .find_by_id(1, "nonexistent-id")
            .await
            .expect("find_by_id 应成功");
        assert!(result.is_none(), "不存在的 ID 应返回 None");
    }

    /// find_by_user_id 查询不存在用户的日志返回空 Vec。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_user_id_returns_empty_for_nonexistent_user() {
        let pool = setup_db().await;
        let repo = DbnexusLoginLogRepository::new(pool);

        let result = repo
            .find_by_user_id(1, "nonexistent-user", 0, 10)
            .await
            .expect("find_by_user_id 应成功");
        assert!(result.is_empty(), "不存在用户的日志应为空 Vec");
    }

    /// list 查询空表返回空 Vec。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_returns_empty_for_empty_table() {
        let pool = setup_db().await;
        let repo = DbnexusLoginLogRepository::new(pool);

        let result = repo.list(1, 0, 10).await.expect("list 应成功");
        assert!(result.is_empty(), "空表应返回空 Vec");
    }

    /// find_by_user_id 跨租户查询返回空 Vec（tenant_id 隔离）。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_user_id_isolates_by_tenant() {
        let pool = setup_db().await;
        let repo = DbnexusLoginLogRepository::new(pool.clone());
        let user_1 = setup_user(&pool, 1).await;

        repo.create(
            1,
            NewLoginLog {
                user_id: Some(user_1.clone()),
                action: "login".to_string(),
                ip: None,
                device_id: None,
                success: true,
                fail_reason: None,
            },
        )
        .await
        .expect("create 应成功");

        // tenant 2 查询 tenant 1 的用户日志，应为空
        let result = repo
            .find_by_user_id(2, &user_1, 0, 10)
            .await
            .expect("find_by_user_id 应成功");
        assert!(result.is_empty(), "跨租户查询应返回空 Vec（tenant 隔离）");
    }

    /// create 返回的 ID 为合法 UUID v4。
    #[tokio::test(flavor = "multi_thread")]
    async fn create_returns_valid_uuid_v4() {
        let pool = setup_db().await;
        let repo = DbnexusLoginLogRepository::new(pool);

        let id = repo
            .create(
                1,
                NewLoginLog {
                    user_id: None,
                    action: "logout".to_string(),
                    ip: None,
                    device_id: None,
                    success: true,
                    fail_reason: None,
                },
            )
            .await
            .expect("create 应成功");

        let parsed = uuid::Uuid::parse_str(&id).expect("返回的 id 应为合法 UUID");
        assert_eq!(
            parsed.get_version(),
            Some(uuid::Version::Random),
            "返回的 id 应为 UUID v4"
        );
    }
}
