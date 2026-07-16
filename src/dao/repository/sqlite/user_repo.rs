//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusUserRepository 实现（app_user 表）。

use super::{v_i64, v_str, DbnexusUserRepository};
use crate::dao::repository::{make_statement, NewUser, UpdateUser, UserRepository, UserRow};
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, QueryResult};

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

#[cfg(all(test, feature = "db-sqlite"))]
mod tests {
    use super::*;
    use crate::dao::repository::sqlite::test_support::setup_db;

    /// create 插入用户后 find_by_id 应返回相同字段。
    #[tokio::test(flavor = "multi_thread")]
    async fn create_and_find_by_id_roundtrip() {
        let pool = setup_db().await;
        let repo = DbnexusUserRepository::new(pool);

        let id = repo
            .create(
                1,
                NewUser {
                    username: "alice".to_string(),
                    password_hash: "$argon2id$hash".to_string(),
                    status: "active".to_string(),
                },
            )
            .await
            .expect("create 应成功");

        let row = repo
            .find_by_id(1, &id)
            .await
            .expect("find_by_id 应成功")
            .expect("用户应存在");
        assert_eq!(row.id, id);
        assert_eq!(row.username, "alice");
        assert_eq!(row.password_hash, "$argon2id$hash");
        assert_eq!(row.status, "active");
        assert_eq!(row.tenant_id, 1);
        assert!(
            row.last_login_at.is_none(),
            "新用户 last_login_at 应为 None"
        );
    }

    /// find_by_id 查询不存在的 ID 应返回 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_id_returns_none_for_nonexistent() {
        let pool = setup_db().await;
        let repo = DbnexusUserRepository::new(pool);

        let result = repo
            .find_by_id(1, "nonexistent-uuid")
            .await
            .expect("find_by_id 应成功");
        assert!(result.is_none(), "不存在的 ID 应返回 None");
    }

    /// find_by_username 按 username 精确查询。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_username_returns_user() {
        let pool = setup_db().await;
        let repo = DbnexusUserRepository::new(pool);

        repo.create(
            1,
            NewUser {
                username: "bob".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .expect("create 应成功");

        let row = repo
            .find_by_username(1, "bob")
            .await
            .expect("find_by_username 应成功")
            .expect("用户应存在");
        assert_eq!(row.username, "bob");
    }

    /// find_by_username 查询不存在的用户名应返回 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_username_returns_none_for_nonexistent() {
        let pool = setup_db().await;
        let repo = DbnexusUserRepository::new(pool);

        let result = repo
            .find_by_username(1, "nonexistent-user")
            .await
            .expect("find_by_username 应成功");
        assert!(result.is_none(), "不存在的用户名应返回 None");
    }

    /// update 更新 username/password_hash/status/last_login_at 后查询应反映新值；全 None 时不更新。
    #[tokio::test(flavor = "multi_thread")]
    async fn update_changes_fields_and_noop_when_all_none() {
        let pool = setup_db().await;
        let repo = DbnexusUserRepository::new(pool);

        let id = repo
            .create(
                1,
                NewUser {
                    username: "old-name".to_string(),
                    password_hash: "old-hash".to_string(),
                    status: "active".to_string(),
                },
            )
            .await
            .expect("create 应成功");

        // 全 None 时应直接返回 Ok(()) 不执行 SQL
        repo.update(1, &id, UpdateUser::default())
            .await
            .expect("全 None update 应为 no-op");

        // 更新所有字段
        repo.update(
            1,
            &id,
            UpdateUser {
                username: Some("new-name".to_string()),
                password_hash: Some("new-hash".to_string()),
                status: Some("suspended".to_string()),
                last_login_at: Some("2026-07-14T00:00:00Z".to_string()),
            },
        )
        .await
        .expect("update 应成功");

        let row = repo
            .find_by_id(1, &id)
            .await
            .expect("find_by_id 应成功")
            .expect("用户应存在");
        assert_eq!(row.username, "new-name");
        assert_eq!(row.password_hash, "new-hash");
        assert_eq!(row.status, "suspended");
        assert_eq!(row.last_login_at.as_deref(), Some("2026-07-14T00:00:00Z"));
    }

    /// update 仅更新 status 字段。
    #[tokio::test(flavor = "multi_thread")]
    async fn update_partial_only_status() {
        let pool = setup_db().await;
        let repo = DbnexusUserRepository::new(pool);

        let id = repo
            .create(
                1,
                NewUser {
                    username: "partial-user".to_string(),
                    password_hash: "h".to_string(),
                    status: "active".to_string(),
                },
            )
            .await
            .expect("create 应成功");

        repo.update(
            1,
            &id,
            UpdateUser {
                status: Some("inactive".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("update 应成功");

        let row = repo
            .find_by_id(1, &id)
            .await
            .expect("find_by_id 应成功")
            .expect("用户应存在");
        assert_eq!(row.status, "inactive");
        assert_eq!(row.username, "partial-user", "username 不应变");
        assert_eq!(row.password_hash, "h", "password_hash 不应变");
    }

    /// update 仅更新 last_login_at。
    #[tokio::test(flavor = "multi_thread")]
    async fn update_partial_only_last_login_at() {
        let pool = setup_db().await;
        let repo = DbnexusUserRepository::new(pool);

        let id = repo
            .create(
                1,
                NewUser {
                    username: "login-user".to_string(),
                    password_hash: "h".to_string(),
                    status: "active".to_string(),
                },
            )
            .await
            .expect("create 应成功");

        repo.update(
            1,
            &id,
            UpdateUser {
                last_login_at: Some("2026-07-14T12:00:00Z".to_string()),
                ..Default::default()
            },
        )
        .await
        .expect("update 应成功");

        let row = repo
            .find_by_id(1, &id)
            .await
            .expect("find_by_id 应成功")
            .expect("用户应存在");
        assert_eq!(row.last_login_at.as_deref(), Some("2026-07-14T12:00:00Z"));
    }

    /// delete 删除后 find_by_id 返回 None；重复删除不报错（幂等）。
    #[tokio::test(flavor = "multi_thread")]
    async fn delete_is_idempotent() {
        let pool = setup_db().await;
        let repo = DbnexusUserRepository::new(pool);

        let id = repo
            .create(
                1,
                NewUser {
                    username: "temp-user".to_string(),
                    password_hash: "h".to_string(),
                    status: "active".to_string(),
                },
            )
            .await
            .expect("create 应成功");

        repo.delete(1, &id).await.expect("首次 delete 应成功");
        let after = repo.find_by_id(1, &id).await.expect("find_by_id 应成功");
        assert!(after.is_none(), "删除后应查不到");

        // 幂等：再次删除
        repo.delete(1, &id).await.expect("幂等 delete 应成功");
    }

    /// list 分页查询：插入 3 条记录后 offset/limit 正确分页。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_paginates_correctly() {
        let pool = setup_db().await;
        let repo = DbnexusUserRepository::new(pool);

        for i in 0..3 {
            repo.create(
                1,
                NewUser {
                    username: format!("user-{}", i),
                    password_hash: "h".to_string(),
                    status: "active".to_string(),
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

    /// find_by_username 跨租户查询应返回 None（同一 username 可在不同租户存在）。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_username_same_name_in_different_tenants() {
        let pool = setup_db().await;
        let repo = DbnexusUserRepository::new(pool);

        // tenant 1 创建 alice
        repo.create(
            1,
            NewUser {
                username: "shared-name".to_string(),
                password_hash: "h1".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .expect("create tenant 1 应成功");

        // tenant 2 也创建 alice（同一 username 不同租户可共存）
        repo.create(
            2,
            NewUser {
                username: "shared-name".to_string(),
                password_hash: "h2".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .expect("create tenant 2 应成功");

        let row_1 = repo
            .find_by_username(1, "shared-name")
            .await
            .expect("find tenant 1 应成功")
            .expect("tenant 1 应有该用户");
        let row_2 = repo
            .find_by_username(2, "shared-name")
            .await
            .expect("find tenant 2 应成功")
            .expect("tenant 2 应有该用户");
        assert_eq!(row_1.password_hash, "h1");
        assert_eq!(row_2.password_hash, "h2");
        assert_eq!(row_1.tenant_id, 1);
        assert_eq!(row_2.tenant_id, 2);
        assert_ne!(row_1.id, row_2.id, "不同租户的用户 ID 应不同");
    }

    /// list 按 tenant_id 隔离。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_filters_by_tenant_id() {
        let pool = setup_db().await;
        let repo = DbnexusUserRepository::new(pool);

        repo.create(
            1,
            NewUser {
                username: "t1-user".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
            },
        )
        .await
        .expect("create tenant 1 应成功");

        repo.create(
            2,
            NewUser {
                username: "t2-user".to_string(),
                password_hash: "h".to_string(),
                status: "active".to_string(),
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

    /// find_by_id 跨租户查询应返回 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_id_cross_tenant_returns_none() {
        let pool = setup_db().await;
        let repo = DbnexusUserRepository::new(pool);

        let id = repo
            .create(
                1,
                NewUser {
                    username: "cross-user".to_string(),
                    password_hash: "h".to_string(),
                    status: "active".to_string(),
                },
            )
            .await
            .expect("create 应成功");

        let cross = repo.find_by_id(2, &id).await.expect("find_by_id 应成功");
        assert!(cross.is_none(), "跨租户查询应返回 None");
    }
}
