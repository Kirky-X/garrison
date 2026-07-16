//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusUserRoleRepository 实现（app_user_role 表）。

use super::{v_i64, v_opt_str, v_str, DbnexusUserRoleRepository};
use crate::dao::repository::{make_statement, UserRoleRepository, UserRoleRow};
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, QueryResult};

impl DbnexusUserRoleRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserRoleRepository for DbnexusUserRoleRepository {
    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
    ) -> BulwarkResult<Vec<UserRoleRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_role find_by_user_id 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_role find_by_user_id 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT user_id, role_id, scope, grant_time, tenant_id \
                   FROM app_user_role WHERE tenant_id = ? AND user_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(user_id)]);
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_role find_by_user_id 查询失败: {}", e))
        })?;
        rows.iter().map(parse_user_role_row).collect()
    }

    async fn find_by_role_id(
        &self,
        tenant_id: i64,
        role_id: &str,
    ) -> BulwarkResult<Vec<UserRoleRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_role find_by_role_id 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_user_role find_by_role_id 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT user_id, role_id, scope, grant_time, tenant_id \
                   FROM app_user_role WHERE tenant_id = ? AND role_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(role_id)]);
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_role find_by_role_id 查询失败: {}", e))
        })?;
        rows.iter().map(parse_user_role_row).collect()
    }

    async fn assign(
        &self,
        tenant_id: i64,
        user_id: &str,
        role_id: &str,
        scope: Option<String>,
    ) -> BulwarkResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_role assign 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_user_role assign 获取 connection 失败: {}", e))
        })?;
        let sql = "INSERT INTO app_user_role (user_id, role_id, scope, tenant_id) \
                   VALUES (?, ?, ?, ?)";
        let stmt = make_statement(
            conn,
            sql,
            vec![
                v_str(user_id),
                v_str(role_id),
                v_opt_str(&scope),
                v_i64(tenant_id),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_role assign 插入失败: {}", e)))?;
        Ok(())
    }

    async fn revoke(&self, tenant_id: i64, user_id: &str, role_id: &str) -> BulwarkResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_role revoke 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_user_role revoke 获取 connection 失败: {}", e))
        })?;
        let sql = "DELETE FROM app_user_role WHERE tenant_id = ? AND user_id = ? AND role_id = ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_str(user_id), v_str(role_id)],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_role revoke 删除失败: {}", e)))?;
        Ok(())
    }

    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> BulwarkResult<Vec<UserRoleRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_user_role list 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("app_user_role list 获取 connection 失败: {}", e))
        })?;
        let sql = "SELECT user_id, role_id, scope, grant_time, tenant_id \
                   FROM app_user_role WHERE tenant_id = ? LIMIT ? OFFSET ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_i64(limit), v_i64(offset)],
        );
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_user_role list 查询失败: {}", e)))?;
        rows.iter().map(parse_user_role_row).collect()
    }
}

/// 解析 app_user_role 行。
fn parse_user_role_row(row: &QueryResult) -> BulwarkResult<UserRoleRow> {
    Ok(UserRoleRow {
        user_id: row
            .try_get("", "user_id")
            .map_err(|e| BulwarkError::Dao(format!("app_user_role 行解析失败 (user_id): {}", e)))?,
        role_id: row
            .try_get("", "role_id")
            .map_err(|e| BulwarkError::Dao(format!("app_user_role 行解析失败 (role_id): {}", e)))?,
        scope: row
            .try_get("", "scope")
            .map_err(|e| BulwarkError::Dao(format!("app_user_role 行解析失败 (scope): {}", e)))?,
        grant_time: row.try_get("", "grant_time").map_err(|e| {
            BulwarkError::Dao(format!("app_user_role 行解析失败 (grant_time): {}", e))
        })?,
        tenant_id: row.try_get("", "tenant_id").map_err(|e| {
            BulwarkError::Dao(format!("app_user_role 行解析失败 (tenant_id): {}", e))
        })?,
    })
}

#[cfg(all(test, feature = "db-sqlite"))]
mod tests {
    use super::super::{DbnexusRoleRepository, DbnexusUserRepository};
    use super::*;
    use crate::dao::repository::sqlite::test_support::setup_db;
    use crate::dao::repository::{NewRole, NewUser, RoleRepository, UserRepository};

    /// 创建辅助：在 tenant 1 中创建 1 个 user + 1 个 role，返回 (user_id, role_id)。
    async fn setup_user_and_role(pool: &DbPool, tenant_id: i64) -> (String, String) {
        let user_repo = DbnexusUserRepository::new(pool.clone());
        let role_repo = DbnexusRoleRepository::new(pool.clone());
        let user_id = user_repo
            .create(
                tenant_id,
                NewUser {
                    username: format!("ur-user-{}", tenant_id),
                    password_hash: "h".to_string(),
                    status: "active".to_string(),
                },
            )
            .await
            .expect("创建 user 应成功");
        let role_id = role_repo
            .create(
                tenant_id,
                NewRole {
                    code: format!("ur-role-{}", tenant_id),
                    name: "测试角色".to_string(),
                    description: None,
                    is_system: false,
                },
            )
            .await
            .expect("创建 role 应成功");
        (user_id, role_id)
    }

    /// assign 分配角色后 find_by_user_id 应返回关联记录（含 scope 字段）。
    #[tokio::test(flavor = "multi_thread")]
    async fn assign_and_find_by_user_id() {
        let pool = setup_db().await;
        let repo = DbnexusUserRoleRepository::new(pool.clone());
        let (user_id, role_id) = setup_user_and_role(&pool, 1).await;

        repo.assign(1, &user_id, &role_id, Some("read".to_string()))
            .await
            .expect("assign 应成功");

        let rows = repo
            .find_by_user_id(1, &user_id)
            .await
            .expect("find_by_user_id 应成功");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].user_id, user_id);
        assert_eq!(rows[0].role_id, role_id);
        assert_eq!(rows[0].scope.as_deref(), Some("read"));
        assert_eq!(rows[0].tenant_id, 1);
    }

    /// find_by_role_id 查询同一角色下的所有用户关联。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_role_id_returns_all_assignments() {
        let pool = setup_db().await;
        let repo = DbnexusUserRoleRepository::new(pool.clone());
        let role_repo = DbnexusRoleRepository::new(pool.clone());
        let user_repo = DbnexusUserRepository::new(pool.clone());

        let role_id = role_repo
            .create(
                1,
                NewRole {
                    code: "shared-role".to_string(),
                    name: "共享角色".to_string(),
                    description: None,
                    is_system: false,
                },
            )
            .await
            .expect("创建 role 应成功");

        // 为同一角色分配 2 个用户
        for i in 0..2 {
            let user_id = user_repo
                .create(
                    1,
                    NewUser {
                        username: format!("rbu-{}", i),
                        password_hash: "h".to_string(),
                        status: "active".to_string(),
                    },
                )
                .await
                .expect("创建 user 应成功");
            repo.assign(1, &user_id, &role_id, None)
                .await
                .expect("assign 应成功");
        }

        let rows = repo
            .find_by_role_id(1, &role_id)
            .await
            .expect("find_by_role_id 应成功");
        assert_eq!(rows.len(), 2, "应有 2 条关联记录");
        assert!(rows.iter().all(|r| r.role_id == role_id));
    }

    /// revoke 撤销角色后 find_by_user_id 返回空列表；重复 revoke 不报错。
    #[tokio::test(flavor = "multi_thread")]
    async fn revoke_is_idempotent() {
        let pool = setup_db().await;
        let repo = DbnexusUserRoleRepository::new(pool.clone());
        let (user_id, role_id) = setup_user_and_role(&pool, 1).await;

        repo.assign(1, &user_id, &role_id, None)
            .await
            .expect("assign 应成功");
        repo.revoke(1, &user_id, &role_id)
            .await
            .expect("首次 revoke 应成功");

        let rows = repo
            .find_by_user_id(1, &user_id)
            .await
            .expect("find_by_user_id 应成功");
        assert!(rows.is_empty(), "revoke 后应查不到关联");

        // 幂等：再次 revoke 不报错
        repo.revoke(1, &user_id, &role_id)
            .await
            .expect("幂等 revoke 应成功");
    }

    /// list 按 tenant_id 隔离：不同租户的关联记录互不干扰。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_filters_by_tenant_id() {
        let pool = setup_db().await;
        let repo = DbnexusUserRoleRepository::new(pool.clone());

        // tenant 1 分配 1 条
        let (user_1, role_1) = setup_user_and_role(&pool, 1).await;
        repo.assign(1, &user_1, &role_1, None)
            .await
            .expect("assign tenant 1 应成功");

        // tenant 2 分配 1 条
        let (user_2, role_2) = setup_user_and_role(&pool, 2).await;
        repo.assign(2, &user_2, &role_2, None)
            .await
            .expect("assign tenant 2 应成功");

        let list_1 = repo.list(1, 0, 100).await.expect("list tenant 1 应成功");
        let list_2 = repo.list(2, 0, 100).await.expect("list tenant 2 应成功");
        assert_eq!(list_1.len(), 1, "tenant 1 应有 1 条");
        assert_eq!(list_2.len(), 1, "tenant 2 应有 1 条");
        assert_eq!(list_1[0].tenant_id, 1);
        assert_eq!(list_2[0].tenant_id, 2);
    }

    /// assign 同一 user+role 组合两次应因主键约束失败（Dao 错误）。
    #[tokio::test(flavor = "multi_thread")]
    async fn assign_duplicate_pair_returns_error() {
        let pool = setup_db().await;
        let repo = DbnexusUserRoleRepository::new(pool.clone());
        let (user_id, role_id) = setup_user_and_role(&pool, 1).await;

        repo.assign(1, &user_id, &role_id, None)
            .await
            .expect("首次 assign 应成功");

        // 第二次 assign 同一组合应失败（复合主键冲突）
        let result = repo.assign(1, &user_id, &role_id, None).await;
        assert!(result.is_err(), "重复 assign 应返回错误");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("app_user_role") || err_msg.contains("UNIQUE"),
            "错误信息应包含表名或约束信息，实际: {}",
            err_msg
        );
    }

    /// find_by_user_id 查询无角色关联的用户应返回空列表。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_user_id_returns_empty_for_no_roles() {
        let pool = setup_db().await;
        let repo = DbnexusUserRoleRepository::new(pool.clone());
        let (user_id, _) = setup_user_and_role(&pool, 1).await;

        let rows = repo
            .find_by_user_id(1, &user_id)
            .await
            .expect("find_by_user_id 应成功");
        assert!(rows.is_empty(), "无角色关联的用户应返回空列表");
    }

    /// find_by_role_id 查询无用户关联的角色应返回空列表。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_role_id_returns_empty_for_no_users() {
        let pool = setup_db().await;
        let repo = DbnexusUserRoleRepository::new(pool.clone());
        let (_, role_id) = setup_user_and_role(&pool, 1).await;

        let rows = repo
            .find_by_role_id(1, &role_id)
            .await
            .expect("find_by_role_id 应成功");
        assert!(rows.is_empty(), "无用户关联的角色应返回空列表");
    }

    /// assign 时 scope 为 None 也能正确插入。
    #[tokio::test(flavor = "multi_thread")]
    async fn assign_with_scope_none() {
        let pool = setup_db().await;
        let repo = DbnexusUserRoleRepository::new(pool.clone());
        let (user_id, role_id) = setup_user_and_role(&pool, 1).await;

        repo.assign(1, &user_id, &role_id, None)
            .await
            .expect("assign scope=None 应成功");

        let rows = repo
            .find_by_user_id(1, &user_id)
            .await
            .expect("find_by_user_id 应成功");
        assert_eq!(rows.len(), 1);
        assert!(rows[0].scope.is_none(), "scope 应为 None");
    }

    /// list 分页查询：插入 3 条后 offset/limit 正确分页。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_paginates_correctly() {
        let pool = setup_db().await;
        let repo = DbnexusUserRoleRepository::new(pool.clone());
        let role_repo = DbnexusRoleRepository::new(pool.clone());
        let user_repo = DbnexusUserRepository::new(pool.clone());

        let role_id = role_repo
            .create(
                1,
                NewRole {
                    code: "page-shared-role".to_string(),
                    name: "共享角色".to_string(),
                    description: None,
                    is_system: false,
                },
            )
            .await
            .expect("创建 role 应成功");

        for i in 0..3 {
            let user_id = user_repo
                .create(
                    1,
                    NewUser {
                        username: format!("page-user-{}", i),
                        password_hash: "h".to_string(),
                        status: "active".to_string(),
                    },
                )
                .await
                .expect("创建 user 应成功");
            repo.assign(1, &user_id, &role_id, None)
                .await
                .expect("assign 应成功");
        }

        let all = repo.list(1, 0, 100).await.expect("list 应成功");
        assert_eq!(all.len(), 3, "应有 3 条记录");

        let page = repo.list(1, 1, 1).await.expect("list 分页应成功");
        assert_eq!(page.len(), 1, "分页应返回 1 条");

        let empty = repo.list(1, 100, 10).await.expect("list 超范围应成功");
        assert!(empty.is_empty(), "超出范围的 offset 应返回空");
    }

    /// list 空表查询应返回空列表。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_empty_returns_empty() {
        let pool = setup_db().await;
        let repo = DbnexusUserRoleRepository::new(pool);

        let result = repo.list(1, 0, 100).await.expect("list 应成功");
        assert!(result.is_empty(), "空表应返回空列表");
    }

    /// revoke 对不存在的关联不报错（幂等）。
    #[tokio::test(flavor = "multi_thread")]
    async fn revoke_nonexistent_is_noop() {
        let pool = setup_db().await;
        let repo = DbnexusUserRoleRepository::new(pool);

        repo.revoke(1, "nonexistent-user", "nonexistent-role")
            .await
            .expect("revoke 不存在的关联应为 no-op");
    }
}
