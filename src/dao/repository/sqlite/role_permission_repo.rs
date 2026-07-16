//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusRolePermissionRepository 实现（app_role_permission 表）。

use super::{v_i64, v_str, DbnexusRolePermissionRepository};
use crate::dao::repository::{make_statement, RolePermissionRepository, RolePermissionRow};
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, QueryResult};

impl DbnexusRolePermissionRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RolePermissionRepository for DbnexusRolePermissionRepository {
    async fn find_by_role_id(
        &self,
        tenant_id: i64,
        role_id: &str,
    ) -> BulwarkResult<Vec<RolePermissionRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission find_by_role_id 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission find_by_role_id 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT role_id, permission_id, tenant_id \
                   FROM app_role_permission WHERE tenant_id = ? AND role_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(role_id)]);
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission find_by_role_id 查询失败: {}",
                e
            ))
        })?;
        rows.iter().map(parse_role_permission_row).collect()
    }

    async fn find_by_permission_id(
        &self,
        tenant_id: i64,
        permission_id: &str,
    ) -> BulwarkResult<Vec<RolePermissionRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission find_by_permission_id 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission find_by_permission_id 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT role_id, permission_id, tenant_id \
                   FROM app_role_permission WHERE tenant_id = ? AND permission_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(permission_id)]);
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission find_by_permission_id 查询失败: {}",
                e
            ))
        })?;
        rows.iter().map(parse_role_permission_row).collect()
    }

    async fn assign(
        &self,
        tenant_id: i64,
        role_id: &str,
        permission_id: &str,
    ) -> BulwarkResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission assign 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission assign 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "INSERT INTO app_role_permission (role_id, permission_id, tenant_id) \
                   VALUES (?, ?, ?)";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_str(role_id), v_str(permission_id), v_i64(tenant_id)],
        );
        conn.execute_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("app_role_permission assign 插入失败: {}", e))
        })?;
        Ok(())
    }

    async fn revoke(
        &self,
        tenant_id: i64,
        role_id: &str,
        permission_id: &str,
    ) -> BulwarkResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission revoke 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission revoke 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "DELETE FROM app_role_permission \
                   WHERE tenant_id = ? AND role_id = ? AND permission_id = ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_str(role_id), v_str(permission_id)],
        );
        conn.execute_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("app_role_permission revoke 删除失败: {}", e))
        })?;
        Ok(())
    }

    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> BulwarkResult<Vec<RolePermissionRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!("app_role_permission list 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission list 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT role_id, permission_id, tenant_id \
                   FROM app_role_permission WHERE tenant_id = ? LIMIT ? OFFSET ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_i64(limit), v_i64(offset)],
        );
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("app_role_permission list 查询失败: {}", e)))?;
        rows.iter().map(parse_role_permission_row).collect()
    }
}

/// 解析 app_role_permission 行。
fn parse_role_permission_row(row: &QueryResult) -> BulwarkResult<RolePermissionRow> {
    Ok(RolePermissionRow {
        role_id: row.try_get("", "role_id").map_err(|e| {
            BulwarkError::Dao(format!("app_role_permission 行解析失败 (role_id): {}", e))
        })?,
        permission_id: row.try_get("", "permission_id").map_err(|e| {
            BulwarkError::Dao(format!(
                "app_role_permission 行解析失败 (permission_id): {}",
                e
            ))
        })?,
        tenant_id: row.try_get("", "tenant_id").map_err(|e| {
            BulwarkError::Dao(format!("app_role_permission 行解析失败 (tenant_id): {}", e))
        })?,
    })
}

#[cfg(all(test, feature = "db-sqlite"))]
mod tests {
    use super::super::{DbnexusPermissionRepository, DbnexusRoleRepository};
    use super::*;
    use crate::dao::repository::sqlite::test_support::setup_db;
    use crate::dao::repository::{NewPermission, NewRole, PermissionRepository, RoleRepository};

    /// 创建辅助：在指定 tenant 中创建 1 个 role + 1 个 permission。
    async fn setup_role_and_permission(pool: &DbPool, tenant_id: i64) -> (String, String) {
        let role_repo = DbnexusRoleRepository::new(pool.clone());
        let perm_repo = DbnexusPermissionRepository::new(pool.clone());
        let role_id = role_repo
            .create(
                tenant_id,
                NewRole {
                    code: format!("rp-role-{}", tenant_id),
                    name: "测试角色".to_string(),
                    description: None,
                    is_system: false,
                },
            )
            .await
            .expect("创建 role 应成功");
        let perm_id = perm_repo
            .create(NewPermission {
                code: format!("rp-perm-{}", tenant_id),
                name: "测试权限".to_string(),
                resource_type: Some("user".to_string()),
                action: Some("read".to_string()),
            })
            .await
            .expect("创建 permission 应成功");
        (role_id, perm_id)
    }

    /// assign 分配权限后 find_by_role_id 应返回关联记录。
    #[tokio::test(flavor = "multi_thread")]
    async fn assign_and_find_by_role_id() {
        let pool = setup_db().await;
        let repo = DbnexusRolePermissionRepository::new(pool.clone());
        let (role_id, perm_id) = setup_role_and_permission(&pool, 1).await;

        repo.assign(1, &role_id, &perm_id)
            .await
            .expect("assign 应成功");

        let rows = repo
            .find_by_role_id(1, &role_id)
            .await
            .expect("find_by_role_id 应成功");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].role_id, role_id);
        assert_eq!(rows[0].permission_id, perm_id);
        assert_eq!(rows[0].tenant_id, 1);
    }

    /// find_by_permission_id 查询同一权限关联的所有角色。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_permission_id_returns_all_roles() {
        let pool = setup_db().await;
        let repo = DbnexusRolePermissionRepository::new(pool.clone());
        let role_repo = DbnexusRoleRepository::new(pool.clone());
        let perm_repo = DbnexusPermissionRepository::new(pool.clone());

        // 创建 1 个权限 + 2 个角色，分配到同一权限
        let perm_id = perm_repo
            .create(NewPermission {
                code: "shared:perm".to_string(),
                name: "共享权限".to_string(),
                resource_type: None,
                action: None,
            })
            .await
            .expect("创建 permission 应成功");

        for i in 0..2 {
            let role_id = role_repo
                .create(
                    1,
                    NewRole {
                        code: format!("rbp-role-{}", i),
                        name: format!("角色{}", i),
                        description: None,
                        is_system: false,
                    },
                )
                .await
                .expect("创建 role 应成功");
            repo.assign(1, &role_id, &perm_id)
                .await
                .expect("assign 应成功");
        }

        let rows = repo
            .find_by_permission_id(1, &perm_id)
            .await
            .expect("find_by_permission_id 应成功");
        assert_eq!(rows.len(), 2, "应有 2 条关联");
        assert!(rows.iter().all(|r| r.permission_id == perm_id));
    }

    /// revoke 撤销权限后 find_by_role_id 返回空；重复 revoke 不报错。
    #[tokio::test(flavor = "multi_thread")]
    async fn revoke_is_idempotent() {
        let pool = setup_db().await;
        let repo = DbnexusRolePermissionRepository::new(pool.clone());
        let (role_id, perm_id) = setup_role_and_permission(&pool, 1).await;

        repo.assign(1, &role_id, &perm_id)
            .await
            .expect("assign 应成功");
        repo.revoke(1, &role_id, &perm_id)
            .await
            .expect("首次 revoke 应成功");

        let rows = repo
            .find_by_role_id(1, &role_id)
            .await
            .expect("find_by_role_id 应成功");
        assert!(rows.is_empty(), "revoke 后应查不到关联");

        // 幂等：再次 revoke
        repo.revoke(1, &role_id, &perm_id)
            .await
            .expect("幂等 revoke 应成功");
    }

    /// list 按 tenant_id 隔离。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_filters_by_tenant_id() {
        let pool = setup_db().await;
        let repo = DbnexusRolePermissionRepository::new(pool.clone());

        let (role_1, perm_1) = setup_role_and_permission(&pool, 1).await;
        repo.assign(1, &role_1, &perm_1)
            .await
            .expect("assign tenant 1 应成功");

        let (role_2, perm_2) = setup_role_and_permission(&pool, 2).await;
        repo.assign(2, &role_2, &perm_2)
            .await
            .expect("assign tenant 2 应成功");

        let list_1 = repo.list(1, 0, 100).await.expect("list tenant 1 应成功");
        let list_2 = repo.list(2, 0, 100).await.expect("list tenant 2 应成功");
        assert_eq!(list_1.len(), 1, "tenant 1 应有 1 条");
        assert_eq!(list_2.len(), 1, "tenant 2 应有 1 条");
        assert_eq!(list_1[0].tenant_id, 1);
        assert_eq!(list_2[0].tenant_id, 2);
    }

    /// assign 同一 role+permission 组合两次应因主键约束失败。
    #[tokio::test(flavor = "multi_thread")]
    async fn assign_duplicate_pair_returns_error() {
        let pool = setup_db().await;
        let repo = DbnexusRolePermissionRepository::new(pool.clone());
        let (role_id, perm_id) = setup_role_and_permission(&pool, 1).await;

        repo.assign(1, &role_id, &perm_id)
            .await
            .expect("首次 assign 应成功");

        let result = repo.assign(1, &role_id, &perm_id).await;
        assert!(result.is_err(), "重复 assign 应返回错误");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("app_role_permission") || err_msg.contains("UNIQUE"),
            "错误信息应包含表名或约束信息，实际: {}",
            err_msg
        );
    }

    /// find_by_role_id 查询无关联权限的角色应返回空列表。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_role_id_returns_empty_for_no_assignments() {
        let pool = setup_db().await;
        let repo = DbnexusRolePermissionRepository::new(pool.clone());
        let (role_id, _) = setup_role_and_permission(&pool, 1).await;

        let rows = repo
            .find_by_role_id(1, &role_id)
            .await
            .expect("find_by_role_id 应成功");
        assert!(rows.is_empty(), "无关联的角色应返回空列表");
    }

    /// find_by_permission_id 查询无关联角色的权限应返回空列表。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_permission_id_returns_empty_for_no_assignments() {
        let pool = setup_db().await;
        let repo = DbnexusRolePermissionRepository::new(pool.clone());
        let (_, perm_id) = setup_role_and_permission(&pool, 1).await;

        let rows = repo
            .find_by_permission_id(1, &perm_id)
            .await
            .expect("find_by_permission_id 应成功");
        assert!(rows.is_empty(), "无关联的权限应返回空列表");
    }

    /// list 分页查询：插入 3 条后 offset/limit 正确分页。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_paginates_correctly() {
        let pool = setup_db().await;
        let repo = DbnexusRolePermissionRepository::new(pool.clone());
        let perm_repo = DbnexusPermissionRepository::new(pool.clone());
        let role_repo = DbnexusRoleRepository::new(pool.clone());

        let perm_id = perm_repo
            .create(NewPermission {
                code: "shared-page".to_string(),
                name: "共享".to_string(),
                resource_type: None,
                action: None,
            })
            .await
            .expect("创建 permission 应成功");

        for i in 0..3 {
            let role_id = role_repo
                .create(
                    1,
                    NewRole {
                        code: format!("page-role-{}", i),
                        name: format!("角色{}", i),
                        description: None,
                        is_system: false,
                    },
                )
                .await
                .expect("创建 role 应成功");
            repo.assign(1, &role_id, &perm_id)
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
        let repo = DbnexusRolePermissionRepository::new(pool);

        let result = repo.list(1, 0, 100).await.expect("list 应成功");
        assert!(result.is_empty(), "空表应返回空列表");
    }

    /// revoke 对不存在的关联不报错（幂等）。
    #[tokio::test(flavor = "multi_thread")]
    async fn revoke_nonexistent_is_noop() {
        let pool = setup_db().await;
        let repo = DbnexusRolePermissionRepository::new(pool);

        repo.revoke(1, "nonexistent-role", "nonexistent-perm")
            .await
            .expect("revoke 不存在的关联应为 no-op");
    }
}
