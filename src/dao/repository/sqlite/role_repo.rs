//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusRoleRepository 实现（app_role 表）。

use super::{read_bool, v_bool, v_i64, v_opt_str, v_str, DbnexusRoleRepository};
use crate::dao::dao_session;
use crate::dao::repository::{make_statement, NewRole, RoleRepository, RoleRow};
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, QueryResult};

impl DbnexusRoleRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl RoleRepository for DbnexusRoleRepository {
    async fn find_by_id(&self, tenant_id: i64, id: &str) -> GarrisonResult<Option<RoleRow>> {
        dao_session!(self.pool, "dao-app-role-find-by-id", session, conn);
        let sql =
            "SELECT id, code, name, description, tenant_id, is_system, created_at, updated_at \
                   FROM app_role WHERE tenant_id = ? AND id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(id)]);
        let row = conn
            .query_one_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-role-find-by-id-query::{}", e)))?;
        row.map(|r| parse_role_row(&r)).transpose()
    }

    async fn find_by_code(&self, tenant_id: i64, code: &str) -> GarrisonResult<Option<RoleRow>> {
        dao_session!(self.pool, "dao-app-role-find-by-code", session, conn);
        let sql =
            "SELECT id, code, name, description, tenant_id, is_system, created_at, updated_at \
                   FROM app_role WHERE tenant_id = ? AND code = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(code)]);
        let row = conn
            .query_one_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-role-find-by-code-query::{}", e)))?;
        row.map(|r| parse_role_row(&r)).transpose()
    }

    async fn create(&self, tenant_id: i64, role: NewRole) -> GarrisonResult<String> {
        let id = uuid::Uuid::new_v4().to_string();
        dao_session!(self.pool, "dao-app-role-create", session, conn);
        let sql = "INSERT INTO app_role (id, code, name, description, tenant_id, is_system) \
                   VALUES (?, ?, ?, ?, ?, ?)";
        let stmt = make_statement(
            conn,
            sql,
            vec![
                v_str(&id),
                v_str(&role.code),
                v_str(&role.name),
                v_opt_str(&role.description),
                v_i64(tenant_id),
                v_bool(role.is_system),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-role-create-insert::{}", e)))?;
        Ok(id)
    }

    async fn update(
        &self,
        tenant_id: i64,
        id: &str,
        code: Option<String>,
        name: Option<String>,
        description: Option<String>,
    ) -> GarrisonResult<()> {
        let mut sets = Vec::new();
        let mut params = Vec::new();
        if let Some(code) = code {
            sets.push("code = ?");
            params.push(v_str(&code));
        }
        if let Some(name) = name {
            sets.push("name = ?");
            params.push(v_str(&name));
        }
        if let Some(description) = description {
            sets.push("description = ?");
            params.push(v_str(&description));
        }
        if sets.is_empty() {
            return Ok(());
        }
        params.push(v_i64(tenant_id));
        params.push(v_str(id));
        let sql = format!(
            "UPDATE app_role SET {} WHERE tenant_id = ? AND id = ?",
            sets.join(", ")
        );
        dao_session!(self.pool, "dao-app-role-update", session, conn);
        let stmt = make_statement(conn, &sql, params);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-role-update-update::{}", e)))?;
        Ok(())
    }

    async fn delete(&self, tenant_id: i64, id: &str) -> GarrisonResult<()> {
        dao_session!(self.pool, "dao-app-role-delete", session, conn);
        let sql = "DELETE FROM app_role WHERE tenant_id = ? AND id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(id)]);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-role-delete-delete::{}", e)))?;
        Ok(())
    }

    async fn list(&self, tenant_id: i64, offset: i64, limit: i64) -> GarrisonResult<Vec<RoleRow>> {
        dao_session!(self.pool, "dao-app-role-list", session, conn);
        let sql =
            "SELECT id, code, name, description, tenant_id, is_system, created_at, updated_at \
                   FROM app_role WHERE tenant_id = ? LIMIT ? OFFSET ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_i64(limit), v_i64(offset)],
        );
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-role-list-query::{}", e)))?;
        rows.iter().map(parse_role_row).collect()
    }
}

/// 解析 app_role 行。
fn parse_role_row(row: &QueryResult) -> GarrisonResult<RoleRow> {
    Ok(RoleRow {
        id: row
            .try_get("", "id")
            .map_err(|e| GarrisonError::Dao(format!("dao-app-role-row-parse-id::{}", e)))?,
        code: row
            .try_get("", "code")
            .map_err(|e| GarrisonError::Dao(format!("dao-app-role-row-parse-code::{}", e)))?,
        name: row
            .try_get("", "name")
            .map_err(|e| GarrisonError::Dao(format!("dao-app-role-row-parse-name::{}", e)))?,
        description: row.try_get("", "description").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-role-row-parse-description::{}", e))
        })?,
        tenant_id: row
            .try_get("", "tenant_id")
            .map_err(|e| GarrisonError::Dao(format!("dao-app-role-row-parse-tenant-id::{}", e)))?,
        is_system: read_bool(row, "is_system"),
        created_at: row
            .try_get("", "created_at")
            .map_err(|e| GarrisonError::Dao(format!("dao-app-role-row-parse-created-at::{}", e)))?,
        updated_at: row
            .try_get("", "updated_at")
            .map_err(|e| GarrisonError::Dao(format!("dao-app-role-row-parse-updated-at::{}", e)))?,
    })
}

#[cfg(all(test, feature = "db-sqlite"))]
mod tests {
    use super::*;
    use crate::dao::repository::sqlite::test_support::setup_db;

    /// create 插入角色后 find_by_id 应返回相同字段（含 is_system/description）。
    #[tokio::test(flavor = "multi_thread")]
    async fn create_and_find_by_id_roundtrip() {
        let pool = setup_db().await;
        let repo = DbnexusRoleRepository::new(pool);

        let id = repo
            .create(
                1,
                NewRole {
                    code: "admin".to_string(),
                    name: "管理员".to_string(),
                    description: Some("系统管理员".to_string()),
                    is_system: true,
                },
            )
            .await
            .expect("create 应成功");

        let row = repo
            .find_by_id(1, &id)
            .await
            .expect("find_by_id 应成功")
            .expect("角色应存在");
        assert_eq!(row.id, id);
        assert_eq!(row.code, "admin");
        assert_eq!(row.name, "管理员");
        assert_eq!(row.description.as_deref(), Some("系统管理员"));
        assert_eq!(row.tenant_id, 1);
        assert!(row.is_system, "is_system 应为 true");
    }

    /// find_by_id 查询不存在的 ID 应返回 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_id_returns_none_for_nonexistent() {
        let pool = setup_db().await;
        let repo = DbnexusRoleRepository::new(pool);

        let result = repo
            .find_by_id(1, "nonexistent-uuid")
            .await
            .expect("find_by_id 应成功");
        assert!(result.is_none(), "不存在的 ID 应返回 None");
    }

    /// find_by_code 按 code 精确查询。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_code_returns_role() {
        let pool = setup_db().await;
        let repo = DbnexusRoleRepository::new(pool);

        repo.create(
            1,
            NewRole {
                code: "editor".to_string(),
                name: "编辑".to_string(),
                description: None,
                is_system: false,
            },
        )
        .await
        .expect("create 应成功");

        let row = repo
            .find_by_code(1, "editor")
            .await
            .expect("find_by_code 应成功")
            .expect("角色应存在");
        assert_eq!(row.code, "editor");
        assert_eq!(row.name, "编辑");
        assert!(row.description.is_none());
        assert!(!row.is_system);
    }

    /// find_by_code 查询不存在的 code 应返回 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_code_returns_none_for_nonexistent() {
        let pool = setup_db().await;
        let repo = DbnexusRoleRepository::new(pool);

        let result = repo
            .find_by_code(1, "nonexistent-code")
            .await
            .expect("find_by_code 应成功");
        assert!(result.is_none(), "不存在的 code 应返回 None");
    }

    /// update 更新 code/name/description 后查询应反映新值；全 None 时不更新。
    #[tokio::test(flavor = "multi_thread")]
    async fn update_changes_fields_and_noop_when_all_none() {
        let pool = setup_db().await;
        let repo = DbnexusRoleRepository::new(pool);

        let id = repo
            .create(
                1,
                NewRole {
                    code: "old-code".to_string(),
                    name: "旧名".to_string(),
                    description: Some("旧描述".to_string()),
                    is_system: false,
                },
            )
            .await
            .expect("create 应成功");

        // 全 None 时应直接返回 Ok(()) 不执行 SQL
        repo.update(1, &id, None, None, None)
            .await
            .expect("全 None update 应为 no-op");

        // 更新所有字段
        repo.update(
            1,
            &id,
            Some("new-code".to_string()),
            Some("新名".to_string()),
            Some("新描述".to_string()),
        )
        .await
        .expect("update 应成功");

        let row = repo
            .find_by_id(1, &id)
            .await
            .expect("find_by_id 应成功")
            .expect("角色应存在");
        assert_eq!(row.code, "new-code");
        assert_eq!(row.name, "新名");
        assert_eq!(row.description.as_deref(), Some("新描述"));
    }

    /// update 仅更新部分字段（仅 name）。
    #[tokio::test(flavor = "multi_thread")]
    async fn update_partial_only_name() {
        let pool = setup_db().await;
        let repo = DbnexusRoleRepository::new(pool);

        let id = repo
            .create(
                1,
                NewRole {
                    code: "partial".to_string(),
                    name: "原名".to_string(),
                    description: Some("保留描述".to_string()),
                    is_system: false,
                },
            )
            .await
            .expect("create 应成功");

        repo.update(1, &id, None, Some("新名".to_string()), None)
            .await
            .expect("update 应成功");

        let row = repo
            .find_by_id(1, &id)
            .await
            .expect("find_by_id 应成功")
            .expect("角色应存在");
        assert_eq!(row.name, "新名");
        assert_eq!(row.code, "partial", "code 不应变");
        assert_eq!(
            row.description.as_deref(),
            Some("保留描述"),
            "description 不应变"
        );
    }

    /// update 仅更新 description（含设为 None 的场景用空字符串替代）。
    #[tokio::test(flavor = "multi_thread")]
    async fn update_partial_only_description() {
        let pool = setup_db().await;
        let repo = DbnexusRoleRepository::new(pool);

        let id = repo
            .create(
                1,
                NewRole {
                    code: "desc-role".to_string(),
                    name: "名".to_string(),
                    description: None,
                    is_system: false,
                },
            )
            .await
            .expect("create 应成功");

        repo.update(1, &id, None, None, Some("新增描述".to_string()))
            .await
            .expect("update 应成功");

        let row = repo
            .find_by_id(1, &id)
            .await
            .expect("find_by_id 应成功")
            .expect("角色应存在");
        assert_eq!(row.description.as_deref(), Some("新增描述"));
    }

    /// delete 删除后 find_by_id 返回 None；重复删除不报错（幂等）。
    #[tokio::test(flavor = "multi_thread")]
    async fn delete_is_idempotent() {
        let pool = setup_db().await;
        let repo = DbnexusRoleRepository::new(pool);

        let id = repo
            .create(
                1,
                NewRole {
                    code: "temp-role".to_string(),
                    name: "临时".to_string(),
                    description: None,
                    is_system: false,
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
        let repo = DbnexusRoleRepository::new(pool);

        for i in 0..3 {
            repo.create(
                1,
                NewRole {
                    code: format!("role-{}", i),
                    name: format!("角色{}", i),
                    description: None,
                    is_system: false,
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

    /// list 按 tenant_id 隔离。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_filters_by_tenant_id() {
        let pool = setup_db().await;
        let repo = DbnexusRoleRepository::new(pool);

        repo.create(
            1,
            NewRole {
                code: "t1-role".to_string(),
                name: "租户1角色".to_string(),
                description: None,
                is_system: false,
            },
        )
        .await
        .expect("create tenant 1 应成功");

        repo.create(
            2,
            NewRole {
                code: "t2-role".to_string(),
                name: "租户2角色".to_string(),
                description: None,
                is_system: false,
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
        let repo = DbnexusRoleRepository::new(pool);

        let id = repo
            .create(
                1,
                NewRole {
                    code: "cross-role".to_string(),
                    name: "跨租户".to_string(),
                    description: None,
                    is_system: false,
                },
            )
            .await
            .expect("create 应成功");

        let cross = repo.find_by_id(2, &id).await.expect("find_by_id 应成功");
        assert!(cross.is_none(), "跨租户查询应返回 None");
    }

    /// create 生成合法 UUID v4。
    #[tokio::test(flavor = "multi_thread")]
    async fn create_generates_valid_uuid_v4() {
        let pool = setup_db().await;
        let repo = DbnexusRoleRepository::new(pool);

        let id = repo
            .create(
                1,
                NewRole {
                    code: "uuid-role".to_string(),
                    name: "UUID测试".to_string(),
                    description: None,
                    is_system: false,
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
