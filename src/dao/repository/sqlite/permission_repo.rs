//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusPermissionRepository 实现（app_permission 表，全局表无 tenant_id）。

use super::{v_i64, v_opt_str, v_str, DbnexusPermissionRepository};
use crate::dao::repository::{make_statement, NewPermission, PermissionRepository, PermissionRow};
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, QueryResult};

impl DbnexusPermissionRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl PermissionRepository for DbnexusPermissionRepository {
    async fn find_by_id(&self, id: &str) -> BulwarkResult<Option<PermissionRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_permission find_by_id 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_permission find_by_id 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT id, code, name, resource_type, action, created_at, updated_at \
                   FROM app_permission WHERE id = ?";
        let stmt = make_statement(conn, sql, vec![v_str(id)]);
        let row = conn.query_one_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("dao-app-permission-find-by-id-query::{}", e))
        })?;
        row.map(|r| parse_permission_row(&r)).transpose()
    }

    async fn find_by_code(&self, code: &str) -> BulwarkResult<Option<PermissionRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            BulwarkError::Dao(format!(
                "app_permission find_by_code 获取 session 失败: {}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!(
                "app_permission find_by_code 获取 connection 失败: {}",
                e
            ))
        })?;
        let sql = "SELECT id, code, name, resource_type, action, created_at, updated_at \
                   FROM app_permission WHERE code = ?";
        let stmt = make_statement(conn, sql, vec![v_str(code)]);
        let row = conn.query_one_raw(stmt).await.map_err(|e| {
            BulwarkError::Dao(format!("dao-app-permission-find-by-code-query::{}", e))
        })?;
        row.map(|r| parse_permission_row(&r)).transpose()
    }

    async fn create(&self, permission: NewPermission) -> BulwarkResult<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("dao-app-permission-create-session::{}", e))
            })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("dao-app-permission-create-connection::{}", e))
        })?;
        let sql = "INSERT INTO app_permission (id, code, name, resource_type, action) \
                   VALUES (?, ?, ?, ?, ?)";
        let stmt = make_statement(
            conn,
            sql,
            vec![
                v_str(&id),
                v_str(&permission.code),
                v_str(&permission.name),
                v_opt_str(&permission.resource_type),
                v_opt_str(&permission.action),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("dao-app-permission-create-insert::{}", e)))?;
        Ok(id)
    }

    async fn update(
        &self,
        id: &str,
        name: Option<String>,
        resource_type: Option<String>,
        action: Option<String>,
    ) -> BulwarkResult<()> {
        let mut sets = Vec::new();
        let mut params = Vec::new();
        if let Some(name) = name {
            sets.push("name = ?");
            params.push(v_str(&name));
        }
        if let Some(resource_type) = resource_type {
            sets.push("resource_type = ?");
            params.push(v_str(&resource_type));
        }
        if let Some(action) = action {
            sets.push("action = ?");
            params.push(v_str(&action));
        }
        if sets.is_empty() {
            return Ok(());
        }
        params.push(v_str(id));
        let sql = format!("UPDATE app_permission SET {} WHERE id = ?", sets.join(", "));
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("dao-app-permission-update-session::{}", e))
            })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("dao-app-permission-update-connection::{}", e))
        })?;
        let stmt = make_statement(conn, &sql, params);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("dao-app-permission-update-update::{}", e)))?;
        Ok(())
    }

    async fn delete(&self, id: &str) -> BulwarkResult<()> {
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("dao-app-permission-delete-session::{}", e))
            })?;
        let conn = session.connection().map_err(|e| {
            BulwarkError::Dao(format!("dao-app-permission-delete-connection::{}", e))
        })?;
        let sql = "DELETE FROM app_permission WHERE id = ?";
        let stmt = make_statement(conn, sql, vec![v_str(id)]);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("dao-app-permission-delete-delete::{}", e)))?;
        Ok(())
    }

    async fn list(&self, offset: i64, limit: i64) -> BulwarkResult<Vec<PermissionRow>> {
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                BulwarkError::Dao(format!("dao-app-permission-list-session::{}", e))
            })?;
        let conn = session
            .connection()
            .map_err(|e| BulwarkError::Dao(format!("dao-app-permission-list-connection::{}", e)))?;
        let sql = "SELECT id, code, name, resource_type, action, created_at, updated_at \
                   FROM app_permission LIMIT ? OFFSET ?";
        let stmt = make_statement(conn, sql, vec![v_i64(limit), v_i64(offset)]);
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| BulwarkError::Dao(format!("dao-app-permission-list-query::{}", e)))?;
        rows.iter().map(parse_permission_row).collect()
    }
}

/// 解析 app_permission 行。
fn parse_permission_row(row: &QueryResult) -> BulwarkResult<PermissionRow> {
    Ok(PermissionRow {
        id: row
            .try_get("", "id")
            .map_err(|e| BulwarkError::Dao(format!("dao-app-permission-row-parse-id::{}", e)))?,
        code: row
            .try_get("", "code")
            .map_err(|e| BulwarkError::Dao(format!("dao-app-permission-row-parse-code::{}", e)))?,
        name: row
            .try_get("", "name")
            .map_err(|e| BulwarkError::Dao(format!("dao-app-permission-row-parse-name::{}", e)))?,
        resource_type: row.try_get("", "resource_type").map_err(|e| {
            BulwarkError::Dao(format!("dao-app-permission-row-parse-resource-type::{}", e))
        })?,
        action: row.try_get("", "action").map_err(|e| {
            BulwarkError::Dao(format!("dao-app-permission-row-parse-action::{}", e))
        })?,
        created_at: row.try_get("", "created_at").map_err(|e| {
            BulwarkError::Dao(format!("dao-app-permission-row-parse-created-at::{}", e))
        })?,
        updated_at: row.try_get("", "updated_at").map_err(|e| {
            BulwarkError::Dao(format!("dao-app-permission-row-parse-updated-at::{}", e))
        })?,
    })
}

#[cfg(all(test, feature = "db-sqlite"))]
mod tests {
    use super::*;
    use crate::dao::repository::sqlite::test_support::setup_db;

    /// create 插入权限后 find_by_id 应返回相同字段（含可选字段 resource_type/action）。
    #[tokio::test(flavor = "multi_thread")]
    async fn create_and_find_by_id_roundtrip() {
        let pool = setup_db().await;
        let repo = DbnexusPermissionRepository::new(pool);

        let id = repo
            .create(NewPermission {
                code: "user:read".to_string(),
                name: "读取用户".to_string(),
                resource_type: Some("user".to_string()),
                action: Some("read".to_string()),
            })
            .await
            .expect("create 应成功");

        let row = repo
            .find_by_id(&id)
            .await
            .expect("find_by_id 应成功")
            .expect("权限应存在");
        assert_eq!(row.id, id);
        assert_eq!(row.code, "user:read");
        assert_eq!(row.name, "读取用户");
        assert_eq!(row.resource_type.as_deref(), Some("user"));
        assert_eq!(row.action.as_deref(), Some("read"));
    }

    /// find_by_id 查询不存在的 ID 应返回 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_id_returns_none_for_nonexistent() {
        let pool = setup_db().await;
        let repo = DbnexusPermissionRepository::new(pool);

        let result = repo
            .find_by_id("nonexistent-uuid")
            .await
            .expect("find_by_id 应成功");
        assert!(result.is_none(), "不存在的 ID 应返回 None");
    }

    /// find_by_code 按 code 精确查询，可选字段为 None 时也能正确返回。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_code_with_optional_fields_none() {
        let pool = setup_db().await;
        let repo = DbnexusPermissionRepository::new(pool);

        repo.create(NewPermission {
            code: "role:list".to_string(),
            name: "列角色".to_string(),
            resource_type: None,
            action: None,
        })
        .await
        .expect("create 应成功");

        let row = repo
            .find_by_code("role:list")
            .await
            .expect("find_by_code 应成功")
            .expect("权限应存在");
        assert_eq!(row.code, "role:list");
        assert!(row.resource_type.is_none());
        assert!(row.action.is_none());
    }

    /// update 更新 name/resource_type/action 后查询应反映新值；全 None 时不更新。
    #[tokio::test(flavor = "multi_thread")]
    async fn update_changes_fields_and_noop_when_all_none() {
        let pool = setup_db().await;
        let repo = DbnexusPermissionRepository::new(pool);

        let id = repo
            .create(NewPermission {
                code: "order:write".to_string(),
                name: "旧名称".to_string(),
                resource_type: Some("old_type".to_string()),
                action: Some("old_action".to_string()),
            })
            .await
            .expect("create 应成功");

        // 全 None 时应直接返回 Ok(()) 不执行 SQL
        repo.update(&id, None, None, None)
            .await
            .expect("全 None update 应为 no-op");

        // 更新所有字段
        repo.update(
            &id,
            Some("新名称".to_string()),
            Some("new_type".to_string()),
            Some("new_action".to_string()),
        )
        .await
        .expect("update 应成功");

        let row = repo
            .find_by_id(&id)
            .await
            .expect("find_by_id 应成功")
            .expect("权限应存在");
        assert_eq!(row.name, "新名称");
        assert_eq!(row.resource_type.as_deref(), Some("new_type"));
        assert_eq!(row.action.as_deref(), Some("new_action"));
        // code 不应被 update 改变
        assert_eq!(row.code, "order:write");
    }

    /// delete 删除后 find_by_id 返回 None；重复删除不报错（幂等）。
    #[tokio::test(flavor = "multi_thread")]
    async fn delete_is_idempotent() {
        let pool = setup_db().await;
        let repo = DbnexusPermissionRepository::new(pool);

        let id = repo
            .create(NewPermission {
                code: "temp:delete".to_string(),
                name: "临时".to_string(),
                resource_type: None,
                action: None,
            })
            .await
            .expect("create 应成功");

        repo.delete(&id).await.expect("首次 delete 应成功");
        let after = repo.find_by_id(&id).await.expect("find_by_id 应成功");
        assert!(after.is_none(), "删除后应查不到");

        // 幂等：再次删除不存在的记录不报错
        repo.delete(&id).await.expect("幂等 delete 应成功");
    }

    /// list 分页查询：插入 3 条记录后 offset/limit 正确分页。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_paginates_correctly() {
        let pool = setup_db().await;
        let repo = DbnexusPermissionRepository::new(pool);

        for i in 0..3 {
            repo.create(NewPermission {
                code: format!("perm:list:{}", i),
                name: format!("权限{}", i),
                resource_type: None,
                action: None,
            })
            .await
            .expect("create 应成功");
        }

        // 查询全部 3 条
        let all = repo.list(0, 100).await.expect("list 应成功");
        assert_eq!(all.len(), 3, "应有 3 条记录");

        // 分页：offset=1, limit=1 应返回第 2 条
        let page = repo.list(1, 1).await.expect("list 分页应成功");
        assert_eq!(page.len(), 1, "分页应返回 1 条");

        // offset 超出范围应返回空
        let empty = repo.list(100, 10).await.expect("list 超范围应成功");
        assert!(empty.is_empty(), "超出范围的 offset 应返回空");
    }

    /// find_by_code 查询不存在的 code 应返回 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_code_returns_none_for_nonexistent() {
        let pool = setup_db().await;
        let repo = DbnexusPermissionRepository::new(pool);

        let result = repo
            .find_by_code("nonexistent-code")
            .await
            .expect("find_by_code 应成功");
        assert!(result.is_none(), "不存在的 code 应返回 None");
    }

    /// update 仅更新 name 字段。
    #[tokio::test(flavor = "multi_thread")]
    async fn update_partial_only_name() {
        let pool = setup_db().await;
        let repo = DbnexusPermissionRepository::new(pool);

        let id = repo
            .create(NewPermission {
                code: "partial-name".to_string(),
                name: "原名".to_string(),
                resource_type: Some("user".to_string()),
                action: Some("read".to_string()),
            })
            .await
            .expect("create 应成功");

        repo.update(&id, Some("仅改名".to_string()), None, None)
            .await
            .expect("update 应成功");

        let row = repo
            .find_by_id(&id)
            .await
            .expect("find_by_id 应成功")
            .expect("权限应存在");
        assert_eq!(row.name, "仅改名");
        assert_eq!(
            row.resource_type.as_deref(),
            Some("user"),
            "resource_type 不应变"
        );
        assert_eq!(row.action.as_deref(), Some("read"), "action 不应变");
    }

    /// update 仅更新 resource_type 字段。
    #[tokio::test(flavor = "multi_thread")]
    async fn update_partial_only_resource_type() {
        let pool = setup_db().await;
        let repo = DbnexusPermissionRepository::new(pool);

        let id = repo
            .create(NewPermission {
                code: "partial-rt".to_string(),
                name: "名".to_string(),
                resource_type: Some("old_type".to_string()),
                action: None,
            })
            .await
            .expect("create 应成功");

        repo.update(&id, None, Some("new_type".to_string()), None)
            .await
            .expect("update 应成功");

        let row = repo
            .find_by_id(&id)
            .await
            .expect("find_by_id 应成功")
            .expect("权限应存在");
        assert_eq!(row.resource_type.as_deref(), Some("new_type"));
        assert_eq!(row.name, "名", "name 不应变");
    }

    /// update 仅更新 action 字段。
    #[tokio::test(flavor = "multi_thread")]
    async fn update_partial_only_action() {
        let pool = setup_db().await;
        let repo = DbnexusPermissionRepository::new(pool);

        let id = repo
            .create(NewPermission {
                code: "partial-act".to_string(),
                name: "名".to_string(),
                resource_type: None,
                action: Some("old_action".to_string()),
            })
            .await
            .expect("create 应成功");

        repo.update(&id, None, None, Some("new_action".to_string()))
            .await
            .expect("update 应成功");

        let row = repo
            .find_by_id(&id)
            .await
            .expect("find_by_id 应成功")
            .expect("权限应存在");
        assert_eq!(row.action.as_deref(), Some("new_action"));
    }

    /// list 空表查询应返回空列表。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_empty_returns_empty() {
        let pool = setup_db().await;
        let repo = DbnexusPermissionRepository::new(pool);

        let result = repo.list(0, 100).await.expect("list 应成功");
        assert!(result.is_empty(), "空表应返回空列表");
    }

    /// create 生成合法 UUID v4。
    #[tokio::test(flavor = "multi_thread")]
    async fn create_generates_valid_uuid_v4() {
        let pool = setup_db().await;
        let repo = DbnexusPermissionRepository::new(pool);

        let id = repo
            .create(NewPermission {
                code: "uuid-test".to_string(),
                name: "UUID测试".to_string(),
                resource_type: None,
                action: None,
            })
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
