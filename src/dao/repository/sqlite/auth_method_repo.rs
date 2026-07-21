//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusAuthMethodRepository 实现（app_auth_method 表）。

use super::{v_i64, v_opt_str, v_str, DbnexusAuthMethodRepository};
use crate::dao::repository::{make_statement, AuthMethodRepository, AuthMethodRow, NewAuthMethod};
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, QueryResult};

impl DbnexusAuthMethodRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuthMethodRepository for DbnexusAuthMethodRepository {
    async fn find_by_id(&self, tenant_id: i64, id: &str) -> GarrisonResult<Option<AuthMethodRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            GarrisonError::Dao(format!("dao-app-auth-method-find-by-id-session::{}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            GarrisonError::Dao(format!("dao-app-auth-method-find-by-id-connection::{}", e))
        })?;
        let sql = "SELECT id, user_id, method_type, external_id, metadata, create_time, tenant_id \
                   FROM app_auth_method WHERE tenant_id = ? AND id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(id)]);
        let row = conn.query_one_raw(stmt).await.map_err(|e| {
            GarrisonError::Dao(format!("dao-app-auth-method-find-by-id-query::{}", e))
        })?;
        row.map(|r| parse_auth_method_row(&r)).transpose()
    }

    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
    ) -> GarrisonResult<Vec<AuthMethodRow>> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            GarrisonError::Dao(format!(
                "dao-app-auth-method-find-by-user-id-session::{}",
                e
            ))
        })?;
        let conn = session.connection().map_err(|e| {
            GarrisonError::Dao(format!(
                "dao-app-auth-method-find-by-user-id-connection::{}",
                e
            ))
        })?;
        let sql = "SELECT id, user_id, method_type, external_id, metadata, create_time, tenant_id \
                   FROM app_auth_method WHERE tenant_id = ? AND user_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(user_id)]);
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            GarrisonError::Dao(format!("dao-app-auth-method-find-by-user-id-query::{}", e))
        })?;
        rows.iter().map(parse_auth_method_row).collect()
    }

    async fn create(&self, tenant_id: i64, method: NewAuthMethod) -> GarrisonResult<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let session = self.pool.get_session("admin").await.map_err(|e| {
            GarrisonError::Dao(format!("dao-app-auth-method-create-session::{}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            GarrisonError::Dao(format!("dao-app-auth-method-create-connection::{}", e))
        })?;
        let sql = "INSERT INTO app_auth_method (id, user_id, method_type, external_id, metadata, tenant_id) \
                   VALUES (?, ?, ?, ?, ?, ?)";
        let stmt = make_statement(
            conn,
            sql,
            vec![
                v_str(&id),
                v_str(&method.user_id),
                v_str(&method.method_type),
                v_opt_str(&method.external_id),
                v_opt_str(&method.metadata),
                v_i64(tenant_id),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-auth-method-create-insert::{}", e)))?;
        Ok(id)
    }

    async fn delete(&self, tenant_id: i64, id: &str) -> GarrisonResult<()> {
        let session = self.pool.get_session("admin").await.map_err(|e| {
            GarrisonError::Dao(format!("dao-app-auth-method-delete-session::{}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            GarrisonError::Dao(format!("dao-app-auth-method-delete-connection::{}", e))
        })?;
        let sql = "DELETE FROM app_auth_method WHERE tenant_id = ? AND id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(id)]);
        conn.execute_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-auth-method-delete-delete::{}", e)))?;
        Ok(())
    }

    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> GarrisonResult<Vec<AuthMethodRow>> {
        let session =
            self.pool.get_session("admin").await.map_err(|e| {
                GarrisonError::Dao(format!("dao-app-auth-method-list-session::{}", e))
            })?;
        let conn = session.connection().map_err(|e| {
            GarrisonError::Dao(format!("dao-app-auth-method-list-connection::{}", e))
        })?;
        let sql = "SELECT id, user_id, method_type, external_id, metadata, create_time, tenant_id \
                   FROM app_auth_method WHERE tenant_id = ? LIMIT ? OFFSET ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_i64(limit), v_i64(offset)],
        );
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-auth-method-list-query::{}", e)))?;
        rows.iter().map(parse_auth_method_row).collect()
    }
}

/// 解析 app_auth_method 行。
fn parse_auth_method_row(row: &QueryResult) -> GarrisonResult<AuthMethodRow> {
    Ok(AuthMethodRow {
        id: row
            .try_get("", "id")
            .map_err(|e| GarrisonError::Dao(format!("dao-app-auth-method-row-parse-id::{}", e)))?,
        user_id: row.try_get("", "user_id").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-auth-method-row-parse-user-id::{}", e))
        })?,
        method_type: row.try_get("", "method_type").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-auth-method-row-parse-method-type::{}", e))
        })?,
        external_id: row.try_get("", "external_id").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-auth-method-row-parse-external-id::{}", e))
        })?,
        metadata: row.try_get("", "metadata").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-auth-method-row-parse-metadata::{}", e))
        })?,
        create_time: row.try_get("", "create_time").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-auth-method-row-parse-create-time::{}", e))
        })?,
        tenant_id: row.try_get("", "tenant_id").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-auth-method-row-parse-tenant-id::{}", e))
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
                    username: format!("am-user-{}", tenant_id),
                    password_hash: "h".to_string(),
                    status: "active".to_string(),
                },
            )
            .await
            .expect("创建 user 应成功")
    }

    /// create 插入认证方式后 find_by_id 应返回相同字段。
    #[tokio::test(flavor = "multi_thread")]
    async fn create_and_find_by_id_roundtrip() {
        let pool = setup_db().await;
        let repo = DbnexusAuthMethodRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        let id = repo
            .create(
                1,
                NewAuthMethod {
                    user_id: user_id.clone(),
                    method_type: "password".to_string(),
                    external_id: None,
                    metadata: Some(r#"{"v":1}"#.to_string()),
                },
            )
            .await
            .expect("create 应成功");

        let row = repo
            .find_by_id(1, &id)
            .await
            .expect("find_by_id 应成功")
            .expect("认证方式应存在");
        assert_eq!(row.id, id);
        assert_eq!(row.user_id, user_id);
        assert_eq!(row.method_type, "password");
        assert!(row.external_id.is_none());
        assert_eq!(row.metadata.as_deref(), Some(r#"{"v":1}"#));
        assert_eq!(row.tenant_id, 1);
    }

    /// find_by_user_id 返回同一用户的所有认证方式。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_user_id_returns_all_methods() {
        let pool = setup_db().await;
        let repo = DbnexusAuthMethodRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        // 为同一用户创建 2 种认证方式
        repo.create(
            1,
            NewAuthMethod {
                user_id: user_id.clone(),
                method_type: "password".to_string(),
                external_id: None,
                metadata: None,
            },
        )
        .await
        .expect("创建 password 方式应成功");

        repo.create(
            1,
            NewAuthMethod {
                user_id: user_id.clone(),
                method_type: "oauth".to_string(),
                external_id: Some("google-123".to_string()),
                metadata: None,
            },
        )
        .await
        .expect("创建 oauth 方式应成功");

        let rows = repo
            .find_by_user_id(1, &user_id)
            .await
            .expect("find_by_user_id 应成功");
        assert_eq!(rows.len(), 2, "应有 2 种认证方式");
        let types: Vec<&str> = rows.iter().map(|r| r.method_type.as_str()).collect();
        assert!(types.contains(&"password"));
        assert!(types.contains(&"oauth"));
    }

    /// delete 删除后 find_by_id 返回 None；重复删除不报错。
    #[tokio::test(flavor = "multi_thread")]
    async fn delete_is_idempotent() {
        let pool = setup_db().await;
        let repo = DbnexusAuthMethodRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        let id = repo
            .create(
                1,
                NewAuthMethod {
                    user_id: user_id.clone(),
                    method_type: "passkey".to_string(),
                    external_id: None,
                    metadata: None,
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

    /// list 按 tenant_id 隔离：不同租户的认证方式互不干扰。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_filters_by_tenant_id() {
        let pool = setup_db().await;
        let repo = DbnexusAuthMethodRepository::new(pool.clone());

        // tenant 1
        let user_1 = setup_user(&pool, 1).await;
        repo.create(
            1,
            NewAuthMethod {
                user_id: user_1,
                method_type: "password".to_string(),
                external_id: None,
                metadata: None,
            },
        )
        .await
        .expect("create tenant 1 应成功");

        // tenant 2
        let user_2 = setup_user(&pool, 2).await;
        repo.create(
            2,
            NewAuthMethod {
                user_id: user_2,
                method_type: "password".to_string(),
                external_id: None,
                metadata: None,
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

    /// find_by_id 跨租户查询应返回 None（tenant_id 过滤生效）。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_id_cross_tenant_returns_none() {
        let pool = setup_db().await;
        let repo = DbnexusAuthMethodRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        let id = repo
            .create(
                1,
                NewAuthMethod {
                    user_id,
                    method_type: "password".to_string(),
                    external_id: None,
                    metadata: None,
                },
            )
            .await
            .expect("create 应成功");

        // 用 tenant 2 查询 tenant 1 的记录应返回 None
        let cross = repo.find_by_id(2, &id).await.expect("find_by_id 应成功");
        assert!(cross.is_none(), "跨租户查询应返回 None");
    }

    /// find_by_id 查询不存在的 ID 应返回 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_id_returns_none_for_nonexistent() {
        let pool = setup_db().await;
        let repo = DbnexusAuthMethodRepository::new(pool);

        let result = repo
            .find_by_id(1, "nonexistent-id")
            .await
            .expect("find_by_id 应成功");
        assert!(result.is_none(), "不存在的 ID 应返回 None");
    }

    /// find_by_user_id 查询无认证方式的用户应返回空列表。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_user_id_returns_empty_for_no_methods() {
        let pool = setup_db().await;
        let repo = DbnexusAuthMethodRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        let rows = repo
            .find_by_user_id(1, &user_id)
            .await
            .expect("find_by_user_id 应成功");
        assert!(rows.is_empty(), "无认证方式的用户应返回空列表");
    }

    /// list 分页查询：插入 3 条后 offset/limit 正确分页。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_paginates_correctly() {
        let pool = setup_db().await;
        let repo = DbnexusAuthMethodRepository::new(pool.clone());
        let user_repo = DbnexusUserRepository::new(pool.clone());

        for i in 0..3 {
            // 每次创建不同 username 的用户（避免 unique 约束冲突）
            let user_id = user_repo
                .create(
                    1,
                    NewUser {
                        username: format!("am-page-user-{}", i),
                        password_hash: "h".to_string(),
                        status: "active".to_string(),
                    },
                )
                .await
                .expect("创建 user 应成功");
            repo.create(
                1,
                NewAuthMethod {
                    user_id,
                    method_type: "password".to_string(),
                    external_id: None,
                    metadata: None,
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

    /// create 生成合法 UUID v4。
    #[tokio::test(flavor = "multi_thread")]
    async fn create_generates_valid_uuid_v4() {
        let pool = setup_db().await;
        let repo = DbnexusAuthMethodRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        let id = repo
            .create(
                1,
                NewAuthMethod {
                    user_id,
                    method_type: "password".to_string(),
                    external_id: None,
                    metadata: None,
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

    /// create 时 external_id 和 metadata 均为 None 也能正确插入。
    #[tokio::test(flavor = "multi_thread")]
    async fn create_with_all_optional_none() {
        let pool = setup_db().await;
        let repo = DbnexusAuthMethodRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        let id = repo
            .create(
                1,
                NewAuthMethod {
                    user_id: user_id.clone(),
                    method_type: "did".to_string(),
                    external_id: None,
                    metadata: None,
                },
            )
            .await
            .expect("create 应成功");

        let row = repo
            .find_by_id(1, &id)
            .await
            .expect("find_by_id 应成功")
            .expect("认证方式应存在");
        assert!(row.external_id.is_none());
        assert!(row.metadata.is_none());
        assert_eq!(row.method_type, "did");
    }

    /// list 空表查询应返回空列表。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_empty_returns_empty() {
        let pool = setup_db().await;
        let repo = DbnexusAuthMethodRepository::new(pool);

        let result = repo.list(1, 0, 100).await.expect("list 应成功");
        assert!(result.is_empty(), "空表应返回空列表");
    }
}
