//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! DbnexusUserExtRepository 实现（app_user_ext 表）。

use super::{v_i64, v_opt_str, v_str, DbnexusUserExtRepository};
use crate::dao::dao_session;
use crate::dao::repository::{make_statement, UserExtRepository, UserExtRow};
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use dbnexus::DbPool;
use sea_orm::{ConnectionTrait, QueryResult};

impl DbnexusUserExtRepository {
    /// 创建实例。
    pub fn new(pool: DbPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl UserExtRepository for DbnexusUserExtRepository {
    async fn find_by_user_id(
        &self,
        tenant_id: i64,
        user_id: &str,
    ) -> GarrisonResult<Vec<UserExtRow>> {
        dao_session!(self.pool, "dao-app-user-ext-find-by-user-id", session, conn);
        let sql = "SELECT id, user_id, field_key, field_value, field_type, created_at, updated_at, tenant_id \
                   FROM app_user_ext WHERE tenant_id = ? AND user_id = ?";
        let stmt = make_statement(conn, sql, vec![v_i64(tenant_id), v_str(user_id)]);
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-ext-find-by-user-id-query::{}", e))
        })?;
        rows.iter().map(parse_user_ext_row).collect()
    }

    async fn find_by_user_and_key(
        &self,
        tenant_id: i64,
        user_id: &str,
        field_key: &str,
    ) -> GarrisonResult<Option<UserExtRow>> {
        dao_session!(
            self.pool,
            "dao-app-user-ext-find-by-user-and-key",
            session,
            conn
        );
        let sql = "SELECT id, user_id, field_key, field_value, field_type, created_at, updated_at, tenant_id \
                   FROM app_user_ext WHERE tenant_id = ? AND user_id = ? AND field_key = ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_str(user_id), v_str(field_key)],
        );
        let row = conn.query_one_raw(stmt).await.map_err(|e| {
            GarrisonError::Dao(format!(
                "dao-app-user-ext-find-by-user-and-key-query::{}",
                e
            ))
        })?;
        row.map(|r| parse_user_ext_row(&r)).transpose()
    }

    async fn upsert(
        &self,
        tenant_id: i64,
        user_id: &str,
        field_key: &str,
        field_value: Option<String>,
        field_type: &str,
    ) -> GarrisonResult<()> {
        dao_session!(self.pool, "dao-app-user-ext-upsert", session, conn);
        // UPSERT，依赖 UK(user_id, field_key)。
        // 插入时生成新 UUID；冲突时更新 field_value/field_type/updated_at（保留原 id/created_at）。
        // SQLite/Postgres 使用 ON CONFLICT ... DO UPDATE SET ... = excluded.field；
        // MySQL 使用 ON DUPLICATE KEY UPDATE ... = VALUES(field)（MySQL 不支持 ON CONFLICT 语法）。
        let new_id = uuid::Uuid::new_v4().to_string();
        let sql = if conn.get_database_backend() == sea_orm::DbBackend::MySql {
            "INSERT INTO app_user_ext (id, user_id, field_key, field_value, field_type, tenant_id) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON DUPLICATE KEY UPDATE \
             field_value = VALUES(field_value), \
             field_type = VALUES(field_type), \
             updated_at = CURRENT_TIMESTAMP"
        } else {
            "INSERT INTO app_user_ext (id, user_id, field_key, field_value, field_type, tenant_id) \
             VALUES (?, ?, ?, ?, ?, ?) \
             ON CONFLICT(user_id, field_key) DO UPDATE SET \
             field_value = excluded.field_value, \
             field_type = excluded.field_type, \
             updated_at = CURRENT_TIMESTAMP"
        };
        let stmt = make_statement(
            conn,
            sql,
            vec![
                v_str(&new_id),
                v_str(user_id),
                v_str(field_key),
                v_opt_str(&field_value),
                v_str(field_type),
                v_i64(tenant_id),
            ],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-user-ext-upsert::{}", e)))?;
        Ok(())
    }

    async fn delete(&self, tenant_id: i64, user_id: &str, field_key: &str) -> GarrisonResult<()> {
        dao_session!(self.pool, "dao-app-user-ext-delete", session, conn);
        let sql = "DELETE FROM app_user_ext \
                   WHERE tenant_id = ? AND user_id = ? AND field_key = ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_str(user_id), v_str(field_key)],
        );
        conn.execute_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-user-ext-delete-delete::{}", e)))?;
        Ok(())
    }

    async fn list(
        &self,
        tenant_id: i64,
        offset: i64,
        limit: i64,
    ) -> GarrisonResult<Vec<UserExtRow>> {
        dao_session!(self.pool, "dao-app-user-ext-list", session, conn);
        let sql = "SELECT id, user_id, field_key, field_value, field_type, created_at, updated_at, tenant_id \
                   FROM app_user_ext WHERE tenant_id = ? LIMIT ? OFFSET ?";
        let stmt = make_statement(
            conn,
            sql,
            vec![v_i64(tenant_id), v_i64(limit), v_i64(offset)],
        );
        let rows = conn
            .query_all_raw(stmt)
            .await
            .map_err(|e| GarrisonError::Dao(format!("dao-app-user-ext-list-query::{}", e)))?;
        rows.iter().map(parse_user_ext_row).collect()
    }
}

/// 解析 app_user_ext 行。
fn parse_user_ext_row(row: &QueryResult) -> GarrisonResult<UserExtRow> {
    Ok(UserExtRow {
        id: row
            .try_get("", "id")
            .map_err(|e| GarrisonError::Dao(format!("dao-app-user-ext-row-parse-id::{}", e)))?,
        user_id: row.try_get("", "user_id").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-ext-row-parse-user-id::{}", e))
        })?,
        field_key: row.try_get("", "field_key").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-ext-row-parse-field-key::{}", e))
        })?,
        field_value: row.try_get("", "field_value").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-ext-row-parse-field-value::{}", e))
        })?,
        field_type: row.try_get("", "field_type").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-ext-row-parse-field-type::{}", e))
        })?,
        created_at: row.try_get("", "created_at").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-ext-row-parse-created-at::{}", e))
        })?,
        updated_at: row.try_get("", "updated_at").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-ext-row-parse-updated-at::{}", e))
        })?,
        tenant_id: row.try_get("", "tenant_id").map_err(|e| {
            GarrisonError::Dao(format!("dao-app-user-ext-row-parse-tenant-id::{}", e))
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
                    username: format!("ext-user-{}", tenant_id),
                    password_hash: "h".to_string(),
                    status: "active".to_string(),
                },
            )
            .await
            .expect("创建 user 应成功")
    }

    /// upsert 插入扩展字段后 find_by_user_id 应返回该字段。
    #[tokio::test(flavor = "multi_thread")]
    async fn upsert_inserts_and_finds_by_user_id() {
        let pool = setup_db().await;
        let repo = DbnexusUserExtRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        repo.upsert(
            1,
            &user_id,
            "email",
            Some("alice@example.com".to_string()),
            "string",
        )
        .await
        .expect("upsert 应成功");

        let rows = repo
            .find_by_user_id(1, &user_id)
            .await
            .expect("find_by_user_id 应成功");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].user_id, user_id);
        assert_eq!(rows[0].field_key, "email");
        assert_eq!(rows[0].field_value.as_deref(), Some("alice@example.com"));
        assert_eq!(rows[0].field_type, "string");
        assert_eq!(rows[0].tenant_id, 1);
    }

    /// upsert 对同一 user_id + field_key 执行两次应更新而非插入新记录。
    #[tokio::test(flavor = "multi_thread")]
    async fn upsert_updates_existing_field() {
        let pool = setup_db().await;
        let repo = DbnexusUserExtRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        // 第一次插入
        repo.upsert(1, &user_id, "phone", Some("12345".to_string()), "string")
            .await
            .expect("首次 upsert 应成功");

        // 第二次 upsert 应更新
        repo.upsert(1, &user_id, "phone", Some("67890".to_string()), "string")
            .await
            .expect("二次 upsert 应成功");

        let rows = repo
            .find_by_user_id(1, &user_id)
            .await
            .expect("find_by_user_id 应成功");
        assert_eq!(rows.len(), 1, "upsert 不应新增记录");
        assert_eq!(rows[0].field_value.as_deref(), Some("67890"), "值应被更新");
    }

    /// upsert 更新 field_type 字段。
    #[tokio::test(flavor = "multi_thread")]
    async fn upsert_updates_field_type() {
        let pool = setup_db().await;
        let repo = DbnexusUserExtRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        repo.upsert(1, &user_id, "age", Some("30".to_string()), "string")
            .await
            .expect("首次 upsert 应成功");
        repo.upsert(1, &user_id, "age", Some("30".to_string()), "number")
            .await
            .expect("二次 upsert 应成功");

        let row = repo
            .find_by_user_and_key(1, &user_id, "age")
            .await
            .expect("find_by_user_and_key 应成功")
            .expect("字段应存在");
        assert_eq!(row.field_type, "number", "field_type 应被更新");
    }

    /// upsert 插入 field_value 为 None 的字段。
    #[tokio::test(flavor = "multi_thread")]
    async fn upsert_with_none_field_value() {
        let pool = setup_db().await;
        let repo = DbnexusUserExtRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        repo.upsert(1, &user_id, "avatar", None, "string")
            .await
            .expect("upsert None 应成功");

        let row = repo
            .find_by_user_and_key(1, &user_id, "avatar")
            .await
            .expect("find 应成功")
            .expect("字段应存在");
        assert!(row.field_value.is_none(), "field_value 应为 None");
    }

    /// find_by_user_and_key 按 user_id + field_key 精确查询。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_user_and_key_returns_specific_field() {
        let pool = setup_db().await;
        let repo = DbnexusUserExtRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        // 插入多个字段
        repo.upsert(1, &user_id, "email", Some("a@b.com".to_string()), "string")
            .await
            .expect("upsert email 应成功");
        repo.upsert(1, &user_id, "phone", Some("123".to_string()), "string")
            .await
            .expect("upsert phone 应成功");

        let row = repo
            .find_by_user_and_key(1, &user_id, "phone")
            .await
            .expect("find_by_user_and_key 应成功")
            .expect("字段应存在");
        assert_eq!(row.field_key, "phone");
        assert_eq!(row.field_value.as_deref(), Some("123"));
    }

    /// find_by_user_and_key 查询不存在的 key 应返回 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_user_and_key_returns_none_for_nonexistent() {
        let pool = setup_db().await;
        let repo = DbnexusUserExtRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        let result = repo
            .find_by_user_and_key(1, &user_id, "nonexistent")
            .await
            .expect("find_by_user_and_key 应成功");
        assert!(result.is_none(), "不存在的 key 应返回 None");
    }

    /// find_by_user_id 查询无扩展字段的用户应返回空列表。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_user_id_returns_empty_for_no_fields() {
        let pool = setup_db().await;
        let repo = DbnexusUserExtRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        let rows = repo
            .find_by_user_id(1, &user_id)
            .await
            .expect("find_by_user_id 应成功");
        assert!(rows.is_empty(), "无扩展字段的用户应返回空列表");
    }

    /// delete 删除后 find_by_user_and_key 返回 None；重复删除不报错。
    #[tokio::test(flavor = "multi_thread")]
    async fn delete_is_idempotent() {
        let pool = setup_db().await;
        let repo = DbnexusUserExtRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        repo.upsert(1, &user_id, "temp", Some("val".to_string()), "string")
            .await
            .expect("upsert 应成功");

        repo.delete(1, &user_id, "temp")
            .await
            .expect("首次 delete 应成功");
        let after = repo
            .find_by_user_and_key(1, &user_id, "temp")
            .await
            .expect("find 应成功");
        assert!(after.is_none(), "删除后应查不到");

        // 幂等：再次删除
        repo.delete(1, &user_id, "temp")
            .await
            .expect("幂等 delete 应成功");
    }

    /// list 分页查询：插入 3 条记录后 offset/limit 正确分页。
    #[tokio::test(flavor = "multi_thread")]
    async fn list_paginates_correctly() {
        let pool = setup_db().await;
        let repo = DbnexusUserExtRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        for i in 0..3 {
            repo.upsert(
                1,
                &user_id,
                &format!("key-{}", i),
                Some(format!("val-{}", i)),
                "string",
            )
            .await
            .expect("upsert 应成功");
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
        let repo = DbnexusUserExtRepository::new(pool.clone());

        let user_1 = setup_user(&pool, 1).await;
        repo.upsert(1, &user_1, "email", Some("t1@x.com".to_string()), "string")
            .await
            .expect("upsert tenant 1 应成功");

        let user_2 = setup_user(&pool, 2).await;
        repo.upsert(2, &user_2, "email", Some("t2@x.com".to_string()), "string")
            .await
            .expect("upsert tenant 2 应成功");

        let list_1 = repo.list(1, 0, 100).await.expect("list tenant 1 应成功");
        let list_2 = repo.list(2, 0, 100).await.expect("list tenant 2 应成功");
        assert_eq!(list_1.len(), 1, "tenant 1 应有 1 条");
        assert_eq!(list_2.len(), 1, "tenant 2 应有 1 条");
        assert_eq!(list_1[0].tenant_id, 1);
        assert_eq!(list_2[0].tenant_id, 2);
    }

    /// find_by_user_and_key 跨租户查询应返回 None。
    #[tokio::test(flavor = "multi_thread")]
    async fn find_by_user_and_key_cross_tenant_returns_none() {
        let pool = setup_db().await;
        let repo = DbnexusUserExtRepository::new(pool.clone());
        let user_id = setup_user(&pool, 1).await;

        repo.upsert(1, &user_id, "email", Some("x@y.com".to_string()), "string")
            .await
            .expect("upsert 应成功");

        // 用 tenant 2 查询 tenant 1 的字段应返回 None
        let cross = repo
            .find_by_user_and_key(2, &user_id, "email")
            .await
            .expect("find 应成功");
        assert!(cross.is_none(), "跨租户查询应返回 None");
    }
}
