//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `SocialBindingService` 实现模块（任意 db 后端 feature）。
//!
//! 从 `mod.rs` 迁移以符合规则 25（mod.rs 接口隔离）：
//! impl 块不允许留在 `mod.rs`。
//!
//! 提供 `find_or_create` 语义：首次社交登录时自动创建绑定关系并生成新 `login_id`，
//! 后续登录返回已有 `login_id`（幂等）。
//!
//! # 多后端支持
//!
//! 通过 [`crate::dao::repository::convert_placeholders`] 动态适配 SQL 占位符：
//! - SQLite：保留 `?`
//! - PostgreSQL：转换为 `$1`, `$2`, ...
//! - MySQL：保留 `?`
//!
//! 通过 `conn.get_database_backend()` 动态获取后端类型，
//! 同一份 SQL 代码可在 SQLite/PostgreSQL/MySQL 任意后端运行。

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
use super::{SocialBindingService, SocialUserInfo};

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
impl SocialBindingService {
    /// 创建 `SocialBindingService` 实例。
    ///
    /// # 参数
    /// - `pool`: 数据库连接池（SQLite/PostgreSQL/MySQL 任意后端，用于查 `social_bindings` 表）
    /// - `dao`: 缓存层抽象（保留扩展点，当前未使用）
    pub fn new(pool: dbnexus::DbPool, dao: std::sync::Arc<dyn crate::dao::GarrisonDao>) -> Self {
        Self { pool, dao }
    }

    /// 查找或创建社交账号绑定关系。
    ///
    /// # 流程
    ///
    /// 1. 按 `(tenant_id, provider, provider_user_id)` 查询 `social_bindings` 表
    /// 2. 命中 → 返回已有 `login_id`（幂等）
    /// 3. 未命中 → 用单条 `INSERT` 插入新绑定，`login_id` 用 UUID 生成
    ///    4. INSERT 成功 → SELECT 返回新建的 `login_id`
    ///    5. INSERT 失败（UNIQUE 冲突，并发场景下另一事务已插入）→ SELECT 返回已有 `login_id`
    ///
    /// # login_id 生成策略
    ///
    /// `login_id = uuid::Uuid::new_v4()`（UUID v4，全局唯一）。
    /// `UNIQUE(tenant_id, provider, provider_user_id)` 约束保证幂等性。
    ///
    /// # 多后端占位符适配
    ///
    /// SQL 模板用 `?` 占位符编写，通过 [`crate::dao::repository::convert_placeholders`]
    /// 在 PostgreSQL 后端自动转换为 `$1`, `$2`, ...，SQLite/MySQL 保持 `?` 不变。
    ///
    /// # 参数
    /// - `user`: 社交用户信息（含 provider 字符串 / provider_user_id / union_id）
    /// - `tenant_id`: 租户 ID（0=默认租户）
    ///
    /// # 返回
    /// - `Ok(login_id)`: 已有或新建的 login_id（String，UUID）
    ///
    /// # 错误
    /// - `GarrisonError::Dao`: SQL 查询/插入失败
    pub async fn find_or_create(
        &self,
        user: &SocialUserInfo,
        tenant_id: i64,
    ) -> crate::error::GarrisonResult<String> {
        use sea_orm::{ConnectionTrait, Statement, Value};

        // provider 字段已是 String，直接用 as_str()
        let provider_str = user.provider.as_str();

        // 1. 查询已有绑定
        let session = self.pool.get_session("admin").await.map_err(|e| {
            crate::error::GarrisonError::Dao(format!("dao-social-binding-get-session::{}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            crate::error::GarrisonError::Dao(format!("dao-social-binding-get-conn::{}", e))
        })?;

        // 动态获取后端类型，适配 SQLite/PostgreSQL/MySQL
        let backend = conn.get_database_backend();

        // 2. 查询已有绑定（用 convert_placeholders 适配占位符）
        let sql_select = "SELECT login_id FROM social_bindings \
             WHERE tenant_id = ? AND provider = ? AND provider_user_id = ?";
        let sql_select = crate::dao::repository::convert_placeholders(sql_select, backend);
        let stmt = Statement::from_sql_and_values(
            backend,
            sql_select.as_str(),
            vec![
                Value::BigInt(Some(tenant_id)),
                Value::String(Some(provider_str.to_string())),
                Value::String(Some(user.provider_user_id.clone())),
            ],
        );
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            crate::error::GarrisonError::Dao(format!("dao-social-binding-query::{}", e))
        })?;

        // 3. 命中 → 返回已有 login_id
        if let Some(row) = rows.into_iter().next() {
            let login_id: String = row.try_get::<String>("", "login_id").map_err(|e| {
                crate::error::GarrisonError::Dao(format!("dao-social-binding-login-id-read::{}", e))
            })?;
            return Ok(login_id);
        }

        // 4. 未命中 → INSERT（login_id 用 UUID 生成，UNIQUE 约束保证幂等性）
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let new_login_id = uuid::Uuid::new_v4().to_string();

        let sql_insert = "INSERT INTO social_bindings \
             (tenant_id, login_id, provider, provider_user_id, union_id, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)";
        let sql_insert = crate::dao::repository::convert_placeholders(sql_insert, backend);
        let stmt = Statement::from_sql_and_values(
            backend,
            sql_insert.as_str(),
            vec![
                Value::BigInt(Some(tenant_id)),
                Value::String(Some(new_login_id)),
                Value::String(Some(provider_str.to_string())),
                Value::String(Some(user.provider_user_id.clone())),
                match user.union_id.clone() {
                    Some(s) => Value::String(Some(s)),
                    None => Value::String(None),
                },
                Value::BigInt(Some(created_at)),
            ],
        );
        // INSERT 可能因 UNIQUE 约束失败（并发场景下另一事务已插入相同绑定），
        // 此时忽略错误，下面 SELECT 会返回已有 login_id。
        match conn.execute_raw(stmt).await {
            Ok(result) if result.rows_affected() == 1 => {
                // INSERT 成功
            },
            Ok(result) => {
                return Err(crate::error::GarrisonError::Dao(format!(
                    "dao-social-binding-insert-select::{}",
                    result.rows_affected()
                )));
            },
            Err(e) => {
                // 检查是否为 UNIQUE 约束冲突（并发场景下另一事务已插入相同绑定）
                //
                // 多后端错误消息特征：
                // - SQLite: "UNIQUE constraint failed: social_bindings(...)"
                // - PostgreSQL: "duplicate key value violates unique constraint" + SQLSTATE 23505
                // - MySQL: "Duplicate entry '...' for key '...'"
                //
                // 同时匹配 SQLSTATE code 23505（PostgreSQL unique_violation），
                // 比 `contains("constraint failed")` 更精确（后者会误匹配 CHECK/FOREIGN KEY 等其他约束冲突）。
                let err_msg = e.to_string();
                if err_msg.contains("UNIQUE constraint failed")
                    || err_msg.contains("duplicate key value violates unique constraint")
                    || err_msg.contains("Duplicate entry")
                    || err_msg.contains("23505")
                {
                    // 并发冲突，忽略错误，下面 SELECT 返回已有 login_id
                } else {
                    return Err(crate::error::GarrisonError::Dao(format!(
                        "dao-social-binding-insert-select::{}",
                        e
                    )));
                }
            },
        }

        // 5. SELECT 返回 login_id（INSERT 成功的新 login_id，或并发冲突时已有的 login_id）
        let sql_select = "SELECT login_id FROM social_bindings \
             WHERE tenant_id = ? AND provider = ? AND provider_user_id = ?";
        let sql_select = crate::dao::repository::convert_placeholders(sql_select, backend);
        let stmt = Statement::from_sql_and_values(
            backend,
            sql_select.as_str(),
            vec![
                Value::BigInt(Some(tenant_id)),
                Value::String(Some(provider_str.to_string())),
                Value::String(Some(user.provider_user_id.clone())),
            ],
        );
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            crate::error::GarrisonError::Dao(format!("dao-social-binding-insert-select::{}", e))
        })?;
        let row = rows.into_iter().next().ok_or_else(|| {
            crate::error::GarrisonError::Dao("dao-social-binding-insert-select".into())
        })?;
        let login_id: String = row.try_get::<String>("", "login_id").map_err(|e| {
            crate::error::GarrisonError::Dao(format!("dao-social-binding-login-id-read::{}", e))
        })?;

        Ok(login_id)
    }
}
