//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `SocialBindingService` 实现模块（feature = "db-sqlite"）。
//!
//! 从 `mod.rs` 迁移以符合规则 25（mod.rs 接口隔离）：
//! impl 块与顶层 `fn provider_to_str` 不允许留在 `mod.rs`。
//!
//! 提供 `find_or_create` 语义：首次社交登录时自动创建绑定关系并生成新 `login_id`，
//! 后续登录返回已有 `login_id`（幂等）。

#[cfg(feature = "db-sqlite")]
use super::{SocialBindingService, SocialProvider, SocialUserInfo};

/// 将 `SocialProvider` enum 转换为字符串标识（用于 `social_bindings.provider` 列）。
///
/// 值与 spec social-login R-social-login-001 `SocialProvider` 变体一一对应：
/// - `Wechat` → `"wechat"`
/// - `Alipay` → `"alipay"`
/// - `WechatMiniApp` → `"wechat_mini_app"`
#[cfg(feature = "db-sqlite")]
pub(crate) fn provider_to_str(provider: &SocialProvider) -> &'static str {
    match provider {
        SocialProvider::Wechat => "wechat",
        SocialProvider::Alipay => "alipay",
        SocialProvider::WechatMiniApp => "wechat_mini_app",
    }
}

#[cfg(feature = "db-sqlite")]
impl SocialBindingService {
    /// 创建 `SocialBindingService` 实例。
    ///
    /// # 参数
    /// - `pool`: SQLite 连接池（用于查 `social_bindings` 表）
    /// - `dao`: 缓存层抽象（保留扩展点，当前未使用）
    pub fn new(pool: dbnexus::DbPool, dao: std::sync::Arc<dyn crate::dao::BulwarkDao>) -> Self {
        Self { pool, dao }
    }

    /// 查找或创建社交账号绑定关系。
    ///
    /// # 流程
    ///
    /// 1. 按 `(tenant_id, provider, provider_user_id)` 查询 `social_bindings` 表
    /// 2. 命中 → 返回已有 `login_id`（幂等）
    /// 3. 未命中 → 用单条 `INSERT ... COALESCE((SELECT MAX(login_id)+1 ...), 1)` 原子插入
    ///    4. INSERT 成功 → SELECT 返回新建的 `login_id`
    ///    5. INSERT 失败（UNIQUE 冲突，并发场景下另一事务已插入）→ SELECT 返回已有 `login_id`
    ///
    /// # login_id 生成策略
    ///
    /// `login_id = COALESCE((SELECT MAX(login_id) + 1 FROM social_bindings WHERE tenant_id = ?), 1)`
    ///（按租户自增）。用单条 INSERT 的子查询生成，避免显式事务的连接占用问题
    ///（dbnexus 的 `begin_transaction` 在 sea-orm 连接池中可能死锁）。
    /// UNIQUE(tenant_id, provider, provider_user_id) 约束保证幂等性。
    ///
    /// # 参数
    /// - `user`: 社交用户信息（含 provider / provider_user_id / union_id）
    /// - `tenant_id`: 租户 ID（0=默认租户）
    ///
    /// # 返回
    /// - `Ok(login_id)`: 已有或新建的 login_id（String，UUID）
    ///
    /// # 错误
    /// - `BulwarkError::Dao`: SQL 查询/插入失败
    pub async fn find_or_create(
        &self,
        user: &SocialUserInfo,
        tenant_id: i64,
    ) -> crate::error::BulwarkResult<String> {
        use sea_orm::{ConnectionTrait, DbBackend, Statement, Value};

        let provider_str = provider_to_str(&user.provider);

        // 1. 查询已有绑定
        let session = self.pool.get_session("admin").await.map_err(|e| {
            crate::error::BulwarkError::Dao(format!("social_binding 获取 session 失败: {}", e))
        })?;
        let conn = session.connection().map_err(|e| {
            crate::error::BulwarkError::Dao(format!("social_binding 获取 connection 失败: {}", e))
        })?;

        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT login_id FROM social_bindings \
             WHERE tenant_id = ? AND provider = ? AND provider_user_id = ?",
            vec![
                Value::BigInt(Some(tenant_id)),
                Value::String(Some(provider_str.to_string())),
                Value::String(Some(user.provider_user_id.clone())),
            ],
        );
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            crate::error::BulwarkError::Dao(format!("social_binding 查询失败: {}", e))
        })?;

        // 2. 命中 → 返回已有 login_id
        if let Some(row) = rows.into_iter().next() {
            let login_id: String = row.try_get::<String>("", "login_id").map_err(|e| {
                crate::error::BulwarkError::Dao(format!("login_id 读取失败: {}", e))
            })?;
            return Ok(login_id);
        }

        // 3. 未命中 → 单条 INSERT（login_id 用 UUID 生成，UNIQUE 约束保证幂等性）
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let new_login_id = uuid::Uuid::new_v4().to_string();

        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "INSERT INTO social_bindings \
             (tenant_id, login_id, provider, provider_user_id, union_id, created_at) \
             VALUES (?, ?, ?, ?, ?, ?)",
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
                return Err(crate::error::BulwarkError::Dao(format!(
                    "INSERT 未生效（rows_affected={}, 可能并发冲突）",
                    result.rows_affected()
                )));
            },
            Err(e) => {
                // 检查是否为 UNIQUE 约束冲突（SQLite 错误码 19 / 2067）
                let err_msg = e.to_string();
                if err_msg.contains("UNIQUE constraint failed")
                    || err_msg.contains("constraint failed")
                {
                    // 并发冲突，忽略错误，下面 SELECT 返回已有 login_id
                } else {
                    return Err(crate::error::BulwarkError::Dao(format!(
                        "INSERT social_bindings 失败: {}",
                        e
                    )));
                }
            },
        }

        // 4. SELECT 返回 login_id（INSERT 成功的新 login_id，或并发冲突时已有的 login_id）
        let stmt = Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT login_id FROM social_bindings \
             WHERE tenant_id = ? AND provider = ? AND provider_user_id = ?",
            vec![
                Value::BigInt(Some(tenant_id)),
                Value::String(Some(provider_str.to_string())),
                Value::String(Some(user.provider_user_id.clone())),
            ],
        );
        let rows = conn.query_all_raw(stmt).await.map_err(|e| {
            crate::error::BulwarkError::Dao(format!("INSERT 后 SELECT login_id 失败: {}", e))
        })?;
        let row = rows.into_iter().next().ok_or_else(|| {
            crate::error::BulwarkError::Dao(
                "INSERT 后 SELECT 返回空（绑定未创建且查询失败）".into(),
            )
        })?;
        let login_id: String = row
            .try_get::<String>("", "login_id")
            .map_err(|e| crate::error::BulwarkError::Dao(format!("login_id 读取失败: {}", e)))?;

        Ok(login_id)
    }
}
