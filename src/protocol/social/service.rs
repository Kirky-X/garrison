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
//! # 数据访问
//!
//! SQL 操作通过 `GarrisonDao` trait 的 `find_social_binding` / `insert_social_binding`
//! 方法委托执行（由 `GarrisonDaoDbnexus` 实现），业务层不再直接持有 `DbPool`。

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
use super::{SocialBindingService, SocialUserInfo};

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
impl SocialBindingService {
    /// 创建 `SocialBindingService` 实例。
    ///
    /// # 参数
    /// - `dao`: 数据访问抽象（通常为 `GarrisonDaoDbnexus`，支持 SQL 操作）
    pub fn new(dao: std::sync::Arc<dyn crate::dao::GarrisonDao>) -> Self {
        Self { dao }
    }

    /// 查找或创建社交账号绑定关系。
    ///
    /// # 流程
    ///
    /// 1. 按 `(tenant_id, provider, provider_user_id)` 查询 `social_bindings` 表
    /// 2. 命中 → 返回已有 `login_id`（幂等）
    /// 3. 未命中 → 用单条 INSERT 插入新绑定，`login_id` 用 UUID 生成
    ///    4. INSERT 成功 → 返回新建的 `login_id`
    ///    5. INSERT 失败（UNIQUE 约束冲突，并发场景下另一事务已插入）→ SELECT 返回已有 `login_id`
    ///
    /// # login_id 生成策略
    ///
    /// `login_id = uuid::Uuid::new_v4()`（UUID v4，全局唯一）。
    /// `UNIQUE(tenant_id, provider, provider_user_id)` 约束保证幂等性。
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
        let provider_str = user.provider.as_str();

        // 1. 查询已有绑定
        if let Some(login_id) = self
            .dao
            .find_social_binding(tenant_id, provider_str, &user.provider_user_id)
            .await?
        {
            return Ok(login_id);
        }

        // 2. 未命中 → INSERT（login_id 用 UUID 生成，UNIQUE 约束保证幂等性）
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        let new_login_id = uuid::Uuid::new_v4().to_string();

        match self
            .dao
            .insert_social_binding(
                tenant_id,
                &new_login_id,
                provider_str,
                &user.provider_user_id,
                user.union_id.as_deref(),
                created_at,
            )
            .await
        {
            Ok(()) => Ok(new_login_id),
            Err(e) => {
                // 检查是否为 UNIQUE 约束冲突（并发场景下另一事务已插入相同绑定）
                //
                // 多后端错误消息特征：
                // - SQLite: "UNIQUE constraint failed: social_bindings(...)"
                // - PostgreSQL: "duplicate key value violates unique constraint" + SQLSTATE 23505
                // - MySQL: "Duplicate entry '...' for key '...'"
                let err_msg = e.to_string();
                if err_msg.contains("UNIQUE constraint failed")
                    || err_msg.contains("duplicate key value violates unique constraint")
                    || err_msg.contains("Duplicate entry")
                    || err_msg.contains("23505")
                {
                    // 并发冲突，重新查询返回已有 login_id
                    self.dao
                        .find_social_binding(tenant_id, provider_str, &user.provider_user_id)
                        .await?
                        .ok_or_else(|| {
                            crate::error::GarrisonError::Dao(
                                "dao-social-binding-insert-select".into(),
                            )
                        })
                } else {
                    Err(e)
                }
            },
        }
    }
}
