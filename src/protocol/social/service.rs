// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `SocialBindingService` 实现（任意 db 后端 feature；接口隔离：impl 不放 `mod.rs`）。
//!
//! `find_or_create` 幂等：首次社交登录创建绑定并生成新 `login_id`，后续返回已有值。
//!
//! SQL 经 `GarrisonDao` 的 `find_social_binding` / `insert_social_binding` 委托执行（由 `GarrisonDaoDbnexus` 实现），业务层不直接持有 `DbPool`。

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
use super::{SocialBindingService, SocialUserInfo};

/// UNIQUE 冲突的多后端错误消息特征（子串匹配，单点维护）：`GarrisonDao` 折叠驱动错误为 `Dao(String)`、SQLSTATE 不可达，
/// 只能按消息子串识别（SQLite / PostgreSQL / MySQL / 通用 23505）；驱动文本变更时 fail-closed 透传原始错误（不误判冲突、
/// 不返回旧 login_id），新增后端在此补齐特征串，由 `social::tests` 冲突用例覆盖。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub(crate) mod unique_conflict_markers {
    pub const SQLITE: &str = "UNIQUE constraint failed";
    pub const POSTGRES: &str = "duplicate key value violates unique constraint";
    pub const MYSQL: &str = "Duplicate entry";
    pub const SQLSTATE_UNIQUE: &str = "23505";
}

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
impl SocialBindingService {
    /// 创建 `SocialBindingService` 实例（`dao` 通常为 `GarrisonDaoDbnexus`）。
    pub fn new(dao: std::sync::Arc<dyn crate::dao::GarrisonDao>) -> Self {
        Self { dao }
    }

    /// 查找或创建社交账号绑定关系。
    ///
    /// 按 `(tenant_id, provider, provider_user_id)` 查询命中即返回已有 `login_id`；未命中则
    /// 单条 INSERT（`login_id` 用 UUID v4）返回新值；INSERT 撞 UNIQUE（并发下另一事务已插入）回查返回已有值。
    ///
    /// `UNIQUE(tenant_id, provider, provider_user_id)` 约束保证幂等；SQL 失败返回 `GarrisonError::Dao`。
    pub async fn find_or_create(
        &self,
        user: &SocialUserInfo,
        tenant_id: i64,
    ) -> crate::error::GarrisonResult<String> {
        let provider_str = user.provider.as_str();

        if let Some(login_id) = self
            .dao
            .find_social_binding(tenant_id, provider_str, &user.provider_user_id)
            .await?
        {
            return Ok(login_id);
        }

        // 系统时钟早于 1970（如未同步 NTP 的 VM/嵌入式设备）时 duration_since 失败：0 是自然钳位值
        // （时间戳不允许为负），显式 warn 留痕便于排查，不再无告警吞错。
        let created_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or_else(|e| {
                tracing::warn!(
                    "system clock before UNIX_EPOCH, created_at falls back to 0: {}",
                    e
                );
                0
            });

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
                // 并发下另一事务已插入相同绑定：按特征串判 UNIQUE 冲突（特征串单点维护于
                // `unique_conflict_markers`，驱动文本变更时 fail-closed 透传原始错误）。
                use unique_conflict_markers as markers;
                let err_msg = e.to_string();
                if err_msg.contains(markers::SQLITE)
                    || err_msg.contains(markers::POSTGRES)
                    || err_msg.contains(markers::MYSQL)
                    || err_msg.contains(markers::SQLSTATE_UNIQUE)
                {
                    self.dao
                        .find_social_binding(tenant_id, provider_str, &user.provider_user_id)
                        .await?
                        .ok_or_else(|| {
                            crate::error::GarrisonError::Dao(
                                "dao-social-binding-insert-select::".into(),
                            )
                        })
                } else {
                    Err(e)
                }
            },
        }
    }
}
