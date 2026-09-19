// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `SocialBindingService` 实现模块（任意 db 后端 feature）。
//!
//! mod.rs 接口隔离：impl 块不允许留在 `mod.rs`。
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

/// UNIQUE 约束冲突的多后端错误消息特征（子串匹配，单点维护）。
///
/// # 为什么用消息子串而非错误类型/SQLSTATE
///
/// `GarrisonDao` 抽象层把驱动错误折叠为 `GarrisonError::Dao(String)`
/// （如 `sqlx::Error::Database` 的 SQLSTATE 信息在此层不可达），
/// 故只能以错误消息子串识别 UNIQUE 冲突。已知特征（按后端）：
///
/// - SQLite: `UNIQUE constraint failed: <table>(<cols>)`
/// - PostgreSQL: `duplicate key value violates unique constraint "<name>"`（SQLSTATE 23505）
/// - MySQL: `Duplicate entry '<value>' for key '<name>'`
/// - 通用：任意携带 SQLSTATE `23505` 的消息
///
/// # 风险与失效模式（fail-closed）
///
/// 驱动版本/本地化变更若改变消息文本，冲突分支会静默失效——退化为
/// 把原始 `Dao` 错误原样透传给调用方（不误判为冲突、不返回旧 login_id），
/// 不会造成错误放行。新增后端支持时在此补齐对应特征串，并由
/// `social::tests` 的冲突用例（`find_or_create_*_unique_conflict_*`）覆盖。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub(crate) mod unique_conflict_markers {
    /// SQLite UNIQUE 冲突消息特征。
    pub const SQLITE: &str = "UNIQUE constraint failed";
    /// PostgreSQL UNIQUE 冲突消息特征。
    pub const POSTGRES: &str = "duplicate key value violates unique constraint";
    /// MySQL UNIQUE 冲突消息特征。
    pub const MYSQL: &str = "Duplicate entry";
    /// 通用 SQLSTATE 23505（UNIQUE 约束冲突）特征。
    pub const SQLSTATE_UNIQUE: &str = "23505";
}

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
    /// 4. INSERT 成功 → 返回新建的 `login_id`
    /// 5. INSERT 失败（UNIQUE 约束冲突，并发场景下另一事务已插入）→ SELECT 返回已有 `login_id`
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
        //
        // 时钟异常处理（不再静默 unwrap_or(0)）：`duration_since(UNIX_EPOCH)`
        // 仅在系统时钟早于 1970（未同步 NTP 的 VM/嵌入式设备）时失败。
        // 语义上 0 是该情形的自然钳位值（时间戳不允许为负），故保留 0
        // 兜底，但显式 warn 留痕，便于排查时钟配置问题——不再无告警吞错。
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
                // 检查是否为 UNIQUE 约束冲突（并发场景下另一事务已插入相同绑定）
                //
                // 特征串单点维护于 [`unique_conflict_markers`]（见模块注释：
                // 驱动文本变更时失效模式为 fail-closed 透传原始错误）。
                use unique_conflict_markers as markers;
                let err_msg = e.to_string();
                if err_msg.contains(markers::SQLITE)
                    || err_msg.contains(markers::POSTGRES)
                    || err_msg.contains(markers::MYSQL)
                    || err_msg.contains(markers::SQLSTATE_UNIQUE)
                {
                    // 并发冲突，重新查询返回已有 login_id
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
