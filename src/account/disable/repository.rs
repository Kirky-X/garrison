//! 封禁库 trait 与持久化数据模型定义。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 本模块仅定义接口契约（`DisableEntry` struct + `DisableRepository` trait），
//! 不包含实现。`DefaultDisableRepository` 实现见 T016-T018。

use crate::error::BulwarkResult;
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// 封禁条目，记录单个 login_id 在指定 service 上的封禁状态。
///
/// 持久化为 JSON 存储在 DAO 中，key 格式 `disable:{service}:{login_id}`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisableEntry {
    /// 被封禁的登录主体标识。
    pub login_id: String,
    /// 封禁服务名称（如 "default"、"payment"），支持多服务独立封禁。
    pub service: String,
    /// 封禁到期时间；`None` 表示永久封禁。
    pub until: Option<DateTime<Utc>>,
    /// 封禁级别（0=普通封禁，1+=阶梯封禁，业务方可据此分级阻断）。
    pub level: u32,
    /// 封禁创建时间。
    pub created_at: DateTime<Utc>,
}

/// 封禁库 trait，提供账号封禁/解封/查询能力。
///
/// 独立于 [`BulwarkDao`](crate::dao::BulwarkDao) trait，通过持有 `Arc<dyn BulwarkDao>` 委托实现。
/// key 格式：`disable:{service}:{login_id}`，value 为 [`DisableEntry`] 的 JSON 序列化。
#[async_trait]
pub trait DisableRepository: Send + Sync {
    /// 封禁指定 login_id 的指定 service。
    ///
    /// # 参数
    /// - `login_id`: 被封禁的登录主体标识。
    /// - `service`: 封禁服务名称。
    /// - `until`: 封禁到期时间；`None` 表示永久封禁。
    /// - `level`: 封禁级别（0=普通，1+=阶梯）。
    /// - `duration_secs`: DAO 存储 TTL（秒）；0 表示永久驻留（不自动过期）。
    async fn disable(
        &self,
        login_id: &str,
        service: &str,
        until: Option<DateTime<Utc>>,
        level: u32,
        duration_secs: u64,
    ) -> BulwarkResult<()>;

    /// 解封指定 login_id 的指定 service。
    ///
    /// # 参数
    /// - `login_id`: 被解封的登录主体标识。
    /// - `service`: 封禁服务名称。
    async fn untie_disable(&self, login_id: &str, service: &str) -> BulwarkResult<()>;

    /// 查询指定 login_id 的指定 service 是否被封禁。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `service`: 封禁服务名称。
    ///
    /// # 返回
    /// - `Ok(true)`: 已封禁。
    /// - `Ok(false)`: 未封禁。
    async fn is_disable(&self, login_id: &str, service: &str) -> BulwarkResult<bool>;

    /// 获取封禁到期时间。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `service`: 封禁服务名称。
    ///
    /// # 返回
    /// - `Ok(Some(time))`: 定时解封时间。
    /// - `Ok(None)`: 永久封禁或未封禁。
    async fn get_disable_time(
        &self,
        login_id: &str,
        service: &str,
    ) -> BulwarkResult<Option<DateTime<Utc>>>;

    /// 获取封禁级别。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    /// - `service`: 封禁服务名称。
    ///
    /// # 返回
    /// - `Ok(level)`: 封禁级别（0=普通，1+=阶梯）。
    /// - `Ok(0)`: 未封禁。
    async fn get_disable_level(&self, login_id: &str, service: &str) -> BulwarkResult<u32>;
}
