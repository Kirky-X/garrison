//! 会话模块，提供 BulwarkSession 会话模型。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `SaSession`，
//! 提供会话级数据存储与 Token 列表管理。

use crate::error::BulwarkResult;
use serde::{Deserialize, Serialize};

/// 会话模型，表示一个用户会话。
///
/// [借鉴 Sa-Token] 对应 `SaSession`，存储会话级数据与关联 Token。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulwarkSession {
    /// 会话 ID。
    pub id: String,

    /// 会话关联的登录主体标识。
    pub login_id: i64,

    /// 会话创建时间戳（Unix 秒）。
    pub created_at: i64,

    /// 会话最后活跃时间戳（Unix 秒）。
    pub last_active_at: i64,
}

impl BulwarkSession {
    /// 创建新的会话实例。
    ///
    /// # 参数
    /// - `id`: 会话 ID。
    /// - `login_id`: 登录主体标识。
    pub fn new(id: impl Into<String>, login_id: i64) -> Self {
        todo!()
    }

    /// 检查会话是否过期。
    pub fn is_expired(&self) -> bool {
        todo!()
    }

    /// 刷新会话最后活跃时间。
    pub fn refresh(&mut self) -> BulwarkResult<()> {
        todo!()
    }
}
