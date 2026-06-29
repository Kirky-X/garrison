//! Token 模型模块，定义 Token 数据结构。
//!
//! [借鉴 Sa-Token] Token 信息模型，对应 Sa-Token 的 `SaTokenInfo` / `TokenSign` 数据结构。

use serde::{Deserialize, Serialize};

/// Token 数据结构，表示一个认证令牌。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Token {
    /// Token 字符串值。
    pub value: String,

    /// 关联的登录主体标识。
    pub login_id: i64,

    /// 创建时间戳（Unix 秒）。
    pub created_at: i64,

    /// 过期时间戳（Unix 秒）。
    pub expires_at: i64,
}

impl Token {
    /// 创建新的 Token 实例。
    ///
    /// # 参数
    /// - `value`: Token 字符串值。
    /// - `login_id`: 登录主体标识。
    pub fn new(value: impl Into<String>, login_id: i64) -> Self {
        todo!()
    }

    /// 检查 Token 是否已过期。
    pub fn is_expired(&self) -> bool {
        todo!()
    }
}
