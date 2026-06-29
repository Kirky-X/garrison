//! 配置模块，提供 BulwarkConfig 全局配置。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `SaTokenConfig`，
//! 定义 Token 名称、超时、持久化等配置项。

use serde::{Deserialize, Serialize};

/// 全局配置结构体，定义框架运行参数。
///
/// [借鉴 Sa-Token] 对应 `SaTokenConfig`。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulwarkConfig {
    /// Token 名称（对应 HTTP Header / Cookie 字段名）。
    pub token_name: String,

    /// Token 超时秒数（-1 表示永不过期）。
    pub timeout: i64,

    /// 是否启用活动超时检测。
    pub active_timeout: i64,

    /// 是否从 Cookie 中读取 Token。
    pub is_read_cookie: bool,

    /// 是否从 Header 中读取 Token。
    pub is_read_header: bool,

    /// 是否在登录后自动写入 Cookie。
    pub is_write_header: bool,

    /// Token 风格（如 uuid / simple / jwt）。
    pub token_style: String,
}

impl BulwarkConfig {
    /// 创建默认配置实例。
    pub fn default_config() -> Self {
        todo!()
    }
}

impl Default for BulwarkConfig {
    fn default() -> Self {
        Self::default_config()
    }
}
