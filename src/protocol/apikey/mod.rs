//! API Key 协议插件模块。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 API 接口鉴权能力，
//! 提供基于 API Key 的认证机制，适用于服务间调用与开放 API 场景。
//!
//! 仅在启用 `protocol-apikey` 特性时编译。

use crate::error::BulwarkResult;

/// API Key 配置。
pub struct ApiKeyConfig {
    /// 请求头字段名，默认 `X-API-Key`。
    pub header_name: String,

    /// 是否启用前缀校验（如 `Bearer ` 前缀）。
    pub prefix: Option<String>,
}

/// API Key 认证处理器。
pub struct ApiKeyHandler {
    /// 认证配置。
    pub config: ApiKeyConfig,
}

impl ApiKeyHandler {
    /// 创建新的 API Key 认证处理器。
    pub fn new() -> Self {
        todo!()
    }

    /// 从请求头中提取 API Key。
    ///
    /// # 参数
    /// - `header_value`: 请求头字段值。
    pub fn extract(&self, header_value: &str) -> BulwarkResult<String> {
        todo!()
    }

    /// 校验 API Key 有效性。
    ///
    /// # 参数
    /// - `api_key`: 待校验的 API Key。
    pub fn verify(&self, api_key: &str) -> BulwarkResult<i64> {
        todo!()
    }
}
