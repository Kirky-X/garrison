//! 签名协议插件模块。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的微服务网关签名认证，
//! 基于 `sha2` / `hmac` / `base64` 实现请求签名校验。
//!
//! 仅在启用 `protocol-sign` 特性时编译。
//!
//! 该模块在 0.1.0 为占位实现，完整功能将在 0.2.0+ 提供。

use crate::error::BulwarkResult;

/// 网关签名配置。
pub struct GatewaySignConfig {
    /// 签名密钥。
    pub secret: String,

    /// 时间窗口（秒），超出窗口的请求视为重放。
    pub time_window: i64,
}

/// 网关签名校验器，提供微服务间请求签名认证。
pub struct GatewaySignChecker {
    /// 签名配置。
    pub config: GatewaySignConfig,
}

impl GatewaySignChecker {
    /// 创建新的网关签名校验器。
    ///
    /// # 参数
    /// - `secret`: 签名密钥。
    pub fn new(_secret: impl Into<String>) -> Self {
        todo!()
    }

    /// 校验请求签名。
    ///
    /// # 参数
    /// - `timestamp`: 请求时间戳。
    /// - `nonce`: 随机串。
    /// - `data`: 请求体数据。
    /// - `sign`: 请求签名。
    pub fn verify(
        &self,
        _timestamp: i64,
        _nonce: &str,
        _data: &str,
        _sign: &str,
    ) -> BulwarkResult<bool> {
        todo!()
    }
}
