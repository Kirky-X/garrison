//! OAuth2 协议插件模块。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 OAuth2 协议支持，
//! 基于 `reqwest` crate 实现授权码、隐式、密码、客户端凭证四种授权流程。
//!
//! 仅在启用 `protocol-oauth2` 特性时编译。
//!
//! 该模块在 0.1.0 为占位实现，完整功能将在 0.2.0+ 提供。

use crate::error::BulwarkResult;

/// OAuth2 客户端配置。
pub struct OAuth2Config {
    /// 授权服务器地址。
    pub auth_url: String,

    /// Token 端点地址。
    pub token_url: String,

    /// 客户端 ID。
    pub client_id: String,

    /// 客户端密钥。
    pub client_secret: String,

    /// 回调地址。
    pub redirect_uri: String,
}

/// OAuth2 协议处理器，提供授权流程入口。
pub struct OAuth2Handler {
    /// 客户端配置。
    pub config: OAuth2Config,
}

impl OAuth2Handler {
    /// 生成授权码请求 URL。
    pub fn authorize_url(&self) -> BulwarkResult<String> {
        todo!()
    }

    /// 使用授权码换取 Token。
    ///
    /// # 参数
    /// - `code`: 授权码。
    pub fn exchange_token(&self, _code: &str) -> BulwarkResult<String> {
        todo!()
    }
}
