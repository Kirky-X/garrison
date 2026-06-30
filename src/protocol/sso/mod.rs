//! 单点登录 (SSO) 协议插件模块。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 SSO 单点登录支持，
//! 提供跨系统统一登录、登出与票据校验能力。
//!
//! 仅在启用 `protocol-sso` 特性时编译。
//!
//! 该模块在 0.1.0 为占位实现，完整功能将在 0.2.0+ 提供。

use crate::error::BulwarkResult;

/// SSO 客户端配置。
pub struct SsoConfig {
    /// SSO 服务端地址。
    pub server_url: String,

    /// 当前客户端标识。
    pub client_id: String,

    /// 登录回调地址。
    pub callback_url: String,
}

/// SSO 协议处理器，提供单点登录流程入口。
pub struct SsoHandler {
    /// 客户端配置。
    pub config: SsoConfig,
}

impl SsoHandler {
    /// 生成 SSO 登录重定向 URL。
    pub fn login_redirect(&self) -> BulwarkResult<String> {
        todo!()
    }

    /// 校验 SSO 票据。
    ///
    /// # 参数
    /// - `ticket`: 登录票据。
    pub fn validate_ticket(&self, ticket: &str) -> BulwarkResult<i64> {
        todo!()
    }

    /// 通知 SSO 服务端登出。
    ///
    /// # 参数
    /// - `login_id`: 登录主体标识。
    pub fn logout(&self, login_id: i64) -> BulwarkResult<()> {
        todo!()
    }
}
