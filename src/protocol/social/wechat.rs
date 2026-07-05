//! 微信扫码登录 provider（0.5.0 新增，依据 spec social-login R-social-login-002）。
//!
//! 实现 `SocialLoginProvider` trait，覆盖微信开放平台扫码登录的 OAuth2 流程：
//! - `get_authorization_url`：拼接 `https://open.weixin.qq.com/connect/qrconnect?` 授权页 URL
//! - `exchange_token`：调用 `https://api.weixin.qq.com/sns/oauth2/access_token` 用 code 换 access_token
//! - `get_user_info`：调用 `https://api.weixin.qq.com/sns/userinfo` 获取用户昵称头像
//!
//! ## Feature 门控
//!
//! 启用 `social-wechat` feature 时编译，依赖 `protocol-oauth2`（提供 reqwest HTTP client）。

use crate::error::BulwarkResult;
use crate::protocol::social::{SocialLoginProvider, SocialUserInfo};
use async_trait::async_trait;

/// 微信扫码登录授权页端点。
const WECHAT_AUTH_URL: &str = "https://open.weixin.qq.com/connect/qrconnect";

/// 微信扫码登录 provider（依据 spec social-login R-social-login-002）。
///
/// 实现 `SocialLoginProvider` trait，封装微信开放平台扫码登录的 OAuth2 流程。
///
/// # 示例
///
/// ```ignore
/// use bulwark::protocol::social::wechat::WechatProvider;
/// use bulwark::protocol::social::SocialLoginProvider;
///
/// let provider = WechatProvider::new("wx_appid", "wx_secret");
/// let url = provider.get_authorization_url("state123", "https://example.com/cb").await?;
/// ```
pub struct WechatProvider {
    /// 微信开放平台 AppID。
    client_id: String,
    /// 微信开放平台 AppSecret。
    client_secret: String,
    /// HTTP 客户端（复用连接池）。
    http: reqwest::Client,
}

impl WechatProvider {
    /// 创建 `WechatProvider` 实例。
    ///
    /// # 参数
    /// - `client_id`: 微信开放平台 AppID
    /// - `client_secret`: 微信开放平台 AppSecret
    pub fn new(client_id: &str, client_secret: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl SocialLoginProvider for WechatProvider {
    /// 拼接微信扫码登录授权页 URL。
    ///
    /// URL 格式：`https://open.weixin.qq.com/connect/qrconnect?appid={client_id}&redirect_uri={redirect_uri}&state={state}`
    ///（依据 spec social-login R-social-login-002 验收标准）。
    async fn get_authorization_url(
        &self,
        state: &str,
        redirect_uri: &str,
    ) -> BulwarkResult<String> {
        Ok(format!(
            "{}?appid={}&redirect_uri={}&state={}",
            WECHAT_AUTH_URL,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
        ))
    }

    /// 用授权码换取用户信息（T101-T102 实现）。
    async fn exchange_token(&self, _code: &str, _state: &str) -> BulwarkResult<SocialUserInfo> {
        // 抑制 dead_code：client_secret 与 http 将在 T101-T102 exchange_token 实现中读取
        let _ = (&self.client_secret, &self.http);
        // T101-T102 将实现：POST https://api.weixin.qq.com/sns/oauth2/access_token 解析 access_token/openid/unionid
        todo!("T101-T102: implement exchange_token with mockito test")
    }

    /// 用 access_token 获取用户信息（后续任务实现）。
    async fn get_user_info(&self, _access_token: &str) -> BulwarkResult<SocialUserInfo> {
        // 后续任务将实现：GET https://api.weixin.qq.com/sns/userinfo 解析 nickname/headimgurl
        todo!("implement get_user_info with userinfo endpoint")
    }
}

/// 简单的 URL 编码工具（与 `protocol::oauth2::urlencoding` 同实现，避免跨模块耦合）。
///
/// 对查询参数值进行百分号编码，保留字母、数字、`-`、`_`、`.`、`~`。
mod urlencoding {
    pub fn encode(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for b in s.bytes() {
            if b.is_ascii_alphanumeric() || b == b'-' || b == b'_' || b == b'.' || b == b'~' {
                out.push(b as char);
            } else {
                out.push_str(&format!("%{:02X}", b));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证 `WechatProvider::get_authorization_url` 返回符合微信扫码登录规范的 URL
    ///（依据 spec social-login R-social-login-002 验收标准）。
    ///
    /// Red 阶段：`WechatProvider` 类型不存在 → 编译失败。
    /// Green 阶段（T100）：定义 struct + impl 后测试通过。
    #[tokio::test]
    async fn wechat_provider_get_authorization_url_returns_correct_format() {
        let provider = WechatProvider::new("wx_appid", "wx_secret");
        let url = provider
            .get_authorization_url("state123", "https://example.com/cb")
            .await
            .expect("get_authorization_url 应返回 Ok");

        assert!(
            url.starts_with("https://open.weixin.qq.com/connect/qrconnect?"),
            "URL 应以微信扫码登录端点开头，实际: {}",
            url
        );
        assert!(
            url.contains("appid=wx_appid"),
            "URL 应含 appid 参数，实际: {}",
            url
        );
        assert!(
            url.contains("state=state123"),
            "URL 应含 state 参数，实际: {}",
            url
        );
    }
}
