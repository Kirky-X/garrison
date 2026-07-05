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

use crate::error::{BulwarkError, BulwarkResult};
use crate::protocol::social::{SocialLoginProvider, SocialProvider, SocialUserInfo};
use async_trait::async_trait;
use serde_json::Value;

/// 微信扫码登录授权页端点。
const WECHAT_AUTH_URL: &str = "https://open.weixin.qq.com/connect/qrconnect";

/// 微信 OAuth2 access_token 端点（默认值，可通过 `with_token_url` 覆盖以适配测试）。
const WECHAT_TOKEN_URL: &str = "https://api.weixin.qq.com/sns/oauth2/access_token";

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
    /// access_token 端点 URL（默认为微信官方端点，测试时可覆盖）。
    token_url: String,
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
            token_url: WECHAT_TOKEN_URL.to_string(),
        }
    }

    /// 覆盖 access_token 端点 URL（用于测试时指向 mock server）。
    #[must_use]
    pub fn with_token_url(mut self, token_url: impl Into<String>) -> Self {
        self.token_url = token_url.into();
        self
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

    /// 用授权码换取用户信息（依据 spec social-login R-social-login-002）。
    ///
    /// 调用微信 `sns/oauth2/access_token` 端点，用授权码换取 access_token + openid + unionid，
    /// 返回 `SocialUserInfo`（nickname/avatar 为 None，需调用 `get_user_info` 获取）。
    async fn exchange_token(&self, code: &str, _state: &str) -> BulwarkResult<SocialUserInfo> {
        let url = format!(
            "{}?appid={}&secret={}&code={}&grant_type=authorization_code",
            self.token_url,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&self.client_secret),
            urlencoding::encode(code),
        );
        let resp =
            self.http.get(&url).send().await.map_err(|e| {
                BulwarkError::Network(format!("wechat token request failed: {}", e))
            })?;

        let raw: Value = resp.json().await.map_err(|e| {
            BulwarkError::Network(format!("wechat token response parse failed: {}", e))
        })?;

        // 微信错误响应含 errcode != 0（成功时 errcode 缺失或为 0）
        if let Some(errcode) = raw.get("errcode").and_then(|v| v.as_i64()) {
            if errcode != 0 {
                let errmsg = raw
                    .get("errmsg")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown wechat error");
                return Err(BulwarkError::Network(format!(
                    "wechat error {}: {}",
                    errcode, errmsg
                )));
            }
        }

        let provider_user_id = raw
            .get("openid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| BulwarkError::Network("wechat response missing openid field".into()))?
            .to_string();

        let union_id = raw
            .get("unionid")
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(SocialUserInfo {
            provider: SocialProvider::Wechat,
            provider_user_id,
            nickname: None,
            avatar: None,
            union_id,
            raw,
        })
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

    /// 验证 `WechatProvider::exchange_token` 解析微信 access_token 响应
    ///（依据 spec social-login R-social-login-002 验收标准）。
    ///
    /// Red 阶段：`with_token_url` 方法不存在 → 编译失败。
    /// Green 阶段（T102）：实现 exchange_token 后测试通过。
    #[tokio::test]
    async fn wechat_provider_exchange_token_parses_access_token_from_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/sns/oauth2/access_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok123",
                "openid": "openid456",
                "unionid": "union789",
            })))
            .mount(&server)
            .await;

        let provider = WechatProvider::new("wx_appid", "wx_secret")
            .with_token_url(format!("{}/sns/oauth2/access_token", server.uri()));
        let user_info = provider
            .exchange_token("code", "state")
            .await
            .expect("exchange_token 应返回 Ok");

        assert_eq!(user_info.provider_user_id, "openid456");
        assert_eq!(user_info.union_id.as_deref(), Some("union789"));
    }
}
