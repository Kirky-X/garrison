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
use crate::loc;
use crate::protocol::social::{SocialLoginProvider, SocialProvider, SocialUserInfo};
use async_trait::async_trait;
use serde_json::Value;

/// 微信扫码登录授权页端点。
const WECHAT_AUTH_URL: &str = "https://open.weixin.qq.com/connect/qrconnect";

/// 微信 OAuth2 access_token 端点（默认值，可通过 `with_token_url` 覆盖以适配测试）。
const WECHAT_TOKEN_URL: &str = "https://api.weixin.qq.com/sns/oauth2/access_token";

/// 微信 OAuth2 userinfo 端点（默认值，可通过 `with_userinfo_url` 覆盖以适配测试）。
const WECHAT_USERINFO_URL: &str = "https://api.weixin.qq.com/sns/userinfo";

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
    /// userinfo 端点 URL（默认为微信官方端点，测试时可覆盖）。
    userinfo_url: String,
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
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client build with timeout should succeed"),
            token_url: WECHAT_TOKEN_URL.to_string(),
            userinfo_url: WECHAT_USERINFO_URL.to_string(),
        }
    }

    /// 覆盖 access_token 端点 URL（用于测试时指向 mock server）。
    #[must_use]
    pub fn with_token_url(mut self, token_url: impl Into<String>) -> Self {
        self.token_url = token_url.into();
        self
    }

    /// 覆盖 userinfo 端点 URL（用于测试时指向 mock server）。
    #[must_use]
    pub fn with_userinfo_url(mut self, userinfo_url: impl Into<String>) -> Self {
        self.userinfo_url = userinfo_url.into();
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
        let resp = self
            .http
            .post(&self.token_url)
            .form(&[
                ("appid", self.client_id.as_str()),
                ("secret", self.client_secret.as_str()),
                ("code", code),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|e| {
                BulwarkError::Network(loc!(
                    "wechat-token-request-failed",
                    format!("wechat token request failed: {}", e),
                    ("detail", &e.to_string())
                ))
            })?;

        if !resp.status().is_success() {
            return Err(BulwarkError::Network(loc!(
                "wechat-token-request-failed",
                format!("wechat token request failed: {}", resp.status()),
                ("detail", &resp.status().to_string())
            )));
        }

        let raw: Value = resp.json().await.map_err(|e| {
            BulwarkError::Network(loc!(
                "wechat-token-response-parse-failed",
                format!("wechat token response parse failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;

        // 微信错误响应含 errcode != 0（成功时 errcode 缺失或为 0）
        if let Some(errcode) = raw.get("errcode").and_then(|v| v.as_i64()) {
            if errcode != 0 {
                let errmsg = raw
                    .get("errmsg")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown wechat error");
                return Err(BulwarkError::Network(loc!(
                    "wechat-error-response",
                    format!("wechat error {}: {}", errcode, errmsg),
                    ("code", &errcode.to_string()),
                    ("message", errmsg)
                )));
            }
        }

        let provider_user_id = raw
            .get("openid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BulwarkError::Network(loc!(
                    "wechat-response-missing-openid",
                    "wechat response missing openid field".to_string()
                ))
            })?
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

    /// 用 access_token 获取用户信息（依据 spec social-login R-social-login-002）。
    ///
    /// 调用微信 `sns/userinfo` 端点，获取 nickname/headimgurl/openid/unionid。
    ///
    /// # 参数
    ///
    /// - `access_token`: 复合格式 `"{access_token}|{openid}"`，用 `|` 分隔 access_token 与 openid。
    ///   微信 userinfo 端点必须同时传入 access_token 和 openid，而 `SocialLoginProvider::get_user_info`
    ///   trait 签名只接受单参数，故采用复合格式编码两个字段。调用方应在 `exchange_token` 后保存
    ///   `SocialUserInfo.provider_user_id`（即 openid），调用时拼接为 `"access_token|openid"`。
    ///   若不含 `|`，整个字符串作为 access_token、openid 为空字符串（微信会返回 errcode，最终映射为 `BulwarkError::Network`）。
    ///
    /// # 错误
    ///
    /// - `BulwarkError::Network`: HTTP 请求失败、状态码非 2xx、JSON 解析失败、或微信返回 errcode != 0。
    async fn get_user_info(&self, access_token: &str) -> BulwarkResult<SocialUserInfo> {
        // 解析 "{access_token}|{openid}" 复合格式
        let (access_token_value, openid) = match access_token.split_once('|') {
            Some((tok, oid)) => (tok, oid),
            None => (access_token, ""),
        };

        let url = format!(
            "{}?access_token={}&openid={}",
            self.userinfo_url,
            urlencoding::encode(access_token_value),
            urlencoding::encode(openid),
        );
        let resp = self.http.get(&url).send().await.map_err(|e| {
            BulwarkError::Network(loc!(
                "wechat-userinfo-request-failed",
                format!("wechat userinfo request failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;

        if !resp.status().is_success() {
            return Err(BulwarkError::Network(loc!(
                "wechat-userinfo-request-failed",
                format!("wechat userinfo request failed: {}", resp.status()),
                ("detail", &resp.status().to_string())
            )));
        }

        let raw: Value = resp.json().await.map_err(|e| {
            BulwarkError::Network(loc!(
                "wechat-userinfo-response-parse-failed",
                format!("wechat userinfo response parse failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;

        // 微信错误响应含 errcode != 0（成功时 errcode 缺失或为 0），与 exchange_token 一致
        if let Some(errcode) = raw.get("errcode").and_then(|v| v.as_i64()) {
            if errcode != 0 {
                let errmsg = raw
                    .get("errmsg")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown wechat error");
                return Err(BulwarkError::Network(loc!(
                    "wechat-error-response",
                    format!("wechat error {}: {}", errcode, errmsg),
                    ("code", &errcode.to_string()),
                    ("message", errmsg)
                )));
            }
        }

        let provider_user_id = raw
            .get("openid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BulwarkError::Network(loc!(
                    "wechat-userinfo-response-missing-openid",
                    "wechat userinfo response missing openid field".to_string()
                ))
            })?
            .to_string();

        let nickname = raw
            .get("nickname")
            .and_then(|v| v.as_str())
            .map(String::from);

        let avatar = raw
            .get("headimgurl")
            .and_then(|v| v.as_str())
            .map(String::from);

        let union_id = raw
            .get("unionid")
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(SocialUserInfo {
            provider: SocialProvider::Wechat,
            provider_user_id,
            nickname,
            avatar,
            union_id,
            raw,
        })
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

// ============================================================================
// WechatMiniAppProvider：微信小程序登录（依据 design.md D11 D1）
// ============================================================================

/// 微信小程序 `jscode2session` 端点（依据 design.md D11 D1）。
const WECHAT_MINI_APP_JSCODE2SESSION_URL: &str = "https://api.weixin.qq.com/sns/jscode2session";

/// 微信小程序登录 provider（依据 design.md D11 D1）。
///
/// 复用 `SocialLoginProvider` trait，`get_user_info` 调用 `jscode2session` 端点，
/// 用小程序客户端 `wx.login()` 返回的 `js_code` 换取 `openid` + `session_key` + `unionid`。
///
/// # 与 `WechatProvider` 的差异
///
/// - `WechatProvider` 用于网站扫码登录（OAuth2 流程：授权页 → code → access_token → userinfo）
/// - `WechatMiniAppProvider` 用于小程序登录（`wx.login()` → js_code → jscode2session → openid）
/// - 小程序无 OAuth2 授权页 URL，`get_authorization_url` 返回 `BulwarkError::NotImplemented`
/// - 小程序无独立 access_token，`exchange_token` 与 `get_user_info` 均调用 jscode2session
///
/// # 示例
///
/// ```ignore
/// use bulwark::protocol::social::wechat::WechatMiniAppProvider;
/// use bulwark::protocol::social::SocialLoginProvider;
///
/// let provider = WechatMiniAppProvider::new("wx_appid", "wx_secret");
/// let user_info = provider.get_user_info("js_code_from_wx_login").await?;
/// ```
pub struct WechatMiniAppProvider {
    /// 小程序 AppID。
    client_id: String,
    /// 小程序 AppSecret。
    client_secret: String,
    /// HTTP 客户端（复用连接池，与 `WechatProvider` 同构造方式）。
    http: reqwest::Client,
    /// `jscode2session` 端点 URL（默认为微信官方端点，测试时可覆盖）。
    jscode2session_url: String,
}

impl WechatMiniAppProvider {
    /// 创建 `WechatMiniAppProvider` 实例。
    ///
    /// # 参数
    /// - `client_id`: 小程序 AppID
    /// - `client_secret`: 小程序 AppSecret
    pub fn new(client_id: &str, client_secret: &str) -> Self {
        Self {
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .connect_timeout(std::time::Duration::from_secs(10))
                .build()
                .expect("reqwest client build with timeout should succeed"),
            jscode2session_url: WECHAT_MINI_APP_JSCODE2SESSION_URL.to_string(),
        }
    }

    /// 覆盖 `jscode2session` 端点 URL（用于测试时指向 mock server）。
    #[must_use]
    pub fn with_jscode2session_url(mut self, url: impl Into<String>) -> Self {
        self.jscode2session_url = url.into();
        self
    }
}

#[async_trait]
impl SocialLoginProvider for WechatMiniAppProvider {
    /// 小程序无 OAuth2 授权页 URL（小程序客户端通过 `wx.login()` 直接获取 js_code）。
    async fn get_authorization_url(
        &self,
        _state: &str,
        _redirect_uri: &str,
    ) -> BulwarkResult<String> {
        Err(BulwarkError::NotImplemented(
            loc!(
                "wechat-mini-app-get-authorization-url-not-supported",
                "WechatMiniAppProvider 不支持 get_authorization_url（小程序用 wx.login() 直接获取 js_code）".to_string()
            )
        ))
    }

    /// 用 js_code 换取用户信息（与 `get_user_info` 等价，均调用 `jscode2session`）。
    async fn exchange_token(&self, code: &str, _state: &str) -> BulwarkResult<SocialUserInfo> {
        self.get_user_info(code).await
    }

    /// 用 js_code 调用 `jscode2session` 获取用户信息（依据 design.md D11 D1）。
    ///
    /// # 参数
    ///
    /// - `access_token`: 实际为小程序 `wx.login()` 返回的 `js_code`（trait 签名限制，
    ///   复用 `access_token` 参数位）
    ///
    /// # 错误
    ///
    /// - `BulwarkError::Network`: HTTP 请求失败、状态码非 2xx、JSON 解析失败、
    ///   或微信返回 `errcode != 0`、或响应缺少 `openid` 字段
    async fn get_user_info(&self, access_token: &str) -> BulwarkResult<SocialUserInfo> {
        // access_token 参数位实际为小程序 wx.login() 返回的 js_code
        let js_code = access_token;

        let url = format!(
            "{}?appid={}&secret={}&js_code={}&grant_type=authorization_code",
            self.jscode2session_url,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&self.client_secret),
            urlencoding::encode(js_code),
        );

        let resp = self.http.get(&url).send().await.map_err(|e| {
            BulwarkError::Network(loc!(
                "wechat-mini-app-jscode2session-request-failed",
                format!("wechat mini-app jscode2session request failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;

        if !resp.status().is_success() {
            return Err(BulwarkError::Network(loc!(
                "wechat-mini-app-jscode2session-request-failed",
                format!(
                    "wechat mini-app jscode2session request failed: {}",
                    resp.status()
                ),
                ("detail", &resp.status().to_string())
            )));
        }

        let raw: Value = resp.json().await.map_err(|e| {
            BulwarkError::Network(loc!(
                "wechat-mini-app-jscode2session-response-parse-failed",
                format!(
                    "wechat mini-app jscode2session response parse failed: {}",
                    e
                ),
                ("detail", &e.to_string())
            ))
        })?;

        // 微信错误响应含 errcode != 0（成功时 errcode 缺失或为 0）
        if let Some(errcode) = raw.get("errcode").and_then(|v| v.as_i64()) {
            if errcode != 0 {
                let errmsg = raw
                    .get("errmsg")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown wechat error");
                return Err(BulwarkError::Network(loc!(
                    "wechat-mini-app-error-response",
                    format!("wechat mini-app error {}: {}", errcode, errmsg),
                    ("code", &errcode.to_string()),
                    ("message", errmsg)
                )));
            }
        }

        let provider_user_id = raw
            .get("openid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                BulwarkError::Network(loc!(
                    "wechat-mini-app-jscode2session-response-missing-openid",
                    "wechat mini-app jscode2session response missing openid field".to_string()
                ))
            })?
            .to_string();

        let union_id = raw
            .get("unionid")
            .and_then(|v| v.as_str())
            .map(String::from);

        Ok(SocialUserInfo {
            provider: SocialProvider::WechatMiniApp,
            provider_user_id,
            nickname: None,
            avatar: None,
            union_id,
            raw,
        })
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
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/sns/oauth2/access_token"))
            .and(body_string_contains("appid=wx_appid"))
            .and(body_string_contains("secret=wx_secret"))
            .and(body_string_contains("code=code"))
            .and(body_string_contains("grant_type=authorization_code"))
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

    /// 验证 `WechatProvider::get_user_info` 解析微信 userinfo 响应的 nickname/headimgurl
    ///（依据 spec social-login R-social-login-002 验收标准）。
    ///
    /// # 测试流程
    ///
    /// 1. wiremock 模拟 `GET /sns/userinfo` 返回 `{"openid":"openid1","nickname":"Alice","headimgurl":"...","unionid":"union1"}`
    /// 2. 构造 `WechatProvider::with_userinfo_url` 指向 mock server
    /// 3. 调用 `get_user_info("tok123|openid1")`（access_token|openid 复合格式）
    /// 4. 断言返回 `SocialUserInfo` 含 nickname/avatar/union_id
    ///
    /// Red 阶段：`with_userinfo_url` / `get_user_info` 实现 missing → panic。
    /// Green 阶段（T004）：实现后测试通过。
    #[tokio::test]
    async fn wechat_provider_get_user_info_parses_nickname_and_avatar() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/sns/userinfo"))
            .and(query_param("access_token", "tok123"))
            .and(query_param("openid", "openid1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "openid": "openid1",
                "nickname": "Alice",
                "headimgurl": "https://img.example.com/a.png",
                "unionid": "union1",
            })))
            .mount(&server)
            .await;

        let provider = WechatProvider::new("wx_appid", "wx_secret")
            .with_userinfo_url(format!("{}/sns/userinfo", server.uri()));
        let user_info = provider
            .get_user_info("tok123|openid1")
            .await
            .expect("get_user_info 应返回 Ok");

        assert_eq!(user_info.provider, SocialProvider::Wechat);
        assert_eq!(user_info.provider_user_id, "openid1");
        assert_eq!(user_info.nickname.as_deref(), Some("Alice"));
        assert_eq!(
            user_info.avatar.as_deref(),
            Some("https://img.example.com/a.png")
        );
        assert_eq!(user_info.union_id.as_deref(), Some("union1"));
    }

    /// 验证 `WechatProvider::get_user_info` 在 HTTP 错误时返回 `BulwarkError`（不 panic）
    ///（依据 spec social-login R-social-login-002，Rule 12 失败显性化）。
    ///
    /// Red 阶段：`get_user_info` 未实现 → panic。
    /// Green 阶段（T004）：实现后返回 `Err(BulwarkError::Network(_))`。
    #[tokio::test]
    async fn wechat_provider_get_user_info_returns_error_on_http_failure() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/sns/userinfo"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let provider = WechatProvider::new("wx_appid", "wx_secret")
            .with_userinfo_url(format!("{}/sns/userinfo", server.uri()));
        let result = provider.get_user_info("tok123|openid1").await;

        assert!(
            result.is_err(),
            "HTTP 500 应返回 Err 而非 panic，实际: {:?}",
            result
        );
        match result {
            Err(BulwarkError::Network(_)) => {},
            Err(other) => panic!("期望 BulwarkError::Network，实际: {:?}", other),
            Ok(_) => unreachable!("HTTP 500 不应返回 Ok"),
        }
    }

    // ========================================================================
    // T088: WechatMiniAppProvider Red 阶段（依据 design.md D11 D1）
    // ========================================================================

    /// 验证 `WechatMiniAppProvider::get_user_info` 调用 `jscode2session` 成功时
    /// 返回 `SocialUserInfo`（依据 design.md D11 D1）。
    ///
    /// Red 阶段：`get_user_info` 含 `todo!()` → panic。
    /// Green 阶段（T089）：实现 jscode2session 调用后测试通过。
    #[tokio::test]
    async fn wechat_mini_app_get_user_info_success() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/sns/jscode2session"))
            .and(query_param("appid", "wx_appid"))
            .and(query_param("secret", "wx_secret"))
            .and(query_param("js_code", "js_code_123"))
            .and(query_param("grant_type", "authorization_code"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "openid": "openid_mini_1",
                "session_key": "sess_key_abc",
                "unionid": "union_mini_1",
            })))
            .mount(&server)
            .await;

        let provider = WechatMiniAppProvider::new("wx_appid", "wx_secret")
            .with_jscode2session_url(format!("{}/sns/jscode2session", server.uri()));
        let user_info = provider
            .get_user_info("js_code_123")
            .await
            .expect("get_user_info 应返回 Ok");

        assert_eq!(user_info.provider, SocialProvider::WechatMiniApp);
        assert_eq!(user_info.provider_user_id, "openid_mini_1");
        assert_eq!(user_info.union_id.as_deref(), Some("union_mini_1"));
    }

    /// 验证 `WechatMiniAppProvider::get_user_info` 在微信返回 `errcode=40029`
    ///（无效 code）时返回 `BulwarkError`（依据 design.md D11 D1，Rule 12 失败显性化）。
    ///
    /// Red 阶段：`get_user_info` 含 `todo!()` → panic。
    /// Green 阶段（T089）：实现 errcode 检查后返回 `Err(BulwarkError::Network(_))`。
    #[tokio::test]
    async fn wechat_mini_app_get_user_info_invalid_code() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/sns/jscode2session"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "errcode": 40029,
                "errmsg": "invalid code",
            })))
            .mount(&server)
            .await;

        let provider = WechatMiniAppProvider::new("wx_appid", "wx_secret")
            .with_jscode2session_url(format!("{}/sns/jscode2session", server.uri()));
        let result = provider.get_user_info("bad_code").await;

        assert!(
            result.is_err(),
            "errcode=40029 应返回 Err 而非 Ok，实际: {:?}",
            result
        );
    }

    /// 验证 `WechatMiniAppProvider::get_user_info` 在 HTTP 500 时返回
    /// `BulwarkError::Network`（依据 design.md D11 D1，Rule 12 失败显性化）。
    ///
    /// Red 阶段：`get_user_info` 含 `todo!()` → panic。
    /// Green 阶段（T089）：实现 HTTP 状态码检查后返回 `Err(BulwarkError::Network(_))`。
    #[tokio::test]
    async fn wechat_mini_app_get_user_info_network_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/sns/jscode2session"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let provider = WechatMiniAppProvider::new("wx_appid", "wx_secret")
            .with_jscode2session_url(format!("{}/sns/jscode2session", server.uri()));
        let result = provider.get_user_info("js_code_123").await;

        assert!(
            result.is_err(),
            "HTTP 500 应返回 Err 而非 Ok，实际: {:?}",
            result
        );
        match result {
            Err(BulwarkError::Network(_)) => {},
            Err(other) => panic!("期望 BulwarkError::Network，实际: {:?}", other),
            Ok(_) => unreachable!("HTTP 500 不应返回 Ok"),
        }
    }

    /// 验证 `WechatMiniAppProvider::get_user_info` 在响应缺少 `openid` 字段时
    /// 返回 `BulwarkError`（依据 design.md D11 D1，Rule 12 失败显性化）。
    ///
    /// Red 阶段：`get_user_info` 含 `todo!()` → panic。
    /// Green 阶段（T089）：实现 openid 缺失检查后返回 `Err(BulwarkError::Network(_))`。
    #[tokio::test]
    async fn wechat_mini_app_get_user_info_missing_openid() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("GET"))
            .and(path("/sns/jscode2session"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "session_key": "sess_key_abc",
            })))
            .mount(&server)
            .await;

        let provider = WechatMiniAppProvider::new("wx_appid", "wx_secret")
            .with_jscode2session_url(format!("{}/sns/jscode2session", server.uri()));
        let result = provider.get_user_info("js_code_123").await;

        assert!(
            result.is_err(),
            "缺少 openid 应返回 Err 而非 Ok，实际: {:?}",
            result
        );
    }
}
