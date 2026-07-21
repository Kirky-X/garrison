//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 微信扫码登录 provider。
//!
//! 实现 `SocialLoginProvider` trait，覆盖微信开放平台扫码登录的 OAuth2 流程：
//! - `get_authorization_url`：拼接 `https://open.weixin.qq.com/connect/qrconnect?` 授权页 URL
//! - `exchange_token`：调用 `https://api.weixin.qq.com/sns/oauth2/access_token` 用 code 换 access_token
//! - `get_user_info`：调用 `https://api.weixin.qq.com/sns/userinfo` 获取用户昵称头像
//!
//! ## Feature 门控
//!
//! 启用 `social-wechat` feature 时编译，依赖 `protocol-oauth2`（提供 reqwest HTTP client）。

use crate::error::{GarrisonError, GarrisonResult};
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

/// 微信扫码登录 provider。
///
/// 实现 `SocialLoginProvider` trait，封装微信开放平台扫码登录的 OAuth2 流程。
///
/// # 示例
///
/// ```ignore
/// use garrison::protocol::social::wechat::WechatProvider;
/// use garrison::protocol::social::SocialLoginProvider;
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
    async fn get_authorization_url(
        &self,
        state: &str,
        redirect_uri: &str,
    ) -> GarrisonResult<String> {
        Ok(format!(
            "{}?appid={}&redirect_uri={}&state={}",
            WECHAT_AUTH_URL,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(redirect_uri),
            urlencoding::encode(state),
        ))
    }

    /// 用授权码换取用户信息。
    ///
    /// 调用微信 `sns/oauth2/access_token` 端点，用授权码换取 access_token + openid + unionid，
    /// 返回 `SocialUserInfo`（nickname/avatar 为 None，需调用 `get_user_info` 获取）。
    async fn exchange_token(&self, code: &str, _state: &str) -> GarrisonResult<SocialUserInfo> {
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
                GarrisonError::Network(loc!(
                    "wechat-token-request-failed",
                    format!("wechat token request failed: {}", e),
                    ("detail", &e.to_string())
                ))
            })?;

        if !resp.status().is_success() {
            return Err(GarrisonError::Network(loc!(
                "wechat-token-request-failed",
                format!("wechat token request failed: {}", resp.status()),
                ("detail", &resp.status().to_string())
            )));
        }

        let raw: Value = resp.json().await.map_err(|e| {
            GarrisonError::Network(loc!(
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
                return Err(GarrisonError::Network(loc!(
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
                GarrisonError::Network(loc!(
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

    /// 用 access_token 获取用户信息。
    ///
    /// 调用微信 `sns/userinfo` 端点，获取 nickname/headimgurl/openid/unionid。
    ///
    /// # 参数
    ///
    /// - `access_token`: 复合格式 `"{access_token}|{openid}"`，用 `|` 分隔 access_token 与 openid。
    ///   微信 userinfo 端点必须同时传入 access_token 和 openid，而 `SocialLoginProvider::get_user_info`
    ///   trait 签名只接受单参数，故采用复合格式编码两个字段。调用方应在 `exchange_token` 后保存
    ///   `SocialUserInfo.provider_user_id`（即 openid），调用时拼接为 `"access_token|openid"`。
    ///   若不含 `|`，整个字符串作为 access_token、openid 为空字符串（微信会返回 errcode，最终映射为 `GarrisonError::Network`）。
    ///
    /// # 错误
    ///
    /// - `GarrisonError::Network`: HTTP 请求失败、状态码非 2xx、JSON 解析失败、或微信返回 errcode != 0。
    async fn get_user_info(&self, access_token: &str) -> GarrisonResult<SocialUserInfo> {
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
            GarrisonError::Network(loc!(
                "wechat-userinfo-request-failed",
                format!("wechat userinfo request failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;

        if !resp.status().is_success() {
            return Err(GarrisonError::Network(loc!(
                "wechat-userinfo-request-failed",
                format!("wechat userinfo request failed: {}", resp.status()),
                ("detail", &resp.status().to_string())
            )));
        }

        let raw: Value = resp.json().await.map_err(|e| {
            GarrisonError::Network(loc!(
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
                return Err(GarrisonError::Network(loc!(
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
                GarrisonError::Network(loc!(
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

#[cfg(feature = "protocol-zeroize")]
impl Drop for WechatProvider {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.client_secret.zeroize();
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
// WechatMiniAppProvider：微信小程序登录
// ============================================================================

/// 微信小程序 `jscode2session` 端点。
const WECHAT_MINI_APP_JSCODE2SESSION_URL: &str = "https://api.weixin.qq.com/sns/jscode2session";

/// 微信小程序登录 provider。
///
/// 复用 `SocialLoginProvider` trait，`get_user_info` 调用 `jscode2session` 端点，
/// 用小程序客户端 `wx.login()` 返回的 `js_code` 换取 `openid` + `session_key` + `unionid`。
///
/// # 与 `WechatProvider` 的差异
///
/// - `WechatProvider` 用于网站扫码登录（OAuth2 流程：授权页 → code → access_token → userinfo）
/// - `WechatMiniAppProvider` 用于小程序登录（`wx.login()` → js_code → jscode2session → openid）
/// - 小程序无 OAuth2 授权页 URL，`get_authorization_url` 返回 `GarrisonError::NotImplemented`
/// - 小程序无独立 access_token，`exchange_token` 与 `get_user_info` 均调用 jscode2session
///
/// # 示例
///
/// ```ignore
/// use garrison::protocol::social::wechat::WechatMiniAppProvider;
/// use garrison::protocol::social::SocialLoginProvider;
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
    ) -> GarrisonResult<String> {
        Err(GarrisonError::NotImplemented(
            loc!(
                "wechat-mini-app-get-authorization-url-not-supported",
                "WechatMiniAppProvider 不支持 get_authorization_url（小程序用 wx.login() 直接获取 js_code）".to_string()
            )
        ))
    }

    /// 用 js_code 换取用户信息（与 `get_user_info` 等价，均调用 `jscode2session`）。
    async fn exchange_token(&self, code: &str, _state: &str) -> GarrisonResult<SocialUserInfo> {
        self.get_user_info(code).await
    }

    /// 用 js_code 调用 `jscode2session` 获取用户信息。
    ///
    /// # 参数
    ///
    /// - `access_token`: 实际为小程序 `wx.login()` 返回的 `js_code`（trait 签名限制，
    ///   复用 `access_token` 参数位）
    ///
    /// # 错误
    ///
    /// - `GarrisonError::Network`: HTTP 请求失败、状态码非 2xx、JSON 解析失败、
    ///   或微信返回 `errcode != 0`、或响应缺少 `openid` 字段
    async fn get_user_info(&self, access_token: &str) -> GarrisonResult<SocialUserInfo> {
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
            GarrisonError::Network(loc!(
                "wechat-mini-app-jscode2session-request-failed",
                format!("wechat mini-app jscode2session request failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;

        if !resp.status().is_success() {
            return Err(GarrisonError::Network(loc!(
                "wechat-mini-app-jscode2session-request-failed",
                format!(
                    "wechat mini-app jscode2session request failed: {}",
                    resp.status()
                ),
                ("detail", &resp.status().to_string())
            )));
        }

        let raw: Value = resp.json().await.map_err(|e| {
            GarrisonError::Network(loc!(
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
                return Err(GarrisonError::Network(loc!(
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
                GarrisonError::Network(loc!(
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

#[cfg(feature = "protocol-zeroize")]
impl Drop for WechatMiniAppProvider {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.client_secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 验证 `WechatProvider::get_authorization_url` 返回符合微信扫码登录规范的 URL
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

    /// 验证 `WechatProvider::get_user_info` 在 HTTP 错误时返回 `GarrisonError`（不 panic）
    ///
    /// Red 阶段：`get_user_info` 未实现 → panic。
    /// Green 阶段（T004）：实现后返回 `Err(GarrisonError::Network(_))`。
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
            Err(GarrisonError::Network(_)) => {},
            Err(other) => panic!("期望 GarrisonError::Network，实际: {:?}", other),
            Ok(_) => unreachable!("HTTP 500 不应返回 Ok"),
        }
    }

    // ========================================================================
    // WechatMiniAppProvider Red 阶段
    // ========================================================================

    /// 验证 `WechatMiniAppProvider::get_user_info` 调用 `jscode2session` 成功时
    /// 返回 `SocialUserInfo`。
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
    ///（无效 code）时返回 `GarrisonError`。
    ///
    /// Red 阶段：`get_user_info` 含 `todo!()` → panic。
    /// Green 阶段（T089）：实现 errcode 检查后返回 `Err(GarrisonError::Network(_))`。
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
    /// `GarrisonError::Network`。
    ///
    /// Red 阶段：`get_user_info` 含 `todo!()` → panic。
    /// Green 阶段（T089）：实现 HTTP 状态码检查后返回 `Err(GarrisonError::Network(_))`。
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
            Err(GarrisonError::Network(_)) => {},
            Err(other) => panic!("期望 GarrisonError::Network，实际: {:?}", other),
            Ok(_) => unreachable!("HTTP 500 不应返回 Ok"),
        }
    }

    /// 验证 `WechatMiniAppProvider::get_user_info` 在响应缺少 `openid` 字段时
    /// 返回 `GarrisonError`。
    ///
    /// Red 阶段：`get_user_info` 含 `todo!()` → panic。
    /// Green 阶段（T089）：实现 openid 缺失检查后返回 `Err(GarrisonError::Network(_))`。
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

    // ========================================================================
    // urlencoding::encode 单元测试
    // ========================================================================

    /// urlencoding::encode 对纯字母数字不编码。
    #[test]
    fn urlencoding_encode_alphanumeric_no_change() {
        assert_eq!(urlencoding::encode("abc123"), "abc123");
    }

    /// urlencoding::encode 对保留字符 -.~ 不编码。
    #[test]
    fn urlencoding_encode_reserved_chars_no_change() {
        assert_eq!(urlencoding::encode("a-b_c.d~e"), "a-b_c.d~e");
    }

    /// urlencoding::encode 对空格编码为 %20。
    #[test]
    fn urlencoding_encode_space_to_percent_20() {
        assert_eq!(urlencoding::encode("a b"), "a%20b");
    }

    /// urlencoding::encode 对特殊字符 &=?# 编码。
    #[test]
    fn urlencoding_encode_special_chars_encoded() {
        let encoded = urlencoding::encode("a&b=c?d#e");
        assert!(!encoded.contains('&'), " & 应被编码");
        assert!(!encoded.contains('='), "= 应被编码");
        assert!(!encoded.contains('?'), "? 应被编码");
        assert!(!encoded.contains('#'), "# 应被编码");
    }

    /// urlencoding::encode 对空字符串返回空字符串。
    #[test]
    fn urlencoding_encode_empty_string_returns_empty() {
        assert_eq!(urlencoding::encode(""), "");
    }

    /// urlencoding::encode 对中文字符按 UTF-8 字节编码。
    #[test]
    fn urlencoding_encode_chinese_chars_encoded() {
        let encoded = urlencoding::encode("微信");
        // 中文字符应全部被编码（每个字节为 %XX）
        assert!(encoded.starts_with('%'), "中文字符应被百分号编码");
        assert!(!encoded.contains('微'), "不应包含原始中文字符");
    }

    // ========================================================================
    // WechatProvider 构造与 builder 测试
    // ========================================================================

    /// WechatProvider::new 正确设置 client_id。
    #[tokio::test]
    async fn wechat_provider_new_sets_client_id() {
        let provider = WechatProvider::new("my_appid", "my_secret");
        let url = provider
            .get_authorization_url("state", "https://example.com/cb")
            .await
            .expect("get_authorization_url 应返回 Ok");
        assert!(
            url.contains("appid=my_appid"),
            "URL 应含 client_id，实际: {}",
            url
        );
    }

    /// with_token_url 返回 Self 支持链式调用。
    #[tokio::test]
    async fn wechat_provider_with_token_url_returns_self_for_chaining() {
        let provider = WechatProvider::new("appid", "secret")
            .with_token_url("https://custom.token.url")
            .with_userinfo_url("https://custom.userinfo.url");
        // 验证链式调用后 provider 仍可用
        let url = provider
            .get_authorization_url("s", "r")
            .await
            .expect("get_authorization_url 应返回 Ok");
        assert!(url.contains("appid=appid"));
    }

    /// get_authorization_url 对含特殊字符的 state 和 redirect_uri 进行 URL 编码。
    #[tokio::test]
    async fn wechat_provider_get_authorization_url_encodes_special_chars() {
        let provider = WechatProvider::new("appid", "secret");
        let url = provider
            .get_authorization_url("state with space", "https://example.com/cb?foo=bar")
            .await
            .expect("get_authorization_url 应返回 Ok");
        assert!(!url.contains("state with space"), "state 应被 URL 编码");
        assert!(
            url.contains("state=state%20with%20space"),
            "state 空格应编码为 %20，实际: {}",
            url
        );
    }

    // ========================================================================
    // WechatProvider::exchange_token 错误路径测试
    // ========================================================================

    /// exchange_token 在微信返回 errcode != 0 时返回 Network 错误。
    #[tokio::test]
    async fn wechat_provider_exchange_token_errcode_nonzero_returns_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/sns/oauth2/access_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "errcode": 40029,
                "errmsg": "invalid code",
            })))
            .mount(&server)
            .await;

        let provider = WechatProvider::new("wx_appid", "wx_secret")
            .with_token_url(format!("{}/sns/oauth2/access_token", server.uri()));
        let result = provider.exchange_token("bad_code", "state").await;

        assert!(result.is_err(), "errcode!=0 应返回 Err");
        match result {
            Err(GarrisonError::Network(_)) => {},
            Err(other) => panic!("期望 Network 错误，实际: {:?}", other),
            Ok(_) => unreachable!("errcode!=0 不应返回 Ok"),
        }
    }

    /// exchange_token 在响应缺少 openid 字段时返回 Network 错误。
    #[tokio::test]
    async fn wechat_provider_exchange_token_missing_openid_returns_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/sns/oauth2/access_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok123",
                "session_key": "sess",
            })))
            .mount(&server)
            .await;

        let provider = WechatProvider::new("wx_appid", "wx_secret")
            .with_token_url(format!("{}/sns/oauth2/access_token", server.uri()));
        let result = provider.exchange_token("code", "state").await;

        assert!(result.is_err(), "缺少 openid 应返回 Err");
        match result {
            Err(GarrisonError::Network(_)) => {},
            Err(other) => panic!("期望 Network 错误，实际: {:?}", other),
            Ok(_) => unreachable!("缺少 openid 不应返回 Ok"),
        }
    }

    /// exchange_token 在 HTTP 500 时返回 Network 错误。
    #[tokio::test]
    async fn wechat_provider_exchange_token_http_500_returns_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/sns/oauth2/access_token"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let provider = WechatProvider::new("wx_appid", "wx_secret")
            .with_token_url(format!("{}/sns/oauth2/access_token", server.uri()));
        let result = provider.exchange_token("code", "state").await;

        assert!(result.is_err(), "HTTP 500 应返回 Err");
        match result {
            Err(GarrisonError::Network(_)) => {},
            Err(other) => panic!("期望 Network 错误，实际: {:?}", other),
            Ok(_) => unreachable!("HTTP 500 不应返回 Ok"),
        }
    }

    /// exchange_token 成功时 unionid 缺失返回 None。
    #[tokio::test]
    async fn wechat_provider_exchange_token_without_unionid_returns_none() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/sns/oauth2/access_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok123",
                "openid": "openid456",
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
        assert!(user_info.union_id.is_none(), "无 unionid 时应为 None");
        assert!(user_info.nickname.is_none());
        assert!(user_info.avatar.is_none());
    }

    // ========================================================================
    // WechatProvider::get_user_info 错误路径与边界测试
    // ========================================================================

    /// get_user_info 在不含 | 分隔符时以整个字符串作为 access_token、openid 为空。
    #[tokio::test]
    async fn wechat_provider_get_user_info_without_separator_uses_empty_openid() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/sns/userinfo"))
            .and(query_param("access_token", "tok_only"))
            .and(query_param("openid", ""))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "openid": "openid1",
                "nickname": "Test",
            })))
            .mount(&server)
            .await;

        let provider = WechatProvider::new("wx_appid", "wx_secret")
            .with_userinfo_url(format!("{}/sns/userinfo", server.uri()));
        let user_info = provider
            .get_user_info("tok_only")
            .await
            .expect("get_user_info 应返回 Ok");

        assert_eq!(user_info.provider_user_id, "openid1");
        assert_eq!(user_info.nickname.as_deref(), Some("Test"));
    }

    /// get_user_info 在微信返回 errcode != 0 时返回 Network 错误。
    #[tokio::test]
    async fn wechat_provider_get_user_info_errcode_nonzero_returns_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/sns/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "errcode": 48001,
                "errmsg": "api unauthorized",
            })))
            .mount(&server)
            .await;

        let provider = WechatProvider::new("wx_appid", "wx_secret")
            .with_userinfo_url(format!("{}/sns/userinfo", server.uri()));
        let result = provider.get_user_info("tok|openid").await;

        assert!(result.is_err(), "errcode!=0 应返回 Err");
        match result {
            Err(GarrisonError::Network(_)) => {},
            Err(other) => panic!("期望 Network 错误，实际: {:?}", other),
            Ok(_) => unreachable!("errcode!=0 不应返回 Ok"),
        }
    }

    /// get_user_info 在响应缺少 openid 字段时返回 Network 错误。
    #[tokio::test]
    async fn wechat_provider_get_user_info_missing_openid_returns_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/sns/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "nickname": "NoOpenid",
                "headimgurl": "https://img.example.com/a.png",
            })))
            .mount(&server)
            .await;

        let provider = WechatProvider::new("wx_appid", "wx_secret")
            .with_userinfo_url(format!("{}/sns/userinfo", server.uri()));
        let result = provider.get_user_info("tok|openid").await;

        assert!(result.is_err(), "缺少 openid 应返回 Err");
        match result {
            Err(GarrisonError::Network(_)) => {},
            Err(other) => panic!("期望 Network 错误，实际: {:?}", other),
            Ok(_) => unreachable!("缺少 openid 不应返回 Ok"),
        }
    }

    /// get_user_info 成功但 nickname/headimgurl/unionid 缺失时返回 None。
    #[tokio::test]
    async fn wechat_provider_get_user_info_missing_optional_fields_returns_none() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/sns/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "openid": "openid_only",
            })))
            .mount(&server)
            .await;

        let provider = WechatProvider::new("wx_appid", "wx_secret")
            .with_userinfo_url(format!("{}/sns/userinfo", server.uri()));
        let user_info = provider
            .get_user_info("tok|openid")
            .await
            .expect("get_user_info 应返回 Ok");

        assert_eq!(user_info.provider_user_id, "openid_only");
        assert!(user_info.nickname.is_none());
        assert!(user_info.avatar.is_none());
        assert!(user_info.union_id.is_none());
    }

    // ========================================================================
    // WechatMiniAppProvider 构造与 builder 测试
    // ========================================================================

    /// WechatMiniAppProvider::new 构造实例可用。
    #[tokio::test]
    async fn wechat_mini_app_provider_new_constructs() {
        let provider = WechatMiniAppProvider::new("mini_appid", "mini_secret");
        // get_authorization_url 返回 NotImplemented，验证实例已构造
        let result = provider.get_authorization_url("state", "redirect").await;
        assert!(
            result.is_err(),
            "get_authorization_url 应返回 NotImplemented"
        );
    }

    /// WechatMiniAppProvider::with_jscode2session_url 返回 Self 支持链式调用。
    #[tokio::test]
    async fn wechat_mini_app_provider_with_jscode2session_url_chaining() {
        let provider = WechatMiniAppProvider::new("appid", "secret")
            .with_jscode2session_url("https://custom.jscode2session.url");
        // 验证链式调用后 provider 仍可用（get_authorization_url 返回 NotImplemented）
        let result = provider.get_authorization_url("s", "r").await;
        assert!(result.is_err());
    }

    /// WechatMiniAppProvider::get_authorization_url 返回 NotImplemented 错误。
    #[tokio::test]
    async fn wechat_mini_app_provider_get_authorization_url_returns_not_implemented() {
        let provider = WechatMiniAppProvider::new("appid", "secret");
        let result = provider.get_authorization_url("state", "redirect").await;
        match result {
            Err(GarrisonError::NotImplemented(_)) => {},
            Err(other) => panic!("期望 NotImplemented，实际: {:?}", other),
            Ok(_) => unreachable!("不应返回 Ok"),
        }
    }

    /// WechatMiniAppProvider::exchange_token 委托给 get_user_info。
    #[tokio::test]
    async fn wechat_mini_app_provider_exchange_token_delegates_to_get_user_info() {
        use wiremock::matchers::{method, path, query_param};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/sns/jscode2session"))
            .and(query_param("js_code", "js_code_xyz"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "openid": "openid_via_exchange",
                "session_key": "sess_key",
            })))
            .mount(&server)
            .await;

        let provider = WechatMiniAppProvider::new("appid", "secret")
            .with_jscode2session_url(format!("{}/sns/jscode2session", server.uri()));
        let user_info = provider
            .exchange_token("js_code_xyz", "state")
            .await
            .expect("exchange_token 应返回 Ok");

        assert_eq!(user_info.provider_user_id, "openid_via_exchange");
        assert_eq!(user_info.provider, SocialProvider::WechatMiniApp);
    }

    /// WechatMiniAppProvider::get_user_info 响应缺少 openid 时返回错误。
    #[tokio::test]
    async fn wechat_mini_app_provider_get_user_info_response_parse_failure() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/sns/jscode2session"))
            .respond_with(ResponseTemplate::new(200).set_body_json("invalid_json_string"))
            .mount(&server)
            .await;

        let provider = WechatMiniAppProvider::new("appid", "secret")
            .with_jscode2session_url(format!("{}/sns/jscode2session", server.uri()));
        let result = provider.get_user_info("js_code").await;

        assert!(result.is_err(), "JSON 解析失败应返回 Err");
    }

    /// WechatMiniAppProvider::get_user_info 成功但 unionid 缺失时返回 None。
    #[tokio::test]
    async fn wechat_mini_app_provider_get_user_info_without_unionid() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/sns/jscode2session"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "openid": "openid_no_union",
                "session_key": "sess_key",
            })))
            .mount(&server)
            .await;

        let provider = WechatMiniAppProvider::new("appid", "secret")
            .with_jscode2session_url(format!("{}/sns/jscode2session", server.uri()));
        let user_info = provider
            .get_user_info("js_code")
            .await
            .expect("get_user_info 应返回 Ok");

        assert_eq!(user_info.provider_user_id, "openid_no_union");
        assert!(user_info.union_id.is_none());
        assert!(user_info.nickname.is_none());
        assert!(user_info.avatar.is_none());
    }

    /// WechatMiniAppProvider::get_user_info errcode=0 时不返回错误（边界：errcode 存在但为 0）。
    #[tokio::test]
    async fn wechat_mini_app_provider_get_user_info_errcode_zero_succeeds() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/sns/jscode2session"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "errcode": 0,
                "openid": "openid_ok",
                "session_key": "sess",
            })))
            .mount(&server)
            .await;

        let provider = WechatMiniAppProvider::new("appid", "secret")
            .with_jscode2session_url(format!("{}/sns/jscode2session", server.uri()));
        let user_info = provider
            .get_user_info("js_code")
            .await
            .expect("errcode=0 应返回 Ok");

        assert_eq!(user_info.provider_user_id, "openid_ok");
    }

    /// WechatProvider::exchange_token errcode=0 时不返回错误（边界：errcode 存在但为 0）。
    #[tokio::test]
    async fn wechat_provider_exchange_token_errcode_zero_succeeds() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/sns/oauth2/access_token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "errcode": 0,
                "access_token": "tok123",
                "openid": "openid456",
            })))
            .mount(&server)
            .await;

        let provider = WechatProvider::new("wx_appid", "wx_secret")
            .with_token_url(format!("{}/sns/oauth2/access_token", server.uri()));
        let user_info = provider
            .exchange_token("code", "state")
            .await
            .expect("errcode=0 应返回 Ok");

        assert_eq!(user_info.provider_user_id, "openid456");
    }

    /// WechatProvider::get_user_info errcode=0 时不返回错误（边界：errcode 存在但为 0）。
    #[tokio::test]
    async fn wechat_provider_get_user_info_errcode_zero_succeeds() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/sns/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "errcode": 0,
                "openid": "openid_ok",
                "nickname": "Alice",
            })))
            .mount(&server)
            .await;

        let provider = WechatProvider::new("wx_appid", "wx_secret")
            .with_userinfo_url(format!("{}/sns/userinfo", server.uri()));
        let user_info = provider
            .get_user_info("tok|openid")
            .await
            .expect("errcode=0 应返回 Ok");

        assert_eq!(user_info.provider_user_id, "openid_ok");
        assert_eq!(user_info.nickname.as_deref(), Some("Alice"));
    }
}
