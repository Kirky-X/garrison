//! OAuth2 协议模块，提供 Authorization Code / Client Credentials / Password / Refresh Token 四种授权流程。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 OAuth2 协议支持，
//! 基于 `reqwest` crate 实现 HTTP 请求。
//!
//! 仅在启用 `protocol-oauth2` 特性时编译。
//!
//! ## 设计决策（依据 spec protocol-oauth2 + design.md Decision 5）
//!
//! - `OAuth2Client` 不持久化 token，由业务方决定存储方式。
//! - HTTP 客户端使用 `reqwest` 0.13（rustls-tls，禁用 native-tls）。
//! - 实现四种授权流程：Authorization Code / Client Credentials / Password / Refresh Token（0.4.0 新增）。

use crate::error::{BulwarkError, BulwarkResult};
use serde::Deserialize;

/// OIDC 扩展模块（0.4.0 新增，依据 spec oauth2-oidc）。
///
/// 提供 `OidcHandler` 用于签发/验证 OIDC id_token + discovery endpoint 元数据生成。
/// 仅在启用 `protocol-oidc` feature 时编译。
#[cfg(feature = "protocol-oidc")]
pub mod oidc;

/// Scope Handler 注册表模块（0.4.0 新增，依据 spec oauth2-scope-handler）。
///
/// 提供 `ScopeHandler` trait + `ScopeRegistry` 动态注册表，用于在 OAuth2 token
/// 请求前对 scope 进行客户端策略校验。仅在启用 `oauth2-scope-handler` feature 时编译。
#[cfg(feature = "oauth2-scope-handler")]
pub mod scope;

/// OAuth2 令牌响应（依据 spec protocol-oauth2）。
///
/// 授权服务器返回的 JSON 通过 `Deserialize` 解析。
/// 可选字段使用 `#[serde(default)]` 以容忍授权服务器省略部分字段。
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct TokenResponse {
    /// 访问令牌（必填）。
    pub access_token: String,
    /// 令牌类型（必填，通常为 "Bearer"）。
    pub token_type: String,
    /// 过期时间（秒，可选）。
    #[serde(default)]
    pub expires_in: Option<i64>,
    /// 刷新令牌（可选）。
    #[serde(default)]
    pub refresh_token: Option<String>,
    /// 作用域（可选）。
    #[serde(default)]
    pub scope: Option<String>,
}

/// OAuth2 客户端（依据 spec protocol-oauth2）。
///
/// 持有 OAuth2 协议所需的配置信息与可复用的 `reqwest::Client`。
/// 实现 `Send + Sync`，可在多线程环境共享。
pub struct OAuth2Client {
    /// 客户端 ID。
    client_id: String,
    /// 客户端密钥。
    client_secret: String,
    /// 回调地址。
    redirect_uri: String,
    /// 授权端点 URL。
    auth_url: String,
    /// 令牌端点 URL。
    token_url: String,
    /// 用户信息端点 URL（可选）。
    user_info_url: Option<String>,
    /// 可复用的 HTTP 客户端。
    http: reqwest::Client,
    /// Scope 注册表（可选，仅在启用 `oauth2-scope-handler` feature 时存在）。
    /// 注入后，`get_password_token` / `get_client_credentials_token` / `refresh_access_token`
    /// 在发送 HTTP 请求前委托 `validate_scope` 校验。
    #[cfg(feature = "oauth2-scope-handler")]
    scope_registry: Option<std::sync::Arc<scope::ScopeRegistry>>,
}

impl OAuth2Client {
    /// 创建新的 OAuth2 客户端（依据 spec protocol-oauth2）。
    ///
    /// # 参数
    /// - `client_id`: 客户端 ID，不可为空。
    /// - `client_secret`: 客户端密钥。
    /// - `redirect_uri`: 回调地址。
    /// - `auth_url`: 授权端点 URL。
    /// - `token_url`: 令牌端点 URL。
    ///
    /// # 错误
    /// - `BulwarkError::Config`: client_id 为空。
    /// - `BulwarkError::Network`: reqwest::Client 构建失败。
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
    ) -> BulwarkResult<Self> {
        let client_id = client_id.into();
        if client_id.is_empty() {
            return Err(BulwarkError::Config("client_id 不可为空".to_string()));
        }
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| BulwarkError::Network(format!("构建 HTTP 客户端失败: {}", e)))?;
        Ok(Self {
            client_id,
            client_secret: client_secret.into(),
            redirect_uri: redirect_uri.into(),
            auth_url: auth_url.into(),
            token_url: token_url.into(),
            user_info_url: None,
            http,
            #[cfg(feature = "oauth2-scope-handler")]
            scope_registry: None,
        })
    }

    /// 设置用户信息端点 URL（依据 spec protocol-oauth2）。
    pub fn with_user_info_url(mut self, url: impl Into<String>) -> Self {
        self.user_info_url = Some(url.into());
        self
    }

    /// 注入 ScopeRegistry，启用 token 请求前的 scope 校验（0.4.0 新增，依据 spec oauth2-scope-handler）。
    ///
    /// 仅在启用 `oauth2-scope-handler` feature 时可用。
    /// 注入后，`get_password_token` / `get_client_credentials_token` / `refresh_access_token`
    /// 在发送 HTTP 请求前委托 `ScopeRegistry::validate` 校验 scope。
    #[cfg(feature = "oauth2-scope-handler")]
    pub fn with_scope_registry(mut self, registry: std::sync::Arc<scope::ScopeRegistry>) -> Self {
        self.scope_registry = Some(registry);
        self
    }

    /// 校验 scope（0.4.0 新增，依据 spec oauth2-scope-handler）。
    ///
    /// - 若 `scope_registry` 未注入 → 跳过校验（Ok(())）。
    /// - 若 `scope` 为 None → 跳过校验（Ok(())）。
    /// - 若 `ScopeRegistry::validate` 返回 `Ok(false)` → 返回 `OAuth2("scope validation failed: ...")`。
    /// - 若 `ScopeRegistry::validate` 返回 `Err` → 向上传播。
    ///
    /// # 参数
    /// - `scope`: OAuth2 请求中的 scope 参数（可能为 None）。
    ///
    /// # 关于 login_id
    /// OAuth2 客户端流程在 token 请求时通常尚未解析出 login_id（password 流需先认证、
    /// client_credentials 流无用户、refresh_token 流需先解码 refresh_token）。
    /// 此处传入 `login_id = 0` 占位，handler 实现可按需通过其他上下文查询真实 login_id。
    /// 详见 `scope` 模块文档说明。
    #[cfg(feature = "oauth2-scope-handler")]
    async fn validate_scope(&self, scope: Option<&str>) -> BulwarkResult<()> {
        if let (Some(registry), Some(s)) = (&self.scope_registry, scope) {
            let allowed = registry.validate(s, 0)?;
            if !allowed {
                return Err(BulwarkError::OAuth2(format!(
                    "scope validation failed: {}",
                    s
                )));
            }
        }
        Ok(())
    }

    /// 获取授权端点 URL。
    pub fn auth_url(&self) -> &str {
        &self.auth_url
    }

    /// 获取令牌端点 URL。
    pub fn token_url(&self) -> &str {
        &self.token_url
    }

    /// 获取用户信息端点 URL。
    pub fn user_info_url(&self) -> Option<&str> {
        self.user_info_url.as_deref()
    }

    /// 构造 Authorization Code 流程的授权 URL（依据 spec protocol-oauth2）。
    ///
    /// URL 拼接 `response_type=code`、`client_id`、`redirect_uri`（URL 编码）、`state` 参数。
    pub fn get_auth_url(&self, state: &str) -> String {
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&state={}",
            self.auth_url,
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&self.redirect_uri),
            urlencoding::encode(state),
        )
    }

    /// 使用授权码换取令牌（依据 spec protocol-oauth2）。
    ///
    /// POST 请求 `token_url`，以 `application/x-www-form-urlencoded` 格式提交
    /// `grant_type=authorization_code`、`code`、`redirect_uri`、`client_id`、`client_secret`。
    pub async fn exchange_code(&self, code: &str, _state: &str) -> BulwarkResult<TokenResponse> {
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.redirect_uri),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ];
        self.post_token_request(&params).await
    }

    /// 获取 Client Credentials 模式令牌（依据 spec protocol-oauth2）。
    ///
    /// POST 请求 `token_url` 提交 `grant_type=client_credentials`、`client_id`、`client_secret`，可选 `scope`。
    pub async fn get_client_credentials_token(
        &self,
        scope: Option<&str>,
    ) -> BulwarkResult<TokenResponse> {
        #[cfg(feature = "oauth2-scope-handler")]
        self.validate_scope(scope).await?;
        let mut params: Vec<(&str, &str)> = vec![
            ("grant_type", "client_credentials"),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ];
        if let Some(s) = scope {
            params.push(("scope", s));
        }
        self.post_token_request(&params).await
    }

    /// 获取 Password 模式令牌（依据 spec protocol-oauth2）。
    ///
    /// POST 请求 `token_url` 提交 `grant_type=password`、`username`、`password`、
    /// `client_id`、`client_secret`，可选 `scope`。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidParam`: username 为空。
    pub async fn get_password_token(
        &self,
        username: &str,
        password: &str,
        scope: Option<&str>,
    ) -> BulwarkResult<TokenResponse> {
        if username.is_empty() {
            return Err(BulwarkError::InvalidParam("username 不可为空".to_string()));
        }
        #[cfg(feature = "oauth2-scope-handler")]
        self.validate_scope(scope).await?;
        let mut params: Vec<(&str, &str)> = vec![
            ("grant_type", "password"),
            ("username", username),
            ("password", password),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ];
        if let Some(s) = scope {
            params.push(("scope", s));
        }
        self.post_token_request(&params).await
    }

    /// 使用 refresh_token 换取新的 access_token（0.4.0 新增，依据 spec protocol-oauth2 RefreshToken GrantType）。
    ///
    /// POST 请求 `token_url` 提交 `grant_type=refresh_token`、`refresh_token`、
    /// `client_id`、`client_secret`，可选 `scope`（用于缩小/扩大授权范围）。
    ///
    /// # 参数
    /// - `refresh_token`: 之前获取的刷新令牌，不可为空。
    /// - `scope`: 可选，请求的 scope（可不同于原始授权范围）。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidParam`: refresh_token 为空。
    /// - `BulwarkError::OAuth2`: token_endpoint 返回非 2xx 或 JSON 解析失败。
    /// - `BulwarkError::Network`: reqwest 请求失败（DNS/连接超时等）。
    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
        scope: Option<&str>,
    ) -> BulwarkResult<TokenResponse> {
        if refresh_token.is_empty() {
            return Err(BulwarkError::InvalidParam(
                "refresh_token 不可为空".to_string(),
            ));
        }
        #[cfg(feature = "oauth2-scope-handler")]
        self.validate_scope(scope).await?;
        let mut params: Vec<(&str, &str)> = vec![
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ];
        if let Some(s) = scope {
            params.push(("scope", s));
        }
        self.post_token_request(&params).await
    }

    /// 内部方法：POST 请求 token 端点并解析响应。
    async fn post_token_request(&self, params: &[(&str, &str)]) -> BulwarkResult<TokenResponse> {
        let resp = self
            .http
            .post(&self.token_url)
            .form(params)
            .send()
            .await
            .map_err(|e| BulwarkError::Network(format!("请求 token 端点失败: {}", e)))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp
                .text()
                .await
                .map_err(|e| BulwarkError::Network(format!("读取错误响应失败: {}", e)))?;
            return Err(BulwarkError::OAuth2(format!(
                "HTTP {}: {}",
                status.as_u16(),
                body
            )));
        }

        let token = resp
            .json::<TokenResponse>()
            .await
            .map_err(|e| BulwarkError::OAuth2(format!("解析 token 响应失败: {}", e)))?;
        Ok(token)
    }
}

/// 简单的 URL 编码工具（避免引入 `urlencoding` crate 依赖）。
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
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// 创建测试用 OAuth2Client，指向 mock server。
    async fn make_client(server: &MockServer) -> OAuth2Client {
        let base = server.uri();
        OAuth2Client::new(
            "test-client-id",
            "test-client-secret",
            "https://example.com/callback",
            format!("{}/auth", base),
            format!("{}/token", base),
        )
        .expect("创建 OAuth2Client 失败")
    }

    // ========================================================================
    // OAuth2Client 构造测试（依据 spec protocol-oauth2）
    // ========================================================================

    /// 构造 OAuth2Client，字段正确填充（spec Scenario）。
    #[test]
    fn new_populates_fields() {
        let client = OAuth2Client::new(
            "cid",
            "secret",
            "https://example.com/cb",
            "https://example.com/auth",
            "https://example.com/token",
        )
        .expect("创建失败");
        assert_eq!(client.auth_url(), "https://example.com/auth");
        assert_eq!(client.token_url(), "https://example.com/token");
        assert_eq!(client.user_info_url(), None);
    }

    /// client_id 为空返回 Config 错误（spec Scenario）。
    #[test]
    fn new_empty_client_id_returns_config_error() {
        let result = OAuth2Client::new("", "secret", "redirect", "auth", "token");
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::Config(_)) => {},
            other => panic!("期望 Config 错误，实际: {:?}", other),
        }
    }

    /// with_user_info_url 设置用户信息端点（spec Scenario）。
    #[test]
    fn with_user_info_url_sets_url() {
        let client = OAuth2Client::new("cid", "secret", "redirect", "auth", "token")
            .unwrap()
            .with_user_info_url("https://example.com/userinfo");
        assert_eq!(client.user_info_url(), Some("https://example.com/userinfo"));
    }

    // ========================================================================
    // get_auth_url 测试（依据 spec protocol-oauth2）
    // ========================================================================

    /// 构造标准授权 URL（spec Scenario）。
    #[test]
    fn get_auth_url_contains_required_params() {
        let client = OAuth2Client::new(
            "my-client",
            "secret",
            "https://example.com/callback",
            "https://auth.example.com/authorize",
            "https://token.example.com/token",
        )
        .unwrap();
        let url = client.get_auth_url("xyz-state");
        assert!(url.starts_with("https://auth.example.com/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=my-client"));
        assert!(url.contains("state=xyz-state"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"));
    }

    /// state 为空时仍包含 state 参数（spec Scenario）。
    #[test]
    fn get_auth_url_empty_state_still_includes_state() {
        let client = OAuth2Client::new("cid", "secret", "redirect", "auth", "token").unwrap();
        let url = client.get_auth_url("");
        assert!(url.contains("state="));
    }

    // ========================================================================
    // TokenResponse 解析测试（依据 spec protocol-oauth2）
    // ========================================================================

    /// 完整 JSON 解析（spec Scenario）。
    #[test]
    fn token_response_full_json_parse() {
        let json = r#"{"access_token":"abc","token_type":"Bearer","expires_in":3600,"refresh_token":"r1","scope":"read"}"#;
        let tr: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(tr.access_token, "abc");
        assert_eq!(tr.token_type, "Bearer");
        assert_eq!(tr.expires_in, Some(3600));
        assert_eq!(tr.refresh_token, Some("r1".to_string()));
        assert_eq!(tr.scope, Some("read".to_string()));
    }

    /// 省略可选字段解析（spec Scenario）。
    #[test]
    fn token_response_omit_optional_fields() {
        let json = r#"{"access_token":"abc","token_type":"Bearer"}"#;
        let tr: TokenResponse = serde_json::from_str(json).unwrap();
        assert_eq!(tr.access_token, "abc");
        assert_eq!(tr.expires_in, None);
        assert_eq!(tr.refresh_token, None);
        assert_eq!(tr.scope, None);
    }

    /// 缺少必填字段返回反序列化错误（spec Scenario）。
    #[test]
    fn token_response_missing_required_field_errors() {
        let json = r#"{"token_type":"Bearer"}"#;
        let result: Result<TokenResponse, _> = serde_json::from_str(json);
        assert!(result.is_err());
    }

    // ========================================================================
    // exchange_code 集成测试（依据 spec protocol-oauth2）
    // ========================================================================

    /// 成功换取令牌（spec Scenario）。
    #[tokio::test]
    async fn exchange_code_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "abc123",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "r1",
                "scope": "read"
            })))
            .mount(&server)
            .await;

        let client = make_client(&server).await;
        let token = client.exchange_code("valid-code", "state").await.unwrap();
        assert_eq!(token.access_token, "abc123");
        assert_eq!(token.token_type, "Bearer");
        assert_eq!(token.expires_in, Some(3600));
        assert_eq!(token.refresh_token, Some("r1".to_string()));
        assert_eq!(token.scope, Some("read".to_string()));
    }

    /// code 无效返回 OAuth2 错误（spec Scenario）。
    #[tokio::test]
    async fn exchange_code_invalid_code_returns_oauth2_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "Invalid authorization code"
            })))
            .mount(&server)
            .await;

        let client = make_client(&server).await;
        let result = client.exchange_code("invalid-code", "state").await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::OAuth2(_)) => {},
            other => panic!("期望 OAuth2 错误，实际: {:?}", other),
        }
    }

    // ========================================================================
    // get_client_credentials_token 集成测试（依据 spec protocol-oauth2）
    // ========================================================================

    /// 成功获取 client credentials token（spec Scenario）。
    #[tokio::test]
    async fn client_credentials_with_scope_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "cc-token",
                "token_type": "Bearer",
                "expires_in": 1800,
                "scope": "read write"
            })))
            .mount(&server)
            .await;

        let client = make_client(&server).await;
        let token = client
            .get_client_credentials_token(Some("read write"))
            .await
            .unwrap();
        assert_eq!(token.access_token, "cc-token");
        assert_eq!(token.scope, Some("read write".to_string()));
    }

    /// 不带 scope 成功获取 token（spec Scenario）。
    #[tokio::test]
    async fn client_credentials_without_scope_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "cc-token",
                "token_type": "Bearer"
            })))
            .mount(&server)
            .await;

        let client = make_client(&server).await;
        let token = client.get_client_credentials_token(None).await.unwrap();
        assert_eq!(token.access_token, "cc-token");
        assert_eq!(token.scope, None);
    }

    /// client_secret 错误返回 OAuth2 错误（spec Scenario）。
    #[tokio::test]
    async fn client_credentials_wrong_secret_returns_oauth2_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "invalid_client"
            })))
            .mount(&server)
            .await;

        let client = make_client(&server).await;
        let result = client.get_client_credentials_token(None).await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::OAuth2(_)) => {},
            other => panic!("期望 OAuth2 错误，实际: {:?}", other),
        }
    }

    // ========================================================================
    // get_password_token 集成测试（依据 spec protocol-oauth2）
    // ========================================================================

    /// 成功获取 password token（spec Scenario）。
    #[tokio::test]
    async fn password_token_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "pwd-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": "read"
            })))
            .mount(&server)
            .await;

        let client = make_client(&server).await;
        let token = client
            .get_password_token("alice", "pwd123", Some("read"))
            .await
            .unwrap();
        assert_eq!(token.access_token, "pwd-token");
    }

    /// 凭据错误返回 OAuth2 错误（spec Scenario）。
    #[tokio::test]
    async fn password_token_wrong_credentials_returns_oauth2_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
                "error": "invalid_grant"
            })))
            .mount(&server)
            .await;

        let client = make_client(&server).await;
        let result = client.get_password_token("alice", "wrong-pwd", None).await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::OAuth2(_)) => {},
            other => panic!("期望 OAuth2 错误，实际: {:?}", other),
        }
    }

    /// 用户名为空返回 InvalidParam 错误（spec Scenario）。
    #[tokio::test]
    async fn password_token_empty_username_returns_invalid_param() {
        let server = MockServer::start().await;
        let client = make_client(&server).await;
        let result = client.get_password_token("", "pwd", None).await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::InvalidParam(_)) => {},
            other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
        }
    }

    // ========================================================================
    // refresh_access_token 集成测试（0.4.0 新增，依据 spec protocol-oauth2 RefreshToken GrantType）
    // ========================================================================

    /// 成功使用 refresh_token 换取新 access_token（spec Scenario: refresh_access_token 成功）。
    #[tokio::test]
    async fn refresh_access_token_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "new-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "new-refresh-token",
                "scope": "openid profile"
            })))
            .mount(&server)
            .await;

        let client = make_client(&server).await;
        let token = client
            .refresh_access_token("old-refresh-token", None)
            .await
            .unwrap();
        assert_eq!(token.access_token, "new-access-token");
        assert_eq!(token.token_type, "Bearer");
        assert_eq!(token.expires_in, Some(3600));
        assert_eq!(token.refresh_token, Some("new-refresh-token".to_string()));
        assert_eq!(token.scope, Some("openid profile".to_string()));
    }

    /// 带 scope 参数成功换取新 token（spec Scenario: refresh_access_token 成功）。
    #[tokio::test]
    async fn refresh_access_token_with_scope_success() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "scoped-token",
                "token_type": "Bearer",
                "expires_in": 1800,
                "scope": "admin"
            })))
            .mount(&server)
            .await;

        let client = make_client(&server).await;
        let token = client
            .refresh_access_token("old-refresh", Some("admin"))
            .await
            .unwrap();
        assert_eq!(token.access_token, "scoped-token");
        assert_eq!(token.scope, Some("admin".to_string()));
    }

    /// token_endpoint 返回 HTTP 400 错误响应（spec Scenario: refresh_access_token 错误响应）。
    #[tokio::test]
    async fn refresh_access_token_error_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
                "error": "invalid_grant",
                "error_description": "The refresh token is invalid or expired."
            })))
            .mount(&server)
            .await;

        let client = make_client(&server).await;
        let result = client
            .refresh_access_token("expired-refresh-token", None)
            .await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::OAuth2(msg)) => {
                assert!(msg.contains("400"), "错误消息应包含 HTTP 状态码 400");
            }
            other => panic!("期望 OAuth2 错误，实际: {:?}", other),
        }
    }

    /// refresh_token 为空返回 InvalidParam 错误（spec Scenario: refresh_access_token 参数校验）。
    #[tokio::test]
    async fn refresh_access_token_empty_token_returns_invalid_param() {
        let server = MockServer::start().await;
        let client = make_client(&server).await;
        let result = client.refresh_access_token("", None).await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::InvalidParam(_)) => {},
            other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
        }
    }

    // ========================================================================
    // urlencoding 模块测试
    // ========================================================================

    /// URL 编码保留安全字符。
    #[test]
    fn url_encode_preserves_safe_chars() {
        assert_eq!(urlencoding::encode("abc-_.~"), "abc-_.~");
    }

    /// URL 编码特殊字符。
    #[test]
    fn url_encode_encodes_special_chars() {
        assert_eq!(urlencoding::encode("a b/c:d"), "a%20b%2Fc%3Ad");
    }

    // ========================================================================
    // OAuth2Client + ScopeRegistry 集成测试（0.4.0 新增，依据 spec oauth2-scope-handler）
    // ========================================================================

    /// 测试用 ScopeHandler：根据 allowed 字段返回结果。
    #[cfg(feature = "oauth2-scope-handler")]
    struct StubScopeHandler {
        allowed: bool,
    }

    #[cfg(feature = "oauth2-scope-handler")]
    impl scope::ScopeHandler for StubScopeHandler {
        fn validate(&self, _scope: &str, _login_id: i64) -> BulwarkResult<bool> {
            Ok(self.allowed)
        }
    }

    /// 未注入 ScopeRegistry 时跳过校验（spec Scenario: 未注入跳过）。
    /// 既有 client_credentials_without_scope_success 等测试已覆盖此场景（未调用 with_scope_registry）。
    /// 这里追加验证：注入 registry 但 scope 为 None 时也跳过校验。
    #[tokio::test]
    #[cfg(feature = "oauth2-scope-handler")]
    async fn scope_registry_injected_but_none_scope_skips_validation() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "tok", "token_type": "Bearer"
            })))
            .mount(&server)
            .await;

        let registry = std::sync::Arc::new(scope::ScopeRegistry::new());
        // 注册一个始终拒绝的 handler，但 scope=None 时不应触发
        registry.register(
            "blocked",
            std::sync::Arc::new(StubScopeHandler { allowed: false }),
        );
        let client = make_client(&server)
            .await
            .with_scope_registry(registry);
        let token = client.get_client_credentials_token(None).await.unwrap();
        assert_eq!(token.access_token, "tok");
    }

    /// 注入 ScopeRegistry 后校验失败返回 OAuth2 错误，不发送 HTTP 请求（spec Scenario）。
    #[tokio::test]
    #[cfg(feature = "oauth2-scope-handler")]
    async fn scope_registry_rejects_scope_returns_oauth2_error() {
        let server = MockServer::start().await;
        // 不挂载任何 mock → 若发送 HTTP 请求会因无匹配 mock 返回 404（但被 reqwest 接收为 response）
        // 我们断言根本不会执行到 HTTP 调用阶段：validate_scope 失败时立即返回

        let registry = std::sync::Arc::new(scope::ScopeRegistry::new());
        registry.register(
            "admin",
            std::sync::Arc::new(StubScopeHandler { allowed: false }),
        );
        let client = make_client(&server)
            .await
            .with_scope_registry(registry);

        let result = client
            .get_password_token("user", "pass", Some("admin"))
            .await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::OAuth2(msg)) => assert!(msg.contains("scope validation failed: admin")),
            other => panic!("期望 OAuth2 错误，实际: {:?}", other),
        }
    }

    /// 注入 ScopeRegistry 后校验通过发送 HTTP 请求（spec Scenario 反向验证）。
    #[tokio::test]
    #[cfg(feature = "oauth2-scope-handler")]
    async fn scope_registry_allows_scope_proceeds_to_http() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "ok", "token_type": "Bearer"
            })))
            .mount(&server)
            .await;

        let registry = std::sync::Arc::new(scope::ScopeRegistry::new());
        registry.register(
            "read",
            std::sync::Arc::new(StubScopeHandler { allowed: true }),
        );
        let client = make_client(&server)
            .await
            .with_scope_registry(registry);

        let token = client
            .get_client_credentials_token(Some("read"))
            .await
            .unwrap();
        assert_eq!(token.access_token, "ok");
    }

    /// ScopeHandler 返回错误时向上传播（Fail Loud），不发送 HTTP 请求。
    #[tokio::test]
    #[cfg(feature = "oauth2-scope-handler")]
    async fn scope_handler_error_propagates_without_http() {
        use crate::error::BulwarkError;

        struct ErrScopeHandler;
        impl scope::ScopeHandler for ErrScopeHandler {
            fn validate(&self, _scope: &str, _login_id: i64) -> BulwarkResult<bool> {
                Err(BulwarkError::Internal("handler failure".to_string()))
            }
        }

        let server = MockServer::start().await;
        let registry = std::sync::Arc::new(scope::ScopeRegistry::new());
        registry.register("bad", std::sync::Arc::new(ErrScopeHandler));
        let client = make_client(&server)
            .await
            .with_scope_registry(registry);

        let result = client
            .refresh_access_token("rtok", Some("bad"))
            .await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::Internal(msg)) => assert!(msg.contains("handler failure")),
            other => panic!("期望 Internal 错误，实际: {:?}", other),
        }
    }

    /// 未注册的 scope 返回 OAuth2 错误，不发送 HTTP 请求。
    #[tokio::test]
    #[cfg(feature = "oauth2-scope-handler")]
    async fn unregistered_scope_returns_oauth2_error_without_http() {
        let server = MockServer::start().await;
        let registry = std::sync::Arc::new(scope::ScopeRegistry::new());
        // 不注册任何 handler
        let client = make_client(&server)
            .await
            .with_scope_registry(registry);

        let result = client
            .get_password_token("user", "pass", Some("unregistered"))
            .await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::OAuth2(msg)) => {
                assert!(msg.contains("scope handler not registered: unregistered"))
            }
            other => panic!("期望 OAuth2 错误，实际: {:?}", other),
        }
    }
}
