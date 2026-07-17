//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OAuth2 客户端实现。
//!
//! `OAuth2Client` 持有 OAuth2 协议所需的配置信息与可复用的 `reqwest::Client`，
//! 实现 Authorization Code / Client Credentials / Password / Refresh Token 四种授权流程，
//! 以及 Token Introspection (RFC 7662)。
//!
//! 仅在启用 `protocol-oauth2` 特性时编译。

use crate::error::{BulwarkError, BulwarkResult};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sha2::{Digest, Sha256};

use super::{TokenIntrospectionResponse, TokenResponse};

/// URL 编码字符集。
///
/// 与原自实现 `encode` 行为等价：保留 `A-Z a-z 0-9 - _ . ~`，
/// 其他字符按 `%HH` 编码。基于 `NON_ALPHANUMERIC` 移除 `- _ . ~` 四个保留字符得到。
const URLENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// 对字符串进行 URL 百分号编码（保留 `A-Z a-z 0-9 - _ . ~`）。
///
/// 与原自实现模块行为完全等价，内部委托 `percent-encoding` crate。
fn url_encode(s: &str) -> String {
    utf8_percent_encode(s, URLENCODE_SET).to_string()
}

/// OAuth2 客户端。
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
    /// Token Introspection 端点 URL（可选）。
    /// 为 `None` 时由 `introspect_url()` 从 `token_url` 推导（`/token` → `/introspect`）。
    introspect_url: Option<String>,
    /// 可复用的 HTTP 客户端。
    http: reqwest::Client,
    /// Scope 注册表（可选，仅在启用 `oauth2-scope-handler` feature 时存在）。
    /// 注入后，`get_password_token` / `get_client_credentials_token` / `refresh_access_token`
    /// 在发送 HTTP 请求前委托 `validate_scope` 校验。
    #[cfg(feature = "oauth2-scope-handler")]
    scope_registry: Option<std::sync::Arc<super::scope::ScopeRegistry>>,
}

impl OAuth2Client {
    /// 创建新的 OAuth2 客户端。
    ///
    /// # 参数
    /// - `client_id`: 客户端 ID，不可为空。
    /// - `client_secret`: 客户端密钥。
    /// - `redirect_uri`: 回调地址，必须为 https 或 localhost/127.0.0.1（spec P2.3）。
    /// - `auth_url`: 授权端点 URL。
    /// - `token_url`: 令牌端点 URL。
    ///
    /// # 错误
    /// - `BulwarkError::Config`: client_id 为空。
    /// - `BulwarkError::InvalidParam`: redirect_uri 非 https 且非 localhost/127.0.0.1（spec P2.3）。
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
        let redirect_uri = redirect_uri.into();
        Self::validate_redirect_uri(&redirect_uri)?;
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| BulwarkError::Network(format!("构建 HTTP 客户端失败: {}", e)))?;
        Ok(Self {
            client_id,
            client_secret: client_secret.into(),
            redirect_uri,
            auth_url: auth_url.into(),
            token_url: token_url.into(),
            user_info_url: None,
            introspect_url: None,
            http,
            #[cfg(feature = "oauth2-scope-handler")]
            scope_registry: None,
        })
    }

    /// 校验 redirect_uri scheme（spec P2.3）。
    ///
    /// 仅允许以下两种：
    /// - `https://` 任意 host
    /// - `http://localhost` 或 `http://127.0.0.1`（开发环境例外，任意端口）
    ///
    /// 其他 scheme（如 `http://evil.com`）返回 `InvalidParam`，避免授权码经明文 HTTP
    /// 回调到公网域名被中间人截获。
    ///
    /// # 安全说明
    ///
    /// 此函数仅校验 **传输层安全**（HTTPS or localhost），不做精确域名匹配。
    /// 精确 redirect_uri 匹配（与客户端注册的回调地址比对）是**授权服务器的职责**，
    /// 非客户端库的职责。使用本库构建授权服务器时，必须在此校验之上自行实现：
    ///
    /// 1. 精确字符串匹配（非前缀/子域名匹配）
    /// 2. 防止路径遍历（如 `https://app.com/../evil`）
    /// 3. 防止参数注入（如 `https://app.com/callback?redirect=evil`）
    /// 4. 防止 fragment 泄漏（如 `https://app.com/callback#code=xxx`）
    ///
    /// # 参数
    /// - `redirect_uri`: 回调地址字符串。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidParam`: redirect_uri 无 `://`、scheme 非 https/http、
    ///   或 http 但 host 非 localhost/127.0.0.1。
    fn validate_redirect_uri(redirect_uri: &str) -> BulwarkResult<()> {
        let Some(scheme_end) = redirect_uri.find("://") else {
            return Err(BulwarkError::InvalidParam(format!(
                "redirect_uri must be https or localhost, got: {}",
                redirect_uri
            )));
        };
        let scheme = &redirect_uri[..scheme_end];
        let rest = &redirect_uri[scheme_end + 3..];

        if scheme == "https" {
            return Ok(());
        }

        if scheme == "http" {
            // host: "://" 之后到下一个 '/' / ':' / '?' 之前
            let host_end = rest.find(['/', ':', '?']).unwrap_or(rest.len());
            let host = &rest[..host_end];
            if host == "localhost" || host == "127.0.0.1" {
                return Ok(());
            }
        }

        Err(BulwarkError::InvalidParam(format!(
            "redirect_uri must be https or localhost, got: {}",
            redirect_uri
        )))
    }

    /// 设置用户信息端点 URL。
    pub fn with_user_info_url(mut self, url: impl Into<String>) -> Self {
        self.user_info_url = Some(url.into());
        self
    }

    /// 设置 Token Introspection 端点 URL。
    ///
    /// 不设置时，[`introspect_token`](Self::introspect_token) 从 `token_url` 推导：
    /// `token_url` 末尾为 `/token` → 替换为 `/introspect`；否则在 `token_url` 末尾追加 `/introspect`。
    ///
    /// # 参数
    /// - `url`: 完整的 introspection 端点 URL（如 `https://auth.example.com/oauth2/introspect`）。
    pub fn with_introspect_url(mut self, url: impl Into<String>) -> Self {
        self.introspect_url = Some(url.into());
        self
    }

    /// 注入 ScopeRegistry，启用 token 请求前的 scope 校验。
    ///
    /// 仅在启用 `oauth2-scope-handler` feature 时可用。
    /// 注入后，`get_password_token` / `get_client_credentials_token` / `refresh_access_token`
    /// 在发送 HTTP 请求前委托 `ScopeRegistry::validate` 校验 scope。
    #[cfg(feature = "oauth2-scope-handler")]
    pub fn with_scope_registry(
        mut self,
        registry: std::sync::Arc<super::scope::ScopeRegistry>,
    ) -> Self {
        self.scope_registry = Some(registry);
        self
    }

    /// 校验 scope。
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

    /// 生成 PKCE code_challenge。
    ///
    /// 计算方式：`code_challenge = base64url_no_pad(sha256(code_verifier))`
    ///
    /// # 参数
    /// - `code_verifier`: 43-128 字符，仅包含 `[A-Z]/[a-z]/[0-9]/-./_/~`
    ///
    /// # 错误
    /// - `BulwarkError::InvalidParam`: 长度不在 43-128 范围内或含非法字符。
    ///
    /// # 示例
    /// RFC 7636 Appendix B 测试向量：
    /// ```
    /// # use bulwark::protocol::oauth2::OAuth2Client;
    /// let challenge = OAuth2Client::generate_pkce_challenge(
    ///     "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    /// ).unwrap();
    /// assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    /// ```
    pub fn generate_pkce_challenge(code_verifier: &str) -> BulwarkResult<String> {
        // 1. 验证长度 43-128（RFC 7636 §4.1）
        if code_verifier.len() < 43 || code_verifier.len() > 128 {
            return Err(BulwarkError::InvalidParam(format!(
                "code_verifier 长度必须在 43-128 之间，当前 {}",
                code_verifier.len()
            )));
        }
        // 2. 验证字符集 [A-Z]/[a-z]/[0-9]/-./_/~（RFC 7636 §4.1）
        if !code_verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == '~')
        {
            return Err(BulwarkError::InvalidParam(
                "code_verifier 仅允许 [A-Z]/[a-z]/[0-9]/-/./_/~ 字符".to_string(),
            ));
        }
        // 3. S256: SHA-256 → base64url 无填充
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let digest = hasher.finalize();
        Ok(URL_SAFE_NO_PAD.encode(digest))
    }

    /// 构造 Authorization Code 流程的授权 URL。
    ///
    /// URL 拼接 `response_type=code`、`client_id`、`redirect_uri`（URL 编码）、`state` 参数。
    ///
    /// # 弃用
    /// OAuth 2.1 要求所有 Authorization Code 流程使用 PKCE。请改用 [`get_auth_url_with_pkce`](Self::get_auth_url_with_pkce)。
    #[deprecated(note = "use get_auth_url_with_pkce for OAuth 2.1 compliance")]
    pub fn get_auth_url(&self, state: &str) -> String {
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&state={}",
            self.auth_url,
            url_encode(&self.client_id),
            url_encode(&self.redirect_uri),
            url_encode(state),
        )
    }

    /// 构造带 PKCE 的授权 URL。
    ///
    /// 在 [`get_auth_url`](Self::get_auth_url) 基础上追加 `code_challenge` 与 `code_challenge_method=S256` 参数。
    ///
    /// # 参数
    /// - `state`: CSRF 防护随机串。
    /// - `code_verifier`: PKCE code_verifier（43-128 字符，合法字符集见 [`generate_pkce_challenge`](Self::generate_pkce_challenge)）。
    ///
    /// # 返回
    /// `(authorization_url, code_challenge)` 元组。`code_challenge` 供调用方与后续 token 交换时关联使用。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidParam`: `code_verifier` 不合法（透传自 `generate_pkce_challenge`）。
    pub fn get_auth_url_with_pkce(
        &self,
        state: &str,
        code_verifier: &str,
    ) -> BulwarkResult<(String, String)> {
        let code_challenge = Self::generate_pkce_challenge(code_verifier)?;
        let url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&state={}&code_challenge={}&code_challenge_method=S256",
            self.auth_url,
            url_encode(&self.client_id),
            url_encode(&self.redirect_uri),
            url_encode(state),
            url_encode(&code_challenge),
        );
        Ok((url, code_challenge))
    }

    /// 使用授权码换取令牌。
    ///
    /// POST 请求 `token_url`，以 `application/x-www-form-urlencoded` 格式提交
    /// `grant_type=authorization_code`、`code`、`redirect_uri`、`client_id`、`client_secret`。
    ///
    /// # 弃用
    /// OAuth 2.1 要求所有 Authorization Code 流程使用 PKCE。请改用 [`exchange_code_with_pkce`](Self::exchange_code_with_pkce)。
    #[deprecated(note = "use exchange_code_with_pkce for OAuth 2.1 compliance")]
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

    /// 使用授权码 + PKCE 换取令牌。
    ///
    /// 在 [`exchange_code`](Self::exchange_code) 基础上，POST 请求体追加 `code_verifier` 字段。
    /// 授权服务器重新计算 `SHA256(code_verifier)` 并与授权请求中的 `code_challenge` 比对，验证客户端身份。
    ///
    /// # CSRF 防护（state 校验）
    ///
    /// 调用方传入 `expected_state`（构造授权 URL 时生成的 state）和 `actual_state`（回调 URL 中
    /// 授权服务器返回的 state），方法内部自动比对。若不匹配则返回 `BulwarkError::OAuth2`，
    /// 阻断 CSRF 攻击。
    ///
    /// # 参数
    /// - `code`: 授权码。
    /// - `expected_state`: 预期 state（构造授权 URL 时生成的 state）。
    /// - `actual_state`: 实际 state（回调 URL 中授权服务器返回的 state）。
    /// - `code_verifier`: PKCE code_verifier（需与构造授权 URL 时传入的 verifier 一致）。
    ///
    /// # 错误
    /// - `BulwarkError::OAuth2`: `expected_state` 与 `actual_state` 不匹配（CSRF 攻击防护）。
    /// - `BulwarkError::InvalidParam`: `code_verifier` 不合法（客户端预校验，透传自 `generate_pkce_challenge`）。
    /// - `BulwarkError::OAuth2`: token 端点返回非 2xx 或 JSON 解析失败。
    /// - `BulwarkError::Network`: reqwest 请求失败。
    pub async fn exchange_code_with_pkce(
        &self,
        code: &str,
        expected_state: &str,
        actual_state: &str,
        code_verifier: &str,
    ) -> BulwarkResult<TokenResponse> {
        // CSRF 防护：校验 state 参数
        if expected_state != actual_state {
            return Err(BulwarkError::OAuth2(
                "state 参数不匹配，可能遭受 CSRF 攻击".to_string(),
            ));
        }
        // 客户端预校验 code_verifier 合法性（即使服务器不校验，客户端也不应发送非法值）
        Self::generate_pkce_challenge(code_verifier)?;
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", &self.redirect_uri),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
            ("code_verifier", code_verifier),
        ];
        self.post_token_request(&params).await
    }

    /// 获取 Client Credentials 模式令牌。
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

    /// 获取 Password 模式令牌。
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

    /// 使用 refresh_token 换取新的 access_token。
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
            // H1 安全加固：错误消息只记录 HTTP status + url，不包含响应体或请求参数
            // （响应体可能被恶意服务器回显请求参数，导致 client_secret / code_verifier 泄露）
            return Err(BulwarkError::OAuth2(format!(
                "token endpoint returned {} for {}",
                status.as_u16(),
                self.token_url
            )));
        }

        let token = resp
            .json::<TokenResponse>()
            .await
            .map_err(|e| BulwarkError::OAuth2(format!("解析 token 响应失败: {}", e)))?;
        Ok(token)
    }

    /// 查询 token 状态。
    ///
    /// 向授权服务器的 introspection 端点 POST 请求，请求体以
    /// `application/x-www-form-urlencoded` 格式提交 `token` + `client_id` + `client_secret`，
    /// 响应解析为 [`TokenIntrospectionResponse`]。
    ///
    /// # 不缓存
    /// 每次调用都请求授权服务器，业务方如需缓存可自行封装。
    ///
    /// # 参数
    /// - `token`: 待查询的 access_token 或 refresh_token。
    ///
    /// # 返回
    /// `TokenIntrospectionResponse`，其中 `active` 字段表示 token 是否有效。
    ///
    /// # 错误
    /// - `BulwarkError::OAuth2`: 服务器返回非 2xx 或 JSON 解析失败。
    /// - `BulwarkError::Network`: reqwest 请求失败（DNS/连接超时/服务器不可达等）。
    pub async fn introspect_token(&self, token: &str) -> BulwarkResult<TokenIntrospectionResponse> {
        let url = self.introspect_url();
        let params = [
            ("token", token),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ];
        let resp = self
            .http
            .post(&url)
            .form(&params)
            .send()
            .await
            .map_err(|e| BulwarkError::Network(format!("请求 introspect 端点失败: {}", e)))?;

        let status = resp.status();
        if !status.is_success() {
            // H1 安全加固：错误消息只记录 HTTP status + url，不包含响应体或请求参数
            // （与 post_token_request 同类修复：响应体可能被恶意服务器回显请求参数，
            //   导致 client_secret 泄露到日志/上层调用方）
            return Err(BulwarkError::OAuth2(format!(
                "introspect endpoint returned {} for {}",
                status.as_u16(),
                url
            )));
        }

        let response = resp
            .json::<TokenIntrospectionResponse>()
            .await
            .map_err(|e| BulwarkError::OAuth2(format!("解析 introspection 响应失败: {}", e)))?;
        Ok(response)
    }

    /// 推导 introspection 端点 URL。
    ///
    /// - 若 [`with_introspect_url`](Self::with_introspect_url) 已设置 → 使用该 URL。
    /// - 否则若 `token_url` 末尾为 `/token` → 替换为 `/introspect`。
    /// - 否则在 `token_url` 末尾追加 `/introspect`。
    fn introspect_url(&self) -> String {
        if let Some(url) = &self.introspect_url {
            url.clone()
        } else if self.token_url.ends_with("/token") {
            self.token_url.replace("/token", "/introspect")
        } else {
            format!("{}/introspect", self.token_url)
        }
    }
}

#[cfg(feature = "protocol-zeroize")]
impl Drop for OAuth2Client {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.client_secret.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::url_encode;

    /// URL 编码保留安全字符（与原自实现 `encode` 行为等价）。
    #[test]
    fn url_encode_preserves_safe_chars() {
        assert_eq!(url_encode("abc-_.~"), "abc-_.~");
    }

    /// URL 编码特殊字符（与原自实现 `encode` 行为等价）。
    #[test]
    fn url_encode_encodes_special_chars() {
        assert_eq!(url_encode("a b/c:d"), "a%20b%2Fc%3Ad");
    }

    /// URLENCODE_SET 应保留 `- _ . ~` 四个字符（行为等价回归保护）。
    #[test]
    fn urlencode_set_preserves_unreserved_chars() {
        // unreserved 字符集（RFC 3986 §2.3）：A-Z a-z 0-9 - _ . ~
        for ch in ['-', '_', '.', '~'] {
            let s = ch.to_string();
            assert_eq!(url_encode(&s), s, "字符 {} 应被保留", ch);
        }
    }
}
