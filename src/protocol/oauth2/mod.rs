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
//! - 支持 Token Introspection (RFC 7662)：通过 `OAuth2Client::introspect_token` 查询 token 状态（0.4.2 新增）。

use crate::error::{BulwarkError, BulwarkResult};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

/// Keycloak OIDC RP 模块（0.5.0 新增，依据 proposal K1 / spec keycloak-oidc-rp）。
///
/// 提供 `KeycloakProvider` 作为 OIDC 依赖方（RP），对接 Keycloak IdP：
/// - `KeycloakConfig`：配置 base_url / client_id / client_secret / redirect_uri
/// - `KeycloakProvider`：discover（fetch discovery metadata）/ verify_id_token（JWKS 验签）
///   / exchange_code（authorization_code → token set）
/// - `KeycloakClaims`：Keycloak 特有 claim（realm_access.roles / resource_access / tenant_id）
///
/// 仅在启用 `keycloak-oidc` feature 时编译。
#[cfg(feature = "keycloak-oidc")]
pub mod keycloak;

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

/// Token Introspection 响应（依据 RFC 7662 / spec token-introspection R-token-introspection-002）。
///
/// 表示授权服务器对 token 的 introspection 结果。`active` 字段为必填，
/// 其他字段在 `active=true` 时由授权服务器按需返回；`active=false` 时通常省略。
///
/// # 字段语义（RFC 7662 §2.2）
/// - `active`: token 是否当前有效（必填）。
/// - `scope`: token 的 scope 列表（空格分隔字符串）。
/// - `client_id`: token 关联的客户端 ID。
/// - `username`: token 关联的人类可读用户名。
/// - `token_type`: token 类型（如 "Bearer"）。
/// - `exp`: token 过期时间（Unix 时间戳）。
/// - `iat`: token 签发时间（Unix 时间戳）。
/// - `nbf`: token 生效时间（Unix 时间戳，之前不可用）。
/// - `sub`: token 主体标识（通常为用户 ID）。
/// - `aud`: token 受众（预期消费者）。
/// - `iss`: token 签发者。
/// - `jti`: token 唯一标识。
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TokenIntrospectionResponse {
    /// token 是否当前有效（必填，RFC 7662 §2.2）。
    pub active: bool,
    /// token 的 scope 列表（空格分隔字符串，RFC 7662 §2.2）。
    #[serde(default)]
    pub scope: Option<String>,
    /// token 关联的客户端 ID（RFC 7662 §2.2）。
    #[serde(default)]
    pub client_id: Option<String>,
    /// token 关联的人类可读用户名（RFC 7662 §2.2）。
    #[serde(default)]
    pub username: Option<String>,
    /// token 类型（如 "Bearer"，RFC 7662 §2.2）。
    #[serde(default)]
    pub token_type: Option<String>,
    /// token 过期时间（Unix 时间戳，RFC 7662 §2.2）。
    #[serde(default)]
    pub exp: Option<i64>,
    /// token 签发时间（Unix 时间戳，RFC 7662 §2.2）。
    #[serde(default)]
    pub iat: Option<i64>,
    /// token 生效时间（Unix 时间戳，之前不可用，RFC 7662 §2.2）。
    #[serde(default)]
    pub nbf: Option<i64>,
    /// token 主体标识（通常为用户 ID，RFC 7662 §2.2）。
    #[serde(default)]
    pub sub: Option<String>,
    /// token 受众（预期消费者，RFC 7662 §2.2）。
    #[serde(default)]
    pub aud: Option<String>,
    /// token 签发者（RFC 7662 §2.2）。
    #[serde(default)]
    pub iss: Option<String>,
    /// token 唯一标识（RFC 7662 §2.2）。
    #[serde(default)]
    pub jti: Option<String>,
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
    /// Token Introspection 端点 URL（可选，0.4.2 新增，依据 spec token-introspection）。
    /// 为 `None` 时由 `introspect_url()` 从 `token_url` 推导（`/token` → `/introspect`）。
    introspect_url: Option<String>,
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

    /// 设置用户信息端点 URL（依据 spec protocol-oauth2）。
    pub fn with_user_info_url(mut self, url: impl Into<String>) -> Self {
        self.user_info_url = Some(url.into());
        self
    }

    /// 设置 Token Introspection 端点 URL（0.4.2 新增，依据 spec token-introspection 设计决策 1）。
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

    /// 生成 PKCE code_challenge（依据 RFC 7636 S256 方法 / spec oauth-2-1-upgrade R-oauth-2-1-002）。
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

    /// 构造 Authorization Code 流程的授权 URL（依据 spec protocol-oauth2）。
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
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&self.redirect_uri),
            urlencoding::encode(state),
        )
    }

    /// 构造带 PKCE 的授权 URL（依据 spec oauth-2-1-upgrade R-oauth-2-1-001）。
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
            urlencoding::encode(&self.client_id),
            urlencoding::encode(&self.redirect_uri),
            urlencoding::encode(state),
            urlencoding::encode(&code_challenge),
        );
        Ok((url, code_challenge))
    }

    /// 使用授权码换取令牌（依据 spec protocol-oauth2）。
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

    /// 使用授权码 + PKCE 换取令牌（依据 spec oauth-2-1-upgrade R-oauth-2-1-001）。
    ///
    /// 在 [`exchange_code`](Self::exchange_code) 基础上，POST 请求体追加 `code_verifier` 字段。
    /// 授权服务器重新计算 `SHA256(code_verifier)` 并与授权请求中的 `code_challenge` 比对，验证客户端身份。
    ///
    /// # 参数
    /// - `code`: 授权码。
    /// - `_state`: CSRF state（保留参数，与旧方法签名对齐）。
    /// - `code_verifier`: PKCE code_verifier（需与构造授权 URL 时传入的 verifier 一致）。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidParam`: `code_verifier` 不合法（客户端预校验，透传自 `generate_pkce_challenge`）。
    /// - `BulwarkError::OAuth2`: token 端点返回非 2xx 或 JSON 解析失败。
    /// - `BulwarkError::Network`: reqwest 请求失败。
    pub async fn exchange_code_with_pkce(
        &self,
        code: &str,
        _state: &str,
        code_verifier: &str,
    ) -> BulwarkResult<TokenResponse> {
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

    /// 查询 token 状态（0.4.2 新增，依据 RFC 7662 / spec token-introspection R-token-introspection-001）。
    ///
    /// 向授权服务器的 introspection 端点 POST 请求，请求体以
    /// `application/x-www-form-urlencoded` 格式提交 `token` + `client_id` + `client_secret`，
    /// 响应解析为 [`TokenIntrospectionResponse`]。
    ///
    /// # 不缓存（依据 spec Constraints）
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

        let response = resp
            .json::<TokenIntrospectionResponse>()
            .await
            .map_err(|e| BulwarkError::OAuth2(format!("解析 introspection 响应失败: {}", e)))?;
        Ok(response)
    }

    /// 推导 introspection 端点 URL（依据 spec token-introspection 设计决策 1）。
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
        let client = OAuth2Client::new("cid", "secret", "https://example.com/cb", "auth", "token")
            .unwrap()
            .with_user_info_url("https://example.com/userinfo");
        assert_eq!(client.user_info_url(), Some("https://example.com/userinfo"));
    }

    /// redirect_uri 非 https 且非 localhost 应返回 InvalidParam 错误（spec P2.3）。
    ///
    /// 仅允许 https:// 或 http://localhost / http://127.0.0.1（开发环境例外）。
    /// http://evil.com 等明文 HTTP 回调应被拒绝，避免授权码被中间人截获。
    #[test]
    fn redirect_uri_rejects_http_in_production() {
        // http://evil.com 应拒绝（明文 HTTP 回调到公网域名）
        let result = OAuth2Client::new("cid", "sec", "http://evil.com/cb", "auth_url", "token_url");
        assert!(
            matches!(result, Err(BulwarkError::InvalidParam(_))),
            "http://evil.com 回调应被拒绝，实际 err: {:?}",
            result.err()
        );

        // https://example.com 应允许
        let result = OAuth2Client::new(
            "cid",
            "sec",
            "https://example.com/cb",
            "auth_url",
            "token_url",
        );
        assert!(
            result.is_ok(),
            "https 回调应允许，实际 err: {:?}",
            result.err()
        );

        // http://localhost 应允许（开发环境例外）
        let result = OAuth2Client::new(
            "cid",
            "sec",
            "http://localhost:8080/cb",
            "auth_url",
            "token_url",
        );
        assert!(
            result.is_ok(),
            "http://localhost 回调应允许（开发环境例外），实际 err: {:?}",
            result.err()
        );

        // http://127.0.0.1 应允许（开发环境例外）
        let result = OAuth2Client::new(
            "cid",
            "sec",
            "http://127.0.0.1:8080/cb",
            "auth_url",
            "token_url",
        );
        assert!(
            result.is_ok(),
            "http://127.0.0.1 回调应允许（开发环境例外），实际 err: {:?}",
            result.err()
        );
    }

    // ========================================================================
    // get_auth_url 测试（依据 spec protocol-oauth2）
    // ========================================================================

    /// 构造标准授权 URL（spec Scenario）。
    #[test]
    #[allow(deprecated)]
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
    #[allow(deprecated)]
    fn get_auth_url_empty_state_still_includes_state() {
        let client =
            OAuth2Client::new("cid", "secret", "https://example.com/cb", "auth", "token").unwrap();
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
    #[allow(deprecated)]
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
    #[allow(deprecated)]
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
            },
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
    // PKCE (RFC 7636 / OAuth 2.1) 测试（0.4.2 新增，依据 spec oauth-2-1-upgrade）
    // ========================================================================

    /// RFC 7636 Appendix B 测试向量：验证 S256 code_challenge 计算正确（spec R-oauth-2-1-002 硬性要求）。
    ///
    /// code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" (43 字符)
    /// code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    #[test]
    fn pkce_challenge_rfc_7636_test_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let challenge =
            OAuth2Client::generate_pkce_challenge(verifier).expect("RFC 7636 测试向量应成功");
        assert_eq!(challenge, expected);
    }

    /// code_verifier < 43 字符返回 InvalidParam 错误（spec R-oauth-2-1-002）。
    #[test]
    fn pkce_challenge_short_verifier_returns_error() {
        let verifier = "a".repeat(42);
        let result = OAuth2Client::generate_pkce_challenge(&verifier);
        assert!(result.is_err(), "42 字符的 verifier 应返回错误");
        match result.err() {
            Some(BulwarkError::InvalidParam(_)) => {},
            other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
        }
    }

    /// code_verifier > 128 字符返回 InvalidParam 错误（spec R-oauth-2-1-002）。
    #[test]
    fn pkce_challenge_long_verifier_returns_error() {
        let verifier = "a".repeat(129);
        let result = OAuth2Client::generate_pkce_challenge(&verifier);
        assert!(result.is_err(), "129 字符的 verifier 应返回错误");
        match result.err() {
            Some(BulwarkError::InvalidParam(_)) => {},
            other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
        }
    }

    /// code_verifier 含非法字符返回 InvalidParam 错误（spec R-oauth-2-1-002）。
    ///
    /// 合法字符集：[A-Z]/[a-z]/[0-9]/-/./_/~。空格、!、@、# 均为非法。
    #[test]
    fn pkce_challenge_invalid_chars_returns_error() {
        let test_cases = [
            format!("{}{}", "a".repeat(42), " "),
            format!("{}{}", "a".repeat(42), "!"),
            format!("{}{}", "a".repeat(42), "@"),
            format!("{}{}", "a".repeat(42), "#"),
        ];
        for verifier in &test_cases {
            let result = OAuth2Client::generate_pkce_challenge(verifier);
            assert!(
                result.is_err(),
                "含非法字符的 verifier 应返回错误: {}",
                verifier
            );
            match result.err() {
                Some(BulwarkError::InvalidParam(_)) => {},
                other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
            }
        }
    }

    /// 43-128 字符的合法 verifier 返回 43 字符的 challenge（spec R-oauth-2-1-002）。
    ///
    /// S256: SHA-256 输出 32 字节 → base64url 无填充编码 = 43 字符。
    #[test]
    fn pkce_challenge_valid_verifier_returns_correct_length() {
        for &len in &[43usize, 64, 128] {
            let verifier = "a".repeat(len);
            let challenge = OAuth2Client::generate_pkce_challenge(&verifier)
                .unwrap_or_else(|e| panic!("长度 {} 的 verifier 应成功: {}", len, e));
            assert_eq!(
                challenge.len(),
                43,
                "S256 challenge 应为 43 字符（32 字节 base64url 无填充），verifier 长度 {}",
                len
            );
        }
    }

    /// get_auth_url_with_pkce 返回的 URL 包含 code_challenge 和 code_challenge_method=S256（spec R-oauth-2-1-001）。
    #[test]
    fn get_auth_url_with_pkce_returns_url_and_challenge() {
        let client = OAuth2Client::new(
            "my-client",
            "secret",
            "https://example.com/callback",
            "https://auth.example.com/authorize",
            "https://token.example.com/token",
        )
        .unwrap();
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let (url, challenge) = client
            .get_auth_url_with_pkce("xyz-state", verifier)
            .expect("get_auth_url_with_pkce 应成功");
        assert!(url.starts_with("https://auth.example.com/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=my-client"));
        assert!(url.contains("state=xyz-state"));
        assert!(url.contains("code_challenge_method=S256"));
        assert!(url.contains("code_challenge="));
        // 返回的 challenge 与 RFC 7636 测试向量一致
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        assert!(url.contains(&format!("code_challenge={}", challenge)));
    }

    /// exchange_code_with_pkce 请求体包含 code_verifier 字段（spec R-oauth-2-1-001）。
    #[tokio::test]
    async fn exchange_code_with_pkce_includes_code_verifier_in_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "pkce-token",
                "token_type": "Bearer"
            })))
            .mount(&server)
            .await;

        let client = make_client(&server).await;
        let code_verifier = "a".repeat(43);
        let token = client
            .exchange_code_with_pkce("auth-code", "state", &code_verifier)
            .await
            .expect("exchange_code_with_pkce 应成功");
        assert_eq!(token.access_token, "pkce-token");

        // 验证请求体包含 code_verifier 字段
        let received = server.received_requests().await.expect("应收到请求");
        assert_eq!(received.len(), 1, "应只收到 1 个请求");
        let body = std::str::from_utf8(&received[0].body).expect("body 应为 UTF-8");
        assert!(
            body.contains("code_verifier="),
            "请求体应包含 code_verifier 字段，实际: {}",
            body
        );
    }

    /// 旧 get_auth_url 标记 deprecated 后仍可工作（向后兼容，spec R-oauth-2-1-003）。
    #[test]
    #[allow(deprecated)]
    fn deprecated_get_auth_url_still_works() {
        let client = OAuth2Client::new(
            "cid",
            "secret",
            "https://example.com/cb",
            "https://auth.example.com/authorize",
            "https://token.example.com/token",
        )
        .unwrap();
        let url = client.get_auth_url("state");
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=cid"));
        assert!(url.contains("state=state"));
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
        let client = make_client(&server).await.with_scope_registry(registry);
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
        let client = make_client(&server).await.with_scope_registry(registry);

        let result = client
            .get_password_token("user", "pass", Some("admin"))
            .await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::OAuth2(msg)) => {
                assert!(msg.contains("scope validation failed: admin"))
            },
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
        let client = make_client(&server).await.with_scope_registry(registry);

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
        let client = make_client(&server).await.with_scope_registry(registry);

        let result = client.refresh_access_token("rtok", Some("bad")).await;
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
        let client = make_client(&server).await.with_scope_registry(registry);

        let result = client
            .get_password_token("user", "pass", Some("unregistered"))
            .await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::OAuth2(msg)) => {
                assert!(msg.contains("scope handler not registered: unregistered"))
            },
            other => panic!("期望 OAuth2 错误，实际: {:?}", other),
        }
    }

    // ========================================================================
    // Token Introspection (RFC 7662) 测试（0.4.2 新增，依据 spec token-introspection）
    // ========================================================================

    /// 完整 introspection 响应解析：active=true 时所有字段正确解析（spec R-token-introspection-002/003）。
    #[tokio::test]
    async fn introspect_active_token_returns_full_response() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/introspect"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "active": true,
                "scope": "read write",
                "client_id": "test-client-id",
                "username": "alice",
                "token_type": "Bearer",
                "exp": 1700000000,
                "iat": 1690000000,
                "nbf": 1695000000,
                "sub": "user-123",
                "aud": "aud-1",
                "iss": "https://issuer.example.com",
                "jti": "token-jti-001"
            })))
            .mount(&server)
            .await;

        let client = make_client(&server).await;
        let resp = client
            .introspect_token("active-token")
            .await
            .expect("introspect_token 应成功");
        assert!(resp.active);
        assert_eq!(resp.scope.as_deref(), Some("read write"));
        assert_eq!(resp.client_id.as_deref(), Some("test-client-id"));
        assert_eq!(resp.username.as_deref(), Some("alice"));
        assert_eq!(resp.token_type.as_deref(), Some("Bearer"));
        assert_eq!(resp.exp, Some(1700000000));
        assert_eq!(resp.iat, Some(1690000000));
        assert_eq!(resp.nbf, Some(1695000000));
        assert_eq!(resp.sub.as_deref(), Some("user-123"));
        assert_eq!(resp.aud.as_deref(), Some("aud-1"));
        assert_eq!(resp.iss.as_deref(), Some("https://issuer.example.com"));
        assert_eq!(resp.jti.as_deref(), Some("token-jti-001"));
    }

    /// 无效 token 返回 active=false，其他字段为 None（spec R-token-introspection-003）。
    #[tokio::test]
    async fn introspect_inactive_token_returns_active_false() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/introspect"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"active": false})),
            )
            .mount(&server)
            .await;

        let client = make_client(&server).await;
        let resp = client
            .introspect_token("revoked-token")
            .await
            .expect("introspect_token 应成功");
        assert!(!resp.active);
        assert_eq!(resp.scope, None);
        assert_eq!(resp.client_id, None);
        assert_eq!(resp.username, None);
        assert_eq!(resp.token_type, None);
        assert_eq!(resp.exp, None);
        assert_eq!(resp.iat, None);
        assert_eq!(resp.nbf, None);
        assert_eq!(resp.sub, None);
        assert_eq!(resp.aud, None);
        assert_eq!(resp.iss, None);
        assert_eq!(resp.jti, None);
    }

    /// 服务器返回 HTTP 500 时返回 OAuth2 错误（spec R-token-introspection-001 错误处理）。
    #[tokio::test]
    async fn introspect_token_server_error_returns_oauth2_error() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/introspect"))
            .respond_with(ResponseTemplate::new(500).set_body_string("internal server error"))
            .mount(&server)
            .await;

        let client = make_client(&server).await;
        let result = client.introspect_token("any-token").await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::OAuth2(msg)) => {
                assert!(msg.contains("500"), "错误消息应包含状态码 500: {}", msg);
            },
            other => panic!("期望 OAuth2 错误，实际: {:?}", other),
        }
    }

    /// 授权服务器不可达返回 Network 错误（spec R-token-introspection-003）。
    ///
    /// 端口 1 通常未启用，reqwest 连接会立即失败（connection refused）→ 触发 Network 错误。
    #[tokio::test]
    async fn introspect_token_network_error_returns_network_error() {
        let client = OAuth2Client::new(
            "cid",
            "secret",
            "https://example.com/cb",
            "http://127.0.0.1:1/auth",
            "http://127.0.0.1:1/token",
        )
        .unwrap()
        .with_introspect_url("http://127.0.0.1:1/introspect");

        let result = client.introspect_token("any-token").await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::Network(_)) => {},
            other => panic!("期望 Network 错误，实际: {:?}", other),
        }
    }

    /// 请求体包含 token + client_id + client_secret 字段，Content-Type 为 form-urlencoded（spec R-token-introspection-001）。
    #[tokio::test]
    async fn introspect_token_sends_token_and_client_credentials_in_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/introspect"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"active": true})),
            )
            .mount(&server)
            .await;

        let client = make_client(&server).await;
        client.introspect_token("my-token").await.unwrap();

        let received = server.received_requests().await.expect("应收到请求");
        assert_eq!(received.len(), 1);
        let req = &received[0];
        // 验证 Content-Type 为 application/x-www-form-urlencoded
        let content_type = req
            .headers
            .get("content-type")
            .expect("应有 Content-Type header")
            .to_str()
            .unwrap();
        assert!(
            content_type.contains("application/x-www-form-urlencoded"),
            "Content-Type 应为 application/x-www-form-urlencoded，实际: {}",
            content_type
        );
        // 验证请求体字段
        let body = std::str::from_utf8(&req.body).expect("body 应为 UTF-8");
        assert!(
            body.contains("token=my-token"),
            "请求体应包含 token=my-token: {}",
            body
        );
        assert!(
            body.contains("client_id=test-client-id"),
            "请求体应包含 client_id: {}",
            body
        );
        assert!(
            body.contains("client_secret=test-client-secret"),
            "请求体应包含 client_secret: {}",
            body
        );
    }

    /// with_introspect_url 覆盖默认 URL，请求发到自定义端点（spec 设计决策 1）。
    #[tokio::test]
    async fn introspect_token_custom_url_uses_provided_endpoint() {
        let server = MockServer::start().await;
        // 仅挂载 /custom-introspect 路径，验证请求确实发到了自定义 URL
        Mock::given(method("POST"))
            .and(path("/custom-introspect"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"active": true})),
            )
            .mount(&server)
            .await;

        let client = make_client(&server)
            .await
            .with_introspect_url(format!("{}/custom-introspect", server.uri()));
        let resp = client.introspect_token("any").await.expect("应成功");
        assert!(resp.active);
    }

    /// 默认 introspect URL 从 token_url 推导（token_url 末尾为 /token 时替换为 /introspect）（spec 设计决策 1）。
    #[tokio::test]
    async fn introspect_token_default_url_derived_from_token_url() {
        let server = MockServer::start().await;
        // 仅挂载 /introspect 路径，验证默认推导逻辑
        // make_client 创建的 token_url = `{base}/token`，默认 introspect_url 应推导为 `{base}/introspect`
        Mock::given(method("POST"))
            .and(path("/introspect"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({"active": true})),
            )
            .mount(&server)
            .await;

        let client = make_client(&server).await;
        let resp = client.introspect_token("any").await.expect("应成功");
        assert!(resp.active);
    }

    /// TokenIntrospectionResponse 派生 Debug/Clone/Serialize/Deserialize（spec R-token-introspection-002）。
    #[test]
    fn token_introspection_response_derives_debug_clone_serde() {
        let resp = TokenIntrospectionResponse {
            active: true,
            scope: Some("read".to_string()),
            client_id: Some("cid".to_string()),
            username: Some("alice".to_string()),
            token_type: Some("Bearer".to_string()),
            exp: Some(1700000000),
            iat: Some(1690000000),
            nbf: Some(1695000000),
            sub: Some("user-123".to_string()),
            aud: Some("aud".to_string()),
            iss: Some("https://issuer.example.com".to_string()),
            jti: Some("jti-1".to_string()),
        };

        // Debug
        let _debug_str = format!("{:?}", resp);
        // Clone
        let cloned = resp.clone();
        assert_eq!(cloned.active, resp.active);
        // Serialize
        let json = serde_json::to_string(&resp).expect("Serialize 应成功");
        assert!(json.contains("\"active\":true"));
        // Deserialize
        let parsed: TokenIntrospectionResponse =
            serde_json::from_str(&json).expect("Deserialize 应成功");
        assert_eq!(parsed.active, resp.active);
        assert_eq!(parsed.scope, resp.scope);
    }

    // ========================================================================
    // H1 安全加固：错误处理不泄露 client_secret / code_verifier（v0.5.1 specmark H1）
    // ========================================================================

    /// post_token_request 错误处理不泄露 client_secret / code_verifier（H1）。
    ///
    /// 模拟恶意/配置错误的 token 端点在 401 响应体中回显请求参数（含 client_secret / code_verifier）。
    /// 修复前，错误消息 `format!("HTTP {}: {}", status, body)` 会原样包含响应体，
    /// 若服务器回显请求参数则 secret 泄露到日志/上层调用方。
    /// 修复后，错误消息只包含 HTTP status + token_url，不包含响应体或请求参数。
    #[tokio::test]
    async fn post_token_request_error_does_not_leak_secret() {
        let server = MockServer::start().await;
        // 模拟恶意服务器在 401 响应体中回显请求参数
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(401).set_body_string(
                "invalid client_secret=leak-me-secret or code_verifier=leak-me-verifier",
            ))
            .mount(&server)
            .await;

        let base = server.uri();
        let client = OAuth2Client::new(
            "test-client-id",
            "leak-me-secret", // client_secret 值
            "https://example.com/callback",
            format!("{}/auth", base),
            format!("{}/token", base),
        )
        .expect("创建 OAuth2Client 失败");

        // code_verifier 需 43-128 字符（RFC 7636），pad 到 43+
        let code_verifier = "leak-me-verifier-value-padded-to-43-characters-or-more";
        assert!(
            code_verifier.len() >= 43 && code_verifier.len() <= 128,
            "code_verifier 长度应在 43-128 之间，实际: {}",
            code_verifier.len()
        );

        let result = client
            .exchange_code_with_pkce("auth-code", "state", code_verifier)
            .await;

        assert!(result.is_err(), "应返回错误");
        let err_msg = result.err().unwrap().to_string();
        assert!(
            !err_msg.contains("leak-me-secret"),
            "错误消息不应包含 client_secret 值，实际: {}",
            err_msg
        );
        assert!(
            !err_msg.contains("leak-me-verifier"),
            "错误消息不应包含 code_verifier 值，实际: {}",
            err_msg
        );
    }
}
