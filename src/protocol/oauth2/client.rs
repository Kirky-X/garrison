// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! OAuth2 客户端实现（`protocol-oauth2` feature）：`OAuth2Client` 持有配置与可复用 `reqwest::Client`，
//! 实现 Authorization Code / Client Credentials / Password / Refresh Token 四种授权流程及 Token Introspection (RFC 7662)。

use crate::error::{GarrisonError, GarrisonResult};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use sha2::{Digest, Sha256};
use std::time::Duration;

use super::{TokenIntrospectionResponse, TokenResponse};

/// HTTP 客户端安全默认配置（E1）：connect_timeout=10s、read_timeout=30s，防慢速 IdP 拖垮连接池（slowloris）；
/// `pub(crate)` 供 `protocol::oauth2` 与 keycloak 复用，`protocol::sso::oidc` 因 feature 隔离自行维护等价 helper。
pub(crate) const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// 构造带超时配置的 `reqwest::Client`（E1 修复），三处 builder 统一委托此函数确保超时不漏配；builder 失败返回 `Network`。
pub(crate) fn build_safe_http_client() -> GarrisonResult<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .read_timeout(HTTP_READ_TIMEOUT)
        .build()
        .map_err(|e| GarrisonError::Network(format!("oauth2-http-client-build::{}", e)))
}

/// HTTP 响应体大小上限（E2）：4 MiB，防止恶意 IdP 通过超大 JSON 触发 OOM / 反序列化放大（4 MiB 足以容纳标准 JWT/JWKS/userinfo 响应）。
pub(crate) const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// 读取响应体并强制大小上限（E2 修复）：超限或读取失败返回 `GarrisonError::Network`。
pub(crate) async fn read_limited_bytes(resp: reqwest::Response) -> GarrisonResult<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    let mut resp = resp;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| GarrisonError::Network(format!("oauth2-body-read::{}", e)))?
    {
        let new_len = buf
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| GarrisonError::Network("oauth2-body-overflow".to_string()))?;
        if new_len > MAX_BODY_BYTES {
            return Err(GarrisonError::Network("oauth2-body-overflow::".to_string()));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// URL 编码字符集：保留 `A-Z a-z 0-9 - _ . ~`（基于 `NON_ALPHANUMERIC` 移除四个保留字符），行为与原自实现一致。
const URLENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// URL 百分号编码（保留 `A-Z a-z 0-9 - _ . ~`）。
fn url_encode(s: &str) -> String {
    utf8_percent_encode(s, URLENCODE_SET).to_string()
}

/// OAuth2 客户端：持有配置与可复用 `reqwest::Client`，可多线程共享。
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
    /// Token Introspection 端点 URL（可选；None 时由 `introspect_url()` 从 `token_url` 推导）。
    introspect_url: Option<String>,
    /// 可复用的 HTTP 客户端。
    http: reqwest::Client,
    /// Scope 注册表（仅 `oauth2-scope-handler` feature）；注入后 token 请求前委托 `validate_scope` 校验。
    #[cfg(feature = "oauth2-scope-handler")]
    scope_registry: Option<std::sync::Arc<super::scope::ScopeRegistry>>,
}

impl OAuth2Client {
    /// 创建新的 OAuth2 客户端：client_id 为空返回 `Config`；redirect_uri / auth_url / token_url 非 https
    /// 且非 localhost/127.0.0.1 返回 `InvalidParam`；reqwest 构建失败返回 `Network`。
    pub fn new(
        client_id: impl Into<String>,
        client_secret: impl Into<String>,
        redirect_uri: impl Into<String>,
        auth_url: impl Into<String>,
        token_url: impl Into<String>,
    ) -> GarrisonResult<Self> {
        let client_id = client_id.into();
        if client_id.is_empty() {
            return Err(GarrisonError::Config("oauth2-client-id-empty".to_string()));
        }
        let redirect_uri = redirect_uri.into();
        Self::validate_redirect_uri(&redirect_uri)?;
        let auth_url = auth_url.into();
        Self::validate_endpoint_url(&auth_url, "auth_url")?;
        let token_url = token_url.into();
        Self::validate_endpoint_url(&token_url, "token_url")?;
        let http = build_safe_http_client()?;
        Ok(Self {
            client_id,
            client_secret: client_secret.into(),
            redirect_uri,
            auth_url,
            token_url,
            user_info_url: None,
            introspect_url: None,
            http,
            #[cfg(feature = "oauth2-scope-handler")]
            scope_registry: None,
        })
    }

    /// 校验 redirect_uri scheme（防授权码明文回调被中间人截获）：仅允许 `https://` 任意 host 或
    /// `http://localhost` / `http://127.0.0.1`（开发例外）；精确 redirect_uri 匹配、前缀/子域名绕过、
    /// 路径遍历与参数注入防护属授权服务器职责。
    fn validate_redirect_uri(redirect_uri: &str) -> GarrisonResult<()> {
        let Some(scheme_end) = redirect_uri.find("://") else {
            return Err(GarrisonError::InvalidParam(format!(
                "url-scheme-https-required::redirect_uri::{}",
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

        Err(GarrisonError::InvalidParam(format!(
            "url-scheme-https-required::redirect_uri::{}",
            redirect_uri
        )))
    }

    /// 校验请求端点 URL scheme（token/introspection 端点携带 `client_secret` 与 authorization code，明文 http 可被中间人窃取）；规则同 [`Self::validate_redirect_uri`]。
    fn validate_endpoint_url(url: &str, field: &str) -> GarrisonResult<()> {
        Self::validate_redirect_uri(url).map_err(|_| {
            GarrisonError::InvalidParam(format!("url-scheme-https-required::{}::{}", field, url))
        })
    }

    /// 设置用户信息端点 URL（本客户端不内部请求该端点，scheme 校验由使用方负责）。
    pub fn with_user_info_url(mut self, url: impl Into<String>) -> Self {
        self.user_info_url = Some(url.into());
        self
    }

    /// 设置 Token Introspection 端点 URL（不设置时由 `introspect_url()` 从 `token_url` 推导）。
    pub fn with_introspect_url(mut self, url: impl Into<String>) -> Self {
        self.introspect_url = Some(url.into());
        self
    }

    /// 注入 ScopeRegistry（仅 `oauth2-scope-handler` feature）：token 请求前委托 `ScopeRegistry::validate` 校验 scope。
    #[cfg(feature = "oauth2-scope-handler")]
    pub fn with_scope_registry(
        mut self,
        registry: std::sync::Arc<super::scope::ScopeRegistry>,
    ) -> Self {
        self.scope_registry = Some(registry);
        self
    }

    /// 校验 scope：未注入 registry 或 scope 为 None 跳过；handler 返回 `Ok(false)` 报 OAuth2 错误；
    /// token 请求时尚无 login_id，传 `login_id = 0` 占位。
    #[cfg(feature = "oauth2-scope-handler")]
    async fn validate_scope(&self, scope: Option<&str>) -> GarrisonResult<()> {
        if let (Some(registry), Some(s)) = (&self.scope_registry, scope) {
            let allowed = registry.validate(s, 0)?;
            if !allowed {
                return Err(GarrisonError::OAuth2(format!(
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

    /// 生成 PKCE code_challenge：`base64url_no_pad(sha256(code_verifier))`；code_verifier 须为 43-128 字符
    /// 且仅含 `[A-Z]/[a-z]/[0-9]/-./_/~`（RFC 7636 §4.1），否则返回 `InvalidParam`。
    ///
    /// # 示例
    /// RFC 7636 Appendix B 测试向量：
    /// ```
    /// # use garrison::protocol::oauth2::OAuth2Client;
    /// let challenge = OAuth2Client::generate_pkce_challenge(
    /// "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    /// ).unwrap();
    /// assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    /// ```
    pub fn generate_pkce_challenge(code_verifier: &str) -> GarrisonResult<String> {
        // 长度 43-128（RFC 7636 §4.1）
        if code_verifier.len() < 43 || code_verifier.len() > 128 {
            return Err(GarrisonError::InvalidParam(format!(
                "oauth2-pkce-length-invalid::{}",
                code_verifier.len()
            )));
        }
        // 字符集 [A-Z]/[a-z]/[0-9]/-./_/~（RFC 7636 §4.1）
        if !code_verifier
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_' || c == '~')
        {
            return Err(GarrisonError::InvalidParam(
                "oauth2-pkce-chars-invalid".to_string(),
            ));
        }
        // S256：SHA-256 → base64url 无填充
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let digest = hasher.finalize();
        Ok(URL_SAFE_NO_PAD.encode(digest))
    }

    /// 构造带 PKCE 的授权 URL：返回 `(authorization_url, code_challenge)`，在 [`Self::get_auth_url_with_pkce`] 基础上追加 `code_challenge` 与 `code_challenge_method=S256` 参数。
    ///
    /// `code_verifier` 不合法时透传 `GarrisonError::InvalidParam`（来自 `generate_pkce_challenge`）。
    pub fn get_auth_url_with_pkce(
        &self,
        state: &str,
        code_verifier: &str,
    ) -> GarrisonResult<(String, String)> {
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

    /// 使用授权码 + PKCE 换取令牌：POST 请求体追加 `code_verifier`（授权服务器重算 SHA256 比对
    /// `code_challenge` 验证客户端身份）；内部比对 expected_state 与 actual_state（CSRF 防护），不匹配返回 `OAuth2`。
    pub async fn exchange_code_with_pkce(
        &self,
        code: &str,
        expected_state: &str,
        actual_state: &str,
        code_verifier: &str,
    ) -> GarrisonResult<TokenResponse> {
        // CSRF 防护：state 缺失（空串）fail-closed 拒绝（双空相等若放行，未生成 state / 回调被剥离 state 的 CSRF 注入将静默通过）
        if expected_state.is_empty() || actual_state.is_empty() {
            return Err(GarrisonError::OAuth2("oauth2-state-missing".to_string()));
        }
        // 校验 state 匹配
        if expected_state != actual_state {
            return Err(GarrisonError::OAuth2("oauth2-state-mismatch".to_string()));
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
    ) -> GarrisonResult<TokenResponse> {
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

    /// 获取 Password 模式令牌：POST 提交 `grant_type=password`、username、password、client_id、client_secret，可选 scope；username 为空返回 `InvalidParam`。
    pub async fn get_password_token(
        &self,
        username: &str,
        password: &str,
        scope: Option<&str>,
    ) -> GarrisonResult<TokenResponse> {
        if username.is_empty() {
            return Err(GarrisonError::InvalidParam(
                "oauth2-username-empty".to_string(),
            ));
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

    /// 使用 refresh_token 换取新 access_token：POST 提交 `grant_type=refresh_token`、refresh_token、client_id、client_secret，
    /// 可选 scope（缩小/扩大授权范围）；refresh_token 为空返回 `InvalidParam`，端点非 2xx / JSON 失败返回 `OAuth2`，请求失败返回 `Network`。
    pub async fn refresh_access_token(
        &self,
        refresh_token: &str,
        scope: Option<&str>,
    ) -> GarrisonResult<TokenResponse> {
        if refresh_token.is_empty() {
            return Err(GarrisonError::InvalidParam(
                "oauth2-refresh-token-empty".to_string(),
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
    async fn post_token_request(&self, params: &[(&str, &str)]) -> GarrisonResult<TokenResponse> {
        let resp = self
            .http
            .post(&self.token_url)
            .form(params)
            .send()
            .await
            .map_err(|e| GarrisonError::Network(format!("oauth2-token-endpoint::{}", e)))?;

        let status = resp.status();
        if !status.is_success() {
            // 安全加固：错误消息只记录 HTTP status + url，不包含响应体或请求参数
            // （响应体可能被恶意服务器回显请求参数，导致 client_secret / code_verifier 泄露）
            return Err(GarrisonError::OAuth2(format!(
                "token endpoint returned {} for {}",
                status.as_u16(),
                self.token_url
            )));
        }

        let token_bytes = read_limited_bytes(resp)
            .await
            .map_err(|e| GarrisonError::OAuth2(format!("oauth2-token-body-read::{}", e)))?;
        let token: TokenResponse = serde_json::from_slice(&token_bytes)
            .map_err(|e| GarrisonError::OAuth2(format!("oauth2-token-body-parse::{}", e)))?;
        Ok(token)
    }

    /// 查询 token 状态：POST introspection 端点（`application/x-www-form-urlencoded` 提交 token + client_id + client_secret），返回 [`TokenIntrospectionResponse`]（`active` 字段表示 token 是否有效）。
    ///
    /// 不缓存：每次调用都请求授权服务器；错误返回 `OAuth2`（非 2xx / JSON 失败）或 `Network`。
    pub async fn introspect_token(
        &self,
        token: &str,
    ) -> GarrisonResult<TokenIntrospectionResponse> {
        let url = self.introspect_url();
        Self::validate_endpoint_url(&url, "introspect_url")?;
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
            .map_err(|e| GarrisonError::Network(format!("oauth2-introspect-endpoint::{}", e)))?;

        let status = resp.status();
        if !status.is_success() {
            // 安全加固：错误消息只记 HTTP status + url，不含响应体/请求参数（防恶意服务器回显泄露 client_secret）
            return Err(GarrisonError::OAuth2(format!(
                "introspect endpoint returned {} for {}",
                status.as_u16(),
                url
            )));
        }

        let introspect_bytes = read_limited_bytes(resp)
            .await
            .map_err(|e| GarrisonError::OAuth2(format!("oauth2-introspect-body-read::{}", e)))?;
        let response: TokenIntrospectionResponse = serde_json::from_slice(&introspect_bytes)
            .map_err(|e| GarrisonError::OAuth2(format!("oauth2-introspect-body-parse::{}", e)))?;
        Ok(response)
    }

    /// 推导 introspection 端点 URL：已设置 [`with_introspect_url`](Self::with_introspect_url) 则用之；
    /// `token_url` 以 `/token` 结尾时仅替换末尾该段（不能全局 replace：中段 `/token` 也会被替换，
    /// 如 `/v2/oauth2/token/rotate/token` → 畸形端点）；否则末尾追加 `/introspect`。
    fn introspect_url(&self) -> String {
        if let Some(url) = &self.introspect_url {
            url.clone()
        } else if let Some(base) = self.token_url.strip_suffix("/token") {
            format!("{base}/introspect")
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
    use super::{url_encode, *};

    /// URL 编码保留安全字符。
    #[test]
    fn url_encode_preserves_safe_chars() {
        assert_eq!(url_encode("abc-_.~"), "abc-_.~");
    }

    /// URL 编码特殊字符。
    #[test]
    fn url_encode_encodes_special_chars() {
        assert_eq!(url_encode("a b/c:d"), "a%20b%2Fc%3Ad");
    }

    /// URLENCODE_SET 保留 `- _ . ~` 四个 unreserved 字符（RFC 3986 §2.3）。
    #[test]
    fn urlencode_set_preserves_unreserved_chars() {
        // unreserved 字符集（RFC 3986 §2.3）：A-Z a-z 0-9 - _ . ~
        for ch in ['-', '_', '.', '~'] {
            let s = ch.to_string();
            assert_eq!(url_encode(&s), s, "字符 {} 应被保留", ch);
        }
    }

    /// state 缺失 fail-closed：expected/actual 任一为空串即拒绝，不发 HTTP
    /// （双空相等若放行，CSRF 注入将静默通过；守卫先于 mismatch 比较与网络请求）。
    #[tokio::test]
    async fn exchange_code_rejects_missing_state_before_http() {
        let client = OAuth2Client::new(
            "cid",
            "secret",
            "https://localhost/callback",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .expect("client 构建成功");
        let verifier = "a".repeat(43);

        // 双空（调用方未生成 state + 回调无 state）
        let err = client
            .exchange_code_with_pkce("code-x", "", "", &verifier)
            .await
            .unwrap_err();
        match err {
            GarrisonError::OAuth2(msg) => {
                assert!(msg.contains("oauth2-state-missing"), "实际: {}", msg)
            },
            other => panic!("期望 OAuth2(state-missing)，实际: {:?}", other),
        }

        // expected 空 / actual 空（回调被剥离 state 的 CSRF 注入形态）
        for (expected, actual) in [("", "s"), ("s", "")] {
            let err = client
                .exchange_code_with_pkce("code-x", expected, actual, &verifier)
                .await
                .unwrap_err();
            match err {
                GarrisonError::OAuth2(msg) => {
                    assert!(msg.contains("oauth2-state-missing"), "实际: {}", msg)
                },
                other => panic!("期望 OAuth2(state-missing)，实际: {:?}", other),
            }
        }
    }

    // introspect_url 推导（仅替换末尾 /token 段，防中段 /token 全局替换产生畸形端点）

    /// token_url 路径中段含 `/token` 时，只应替换末尾那段
    /// （strip_suffix 而非全局 replace 会得到畸形端点）。
    #[test]
    fn introspect_url_replaces_only_trailing_token_segment() {
        let client = OAuth2Client::new(
            "cid",
            "secret",
            "https://localhost/callback",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token/rotate/token",
        )
        .expect("client 构建成功");
        assert_eq!(
            client.introspect_url(),
            "https://auth.example.com/token/rotate/introspect",
        );
    }

    /// token_url 以 /token 结尾：末尾替换为 /introspect。
    #[test]
    fn introspect_url_replaces_trailing_token() {
        let client = OAuth2Client::new(
            "cid",
            "secret",
            "https://localhost/callback",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .expect("client 构建成功");
        assert_eq!(
            client.introspect_url(),
            "https://auth.example.com/introspect"
        );
    }

    /// token_url 不以 /token 结尾时在末尾追加 /introspect。
    #[test]
    fn introspect_url_appends_when_not_ending_with_token() {
        let client = OAuth2Client::new(
            "cid",
            "secret",
            "https://localhost/callback",
            "https://auth.example.com/authorize",
            "https://auth.example.com/oauth2/v2/tokenize",
        )
        .expect("client 构建成功");
        assert_eq!(
            client.introspect_url(),
            "https://auth.example.com/oauth2/v2/tokenize/introspect",
        );
    }

    /// 显式 with_introspect_url 优先于推导。
    #[test]
    fn introspect_url_explicit_overrides_derived() {
        let client = OAuth2Client::new(
            "cid",
            "secret",
            "https://localhost/callback",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .expect("client 构建成功")
        .with_introspect_url("https://introspect.example.com/check");
        assert_eq!(
            client.introspect_url(),
            "https://introspect.example.com/check"
        );
    }

    // E1: reqwest 客户端超时配置

    /// E1 单元测试：`build_safe_http_client()` 返回有效的 Client 实例（超时行为由 `e1_read_timeout_triggers_on_slow_server` 行为测试覆盖）。
    #[test]
    fn e1_build_safe_http_client_returns_valid_client() {
        let client = build_safe_http_client();
        assert!(client.is_ok(), "build_safe_http_client 必须返回 Ok");
    }

    /// E1 单元测试：超时常量值符合 spec（connect=10s, read=30s）。
    #[test]
    fn e1_timeout_constants_match_spec() {
        assert_eq!(HTTP_CONNECT_TIMEOUT, Duration::from_secs(10));
        assert_eq!(HTTP_READ_TIMEOUT, Duration::from_secs(30));
    }

    /// E1 行为测试：read_timeout=30s 触发于慢速 token endpoint（wiremock 延迟 35s，请求应在 ~30s 内失败）；`#[ignore]` 避免拖慢 CI。
    #[tokio::test]
    #[ignore = "慢测试（~30s），按需运行：cargo test e1_read_timeout_triggers -- --ignored"]
    async fn e1_read_timeout_triggers_on_slow_server() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // 延迟 35s > read_timeout=30s，确保触发读超时
        let delay = std::time::Duration::from_secs(35);
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_delay(delay))
            .mount(&server)
            .await;

        let client = build_safe_http_client().expect("client 构建成功");
        let start = std::time::Instant::now();
        let result = client
            .post(format!("{}/token", server.uri()))
            .form(&[("grant_type", "test")])
            .send()
            .await;
        let elapsed = start.elapsed();

        assert!(result.is_err(), "慢服务器必须触发超时错误");
        // 允许 ±2s 抖动：reqwest 内部重试 + tokio 调度
        assert!(
            elapsed >= Duration::from_secs(28) && elapsed <= Duration::from_secs(33),
            "超时应约 30s 触发，实际 {:?}",
            elapsed
        );
    }

    // E2: 响应体大小限制（4 MiB）

    /// E2 单元测试：MAX_BODY_BYTES 常量值为 4 MiB。
    #[test]
    fn e2_max_body_bytes_is_4_mib() {
        assert_eq!(MAX_BODY_BYTES, 4 * 1024 * 1024);
    }

    /// E2 行为测试：超过 4 MiB 的响应被 `read_limited_bytes` 拒绝（wiremock 返回 5 MiB）。
    #[tokio::test]
    async fn e2_read_limited_bytes_rejects_oversized_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // 5 MiB > 4 MiB 上限
        let oversized_body = "x".repeat(5 * 1024 * 1024);
        Mock::given(method("GET"))
            .and(path("/oversized"))
            .respond_with(ResponseTemplate::new(200).set_body_string(oversized_body))
            .mount(&server)
            .await;

        let client = build_safe_http_client().expect("client 构建成功");
        let resp = client
            .get(format!("{}/oversized", server.uri()))
            .send()
            .await
            .expect("请求必须成功（错误在读取阶段）");
        let result = read_limited_bytes(resp).await;
        assert!(result.is_err(), "5 MiB 响应必须被拒绝");
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains(&crate::i18n::translate_detail("oauth2-body-overflow", &[],)),
            "错误消息应含'oauth2-body-overflow'，实际: {}",
            err_msg
        );
    }

    /// E2 行为测试：恰好 4 MiB 的响应被接受（边界值，`>` 而非 `>=` 判定）。
    #[tokio::test]
    async fn e2_read_limited_bytes_accepts_exact_limit() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // 恰好 4 MiB = MAX_BODY_BYTES，应被接受（边界值）
        let exact_body = "x".repeat(MAX_BODY_BYTES);
        Mock::given(method("GET"))
            .and(path("/exact"))
            .respond_with(ResponseTemplate::new(200).set_body_string(exact_body))
            .mount(&server)
            .await;

        let client = build_safe_http_client().expect("client 构建成功");
        let resp = client
            .get(format!("{}/exact", server.uri()))
            .send()
            .await
            .expect("请求必须成功");
        let result = read_limited_bytes(resp).await;
        assert!(result.is_ok(), "恰好 {} 字节应被接受", MAX_BODY_BYTES);
        assert_eq!(result.unwrap().len(), MAX_BODY_BYTES);
    }

    /// E2 行为测试：小响应（< 1 KiB）正常读取（回归保护，不应被错误拒绝）。
    #[tokio::test]
    async fn e2_read_limited_bytes_accepts_small_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/small"))
            .respond_with(ResponseTemplate::new(200).set_body_string("hello world"))
            .mount(&server)
            .await;

        let client = build_safe_http_client().expect("client 构建成功");
        let resp = client
            .get(format!("{}/small", server.uri()))
            .send()
            .await
            .expect("请求必须成功");
        let bytes = read_limited_bytes(resp).await.expect("小响应必须通过");
        assert_eq!(bytes, b"hello world");
    }

    /// E2 集成测试：`OAuth2Client::exchange_code_with_pkce` 端到端拒绝 5 MiB token 响应。
    #[tokio::test]
    async fn e2_oauth2_client_rejects_oversized_token_response() {
        use wiremock::matchers::{body_string_contains, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // 构造 5 MiB 的 JSON（合法 JSON 但超过上限）
        let huge_value = "x".repeat(5 * 1024 * 1024);
        let huge_json = format!(r#"{{"access_token":"{}"}}"#, huge_value);
        Mock::given(method("POST"))
            .and(path("/token"))
            .and(body_string_contains("grant_type=authorization_code"))
            .respond_with(ResponseTemplate::new(200).set_body_string(huge_json))
            .mount(&server)
            .await;

        let client = OAuth2Client::new(
            "cid",
            "secret",
            "https://localhost/callback",
            "https://auth.example.com/auth",
            format!("{}/token", server.uri()),
        )
        .expect("client 构建成功");

        // 使用合法 code_verifier（43 字符）
        let verifier = "a".repeat(43);
        let result = client
            .exchange_code_with_pkce("code123", "state", "state", &verifier)
            .await;
        assert!(result.is_err(), "超大 token 响应必须被拒绝");
    }

    // 端点 scheme 校验（端点明文传输防护）

    /// 构造期拒绝公网明文 http token 端点（client_secret 明文传输风险）。
    #[test]
    fn new_rejects_plaintext_http_token_endpoint() {
        let result = OAuth2Client::new(
            "cid",
            "secret",
            "https://app.example.com/callback",
            "https://auth.example.com/authorize",
            "http://auth.example.com/token",
        );
        match result {
            Err(GarrisonError::InvalidParam(msg)) => {
                assert!(
                    msg.contains("token_url"),
                    "错误应指明 token_url，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 InvalidParam，实际: {:?}", other),
            Ok(_) => panic!("公网明文 http token 端点应被构造期拒绝"),
        }
    }

    /// 构造期拒绝公网明文 http auth 端点（authorization code 明文传输风险）。
    #[test]
    fn new_rejects_plaintext_http_auth_endpoint() {
        let result = OAuth2Client::new(
            "cid",
            "secret",
            "https://app.example.com/callback",
            "http://auth.example.com/authorize",
            "https://auth.example.com/token",
        );
        match result {
            Err(GarrisonError::InvalidParam(msg)) => {
                assert!(
                    msg.contains("auth_url"),
                    "错误应指明 auth_url，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 InvalidParam，实际: {:?}", other),
            Ok(_) => panic!("公网明文 http auth 端点应被构造期拒绝"),
        }
    }

    /// localhost/127.0.0.1 的 http 端点放行（开发/测试场景，与 redirect_uri 约定一致）。
    #[test]
    fn new_allows_localhost_http_endpoints() {
        let result = OAuth2Client::new(
            "cid",
            "secret",
            "http://localhost:8080/cb",
            "http://localhost:9000/authorize",
            "http://127.0.0.1:9000/token",
        );
        assert!(
            result.is_ok(),
            "localhost http 端点应放行，实际: {:?}",
            result.err()
        );
    }

    /// introspect_token 运行时拒绝明文 introspection 端点（builder 不 panic，在请求前拦截）。
    #[tokio::test]
    async fn introspect_token_rejects_plaintext_introspect_url() {
        let client = OAuth2Client::new(
            "cid",
            "secret",
            "https://app.example.com/callback",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .expect("client 构建成功")
        .with_introspect_url("http://evil.example.com/introspect");
        let result = client.introspect_token("token-value").await;
        match result {
            Err(GarrisonError::InvalidParam(msg)) => {
                assert!(
                    msg.contains("introspect_url"),
                    "错误应指明 introspect_url，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 InvalidParam，实际: {:?}", other),
            Ok(_) => panic!("明文 introspection 端点应在请求前被拒绝"),
        }
    }

    // validate_redirect_uri 边界测试

    /// validate_redirect_uri 无 scheme 返回 InvalidParam。
    #[test]
    fn validate_redirect_uri_no_scheme() {
        let result = OAuth2Client::new(
            "cid",
            "secret",
            "no-scheme-here",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        );
        assert!(result.is_err(), "无 scheme 应报错");
    }

    /// validate_redirect_uri http + 公网域名返回 InvalidParam。
    #[test]
    fn validate_redirect_uri_http_public_host() {
        let result = OAuth2Client::new(
            "cid",
            "secret",
            "http://evil.com/callback",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        );
        assert!(result.is_err(), "http + 公网域名应报错");
    }

    /// validate_redirect_uri http://localhost 放行。
    #[test]
    fn validate_redirect_uri_http_localhost_ok() {
        let result = OAuth2Client::new(
            "cid",
            "secret",
            "http://localhost:3000/callback",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        );
        assert!(
            result.is_ok(),
            "http://localhost 应放行，实际: {:?}",
            result.err()
        );
    }

    /// validate_redirect_uri http://127.0.0.1 放行。
    #[test]
    fn validate_redirect_uri_http_127_ok() {
        let result = OAuth2Client::new(
            "cid",
            "secret",
            "http://127.0.0.1:8080/cb",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        );
        assert!(
            result.is_ok(),
            "http://127.0.0.1 应放行，实际: {:?}",
            result.err()
        );
    }

    // generate_pkce_challenge 边界测试

    /// generate_pkce_challenge 长度 < 43 返回 InvalidParam。
    #[test]
    fn pkce_challenge_too_short() {
        let short = "a".repeat(42);
        let result = OAuth2Client::generate_pkce_challenge(&short);
        assert!(result.is_err(), "长度 < 43 应报错");
    }

    /// generate_pkce_challenge 长度 > 128 返回 InvalidParam。
    #[test]
    fn pkce_challenge_too_long() {
        let long = "a".repeat(129);
        let result = OAuth2Client::generate_pkce_challenge(&long);
        assert!(result.is_err(), "长度 > 128 应报错");
    }

    /// generate_pkce_challenge 含非法字符返回 InvalidParam。
    #[test]
    fn pkce_challenge_invalid字符() {
        // 43 字符但包含空格（非法）
        let invalid = "a b".to_string() + &"c".repeat(40);
        let result = OAuth2Client::generate_pkce_challenge(&invalid);
        assert!(result.is_err(), "含非法字符应报错");
    }

    /// generate_pkce_challenge 合法输入返回正确 challenge。
    #[test]
    fn pkce_challenge_valid_input() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = OAuth2Client::generate_pkce_challenge(verifier).unwrap();
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    /// new 空 client_id 返回 Config 错误。
    #[test]
    fn new_empty_client_id_returns_config_error() {
        let result = OAuth2Client::new(
            "",
            "secret",
            "https://localhost/cb",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        );
        assert!(result.is_err(), "空 client_id 应报错");
    }
}
