//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OIDC（OpenID Connect）RP 协议支持骨架。
//!
//! 提供 OIDC RP（Relying Party）核心数据结构（`OidcDiscoveryConfig`/`OidcUserInfo`）
//! 和 `OidcProvider` trait（`get_authorization_url`/`exchange_code`/`get_user_info`/`validate_id_token`）。
//!
//! `DefaultOidcProvider` 提供基础实现：
//! - `get_authorization_url`：构造授权 URL（纯 URL 拼接，不需 HTTP）
//! - `exchange_code`：通过 reqwest POST 到 token_endpoint 交换 id_token
//! - `get_user_info`：通过 reqwest GET userinfo_endpoint 获取用户信息
//! - `validate_id_token`：返回 `NotImplemented`（JWT 验证需 `protocol-jwt` feature，defer 到后续变更）
//!
//! 与 `protocol::oauth2::oidc::OidcHandler` 的区别：
//! - `OidcHandler`：Bulwark 作为 IdP 签发/验证 id_token
//! - `OidcProvider` trait：Bulwark 作为 RP 与外部 IdP 交互
//!
//! 仅在启用 `protocol-sso` 特性时编译。

use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

// ============================================================================
// OIDC 数据结构
// ============================================================================

/// OIDC Discovery 配置。
///
/// 调用方负责提供 endpoints（不自动 discovery）
/// "OIDC discovery 文档的自动获取和缓存"。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscoveryConfig {
    /// 签发者标识（issuer），如 `https://accounts.google.com`。
    pub issuer: String,
    /// 授权端点 URL（authorization_endpoint）。
    pub authorization_endpoint: String,
    /// Token 端点 URL（token_endpoint）。
    pub token_endpoint: String,
    /// UserInfo 端点 URL（userinfo_endpoint）。
    pub userinfo_endpoint: String,
    /// JWKS URI（用于获取验证 id_token 的公钥）。
    pub jwks_uri: String,
}

/// OIDC UserInfo 响应。
///
/// 对应 OIDC UserInfo endpoint 返回的标准 claims。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcUserInfo {
    /// 主体标识（subject identifier）。
    pub sub: String,
    /// 邮箱地址。
    pub email: String,
    /// 显示名称。
    pub name: String,
    /// 首选用户名。
    pub preferred_username: String,
    /// 头像 URL。
    pub picture: String,
}

// ============================================================================
// OidcProvider trait
// ============================================================================

/// OIDC 协议交互 trait。
///
/// 支持授权码流程（Authorization Code Flow）。
#[async_trait]
pub trait OidcProvider: Send + Sync {
    /// 构造授权 URL。
    ///
    /// # 参数
    /// - `redirect_uri`: 回调 URL。
    /// - `state`: OAuth2 state 参数（防 CSRF）。
    /// - `scopes`: 请求的 scope 列表（如 `["openid", "profile", "email"]`）。
    ///
    /// # 返回
    /// 完整的授权 URL 字符串。
    async fn get_authorization_url(
        &self,
        redirect_uri: &str,
        state: &str,
        scopes: &[&str],
    ) -> BulwarkResult<String>;

    /// 交换授权码获取 id_token。
    ///
    /// # 参数
    /// - `code`: 授权码。
    /// - `redirect_uri`: 回调 URL（必须与 `get_authorization_url` 一致）。
    ///
    /// # 返回
    /// id_token 字符串（JWT 格式）。
    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> BulwarkResult<String>;

    /// 获取用户信息。
    ///
    /// # 参数
    /// - `access_token`: 访问令牌。
    ///
    /// # 返回
    /// `OidcUserInfo` 结构。
    async fn get_user_info(&self, access_token: &str) -> BulwarkResult<OidcUserInfo>;

    /// 验证 id_token。
    ///
    /// # 参数
    /// - `id_token`: JWT 格式的 id_token。
    ///
    /// # 返回
    /// - `Ok(true)`: 验证通过。
    /// - `Err(BulwarkError::NotImplemented)`: JWT 验证尚未实现。
    async fn validate_id_token(&self, id_token: &str) -> BulwarkResult<bool>;
}

// ============================================================================
// DefaultOidcProvider
// ============================================================================

/// 默认 OIDC Provider 实现。
///
/// 使用 reqwest 发送 HTTP 请求，与外部 IdP 交互。
/// `validate_id_token` 返回 `NotImplemented`（JWT 验证需 `protocol-jwt` feature）。
pub struct DefaultOidcProvider {
    /// Discovery 配置（含 endpoints）。
    config: OidcDiscoveryConfig,
    /// 客户端 ID。
    client_id: String,
    /// 客户端密钥。
    client_secret: String,
    /// HTTP 客户端。
    http_client: reqwest::Client,
}

impl DefaultOidcProvider {
    /// 创建新的 `DefaultOidcProvider` 实例。
    ///
    /// 调用方负责提供 `OidcDiscoveryConfig`（含 endpoints），provider 不自动获取 discovery 文档。
    ///
    /// # 参数
    /// - `config`: OIDC Discovery 配置（含 issuer 和 endpoints）。
    /// - `client_id`: 客户端 ID。
    /// - `client_secret`: 客户端密钥。
    pub fn new(config: OidcDiscoveryConfig, client_id: &str, client_secret: &str) -> Self {
        Self {
            config,
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            http_client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl OidcProvider for DefaultOidcProvider {
    async fn get_authorization_url(
        &self,
        redirect_uri: &str,
        state: &str,
        scopes: &[&str],
    ) -> BulwarkResult<String> {
        let scope = scopes.join(" ");
        let url = format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&state={}&scope={}",
            self.config.authorization_endpoint,
            url_encode(&self.client_id),
            url_encode(redirect_uri),
            url_encode(state),
            url_encode(&scope),
        );
        Ok(url)
    }

    async fn exchange_code(&self, code: &str, redirect_uri: &str) -> BulwarkResult<String> {
        let params = [
            ("grant_type", "authorization_code"),
            ("code", code),
            ("redirect_uri", redirect_uri),
            ("client_id", &self.client_id),
            ("client_secret", &self.client_secret),
        ];

        let resp = self
            .http_client
            .post(&self.config.token_endpoint)
            .form(&params)
            .send()
            .await
            .map_err(|e| BulwarkError::Internal(format!("OIDC token 交换失败: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(BulwarkError::Internal(format!(
                "OIDC token 端点返回错误状态: {} body: {}",
                status, body
            )));
        }

        let token_response: TokenResponse = resp
            .json()
            .await
            .map_err(|e| BulwarkError::Internal(format!("OIDC token 响应解析失败: {}", e)))?;

        token_response
            .id_token
            .ok_or_else(|| BulwarkError::Internal("OIDC token 响应中缺少 id_token".to_string()))
    }

    async fn get_user_info(&self, access_token: &str) -> BulwarkResult<OidcUserInfo> {
        let resp = self
            .http_client
            .get(&self.config.userinfo_endpoint)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| BulwarkError::Internal(format!("OIDC userinfo 请求失败: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(BulwarkError::Internal(format!(
                "OIDC userinfo 端点返回错误状态: {} body: {}",
                status, body
            )));
        }

        resp.json()
            .await
            .map_err(|e| BulwarkError::Internal(format!("OIDC userinfo 响应解析失败: {}", e)))
    }

    async fn validate_id_token(&self, _id_token: &str) -> BulwarkResult<bool> {
        Err(BulwarkError::NotImplemented(
            "OIDC id_token 验证尚未实现（需 protocol-jwt feature）".to_string(),
        ))
    }
}

#[cfg(feature = "protocol-zeroize")]
impl Drop for DefaultOidcProvider {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.client_secret.zeroize();
    }
}

// ============================================================================
// 辅助类型和函数（Refactor: extract helper）
// ============================================================================

/// OIDC token 端点响应（内部使用）。
#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
    #[allow(dead_code)]
    access_token: Option<String>,
    #[allow(dead_code)]
    token_type: Option<String>,
    #[allow(dead_code)]
    expires_in: Option<i64>,
}

/// 简单的 URL 编码（仅编码特殊字符）。
fn url_encode(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            ' ' => result.push_str("%20"),
            '!' => result.push_str("%21"),
            '#' => result.push_str("%23"),
            '$' => result.push_str("%24"),
            '%' => result.push_str("%25"),
            '&' => result.push_str("%26"),
            '\'' => result.push_str("%27"),
            '(' => result.push_str("%28"),
            ')' => result.push_str("%29"),
            '*' => result.push_str("%2A"),
            '+' => result.push_str("%2B"),
            ',' => result.push_str("%2C"),
            '/' => result.push_str("%2F"),
            ':' => result.push_str("%3A"),
            ';' => result.push_str("%3B"),
            '=' => result.push_str("%3D"),
            '?' => result.push_str("%3F"),
            '@' => result.push_str("%40"),
            '[' => result.push_str("%5B"),
            ']' => result.push_str("%5D"),
            _ => result.push(c),
        }
    }
    result
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // 数据结构测试
    // ========================================================================

    /// OidcDiscoveryConfig 序列化/反序列化往返（spec R-003）。
    #[test]
    fn oidc_discovery_config_serde_roundtrip() {
        let config = OidcDiscoveryConfig {
            issuer: "https://accounts.google.com".to_string(),
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".to_string(),
            token_endpoint: "https://oauth2.googleapis.com/token".to_string(),
            userinfo_endpoint: "https://openidconnect.googleapis.com/v1/userinfo".to_string(),
            jwks_uri: "https://www.googleapis.com/oauth2/v3/certs".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        let deserialized: OidcDiscoveryConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.issuer, config.issuer);
        assert_eq!(
            deserialized.authorization_endpoint,
            config.authorization_endpoint
        );
        assert_eq!(deserialized.token_endpoint, config.token_endpoint);
        assert_eq!(deserialized.userinfo_endpoint, config.userinfo_endpoint);
        assert_eq!(deserialized.jwks_uri, config.jwks_uri);
    }

    /// OidcUserInfo 序列化/反序列化往返（spec R-003）。
    #[test]
    fn oidc_user_info_serde_roundtrip() {
        let user_info = OidcUserInfo {
            sub: "1234567890".to_string(),
            email: "user@example.com".to_string(),
            name: "Test User".to_string(),
            preferred_username: "testuser".to_string(),
            picture: "https://example.com/avatar.png".to_string(),
        };
        let json = serde_json::to_string(&user_info).unwrap();
        let deserialized: OidcUserInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.sub, user_info.sub);
        assert_eq!(deserialized.email, user_info.email);
        assert_eq!(deserialized.name, user_info.name);
        assert_eq!(
            deserialized.preferred_username,
            user_info.preferred_username
        );
        assert_eq!(deserialized.picture, user_info.picture);
    }

    /// OidcDiscoveryConfig 实现 Clone + Debug（spec R-003 验收标准）。
    #[test]
    fn oidc_discovery_config_implements_clone_debug() {
        let config = make_test_config();
        let cloned = config.clone();
        assert_eq!(cloned.issuer, config.issuer);
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("OidcDiscoveryConfig"));
    }

    /// OidcUserInfo 实现 Clone + Debug（spec R-003 验收标准）。
    #[test]
    fn oidc_user_info_implements_clone_debug() {
        let user_info = OidcUserInfo {
            sub: "sub-1".to_string(),
            email: "a@b.com".to_string(),
            name: "A".to_string(),
            preferred_username: "a".to_string(),
            picture: "pic".to_string(),
        };
        let cloned = user_info.clone();
        assert_eq!(cloned.sub, user_info.sub);
        let debug_str = format!("{:?}", user_info);
        assert!(debug_str.contains("OidcUserInfo"));
    }

    // ========================================================================
    // DefaultOidcProvider 构造测试
    // ========================================================================

    /// 创建测试用 OidcDiscoveryConfig。
    fn make_test_config() -> OidcDiscoveryConfig {
        OidcDiscoveryConfig {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: "https://idp.example.com/token".to_string(),
            userinfo_endpoint: "https://idp.example.com/userinfo".to_string(),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
        }
    }

    /// DefaultOidcProvider::new 返回实例（spec R-004 验收标准）。
    #[test]
    fn default_oidc_provider_new_returns_instance() {
        let config = make_test_config();
        let provider = DefaultOidcProvider::new(config, "client-id", "client-secret");
        assert_eq!(provider.client_id, "client-id");
        assert_eq!(provider.client_secret, "client-secret");
    }

    /// OidcProvider trait 编译验证：DefaultOidcProvider 实现 OidcProvider trait（spec R-004）。
    #[test]
    fn default_oidc_provider_implements_oidc_provider() {
        fn assert_oidc_provider<T: OidcProvider>(_provider: &T) {}
        let config = make_test_config();
        let provider = DefaultOidcProvider::new(config, "id", "secret");
        assert_oidc_provider(&provider);
    }

    // ========================================================================
    // get_authorization_url 测试
    // ========================================================================

    /// get_authorization_url 构造正确 URL（spec R-004）。
    #[tokio::test]
    async fn get_authorization_url_constructs_valid_url() {
        let config = make_test_config();
        let provider = DefaultOidcProvider::new(config, "test-client-id", "secret");
        let url = provider
            .get_authorization_url(
                "https://sp.example.com/callback",
                "xyz-state",
                &["openid", "profile", "email"],
            )
            .await
            .unwrap();

        assert!(url.starts_with("https://idp.example.com/authorize?"));
        assert!(url.contains("response_type=code"));
        assert!(url.contains("client_id=test-client-id"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fsp.example.com%2Fcallback"));
        assert!(url.contains("state=xyz-state"));
        assert!(url.contains("scope=openid%20profile%20email"));
    }

    /// get_authorization_url 单个 scope 也正常工作。
    #[tokio::test]
    async fn get_authorization_url_single_scope() {
        let config = make_test_config();
        let provider = DefaultOidcProvider::new(config, "cid", "cs");
        let url = provider
            .get_authorization_url("https://cb.com/cb", "st", &["openid"])
            .await
            .unwrap();
        assert!(url.contains("scope=openid"));
    }

    /// get_authorization_url 空 scope 列表也正常工作。
    #[tokio::test]
    async fn get_authorization_url_empty_scopes() {
        let config = make_test_config();
        let provider = DefaultOidcProvider::new(config, "cid", "cs");
        let url = provider
            .get_authorization_url("https://cb.com/cb", "st", &[])
            .await
            .unwrap();
        assert!(url.contains("scope="));
    }

    // ========================================================================
    // validate_id_token 测试
    // ========================================================================

    /// validate_id_token 返回 NotImplemented（spec R-004: JWT 验证需 protocol-jwt feature）。
    #[tokio::test]
    async fn validate_id_token_returns_not_implemented() {
        let config = make_test_config();
        let provider = DefaultOidcProvider::new(config, "id", "secret");
        let result = provider.validate_id_token("fake.jwt.token").await;
        assert!(result.is_err());
        match result.err() {
            Some(BulwarkError::NotImplemented(_)) => {},
            other => panic!("期望 NotImplemented 错误，实际: {:?}", other),
        }
    }

    // ========================================================================
    // exchange_code / get_user_info 测试（使用 wiremock mock server）
    // ========================================================================

    /// exchange_code 成功返回 id_token（spec R-004）。
    #[tokio::test]
    async fn exchange_code_success_returns_id_token() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let config = OidcDiscoveryConfig {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: format!("{}/token", mock_server.uri()),
            userinfo_endpoint: format!("{}/userinfo", mock_server.uri()),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
        };

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature", // nosemgrep
                "access_token": "access-123",
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .mount(&mock_server)
            .await;

        let provider = DefaultOidcProvider::new(config, "cid", "cs");
        let id_token = provider
            .exchange_code("auth-code-123", "https://sp.example.com/callback")
            .await
            .unwrap();
        assert_eq!(
            id_token,
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature" // nosemgrep
        );
    }

    /// exchange_code 端点返回错误状态时返回 Internal 错误（spec R-004）。
    #[tokio::test]
    async fn exchange_code_error_status_returns_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let config = OidcDiscoveryConfig {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: format!("{}/token", mock_server.uri()),
            userinfo_endpoint: format!("{}/userinfo", mock_server.uri()),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
        };

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(400).set_body_string("invalid_grant"))
            .mount(&mock_server)
            .await;

        let provider = DefaultOidcProvider::new(config, "cid", "cs");
        let result = provider
            .exchange_code("bad-code", "https://sp.example.com/callback")
            .await;
        assert!(result.is_err());
    }

    /// exchange_code 响应缺少 id_token 时返回错误（spec R-004）。
    #[tokio::test]
    async fn exchange_code_missing_id_token_returns_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let config = OidcDiscoveryConfig {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: format!("{}/token", mock_server.uri()),
            userinfo_endpoint: format!("{}/userinfo", mock_server.uri()),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
        };

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "access-123",
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .mount(&mock_server)
            .await;

        let provider = DefaultOidcProvider::new(config, "cid", "cs");
        let result = provider
            .exchange_code("auth-code", "https://sp.example.com/callback")
            .await;
        assert!(result.is_err());
    }

    /// get_user_info 成功返回用户信息（spec R-004）。
    #[tokio::test]
    async fn get_user_info_success_returns_user_info() {
        use wiremock::matchers::{header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let config = OidcDiscoveryConfig {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: format!("{}/token", mock_server.uri()),
            userinfo_endpoint: format!("{}/userinfo", mock_server.uri()),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
        };

        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .and(header("authorization", "Bearer access-token-123"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "sub": "user-123",
                "email": "user@example.com",
                "name": "Test User",
                "preferred_username": "testuser",
                "picture": "https://example.com/avatar.png"
            })))
            .mount(&mock_server)
            .await;

        let provider = DefaultOidcProvider::new(config, "cid", "cs");
        let user_info = provider.get_user_info("access-token-123").await.unwrap();
        assert_eq!(user_info.sub, "user-123");
        assert_eq!(user_info.email, "user@example.com");
        assert_eq!(user_info.name, "Test User");
        assert_eq!(user_info.preferred_username, "testuser");
        assert_eq!(user_info.picture, "https://example.com/avatar.png");
    }

    /// get_user_info 端点返回错误状态时返回 Internal 错误（spec R-004）。
    #[tokio::test]
    async fn get_user_info_error_status_returns_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let config = OidcDiscoveryConfig {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: format!("{}/token", mock_server.uri()),
            userinfo_endpoint: format!("{}/userinfo", mock_server.uri()),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
        };

        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(401).set_body_string("invalid_token"))
            .mount(&mock_server)
            .await;

        let provider = DefaultOidcProvider::new(config, "cid", "cs");
        let result = provider.get_user_info("bad-token").await;
        assert!(result.is_err());
    }

    // ========================================================================
    // 辅助函数测试
    // ========================================================================

    /// url_encode 正确编码特殊字符。
    #[test]
    fn url_encode_encodes_special_chars() {
        assert_eq!(url_encode("hello world"), "hello%20world");
        assert_eq!(url_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(
            url_encode("https://example.com"),
            "https%3A%2F%2Fexample.com"
        );
        assert_eq!(url_encode("plain"), "plain");
    }

    /// VULN-0004 修复: url_encode 必须编码百分号，否则已编码序列会被二次解码导致注入。
    /// "%" → "%25"，防止攻击者构造 "%26" 绕过 scope/redirect_uri 校验。
    #[test]
    fn url_encode_encodes_percent_sign() {
        assert_eq!(url_encode("%"), "%25");
        assert_eq!(url_encode("100%done"), "100%25done");
        // 已编码序列应被双重编码，防止解码后注入
        assert_eq!(url_encode("%26"), "%2526");
        assert_eq!(url_encode("%3D"), "%253D");
    }
}
