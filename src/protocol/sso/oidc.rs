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
//! - `validate_id_token`：JWKS 验签（RS256）+ iss/aud/exp 校验（需 `protocol-jwt` feature，
//!   VULN-0001 修复）；未启用 feature 时返回 `NotImplemented`
//!
//! 与 `protocol::oauth2::oidc::OidcHandler` 的区别：
//! - `OidcHandler`：Bulwark 作为 IdP 签发/验证 id_token
//! - `OidcProvider` trait：Bulwark 作为 RP 与外部 IdP 交互
//!
//! 仅在启用 `protocol-sso` 特性时编译。`protocol-jwt` 特性启用后 `exchange_code`
//! 在返回前自动调用 `validate_id_token`，未启用时保持向后兼容行为。

use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// JWKS 公钥缓存 TTL（VULN-0001 修复）。
///
/// 10 分钟内复用缓存的 JWKS 公钥，避免每次 `validate_id_token` 都拉取 JWKS endpoint。
/// 与 `protocol::oauth2::keycloak::JWKS_CACHE_TTL` 保持一致。
const JWKS_CACHE_TTL: Duration = Duration::from_secs(600);

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

/// JWKS 中的单个 RSA 公钥（VULN-0001 修复）。
///
/// 表示从 `jwks_uri` 拉取的公钥集合中的一个条目。
/// 仅声明 RS256 验签所需字段；其他字段（如 `use` / `alg`）在反序列化时被忽略。
#[cfg_attr(not(feature = "protocol-jwt"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
struct Jwk {
    /// 公钥标识（Key ID），与 JWT header 的 `kid` 匹配以选择验签公钥。
    kid: String,
    /// RSA 模数（base64url 编码，无 padding）。
    n: String,
    /// RSA 公钥指数（base64url 编码，无 padding）。
    e: String,
}

/// JWKS 公钥集合响应（VULN-0001 修复）。
#[cfg_attr(not(feature = "protocol-jwt"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize)]
struct JwksResponse {
    /// 公钥列表。
    keys: Vec<Jwk>,
}

/// JWKS 公钥缓存（VULN-0001 修复）。
///
/// 缓存 JWKS 公钥集合 + 拉取时间戳，避免每次 `validate_id_token` 都拉取 JWKS endpoint。
/// TTL 由 [`JWKS_CACHE_TTL`] 控制，过期后下次调用重新拉取。
/// 设计与 `protocol::oauth2::keycloak::JwksCache` 一致。
#[cfg_attr(not(feature = "protocol-jwt"), allow(dead_code))]
#[derive(Debug, Clone, Default)]
struct JwksCache {
    /// 缓存的公钥列表。
    keys: Vec<Jwk>,
    /// 上次拉取时间戳（`None` 表示从未拉取）。
    fetched_at: Option<Instant>,
}

#[cfg_attr(not(feature = "protocol-jwt"), allow(dead_code))]
impl JwksCache {
    /// 判断缓存是否为空或已过期。
    ///
    /// 缓存为空或距上次拉取超过 [`JWKS_CACHE_TTL`] 时返回 `true`。
    fn is_empty_or_expired(&self) -> bool {
        match self.fetched_at {
            None => true,
            Some(t) => Instant::now().duration_since(t) > JWKS_CACHE_TTL,
        }
    }

    /// 按 `kid` 查找公钥。
    fn find_by_kid(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid == kid)
    }
}

/// 默认 OIDC Provider 实现。
///
/// 使用 reqwest 发送 HTTP 请求，与外部 IdP 交互。
///
/// # VULN-0001 修复
///
/// `validate_id_token` 在启用 `protocol-jwt` feature 时执行 JWKS 验签（RS256）+
/// iss/aud/exp 校验；未启用时返回 `NotImplemented`。
/// `exchange_code` 在启用 `protocol-jwt` feature 时返回前自动调用
/// `validate_id_token`，未启用时保持向后兼容行为（不验签）。
pub struct DefaultOidcProvider {
    /// Discovery 配置（含 endpoints）。
    config: OidcDiscoveryConfig,
    /// 客户端 ID。
    client_id: String,
    /// 客户端密钥。
    client_secret: String,
    /// HTTP 客户端。
    http_client: reqwest::Client,
    /// JWKS 公钥缓存（TTL 控制，避免每次验签都拉取，VULN-0001 修复）。
    #[cfg_attr(not(feature = "protocol-jwt"), allow(dead_code))]
    jwks_cache: Arc<RwLock<JwksCache>>,
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
            jwks_cache: Arc::new(RwLock::new(JwksCache::default())),
        }
    }

    /// 拉取 JWKS 公钥集合并更新缓存（VULN-0001 修复）。
    ///
    /// HTTP GET [`OidcDiscoveryConfig::jwks_uri`]，响应体按 JSON 解析为 [`JwksResponse`]，
    /// 将 `keys` 写入 `jwks_cache` 并更新 `fetched_at` 时间戳。
    ///
    /// # 错误
    ///
    /// - `BulwarkError::Internal`: HTTP 请求失败、非 2xx 状态码或 JSON 解析失败。
    #[cfg(feature = "protocol-jwt")]
    async fn fetch_jwks(&self) -> BulwarkResult<()> {
        let resp = self
            .http_client
            .get(&self.config.jwks_uri)
            .send()
            .await
            .map_err(|e| BulwarkError::Internal(format!("OIDC JWKS 请求失败: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(BulwarkError::Internal(format!(
                "OIDC JWKS 端点返回错误状态: {} body: {}",
                status, body
            )));
        }

        let jwks = resp
            .json::<JwksResponse>()
            .await
            .map_err(|e| BulwarkError::Internal(format!("OIDC JWKS 响应解析失败: {}", e)))?;

        let mut cache = self.jwks_cache.write();
        cache.keys = jwks.keys;
        cache.fetched_at = Some(Instant::now());
        Ok(())
    }

    /// 验证 id_token 的内部实现（VULN-0001 修复）。
    ///
    /// 仅在启用 `protocol-jwt` feature 时编译。流程参考
    /// `protocol::oauth2::keycloak::KeycloakProvider::verify_id_token`：
    ///
    /// 1. 解析 JWT header，提取 `kid`。
    /// 2. 检查 `jwks_cache`，缓存为空或过期时调用 `fetch_jwks` 拉取。
    /// 3. 按 `kid` 匹配 JWKS 公钥，用 `n`/`e` 模数构造 `DecodingKey`。
    /// 4. 用 RS256 算法验签，解析为 [`IdTokenClaims`]。
    /// 5. 校验 `iss`（匹配 `config.issuer`）。
    /// 6. 校验 `aud`（匹配 `client_id`）。
    /// 7. 校验 `exp`（由 jsonwebtoken 内置 `validate_exp = true` 完成）。
    ///
    /// # 错误
    ///
    /// - `BulwarkError::InvalidToken`: JWT header 解析失败 / kid 缺失 / JWKS 无匹配公钥 /
    ///   签名验证失败 / claims 解析失败 / token 已过期 / iss 不匹配 / aud 不匹配。
    /// - `BulwarkError::Internal`: JWKS 拉取失败。
    #[cfg(feature = "protocol-jwt")]
    async fn validate_id_token_impl(&self, id_token: &str) -> BulwarkResult<bool> {
        use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

        /// id_token 标准 claims（仅声明验签所需字段，其他字段被忽略）。
        #[derive(Deserialize)]
        struct IdTokenClaims {
            /// 签发者标识（必须匹配 `config.issuer`）。
            iss: String,
            /// 受众（必须匹配 `client_id`）。
            aud: String,
        }

        // 1. 解析 JWT header，提取 kid
        let header = jsonwebtoken::decode_header(id_token).map_err(|e| {
            BulwarkError::InvalidToken(format!("OIDC id_token header 解析失败: {}", e))
        })?;
        let kid = header.kid.as_deref().ok_or_else(|| {
            BulwarkError::InvalidToken("OIDC id_token header 缺少 kid 字段".to_string())
        })?;

        // 2. 检查 jwks_cache，缓存为空或过期时拉取
        //    用独立作用域确保 read guard 在 await 前 drop（避免 clippy::await_holding_lock）
        let needs_fetch = {
            let cache = self.jwks_cache.read();
            cache.is_empty_or_expired()
        };
        if needs_fetch {
            self.fetch_jwks().await?;
        }

        // 3. 按 kid 匹配 JWKS 公钥
        let jwk = {
            let cache = self.jwks_cache.read();
            cache.find_by_kid(kid).cloned()
        };
        let jwk = jwk.ok_or_else(|| {
            BulwarkError::InvalidToken(format!("OIDC JWKS 中未找到 kid={} 的公钥", kid))
        })?;

        // 4. 构造 DecodingKey 并验签
        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|e| BulwarkError::InvalidToken(format!("OIDC 构造 RSA 公钥失败: {}", e)))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        validation.leeway = 0;
        // jsonwebtoken 10 默认 validate_aud=true，但未设置 expected audience 会触发
        // InvalidAudience。关闭库内置 aud 校验，由我们手动校验 client_id 以提供精确错误信息。
        validation.validate_aud = false;

        let token_data =
            decode::<IdTokenClaims>(id_token, &decoding_key, &validation).map_err(|e| {
                let msg = e.to_string();
                if msg.contains("ExpiredSignature") {
                    BulwarkError::InvalidToken("OIDC id_token 已过期".to_string())
                } else {
                    BulwarkError::InvalidToken(format!("OIDC id_token 验签失败: {}", e))
                }
            })?;

        // 5. 校验 iss（必须匹配 config.issuer）
        if token_data.claims.iss != self.config.issuer {
            return Err(BulwarkError::InvalidToken(format!(
                "OIDC id_token iss 不匹配: 期望 {}, 实际 {}",
                self.config.issuer, token_data.claims.iss
            )));
        }

        // 6. 校验 aud（必须匹配 client_id）
        if token_data.claims.aud != self.client_id {
            return Err(BulwarkError::InvalidToken(format!(
                "OIDC id_token aud 不匹配: 期望 {}, 实际 {}",
                self.client_id, token_data.claims.aud
            )));
        }

        Ok(true)
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

        let id_token = token_response
            .id_token
            .ok_or_else(|| BulwarkError::Internal("OIDC token 响应中缺少 id_token".to_string()))?;

        // VULN-0001 修复：启用 protocol-jwt 时在返回前验证 id_token 签名 + iss/aud/exp。
        // 未启用 protocol-jwt 时保持向后兼容行为（不验签，直接返回 id_token）。
        #[cfg(feature = "protocol-jwt")]
        {
            self.validate_id_token_impl(&id_token).await?;
        }

        Ok(id_token)
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

    async fn validate_id_token(&self, id_token: &str) -> BulwarkResult<bool> {
        // VULN-0001 修复：启用 protocol-jwt 时执行 JWKS 验签 + iss/aud/exp 校验。
        // 未启用 protocol-jwt 时返回 NotImplemented（保持向后兼容）。
        #[cfg(feature = "protocol-jwt")]
        {
            return self.validate_id_token_impl(id_token).await;
        }
        #[cfg(not(feature = "protocol-jwt"))]
        {
            let _ = id_token;
            Err(BulwarkError::NotImplemented(
                "OIDC id_token 验证尚未实现（需 protocol-jwt feature）".to_string(),
            ))
        }
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
    ///
    /// VULN-0001 修复后：此测试仅在未启用 `protocol-jwt` feature 时运行。
    /// 启用 `protocol-jwt` 时 `validate_id_token` 执行 JWKS 验签，由下面的
    /// `validate_id_token_rejects_*` 系列测试覆盖。
    #[cfg(not(feature = "protocol-jwt"))]
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
    ///
    /// VULN-0001 修复后：启用 `protocol-jwt` 时 `exchange_code` 返回前会调用
    /// `validate_id_token`，需要 mock JWKS endpoint + 真实 RSA 签发的 JWT。
    /// 未启用 `protocol-jwt` 时不验签，使用假 JWT（保持向后兼容行为）。
    #[tokio::test]
    async fn exchange_code_success_returns_id_token() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let issuer = "https://idp.example.com".to_string();

        // 启用 protocol-jwt 时生成真实 RSA 签发的 JWT + JWKS JSON
        // 未启用时使用假 JWT 字符串（不验签）
        #[cfg(feature = "protocol-jwt")]
        let (id_token, jwks_json) = make_valid_id_token(&issuer, "cid");
        #[cfg(not(feature = "protocol-jwt"))]
        let id_token: String = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature".to_string(); // nosemgrep

        // 启用 protocol-jwt 时 mock JWKS endpoint
        #[cfg(feature = "protocol-jwt")]
        {
            Mock::given(method("GET"))
                .and(path("/jwks"))
                .respond_with(ResponseTemplate::new(200).set_body_json(jwks_json))
                .mount(&mock_server)
                .await;
        }

        let config = OidcDiscoveryConfig {
            issuer,
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: format!("{}/token", mock_server.uri()),
            userinfo_endpoint: format!("{}/userinfo", mock_server.uri()),
            jwks_uri: format!("{}/jwks", mock_server.uri()),
        };

        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_token": id_token,
                "access_token": "access-123",
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .mount(&mock_server)
            .await;

        let provider = DefaultOidcProvider::new(config, "cid", "cs");
        let returned_id_token = provider
            .exchange_code("auth-code-123", "https://sp.example.com/callback")
            .await
            .unwrap();
        assert_eq!(returned_id_token, id_token);
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

    // ========================================================================
    // VULN-0001 修复：validate_id_token JWKS 验签测试
    //
    // 启用 protocol-jwt feature 时执行 JWKS 验签（RS256）+ iss/aud/exp 校验。
    // 测试使用 wiremock mock JWKS 端点 + RSA 2048 测试密钥对。
    // 参考实现：protocol::oauth2::keycloak::tests::keycloak_provider_verify_id_token_validates_signature_and_claims
    // ========================================================================

    /// VULN-0001 测试辅助：生成 RSA 2048 测试密钥对。
    ///
    /// 返回 (EncodingKey, n_b64, e_b64)，其中 n_b64/e_b64 为 base64url 无 padding 编码，
    /// 可直接构造 JWKS JSON。
    #[cfg(feature = "protocol-jwt")]
    fn make_test_rsa_key() -> (jsonwebtoken::EncodingKey, String, String) {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use jsonwebtoken::EncodingKey;
        use rand::rngs::OsRng;
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;
        use rsa::{RsaPrivateKey, RsaPublicKey};

        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("生成 RSA 私钥应成功");
        let public_key = RsaPublicKey::from(&private_key);
        let n_b64 = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e_b64 = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
        // jsonwebtoken 10 的 EncodingKey::from_rsa_der 期望 PKCS#1 DER（非 PKCS#8）
        let der = private_key.to_pkcs1_der().expect("转 PKCS#1 DER 应成功");
        let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());
        (encoding_key, n_b64, e_b64)
    }

    /// VULN-0001 测试辅助：当前 Unix 时间戳（秒）。
    #[cfg(feature = "protocol-jwt")]
    fn now_unix() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("系统时间应早于 UNIX_EPOCH")
            .as_secs() as i64
    }

    /// VULN-0001 测试辅助：用 RSA 私钥签发 JWT。
    ///
    /// # 参数
    /// - `encoding_key`: RSA 编码密钥
    /// - `kid`: JWT header 的 key ID
    /// - `iss`: 签发者
    /// - `aud`: 受众
    /// - `exp`: 过期时间（Unix 秒）
    #[cfg(feature = "protocol-jwt")]
    fn sign_test_jwt(
        encoding_key: &jsonwebtoken::EncodingKey,
        kid: &str,
        iss: &str,
        aud: &str,
        exp: i64,
    ) -> String {
        use jsonwebtoken::{encode, Algorithm, Header};
        use serde::Serialize;

        #[derive(Serialize)]
        struct TestClaims {
            iss: String,
            aud: String,
            exp: i64,
            sub: String,
        }

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let claims = TestClaims {
            iss: iss.to_string(),
            aud: aud.to_string(),
            exp,
            sub: "user-123".to_string(),
        };
        encode(&header, &claims, encoding_key).expect("签发 JWT 应成功")
    }

    /// VULN-0001 测试辅助：构造 JWKS JSON 响应体（单个 RSA 公钥）。
    #[cfg(feature = "protocol-jwt")]
    fn make_jwks_json(kid: &str, n_b64: &str, e_b64: &str) -> serde_json::Value {
        serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": kid,
                "use": "sig",
                "alg": "RS256",
                "n": n_b64,
                "e": e_b64,
            }]
        })
    }

    /// VULN-0001 测试辅助：生成有效 id_token + 对应的 JWKS JSON。
    ///
    /// 生成 RSA 密钥对，用私钥签发 JWT（iss/aud/exp 与 provider 配置匹配），
    /// 返回 (id_token, jwks_json) 供 mock 使用。
    #[cfg(feature = "protocol-jwt")]
    fn make_valid_id_token(issuer: &str, client_id: &str) -> (String, serde_json::Value) {
        let (encoding_key, n_b64, e_b64) = make_test_rsa_key();
        // exp 设为当前时间 + 3600 秒（1 小时后过期，确保 validate_exp 通过）
        let id_token = sign_test_jwt(&encoding_key, "key1", issuer, client_id, now_unix() + 3600);
        let jwks_json = make_jwks_json("key1", &n_b64, &e_b64);
        (id_token, jwks_json)
    }

    /// VULN-0001 测试辅助：启动 mock server 并挂载 JWKS endpoint，返回 OidcDiscoveryConfig。
    #[cfg(feature = "protocol-jwt")]
    async fn setup_jwks_mock_server(
        jwks_json: serde_json::Value,
    ) -> (wiremock::MockServer, OidcDiscoveryConfig) {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let issuer = "https://idp.example.com".to_string();

        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(ResponseTemplate::new(200).set_body_json(jwks_json))
            .mount(&server)
            .await;

        let config = OidcDiscoveryConfig {
            issuer,
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: format!("{}/token", server.uri()),
            userinfo_endpoint: format!("{}/userinfo", server.uri()),
            jwks_uri: format!("{}/jwks", server.uri()),
        };
        (server, config)
    }

    /// VULN-0001 测试 1：validate_id_token 拒绝无效签名的 JWT。
    ///
    /// 用 key_signer 私钥签发 JWT，但 JWKS 返回 key_other 公钥 → 验签失败。
    /// 覆盖 `validate_id_token_impl` 中 `decode` 失败分支。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn validate_id_token_rejects_invalid_signature() {
        // 签发用 key_signer，JWKS 返回 key_other（不同密钥对）的公钥
        let (encoding_key_signer, _n_signer, _e_signer) = make_test_rsa_key();
        let (_encoding_key_other, n_other, e_other) = make_test_rsa_key();

        let jwks_json = make_jwks_json("key1", &n_other, &e_other);
        let (_server, config) = setup_jwks_mock_server(jwks_json).await;

        let id_token = sign_test_jwt(
            &encoding_key_signer,
            "key1",
            &config.issuer,
            "client-id",
            now_unix() + 3600,
        );

        let provider = DefaultOidcProvider::new(config, "client-id", "secret");
        let result = provider.validate_id_token(&id_token).await;
        assert!(result.is_err(), "无效签名应返回错误");
        match result.err() {
            Some(BulwarkError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("验签失败") || msg.contains("signature"),
                    "无效签名应返回验签失败消息，实际: {}",
                    msg
                );
            },
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    /// VULN-0001 测试 2：validate_id_token 拒绝过期 token。
    ///
    /// 签发 exp=now-3600（1 小时前已过期）的 JWT，验签时 jsonwebtoken 触发
    /// ExpiredSignature，映射到 InvalidToken("OIDC id_token 已过期")。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn validate_id_token_rejects_expired_token() {
        let (encoding_key, n_b64, e_b64) = make_test_rsa_key();
        let jwks_json = make_jwks_json("key1", &n_b64, &e_b64);
        let (_server, config) = setup_jwks_mock_server(jwks_json).await;

        // exp 设为当前时间 - 3600 秒（已过期）
        let id_token = sign_test_jwt(
            &encoding_key,
            "key1",
            &config.issuer,
            "client-id",
            now_unix() - 3600,
        );

        let provider = DefaultOidcProvider::new(config, "client-id", "secret");
        let result = provider.validate_id_token(&id_token).await;
        assert!(result.is_err(), "过期 token 应返回错误");
        match result.err() {
            Some(BulwarkError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("过期") || msg.contains("expired"),
                    "过期 token 应返回过期相关消息，实际: {}",
                    msg
                );
            },
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    /// VULN-0001 测试 3：validate_id_token 拒绝 iss 不匹配的 token。
    ///
    /// 签发 iss="https://wrong-issuer.example.com"，但 provider 配置 issuer 不同。
    /// 验签通过，但 iss 校验失败。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn validate_id_token_rejects_wrong_issuer() {
        let (encoding_key, n_b64, e_b64) = make_test_rsa_key();
        let jwks_json = make_jwks_json("key1", &n_b64, &e_b64);
        let (_server, config) = setup_jwks_mock_server(jwks_json).await;

        // 用错误的 issuer 签发
        let id_token = sign_test_jwt(
            &encoding_key,
            "key1",
            "https://wrong-issuer.example.com",
            "client-id",
            now_unix() + 3600,
        );

        let provider = DefaultOidcProvider::new(config, "client-id", "secret");
        let result = provider.validate_id_token(&id_token).await;
        assert!(result.is_err(), "iss 不匹配应返回错误");
        match result.err() {
            Some(BulwarkError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("iss"),
                    "iss 不匹配应返回 iss 相关消息，实际: {}",
                    msg
                );
            },
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    /// VULN-0001 测试 4：validate_id_token 拒绝 aud 不匹配的 token。
    ///
    /// 签发 aud="wrong-aud"，但 provider 配置 client_id="client-id"。
    /// 验签通过，但 aud 校验失败。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn validate_id_token_rejects_wrong_audience() {
        let (encoding_key, n_b64, e_b64) = make_test_rsa_key();
        let jwks_json = make_jwks_json("key1", &n_b64, &e_b64);
        let (_server, config) = setup_jwks_mock_server(jwks_json).await;

        // 用错误的 audience 签发
        let id_token = sign_test_jwt(
            &encoding_key,
            "key1",
            &config.issuer,
            "wrong-aud",
            now_unix() + 3600,
        );

        let provider = DefaultOidcProvider::new(config, "client-id", "secret");
        let result = provider.validate_id_token(&id_token).await;
        assert!(result.is_err(), "aud 不匹配应返回错误");
        match result.err() {
            Some(BulwarkError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("aud"),
                    "aud 不匹配应返回 aud 相关消息，实际: {}",
                    msg
                );
            },
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    /// VULN-0001 测试 5：exchange_code 在返回前调用 validate_id_token。
    ///
    /// mock token endpoint 返回无效签名的 id_token（用 key_signer 签发，
    /// 但 JWKS 返回 key_other 公钥），exchange_code 应在返回前调用
    /// validate_id_token 并失败。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn exchange_code_validates_id_token() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // 签发用 key_signer，JWKS 返回 key_other（不同密钥对）的公钥
        let (encoding_key_signer, _n_signer, _e_signer) = make_test_rsa_key();
        let (_encoding_key_other, n_other, e_other) = make_test_rsa_key();

        let mock_server = MockServer::start().await;
        let issuer = "https://idp.example.com".to_string();

        // mock JWKS endpoint（返回与签名密钥不匹配的公钥）
        Mock::given(method("GET"))
            .and(path("/jwks"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json(make_jwks_json("key1", &n_other, &e_other)),
            )
            .mount(&mock_server)
            .await;

        // mock token endpoint 返回无效签名的 id_token
        let id_token = sign_test_jwt(
            &encoding_key_signer,
            "key1",
            &issuer,
            "cid",
            now_unix() + 3600,
        );
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_token": id_token,
                "access_token": "access-123",
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .mount(&mock_server)
            .await;

        let config = OidcDiscoveryConfig {
            issuer,
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: format!("{}/token", mock_server.uri()),
            userinfo_endpoint: format!("{}/userinfo", mock_server.uri()),
            jwks_uri: format!("{}/jwks", mock_server.uri()),
        };

        let provider = DefaultOidcProvider::new(config, "cid", "secret");
        let result = provider
            .exchange_code("auth-code-123", "https://sp.example.com/callback")
            .await;
        assert!(
            result.is_err(),
            "exchange_code 应在 validate_id_token 失败时返回错误"
        );
        match result.err() {
            Some(BulwarkError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("验签失败") || msg.contains("signature"),
                    "exchange_code 应传递验签失败错误，实际: {}",
                    msg
                );
            },
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }
}
