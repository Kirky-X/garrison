//! Keycloak OIDC RP 模块（0.5.0 新增，依据 proposal K1 / spec keycloak-oidc-rp）。
//!
//! 提供 `KeycloakProvider` 作为 OIDC 依赖方（RP），对接 Keycloak IdP：
//! - `KeycloakConfig`：配置 base_url / client_id / client_secret / redirect_uri
//! - `KeycloakProvider`：discover / verify_id_token / exchange_code
//! - `KeycloakClaims`：Keycloak 特有 claim（realm_access.roles / resource_access）
//!
//! ## 与 `oauth2::oidc` 模块的关系
//!
//! `oauth2::oidc` 提供通用 OIDC handler（HS256 sign/verify id_token + discovery metadata），
//! 本模块针对 Keycloak 特化（JWKS 验签、Keycloak 特有 claim 解析、RP 流程）。
//!
//! ## Keycloak OIDC 端点约定
//!
//! Keycloak realm 的 OIDC 端点均基于 `{base_url}`（即 realm URL，形如
//! `https://kc.example.com:8443/realms/{realm}`），按 Keycloak 官方文档约定：
//!
//! | 端点 | 路径 |
//! |------|------|
//! | Discovery | `{base_url}/.well-known/openid-configuration` |
//! | JWKS | `{base_url}/protocol/openid-connect/certs` |
//! | Authorization | `{base_url}/protocol/openid-connect/auth` |
//! | Token | `{base_url}/protocol/openid-connect/token` |
//! | UserInfo | `{base_url}/protocol/openid-connect/userinfo` |

use crate::error::{BulwarkError, BulwarkResult};
use parking_lot::RwLock;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// JWKS 公钥缓存 TTL（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-003 设计决策 2）。
///
/// 10 分钟内复用缓存的 JWKS 公钥，避免每次 `verify_id_token` 都拉取 JWKS endpoint。
const JWKS_CACHE_TTL: Duration = Duration::from_secs(600);

/// Keycloak OIDC RP 配置（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-001）。
///
/// 持有对接 Keycloak IdP 所需的最小配置：realm base_url、client_id、
/// client_secret（confidential client 必填，public client 可为 None）、redirect_uri。
///
/// # 字段
///
/// - `base_url`: Keycloak realm 根 URL，形如 `https://kc.example.com:8443/realms/myrealm`。
///   末尾不应有 `/`（URL 拼接时直接追加路径）。
/// - `client_id`: 在 Keycloak 中注册的 OIDC client ID。
/// - `client_secret`: confidential client 的密钥；public client（如 SPA）为 `None`。
/// - `redirect_uri`: 授权码回调地址，必须与 Keycloak client 配置中登记的 URL 一致。
///
/// # 端点推导
///
/// [`KeycloakConfig`] 提供 5 个端点推导方法，按 Keycloak OIDC 约定拼接 URL：
/// [`discovery_url`](Self::discovery_url) / [`jwks_url`](Self::jwks_url) /
/// [`authorize_url`](Self::authorize_url) / [`token_url`](Self::token_url) /
/// [`userinfo_url`](Self::userinfo_url)。
#[derive(Debug, Clone)]
pub struct KeycloakConfig {
    /// Keycloak realm 根 URL（末尾无 `/`）。
    pub base_url: String,
    /// OIDC client ID。
    pub client_id: String,
    /// confidential client 密钥（public client 为 `None`）。
    pub client_secret: Option<String>,
    /// 授权码回调地址。
    pub redirect_uri: String,
}

impl KeycloakConfig {
    /// 构造 OIDC Discovery 端点 URL（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-001）。
    ///
    /// 返回 `{base_url}/.well-known/openid-configuration`，用于 `KeycloakProvider::discover`
    /// 拉取 Keycloak 的 OIDC discovery metadata。
    pub fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.base_url)
    }

    /// 构造 JWKS 端点 URL（依据 Keycloak OIDC 约定）。
    ///
    /// 返回 `{base_url}/protocol/openid-connect/certs`，用于 `KeycloakProvider::verify_id_token`
    /// 拉取公钥集合以验签 id_token。
    pub fn jwks_url(&self) -> String {
        format!("{}/protocol/openid-connect/certs", self.base_url)
    }

    /// 构造 Authorization 端点 URL（依据 Keycloak OIDC 约定）。
    ///
    /// 返回 `{base_url}/protocol/openid-connect/auth`，用于浏览器跳转引导用户完成登录。
    pub fn authorize_url(&self) -> String {
        format!("{}/protocol/openid-connect/auth", self.base_url)
    }

    /// 构造 Token 端点 URL（依据 Keycloak OIDC 约定）。
    ///
    /// 返回 `{base_url}/protocol/openid-connect/token`，用于 `KeycloakProvider::exchange_code`
    /// 以授权码换取 access_token / refresh_token / id_token。
    pub fn token_url(&self) -> String {
        format!("{}/protocol/openid-connect/token", self.base_url)
    }

    /// 构造 UserInfo 端点 URL（依据 Keycloak OIDC 约定）。
    ///
    /// 返回 `{base_url}/protocol/openid-connect/userinfo`，用于查询用户信息 claim。
    pub fn userinfo_url(&self) -> String {
        format!("{}/protocol/openid-connect/userinfo", self.base_url)
    }
}

/// OIDC Discovery Metadata（依据 RFC 8414 / spec keycloak-oidc-rp R-keycloak-oidc-rp-002）。
///
/// 表示从 `/.well-known/openid-configuration` 拉取的 IdP 元数据。
/// 仅声明 Keycloak RP 流程所需的最小子集；其他字段（如 `response_types_supported`）
/// 在反序列化时被忽略。
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct OidcDiscoveryMetadata {
    /// 签发者标识（Keycloak realm URL）。
    pub issuer: String,
    /// 授权端点 URL。
    pub authorization_endpoint: String,
    /// 令牌端点 URL。
    pub token_endpoint: String,
    /// JWKS 公钥集合端点 URL。
    pub jwks_uri: String,
}

/// JWKS 中的单个 RSA 公钥（依据 RFC 7517 / spec keycloak-oidc-rp R-keycloak-oidc-rp-003）。
///
/// 表示从 `/.well-known/openid-configuration` 的 `jwks_uri` 拉取的公钥集合中的一个条目。
/// 仅声明 RS256 验签所需字段；其他字段（如 `use` / `alg`）在反序列化时被忽略。
#[derive(Debug, Clone, Deserialize)]
pub struct Jwk {
    /// 公钥标识（Key ID），与 JWT header 的 `kid` 匹配以选择验签公钥。
    pub kid: String,
    /// RSA 模数（base64url 编码，无 padding）。
    pub n: String,
    /// RSA 公钥指数（base64url 编码，无 padding）。
    pub e: String,
}

/// JWKS 公钥集合响应（依据 RFC 7517）。
#[derive(Debug, Clone, Deserialize)]
pub struct JwksResponse {
    /// 公钥列表。
    pub keys: Vec<Jwk>,
}

/// JWKS 公钥缓存（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-003 设计决策 2）。
///
/// 缓存 JWKS 公钥集合 + 拉取时间戳，避免每次 `verify_id_token` 都拉取 JWKS endpoint。
/// TTL 由 [`JWKS_CACHE_TTL`] 控制，过期后下次调用重新拉取。
#[derive(Debug, Clone, Default)]
pub struct JwksCache {
    /// 缓存的公钥列表。
    keys: Vec<Jwk>,
    /// 上次拉取时间戳（`None` 表示从未拉取）。
    fetched_at: Option<Instant>,
}

impl JwksCache {
    /// 判断缓存是否为空或已过期（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-003）。
    ///
    /// 缓存为空或距上次拉取超过 [`JWKS_CACHE_TTL`] 时返回 `true`。
    fn is_empty_or_expired(&self) -> bool {
        match self.fetched_at {
            None => true,
            Some(t) => Instant::now().duration_since(t) > JWKS_CACHE_TTL,
        }
    }

    /// 按 `kid` 查找公钥（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-003）。
    fn find_by_kid(&self, kid: &str) -> Option<&Jwk> {
        self.keys.iter().find(|k| k.kid == kid)
    }
}

/// Keycloak realm 访问信息（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-003）。
///
/// 对应 Keycloak id_token 中 `realm_access` claim，含 realm 级别的角色列表。
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RealmAccess {
    /// realm 级别角色列表（如 `user` / `admin`）。
    pub roles: Vec<String>,
}

/// Keycloak id_token 的 claims（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-003）。
///
/// 包含标准 OIDC claims（`sub` / `preferred_username` / `email`）+ Keycloak 特有 claim
/// （`realm_access` / `resource_access`）+ 多租户扩展（`tenant_id`）。
///
/// # 字段
///
/// - `sub`: 主体标识（Keycloak 用户 ID）。
/// - `preferred_username`: 用户名（Keycloak 登录名）。
/// - `email`: 邮箱（可选，需 `email` scope）。
/// - `realm_access`: realm 级别角色（[`RealmAccess`]）。
/// - `resource_access`: client 级别角色映射（key 为 client_id，value 为 [`RealmAccess`]）。
/// - `tenant_id`: Bulwark 多租户标识（可选，由 Keycloak mapper 注入）。
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct KeycloakClaims {
    /// 主体标识（Keycloak 用户 ID）。
    pub sub: String,
    /// 过期时间（Unix 秒，RFC 7519 标准 claim，用于 `validate_exp` 校验）。
    pub exp: i64,
    /// 用户名（Keycloak 登录名）。
    pub preferred_username: Option<String>,
    /// 邮箱（可选，需 `email` scope）。
    pub email: Option<String>,
    /// realm 级别角色。
    pub realm_access: RealmAccess,
    /// client 级别角色映射（key 为 client_id）。
    pub resource_access: HashMap<String, RealmAccess>,
    /// 多租户标识（可选，由 Keycloak mapper 注入）。
    #[serde(default)]
    pub tenant_id: Option<i64>,
}

/// Keycloak token endpoint 响应（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-004）。
///
/// 表示 `exchange_code` 成功后 Keycloak 返回的 token 集合。
/// 仅声明 RP 流程所需的最小字段；其他字段（如 `token_type` / `scope`）在反序列化时被忽略。
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct KeycloakTokenSet {
    /// 访问令牌（用于调用 Keycloak 保护的资源 API）。
    pub access_token: String,
    /// 刷新令牌（用于在 access_token 过期后获取新的 access_token）。
    pub refresh_token: String,
    /// OIDC id_token（JWT 格式，含用户身份 claims，可由 `verify_id_token` 验签解析）。
    pub id_token: String,
    /// access_token 过期时间（秒）。
    pub expires_in: u64,
}

/// Keycloak OIDC 依赖方（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-002）。
///
/// 持有 `KeycloakConfig` 与可复用的 `reqwest::Client`，提供 OIDC RP 流程：
/// - [`discover`](Self::discover)：从 `/.well-known/openid-configuration` 拉取 IdP 元数据
/// - [`verify_id_token`](Self::verify_id_token)：JWKS 验签 + Keycloak claim 解析
/// - [`exchange_code`](Self::exchange_code)（T117-T118 实现）：授权码换 token set
///
/// # 设计决策
///
/// - `http: reqwest::Client` 复用连接池，`Send + Sync` 可在多线程共享。
/// - `jwks_cache: Arc<RwLock<JwksCache>>` 缓存 JWKS 公钥，TTL 由 [`JWKS_CACHE_TTL`] 控制，
///   避免每次 `verify_id_token` 都拉取 JWKS endpoint。
pub struct KeycloakProvider {
    /// RP 配置（base_url / client_id / client_secret / redirect_uri）。
    config: KeycloakConfig,
    /// 可复用的 HTTP 客户端。
    http: reqwest::Client,
    /// JWKS 公钥缓存（TTL 控制，避免每次验签都拉取）。
    jwks_cache: Arc<RwLock<JwksCache>>,
}

impl KeycloakProvider {
    /// 构造 `KeycloakProvider`（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-002）。
    ///
    /// # 参数
    ///
    /// - `config`: [`KeycloakConfig`] 配置实例。
    ///
    /// # 错误
    ///
    /// - `BulwarkError::Network`: `reqwest::Client` 构建失败。
    pub fn new(config: KeycloakConfig) -> BulwarkResult<Self> {
        let http = reqwest::Client::builder()
            .build()
            .map_err(|e| BulwarkError::Network(format!("构建 HTTP 客户端失败: {}", e)))?;
        Ok(Self {
            config,
            http,
            jwks_cache: Arc::new(RwLock::new(JwksCache::default())),
        })
    }

    /// 从 `/.well-known/openid-configuration` 拉取 OIDC discovery metadata
    ///（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-002）。
    ///
    /// HTTP GET [`KeycloakConfig::discovery_url`]，响应体按 JSON 解析为
    /// [`OidcDiscoveryMetadata`]。
    ///
    /// # 错误
    ///
    /// - `BulwarkError::Network`: HTTP 请求失败或非 2xx 状态码。
    /// - `BulwarkError::Deserialize`: 响应体 JSON 无法解析为 `OidcDiscoveryMetadata`。
    pub async fn discover(&self) -> BulwarkResult<OidcDiscoveryMetadata> {
        let url = self.config.discovery_url();
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| BulwarkError::Network(format!("discovery 请求失败: {}", e)))?;
        if !resp.status().is_success() {
            return Err(BulwarkError::Network(format!(
                "discovery 响应状态码非 2xx: {}",
                resp.status()
            )));
        }
        resp.json::<OidcDiscoveryMetadata>()
            .await
            .map_err(|e| BulwarkError::Network(format!("discovery 响应解析失败: {}", e)))
    }

    /// 拉取 JWKS 公钥集合并更新缓存（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-003）。
    ///
    /// HTTP GET [`KeycloakConfig::jwks_url`]，响应体按 JSON 解析为 [`JwksResponse`]，
    /// 将 `keys` 写入 `jwks_cache` 并更新 `fetched_at` 时间戳。
    ///
    /// # 错误
    ///
    /// - `BulwarkError::Network`: HTTP 请求失败、非 2xx 状态码或 JSON 解析失败。
    async fn fetch_jwks(&self) -> BulwarkResult<()> {
        let url = self.config.jwks_url();
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| BulwarkError::Network(format!("JWKS 请求失败: {}", e)))?;
        if !resp.status().is_success() {
            return Err(BulwarkError::Network(format!(
                "JWKS 响应状态码非 2xx: {}",
                resp.status()
            )));
        }
        let jwks = resp
            .json::<JwksResponse>()
            .await
            .map_err(|e| BulwarkError::Network(format!("JWKS 响应解析失败: {}", e)))?;
        let mut cache = self.jwks_cache.write();
        cache.keys = jwks.keys;
        cache.fetched_at = Some(Instant::now());
        Ok(())
    }

    /// 验证 id_token 签名并解析 Keycloak claims
    ///（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-003）。
    ///
    /// # 流程
    ///
    /// 1. 解析 JWT header，提取 `kid`。
    /// 2. 检查 `jwks_cache`，缓存为空或过期时调用 [`fetch_jwks`](Self::fetch_jwks) 拉取。
    /// 3. 按 `kid` 匹配 JWKS 公钥，用 `n`/`e` 模数构造 `DecodingKey`。
    /// 4. 用 RS256 算法验签，解析为 [`KeycloakClaims`]。
    /// 5. 校验 `exp`（过期时间），过期返回 `InvalidToken`（T119-T120 强化）。
    ///
    /// # 错误
    ///
    /// - `BulwarkError::InvalidToken`: JWT header 解析失败 / kid 缺失 / JWKS 无匹配公钥 /
    ///   签名验证失败 / claims 解析失败 / token 已过期。
    /// - `BulwarkError::Network`: JWKS 拉取失败。
    pub async fn verify_id_token(&self, id_token: &str) -> BulwarkResult<KeycloakClaims> {
        use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

        // 1. 解析 JWT header，提取 kid
        let header = jsonwebtoken::decode_header(id_token)
            .map_err(|e| BulwarkError::InvalidToken(format!("id_token header 解析失败: {}", e)))?;
        let kid = header.kid.as_deref().ok_or_else(|| {
            BulwarkError::InvalidToken("id_token header 缺少 kid 字段".to_string())
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
            BulwarkError::InvalidToken(format!("JWKS 中未找到 kid={} 的公钥", kid))
        })?;

        // 4. 构造 DecodingKey 并验签
        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|e| BulwarkError::InvalidToken(format!("构造 RSA 公钥失败: {}", e)))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        validation.leeway = 0;
        // jsonwebtoken 10 默认 validate_aud=true，但未设置 expected audience 会触发
        // InvalidAudience。关闭库内置 aud 校验，由调用方按需校验 client_id。
        validation.validate_aud = false;

        let token_data =
            decode::<KeycloakClaims>(id_token, &decoding_key, &validation).map_err(|e| {
                let msg = e.to_string();
                if msg.contains("ExpiredSignature") {
                    BulwarkError::InvalidToken("token expired".to_string())
                } else {
                    BulwarkError::InvalidToken(format!("id_token 验签失败: {}", e))
                }
            })?;
        Ok(token_data.claims)
    }

    /// 用授权码换取 token set
    ///（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-004 / RFC 6749 §4.1.3）。
    ///
    /// # 流程
    ///
    /// POST 请求 [`KeycloakConfig::token_url`]，以 `application/x-www-form-urlencoded`
    /// 格式提交：
    /// - `grant_type=authorization_code`
    /// - `code`: 授权码
    /// - `client_id`: [`KeycloakConfig::client_id`]
    /// - `redirect_uri`: [`KeycloakConfig::redirect_uri`]
    /// - `client_secret`: [`KeycloakConfig::client_secret`]（confidential client 必填，
    ///   public client 跳过此字段）
    ///
    /// # 错误
    ///
    /// - `BulwarkError::Network`: HTTP 请求失败、非 2xx 状态码或 JSON 解析失败。
    /// - `BulwarkError::InvalidParam`: `code` 为空。
    pub async fn exchange_code(&self, code: &str) -> BulwarkResult<KeycloakTokenSet> {
        if code.is_empty() {
            return Err(BulwarkError::InvalidParam("code 不可为空".to_string()));
        }

        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", &self.config.client_id),
            ("redirect_uri", &self.config.redirect_uri),
        ];
        if let Some(secret) = &self.config.client_secret {
            form.push(("client_secret", secret));
        }

        let url = self.config.token_url();
        let resp = self
            .http
            .post(&url)
            .form(&form)
            .send()
            .await
            .map_err(|e| BulwarkError::Network(format!("exchange_code 请求失败: {}", e)))?;
        if !resp.status().is_success() {
            return Err(BulwarkError::Network(format!(
                "exchange_code 响应状态码非 2xx: {}",
                resp.status()
            )));
        }
        resp.json::<KeycloakTokenSet>()
            .await
            .map_err(|e| BulwarkError::Network(format!("exchange_code 响应解析失败: {}", e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ========================================================================
    // T111-T112: KeycloakConfig Red-Green
    // ========================================================================

    /// T111 Red: `KeycloakConfig` 构造 + `discovery_url()` 返回正确 URL
    ///（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-001 验收标准 1）。
    ///
    /// Red 阶段：`KeycloakConfig` 类型不存在 → 编译失败。
    /// Green 阶段（T112）：定义 `KeycloakConfig` + `discovery_url()` 后测试通过。
    ///
    /// # 测试流程
    ///
    /// 1. 构造 `KeycloakConfig { base_url, client_id, client_secret: None, redirect_uri }`
    /// 2. 断言四个字段可读且值正确
    /// 3. 断言 `discovery_url()` 返回 `{base_url}/.well-known/openid-configuration`
    #[test]
    fn keycloak_config_constructs_with_base_url_client_id() {
        let config = KeycloakConfig {
            base_url: "https://kc.example.com:8443/realms/myrealm".into(),
            client_id: "bulwark-rp".into(),
            client_secret: None,
            redirect_uri: "https://app.example.com/cb".into(),
        };

        assert_eq!(
            config.base_url,
            "https://kc.example.com:8443/realms/myrealm"
        );
        assert_eq!(config.client_id, "bulwark-rp");
        assert!(config.client_secret.is_none());
        assert_eq!(config.redirect_uri, "https://app.example.com/cb");

        assert_eq!(
            config.discovery_url(),
            "https://kc.example.com:8443/realms/myrealm/.well-known/openid-configuration"
        );
    }

    // ========================================================================
    // T113-T114: KeycloakProvider::discover Red-Green
    // ========================================================================

    /// T113 Red: `KeycloakProvider::discover` 从 `/.well-known/openid-configuration`
    /// 拉取 OIDC discovery metadata（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-002）。
    ///
    /// Red 阶段：`KeycloakProvider` / `OidcDiscoveryMetadata` 类型不存在 → 编译失败。
    /// Green 阶段（T114）：定义 struct + discover 方法后测试通过。
    ///
    /// # 测试流程
    ///
    /// 1. 启动 wiremock MockServer，挂载 `GET /.well-known/openid-configuration`
    ///    返回标准 OIDC discovery JSON（含 issuer / authorization_endpoint / token_endpoint / jwks_uri）
    /// 2. 用 mock server URI 作为 base_url 构造 `KeycloakConfig`
    /// 3. 构造 `KeycloakProvider::new(config)`，调用 `discover().await?`
    /// 4. 断言返回 `OidcDiscoveryMetadata` 的四个字段值正确
    #[tokio::test]
    async fn keycloak_provider_discover_fetches_metadata_from_well_known() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        let issuer = server.uri();
        let authorization_endpoint = format!("{}/protocol/openid-connect/auth", server.uri());
        let token_endpoint = format!("{}/protocol/openid-connect/token", server.uri());
        let jwks_uri = format!("{}/protocol/openid-connect/certs", server.uri());

        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "issuer": issuer,
                "authorization_endpoint": authorization_endpoint,
                "token_endpoint": token_endpoint,
                "jwks_uri": jwks_uri,
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
            })))
            .mount(&server)
            .await;

        let config = KeycloakConfig {
            base_url: server.uri(),
            client_id: "bulwark-rp".into(),
            client_secret: None,
            redirect_uri: "https://app.example.com/cb".into(),
        };
        let provider = KeycloakProvider::new(config).expect("KeycloakProvider::new 应成功");
        let metadata = provider.discover().await.expect("discover 应返回 Ok");

        assert_eq!(metadata.issuer, issuer);
        assert_eq!(metadata.authorization_endpoint, authorization_endpoint);
        assert_eq!(metadata.token_endpoint, token_endpoint);
        assert_eq!(metadata.jwks_uri, jwks_uri);
    }

    // ========================================================================
    // T115-T116: KeycloakProvider::verify_id_token Red-Green
    // ========================================================================

    /// T115 Red: `KeycloakProvider::verify_id_token` 用 JWKS 公钥验签 id_token
    /// 并解析 Keycloak 特有 claim（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-003）。
    ///
    /// Red 阶段：`KeycloakClaims` 类型不存在 → 编译失败。
    /// Green 阶段（T116）：定义 struct + verify_id_token 方法后测试通过。
    ///
    /// # 测试流程
    ///
    /// 1. 生成 RSA 2048 测试密钥对
    /// 2. 提取公钥 n/e 模数编码为 base64url（JWKS 格式）
    /// 3. 用私钥签发 JWT（header 含 kid=key1，claims 含 sub/preferred_username/
    ///    realm_access.roles/resource_access.account.roles）
    /// 4. mock JWKS endpoint 返回公钥集合
    /// 5. 调用 `verify_id_token(id_token).await?`
    /// 6. 断言返回 `KeycloakClaims` 的 `sub` 与 `realm_access.roles` 正确
    #[tokio::test]
    async fn keycloak_provider_verify_id_token_validates_signature_and_claims() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use rand::rngs::OsRng;
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;
        use rsa::{RsaPrivateKey, RsaPublicKey};
        use serde::Serialize;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // 1. 生成 RSA 2048 测试密钥对
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("生成 RSA 私钥应成功");
        let public_key = RsaPublicKey::from(&private_key);

        // 2. 提取公钥 n/e 模数编码为 base64url（JWKS 格式）
        let n_bytes = public_key.n().to_bytes_be();
        let e_bytes = public_key.e().to_bytes_be();
        let n_b64 = URL_SAFE_NO_PAD.encode(n_bytes);
        let e_b64 = URL_SAFE_NO_PAD.encode(e_bytes);

        // 3. 用私钥签发 JWT（header 含 kid=key1）
        //    jsonwebtoken 10 的 EncodingKey::from_rsa_der 期望 PKCS#1 DER（非 PKCS#8）
        let der = private_key.to_pkcs1_der().expect("转 PKCS#1 DER 应成功");
        let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());

        #[derive(Serialize)]
        struct KeycloakTestClaims {
            sub: String,
            exp: i64,
            preferred_username: String,
            email: String,
            realm_access: serde_json::Value,
            resource_access: serde_json::Value,
        }

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("key1".to_string());

        // exp 设为当前时间 + 3600 秒（1 小时后过期，确保 validate_exp 通过）
        let exp = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("系统时间应早于 UNIX_EPOCH")
            .as_secs() as i64)
            + 3600;

        let claims = KeycloakTestClaims {
            sub: "user-123".into(),
            exp,
            preferred_username: "alice".into(),
            email: "alice@example.com".into(),
            realm_access: serde_json::json!({ "roles": ["user", "admin"] }),
            resource_access: serde_json::json!({
                "account": { "roles": ["manage-account"] }
            }),
        };

        let id_token = encode(&header, &claims, &encoding_key).expect("签发 JWT 应成功");

        // 4. mock JWKS endpoint
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/protocol/openid-connect/certs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [{
                    "kty": "RSA",
                    "kid": "key1",
                    "use": "sig",
                    "alg": "RS256",
                    "n": n_b64,
                    "e": e_b64,
                }]
            })))
            .mount(&server)
            .await;

        // 5. 构造 KeycloakProvider 并调用 verify_id_token
        let config = KeycloakConfig {
            base_url: server.uri(),
            client_id: "bulwark-rp".into(),
            client_secret: None,
            redirect_uri: "https://app.example.com/cb".into(),
        };
        let provider = KeycloakProvider::new(config).expect("KeycloakProvider::new 应成功");
        let keycloak_claims = provider
            .verify_id_token(&id_token)
            .await
            .expect("verify_id_token 应返回 Ok");

        // 6. 断言 KeycloakClaims 字段
        assert_eq!(keycloak_claims.sub, "user-123");
        assert_eq!(keycloak_claims.realm_access.roles, vec!["user", "admin"]);
    }

    // ========================================================================
    // T117-T118: KeycloakProvider::exchange_code Red-Green
    // ========================================================================

    /// T117 Red: `KeycloakProvider::exchange_code` 用授权码换取 token set
    ///（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-004）。
    ///
    /// Red 阶段：`KeycloakTokenSet` 类型 / `exchange_code` 方法不存在 → 编译失败。
    /// Green 阶段（T118）：定义 struct + exchange_code 方法后测试通过。
    ///
    /// # 测试流程
    ///
    /// 1. 启动 wiremock MockServer，挂载 `POST /protocol/openid-connect/token`
    ///    返回标准 token 响应 JSON
    /// 2. 构造 `KeycloakProvider`，调用 `exchange_code("code").await?`
    /// 3. 断言返回 `KeycloakTokenSet` 含 access_token / refresh_token / id_token / expires_in
    #[tokio::test]
    async fn keycloak_provider_exchange_code_returns_token_set() {
        use wiremock::matchers::{body_string, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/protocol/openid-connect/token"))
            .and(body_string(
                "grant_type=authorization_code&code=auth_code_123&client_id=bulwark-rp&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&client_secret=secret123",
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "at-456",
                "refresh_token": "rt-789",
                "id_token": "it-012",
                "expires_in": 3600,
                "token_type": "Bearer",
            })))
            .mount(&server)
            .await;

        let config = KeycloakConfig {
            base_url: server.uri(),
            client_id: "bulwark-rp".into(),
            client_secret: Some("secret123".into()),
            redirect_uri: "https://app.example.com/cb".into(),
        };
        let provider = KeycloakProvider::new(config).expect("KeycloakProvider::new 应成功");
        let token_set = provider
            .exchange_code("auth_code_123")
            .await
            .expect("exchange_code 应返回 Ok");

        assert_eq!(token_set.access_token, "at-456");
        assert_eq!(token_set.refresh_token, "rt-789");
        assert_eq!(token_set.id_token, "it-012");
        assert_eq!(token_set.expires_in, 3600);
    }

    // ========================================================================
    // T119-T120: 过期 id_token 被拒绝（已实现于 T116，此为回归测试）
    // ========================================================================

    /// T119 回归测试: `verify_id_token` 拒绝已过期的 id_token
    ///（依据 spec keycloak-oidc-rp R-keycloak-oidc-rp-003 + Rule 12 失败显性化）。
    ///
    /// T116 的 `verify_id_token` 实现已含 `validate_exp = true` +
    /// `ExpiredSignature` → `InvalidToken("token expired")` 映射。
    /// 本测试验证该行为，确保过期 token 不会被误判为有效。
    ///
    /// # 测试流程
    ///
    /// 1. 生成 RSA 密钥对，签发一个 `exp` 已过期的 ID Token
    /// 2. mock JWKS endpoint 返回公钥
    /// 3. 调用 `verify_id_token`，断言返回 `BulwarkError::InvalidToken("token expired")`
    #[tokio::test]
    async fn keycloak_provider_rejects_expired_id_token() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use rand::rngs::OsRng;
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;
        use rsa::{RsaPrivateKey, RsaPublicKey};
        use serde::Serialize;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // 1. 生成 RSA 密钥对 + 签发过期 JWT
        let mut rng = OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("生成 RSA 私钥应成功");
        let public_key = RsaPublicKey::from(&private_key);

        let n_b64 = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e_b64 = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        let der = private_key.to_pkcs1_der().expect("转 PKCS#1 DER 应成功");
        let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());

        #[derive(Serialize)]
        struct ExpiredTestClaims {
            sub: String,
            exp: i64,
            realm_access: serde_json::Value,
            resource_access: serde_json::Value,
        }

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("key1".to_string());

        // exp 设为当前时间 - 3600 秒（1 小时前已过期）
        let exp = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("系统时间应早于 UNIX_EPOCH")
            .as_secs() as i64)
            - 3600;

        let claims = ExpiredTestClaims {
            sub: "user-123".into(),
            exp,
            realm_access: serde_json::json!({ "roles": ["user"] }),
            resource_access: serde_json::json!({
                "account": { "roles": ["manage-account"] }
            }),
        };

        let id_token = encode(&header, &claims, &encoding_key).expect("签发 JWT 应成功");

        // 2. mock JWKS endpoint
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/protocol/openid-connect/certs"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "keys": [{
                    "kty": "RSA",
                    "kid": "key1",
                    "n": n_b64,
                    "e": e_b64,
                }]
            })))
            .mount(&server)
            .await;

        // 3. 调用 verify_id_token，断言返回 InvalidToken("token expired")
        let config = KeycloakConfig {
            base_url: server.uri(),
            client_id: "bulwark-rp".into(),
            client_secret: None,
            redirect_uri: "https://app.example.com/cb".into(),
        };
        let provider = KeycloakProvider::new(config).expect("KeycloakProvider::new 应成功");
        let result = provider.verify_id_token(&id_token).await;

        match result {
            Err(crate::error::BulwarkError::InvalidToken(msg)) => {
                assert_eq!(
                    msg, "token expired",
                    "过期 token 应返回 InvalidToken(\"token expired\")，实际: {}",
                    msg
                );
            },
            other => panic!(
                "过期 token 应返回 InvalidToken(\"token expired\")，实际: {:?}",
                other
            ),
        }
    }
}
