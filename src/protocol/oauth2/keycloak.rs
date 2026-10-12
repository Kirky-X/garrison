// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! Keycloak OIDC RP 模块：`KeycloakProvider` 作为 OIDC 依赖方，针对 Keycloak 特化（JWKS 验签、Keycloak 特有 claim 解析），区别于 `oauth2::oidc` 的通用 OIDC handler。
//!
//! 端点均基于 realm URL `{base_url}`（形如 `https://kc.example.com:8443/realms/{realm}`）：
//! Discovery `/.well-known/openid-configuration`、JWKS / Authorization / Token / UserInfo 均为 `/protocol/openid-connect/*`。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use crate::loc;
use crate::protocol::oauth2::client::{build_safe_http_client, read_limited_bytes};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

/// JWKS 公钥缓存 TTL（10 分钟）：避免每次 `verify_id_token` 都拉取 JWKS endpoint。
const JWKS_CACHE_TTL: Duration = Duration::from_secs(600);

/// Keycloak OIDC RP 配置：realm base_url、client_id、client_secret（confidential client 必填，public client 为 None）、redirect_uri、expected_iss。
///
/// 5 个端点推导方法按 Keycloak OIDC 约定拼接 URL。
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
    /// 预期的 issuer。
    /// 通常等于 `base_url`，用于 [`KeycloakProvider::verify_id_token`] 的 `validate_iss` 校验。
    pub expected_iss: String,
}

impl KeycloakConfig {
    /// Discovery 端点 URL：`{base_url}/.well-known/openid-configuration`。
    pub fn discovery_url(&self) -> String {
        format!("{}/.well-known/openid-configuration", self.base_url)
    }

    /// JWKS 端点 URL：`{base_url}/protocol/openid-connect/certs`。
    pub fn jwks_url(&self) -> String {
        format!("{}/protocol/openid-connect/certs", self.base_url)
    }

    /// Authorization 端点 URL：`{base_url}/protocol/openid-connect/auth`（浏览器跳转登录）。
    pub fn authorize_url(&self) -> String {
        format!("{}/protocol/openid-connect/auth", self.base_url)
    }

    /// Token 端点 URL：`{base_url}/protocol/openid-connect/token`（授权码换 token set）。
    pub fn token_url(&self) -> String {
        format!("{}/protocol/openid-connect/token", self.base_url)
    }

    /// UserInfo 端点 URL：`{base_url}/protocol/openid-connect/userinfo`。
    pub fn userinfo_url(&self) -> String {
        format!("{}/protocol/openid-connect/userinfo", self.base_url)
    }
}

/// OIDC Discovery Metadata：`/.well-known/openid-configuration` 拉取的 IdP 元数据（仅声明 RP 流程所需子集，其他字段反序列化时忽略）。
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

/// JWKS 中的单个 RSA 公钥：仅声明 RS256 验签所需字段，其他字段（`use` / `alg` 等）反序列化时忽略。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Jwk {
    /// 公钥标识（Key ID），与 JWT header 的 `kid` 匹配以选择验签公钥。
    pub kid: String,
    /// RSA 模数（base64url 编码，无 padding）。
    pub n: String,
    /// RSA 公钥指数（base64url 编码，无 padding）。
    pub e: String,
}

/// JWKS 公钥集合响应。
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct JwksResponse {
    /// 公钥列表。
    pub keys: Vec<Jwk>,
}

/// JWKS 缓存 key 前缀（拼入 DAO key：`keycloak:jwks:{expected_iss}`）；经 [`GarrisonDao`] 委托 oxcache 管理 JWKS JSON + TTL，禁止手写内存缓存。
const JWKS_CACHE_KEY_PREFIX: &str = "keycloak:jwks:";

/// Keycloak realm 访问信息（id_token 的 `realm_access` claim）。
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct RealmAccess {
    /// realm 级别角色列表（如 `user` / `admin`）。
    pub roles: Vec<String>,
}

/// Keycloak id_token 的 claims：标准 OIDC claims + Keycloak 特有 claim（`realm_access` / `resource_access`）+ 多租户扩展（`tenant_id`）。
#[derive(Debug, Clone, Deserialize, PartialEq)]
pub struct KeycloakClaims {
    /// 主体标识（Keycloak 用户 ID）。
    pub sub: String,
    /// 过期时间（Unix 秒，RFC 7519 §4.1.4，用于 `validate_exp` 校验）。
    pub exp: i64,
    /// Audience（RFC 7519 §4.1.3）：单个 String 或数组，用 `serde_json::Value` 兼容两种形式。
    #[serde(default)]
    pub aud: serde_json::Value,
    /// Issuer（RFC 7519 §4.1.1）。旧 token 可能无此字段故用 `Option`。
    #[serde(default)]
    pub iss: Option<String>,
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

/// Keycloak token endpoint 响应（`exchange_code` 成功后返回）：仅声明 RP 流程所需最小字段，其他字段反序列化时忽略。
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

/// Keycloak OIDC 依赖方：持有 `KeycloakConfig` 与可复用 `reqwest::Client`，提供 discover / verify_id_token / exchange_code 流程。
///
/// JWKS 缓存经 [`GarrisonDao`]（oxcache）管理，TTL 由 [`JWKS_CACHE_TTL`] 控制；须经 [`with_dao`](Self::with_dao) 注入 DAO，否则 `verify_id_token` 返回 [`GarrisonError::Config`]。
pub struct KeycloakProvider {
    /// RP 配置。
    config: KeycloakConfig,
    /// 可复用的 HTTP 客户端。
    http: reqwest::Client,
    /// DAO 抽象（oxcache 管理 JWKS 缓存）；`None` 时 `verify_id_token` 返回 `Config` 错误。
    dao: Option<Arc<dyn GarrisonDao>>,
    /// PKCE code_verifier：`Some` 时 `exchange_code` 改用 PKCE 鉴权（追加 `code_verifier`、跳过 `client_secret`）；
    /// public client（`client_secret=None`）必须经 [`with_pkce`](Self::with_pkce) 设置。
    pkce_verifier: Option<String>,
}

impl KeycloakProvider {
    /// 构造 `KeycloakProvider`（reqwest Client 构建失败返回 `Network`）。
    pub fn new(config: KeycloakConfig) -> GarrisonResult<Self> {
        let http = build_safe_http_client().map_err(|e| {
            GarrisonError::Network(loc!(
                "keycloak-http-client-build-failed",
                format!("Failed to build HTTP client: {}", e),
                ("detail", &e.to_string())
            ))
        })?;
        Ok(Self {
            config,
            http,
            dao: None,
            pkce_verifier: None,
        })
    }

    /// 注入 [`GarrisonDao`] 接管 JWKS 缓存（`verify_id_token` 依赖，未注入返回 `Config`；缓存 key `keycloak:jwks:{expected_iss}`）。
    ///
    /// # 示例
    ///
    /// ```ignore
    /// let provider = KeycloakProvider::new(config)?
    /// .with_dao(Arc::new(GarrisonDaoOxcache::new().await?));
    /// ```
    pub fn with_dao(mut self, dao: Arc<dyn GarrisonDao>) -> Self {
        self.dao = Some(dao);
        self
    }

    /// 设置 PKCE code_verifier（verifier 须 43-128 字符、仅 `[A-Z]/[a-z]/[0-9]/-./_/~`，RFC 7636 §4.1，非法返回 `InvalidParam`）。
    ///
    /// 调用后 [`exchange_code`](Self::exchange_code) 改用 PKCE 鉴权：追加 `code_verifier` 并跳过 `client_secret`（即使已配置，PKCE 优先）；
    /// public client（`client_secret=None`）必须调用，否则 `exchange_code` 返回 `Config` 错误。
    pub fn with_pkce(mut self, verifier: &str) -> GarrisonResult<Self> {
        // 复用 generate_pkce_challenge 校验 verifier 长度与字符集；challenge 值不使用（授权服务器在 token endpoint 重算比对）
        crate::protocol::oauth2::OAuth2Client::generate_pkce_challenge(verifier)?;
        self.pkce_verifier = Some(verifier.to_string());
        Ok(self)
    }

    /// 拉取 OIDC discovery metadata：GET [`KeycloakConfig::discovery_url`]，JSON 解析为 [`OidcDiscoveryMetadata`]；
    /// 请求失败/非 2xx/解析失败均返回 `Network`。
    pub async fn discover(&self) -> GarrisonResult<OidcDiscoveryMetadata> {
        let url = self.config.discovery_url();
        let resp = self.http.get(&url).send().await.map_err(|e| {
            GarrisonError::Network(loc!(
                "keycloak-discovery-request-failed",
                format!("discovery request failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;
        if !resp.status().is_success() {
            return Err(GarrisonError::Network(loc!(
                "keycloak-discovery-status-not-2xx",
                format!("discovery response status not 2xx: {}", resp.status()),
                ("detail", &resp.status().to_string())
            )));
        }
        // E2：限制响应体大小，防止恶意 IdP 通过超大 discovery JSON 触发 OOM
        let bytes = read_limited_bytes(resp).await.map_err(|e| {
            GarrisonError::Network(loc!(
                "keycloak-discovery-body-read-failed",
                format!("discovery body read failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;
        serde_json::from_slice::<OidcDiscoveryMetadata>(&bytes).map_err(|e| {
            GarrisonError::Network(loc!(
                "keycloak-discovery-response-parse-failed",
                format!("discovery response parse failed: {}", e),
                ("detail", &e.to_string())
            ))
        })
    }

    /// JWKS 缓存 key：`keycloak:jwks:{expected_iss}`（按 issuer 区分 realm）。
    fn jwks_cache_key(&self) -> String {
        format!("{}{}", JWKS_CACHE_KEY_PREFIX, self.config.expected_iss)
    }

    /// 拉取 JWKS 公钥集合并写入 DAO 缓存（JSON + [`JWKS_CACHE_TTL`]，过期后下次验签自动重拉）。
    ///
    /// 未注入 DAO 返回 `Config`；请求失败/非 2xx/解析失败返回 `Network`，DAO 写入失败返回 `Dao`。
    async fn fetch_jwks(&self) -> GarrisonResult<()> {
        let dao = self.dao.as_ref().ok_or_else(|| {
            GarrisonError::Config(loc!(
                "keycloak-dao-not-injected",
                "KeycloakProvider DAO not injected, cannot cache JWKS (call with_dao to inject GarrisonDao)"
                    .to_string()
            ))
        })?;
        let url = self.config.jwks_url();
        let resp = self.http.get(&url).send().await.map_err(|e| {
            GarrisonError::Network(loc!(
                "keycloak-jwks-request-failed",
                format!("JWKS request failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;
        if !resp.status().is_success() {
            return Err(GarrisonError::Network(loc!(
                "keycloak-jwks-status-not-2xx",
                format!("JWKS response status not 2xx: {}", resp.status()),
                ("detail", &resp.status().to_string())
            )));
        }
        // E2：限制响应体大小，防止恶意 IdP 通过超大 JWKS JSON 触发 OOM
        let bytes = read_limited_bytes(resp).await.map_err(|e| {
            GarrisonError::Network(loc!(
                "keycloak-jwks-body-read-failed",
                format!("JWKS body read failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;
        let jwks: JwksResponse = serde_json::from_slice(&bytes).map_err(|e| {
            GarrisonError::Network(loc!(
                "keycloak-jwks-response-parse-failed",
                format!("JWKS response parse failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;
        // 序列化为 JSON 字符串存入 DAO（反序列化时按相同结构解析）
        let json = serde_json::to_string(&jwks).map_err(|e| {
            GarrisonError::Internal(loc!(
                "keycloak-jwks-serialize-failed",
                format!("JWKS serialize failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;
        let cache_key = self.jwks_cache_key();
        dao.set(&cache_key, &json, JWKS_CACHE_TTL.as_secs()).await?;
        Ok(())
    }

    // 清洗 JWT `kid` 用于日志/错误输出：过滤控制字符并限长 128，防污染日志。
    fn sanitize_kid(kid: &str) -> String {
        let filtered: String = kid.chars().filter(|c| !c.is_control()).collect();
        filtered.chars().take(128).collect()
    }

    /// 校验 Keycloak 签发的 `id_token`：解析 header 取 kid → DAO 缓存 JWKS（miss 时经 `fetch_jwks` 重拉）→
    /// 按 kid 匹配公钥 → RS256 验签并校验 exp/nbf/aud/iss（三重校验防重放给非预期 client/issuer），返回 claims。
    ///
    /// 未注入 DAO 返回 `Config`；header/kid/验签/claims 失败返回 `InvalidToken`；JWKS 拉取失败返回 `Network`，DAO 读写失败返回 `Dao`。
    pub async fn verify_id_token(&self, id_token: &str) -> GarrisonResult<KeycloakClaims> {
        use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

        let dao = self.dao.as_ref().ok_or_else(|| {
            GarrisonError::Config(loc!(
                "keycloak-dao-not-injected",
                "KeycloakProvider DAO not injected, cannot cache JWKS (call with_dao to inject GarrisonDao)"
                    .to_string()
            ))
        })?;

        // 解析 JWT header 取 kid
        let header = jsonwebtoken::decode_header(id_token).map_err(|e| {
            GarrisonError::InvalidToken(loc!(
                "keycloak-id-token-header-parse-failed",
                format!("id_token header parse failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;
        let kid = header.kid.as_deref().ok_or_else(|| {
            GarrisonError::InvalidToken(loc!(
                "keycloak-id-token-header-missing-kid",
                "id_token header missing kid field".to_string()
            ))
        })?;

        // 读 DAO JWKS 缓存；miss/损坏时重新拉取并写入缓存
        let cache_key = self.jwks_cache_key();
        let cached = dao.get(&cache_key).await?;
        let (jwks, fresh): (JwksResponse, bool) = match cached
            .as_deref()
            .and_then(|json| serde_json::from_str(json).ok())
        {
            Some(jwks) => (jwks, false),
            None => {
                // 缓存 miss / TTL 过期 / 反序列化失败：重新拉取并写入缓存
                self.fetch_jwks().await?;
                let json = dao.get(&cache_key).await?.ok_or_else(|| {
                    GarrisonError::Internal(loc!(
                        "keycloak-jwks-cache-miss-after-fetch",
                        "cache miss after fetch_jwks (DAO write anomaly)".to_string()
                    ))
                })?;
                (
                    serde_json::from_str(&json).map_err(|e| {
                        GarrisonError::Internal(loc!(
                            "keycloak-jwks-deserialize-failed",
                            format!("JWKS deserialize failed: {}", e),
                            ("detail", &e.to_string())
                        ))
                    })?,
                    true,
                )
            },
        };

        // 按 kid 匹配 JWKS 公钥；缓存命中但 kid 未命中（密钥轮换）时强制重拉一次，已 freshly-fetched 则直接报错
        let jwk = match jwks.keys.iter().find(|k| k.kid == kid).cloned() {
            Some(jwk) => jwk,
            None if !fresh => {
                self.fetch_jwks().await?;
                let json = dao.get(&cache_key).await?.ok_or_else(|| {
                    GarrisonError::Internal(loc!(
                        "keycloak-jwks-cache-miss-after-fetch",
                        "cache miss after fetch_jwks (DAO write anomaly)".to_string()
                    ))
                })?;
                let refreshed: JwksResponse = serde_json::from_str(&json).map_err(|e| {
                    GarrisonError::Internal(loc!(
                        "keycloak-jwks-deserialize-failed",
                        format!("JWKS deserialize failed: {}", e),
                        ("detail", &e.to_string())
                    ))
                })?;
                refreshed
                    .keys
                    .iter()
                    .find(|k| k.kid == kid)
                    .cloned()
                    .ok_or_else(|| {
                        GarrisonError::InvalidToken(loc!(
                            "keycloak-jwks-key-not-found",
                            format!("JWKS key not found for kid={}", Self::sanitize_kid(kid)),
                            ("kid", &Self::sanitize_kid(kid))
                        ))
                    })?
            },
            None => {
                return Err(GarrisonError::InvalidToken(loc!(
                    "keycloak-jwks-key-not-found",
                    format!("JWKS key not found for kid={}", kid),
                    ("kid", kid)
                )))
            },
        };

        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e).map_err(|e| {
            GarrisonError::InvalidToken(loc!(
                "keycloak-rsa-public-key-build-failed",
                format!("Failed to build RSA public key: {}", e),
                ("detail", &e.to_string())
            ))
        })?;
        // aud/iss/nbf 三重校验（防重放给非预期 client/issuer）：exp 已启用，nbf 防生效前使用，aud 须含 client_id，iss 须等于 expected_iss
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        validation.validate_nbf = true;
        validation.validate_aud = true;
        validation.set_audience(&[&self.config.client_id]);
        validation.set_issuer(&[&self.config.expected_iss]);
        validation.leeway = 0;

        let token_data =
            decode::<KeycloakClaims>(id_token, &decoding_key, &validation).map_err(|e| {
                let msg = e.to_string();
                if msg.contains("ExpiredSignature") {
                    GarrisonError::InvalidToken(loc!(
                        "keycloak-token-expired",
                        "token expired".to_string()
                    ))
                } else if msg.contains("ImmatureSignature") {
                    GarrisonError::InvalidToken(loc!(
                        "keycloak-token-immature",
                        "token not yet valid (nbf)".to_string()
                    ))
                } else if msg.contains("InvalidAudience") {
                    GarrisonError::InvalidToken(loc!(
                        "keycloak-token-invalid-audience",
                        "invalid audience".to_string()
                    ))
                } else if msg.contains("InvalidIssuer") {
                    GarrisonError::InvalidToken(loc!(
                        "keycloak-token-invalid-issuer",
                        "invalid issuer".to_string()
                    ))
                } else {
                    GarrisonError::InvalidToken(loc!(
                        "keycloak-id-token-verify-failed",
                        format!("id_token verify failed: {}", e),
                        ("detail", &e.to_string())
                    ))
                }
            })?;
        Ok(token_data.claims)
    }

    /// 用授权码换取 token set：POST `token_url`（form-urlencoded，grant_type=authorization_code + code + client_id + redirect_uri），
    /// 鉴权字段为 PKCE `code_verifier`（已 with_pkce，跳过 client_secret）或 `client_secret`。
    ///
    /// `code` 为空返回 `InvalidParam`；`client_secret=None` 且未 with_pkce 返回 `Config`（public client 必须用 PKCE）；
    /// 请求失败/非 2xx/解析失败返回 `Network`。
    pub async fn exchange_code(&self, code: &str) -> GarrisonResult<KeycloakTokenSet> {
        if code.is_empty() {
            return Err(GarrisonError::InvalidParam(loc!(
                "keycloak-code-empty",
                "code cannot be empty".to_string()
            )));
        }

        let mut form: Vec<(&str, &str)> = vec![
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", &self.config.client_id),
            ("redirect_uri", &self.config.redirect_uri),
        ];

        // 鉴权方式：有 PKCE verifier 用 code_verifier（跳过 client_secret）；仅 client_secret 用之；两者皆无报错
        match (&self.pkce_verifier, &self.config.client_secret) {
            (Some(verifier), _) => form.push(("code_verifier", verifier.as_str())),
            (None, Some(secret)) => form.push(("client_secret", secret.as_str())),
            (None, None) => {
                return Err(GarrisonError::Config(loc!(
                    "keycloak-public-client-requires-pkce",
                    "public client (client_secret=None) must call with_pkce to set PKCE verifier"
                        .to_string()
                )));
            },
        }

        let url = self.config.token_url();
        let resp = self.http.post(&url).form(&form).send().await.map_err(|e| {
            GarrisonError::Network(loc!(
                "keycloak-exchange-code-request-failed",
                format!("exchange_code request failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;
        if !resp.status().is_success() {
            return Err(GarrisonError::Network(loc!(
                "keycloak-exchange-code-status-not-2xx",
                format!("exchange_code response status not 2xx: {}", resp.status()),
                ("detail", &resp.status().to_string())
            )));
        }
        // E2：限制响应体大小，防止恶意 IdP 通过超大 token JSON 触发 OOM
        let bytes = read_limited_bytes(resp).await.map_err(|e| {
            GarrisonError::Network(loc!(
                "keycloak-exchange-code-body-read-failed",
                format!("exchange_code body read failed: {}", e),
                ("detail", &e.to_string())
            ))
        })?;
        serde_json::from_slice::<KeycloakTokenSet>(&bytes).map_err(|e| {
            GarrisonError::Network(loc!(
                "keycloak-exchange-code-response-parse-failed",
                format!("exchange_code response parse failed: {}", e),
                ("detail", &e.to_string())
            ))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::InMemoryDao;

    // KeycloakConfig 构造 + discovery_url

    /// `KeycloakConfig` 构造后字段可读，`discovery_url()` 返回 `{base_url}/.well-known/openid-configuration`。
    #[test]
    fn keycloak_config_constructs_with_base_url_client_id() {
        let config = KeycloakConfig {
            base_url: "https://kc.example.com:8443/realms/myrealm".into(),
            client_id: "garrison-rp".into(),
            client_secret: None,
            redirect_uri: "https://app.example.com/cb".into(),
            expected_iss: "https://kc.example.com:8443/realms/myrealm".into(),
        };

        assert_eq!(
            config.base_url,
            "https://kc.example.com:8443/realms/myrealm"
        );
        assert_eq!(config.client_id, "garrison-rp");
        assert!(config.client_secret.is_none());
        assert_eq!(config.redirect_uri, "https://app.example.com/cb");

        assert_eq!(
            config.discovery_url(),
            "https://kc.example.com:8443/realms/myrealm/.well-known/openid-configuration"
        );
    }

    // discover

    /// `discover` 从 `/.well-known/openid-configuration` 拉取 metadata，返回 issuer / authorization_endpoint / token_endpoint / jwks_uri。
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
            client_id: "garrison-rp".into(),
            client_secret: None,
            redirect_uri: "https://app.example.com/cb".into(),
            expected_iss: server.uri(),
        };
        let provider = KeycloakProvider::new(config).expect("KeycloakProvider::new 应成功");
        let metadata = provider.discover().await.expect("discover 应返回 Ok");

        assert_eq!(metadata.issuer, issuer);
        assert_eq!(metadata.authorization_endpoint, authorization_endpoint);
        assert_eq!(metadata.token_endpoint, token_endpoint);
        assert_eq!(metadata.jwks_uri, jwks_uri);
    }

    // verify_id_token

    /// `verify_id_token` 用 JWKS 公钥验签 id_token 并解析 Keycloak 特有 claim（sub / realm_access.roles 等）。
    #[tokio::test]
    async fn keycloak_provider_verify_id_token_validates_signature_and_claims() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;
        use rsa::{RsaPrivateKey, RsaPublicKey};
        use serde::Serialize;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        // rsa 0.9 基于 rand_core 0.6，rand 0.10 的 RNG trait 不兼容，用 rsa::rand_core::OsRng
        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("生成 RSA 私钥应成功");
        let public_key = RsaPublicKey::from(&private_key);

        let n_bytes = public_key.n().to_bytes_be();
        let e_bytes = public_key.e().to_bytes_be();
        let n_b64 = URL_SAFE_NO_PAD.encode(n_bytes);
        let e_b64 = URL_SAFE_NO_PAD.encode(e_bytes);

        // jsonwebtoken 10 的 EncodingKey::from_rsa_der 期望 PKCS#1 DER（非 PKCS#8）
        let der = private_key.to_pkcs1_der().expect("转 PKCS#1 DER 应成功");
        let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());

        // 先启动 mock server，iss claim 需要 server.uri() 作为 issuer
        let server = MockServer::start().await;
        let issuer = server.uri();

        #[derive(Serialize)]
        struct KeycloakTestClaims {
            sub: String,
            exp: i64,
            aud: serde_json::Value, // audience claim
            iss: String,            // issuer claim
            preferred_username: String,
            email: String,
            realm_access: serde_json::Value,
            resource_access: serde_json::Value,
        }

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("key1".to_string());

        // exp = now + 3600，确保 validate_exp 通过
        let exp = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("系统时间应早于 UNIX_EPOCH")
            .as_secs() as i64)
            + 3600;

        let claims = KeycloakTestClaims {
            sub: "user-123".into(),
            exp,
            aud: serde_json::Value::String("garrison-rp".to_string()), // aud = client_id
            iss: issuer.clone(),                                       // iss = expected_iss
            preferred_username: "alice".into(),
            email: "alice@example.com".into(),
            realm_access: serde_json::json!({ "roles": ["user", "admin"] }),
            resource_access: serde_json::json!({
                "account": { "roles": ["manage-account"] }
            }),
        };

        let id_token = encode(&header, &claims, &encoding_key).expect("签发 JWT 应成功");

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

        let config = KeycloakConfig {
            base_url: server.uri(),
            client_id: "garrison-rp".into(),
            client_secret: None,
            redirect_uri: "https://app.example.com/cb".into(),
            expected_iss: issuer,
        };
        let provider = KeycloakProvider::new(config)
            .expect("KeycloakProvider::new 应成功")
            .with_dao(Arc::new(InMemoryDao::new()));
        let keycloak_claims = provider
            .verify_id_token(&id_token)
            .await
            .expect("verify_id_token 应返回 Ok");

        assert_eq!(keycloak_claims.sub, "user-123");
        assert_eq!(keycloak_claims.realm_access.roles, vec!["user", "admin"]);
    }

    // exchange_code

    /// `exchange_code` 用授权码换取 token set（POST token endpoint，断言 access_token / refresh_token / id_token / expires_in）。
    #[tokio::test]
    async fn keycloak_provider_exchange_code_returns_token_set() {
        use wiremock::matchers::{body_string, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;

        Mock::given(method("POST"))
            .and(path("/protocol/openid-connect/token"))
            .and(body_string(
                "grant_type=authorization_code&code=auth_code_123&client_id=garrison-rp&redirect_uri=https%3A%2F%2Fapp.example.com%2Fcb&client_secret=secret123",
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
            client_id: "garrison-rp".into(),
            client_secret: Some("secret123".into()),
            redirect_uri: "https://app.example.com/cb".into(),
            expected_iss: server.uri(),
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

    // 过期 id_token 被拒绝（回归测试）

    /// 回归测试：`verify_id_token` 拒绝已过期的 id_token（validate_exp + ExpiredSignature → InvalidToken 映射）。
    #[tokio::test]
    async fn keycloak_provider_rejects_expired_id_token() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;
        use rsa::{RsaPrivateKey, RsaPublicKey};
        use serde::Serialize;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("生成 RSA 私钥应成功");
        let public_key = RsaPublicKey::from(&private_key);

        let n_b64 = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e_b64 = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        let der = private_key.to_pkcs1_der().expect("转 PKCS#1 DER 应成功");
        let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());

        // 先启动 mock server，iss claim 需要 server.uri() 作为 issuer
        let server = MockServer::start().await;
        let issuer = server.uri();

        #[derive(Serialize)]
        struct ExpiredTestClaims {
            sub: String,
            exp: i64,
            aud: serde_json::Value, // audience claim（正确值以隔离 exp 校验）
            iss: String,            // issuer claim（正确值以隔离 exp 校验）
            realm_access: serde_json::Value,
            resource_access: serde_json::Value,
        }

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("key1".to_string());

        // exp = now - 3600（已过期）
        let exp = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("系统时间应早于 UNIX_EPOCH")
            .as_secs() as i64)
            - 3600;

        let claims = ExpiredTestClaims {
            sub: "user-123".into(),
            exp,
            aud: serde_json::Value::String("garrison-rp".to_string()), // aud 正确
            iss: issuer.clone(),                                       // iss 正确
            realm_access: serde_json::json!({ "roles": ["user"] }),
            resource_access: serde_json::json!({
                "account": { "roles": ["manage-account"] }
            }),
        };

        let id_token = encode(&header, &claims, &encoding_key).expect("签发 JWT 应成功");

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

        // i18n 启用时错误消息本地化、关闭时回退 fallback 字面量，断言用 contains 兼容两种构建
        let config = KeycloakConfig {
            base_url: server.uri(),
            client_id: "garrison-rp".into(),
            client_secret: None,
            redirect_uri: "https://app.example.com/cb".into(),
            expected_iss: issuer,
        };
        let provider = KeycloakProvider::new(config)
            .expect("KeycloakProvider::new 应成功")
            .with_dao(Arc::new(InMemoryDao::new()));
        let result = provider.verify_id_token(&id_token).await;

        match result {
            Err(crate::error::GarrisonError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("expired") || msg.contains("过期"),
                    "过期 token 应返回过期相关消息，实际: {}",
                    msg
                );
            },
            other => panic!("过期 token 应返回 InvalidToken 过期消息，实际: {:?}", other),
        }
    }

    // aud/iss 校验测试

    /// `verify_id_token` 拒绝 aud 不匹配 client_id 的 id_token（validate_aud + set_audience(client_id) → InvalidToken）。
    #[tokio::test]
    async fn keycloak_verify_id_token_rejects_wrong_audience() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;
        use rsa::{RsaPrivateKey, RsaPublicKey};
        use serde::Serialize;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("生成 RSA 私钥应成功");
        let public_key = RsaPublicKey::from(&private_key);

        let n_b64 = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e_b64 = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        let der = private_key.to_pkcs1_der().expect("转 PKCS#1 DER 应成功");
        let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());

        let server = MockServer::start().await;
        let issuer = server.uri();

        #[derive(Serialize)]
        struct WrongAudTestClaims {
            sub: String,
            exp: i64,
            aud: serde_json::Value,
            iss: String,
            realm_access: serde_json::Value,
            resource_access: serde_json::Value,
        }

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("key1".to_string());

        let exp = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("系统时间应早于 UNIX_EPOCH")
            .as_secs() as i64)
            + 3600;

        let claims = WrongAudTestClaims {
            sub: "user-123".into(),
            exp,
            aud: serde_json::Value::String("wrong-audience".to_string()), // 故意不匹配 client_id
            iss: issuer.clone(),
            realm_access: serde_json::json!({ "roles": ["user"] }),
            resource_access: serde_json::json!({
                "account": { "roles": ["manage-account"] }
            }),
        };

        let id_token = encode(&header, &claims, &encoding_key).expect("签发 JWT 应成功");

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

        let config = KeycloakConfig {
            base_url: server.uri(),
            client_id: "garrison-rp".into(),
            client_secret: None,
            redirect_uri: "https://app.example.com/cb".into(),
            expected_iss: issuer,
        };
        let provider = KeycloakProvider::new(config)
            .expect("KeycloakProvider::new 应成功")
            .with_dao(Arc::new(InMemoryDao::new()));
        let result = provider.verify_id_token(&id_token).await;

        match result {
            Err(crate::error::GarrisonError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("audience"),
                    "aud 不匹配应返回 audience 相关消息，实际: {}",
                    msg
                );
            },
            other => panic!("aud 不匹配应返回 InvalidToken，实际: {:?}", other),
        }
    }

    /// `verify_id_token` 拒绝 iss 不匹配 expected_iss 的 id_token（set_issuer(expected_iss) → InvalidToken）。
    #[tokio::test]
    async fn keycloak_verify_id_token_rejects_wrong_issuer() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;
        use rsa::{RsaPrivateKey, RsaPublicKey};
        use serde::Serialize;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("生成 RSA 私钥应成功");
        let public_key = RsaPublicKey::from(&private_key);

        let n_b64 = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e_b64 = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        let der = private_key.to_pkcs1_der().expect("转 PKCS#1 DER 应成功");
        let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());

        let server = MockServer::start().await;
        let issuer = server.uri();

        #[derive(Serialize)]
        struct WrongIssTestClaims {
            sub: String,
            exp: i64,
            aud: serde_json::Value,
            iss: String,
            realm_access: serde_json::Value,
            resource_access: serde_json::Value,
        }

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("key1".to_string());

        let exp = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("系统时间应早于 UNIX_EPOCH")
            .as_secs() as i64)
            + 3600;

        let claims = WrongIssTestClaims {
            sub: "user-123".into(),
            exp,
            aud: serde_json::Value::String("garrison-rp".to_string()), // aud 正确
            iss: "https://wrong-issuer.example.com".to_string(),       // 故意不匹配 expected_iss
            realm_access: serde_json::json!({ "roles": ["user"] }),
            resource_access: serde_json::json!({
                "account": { "roles": ["manage-account"] }
            }),
        };

        let id_token = encode(&header, &claims, &encoding_key).expect("签发 JWT 应成功");

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

        let config = KeycloakConfig {
            base_url: server.uri(),
            client_id: "garrison-rp".into(),
            client_secret: None,
            redirect_uri: "https://app.example.com/cb".into(),
            expected_iss: issuer,
        };
        let provider = KeycloakProvider::new(config)
            .expect("KeycloakProvider::new 应成功")
            .with_dao(Arc::new(InMemoryDao::new()));
        let result = provider.verify_id_token(&id_token).await;

        match result {
            Err(crate::error::GarrisonError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("issuer"),
                    "iss 不匹配应返回 issuer 相关消息，实际: {}",
                    msg
                );
            },
            other => panic!("iss 不匹配应返回 InvalidToken，实际: {:?}", other),
        }
    }

    /// `verify_id_token` 接受 aud 为数组（含 client_id）的 id_token：RFC 7519 §4.1.3 允许数组，Keycloak 常签发 `["garrison-rp", "account"]`。
    #[tokio::test]
    async fn keycloak_verify_id_token_accepts_aud_array() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;
        use rsa::{RsaPrivateKey, RsaPublicKey};
        use serde::Serialize;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("生成 RSA 私钥应成功");
        let public_key = RsaPublicKey::from(&private_key);

        let n_b64 = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e_b64 = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());

        let der = private_key.to_pkcs1_der().expect("转 PKCS#1 DER 应成功");
        let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());

        let server = MockServer::start().await;
        let issuer = server.uri();

        #[derive(Serialize)]
        struct AudArrayTestClaims {
            sub: String,
            exp: i64,
            aud: serde_json::Value,
            iss: String,
            realm_access: serde_json::Value,
            resource_access: serde_json::Value,
        }

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some("key1".to_string());

        let exp = (std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("系统时间应早于 UNIX_EPOCH")
            .as_secs() as i64)
            + 3600;

        let claims = AudArrayTestClaims {
            sub: "user-123".into(),
            exp,
            // aud 为数组形式，包含 client_id "garrison-rp" 和 "account"
            aud: serde_json::json!(["garrison-rp", "account"]),
            iss: issuer.clone(),
            realm_access: serde_json::json!({ "roles": ["user", "admin"] }),
            resource_access: serde_json::json!({
                "account": { "roles": ["manage-account"] }
            }),
        };

        let id_token = encode(&header, &claims, &encoding_key).expect("签发 JWT 应成功");

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

        let config = KeycloakConfig {
            base_url: server.uri(),
            client_id: "garrison-rp".into(),
            client_secret: None,
            redirect_uri: "https://app.example.com/cb".into(),
            expected_iss: issuer,
        };
        let provider = KeycloakProvider::new(config)
            .expect("KeycloakProvider::new 应成功")
            .with_dao(Arc::new(InMemoryDao::new()));
        let keycloak_claims = provider
            .verify_id_token(&id_token)
            .await
            .expect("aud 为数组含 client_id 时应返回 Ok");

        assert_eq!(keycloak_claims.sub, "user-123");
        assert_eq!(keycloak_claims.realm_access.roles, vec!["user", "admin"]);
    }

    // PKCE (RFC 7636)

    /// `with_pkce` 设置有效 verifier 后 `exchange_code` 请求体含 `code_verifier=` 且不含 `client_secret=`。
    #[tokio::test]
    async fn keycloak_pkce_flow_succeeds_with_valid_verifier() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/protocol/openid-connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "at-pkce",
                "refresh_token": "rt-pkce",
                "id_token": "it-pkce",
                "expires_in": 3600,
            })))
            .mount(&server)
            .await;

        let config = KeycloakConfig {
            base_url: server.uri(),
            client_id: "garrison-rp".into(),
            client_secret: None,
            redirect_uri: "https://app.example.com/cb".into(),
            expected_iss: server.uri(),
        };
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let provider = KeycloakProvider::new(config)
            .expect("KeycloakProvider::new 应成功")
            .with_pkce(verifier)
            .expect("with_pkce 应成功");

        let token_set = provider
            .exchange_code("auth_code_123")
            .await
            .expect("exchange_code 应返回 Ok");
        assert_eq!(token_set.access_token, "at-pkce");
        assert_eq!(token_set.refresh_token, "rt-pkce");
        assert_eq!(token_set.id_token, "it-pkce");
        assert_eq!(token_set.expires_in, 3600);

        // 验证请求体包含 code_verifier，不包含 client_secret
        let received = server.received_requests().await.expect("应收到请求");
        assert_eq!(received.len(), 1, "应只收到 1 个请求");
        let body = std::str::from_utf8(&received[0].body).expect("body 应为 UTF-8");
        assert!(
            body.contains("code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "请求体应包含 code_verifier 字段，实际: {}",
            body
        );
        assert!(
            !body.contains("client_secret="),
            "PKCE 流程不应包含 client_secret 字段，实际: {}",
            body
        );
    }

    /// `with_pkce` 传入无效 verifier（长度 < 43，RFC 7636 §4.1 下限）返回 `InvalidParam`。
    #[test]
    fn keycloak_pkce_flow_fails_on_invalid_verifier() {
        let config = KeycloakConfig {
            base_url: "https://kc.example.com:8443/realms/myrealm".into(),
            client_id: "garrison-rp".into(),
            client_secret: None,
            redirect_uri: "https://app.example.com/cb".into(),
            expected_iss: "https://kc.example.com:8443/realms/myrealm".into(),
        };
        let provider = KeycloakProvider::new(config).expect("KeycloakProvider::new 应成功");

        // verifier 长度 5 < 43（RFC 7636 §4.1 下限）
        let result = provider.with_pkce("short");
        assert!(result.is_err(), "无效 verifier 应返回错误");
        match result.err() {
            Some(crate::error::GarrisonError::InvalidParam(msg)) => {
                assert!(
                    msg.contains("43")
                        || msg.contains("长度")
                        || msg.contains("length")
                        || msg.contains("pkce-length-invalid"),
                    "错误消息应说明长度约束，实际: {}",
                    msg
                );
            },
            other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
        }
    }

    /// `client_secret=None` 且未调用 `with_pkce` 时 `exchange_code` 返回 `Config` 错误，且在发送 HTTP 请求前失败。
    #[tokio::test]
    async fn keycloak_without_client_secret_and_without_pkce_returns_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // 即使挂载了成功的 mock，exchange_code 也应在发送 HTTP 请求前返回错误
        Mock::given(method("POST"))
            .and(path("/protocol/openid-connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "should-not-reach",
                "refresh_token": "x",
                "id_token": "x",
                "expires_in": 3600,
            })))
            .mount(&server)
            .await;

        let config = KeycloakConfig {
            base_url: server.uri(),
            client_id: "garrison-rp".into(),
            client_secret: None,
            redirect_uri: "https://app.example.com/cb".into(),
            expected_iss: server.uri(),
        };
        let provider = KeycloakProvider::new(config).expect("KeycloakProvider::new 应成功");

        let result = provider.exchange_code("auth_code_123").await;
        assert!(result.is_err(), "无 client_secret 且无 PKCE 应返回错误");
        match result.err() {
            Some(crate::error::GarrisonError::Config(msg)) => {
                assert!(
                    msg.contains("with_pkce") || msg.contains("PKCE"),
                    "错误消息应提示调用 with_pkce，实际: {}",
                    msg
                );
            },
            other => panic!("期望 Config 错误，实际: {:?}", other),
        }

        // 验证未发送 HTTP 请求（鉴权校验应在 HTTP 调用前失败）
        let received = server.received_requests().await.expect("应能获取请求记录");
        assert_eq!(
            received.len(),
            0,
            "无鉴权方式时不应发送 HTTP 请求，实际收到 {} 个请求",
            received.len()
        );
    }

    /// 同时配置 `client_secret` 与 PKCE 时 `exchange_code` 使用 PKCE（请求体含 `code_verifier=`、不含 `client_secret=`）。
    #[tokio::test]
    async fn keycloak_with_pkce_overrides_client_secret_auth() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/protocol/openid-connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "access_token": "at-override",
                "refresh_token": "rt-override",
                "id_token": "it-override",
                "expires_in": 1800,
            })))
            .mount(&server)
            .await;

        let config = KeycloakConfig {
            base_url: server.uri(),
            client_id: "garrison-rp".into(),
            client_secret: Some("secret123".into()),
            redirect_uri: "https://app.example.com/cb".into(),
            expected_iss: server.uri(),
        };
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let provider = KeycloakProvider::new(config)
            .expect("KeycloakProvider::new 应成功")
            .with_pkce(verifier)
            .expect("with_pkce 应成功");

        let token_set = provider
            .exchange_code("auth_code_456")
            .await
            .expect("exchange_code 应返回 Ok");
        assert_eq!(token_set.access_token, "at-override");

        // 验证请求体使用 PKCE（code_verifier），不使用 client_secret
        let received = server.received_requests().await.expect("应收到请求");
        assert_eq!(received.len(), 1, "应只收到 1 个请求");
        let body = std::str::from_utf8(&received[0].body).expect("body 应为 UTF-8");
        assert!(
            body.contains("code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "PKCE 优先：请求体应包含 code_verifier 字段，实际: {}",
            body
        );
        assert!(
            !body.contains("client_secret="),
            "PKCE 优先：请求体不应包含 client_secret 字段，实际: {}",
            body
        );
    }

    // Keycloak 异常消息 i18n（feature = "i18n"）：直接调用 loc! 宏验证中英文翻译

    /// zh locale 下 keycloak-token-expired 返回中文消息（无参数）。
    #[cfg(feature = "i18n")]
    #[test]
    fn loc_i18n_keycloak_token_expired_zh() {
        use crate::i18n::{set_locale, GarrisonLocale};
        let _guard = set_locale(GarrisonLocale::Zh);
        let msg = crate::loc!("keycloak-token-expired", "token expired".to_string());
        assert_eq!(msg, "token 已过期");
    }

    /// en locale 下 keycloak-token-expired 返回英文消息（无参数）。
    #[cfg(feature = "i18n")]
    #[test]
    fn loc_i18n_keycloak_token_expired_en() {
        use crate::i18n::{set_locale, GarrisonLocale};
        let _guard = set_locale(GarrisonLocale::En);
        let msg = crate::loc!("keycloak-token-expired", "token expired".to_string());
        assert_eq!(msg, "Token expired");
    }

    /// zh locale 下 keycloak-jwks-key-not-found 带 kid 参数返回中文。
    #[cfg(feature = "i18n")]
    #[test]
    fn loc_i18n_keycloak_jwks_key_not_found_with_kid_zh() {
        use crate::i18n::{set_locale, GarrisonLocale};
        let _guard = set_locale(GarrisonLocale::Zh);
        let msg = crate::loc!(
            "keycloak-jwks-key-not-found",
            "JWKS key not found for kid=abc123".to_string(),
            ("kid", "abc123")
        );
        assert_eq!(msg, "JWKS 中未找到 kid=abc123 的公钥");
    }

    /// sanitize_kid 过滤控制字符并限长 128。
    #[test]
    fn sanitize_kid_filters_control_chars_and_limits_len() {
        assert_eq!(KeycloakProvider::sanitize_kid("abc123"), "abc123");
        assert_eq!(KeycloakProvider::sanitize_kid("bad\x01kid\x7f"), "badkid");
        let long = "a".repeat(200);
        assert_eq!(KeycloakProvider::sanitize_kid(&long).len(), 128);
    }

    // E1: reqwest 客户端超时（KeycloakProvider 复用 protocol::oauth2::client）

    /// E1 回归测试：`KeycloakProvider::new` 经 `build_safe_http_client()` 注入带超时的 HTTP 客户端（超时值由 client.rs 行为测试覆盖）。
    #[test]
    fn e1_keycloak_provider_new_uses_safe_http_client() {
        let config = KeycloakConfig {
            base_url: "https://kc.example.com:8443/realms/myrealm".into(),
            client_id: "garrison-rp".into(),
            client_secret: Some("secret".into()),
            redirect_uri: "https://app.example.com/cb".into(),
            expected_iss: "https://kc.example.com:8443/realms/myrealm".into(),
        };
        let provider = KeycloakProvider::new(config);
        assert!(provider.is_ok(), "KeycloakProvider::new 必须成功");
    }

    // E2: 响应体大小限制（KeycloakProvider discover/fetch_jwks/exchange_code）

    /// E2 集成测试：`discover` 拒绝 5 MiB 的 discovery JSON（返回 Err）。
    #[tokio::test]
    async fn e2_keycloak_discover_rejects_oversized_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        // 构造 5 MiB 的 discovery JSON（合法结构但超过上限）
        let huge_value = "x".repeat(5 * 1024 * 1024);
        let huge_json = format!(
            r#"{{"issuer":"https://kc.example.com","authorization_endpoint":"{}","token_endpoint":"{}","jwks_uri":"{}","userinfo_endpoint":"{}"}}"#,
            huge_value, huge_value, huge_value, huge_value
        );
        Mock::given(method("GET"))
            .and(path("/.well-known/openid-configuration"))
            .respond_with(ResponseTemplate::new(200).set_body_string(huge_json))
            .mount(&server)
            .await;

        let config = KeycloakConfig {
            base_url: server.uri(),
            client_id: "garrison-rp".into(),
            client_secret: Some("secret".into()),
            redirect_uri: "https://app.example.com/cb".into(),
            expected_iss: server.uri(),
        };
        let provider = KeycloakProvider::new(config).expect("provider 构建成功");
        let result = provider.discover().await;
        assert!(result.is_err(), "超大 discovery JSON 必须被拒绝");
    }

    /// E2 集成测试：`exchange_code` 拒绝 5 MiB 的 token JSON（返回 Err）。
    #[tokio::test]
    async fn e2_keycloak_exchange_code_rejects_oversized_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        let huge_value = "x".repeat(5 * 1024 * 1024);
        let huge_json = format!(r#"{{"access_token":"{}"}}"#, huge_value);
        Mock::given(method("POST"))
            .and(path("/protocol/openid-connect/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string(huge_json))
            .mount(&server)
            .await;

        let config = KeycloakConfig {
            base_url: server.uri(),
            client_id: "garrison-rp".into(),
            client_secret: Some("secret".into()),
            redirect_uri: "https://app.example.com/cb".into(),
            expected_iss: server.uri(),
        };
        let provider = KeycloakProvider::new(config).expect("provider 构建成功");
        let result = provider.exchange_code("code123").await;
        assert!(result.is_err(), "超大 token JSON 必须被拒绝");
    }
}
