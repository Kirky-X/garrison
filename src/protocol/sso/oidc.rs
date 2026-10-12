// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! OIDC（OpenID Connect）RP 协议支持骨架（`protocol-sso` feature）：提供 `OidcDiscoveryConfig` / `OidcUserInfo` 与 `OidcProvider` trait。
//!
//! `DefaultOidcProvider`：授权 URL 拼接、POST token_endpoint 交换 id_token、GET userinfo_endpoint、JWKS 验签（RS256）+ iss/aud/exp 校验（需 `protocol-jwt`，未启用返回 `NotImplemented`）。
//!
//! 与 `protocol::oauth2::oidc::OidcHandler` 的区别：`OidcHandler` 是 Garrison 作为 IdP 签发/验证 id_token，`OidcProvider` 是 Garrison 作为 RP 与外部 IdP 交互。
//!
//! `exchange_code` 返回前强制调用 `validate_id_token` 验签（fail-closed）。

use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use async_trait::async_trait;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// HTTP 客户端安全默认配置（protocol-sso 本地副本）：不依赖 `protocol-oauth2`，故维护等价实现，与 `oauth2::client` 的常量同值。
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// HTTP 响应体大小上限（protocol-sso 本地副本）：4 MiB，与 `oauth2::client::MAX_BODY_BYTES` 同值。
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// 构造带超时配置的 `reqwest::Client`（protocol-sso 本地副本）。
fn build_safe_http_client() -> GarrisonResult<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .read_timeout(HTTP_READ_TIMEOUT)
        .build()
        .map_err(|e| GarrisonError::Network(format!("sso-oidc-http-client-build::{}", e)))
}

/// 校验 OIDC 端点 URL scheme：discovery/token 端点携带 authorization code 与 `client_secret`，明文 http 可被中间人窃取；仅允许 `https://` 任意 host 或 `http://localhost` / `http://127.0.0.1`（开发/测试）。
fn validate_endpoint_scheme(url: &str, field: &str) -> GarrisonResult<()> {
    let reject = || GarrisonError::Config(format!("url-scheme-https-required::{}::{}", field, url));
    let scheme_end = url.find("://").ok_or_else(reject)?;
    let rest = &url[scheme_end + 3..];
    match &url[..scheme_end] {
        "https" => Ok(()),
        "http" => {
            let host_end = rest.find(['/', ':', '?']).unwrap_or(rest.len());
            if matches!(&rest[..host_end], "localhost" | "127.0.0.1") {
                Ok(())
            } else {
                Err(reject())
            }
        },
        _ => Err(reject()),
    }
}

/// 读取响应体并强制大小上限（protocol-sso 本地副本）：`resp.chunk()` 流式累积，超 [`MAX_BODY_BYTES`] 立即中断返回 Err。
async fn read_limited_bytes(resp: reqwest::Response) -> GarrisonResult<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    let mut resp = resp;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| GarrisonError::Network(format!("sso-oidc-body-read::{}", e)))?
    {
        let new_len = buf
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| GarrisonError::Network("sso-oidc-body-overflow".to_string()))?;
        if new_len > MAX_BODY_BYTES {
            return Err(GarrisonError::Network(format!(
                "sso-oidc-body-exceeds-limit::{}",
                MAX_BODY_BYTES
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// 读取响应体为 UTF-8 字符串，强制大小上限（protocol-sso 本地副本）。
async fn read_limited_text(resp: reqwest::Response) -> GarrisonResult<String> {
    let bytes = read_limited_bytes(resp).await?;
    String::from_utf8(bytes)
        .map_err(|e| GarrisonError::Network(format!("sso-oidc-body-utf8::{}", e)))
}

/// JWKS 公钥缓存 TTL（10 分钟，与 `oauth2::keycloak::JWKS_CACHE_TTL` 一致），避免每次验签都拉取 JWKS endpoint。
#[cfg(feature = "protocol-jwt")]
const JWKS_CACHE_TTL: Duration = Duration::from_secs(600);

/// OIDC state TTL（10 分钟，覆盖授权码典型生命周期）：`get_authorization_url` 注册的 state 超时后 `exchange_code` 拒绝。
const OIDC_STATE_TTL: Duration = Duration::from_secs(600);

/// JWKS 缓存 key 前缀（`oidc:jwks:{issuer}`）：经 `GarrisonDao` 委托 oxcache 管理 JSON + TTL，禁止手写内存缓存。
#[cfg(feature = "protocol-jwt")]
const JWKS_CACHE_KEY_PREFIX: &str = "oidc:jwks:";

/// OIDC state 缓存 key 前缀（`oidc:state:{state}`）：经 `GarrisonDao` 委托 oxcache 管理注册/消费/TTL，替代手写 `Mutex<HashMap<String, Instant>>`。
const OIDC_STATE_KEY_PREFIX: &str = "oidc:state:";

/// URL 编码集（与 `oauth2/client.rs` 一致）：`NON_ALPHANUMERIC` 移除 RFC 3986 unreserved 的 `- _ . ~`，其余按 `%HH` 编码；统一委托 `percent-encoding`（原手写实现不编码非 ASCII/控制字符，有 URL 注入风险）。
const URLENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

// OIDC 数据结构

/// OIDC Discovery 配置：调用方提供 endpoints，provider 不自动获取/缓存 discovery 文档。
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

/// OIDC UserInfo 响应（对应 UserInfo endpoint 的标准 claims）。
///
/// # 可选 claims（真实 IdP 兼容性）
///
/// 按 OIDC Core spec 仅 `sub` 必需，`email` / `name` / `preferred_username` / `picture` 均可选——真实 IdP（Google/Azure AD/Okta）按请求 scope 常省略部分字段；
/// 故除 `sub` 外全部标注 `#[serde(default)]`（缺失反序列化为空字符串），避免解析失败导致登录不可用。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcUserInfo {
    /// 主体标识（OIDC spec 唯一必需 claim）。
    pub sub: String,
    /// 邮箱地址（可选，缺失为空字符串）。
    #[serde(default)]
    pub email: String,
    /// 显示名称（可选，缺失为空字符串）。
    #[serde(default)]
    pub name: String,
    /// 首选用户名（可选，缺失为空字符串）。
    #[serde(default)]
    pub preferred_username: String,
    /// 头像 URL（可选，缺失为空字符串）。
    #[serde(default)]
    pub picture: String,
}

// OidcProvider trait

/// OIDC 协议交互 trait（Authorization Code Flow）。
#[async_trait]
pub trait OidcProvider: Send + Sync {
    /// 构造授权 URL（`state` 防 CSRF；`scopes` 如 `["openid", "profile", "email"]`）。
    async fn get_authorization_url(
        &self,
        redirect_uri: &str,
        state: &str,
        scopes: &[&str],
    ) -> GarrisonResult<String>;

    /// 交换授权码获取 id_token（JWT）；`redirect_uri` 须与授权请求一致，`state` 须匹配已注册值，否则返回 `GarrisonError::InvalidParam`（CSRF 防护）。
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        state: &str,
    ) -> GarrisonResult<String>;

    /// 用 access_token 获取用户信息（`OidcUserInfo`）。
    async fn get_user_info(&self, access_token: &str) -> GarrisonResult<OidcUserInfo>;

    /// 验证 id_token（JWT）；未启用 JWT 验签时返回 `GarrisonError::NotImplemented`。
    async fn validate_id_token(&self, id_token: &str) -> GarrisonResult<bool>;
}

// DefaultOidcProvider

/// JWKS 中的单个 RSA 公钥（仅声明 RS256 验签所需字段，`use`/`alg` 等反序列化时忽略）；JWKS 仅被 jwt 门控的验签路径消费，无 jwt 构建不编译本结构。
#[cfg(feature = "protocol-jwt")]
#[derive(Debug, Clone, Deserialize, Serialize)]
struct Jwk {
    /// 公钥标识（Key ID），与 JWT header 的 `kid` 匹配以选择验签公钥。
    kid: String,
    /// RSA 模数（base64url 编码，无 padding）。
    n: String,
    /// RSA 公钥指数（base64url 编码，无 padding）。
    e: String,
}

/// JWKS 公钥集合响应。
#[cfg(feature = "protocol-jwt")]
#[derive(Debug, Clone, Deserialize, Serialize)]
struct JwksResponse {
    /// 公钥列表。
    keys: Vec<Jwk>,
}

/// 默认 OIDC Provider 实现（reqwest 与外部 IdP 交互）。
///
/// # 验签行为
///
/// `validate_id_token` 在 `protocol-jwt` 下执行 JWKS 验签（RS256）+ iss/aud/exp 校验；`protocol-sso` 隐含启用该 feature，`exchange_code` 返回前强制验签；未启用分支 fail-closed 返回 `Config`（不验签不放行）。
///
/// # 缓存行为
///
/// JWKS 缓存与 state 注册表经 `GarrisonDao`（oxcache）管理，禁止手写内存缓存；调用方必须经 [`with_dao`](Self::with_dao) 注入 DAO，否则相关方法返回 [`GarrisonError::Config`]。
pub struct DefaultOidcProvider {
    /// Discovery 配置（含 endpoints）。
    config: OidcDiscoveryConfig,
    /// 客户端 ID。
    client_id: String,
    /// 客户端密钥。
    client_secret: String,
    /// HTTP 客户端。
    http_client: reqwest::Client,
    /// DAO 抽象（oxcache 管理 JWKS 缓存 + state 注册表）；`None` 时相关方法返回 `Config` 错误，经 [`with_dao`](Self::with_dao) 注入。
    dao: Option<Arc<dyn GarrisonDao>>,
    /// state TTL（默认 `OIDC_STATE_TTL`，测试可经 `with_state_ttl` 覆盖）；写入 DAO 后由 oxcache 管理过期。
    state_ttl: Duration,
    /// JWKS 拉取 single-flight 锁（防缓存击穿）：缓存 miss 时持锁并二次检查缓存，避免并发 `validate_id_token` 对 JWKS endpoint 形成惊群。
    #[cfg(feature = "protocol-jwt")]
    jwks_fetch_lock: tokio::sync::Mutex<()>,
}

impl DefaultOidcProvider {
    /// 创建 `DefaultOidcProvider`（调用方提供 `OidcDiscoveryConfig`，不自动获取 discovery 文档）。
    ///
    /// 实例未注入 DAO，相关方法返回 `Config` 错误，须调用 [`with_dao`](Self::with_dao)；端点 scheme 非 https/localhost 或 reqwest 构建失败返回错误。
    pub fn new(
        config: OidcDiscoveryConfig,
        client_id: &str,
        client_secret: &str,
    ) -> GarrisonResult<Self> {
        // 四个端点均携带敏感数据或影响验签信任链，明文 http 仅允许本机回环
        validate_endpoint_scheme(&config.authorization_endpoint, "authorization_endpoint")?;
        validate_endpoint_scheme(&config.token_endpoint, "token_endpoint")?;
        validate_endpoint_scheme(&config.userinfo_endpoint, "userinfo_endpoint")?;
        validate_endpoint_scheme(&config.jwks_uri, "jwks_uri")?;
        // 注入 connect/read 超时，防慢速 IdP 拖垮连接池（slowloris）
        let http_client = build_safe_http_client()?;
        Ok(Self {
            config,
            client_id: client_id.to_string(),
            client_secret: client_secret.to_string(),
            http_client,
            dao: None,
            state_ttl: OIDC_STATE_TTL,
            #[cfg(feature = "protocol-jwt")]
            jwks_fetch_lock: tokio::sync::Mutex::new(()),
        })
    }

    /// 注入 [`GarrisonDao`] 接管 JWKS 缓存与 state 注册表（必选调用，否则相关方法返回 `Config`）。
    ///
    /// JWKS key `oidc:jwks:{issuer}`（TTL `JWKS_CACHE_TTL`）；state key `oidc:state:{state}`（TTL `OIDC_STATE_TTL` 或 `with_state_ttl`）。
    ///
    /// # 示例
    ///
    /// ```ignore
    /// let provider = DefaultOidcProvider::new(config, "cid", "secret")
    /// .with_dao(Arc::new(GarrisonDaoOxcache::new().await?));
    /// ```
    pub fn with_dao(mut self, dao: Arc<dyn GarrisonDao>) -> Self {
        self.dao = Some(dao);
        self
    }

    /// 自定义 state TTL（测试用；设极短时长可测过期场景）。
    #[cfg(test)]
    pub fn with_state_ttl(mut self, ttl: Duration) -> Self {
        self.state_ttl = ttl;
        self
    }

    /// JWKS 缓存 key（`oidc:jwks:{issuer}`，按 issuer 区分 IdP）。
    #[cfg(feature = "protocol-jwt")]
    fn jwks_cache_key(&self) -> String {
        format!("{}{}", JWKS_CACHE_KEY_PREFIX, self.config.issuer)
    }

    /// state 缓存 key（`oidc:state:{state}`）。
    fn state_cache_key(state: &str) -> String {
        format!("{}{}", OIDC_STATE_KEY_PREFIX, state)
    }

    /// 注册 state 到 DAO（`get_authorization_url` 调用；TTL 由 oxcache 管理）。
    async fn register_state(&self, state: &str) -> GarrisonResult<()> {
        let dao = self.dao.as_ref().ok_or_else(|| {
            GarrisonError::Config("sso-oidc-dao-missing-register-state".to_string())
        })?;
        let key = Self::state_cache_key(state);
        dao.set(&key, "1", self.state_ttl.as_secs()).await
    }

    /// 校验并消费 state（one-time use，经 `get_and_delete` 原子消费，防重放）；未注册/不匹配/已过期返回 `InvalidParam`，未注入 DAO 返回 `Config`。
    async fn validate_and_consume_state(&self, state: &str) -> GarrisonResult<()> {
        let dao = self.dao.as_ref().ok_or_else(|| {
            GarrisonError::Config("sso-oidc-dao-missing-validate-state".to_string())
        })?;
        let key = Self::state_cache_key(state);
        let value = dao.get_and_delete(&key).await?;
        match value {
            Some(_) => Ok(()),
            None => Err(GarrisonError::InvalidParam(format!(
                "sso-oidc-state-mismatch-or-expired::{}",
                self.state_ttl.as_secs()
            ))),
        }
    }

    /// 拉取 JWKS 公钥集合并写入 DAO 缓存（`dao.set` + `JWKS_CACHE_TTL`，过期后下次验签自动重拉）；未注入 DAO 返回 `Config`，HTTP/解析/写入失败返回 `Internal`。
    #[cfg(feature = "protocol-jwt")]
    async fn fetch_jwks(&self) -> GarrisonResult<()> {
        let dao = self
            .dao
            .as_ref()
            .ok_or_else(|| GarrisonError::Config("sso-oidc-dao-missing-cache-jwks".to_string()))?;

        // 幂等 GET 对传输层错误做一次有界重试（回环/内网链路偶发截断，重试成本远低于认证作废）；
        // 非 2xx 与解析错误不重试（IdP 行为语义，重试会掩盖真问题）
        let resp = {
            let mut attempt = 1;
            loop {
                match self.http_client.get(&self.config.jwks_uri).send().await {
                    Ok(resp) => break resp,
                    Err(e) if attempt < 2 => {
                        attempt += 1;
                        tracing::warn!(
                            "{}",
                            crate::i18n::translate_detail(
                                "logs-sso-oidc-jwks-fetch-retry",
                                &[("error", &e.to_string())]
                            )
                        );
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    },
                    Err(e) => {
                        return Err(GarrisonError::Internal(format!(
                            "sso-oidc-jwks-request::{}",
                            e
                        )));
                    },
                }
            }
        };

        if !resp.status().is_success() {
            let status = resp.status();
            // 错误响应体同样限 4 MiB，防恶意 IdP 触发 OOM
            let body = read_limited_text(resp).await.unwrap_or_default();
            return Err(GarrisonError::Internal(format!(
                "sso-oidc-jwks-status-error::{}::{}",
                status, body
            )));
        }

        // 限制响应体 4 MiB，防超大 JWKS JSON 触发 OOM
        let bytes = read_limited_bytes(resp)
            .await
            .map_err(|e| GarrisonError::Internal(format!("sso-oidc-jwks-body-read::{}", e)))?;
        let jwks: JwksResponse = serde_json::from_slice(&bytes)
            .map_err(|e| GarrisonError::Internal(format!("sso-oidc-jwks-parse::{}", e)))?;

        // 序列化为 JSON 存入 DAO
        let json = serde_json::to_string(&jwks)
            .map_err(|e| GarrisonError::Internal(format!("sso-oidc-jwks-serialize::{}", e)))?;
        let cache_key = self.jwks_cache_key();
        dao.set(&cache_key, &json, JWKS_CACHE_TTL.as_secs()).await?;
        Ok(())
    }

    #[cfg(feature = "protocol-jwt")]
    // 清洗 JWT `kid` 用于日志/错误输出：过滤控制字符并限长 128，防污染日志。
    fn sanitize_kid(kid: &str) -> String {
        let filtered: String = kid.chars().filter(|c| !c.is_control()).collect();
        filtered.chars().take(128).collect()
    }

    /// 验证 id_token：解析 header 取 kid → DAO 缓存 JWKS（miss 时拉取）→ 按 kid 匹配公钥 →
    /// RS256 验签并校验 iss/aud/exp；未注入 DAO 返回 `Config`，验签或 claims 失败返回 `InvalidToken`。
    async fn validate_id_token_impl(&self, id_token: &str) -> GarrisonResult<bool> {
        use jsonwebtoken::{decode, Algorithm, DecodingKey, Validation};

        /// id_token 的 aud claim（RFC 7519 §4.1.3：String 或数组形式；untagged 反序列化）。
        #[derive(Deserialize, Debug)]
        #[serde(untagged)]
        enum Aud {
            Single(String),
            Multi(Vec<String>),
        }

        impl Aud {
            /// 判断 client_id 是否在 aud 中（支持 String 和数组形式）。
            fn contains(&self, client_id: &str) -> bool {
                match self {
                    Aud::Single(s) => s == client_id,
                    Aud::Multi(v) => v.iter().any(|s| s == client_id),
                }
            }
        }

        /// id_token 标准 claims（仅声明验签所需字段，其他字段被忽略）。
        #[derive(Deserialize)]
        struct IdTokenClaims {
            /// 签发者标识（必须匹配 `config.issuer`）。
            iss: String,
            /// 受众（必须包含 `client_id`，支持 String 或数组形式）。
            aud: Aud,
        }

        let dao = self
            .dao
            .as_ref()
            .ok_or_else(|| GarrisonError::Config("sso-oidc-dao-missing-cache-jwks".to_string()))?;

        let header = jsonwebtoken::decode_header(id_token).map_err(|e| {
            GarrisonError::InvalidToken(format!("sso-oidc-id-token-header-parse::{}", e))
        })?;
        let kid = header.kid.as_deref().ok_or_else(|| {
            GarrisonError::InvalidToken("sso-oidc-id-token-header-missing-kid".to_string())
        })?;

        // DAO 缓存 miss/损坏时经 single-flight 锁拉取（持锁后二次检查缓存，防惊群）。
        let cache_key = self.jwks_cache_key();
        let cached = dao.get(&cache_key).await?;
        let (jwks, fresh): (JwksResponse, bool) = match cached
            .as_deref()
            .and_then(|json| serde_json::from_str(json).ok())
        {
            Some(jwks) => (jwks, false),
            None => {
                // 缓存 miss / TTL 过期 / 反序列化失败：获取 single-flight 锁
                let _lock = self.jwks_fetch_lock.lock().await;
                // 二次检查：持锁期间其他请求可能已填充缓存，命中则直接复用
                let cached = dao.get(&cache_key).await?;
                match cached
                    .as_deref()
                    .and_then(|s| serde_json::from_str::<JwksResponse>(s).ok())
                {
                    Some(jwks) => (jwks, false),
                    None => {
                        // 仍未命中：真正发起 JWKS 拉取并写入缓存
                        self.fetch_jwks().await?;
                        let json = dao.get(&cache_key).await?.ok_or_else(|| {
                            GarrisonError::Internal(
                                "sso-oidc-jwks-cache-empty-after-fetch".to_string(),
                            )
                        })?;
                        (
                            serde_json::from_str(&json).map_err(|e| {
                                GarrisonError::Internal(format!("sso-oidc-jwks-parse::{}", e))
                            })?,
                            true,
                        )
                    },
                }
            },
        };

        // kid 未命中（密钥轮换场景）且非 freshly-fetched 时强制重拉 JWKS 一次再匹配。
        let jwk = match jwks.keys.iter().find(|k| k.kid == kid).cloned() {
            Some(jwk) => jwk,
            None if !fresh => {
                let _lock = self.jwks_fetch_lock.lock().await;
                let cached = dao.get(&cache_key).await?;
                let refreshed = match cached
                    .as_deref()
                    .and_then(|s| serde_json::from_str::<JwksResponse>(s).ok())
                {
                    Some(jwks) => jwks,
                    None => {
                        self.fetch_jwks().await?;
                        let json = dao.get(&cache_key).await?.ok_or_else(|| {
                            GarrisonError::Internal(
                                "sso-oidc-jwks-cache-empty-after-fetch".to_string(),
                            )
                        })?;
                        serde_json::from_str(&json).map_err(|e| {
                            GarrisonError::Internal(format!("sso-oidc-jwks-parse::{}", e))
                        })?
                    },
                };
                refreshed
                    .keys
                    .iter()
                    .find(|k| k.kid == kid)
                    .cloned()
                    .ok_or_else(|| {
                        GarrisonError::InvalidToken(format!(
                            "sso-oidc-jwks-key-not-found::{}",
                            Self::sanitize_kid(kid)
                        ))
                    })?
            },
            None => {
                return Err(GarrisonError::InvalidToken(format!(
                    "sso-oidc-jwks-key-not-found::{}",
                    Self::sanitize_kid(kid)
                )))
            },
        };

        let decoding_key = DecodingKey::from_rsa_components(&jwk.n, &jwk.e)
            .map_err(|e| GarrisonError::InvalidToken(format!("sso-oidc-rsa-build::{}", e)))?;
        let mut validation = Validation::new(Algorithm::RS256);
        validation.validate_exp = true;
        validation.validate_nbf = true; // 对齐 keycloak 版，启用 nbf 生效时间校验
        validation.leeway = 0;
        // 关闭库内置 aud 校验（未设 expected audience 会报 InvalidAudience），改为手动校验 client_id 以给出精确错误
        validation.validate_aud = false;

        let token_data =
            decode::<IdTokenClaims>(id_token, &decoding_key, &validation).map_err(|e| {
                let msg = e.to_string();
                if msg.contains("ExpiredSignature") {
                    GarrisonError::InvalidToken("sso-oidc-id-token-expired".to_string())
                } else {
                    GarrisonError::InvalidToken(format!("sso-oidc-id-token-verify::{}", e))
                }
            })?;

        // 校验 iss（必须匹配 config.issuer）
        if token_data.claims.iss != self.config.issuer {
            return Err(GarrisonError::InvalidToken(format!(
                "sso-oidc-id-token-invalid::{}::{}",
                self.config.issuer, token_data.claims.iss
            )));
        }

        // 校验 aud（必须包含 client_id，支持 String 或数组形式）
        if !token_data.claims.aud.contains(&self.client_id) {
            return Err(GarrisonError::InvalidToken(format!(
                "sso-oidc-id-token-invalid::{}::{:?}",
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
    ) -> GarrisonResult<String> {
        // 注册 state 供 exchange_code 校验（CSRF 防护）；TTL 过期由 oxcache 自动管理
        self.register_state(state).await?;

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

    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        state: &str,
    ) -> GarrisonResult<String> {
        // 校验并消费 state（CSRF 防护 + 一次性防重放）
        self.validate_and_consume_state(state).await?;

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
            .map_err(|e| GarrisonError::Internal(format!("sso-oidc-token-exchange::{}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            // 错误响应体同样限 4 MiB，防恶意 IdP 触发 OOM
            let body = read_limited_text(resp).await.unwrap_or_default();
            return Err(GarrisonError::Internal(format!(
                "sso-oidc-token-status-error::{}::{}",
                status, body
            )));
        }

        // E2：限制响应体大小（4 MiB），防止恶意 IdP 通过超大 token JSON 触发 OOM
        let bytes = read_limited_bytes(resp)
            .await
            .map_err(|e| GarrisonError::Internal(format!("sso-oidc-token-body-read::{}", e)))?;
        let token_response: TokenResponse = serde_json::from_slice(&bytes)
            .map_err(|e| GarrisonError::Internal(format!("sso-oidc-token-parse::{}", e)))?;

        let id_token = token_response
            .id_token
            .ok_or_else(|| GarrisonError::Internal("sso-oidc-missing-id-token".to_string()))?;

        // 返回前强制验签（protocol-sso 隐含 protocol-jwt）；未启用分支 fail-closed 拒绝，不静默放行。
        #[cfg(feature = "protocol-jwt")]
        {
            self.validate_id_token_impl(&id_token).await?;
        }
        #[cfg(not(feature = "protocol-jwt"))]
        {
            return Err(GarrisonError::Config(
                "sso-oidc-id-token-verification-unavailable::enable-protocol-jwt".to_string(),
            ));
        }

        Ok(id_token)
    }

    async fn get_user_info(&self, access_token: &str) -> GarrisonResult<OidcUserInfo> {
        let resp = self
            .http_client
            .get(&self.config.userinfo_endpoint)
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| GarrisonError::Internal(format!("sso-oidc-userinfo-request::{}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            // 错误响应体同样限 4 MiB，防恶意 IdP 触发 OOM
            let body = read_limited_text(resp).await.unwrap_or_default();
            return Err(GarrisonError::Internal(format!(
                "sso-oidc-userinfo-status-error::{}::{}",
                status, body
            )));
        }

        // E2：限制响应体大小（4 MiB），防止恶意 IdP 通过超大 userinfo JSON 触发 OOM
        let bytes = read_limited_bytes(resp)
            .await
            .map_err(|e| GarrisonError::Internal(format!("sso-oidc-userinfo-body-read::{}", e)))?;
        serde_json::from_slice::<OidcUserInfo>(&bytes)
            .map_err(|e| GarrisonError::Internal(format!("sso-oidc-userinfo-parse::{}", e)))
    }

    async fn validate_id_token(&self, id_token: &str) -> GarrisonResult<bool> {
        // 启用 protocol-jwt 时执行 JWKS 验签 + iss/aud/exp 校验；未启用返回 NotImplemented（纵深防御分支）。
        #[cfg(feature = "protocol-jwt")]
        {
            return self.validate_id_token_impl(id_token).await;
        }
        #[cfg(not(feature = "protocol-jwt"))]
        {
            let _ = id_token;
            Err(GarrisonError::NotImplemented(
                "sso-oidc-validate-not-implemented".to_string(),
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

// 辅助类型和函数

/// OIDC token 端点响应（内部使用）。
#[derive(Debug, Deserialize)]
struct TokenResponse {
    id_token: Option<String>,
    #[allow(
        dead_code,
        reason = "OAuth2 标准字段：当前仅用 id_token，access_token 预留供 protocol-jwt 扩展"
    )]
    access_token: Option<String>,
    #[allow(dead_code, reason = "OAuth2 标准字段：预留 token_type 供后续扩展")]
    token_type: Option<String>,
    #[allow(dead_code, reason = "OAuth2 标准字段：预留 expires_in 供后续扩展")]
    expires_in: Option<i64>,
}

/// URL 百分号编码（保留 `-_.~`），委托 `percent-encoding`，与 `protocol::oauth2::client::url_encode` 一致。
fn url_encode(s: &str) -> String {
    utf8_percent_encode(s, URLENCODE_SET).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::InMemoryDao;

    // 数据结构测试

    /// OidcDiscoveryConfig 序列化/反序列化往返。
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

    /// OidcUserInfo 序列化/反序列化往返。
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

    /// 可选 claims 缺失时仍可反序列化（真实 IdP 按 scope 省略 email/name/preferred_username/picture，缺失不得导致解析失败）。
    #[test]
    fn oidc_user_info_missing_optional_claims_deserializes() {
        // 仅含必需的 sub（真实 IdP 常见最小响应）
        let deserialized: OidcUserInfo =
            serde_json::from_str(r#"{"sub":"sub-only"}"#).expect("仅 sub 应可反序列化");
        assert_eq!(deserialized.sub, "sub-only");
        assert_eq!(deserialized.email, "", "缺失的可选 claim 应为空字符串");
        assert_eq!(deserialized.name, "");
        assert_eq!(deserialized.preferred_username, "");
        assert_eq!(deserialized.picture, "");

        // 缺 sub 仍应失败（必需 claim 不能静默为空）
        assert!(
            serde_json::from_str::<OidcUserInfo>(r#"{"email":"a@b.com"}"#).is_err(),
            "缺失必需的 sub 应反序列化失败"
        );
    }

    /// OidcDiscoveryConfig 实现 Clone + Debug（验收标准）。
    #[test]
    fn oidc_discovery_config_implements_clone_debug() {
        let config = make_test_config();
        let cloned = config.clone();
        assert_eq!(cloned.issuer, config.issuer);
        let debug_str = format!("{:?}", config);
        assert!(debug_str.contains("OidcDiscoveryConfig"));
    }

    /// OidcUserInfo 实现 Clone + Debug（验收标准）。
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

    // DefaultOidcProvider 构造测试

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

    /// DefaultOidcProvider::new 返回实例（验收标准）。
    #[test]
    fn default_oidc_provider_new_returns_instance() {
        let config = make_test_config();
        let provider = DefaultOidcProvider::new(config, "client-id", "client-secret").unwrap();
        assert_eq!(provider.client_id, "client-id");
        assert_eq!(provider.client_secret, "client-secret");
    }

    /// 构造期拒绝公网明文 http 端点（token 端点携带 client_secret，明文可被中间人窃取）。
    #[test]
    fn new_rejects_plaintext_http_endpoint() {
        let mut config = make_test_config();
        config.token_endpoint = "http://idp.example.com/token".to_string();
        let result = DefaultOidcProvider::new(config, "cid", "secret");
        match result {
            Err(GarrisonError::Config(msg)) => {
                assert!(
                    msg.contains("token_endpoint"),
                    "错误应指明 token_endpoint，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 Config，实际: {:?}", other),
            Ok(_) => panic!("公网明文 http token_endpoint 应被构造期拒绝"),
        }
    }

    /// localhost/127.0.0.1 的 http 端点放行（开发/测试场景，与 redirect_uri 约定一致）。
    #[test]
    fn new_allows_localhost_http_endpoints() {
        let mut config = make_test_config();
        config.authorization_endpoint = "http://127.0.0.1:9000/authorize".to_string();
        config.token_endpoint = "http://localhost:9000/token".to_string();
        let result = DefaultOidcProvider::new(config, "cid", "secret");
        assert!(
            result.is_ok(),
            "localhost http 端点应放行，实际: {:?}",
            result.err()
        );
    }

    /// OidcProvider trait 编译验证：DefaultOidcProvider 实现 OidcProvider trait。
    #[test]
    fn default_oidc_provider_implements_oidc_provider() {
        fn assert_oidc_provider<T: OidcProvider>(_provider: &T) {}
        let config = make_test_config();
        let provider = DefaultOidcProvider::new(config, "id", "secret").unwrap();
        assert_oidc_provider(&provider);
    }

    // get_authorization_url 测试

    /// get_authorization_url 构造正确 URL。
    #[tokio::test]
    async fn get_authorization_url_constructs_valid_url() {
        let config = make_test_config();
        let provider = DefaultOidcProvider::new(config, "test-client-id", "secret")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
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
        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
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
        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
        let url = provider
            .get_authorization_url("https://cb.com/cb", "st", &[])
            .await
            .unwrap();
        assert!(url.contains("scope="));
    }

    // validate_id_token 测试

    /// validate_id_token 返回 NotImplemented（JWT 验证需 protocol-jwt feature；启用时走 JWKS 验签，由 `validate_id_token_rejects_*` 系列覆盖）。
    #[cfg(not(feature = "protocol-jwt"))]
    #[tokio::test]
    async fn validate_id_token_returns_not_implemented() {
        let config = make_test_config();
        let provider = DefaultOidcProvider::new(config, "id", "secret").unwrap();
        let result = provider.validate_id_token("fake.jwt.token").await;
        assert!(result.is_err());
        match result.err() {
            Some(GarrisonError::NotImplemented(_)) => {},
            other => panic!("期望 NotImplemented 错误，实际: {:?}", other),
        }
    }

    // exchange_code / get_user_info 测试（使用 wiremock mock server）

    /// exchange_code 成功返回 id_token（protocol-sso 隐含 protocol-jwt，需 mock JWKS + 真实 RSA 签发的 JWT，始终走验签路径）。
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

        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
        // 先注册 state，再交换授权码
        provider
            .get_authorization_url(
                "https://sp.example.com/callback",
                "state-test-1",
                &["openid"],
            )
            .await
            .unwrap();
        let returned_id_token = provider
            .exchange_code(
                "auth-code-123",
                "https://sp.example.com/callback",
                "state-test-1",
            )
            .await
            .unwrap();
        assert_eq!(returned_id_token, id_token);
    }

    /// exchange_code 端点返回错误状态时返回 Internal 错误。
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

        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
        provider
            .get_authorization_url(
                "https://sp.example.com/callback",
                "state-test-2",
                &["openid"],
            )
            .await
            .unwrap();
        let result = provider
            .exchange_code(
                "bad-code",
                "https://sp.example.com/callback",
                "state-test-2",
            )
            .await;
        assert!(result.is_err());
    }

    /// exchange_code 响应缺少 id_token 时返回错误。
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

        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
        provider
            .get_authorization_url(
                "https://sp.example.com/callback",
                "state-test-3",
                &["openid"],
            )
            .await
            .unwrap();
        let result = provider
            .exchange_code(
                "auth-code",
                "https://sp.example.com/callback",
                "state-test-3",
            )
            .await;
        assert!(result.is_err());
    }

    /// get_user_info 成功返回用户信息。
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

        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
        let user_info = provider.get_user_info("access-token-123").await.unwrap();
        assert_eq!(user_info.sub, "user-123");
        assert_eq!(user_info.email, "user@example.com");
        assert_eq!(user_info.name, "Test User");
        assert_eq!(user_info.preferred_username, "testuser");
        assert_eq!(user_info.picture, "https://example.com/avatar.png");
    }

    /// get_user_info 端点返回错误状态时返回 Internal 错误。
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

        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
        let result = provider.get_user_info("bad-token").await;
        assert!(result.is_err());
    }

    // 辅助函数测试

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

    /// url_encode 必须编码百分号，否则已编码序列会被二次解码导致注入。
    /// "%" → "%25"，防止攻击者构造 "%26" 绕过 scope/redirect_uri 校验。
    #[test]
    fn url_encode_encodes_percent_sign() {
        assert_eq!(url_encode("%"), "%25");
        assert_eq!(url_encode("100%done"), "100%25done");
        // 已编码序列应被双重编码，防止解码后注入
        assert_eq!(url_encode("%26"), "%2526");
        assert_eq!(url_encode("%3D"), "%253D");
    }

    // validate_id_token JWKS 验签测试（wiremock JWKS 端点 + RSA 2048 测试密钥对；参考 keycloak 同名校验测试）

    /// 测试辅助：生成 RSA 2048 测试密钥对，返回 (EncodingKey, n_b64, e_b64)（n/e 为 base64url 无 padding，可直接构造 JWKS）。
    #[cfg(feature = "protocol-jwt")]
    fn make_test_rsa_key() -> (jsonwebtoken::EncodingKey, String, String) {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine;
        use jsonwebtoken::EncodingKey;
        use rsa::pkcs1::EncodeRsaPrivateKey;
        use rsa::traits::PublicKeyParts;
        use rsa::{RsaPrivateKey, RsaPublicKey};

        // rsa 0.9 基于 rand_core 0.6，rand 0.10 的 RNG trait 不兼容，用 rsa::rand_core::OsRng
        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("生成 RSA 私钥应成功");
        let public_key = RsaPublicKey::from(&private_key);
        let n_b64 = URL_SAFE_NO_PAD.encode(public_key.n().to_bytes_be());
        let e_b64 = URL_SAFE_NO_PAD.encode(public_key.e().to_bytes_be());
        // jsonwebtoken 10 的 EncodingKey::from_rsa_der 期望 PKCS#1 DER（非 PKCS#8）
        let der = private_key.to_pkcs1_der().expect("转 PKCS#1 DER 应成功");
        let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());
        (encoding_key, n_b64, e_b64)
    }

    /// 测试辅助：当前 Unix 时间戳（秒）。
    #[cfg(feature = "protocol-jwt")]
    fn now_unix() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("系统时间应早于 UNIX_EPOCH")
            .as_secs() as i64
    }

    /// 测试辅助：用 RSA 私钥签发 JWT（encoding_key / kid / iss / aud / exp）。
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

    /// 测试辅助：用 RSA 私钥签发 JWT，aud 接受任意 JSON Value（测试 aud 数组形式），其他参数同 [`sign_test_jwt`]。
    #[cfg(feature = "protocol-jwt")]
    fn sign_test_jwt_with_aud_value(
        encoding_key: &jsonwebtoken::EncodingKey,
        kid: &str,
        iss: &str,
        aud: serde_json::Value,
        exp: i64,
    ) -> String {
        use jsonwebtoken::{encode, Algorithm, Header};
        use serde::Serialize;

        #[derive(Serialize)]
        struct TestClaims {
            iss: String,
            aud: serde_json::Value,
            exp: i64,
            sub: String,
        }

        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(kid.to_string());
        let claims = TestClaims {
            iss: iss.to_string(),
            aud,
            exp,
            sub: "user-123".to_string(),
        };
        encode(&header, &claims, encoding_key).expect("签发 JWT 应成功")
    }

    /// 测试辅助：构造 JWKS JSON 响应体（单个 RSA 公钥）。
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

    /// 测试辅助：生成有效 id_token + 对应 JWKS JSON（iss/aud/exp 与 provider 配置匹配）。
    #[cfg(feature = "protocol-jwt")]
    fn make_valid_id_token(issuer: &str, client_id: &str) -> (String, serde_json::Value) {
        let (encoding_key, n_b64, e_b64) = make_test_rsa_key();
        // exp 设为当前时间 + 3600 秒（1 小时后过期，确保 validate_exp 通过）
        let id_token = sign_test_jwt(&encoding_key, "key1", issuer, client_id, now_unix() + 3600);
        let jwks_json = make_jwks_json("key1", &n_b64, &e_b64);
        (id_token, jwks_json)
    }

    /// 测试辅助：启动 mock server 并挂载 JWKS endpoint，返回 OidcDiscoveryConfig。
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

    #[cfg(feature = "protocol-jwt")]
    /// sanitize_kid 过滤控制字符并限长 128。
    #[test]
    fn sanitize_kid_filters_control_chars_and_limits_len() {
        assert_eq!(DefaultOidcProvider::sanitize_kid("abc123"), "abc123");
        assert_eq!(
            DefaultOidcProvider::sanitize_kid("bad\x01kid\x7f"),
            "badkid"
        );
        let long = "a".repeat(200);
        assert_eq!(DefaultOidcProvider::sanitize_kid(&long).len(), 128);
    }

    /// validate_id_token 拒绝无效签名的 JWT（JWKS 返回与签名私钥不匹配的公钥，覆盖 `decode` 失败分支）。
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

        let provider = DefaultOidcProvider::new(config, "client-id", "secret")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
        let result = provider.validate_id_token(&id_token).await;
        assert!(result.is_err(), "无效签名应返回错误");
        match result.err() {
            Some(GarrisonError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("sso-oidc-id-token-verify"),
                    "无效签名应返回验签失败消息，实际: {}",
                    msg
                );
            },
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    /// validate_id_token 拒绝过期 token（exp=now-3600 触发 ExpiredSignature，映射 InvalidToken）。
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

        let provider = DefaultOidcProvider::new(config, "client-id", "secret")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
        let result = provider.validate_id_token(&id_token).await;
        assert!(result.is_err(), "过期 token 应返回错误");
        match result.err() {
            Some(GarrisonError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("过期") || msg.contains("expired"),
                    "过期 token 应返回过期相关消息，实际: {}",
                    msg
                );
            },
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    /// validate_id_token 拒绝 iss 不匹配的 token（验签通过但 iss 校验失败）。
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

        let provider = DefaultOidcProvider::new(config, "client-id", "secret")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
        let result = provider.validate_id_token(&id_token).await;
        assert!(result.is_err(), "iss 不匹配应返回错误");
        match result.err() {
            Some(GarrisonError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("iss"),
                    "iss 不匹配应返回 iss 相关消息，实际: {}",
                    msg
                );
            },
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    /// validate_id_token 拒绝 aud 不匹配的 token（验签通过但 aud 校验失败）。
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

        let provider = DefaultOidcProvider::new(config, "client-id", "secret")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
        let result = provider.validate_id_token(&id_token).await;
        assert!(result.is_err(), "aud 不匹配应返回错误");
        match result.err() {
            Some(GarrisonError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("sso-oidc-id-token-invalid"),
                    "aud 不匹配应返回 aud 相关消息，实际: {}",
                    msg
                );
            },
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    /// validate_id_token 接受 aud 为数组（含 client_id）的 token：RFC 7519 §4.1.3 允许数组形式，
    /// 真实 IdP（Keycloak/Auth0）常签发 `["client-id", "account"]`，Aud enum（untagged）兼容两种形式。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn validate_id_token_accepts_aud_array_containing_client_id() {
        let (encoding_key, n_b64, e_b64) = make_test_rsa_key();
        let jwks_json = make_jwks_json("key1", &n_b64, &e_b64);
        let (_server, config) = setup_jwks_mock_server(jwks_json).await;

        // aud 为数组形式，包含 client_id "client-id" 和 "account"
        let id_token = sign_test_jwt_with_aud_value(
            &encoding_key,
            "key1",
            &config.issuer,
            serde_json::json!(["client-id", "account"]),
            now_unix() + 3600,
        );

        let provider = DefaultOidcProvider::new(config, "client-id", "secret")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
        let result = provider.validate_id_token(&id_token).await;
        assert!(
            result.is_ok(),
            "aud 为数组含 client_id 时应校验通过（H3），实际: {:?}",
            result
        );
        assert!(result.unwrap());
    }

    /// validate_id_token 拒绝 aud 为数组但不含 client_id 的 token（contains 返回 false → InvalidToken）。
    #[cfg(feature = "protocol-jwt")]
    #[tokio::test]
    async fn validate_id_token_rejects_aud_array_without_client_id() {
        let (encoding_key, n_b64, e_b64) = make_test_rsa_key();
        let jwks_json = make_jwks_json("key1", &n_b64, &e_b64);
        let (_server, config) = setup_jwks_mock_server(jwks_json).await;

        // aud 为数组形式，但不含 client_id "client-id"
        let id_token = sign_test_jwt_with_aud_value(
            &encoding_key,
            "key1",
            &config.issuer,
            serde_json::json!(["other-client", "account"]),
            now_unix() + 3600,
        );

        let provider = DefaultOidcProvider::new(config, "client-id", "secret")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
        let result = provider.validate_id_token(&id_token).await;
        assert!(result.is_err(), "aud 数组不含 client_id 时应返回错误");
        match result.err() {
            Some(GarrisonError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("sso-oidc-id-token-invalid"),
                    "aud 不匹配应返回 aud 相关消息，实际: {}",
                    msg
                );
            },
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    /// exchange_code 在返回前调用 validate_id_token：mock 的 id_token 签名与 JWKS 公钥不匹配时应失败。
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

        let provider = DefaultOidcProvider::new(config, "cid", "secret")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
        provider
            .get_authorization_url(
                "https://sp.example.com/callback",
                "state-jwt-test",
                &["openid"],
            )
            .await
            .unwrap();
        let result = provider
            .exchange_code(
                "auth-code-123",
                "https://sp.example.com/callback",
                "state-jwt-test",
            )
            .await;
        assert!(
            result.is_err(),
            "exchange_code 应在 validate_id_token 失败时返回错误"
        );
        match result.err() {
            Some(GarrisonError::InvalidToken(msg)) => {
                assert!(
                    msg.contains("sso-oidc-id-token-verify"),
                    "exchange_code 应传递验签失败错误，实际: {}",
                    msg
                );
            },
            other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
        }
    }

    // OIDC state 参数验证测试

    /// exchange_code 拒绝未注册的 state（攻击者绕过 get_authorization_url 直接调用 → InvalidParam，CSRF 防护）。
    #[tokio::test]
    async fn exchange_code_rejects_unregistered_state() {
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

        // mock token endpoint（不应被调用，因为 state 校验会先失败）
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_token": "fake-token",
                "access_token": "access",
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .mount(&mock_server)
            .await;

        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
        // 未注册 state 直接调用 exchange_code
        let result = provider
            .exchange_code("code", "https://sp.example.com/cb", "unregistered-state")
            .await;
        assert!(result.is_err(), "未注册的 state 应被拒绝");
        match result.err() {
            Some(GarrisonError::InvalidParam(msg)) => {
                assert!(msg.contains("state"), "错误消息应提及 state，实际: {}", msg);
            },
            other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
        }
    }

    /// exchange_code 拒绝不匹配的 state（注册 "abc" 却传 "xyz" → InvalidParam）。
    #[tokio::test]
    async fn exchange_code_rejects_mismatched_state() {
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
                "id_token": "fake-token",
                "access_token": "access",
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .mount(&mock_server)
            .await;

        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
        provider
            .get_authorization_url("https://sp.example.com/cb", "abc", &["openid"])
            .await
            .unwrap();
        let result = provider
            .exchange_code("code", "https://sp.example.com/cb", "xyz")
            .await;
        assert!(result.is_err(), "不匹配的 state 应被拒绝");
        match result.err() {
            Some(GarrisonError::InvalidParam(_)) => {},
            other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
        }
    }

    /// state 为 one-time use：截获合法 state 重放时第一次成功、第二次失败（已被消费）。
    #[tokio::test]
    async fn exchange_code_state_is_one_time_use() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let issuer = "https://idp.example.com".to_string();

        #[cfg(feature = "protocol-jwt")]
        let (id_token, jwks_json) = make_valid_id_token(&issuer, "cid");
        #[cfg(not(feature = "protocol-jwt"))]
        let id_token: String = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzIn0.signature".to_string(); // nosemgrep

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

        // mock token endpoint，期望被调用一次
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "id_token": id_token,
                "access_token": "access-123",
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .up_to_n_times(1)
            .mount(&mock_server)
            .await;

        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
        provider
            .get_authorization_url("https://sp.example.com/cb", "one-time-state", &["openid"])
            .await
            .unwrap();
        let first = provider
            .exchange_code("code", "https://sp.example.com/cb", "one-time-state")
            .await;
        assert!(first.is_ok(), "首次使用 state 应成功");
        let second = provider
            .exchange_code("code", "https://sp.example.com/cb", "one-time-state")
            .await;
        assert!(second.is_err(), "重用 state 应被拒绝（one-time use）");
        match second.err() {
            Some(GarrisonError::InvalidParam(_)) => {},
            other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
        }
    }

    /// state 过期后应被拒绝：用 1 秒 TTL（受 `ttl_seconds: u64` 秒级精度限制）注册后等待过期，
    /// oxcache 自动管理 TTL，Provider 层不负责清理。
    #[tokio::test]
    async fn exchange_code_rejects_expired_state() {
        use std::thread::sleep;
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
                "id_token": "fake-token",
                "access_token": "access",
                "token_type": "Bearer",
                "expires_in": 3600
            })))
            .mount(&mock_server)
            .await;

        // 使用 1 秒 TTL（GarrisonDao::set 的 ttl_seconds: u64 最小粒度为秒）
        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()))
            .with_state_ttl(Duration::from_secs(1));
        provider
            .get_authorization_url("https://sp.example.com/cb", "expiring-state", &["openid"])
            .await
            .unwrap();
        // 等待 state 过期（阻塞 1.1 秒确保 TTL 到期）
        sleep(Duration::from_millis(1100));
        let result = provider
            .exchange_code("code", "https://sp.example.com/cb", "expiring-state")
            .await;
        assert!(result.is_err(), "过期的 state 应被拒绝");
        match result.err() {
            Some(GarrisonError::InvalidParam(msg)) => {
                assert!(
                    msg.contains("sso-oidc-state-mismatch-or-expired"),
                    "错误消息应提及过期，实际: {}",
                    msg
                );
            },
            other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
        }
    }

    /// 连续注册多个 state 均成功且各自写入 DAO（容量与 TTL 由 oxcache 自管理）。
    #[tokio::test]
    async fn state_registration_allows_multiple_entries() {
        let dao = Arc::new(InMemoryDao::new());
        let config = OidcDiscoveryConfig {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: "https://idp.example.com/token".to_string(),
            userinfo_endpoint: "https://idp.example.com/userinfo".to_string(),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
        };

        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(dao.clone());
        for state in ["state-1", "state-2", "state-3"] {
            provider
                .get_authorization_url("https://cb.com/cb", state, &["openid"])
                .await
                .unwrap();
            assert!(
                dao.get(&DefaultOidcProvider::state_cache_key(state))
                    .await
                    .unwrap()
                    .is_some(),
                "state {} 应已写入 DAO",
                state
            );
        }
    }

    /// get_authorization_url 将 state 注册到 DAO（key `oidc:state:{state}`，TTL 由 oxcache 管理；同一 state 重复注册覆盖写入不报错）。
    #[tokio::test]
    async fn get_authorization_url_registers_state() {
        let dao = Arc::new(InMemoryDao::new());
        let config = OidcDiscoveryConfig {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: "https://idp.example.com/token".to_string(),
            userinfo_endpoint: "https://idp.example.com/userinfo".to_string(),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
        };
        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(dao.clone());
        provider
            .get_authorization_url("https://cb.com/cb", "first-state", &["openid"])
            .await
            .unwrap();
        assert!(
            dao.get(&DefaultOidcProvider::state_cache_key("first-state"))
                .await
                .unwrap()
                .is_some(),
            "first-state 应已写入 DAO"
        );
        provider
            .get_authorization_url("https://cb.com/cb", "second-state", &["openid"])
            .await
            .unwrap();
        assert!(
            dao.get(&DefaultOidcProvider::state_cache_key("second-state"))
                .await
                .unwrap()
                .is_some(),
            "second-state 应已写入 DAO"
        );
        // 同一 state 重复注册不报错（DAO 覆盖写入）
        provider
            .get_authorization_url("https://cb.com/cb", "first-state", &["openid"])
            .await
            .unwrap();
    }

    // E1 + E2 测试：HTTP 客户端超时（connect=10s / read=30s）与响应体 4 MiB 上限（防 slowloris / OOM）

    /// E1：`build_safe_http_client` 返回有效客户端（含 connect/read 超时配置）。
    #[test]
    fn e1_build_safe_http_client_returns_valid_client() {
        let client = build_safe_http_client();
        assert!(client.is_ok(), "build_safe_http_client 应返回 Ok(Client)");
    }

    /// E1：超时常量与规格匹配（connect=10s, read=30s）。
    #[test]
    fn e1_timeout_constants_match_spec() {
        assert_eq!(HTTP_CONNECT_TIMEOUT, Duration::from_secs(10));
        assert_eq!(HTTP_READ_TIMEOUT, Duration::from_secs(30));
    }

    /// E1：`DefaultOidcProvider::new` 成功构造（HTTP 客户端构建不应失败）。
    #[test]
    fn e1_default_oidc_provider_new_succeeds() {
        let config = make_test_config();
        let result = DefaultOidcProvider::new(config, "cid", "cs");
        assert!(result.is_ok(), "DefaultOidcProvider::new 应返回 Ok");
    }

    /// E2：`MAX_BODY_BYTES` 常量等于 4 MiB。
    #[test]
    fn e2_max_body_bytes_is_4_mib() {
        assert_eq!(MAX_BODY_BYTES, 4 * 1024 * 1024);
    }

    /// E2：`read_limited_bytes` 接受小响应（< 4 MiB）。
    #[tokio::test]
    async fn e2_read_limited_bytes_accepts_small_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/small"))
            .respond_with(ResponseTemplate::new(200).set_body_string("hello"))
            .mount(&mock_server)
            .await;

        let client = build_safe_http_client().unwrap();
        let resp = client
            .get(format!("{}/small", mock_server.uri()))
            .send()
            .await
            .unwrap();
        let bytes = read_limited_bytes(resp).await.unwrap();
        assert_eq!(bytes, b"hello");
    }

    /// E2：`read_limited_bytes` 接受恰好等于上限的响应（4 MiB，边界值）。
    #[tokio::test]
    async fn e2_read_limited_bytes_accepts_exact_limit() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let body = "x".repeat(MAX_BODY_BYTES);
        Mock::given(method("GET"))
            .and(path("/exact"))
            .respond_with(ResponseTemplate::new(200).set_body_string(body.clone()))
            .mount(&mock_server)
            .await;

        let client = build_safe_http_client().unwrap();
        let resp = client
            .get(format!("{}/exact", mock_server.uri()))
            .send()
            .await
            .unwrap();
        let bytes = read_limited_bytes(resp).await.unwrap();
        assert_eq!(bytes.len(), MAX_BODY_BYTES);
    }

    /// E2：`read_limited_bytes` 拒绝超过 4 MiB 的响应（返回 Network 错误）。
    #[tokio::test]
    async fn e2_read_limited_bytes_rejects_oversized_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        // 5 MiB 超过 4 MiB 上限
        let oversized_body = "x".repeat(MAX_BODY_BYTES + 1024 * 1024);
        Mock::given(method("GET"))
            .and(path("/oversized"))
            .respond_with(ResponseTemplate::new(200).set_body_string(oversized_body))
            .mount(&mock_server)
            .await;

        let client = build_safe_http_client().unwrap();
        let resp = client
            .get(format!("{}/oversized", mock_server.uri()))
            .send()
            .await
            .unwrap();
        let result = read_limited_bytes(resp).await;
        assert!(result.is_err(), "超大响应应返回错误");
        match result.err() {
            Some(GarrisonError::Network(msg)) => {
                assert!(
                    msg.contains("sso-oidc-body-exceeds-limit")
                        || msg.contains("sso-oidc-body-overflow"),
                    "错误消息应提及上限/E2，实际: {}",
                    msg
                );
            },
            other => panic!("期望 Network 错误，实际: {:?}", other),
        }
    }

    /// E2：`read_limited_text` 正确解码 UTF-8 字符串。
    #[tokio::test]
    async fn e2_read_limited_text_decodes_utf8() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/text"))
            .respond_with(ResponseTemplate::new(200).set_body_string("hello 你好"))
            .mount(&mock_server)
            .await;

        let client = build_safe_http_client().unwrap();
        let resp = client
            .get(format!("{}/text", mock_server.uri()))
            .send()
            .await
            .unwrap();
        let text = read_limited_text(resp).await.unwrap();
        assert_eq!(text, "hello 你好");
    }

    /// E2：`get_user_info` 拒绝超过 4 MiB 的 userinfo 响应（read_limited_bytes 报 Network 后包装为 Internal）。
    #[tokio::test]
    async fn e2_get_user_info_rejects_oversized_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let oversized_body = "x".repeat(MAX_BODY_BYTES + 1024 * 1024);
        Mock::given(method("GET"))
            .and(path("/userinfo"))
            .respond_with(ResponseTemplate::new(200).set_body_string(oversized_body))
            .mount(&mock_server)
            .await;

        let config = OidcDiscoveryConfig {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: format!("{}/token", mock_server.uri()),
            userinfo_endpoint: format!("{}/userinfo", mock_server.uri()),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
        };
        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
        let result = provider.get_user_info("access-token").await;
        assert!(result.is_err(), "超大 userinfo 响应应返回错误");
    }

    /// E2：`exchange_code` 拒绝超过 4 MiB 的 token 响应（mock 返回 5 MiB body → Internal 错误）。
    #[tokio::test]
    async fn e2_exchange_code_rejects_oversized_token_response() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let mock_server = MockServer::start().await;
        let oversized_body = "x".repeat(MAX_BODY_BYTES + 1024 * 1024);
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_string(oversized_body))
            .mount(&mock_server)
            .await;

        let config = OidcDiscoveryConfig {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: format!("{}/token", mock_server.uri()),
            userinfo_endpoint: format!("{}/userinfo", mock_server.uri()),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
        };
        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));
        provider
            .get_authorization_url("https://sp.example.com/cb", "state-e2", &["openid"])
            .await
            .unwrap();
        let result = provider
            .exchange_code("code", "https://sp.example.com/cb", "state-e2")
            .await;
        assert!(result.is_err(), "超大 token 响应应返回错误");
    }

    // validate_endpoint_scheme 边界测试

    /// validate_endpoint_scheme: https URL 始终放行。
    #[test]
    fn validate_endpoint_scheme_allows_https() {
        assert!(
            validate_endpoint_scheme("https://idp.example.com/authorize", "test_field").is_ok()
        );
        assert!(validate_endpoint_scheme("https://127.0.0.1:8443/token", "test_field").is_ok());
        assert!(validate_endpoint_scheme("https://localhost/callback", "test_field").is_ok());
    }

    /// validate_endpoint_scheme: http + localhost/127.0.0.1 放行（开发场景）。
    #[test]
    fn validate_endpoint_scheme_allows_localhost_http() {
        assert!(validate_endpoint_scheme("http://localhost:8080/token", "f").is_ok());
        assert!(validate_endpoint_scheme("http://127.0.0.1/token", "f").is_ok());
        assert!(validate_endpoint_scheme("http://localhost/authorize", "f").is_ok());
    }

    /// validate_endpoint_scheme: http + 非 localhost 拒绝。
    #[test]
    fn validate_endpoint_scheme_rejects_public_http() {
        assert!(validate_endpoint_scheme("http://idp.example.com/token", "f").is_err());
        assert!(validate_endpoint_scheme("http://192.168.1.1/token", "f").is_err());
        assert!(validate_endpoint_scheme("http://10.0.0.1:443/token", "f").is_err());
    }

    /// validate_endpoint_scheme: 无 scheme / 未知 scheme / 空字符串拒绝。
    #[test]
    fn validate_endpoint_scheme_rejects_missing_or_unknown_scheme() {
        assert!(validate_endpoint_scheme("idp.example.com/token", "f").is_err());
        assert!(validate_endpoint_scheme("ftp://idp.example.com/token", "f").is_err());
        assert!(validate_endpoint_scheme("", "f").is_err());
    }

    /// validate_endpoint_scheme: 错误信息包含字段名和 URL。
    #[test]
    fn validate_endpoint_scheme_error_contains_field_and_url() {
        let err = validate_endpoint_scheme("http://evil.com/token", "token_endpoint").unwrap_err();
        match err {
            GarrisonError::Config(msg) => {
                assert!(msg.contains("token_endpoint"), "应含字段名: {}", msg);
                assert!(msg.contains("http://evil.com/token"), "应含 URL: {}", msg);
            },
            other => panic!("期望 Config 错误，实际: {:?}", other),
        }
    }

    // state_cache_key / jwks_cache_key 测试

    /// state_cache_key 格式为 `oidc:state:{state}`。
    #[test]
    fn state_cache_key_format() {
        let key = DefaultOidcProvider::state_cache_key("abc123");
        assert_eq!(key, "oidc:state:abc123");
    }

    /// state_cache_key 不同 state 生成不同 key。
    #[test]
    fn state_cache_key_unique_per_state() {
        let k1 = DefaultOidcProvider::state_cache_key("state-1");
        let k2 = DefaultOidcProvider::state_cache_key("state-2");
        assert_ne!(k1, k2);
    }

    /// jwks_cache_key 格式为 `oidc:jwks:{issuer}`。
    #[cfg(feature = "protocol-jwt")]
    #[test]
    fn jwks_cache_key_format() {
        let config = make_test_config();
        let provider = DefaultOidcProvider::new(config, "cid", "cs").unwrap();
        let key = provider.jwks_cache_key();
        assert_eq!(key, "oidc:jwks:https://idp.example.com");
    }

    // with_state_ttl 测试

    /// with_state_ttl 修改 state TTL 后 state 过期行为正确。
    #[tokio::test]
    async fn with_state_ttl_state_expires_after_ttl() {
        let config = make_test_config();
        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()))
            .with_state_ttl(Duration::from_millis(50));

        provider
            .get_authorization_url("https://sp.example.com/cb", "state-ttl-test", &["openid"])
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(100)).await;

        // exchange_code 应因 state 过期失败
        let result = provider
            .exchange_code("code", "https://sp.example.com/cb", "state-ttl-test")
            .await;
        assert!(result.is_err(), "state 过期后 exchange_code 应失败");
    }

    // register_state / validate_and_consume_state 测试

    /// register_state 写入 DAO 后 validate_and_consume_state 消费成功（one-time use）。
    #[tokio::test]
    async fn register_and_consume_state_roundtrip() {
        let config = make_test_config();
        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));

        provider.register_state("test-state-001").await.unwrap();

        provider
            .validate_and_consume_state("test-state-001")
            .await
            .unwrap();

        // 再次消费应失败（one-time use）
        let result = provider.validate_and_consume_state("test-state-001").await;
        assert!(result.is_err(), "state 应只能消费一次");
    }

    /// register_state 未注入 DAO 时返回 Config 错误。
    #[tokio::test]
    async fn register_state_without_dao_returns_error() {
        let config = make_test_config();
        let provider = DefaultOidcProvider::new(config, "cid", "cs").unwrap();
        // 不调用 with_dao
        let result = provider.register_state("test-state-002").await;
        assert!(result.is_err(), "未注入 DAO 时 register_state 应失败");
    }

    /// validate_and_consume_state 对未注册的 state 返回错误。
    #[tokio::test]
    async fn consume_unregistered_state_returns_error() {
        let config = make_test_config();
        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(InMemoryDao::new()));

        let result = provider
            .validate_and_consume_state("never-registered")
            .await;
        assert!(result.is_err(), "未注册的 state 应返回错误");
    }

    // sanitize_kid 边界测试

    /// sanitize_kid 空字符串返回空字符串。
    #[test]
    fn sanitize_kid_empty_string() {
        assert_eq!(DefaultOidcProvider::sanitize_kid(""), "");
    }

    /// sanitize_kid 超长 kid 截断至限制长度。
    #[test]
    fn sanitize_kid_truncates_long_input() {
        let long_kid = "a".repeat(1000);
        let sanitized = DefaultOidcProvider::sanitize_kid(&long_kid);
        assert!(sanitized.len() <= 256, "sanitize_kid 应限制长度");
    }

    /// sanitize_kid 过滤控制字符。
    #[test]
    fn sanitize_kid_filters_control_chars() {
        let kid_with_control = "valid\x00\x01\x1Fkid";
        let sanitized = DefaultOidcProvider::sanitize_kid(kid_with_control);
        assert!(!sanitized.contains('\x00'));
        assert!(!sanitized.contains('\x01'));
        assert!(sanitized.contains("valid"));
        assert!(sanitized.contains("kid"));
    }

    // OidcDiscoveryConfig Clone + Default 边界测试

    /// OidcDiscoveryConfig 各字段为空字符串时 new 不报错。
    #[test]
    fn new_with_empty_strings_in_config_fails_scheme_validation() {
        let config = OidcDiscoveryConfig {
            issuer: "".to_string(),
            authorization_endpoint: "".to_string(),
            token_endpoint: "".to_string(),
            userinfo_endpoint: "".to_string(),
            jwks_uri: "".to_string(),
        };
        // 空字符串无 :// → validate_endpoint_scheme 应拒绝
        let result = DefaultOidcProvider::new(config, "cid", "cs");
        assert!(result.is_err(), "空端点 URL 应被拒绝");
    }

    // build_safe_http_client / validate_endpoint_scheme 覆盖率补充

    /// `build_safe_http_client` 构造成功（reqwest Client builder 正常返回）。
    #[test]
    fn build_safe_http_client_succeeds() {
        let client = build_safe_http_client();
        assert!(
            client.is_ok(),
            "build_safe_http_client 应成功: {:?}",
            client.err()
        );
    }

    /// `validate_endpoint_scheme`: https 任意 host 通过。
    #[test]
    fn validate_endpoint_scheme_https_any_host_ok() {
        assert!(validate_endpoint_scheme("https://accounts.google.com/oauth", "test").is_ok());
        assert!(validate_endpoint_scheme("https://idp.example.com:8443/oidc", "test").is_ok());
    }

    /// `validate_endpoint_scheme`: http + localhost 通过（开发场景）。
    #[test]
    fn validate_endpoint_scheme_http_localhost_ok() {
        assert!(validate_endpoint_scheme("http://localhost/oauth", "test").is_ok());
        assert!(validate_endpoint_scheme("http://localhost:8080/oauth", "test").is_ok());
    }

    /// `validate_endpoint_scheme`: http + 127.0.0.1 通过（开发场景）。
    #[test]
    fn validate_endpoint_scheme_http_127_ok() {
        assert!(validate_endpoint_scheme("http://127.0.0.1/oauth", "test").is_ok());
        assert!(validate_endpoint_scheme("http://127.0.0.1:3000/oidc", "test").is_ok());
    }

    /// `validate_endpoint_scheme`: http + 非本机 host 拒绝。
    #[test]
    fn validate_endpoint_scheme_http_public_host_rejected() {
        let result = validate_endpoint_scheme("http://idp.example.com/oauth", "test");
        assert!(result.is_err(), "http + 公共 host 应被拒绝");
    }

    /// `validate_endpoint_scheme`: 无 scheme 拒绝。
    #[test]
    fn validate_endpoint_scheme_no_scheme_rejected() {
        let result = validate_endpoint_scheme("idp.example.com/oauth", "test");
        assert!(result.is_err(), "无 scheme 应被拒绝");
    }

    /// `validate_endpoint_scheme`: ftp 等非法 scheme 拒绝。
    #[test]
    fn validate_endpoint_scheme_ftp_rejected() {
        let result = validate_endpoint_scheme("ftp://idp.example.com/oauth", "test");
        assert!(result.is_err(), "ftp scheme 应被拒绝");
    }

    /// `DefaultOidcProvider::new` 所有端点为 https 时构造成功（覆盖 build_safe_http_client 调用路径）。
    #[test]
    fn new_with_valid_https_endpoints_succeeds() {
        let config = OidcDiscoveryConfig {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/auth".to_string(),
            token_endpoint: "https://idp.example.com/token".to_string(),
            userinfo_endpoint: "https://idp.example.com/userinfo".to_string(),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
        };
        let result = DefaultOidcProvider::new(config, "client_id", "client_secret");
        assert!(
            result.is_ok(),
            "有效 https 端点应构造成功: {:?}",
            result.err()
        );
    }

    /// `DefaultOidcProvider::new` 端点为 http+localhost 时构造成功。
    #[test]
    fn new_with_http_localhost_endpoints_succeeds() {
        let config = OidcDiscoveryConfig {
            issuer: "http://localhost:8080".to_string(),
            authorization_endpoint: "http://localhost:8080/auth".to_string(),
            token_endpoint: "http://localhost:8080/token".to_string(),
            userinfo_endpoint: "http://localhost:8080/userinfo".to_string(),
            jwks_uri: "http://localhost:8080/jwks".to_string(),
        };
        let result = DefaultOidcProvider::new(config, "cid", "cs");
        assert!(
            result.is_ok(),
            "http+localhost 端点应构造成功: {:?}",
            result.err()
        );
    }
}
