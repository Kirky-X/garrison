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
//! - `validate_id_token`：JWKS 验签（RS256）+ iss/aud/exp 校验（需 `protocol-jwt` feature）；
//!   未启用 feature 时返回 `NotImplemented`
//!
//! 与 `protocol::oauth2::oidc::OidcHandler` 的区别：
//! - `OidcHandler`：Bulwark 作为 IdP 签发/验证 id_token
//! - `OidcProvider` trait：Bulwark 作为 RP 与外部 IdP 交互
//!
//! 仅在启用 `protocol-sso` 特性时编译。`protocol-jwt` 特性启用后 `exchange_code`
//! 在返回前自动调用 `validate_id_token`，未启用时保持向后兼容行为。

use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use async_trait::async_trait;
use percent_encoding::{utf8_percent_encode, AsciiSet, NON_ALPHANUMERIC};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

/// HTTP 客户端安全默认配置（E1，protocol-sso 本地副本）。
///
/// `protocol-sso` feature 不依赖 `protocol-oauth2`，无法复用
/// `crate::protocol::oauth2::client::build_safe_http_client`。
/// 此处维护等价实现，避免引入跨 feature 强耦合。
/// 与 `protocol::oauth2::client::HTTP_CONNECT_TIMEOUT` / `HTTP_READ_TIMEOUT` 保持同值。
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HTTP_READ_TIMEOUT: Duration = Duration::from_secs(30);

/// HTTP 响应体大小上限（E2，protocol-sso 本地副本）：4 MiB。
///
/// 与 `protocol::oauth2::client::MAX_BODY_BYTES` 保持同值。
const MAX_BODY_BYTES: usize = 4 * 1024 * 1024;

/// 构造带超时配置的 `reqwest::Client`（E1 修复，protocol-sso 本地副本）。
fn build_safe_http_client() -> BulwarkResult<reqwest::Client> {
    reqwest::Client::builder()
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .read_timeout(HTTP_READ_TIMEOUT)
        .build()
        .map_err(|e| BulwarkError::Network(format!("构建 HTTP 客户端失败: {}", e)))
}

/// 读取响应体并强制大小上限（E2 修复，protocol-sso 本地副本）。
///
/// 使用 `resp.chunk()` 流式累积，超过 [`MAX_BODY_BYTES`] 立即中断返回 Err。
async fn read_limited_bytes(resp: reqwest::Response) -> BulwarkResult<Vec<u8>> {
    let mut buf: Vec<u8> = Vec::new();
    let mut resp = resp;
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| BulwarkError::Network(format!("读取响应体失败: {}", e)))?
    {
        let new_len = buf
            .len()
            .checked_add(chunk.len())
            .ok_or_else(|| BulwarkError::Network("响应体长度溢出 usize（E2）".to_string()))?;
        if new_len > MAX_BODY_BYTES {
            return Err(BulwarkError::Network(format!(
                "响应体超过 {} 字节上限（E2）",
                MAX_BODY_BYTES
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf)
}

/// 读取响应体为 UTF-8 字符串，强制大小上限（E2 修复，protocol-sso 本地副本）。
async fn read_limited_text(resp: reqwest::Response) -> BulwarkResult<String> {
    let bytes = read_limited_bytes(resp).await?;
    String::from_utf8(bytes)
        .map_err(|e| BulwarkError::Network(format!("响应体 UTF-8 解码失败: {}", e)))
}

/// JWKS 公钥缓存 TTL。
///
/// 10 分钟内复用缓存的 JWKS 公钥，避免每次 `validate_id_token` 都拉取 JWKS endpoint。
/// 与 `protocol::oauth2::keycloak::JWKS_CACHE_TTL` 保持一致。
#[cfg(feature = "protocol-jwt")]
const JWKS_CACHE_TTL: Duration = Duration::from_secs(600);

/// OIDC state 参数 TTL。
///
/// `get_authorization_url` 注册的 state 在 10 分钟内有效，超时后 `exchange_code` 拒绝。
/// 与 `JWKS_CACHE_TTL` 一致，覆盖 OAuth2 授权码典型生命周期（≤10 min）。
const OIDC_STATE_TTL: Duration = Duration::from_secs(600);

/// JWKS 缓存 key 前缀（拼入 DAO key：`oidc:jwks:{issuer}`）。
///
/// 通过 [`BulwarkDao`] 抽象层委托 oxcache 管理 JWKS JSON + TTL，
/// 禁止手写内存缓存（用户铁律：所有缓存由 oxcache 接管）。
#[cfg(feature = "protocol-jwt")]
const JWKS_CACHE_KEY_PREFIX: &str = "oidc:jwks:";

/// OIDC state 缓存 key 前缀（拼入 DAO key：`oidc:state:{state}`）。
///
/// 通过 [`BulwarkDao`] 抽象层委托 oxcache 管理 state 注册/消费/TTL，
/// 替代手写 `Mutex<HashMap<String, Instant>>`。
/// oxcache 自动管理 TTL 过期与容量上限，无需 LRU 淘汰逻辑。
const OIDC_STATE_KEY_PREFIX: &str = "oidc:state:";

/// URL 编码集（与 oauth2/client.rs 保持一致：保留 `-_.~` 不编码）。
///
/// 基于 `NON_ALPHANUMERIC` 移除 `- _ . ~` 四个 RFC 3986 unreserved 字符，
/// 其余非字母数字字符按 `%HH` 编码。原手写 `url_encode` 不编码非 ASCII 与控制字符，
/// 存在 URL 注入风险，统一委托 `percent-encoding` crate 处理。
const URLENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

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
    /// - `state`: OAuth2 state 参数（必须与 `get_authorization_url`
    ///   注册的 state 匹配，否则返回 `InvalidParam` 错误）。
    ///
    /// # 返回
    /// id_token 字符串（JWT 格式）。
    ///
    /// # 错误
    /// - `BulwarkError::InvalidParam`: state 未注册、不匹配或已过期（CSRF 防护）。
    async fn exchange_code(
        &self,
        code: &str,
        redirect_uri: &str,
        state: &str,
    ) -> BulwarkResult<String>;

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

/// JWKS 中的单个 RSA 公钥。
///
/// 表示从 `jwks_uri` 拉取的公钥集合中的一个条目。
/// 仅声明 RS256 验签所需字段；其他字段（如 `use` / `alg`）在反序列化时被忽略。
#[cfg_attr(not(feature = "protocol-jwt"), allow(dead_code))]
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
#[cfg_attr(not(feature = "protocol-jwt"), allow(dead_code))]
#[derive(Debug, Clone, Deserialize, Serialize)]
struct JwksResponse {
    /// 公钥列表。
    keys: Vec<Jwk>,
}

/// 默认 OIDC Provider 实现。
///
/// 使用 reqwest 发送 HTTP 请求，与外部 IdP 交互。
///
/// # 验签行为
///
/// `validate_id_token` 在启用 `protocol-jwt` feature 时执行 JWKS 验签（RS256）+
/// iss/aud/exp 校验；未启用时返回 `NotImplemented`。
/// `exchange_code` 在启用 `protocol-jwt` feature 时返回前自动调用
/// `validate_id_token`，未启用时保持向后兼容行为（不验签）。
///
/// # 缓存行为
///
/// JWKS 公钥缓存与 state 注册表均通过 [`BulwarkDao`]（oxcache 抽象层）管理，
/// **禁止手写内存缓存**（用户铁律：所有缓存由 oxcache 接管）。
/// 调用方必须通过 [`with_dao`](Self::with_dao) 注入 DAO 实例，
/// 否则 `get_authorization_url` / `exchange_code` / `validate_id_token` 返回
/// [`BulwarkError::Config`] 错误。
pub struct DefaultOidcProvider {
    /// Discovery 配置（含 endpoints）。
    config: OidcDiscoveryConfig,
    /// 客户端 ID。
    client_id: String,
    /// 客户端密钥。
    client_secret: String,
    /// HTTP 客户端。
    http_client: reqwest::Client,
    /// DAO 抽象（通过 oxcache 管理 JWKS 缓存 + state 注册表）。
    ///
    /// `None` 时 `get_authorization_url` / `exchange_code` / `validate_id_token`
    /// 返回 [`BulwarkError::Config`] 错误。调用方通过 [`with_dao`](Self::with_dao) 注入。
    dao: Option<Arc<dyn BulwarkDao>>,
    /// state TTL（默认 `OIDC_STATE_TTL`，可通过 `with_state_ttl` 自定义）。
    ///
    /// 通过 `dao.set("oidc:state:{state}", "1", state_ttl.as_secs())` 写入 DAO，
    /// oxcache 自动管理 TTL 过期。
    state_ttl: Duration,
    /// JWKS 拉取 single-flight 锁（防止缓存击穿惊群效应）。
    ///
    /// 仅在启用 `protocol-jwt` feature 时使用：JWKS 缓存 miss 时获取锁，
    /// 防止 N 个并发 `validate_id_token` 同时触发 `fetch_jwks` 对 IdP JWKS endpoint
    /// 形成"惊群效应"。持锁后二次检查缓存，命中则直接复用，未命中才真正发起 HTTP 请求。
    #[cfg(feature = "protocol-jwt")]
    jwks_fetch_lock: tokio::sync::Mutex<()>,
}

impl DefaultOidcProvider {
    /// 创建新的 `DefaultOidcProvider` 实例。
    ///
    /// 调用方负责提供 `OidcDiscoveryConfig`（含 endpoints），provider 不自动获取 discovery 文档。
    ///
    /// **注意**：返回的实例未注入 DAO，`get_authorization_url` / `exchange_code` /
    /// `validate_id_token` 会返回 [`BulwarkError::Config`] 错误。
    /// 必须调用 [`with_dao`](Self::with_dao) 注入 DAO 实例后才能正常工作。
    ///
    /// # 参数
    /// - `config`: OIDC Discovery 配置（含 issuer 和 endpoints）。
    /// - `client_id`: 客户端 ID。
    /// - `client_secret`: 客户端密钥。
    ///
    /// # 错误
    /// - `BulwarkError::Network`: `reqwest::Client` 构建失败（E1：含超时配置）。
    pub fn new(
        config: OidcDiscoveryConfig,
        client_id: &str,
        client_secret: &str,
    ) -> BulwarkResult<Self> {
        // E1：使用 build_safe_http_client 注入 connect_timeout=10s / read_timeout=30s，
        // 防止恶意或慢速 IdP 拖垮服务端连接池（slowloris 类攻击）。
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

    /// 注入 [`BulwarkDao`] 实例以接管 JWKS 缓存与 state 注册表。
    ///
    /// **必选调用**：`get_authorization_url` / `exchange_code` / `validate_id_token`
    /// 依赖 DAO 管理缓存与 state，未注入 DAO 时返回 [`BulwarkError::Config`] 错误。
    ///
    /// - JWKS 缓存 key：`oidc:jwks:{issuer}`，TTL 由 `JWKS_CACHE_TTL` 控制。
    /// - state 缓存 key：`oidc:state:{state}`，TTL 由 `OIDC_STATE_TTL` 或
    ///   `with_state_ttl` 控制。
    ///
    /// # 参数
    ///
    /// - `dao`: DAO 实例（通常为 `Arc<BulwarkDaoOxcache>` 或测试用 `Arc<MockDao>`）。
    ///
    /// # 示例
    ///
    /// ```ignore
    /// let provider = DefaultOidcProvider::new(config, "cid", "secret")
    ///     .with_dao(Arc::new(BulwarkDaoOxcache::new().await?));
    /// ```
    pub fn with_dao(mut self, dao: Arc<dyn BulwarkDao>) -> Self {
        self.dao = Some(dao);
        self
    }

    /// 自定义 state TTL（主要用于测试）。
    ///
    /// # 参数
    /// - `ttl`: state 有效期。设为极短时长可测试过期场景。
    #[cfg(test)]
    pub fn with_state_ttl(mut self, ttl: Duration) -> Self {
        self.state_ttl = ttl;
        self
    }

    /// 自定义 state_store 最大条目数（no-op，保留以兼容旧测试）。
    ///
    /// **注意**：DAO 模式下 state 容量由 oxcache 自管理，此方法不再生效。
    /// 保留方法签名仅为兼容旧测试调用，新代码不应依赖此方法。
    #[cfg(test)]
    pub fn with_max_state_entries(self, _max: usize) -> Self {
        // no-op：DAO（oxcache）自管理容量，无需 LRU 淘汰
        self
    }

    /// 当前 state_store 条目数（stub，保留以兼容旧测试）。
    ///
    /// **注意**：DAO 模式下 state 存储在 oxcache 中，无法直接查询条目数。
    /// 返回 0 仅用于兼容旧测试签名，新代码不应依赖此返回值。
    #[cfg(test)]
    pub fn state_store_len(&self) -> usize {
        0
    }

    /// 构造 JWKS 在 DAO 中的缓存 key。
    ///
    /// 格式：`oidc:jwks:{issuer}`，按 issuer 区分不同 IdP。
    #[cfg(feature = "protocol-jwt")]
    fn jwks_cache_key(&self) -> String {
        format!("{}{}", JWKS_CACHE_KEY_PREFIX, self.config.issuer)
    }

    /// 构造 state 在 DAO 中的缓存 key。
    ///
    /// 格式：`oidc:state:{state}`。
    fn state_cache_key(state: &str) -> String {
        format!("{}{}", OIDC_STATE_KEY_PREFIX, state)
    }

    /// 注册 state（通过 DAO 写入，TTL 由 oxcache 自动管理）。
    ///
    /// `get_authorization_url` 调用此方法将 state 写入 DAO：
    /// `dao.set("oidc:state:{state}", "1", state_ttl.as_secs())`
    async fn register_state(&self, state: &str) -> BulwarkResult<()> {
        let dao = self.dao.as_ref().ok_or_else(|| {
            BulwarkError::Config(
                "DefaultOidcProvider 未注入 DAO，无法注册 state（调用 with_dao 注入 BulwarkDao）"
                    .to_string(),
            )
        })?;
        let key = Self::state_cache_key(state);
        dao.set(&key, "1", self.state_ttl.as_secs()).await
    }

    /// 校验并消费 state（one-time use，通过 DAO 原子 get_and_delete）。
    ///
    /// `exchange_code` 调用此方法校验 state 是否已注册且未过期。
    /// 校验通过后立即删除 state（one-time use，防止重放）。
    /// TTL 过期由 oxcache 自动管理（state 不存在视为未注册或已过期）。
    ///
    /// # 返回
    /// - `Ok(())`: state 有效
    /// - `Err(BulwarkError::InvalidParam)`: state 未注册 / 不匹配 / 已过期
    /// - `Err(BulwarkError::Config)`: 未注入 DAO
    async fn validate_and_consume_state(&self, state: &str) -> BulwarkResult<()> {
        let dao = self.dao.as_ref().ok_or_else(|| {
            BulwarkError::Config(
                "DefaultOidcProvider 未注入 DAO，无法校验 state（调用 with_dao 注入 BulwarkDao）"
                    .to_string(),
            )
        })?;
        let key = Self::state_cache_key(state);
        let value = dao.get_and_delete(&key).await?;
        match value {
            Some(_) => Ok(()),
            None => Err(BulwarkError::InvalidParam(format!(
                "OIDC state 不匹配或未注册或已过期（CSRF 防护，TTL={}s）",
                self.state_ttl.as_secs()
            ))),
        }
    }

    /// 拉取 JWKS 公钥集合并写入 DAO 缓存。
    ///
    /// HTTP GET [`OidcDiscoveryConfig::jwks_uri`]，响应体按 JSON 解析为 [`JwksResponse`]，
    /// 序列化为 JSON 字符串后通过 `dao.set(key, json, JWKS_CACHE_TTL.as_secs())` 写入缓存。
    /// TTL 由 oxcache 自动管理（set 时传入 TTL），过期后下次 `validate_id_token` 自动重新拉取。
    ///
    /// # 错误
    ///
    /// - `BulwarkError::Config`: 未调用 [`with_dao`](Self::with_dao) 注入 DAO。
    /// - `BulwarkError::Internal`: HTTP 请求失败、非 2xx 状态码、JSON 解析失败或 DAO 写入失败。
    #[cfg(feature = "protocol-jwt")]
    async fn fetch_jwks(&self) -> BulwarkResult<()> {
        let dao = self.dao.as_ref().ok_or_else(|| {
            BulwarkError::Config(
                "DefaultOidcProvider 未注入 DAO，无法缓存 JWKS（调用 with_dao 注入 BulwarkDao）"
                    .to_string(),
            )
        })?;

        let resp = self
            .http_client
            .get(&self.config.jwks_uri)
            .send()
            .await
            .map_err(|e| BulwarkError::Internal(format!("OIDC JWKS 请求失败: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            // E2：错误响应体也限大小（4 MiB），防止恶意 IdP 通过错误响应触发 OOM
            let body = read_limited_text(resp).await.unwrap_or_default();
            return Err(BulwarkError::Internal(format!(
                "OIDC JWKS 端点返回错误状态: {} body: {}",
                status, body
            )));
        }

        // E2：限制响应体大小（4 MiB），防止恶意 IdP 通过超大 JWKS JSON 触发 OOM
        let bytes = read_limited_bytes(resp)
            .await
            .map_err(|e| BulwarkError::Internal(format!("OIDC JWKS 响应体读取失败: {}", e)))?;
        let jwks: JwksResponse = serde_json::from_slice(&bytes)
            .map_err(|e| BulwarkError::Internal(format!("OIDC JWKS 响应解析失败: {}", e)))?;

        // 序列化为 JSON 字符串存入 DAO（反序列化时按相同结构解析）
        let json = serde_json::to_string(&jwks)
            .map_err(|e| BulwarkError::Internal(format!("OIDC JWKS 序列化失败: {}", e)))?;
        let cache_key = self.jwks_cache_key();
        dao.set(&cache_key, &json, JWKS_CACHE_TTL.as_secs()).await?;
        Ok(())
    }

    /// 验证 id_token 的内部实现。
    ///
    /// 仅在启用 `protocol-jwt` feature 时编译。流程参考
    /// `protocol::oauth2::keycloak::KeycloakProvider::verify_id_token`：
    ///
    /// 1. 解析 JWT header，提取 `kid`。
    /// 2. 从 DAO 缓存读取 JWKS（key=`oidc:jwks:{issuer}`），
    ///    缓存 miss 或反序列化失败时调用 `fetch_jwks` 重新拉取并写入缓存。
    /// 3. 按 `kid` 匹配 JWKS 公钥，用 `n`/`e` 模数构造 `DecodingKey`。
    /// 4. 用 RS256 算法验签，解析为 [`IdTokenClaims`]。
    /// 5. 校验 `iss`（匹配 `config.issuer`）。
    /// 6. 校验 `aud`（匹配 `client_id`）。
    /// 7. 校验 `exp`（由 jsonwebtoken 内置 `validate_exp = true` 完成）。
    ///
    /// # 错误
    ///
    /// - `BulwarkError::Config`: 未调用 [`with_dao`](Self::with_dao) 注入 DAO。
    /// - `BulwarkError::InvalidToken`: JWT header 解析失败 / kid 缺失 / JWKS 无匹配公钥 /
    ///   签名验证失败 / claims 解析失败 / token 已过期 / iss 不匹配 / aud 不匹配。
    /// - `BulwarkError::Internal`: JWKS 拉取失败 / DAO 读写失败 / 反序列化失败。
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

        let dao = self.dao.as_ref().ok_or_else(|| {
            BulwarkError::Config(
                "DefaultOidcProvider 未注入 DAO，无法缓存 JWKS（调用 with_dao 注入 BulwarkDao）"
                    .to_string(),
            )
        })?;

        // 1. 解析 JWT header，提取 kid
        let header = jsonwebtoken::decode_header(id_token).map_err(|e| {
            BulwarkError::InvalidToken(format!("OIDC id_token header 解析失败: {}", e))
        })?;
        let kid = header.kid.as_deref().ok_or_else(|| {
            BulwarkError::InvalidToken("OIDC id_token header 缺少 kid 字段".to_string())
        })?;

        // 2. 从 DAO 读取 JWKS 缓存；缓存 miss 或反序列化失败（缓存损坏）时重新拉取。
        //    single-flight 锁：缓存 miss 时获取 `jwks_fetch_lock`，防止 N 个并发请求
        //    同时触发 `fetch_jwks` 对 IdP JWKS endpoint 形成惊群效应。持锁后二次检查
        //    缓存（其他请求可能已填充），命中则复用，未命中才真正发起 HTTP 请求。
        let cache_key = self.jwks_cache_key();
        let cached = dao.get(&cache_key).await?;
        let jwks: JwksResponse = match cached
            .as_deref()
            .and_then(|json| serde_json::from_str(json).ok())
        {
            Some(jwks) => jwks,
            None => {
                // 缓存 miss / TTL 过期 / 反序列化失败：获取 single-flight 锁
                let _lock = self.jwks_fetch_lock.lock().await;
                // 二次检查：持锁期间其他请求可能已填充缓存，命中则直接复用
                let cached = dao.get(&cache_key).await?;
                match cached
                    .as_deref()
                    .and_then(|s| serde_json::from_str::<JwksResponse>(s).ok())
                {
                    Some(jwks) => jwks,
                    None => {
                        // 仍未命中：真正发起 JWKS 拉取并写入缓存
                        self.fetch_jwks().await?;
                        let json = dao.get(&cache_key).await?.ok_or_else(|| {
                            BulwarkError::Internal(
                                "OIDC fetch_jwks 后缓存仍为空（DAO 写入异常）".to_string(),
                            )
                        })?;
                        serde_json::from_str(&json).map_err(|e| {
                            BulwarkError::Internal(format!("OIDC JWKS 反序列化失败: {}", e))
                        })?
                    },
                }
            },
        };

        // 3. 按 kid 匹配 JWKS 公钥
        let jwk = jwks.keys.iter().find(|k| k.kid == kid).cloned();
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
        // 注册 state 供 exchange_code 校验（CSRF 防护）。
        // TTL 过期由 oxcache 自动管理（set 时传入 TTL），无需 cleanup_expired_states。
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
    ) -> BulwarkResult<String> {
        // 校验 state 是否已注册且未过期（CSRF 防护）
        // 校验通过后立即消费 state（one-time use，防止重放）
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
            .map_err(|e| BulwarkError::Internal(format!("OIDC token 交换失败: {}", e)))?;

        if !resp.status().is_success() {
            let status = resp.status();
            // E2：错误响应体也限大小（4 MiB），防止恶意 IdP 通过错误响应触发 OOM
            let body = read_limited_text(resp).await.unwrap_or_default();
            return Err(BulwarkError::Internal(format!(
                "OIDC token 端点返回错误状态: {} body: {}",
                status, body
            )));
        }

        // E2：限制响应体大小（4 MiB），防止恶意 IdP 通过超大 token JSON 触发 OOM
        let bytes = read_limited_bytes(resp)
            .await
            .map_err(|e| BulwarkError::Internal(format!("OIDC token 响应体读取失败: {}", e)))?;
        let token_response: TokenResponse = serde_json::from_slice(&bytes)
            .map_err(|e| BulwarkError::Internal(format!("OIDC token 响应解析失败: {}", e)))?;

        let id_token = token_response
            .id_token
            .ok_or_else(|| BulwarkError::Internal("OIDC token 响应中缺少 id_token".to_string()))?;

        // 启用 protocol-jwt 时在返回前验证 id_token 签名 + iss/aud/exp。
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
            // E2：错误响应体也限大小（4 MiB），防止恶意 IdP 通过错误响应触发 OOM
            let body = read_limited_text(resp).await.unwrap_or_default();
            return Err(BulwarkError::Internal(format!(
                "OIDC userinfo 端点返回错误状态: {} body: {}",
                status, body
            )));
        }

        // E2：限制响应体大小（4 MiB），防止恶意 IdP 通过超大 userinfo JSON 触发 OOM
        let bytes = read_limited_bytes(resp)
            .await
            .map_err(|e| BulwarkError::Internal(format!("OIDC userinfo 响应体读取失败: {}", e)))?;
        serde_json::from_slice::<OidcUserInfo>(&bytes)
            .map_err(|e| BulwarkError::Internal(format!("OIDC userinfo 响应解析失败: {}", e)))
    }

    async fn validate_id_token(&self, id_token: &str) -> BulwarkResult<bool> {
        // 启用 protocol-jwt 时执行 JWKS 验签 + iss/aud/exp 校验。
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
    #[allow(
        dead_code,
        reason = "OAuth2 兼容字段：当前仅用 id_token，access_token 预留供 protocol-jwt 扩展"
    )]
    access_token: Option<String>,
    #[allow(dead_code, reason = "OAuth2 兼容字段：预留 token_type 供后续扩展")]
    token_type: Option<String>,
    #[allow(dead_code, reason = "OAuth2 兼容字段：预留 expires_in 供后续扩展")]
    expires_in: Option<i64>,
}

/// URL 百分号编码（保留 `-_.~` 不编码）。
///
/// 委托 `percent-encoding` crate，与 `protocol::oauth2::client::url_encode` 行为一致。
/// 原手写实现不编码非 ASCII 与控制字符，存在 URL 注入风险，已废弃。
fn url_encode(s: &str) -> String {
    utf8_percent_encode(s, URLENCODE_SET).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::MockDao;

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
        let provider = DefaultOidcProvider::new(config, "client-id", "client-secret").unwrap();
        assert_eq!(provider.client_id, "client-id");
        assert_eq!(provider.client_secret, "client-secret");
    }

    /// OidcProvider trait 编译验证：DefaultOidcProvider 实现 OidcProvider trait（spec R-004）。
    #[test]
    fn default_oidc_provider_implements_oidc_provider() {
        fn assert_oidc_provider<T: OidcProvider>(_provider: &T) {}
        let config = make_test_config();
        let provider = DefaultOidcProvider::new(config, "id", "secret").unwrap();
        assert_oidc_provider(&provider);
    }

    // ========================================================================
    // get_authorization_url 测试
    // ========================================================================

    /// get_authorization_url 构造正确 URL（spec R-004）。
    #[tokio::test]
    async fn get_authorization_url_constructs_valid_url() {
        let config = make_test_config();
        let provider = DefaultOidcProvider::new(config, "test-client-id", "secret")
            .unwrap()
            .with_dao(Arc::new(MockDao::new()));
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
            .with_dao(Arc::new(MockDao::new()));
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
            .with_dao(Arc::new(MockDao::new()));
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
    /// 此测试仅在未启用 `protocol-jwt` feature 时运行。
    /// 启用 `protocol-jwt` 时 `validate_id_token` 执行 JWKS 验签，由下面的
    /// `validate_id_token_rejects_*` 系列测试覆盖。
    #[cfg(not(feature = "protocol-jwt"))]
    #[tokio::test]
    async fn validate_id_token_returns_not_implemented() {
        let config = make_test_config();
        let provider = DefaultOidcProvider::new(config, "id", "secret").unwrap();
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
    /// 启用 `protocol-jwt` 时 `exchange_code` 返回前会调用
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

        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(MockDao::new()));
        //  先注册 state，再交换授权码
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

        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(MockDao::new()));
        //  先注册 state
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

        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(MockDao::new()));
        //  先注册 state
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

        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(MockDao::new()));
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

        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(MockDao::new()));
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

    // ========================================================================
    // validate_id_token JWKS 验签测试
    //
    // 启用 protocol-jwt feature 时执行 JWKS 验签（RS256）+ iss/aud/exp 校验。
    // 测试使用 wiremock mock JWKS 端点 + RSA 2048 测试密钥对。
    // 参考实现：protocol::oauth2::keycloak::tests::keycloak_provider_verify_id_token_validates_signature_and_claims
    // ========================================================================

    /// 测试辅助：生成 RSA 2048 测试密钥对。
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

    /// 测试辅助：当前 Unix 时间戳（秒）。
    #[cfg(feature = "protocol-jwt")]
    fn now_unix() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("系统时间应早于 UNIX_EPOCH")
            .as_secs() as i64
    }

    /// 测试辅助：用 RSA 私钥签发 JWT。
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

    /// 测试辅助：生成有效 id_token + 对应的 JWKS JSON。
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

    /// 测试 1：validate_id_token 拒绝无效签名的 JWT。
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

        let provider = DefaultOidcProvider::new(config, "client-id", "secret")
            .unwrap()
            .with_dao(Arc::new(MockDao::new()));
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

    /// 测试 2：validate_id_token 拒绝过期 token。
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

        let provider = DefaultOidcProvider::new(config, "client-id", "secret")
            .unwrap()
            .with_dao(Arc::new(MockDao::new()));
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

    /// 测试 3：validate_id_token 拒绝 iss 不匹配的 token。
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

        let provider = DefaultOidcProvider::new(config, "client-id", "secret")
            .unwrap()
            .with_dao(Arc::new(MockDao::new()));
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

    /// 测试 4：validate_id_token 拒绝 aud 不匹配的 token。
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

        let provider = DefaultOidcProvider::new(config, "client-id", "secret")
            .unwrap()
            .with_dao(Arc::new(MockDao::new()));
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

    /// 测试 5：exchange_code 在返回前调用 validate_id_token。
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

        let provider = DefaultOidcProvider::new(config, "cid", "secret")
            .unwrap()
            .with_dao(Arc::new(MockDao::new()));
        //  先注册 state
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

    // ========================================================================
    //  OIDC state 参数验证测试
    // ========================================================================

    ///  exchange_code 拒绝未注册的 state（CSRF 防护）。
    ///
    /// 攻击场景：攻击者直接调用 exchange_code，未经过 get_authorization_url 注册 state。
    /// 期望：返回 InvalidParam 错误。
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
            .with_dao(Arc::new(MockDao::new()));
        // 未注册 state 直接调用 exchange_code
        let result = provider
            .exchange_code("code", "https://sp.example.com/cb", "unregistered-state")
            .await;
        assert!(result.is_err(), "未注册的 state 应被拒绝");
        match result.err() {
            Some(BulwarkError::InvalidParam(msg)) => {
                assert!(msg.contains("state"), "错误消息应提及 state，实际: {}", msg);
            },
            other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
        }
    }

    ///  exchange_code 拒绝不匹配的 state。
    ///
    /// 攻击场景：注册了 state "abc"，但传入 state "xyz"。
    /// 期望：返回 InvalidParam 错误。
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
            .with_dao(Arc::new(MockDao::new()));
        // 注册 state "abc"
        provider
            .get_authorization_url("https://sp.example.com/cb", "abc", &["openid"])
            .await
            .unwrap();
        // 传入不匹配的 state "xyz"
        let result = provider
            .exchange_code("code", "https://sp.example.com/cb", "xyz")
            .await;
        assert!(result.is_err(), "不匹配的 state 应被拒绝");
        match result.err() {
            Some(BulwarkError::InvalidParam(_)) => {},
            other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
        }
    }

    ///  state 是 one-time use，重用应被拒绝。
    ///
    /// 攻击场景：攻击者截获合法的 state，尝试重放。
    /// 期望：第一次成功，第二次失败（state 已被消费）。
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
            .with_dao(Arc::new(MockDao::new()));
        // 注册 state
        provider
            .get_authorization_url("https://sp.example.com/cb", "one-time-state", &["openid"])
            .await
            .unwrap();
        // 第一次：成功
        let first = provider
            .exchange_code("code", "https://sp.example.com/cb", "one-time-state")
            .await;
        assert!(first.is_ok(), "首次使用 state 应成功");
        // 第二次：失败（state 已被消费）
        let second = provider
            .exchange_code("code", "https://sp.example.com/cb", "one-time-state")
            .await;
        assert!(second.is_err(), "重用 state 应被拒绝（one-time use）");
        match second.err() {
            Some(BulwarkError::InvalidParam(_)) => {},
            other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
        }
    }

    ///  state 过期后应被拒绝。
    ///
    /// 使用极短 TTL（1 秒，受 BulwarkDao::set 的 ttl_seconds: u64 精度限制），
    /// 注册后等待过期，再调用 exchange_code 应失败。
    /// oxcache 自动管理 TTL 过期，Provider 层不负责清理。
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

        // 使用 1 秒 TTL（BulwarkDao::set 的 ttl_seconds: u64 最小粒度为秒）
        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(MockDao::new()))
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
            Some(BulwarkError::InvalidParam(msg)) => {
                assert!(msg.contains("过期"), "错误消息应提及过期，实际: {}", msg);
            },
            other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
        }
    }

    ///  DAO 模式下 with_max_state_entries 是 no-op，不影响 state 注册。
    ///
    /// 原 LRU 淘汰机制已迁移到 oxcache 配置层，Provider 层不再负责容量限制。
    /// with_max_state_entries 保留为 no-op 仅为兼容旧测试调用。
    /// 期望：注册多个 state 不报错，state_store_len 始终返回 0（stub）。
    #[tokio::test]
    async fn state_store_evicts_oldest_when_max_entries_reached() {
        let config = OidcDiscoveryConfig {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: "https://idp.example.com/token".to_string(),
            userinfo_endpoint: "https://idp.example.com/userinfo".to_string(),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
        };

        // with_max_state_entries 是 no-op（DAO 模式下容量由 oxcache 自管理）
        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(MockDao::new()))
            .with_max_state_entries(2);
        // 注册 3 个 state（max=2，但 no-op 不淘汰）
        provider
            .get_authorization_url("https://cb.com/cb", "state-1", &["openid"])
            .await
            .unwrap();
        provider
            .get_authorization_url("https://cb.com/cb", "state-2", &["openid"])
            .await
            .unwrap();
        provider
            .get_authorization_url("https://cb.com/cb", "state-3", &["openid"])
            .await
            .unwrap();
        // state_store_len 始终返回 0（stub，DAO 模式下无法查询条目数）
        assert_eq!(provider.state_store_len(), 0);
    }

    ///  DAO 模式下 state_store_len 始终返回 0（stub），但 state 可正常注册。
    ///
    /// state 实际存储在 oxcache 中，Provider 层无法直接查询条目数。
    /// state_store_len 保留为 stub 仅为兼容旧测试调用。
    /// 期望：get_authorization_url 不报错，state_store_len 始终返回 0。
    #[tokio::test]
    async fn get_authorization_url_registers_state() {
        let config = OidcDiscoveryConfig {
            issuer: "https://idp.example.com".to_string(),
            authorization_endpoint: "https://idp.example.com/authorize".to_string(),
            token_endpoint: "https://idp.example.com/token".to_string(),
            userinfo_endpoint: "https://idp.example.com/userinfo".to_string(),
            jwks_uri: "https://idp.example.com/jwks".to_string(),
        };
        let provider = DefaultOidcProvider::new(config, "cid", "cs")
            .unwrap()
            .with_dao(Arc::new(MockDao::new()));
        // state_store_len 始终返回 0（stub）
        assert_eq!(provider.state_store_len(), 0);
        provider
            .get_authorization_url("https://cb.com/cb", "first-state", &["openid"])
            .await
            .unwrap();
        // 注册后仍返回 0（stub，DAO 模式下无法查询条目数）
        assert_eq!(provider.state_store_len(), 0);
        provider
            .get_authorization_url("https://cb.com/cb", "second-state", &["openid"])
            .await
            .unwrap();
        assert_eq!(provider.state_store_len(), 0);
        // 同一 state 重复注册不报错（DAO 覆盖写入）
        provider
            .get_authorization_url("https://cb.com/cb", "first-state", &["openid"])
            .await
            .unwrap();
        assert_eq!(provider.state_store_len(), 0);
    }

    // ========================================================================
    // E1 + E2 测试：HTTP 客户端超时 + 响应体大小限制
    //
    // 验证 DefaultOidcProvider 使用 build_safe_http_client（含 connect_timeout=10s,
    // read_timeout=30s）与 read_limited_bytes（4 MiB 上限），防止恶意 IdP 通过
    // slowloris / 超大响应体 OOM 攻击。
    // ========================================================================

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
            Some(BulwarkError::Network(msg)) => {
                assert!(
                    msg.contains("上限") || msg.contains("E2"),
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

    /// E2：`get_user_info` 拒绝超过 4 MiB 的 userinfo 响应。
    ///
    /// mock userinfo endpoint 返回 5 MiB body，期望 `get_user_info` 返回 Internal 错误
    /// （由 `read_limited_bytes` 返回 Network 错误后包装为 Internal）。
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
            .with_dao(Arc::new(MockDao::new()));
        let result = provider.get_user_info("access-token").await;
        assert!(result.is_err(), "超大 userinfo 响应应返回错误");
    }

    /// E2：`exchange_code` 拒绝超过 4 MiB 的 token 响应。
    ///
    /// mock token endpoint 返回 5 MiB body，期望 `exchange_code` 返回 Internal 错误。
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
            .with_dao(Arc::new(MockDao::new()));
        // 先注册 state
        provider
            .get_authorization_url("https://sp.example.com/cb", "state-e2", &["openid"])
            .await
            .unwrap();
        let result = provider
            .exchange_code("code", "https://sp.example.com/cb", "state-e2")
            .await;
        assert!(result.is_err(), "超大 token 响应应返回错误");
    }
}
