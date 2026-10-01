// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! OAuth2 HTTP 端点路由（feature = "oauth2-server"）。
//!
//! 将 OAuth2 handler 暴露为 HTTP 端点，集成到 GarrisonAuthServer。
//! 与 sdforge_routes.rs（AuthBackend 路由）互补，使用 axum Router::merge 集成。
//!
//! # 端点
//!
//! - 外网：`GET /oauth2/authorize`、`POST /oauth2/token`、`POST /oauth2/revoke`、
//!   `GET /oauth2/jwks.json`（非对称签名时可用）
//! - 内网：`POST /oauth2/introspect`

#![cfg(feature = "oauth2-server")]

use std::sync::Arc;

use axum::extract::{Extension, Query, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde_json::json;

use crate::context::GarrisonPrincipal;
use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use crate::loc;
use crate::oauth2_server::authorize::{AuthorizeHandler, AuthorizeRequest, AuthorizeResponse};
use crate::oauth2_server::client::OAuth2ClientStore;
use crate::oauth2_server::introspect::{IntrospectHandler, IntrospectRequest};
use crate::oauth2_server::revoke::{RevokeHandler, RevokeRequest};
use crate::oauth2_server::token::{
    PasswordRateLimiter, TokenHandler, TokenRateLimiter, TokenRequest,
};

/// OAuth2 路由共享状态。
///
/// 持有所有 OAuth2 handler，通过 `Arc<OAuth2State>` 注入到 axum Router。
pub struct OAuth2State {
    /// 授权码流程 handler（/oauth2/authorize）。
    pub authorize_handler: Arc<AuthorizeHandler>,
    /// Token 签发 handler（/oauth2/token，4 种 grant type）。
    pub token_handler: Arc<TokenHandler>,
    /// Token 撤销 handler（/oauth2/revoke，RFC 7009）。
    pub revoke_handler: Arc<RevokeHandler>,
    /// Token 内省 handler（/oauth2/introspect，RFC 7662）。
    pub introspect_handler: Arc<IntrospectHandler>,
    /// 客户端存储（discovery 元数据 `scopes_supported` 派生源）。
    pub client_store: Arc<dyn OAuth2ClientStore>,
    /// JWKS 导出源（单钥静态形态）：`Some((jwt_algorithm, private_key_pem))` 时
    /// /oauth2/jwks.json 可用；None 且未注入密钥库时端点 404（fail-closed）。
    pub jwks_source: Option<(String, String)>,
    /// 签发者标识（discovery 元数据 `issuer`；未配置时 discovery 端点 404）。
    pub issuer: Option<String>,
    /// 多 kid JWKS 密钥库账本（注入后 JWKS 端点优先从库发布，单钥 `jwks_source`
    /// 退居后备）。
    pub jwks_keystore: Option<Arc<crate::oauth2_server::jwks::JwksKeystore>>,
    /// OIDC discovery（`/.well-known/openid-configuration`）开关。
    ///
    /// 默认跟随 `protocol-oidc` Cargo feature；可用
    /// `with_oidc_discovery_enabled` 运行时覆写（部署按需关闭）。
    pub oidc_discovery_enabled: bool,
    /// password grant 是否宣告进 discovery 元数据 `grant_types_supported`。
    ///
    /// TokenHandler 的 password verifier 为运行时注入（无编译期 feature 可查），
    /// 由装配方在注入 verifier 时同步置位，保证元数据与实际能力一致。
    pub password_grant_advertised: bool,
    /// JWKS 退役保留时长（秒）：Passive 钥超期转 Disabled 并移出 JWKS。
    ///
    /// 同时决定 JWKS 端点 `Cache-Control: max-age`（取一半，缩短客户端重取
    /// 间隔以尽早感知退役；部署应保证 retention ≥ 2× access token TTL，使
    /// 退役时该钥签发的 token 必已过期）。
    pub jwks_retention_secs: u64,
    /// discovery `scopes_supported` 派生缓存：免每请求全客户端 keys 扫描 +
    /// N 次串行 DAO 读（discovery 未认证，可被放大为服务端 DAO 压力）。
    /// TTL 300s 与 discovery 响应 Cache-Control 同周期；客户端增删后元数据
    /// 最迟 300s 刷新（元数据低频变更，短暂陈旧可接受）。
    #[doc(hidden)]
    pub scopes_cache:
        tokio::sync::RwLock<Option<(std::time::Instant, std::sync::Arc<Vec<String>>)>>,
    /// JWKS 发布文档缓存：键 = (状态文档内容哈希, now/60 时间桶, retention)。
    /// 状态不变时免每请求 N 次 PEM 解析重建（无界增长面，未认证端点可被
    /// 放大为 CPU DoS）；60s 时间桶界保证 retention 退役视图最多陈旧 1 分钟。
    #[doc(hidden)]
    pub jwks_doc_cache: tokio::sync::Mutex<Option<JwksDocCacheEntry>>,
}

/// JWKS 发布文档缓存条目（见 [`OAuth2State::jwks_doc_cache`]）。
#[doc(hidden)]
pub struct JwksDocCacheEntry {
    pub state_hash: u64,
    pub now_bucket: i64,
    pub retention_secs: u64,
    pub doc: std::sync::Arc<crate::oauth2_server::jwks::JwkSet>,
}

impl OAuth2State {
    /// 创建 OAuth2State，内部构造 4 个 handler。
    ///
    /// TokenHandler 以安全默认参数构造限速组件（`PasswordRateLimiter::new(5, 300)`
    /// 账户锁定 + `TokenRateLimiter::new()` 端点 QPS 限制），不提供
    /// "未注入 = 无防护"的构造形态。
    pub fn new(
        store: Arc<dyn OAuth2ClientStore>,
        dao: Arc<dyn GarrisonDao>,
        login_url: String,
    ) -> Self {
        let authorize_handler =
            Arc::new(AuthorizeHandler::new(store.clone(), dao.clone(), login_url));
        let token_handler = Arc::new(TokenHandler::new(
            store.clone(),
            dao.clone(),
            authorize_handler.clone(),
            Arc::new(PasswordRateLimiter::new(5, 300)),
            Arc::new(TokenRateLimiter::new()),
        ));
        let revoke_handler = Arc::new(RevokeHandler::new(store.clone(), token_handler.clone()));
        let introspect_handler =
            Arc::new(IntrospectHandler::new(store.clone(), token_handler.clone()));
        // 退化路径结构性告警（构造完成时检测一次）：refresh grant 可用但
        // RefreshTokenRotation 未注入 → refresh 走 DAO 退化路径，reuse detection
        // 不可用（盗用 token 重放不会触发链式撤销）。生产部署应通过
        // `TokenHandler::with_refresh_rotation` 注入轮换服务消除本告警。
        // 注意：GarrisonConfig 的 recent_reuse_behaviour / refresh_grace_* 字段
        // 仅由注入的轮换服务读取——注入时须以 `with_reuse_behaviour` /
        // `with_grace_window` 同步装配配置值，否则配置保持默认不生效。
        #[cfg(feature = "db-sqlite")]
        if !token_handler.has_refresh_rotation() {
            tracing::warn!(
                "OAuth2State constructed without RefreshTokenRotation: /oauth2/token refresh grant will serve via DAO fallback without reuse detection — refresh_token replay/chain revocation is UNAVAILABLE; inject TokenHandler::with_refresh_rotation to enable"
            );
        }
        Self {
            authorize_handler,
            token_handler,
            revoke_handler,
            introspect_handler,
            client_store: store,
            jwks_source: None,
            issuer: None,
            jwks_keystore: None,
            oidc_discovery_enabled: cfg!(feature = "protocol-oidc"),
            password_grant_advertised: false,
            jwks_retention_secs: crate::config::DEFAULT_JWKS_RETENTION_SECS,
            scopes_cache: tokio::sync::RwLock::new(None),
            jwks_doc_cache: tokio::sync::Mutex::new(None),
        }
    }

    /// 启用 /oauth2/jwks.json 端点（仅非对称 JWT 签名时调用）。
    ///
    /// # 参数
    /// - `jwt_algorithm`: 签名算法名（RS256/ES256/EdDSA）。
    /// - `private_key_pem`: 对应私钥 PEM（仅用于导出公钥成分，无私钥暴露）。
    pub fn with_jwks_source(mut self, jwt_algorithm: &str, private_key_pem: &str) -> Self {
        self.jwks_source = Some((jwt_algorithm.to_string(), private_key_pem.to_string()));
        self
    }

    /// 设置 discovery 元数据 `issuer`（同时决定各端点绝对 URL 前缀）。
    pub fn with_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.issuer = Some(issuer.into());
        self
    }

    /// 注入多 kid JWKS 密钥库账本（轮换 API 见
    /// [`JwksKeystore`](crate::oauth2_server::jwks::JwksKeystore)）。
    pub fn with_jwks_keystore(
        mut self,
        keystore: Arc<crate::oauth2_server::jwks::JwksKeystore>,
    ) -> Self {
        self.jwks_keystore = Some(keystore);
        self
    }

    /// 运行时覆写 OIDC discovery 开关（默认跟随 `protocol-oidc` feature）。
    pub fn with_oidc_discovery_enabled(mut self, enabled: bool) -> Self {
        self.oidc_discovery_enabled = enabled;
        self
    }

    /// 宣告 password grant 进 discovery 元数据（装配方注入 password verifier
    /// 时同步置位，保持元数据与实际能力一致）。
    pub fn with_password_grant_advertised(mut self, advertised: bool) -> Self {
        self.password_grant_advertised = advertised;
        self
    }

    /// 覆写 JWKS 退役保留时长（默认 2× access token TTL）。
    /// # Panics-free 误配防护
    ///
    /// `retention_secs = 0` 等价于 Passive 钥即刻退役（发布面清空、验证视图
    /// 失衡），回退默认值并 warn（配置层 `jwks_retention_secs` 校验同语义）。
    pub fn with_jwks_retention_secs(mut self, retention_secs: u64) -> Self {
        if retention_secs == 0 {
            tracing::warn!(
                "with_jwks_retention_secs(0) would retire Passive keys immediately; falling back to default {}s",
                crate::config::DEFAULT_JWKS_RETENTION_SECS
            );
            self.jwks_retention_secs = crate::config::DEFAULT_JWKS_RETENTION_SECS;
            return self;
        }
        self.jwks_retention_secs = retention_secs;
        self
    }
}

/// 构建外网 OAuth2 路由（authorize/token/revoke/jwks/discovery）。
pub fn oauth2_external_router(state: Arc<OAuth2State>) -> Router {
    Router::new()
        .route("/oauth2/authorize", get(authorize_endpoint))
        .route("/oauth2/authorize/resume", get(authorize_resume_endpoint))
        .route("/oauth2/token", post(token_endpoint))
        .route("/oauth2/revoke", post(revoke_endpoint))
        .route("/oauth2/jwks.json", get(jwks_endpoint))
        .route(
            "/.well-known/openid-configuration",
            get(openid_configuration_endpoint),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(oauth_authorization_server_endpoint),
        )
        .with_state(state)
}

/// discovery 端点响应的 Cache-Control（元数据变更频率低，客户端可缓存 5 分钟）。
const DISCOVERY_CACHE_CONTROL: &str = "public, max-age=300";

/// GET /.well-known/openid-configuration — OIDC Discovery 1.0 provider metadata。
///
/// fail-closed：`protocol-oidc` 关闭（feature 或运行时旗标）或 issuer 未配置时 404。
async fn openid_configuration_endpoint(State(state): State<Arc<OAuth2State>>) -> Response {
    if !state.oidc_discovery_enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    discovery_response(&state, DiscoveryFlavor::Oidc).await
}

/// GET /.well-known/oauth-authorization-server — RFC 8414 authorization server
/// metadata（OAuth2 面，与 OIDC 开关解耦）。
///
/// fail-closed：issuer 未配置时 404。
async fn oauth_authorization_server_endpoint(State(state): State<Arc<OAuth2State>>) -> Response {
    discovery_response(&state, DiscoveryFlavor::Rfc8414).await
}

/// discovery 元数据风味：RFC 8414 基础字段 + OIDC 附加字段。
enum DiscoveryFlavor {
    /// RFC 8414 授权服务器元数据。
    Rfc8414,
    /// OIDC Discovery 1.0（在 RFC 8414 基础上补 `subject_types_supported`）。
    Oidc,
}

/// 构建 discovery 元数据并产出 200 响应；issuer 未配置返回 404（fail-closed）。
///
/// 元数据从实际能力派生（非静态模板）：
/// - `grant_types_supported`：authorization_code/refresh_token/client_credentials
///   为 token 端点既有能力；password 仅在装配方宣告后出现；
/// - `scopes_supported`：注册客户端 scope 的并集（运行时查询派生）；
/// - `jwks_uri` / `jwks_algorithms`：仅在实际发布 JWKS 时出现，算法取发布钥集合
///   （防死链误导客户端）；
/// - `code_challenge_methods_supported`：PKCE 强制开启 → 仅 S256。
async fn discovery_response(state: &OAuth2State, flavor: DiscoveryFlavor) -> Response {
    let Some(issuer) = state.issuer.as_deref() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let mut grant_types = vec![
        "authorization_code".to_string(),
        "refresh_token".to_string(),
        "client_credentials".to_string(),
    ];
    if state.password_grant_advertised {
        grant_types.push("password".to_string());
    }
    // scopes 派生带 300s 进程内缓存：discovery 未认证，list() 是
    // 全键空间扫描 + 逐客户端串行 DAO 读，放任每请求执行可被放大为
    // 服务端 DAO 压力。TTL 与 discovery 响应 Cache-Control 同周期。
    let scopes_arc = {
        let cached = state.scopes_cache.read().await.clone();
        match cached {
            Some((at, scopes)) if at.elapsed() < std::time::Duration::from_secs(300) => scopes,
            _ => match derive_scopes_supported(state).await {
                Ok(scopes) => scopes,
                Err(resp) => return resp,
            },
        }
    };
    let mut scopes = (*scopes_arc).clone();
    if scopes.is_empty() {
        scopes.push("openid".to_string());
    }
    let jwks_algorithms = match published_jwk_algorithms(state).await {
        Ok(algs) => algs,
        Err(e) => {
            // 与 scopes 同语义：派生失败不静默降级（错误元数据比无元数据更危险——
            // 丢失 jwks_uri 的元数据会让 RP 无法解析签名钥）
            tracing::error!("discovery metadata jwks algorithms derivation failed: {e}");
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        },
    };
    let mut metadata = serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth2/authorize"),
        "token_endpoint": format!("{issuer}/oauth2/token"),
        "revocation_endpoint": format!("{issuer}/oauth2/revoke"),
        // introspection 端点仅挂内网路由，不进外网 discovery（防死链与内网拓扑泄露）
        "grant_types_supported": grant_types,
        "response_types_supported": ["code"],
        "scopes_supported": scopes,
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
    });
    if let Some(algs) = jwks_algorithms {
        metadata["jwks_uri"] = serde_json::Value::String(format!("{issuer}/oauth2/jwks.json"));
        metadata["jwks_algorithms"] =
            serde_json::Value::Array(algs.into_iter().map(serde_json::Value::String).collect());
    }
    if matches!(flavor, DiscoveryFlavor::Oidc) {
        metadata["subject_types_supported"] = serde_json::json!(["public"]);
    }
    (
        StatusCode::OK,
        [(axum::http::header::CACHE_CONTROL, DISCOVERY_CACHE_CONTROL)],
        axum::Json(metadata),
    )
        .into_response()
}

/// `scopes_supported` 派生（注册客户端 scope 并集）并写入 300s 进程内缓存。
async fn derive_scopes_supported(
    state: &OAuth2State,
) -> Result<std::sync::Arc<Vec<String>>, Response> {
    match state.client_store.list().await {
        Ok(clients) => {
            let mut scopes: Vec<String> = clients.into_iter().flat_map(|c| c.scopes).collect();
            scopes.sort();
            scopes.dedup();
            let scopes = std::sync::Arc::new(scopes);
            let mut cache = state.scopes_cache.write().await;
            *cache = Some((std::time::Instant::now(), std::sync::Arc::clone(&scopes)));
            Ok(scopes)
        },
        Err(e) => {
            // 派生失败不静默降级：500 显性暴露（错误元数据比无元数据更危险）；
            // 失败不写缓存，下一请求重试派生
            tracing::error!("discovery metadata scopes derivation failed: {e}");
            Err(StatusCode::INTERNAL_SERVER_ERROR.into_response())
        },
    }
}

async fn published_jwk_algorithms(state: &OAuth2State) -> GarrisonResult<Option<Vec<String>>> {
    if let Some(keystore) = &state.jwks_keystore {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| GarrisonError::Internal(format!("jwks-clock-invalid::{e}")))?;
        let doc = keystore_jwks_document_cached(state, keystore, now.as_secs() as i64).await?;
        let Some(doc) = doc else {
            return Ok(None);
        };
        if doc.keys.is_empty() {
            return Ok(None);
        }
        let mut algs: Vec<String> = doc.keys.iter().map(|k| k.alg.clone()).collect();
        algs.sort();
        algs.dedup();
        return Ok(Some(algs));
    }
    Ok(state
        .jwks_source
        .as_ref()
        .map(|(algorithm, _)| vec![algorithm.clone()]))
}

/// 状态文档内容哈希（缓存键材料）。
fn state_content_hash(raw: Option<&str>) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    raw.hash(&mut hasher);
    hasher.finish()
}

/// JWKS 发布文档获取（keystore 形态，带 60s 时间桶缓存）。
///
/// 缓存键 = (状态文档内容哈希, now/60, retention)：状态不变时免每请求
/// N 次 PEM 解析重建（Disabled 条目只增不减，重建成本随轮换历史线性
/// 增长，未认证端点可被放大为 CPU DoS）；时间桶界保证 retention 退役
/// 视图最多陈旧 1 分钟（配合 retention ≥ 2× access TTL 部署约定，退役
/// 钥签发的 token 在陈旧窗口内必已过期）。
async fn keystore_jwks_document_cached(
    state: &OAuth2State,
    keystore: &crate::oauth2_server::jwks::JwksKeystore,
    now: i64,
) -> GarrisonResult<Option<std::sync::Arc<crate::oauth2_server::jwks::JwkSet>>> {
    let now_bucket = now.div_euclid(60);
    let raw = keystore.state_raw().await?;
    let hash = state_content_hash(raw.as_deref());
    {
        let cache = state.jwks_doc_cache.lock().await;
        if let Some(entry) = cache.as_ref() {
            if entry.state_hash == hash
                && entry.now_bucket == now_bucket
                && entry.retention_secs == state.jwks_retention_secs
            {
                return Ok(Some(std::sync::Arc::clone(&entry.doc)));
            }
        }
    }
    let doc = std::sync::Arc::new(
        keystore
            .jwks_document(now, state.jwks_retention_secs)
            .await?,
    );
    {
        let mut cache = state.jwks_doc_cache.lock().await;
        *cache = Some(JwksDocCacheEntry {
            state_hash: hash,
            now_bucket,
            retention_secs: state.jwks_retention_secs,
            doc: std::sync::Arc::clone(&doc),
        });
    }
    Ok(Some(doc))
}

/// GET /oauth2/jwks.json — 导出非对称签名公钥 JWK Set。
///
/// 密钥库注入时从库发布（多 kid：Active ∪ Passive，retention 到期键即时移出）；
/// 否则退回单钥 `jwks_source`。fail-closed：两者皆未配置或发布集为空时 404
/// （不暴露空集合/对称密钥信息）。
///
/// `Cache-Control: max-age` 按 `jwks_retention_secs` 动态计算（retention 的一半，
/// 保证客户端在最早可能退役前重取 JWKS）。
async fn jwks_endpoint(State(state): State<Arc<OAuth2State>>) -> Response {
    let max_age = jwks_cache_max_age_secs(state.jwks_retention_secs);
    let cache_control = format!("public, max-age={max_age}");
    if let Some(keystore) = &state.jwks_keystore {
        let now = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => d.as_secs() as i64,
            Err(_) => return StatusCode::NOT_FOUND.into_response(),
        };
        return match keystore_jwks_document_cached(&state, keystore, now).await {
            Ok(Some(doc)) if !doc.keys.is_empty() => (
                StatusCode::OK,
                [(axum::http::header::CACHE_CONTROL, cache_control)],
                axum::Json((*doc).clone()),
            )
                .into_response(),
            Ok(_) => StatusCode::NOT_FOUND.into_response(),
            Err(e) => {
                // 状态损坏不静默：记日志后按 fail-closed 404（不暴露损坏细节）
                tracing::error!("jwks keystore document build failed: {e}");
                StatusCode::NOT_FOUND.into_response()
            },
        };
    }
    match &state.jwks_source {
        Some((algorithm, pem)) => match crate::oauth2_server::jwks::build_jwk_set(algorithm, pem) {
            Ok(jwk_set) => (
                StatusCode::OK,
                [(axum::http::header::CACHE_CONTROL, cache_control)],
                axum::Json(jwk_set),
            )
                .into_response(),
            Err(_) => StatusCode::NOT_FOUND.into_response(),
        },
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// JWKS 客户端缓存时长（秒）= retention 的一半（下限 1）。
///
/// 取一半是工程折中而非精确安全界：客户端最迟每 retention/2 重取，配合
/// 部署侧保证 `retention ≥ 2× access token TTL`，退役钥签发的 token 在
/// 任何缓存窗口内均已过期。
fn jwks_cache_max_age_secs(retention_secs: u64) -> u64 {
    (retention_secs / 2).max(1)
}

/// 构建内网 OAuth2 路由（introspect）。
pub fn oauth2_internal_router(state: Arc<OAuth2State>) -> Router {
    Router::new()
        .route("/oauth2/introspect", post(introspect_endpoint))
        .with_state(state)
}

// === HTTP 端点函数（薄包装，调用 handler） ===

/// 请求体大小上限（防 DoS：OAuth2 端点参数均为短字符串，64KB 足够）。
const OAUTH2_BODY_LIMIT: usize = 64 * 1024;

/// RFC 6749 §5.1 / §5.2 — token 端点所有响应（含错误）必须带 no-store 缓存头。
fn apply_no_store(mut resp: Response) -> Response {
    let headers = resp.headers_mut();
    headers.insert(
        HeaderName::from_static("cache-control"),
        HeaderValue::from_static("no-store"),
    );
    headers.insert(
        HeaderName::from_static("pragma"),
        HeaderValue::from_static("no-cache"),
    );
    resp
}

/// percent-decode `application/x-www-form-urlencoded` 的键/值（`+` 视为空格）。
fn form_percent_decode(input: &[u8]) -> String {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        match input[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            },
            b'%' if i + 2 < input.len() => {
                let hex = std::str::from_utf8(&input[i + 1..i + 3]).ok();
                match hex.and_then(|h| u8::from_str_radix(h, 16).ok()) {
                    Some(b) => {
                        out.push(b);
                        i += 3;
                    },
                    None => {
                        out.push(b'%');
                        i += 1;
                    },
                }
            },
            b => {
                out.push(b);
                i += 1;
            },
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// 将 `application/x-www-form-urlencoded` body 解析为 `serde_json::Value` 对象，
/// 复用请求结构体的 `serde_json` 反序列化路径（RFC 6749 §3.2 表单格式）。
fn parse_form_body(body: &[u8]) -> Result<serde_json::Value, String> {
    let mut map = serde_json::Map::new();
    for pair in body.split(|&b| b == b'&') {
        if pair.is_empty() {
            continue;
        }
        let mut it = pair.splitn(2, |&b| b == b'=');
        let key = form_percent_decode(it.next().unwrap_or_default());
        let value = form_percent_decode(it.next().unwrap_or_default());
        if key.is_empty() {
            return Err("empty form field name".to_string());
        }
        map.insert(key, serde_json::Value::String(value));
    }
    Ok(serde_json::Value::Object(map))
}

/// 按 Content-Type 提取请求结构体：仅接受 `application/x-www-form-urlencoded`
///（RFC 6749 §3.2 / RFC 7009 §2.1 / RFC 7662 §2.2 规定的唯一请求格式）。
///
/// Content-Type 缺失或为其他类型（含 `application/json`）返回
/// 415 Unsupported Media Type；表单解析或字段校验失败返回
/// 400 + RFC 6749 §5.2 `invalid_request` 错误体（均带 no-store 头）。
fn extract_oauth2_request<T: serde::de::DeserializeOwned>(
    content_type: Option<&str>,
    body: &[u8],
) -> Result<T, Box<Response>> {
    let is_form = content_type
        .map(|ct| ct.starts_with("application/x-www-form-urlencoded"))
        .unwrap_or(false);
    if !is_form {
        return Err(Box::new(apply_no_store(
            (
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                Json(json!({
                    "error": "invalid_request",
                    "message": "Content-Type must be application/x-www-form-urlencoded"
                })),
            )
                .into_response(),
        )));
    }
    match parse_form_body(body).and_then(|v| serde_json::from_value(v).map_err(|e| e.to_string())) {
        Ok(req) => Ok(req),
        Err(e) => Err(Box::new(apply_no_store(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_request", "message": e })),
            )
                .into_response(),
        ))),
    }
}

/// 限流错误桥接：token handler 的速率限制错误统一以
/// `GarrisonError::OAuth2("rate_limited: ...")` 形态产出（见
/// `oauth2_server::token` 的 `TokenRateLimiter` / `PasswordRateLimiter`，
/// `rate_limited` 消息前缀为跨层契约），此处映射为 `RateLimited` 变体，
/// 使 `retry_after_secs()` 与 `Retry-After` 响应头真实可达。
///
/// `Retry-After` 取值：滑动窗口 TTL 起点在首次计数时确立，桥接处拿不到
/// 精确剩余秒数，故取 `TokenHandler::rate_limit_window_upper_bound_secs()`
/// （限流器配置窗口上界）作保守提示——客户端不早于任一窗口过期重试。
fn bridge_rate_limited_error(
    e: crate::error::GarrisonError,
    retry_hint_secs: u64,
) -> crate::error::GarrisonError {
    match e {
        crate::error::GarrisonError::OAuth2(msg) if msg.starts_with("rate_limited") => {
            crate::error::GarrisonError::RateLimited {
                retry_after_secs: retry_hint_secs,
            }
        },
        other => other,
    }
}

/// OIDC 端点自建错误体（RFC 6749 `{"error": ...}` 信封）仅补 `Retry-After` 头：
/// body 键保持 OAuth2 惯例不动，限流语义经响应头表达（R04 统一错误模型）。
/// `Retry-After` 仅在错误桥接为 `RateLimited` 后可达（真实 429 路径），
/// 其余 OAuth2 错误为防御性 no-op。
fn with_retry_after(
    mut response: axum::response::Response,
    e: &crate::error::GarrisonError,
) -> axum::response::Response {
    if let Some(secs) = e.retry_after_secs() {
        response.headers_mut().insert(
            axum::http::header::HeaderName::from_static("retry-after"),
            axum::http::HeaderValue::from(secs),
        );
    }
    response
}

async fn authorize_endpoint(
    State(state): State<Arc<OAuth2State>>,
    Query(req): Query<AuthorizeRequest>,
    principal: Option<Extension<GarrisonPrincipal>>,
) -> Response {
    // 从 GarrisonPrincipal Extension 提取 user_id（无 principal 或 login_id 解析失败 → None → LoginRequired）
    let user_id: Option<i64> = principal.and_then(|ext| ext.0.login_id.parse::<i64>().ok());
    // prompt 参数（OIDC Core §3.1.2.1）：none/login 语义仅在显式出现时生效
    let response = if req.prompt.is_some() {
        state
            .authorize_handler
            .authorize_with_prompt(&req, user_id, req.prompt_hint())
            .await
    } else {
        state.authorize_handler.authorize(&req, user_id).await
    };
    match response {
        Ok(AuthorizeResponse::Redirect { location }) => {
            (StatusCode::FOUND, [("Location", location)]).into_response()
        },
        Ok(AuthorizeResponse::LoginRequired { login_url }) => {
            (StatusCode::FOUND, [("Location", login_url)]).into_response()
        },
        Err(e) => {
            let (_, error_code, message, _) = e.response_parts_i18n();
            with_retry_after(
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": error_code, "message": message })),
                )
                    .into_response(),
                &e,
            )
        },
    }
}

/// GET /oauth2/authorize/resume — 登录后凭票据续流（R18 两段式）。
///
/// user_id 取自 GarrisonPrincipal 会话（登录往返建立），不经 query 传入——
/// 票据本身不绑定主体，续流主体以会话为准；未登录 → LoginRequired 重发新
/// 票据（resumable 循环防护：resume 消费旧票据后签发新票据）。
async fn authorize_resume_endpoint(
    State(state): State<Arc<OAuth2State>>,
    Query(params): Query<std::collections::HashMap<String, String>>,
    principal: Option<Extension<GarrisonPrincipal>>,
) -> Response {
    let Some(ticket) = params.get("ticket").cloned() else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "invalid_request",
                "message": loc!("oauth2-resume-ticket-missing", "missing ticket".to_string())
            })),
        )
            .into_response();
    };
    let user_id: Option<i64> = principal.and_then(|ext| ext.0.login_id.parse::<i64>().ok());
    match state.authorize_handler.resume(&ticket, user_id, &[]).await {
        Ok(AuthorizeResponse::Redirect { location }) => {
            (StatusCode::FOUND, [("Location", location)]).into_response()
        },
        Ok(AuthorizeResponse::LoginRequired { login_url }) => {
            (StatusCode::FOUND, [("Location", login_url)]).into_response()
        },
        Err(e) => {
            let (_, error_code, message, _) = e.response_parts_i18n();
            with_retry_after(
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": error_code, "message": message })),
                )
                    .into_response(),
                &e,
            )
        },
    }
}

async fn token_endpoint(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    // 提取 Authorization 头（RFC 6749 §2.3.1 HTTP Basic Auth）
    let authorization = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // RFC 6749 §3.2：/token 仅接受 application/x-www-form-urlencoded
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    if body.len() > OAUTH2_BODY_LIMIT {
        return apply_no_store(
            (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_request", "message": "request body too large" })),
            )
                .into_response(),
        );
    }
    let req: TokenRequest = match extract_oauth2_request(content_type, &body) {
        Ok(req) => req,
        Err(resp) => return *resp,
    };

    match state
        .token_handler
        .handle_with_authorization(&req, authorization.as_deref())
        .await
    {
        Ok(resp) => {
            // RFC 6749 §5.1 — token 响应必须含 Cache-Control: no-store + Pragma: no-cache
            apply_no_store((StatusCode::OK, Json(resp)).into_response())
        },
        Err(e) => {
            // 限流错误桥接为 RateLimited（见 bridge 函数 doc），使 429 判定与
            // Retry-After 头基于变体而非消息前缀
            let e = bridge_rate_limited_error(
                e,
                state.token_handler.rate_limit_window_upper_bound_secs(),
            );
            let (_, error_code, message, _) = e.response_parts_i18n();
            // RFC 6585 §4 — 速率限制错误返回 429 Too Many Requests。
            let is_rate_limited = matches!(e, crate::error::GarrisonError::RateLimited { .. });
            let status = if is_rate_limited {
                StatusCode::TOO_MANY_REQUESTS
            } else {
                StatusCode::BAD_REQUEST
            };
            let body_error: &str = if is_rate_limited {
                "RATE_LIMIT_EXCEEDED"
            } else {
                error_code
            };
            // RFC 6749 §5.1 — token 端点错误响应同样必须 no-store
            apply_no_store(with_retry_after(
                (
                    status,
                    Json(json!({ "error": body_error, "message": message })),
                )
                    .into_response(),
                &e,
            ))
        },
    }
}

async fn revoke_endpoint(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    let req: RevokeRequest = match extract_oauth2_request(content_type, &body) {
        Ok(req) => req,
        Err(resp) => return *resp,
    };
    match state.revoke_handler.handle(&req).await {
        // RFC 7662 §2.2 — introspect/revoke 响应应带 no-store 缓存控制
        Ok(()) => apply_no_store(StatusCode::NO_CONTENT.into_response()),
        Err(e) => {
            let (_, error_code, message, _) = e.response_parts_i18n();
            apply_no_store(with_retry_after(
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": error_code, "message": message })),
                )
                    .into_response(),
                &e,
            ))
        },
    }
}

async fn introspect_endpoint(
    State(state): State<Arc<OAuth2State>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Response {
    let content_type = headers
        .get(axum::http::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok());
    let req: IntrospectRequest = match extract_oauth2_request(content_type, &body) {
        Ok(req) => req,
        Err(resp) => return *resp,
    };
    match state.introspect_handler.handle(&req).await {
        Ok(resp) => apply_no_store((StatusCode::OK, Json(resp)).into_response()),
        Err(e) => {
            let (_, error_code, message, _) = e.response_parts_i18n();
            apply_no_store(with_retry_after(
                (
                    StatusCode::BAD_REQUEST,
                    Json(json!({ "error": error_code, "message": message })),
                )
                    .into_response(),
                &e,
            ))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::{GarrisonDao, InMemoryDao};
    use crate::oauth2_server::client::{
        DaoOAuth2ClientStore, GrantType, OAuth2Client, OAuth2ClientStore,
    };
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// 创建测试用 OAuth2State + store（用于注册客户端）。
    fn make_state() -> (Arc<OAuth2State>, Arc<dyn OAuth2ClientStore>) {
        let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
        let store: Arc<dyn OAuth2ClientStore> = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
        let state = Arc::new(OAuth2State::new(
            store.clone(),
            dao,
            "https://auth.example.com/login".to_string(),
        ));
        (state, store)
    }

    /// 进程内日志捕获 writer（fmt Layer 的 MakeWriter，收集格式化行）。
    #[derive(Clone)]
    struct LogCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for LogCapture {
        type Writer = LogCaptureWriter;
        fn make_writer(&'a self) -> Self::Writer {
            LogCaptureWriter(self.0.clone())
        }
    }

    struct LogCaptureWriter(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

    impl std::io::Write for LogCaptureWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("日志缓冲锁应可用")
                .push(String::from_utf8_lossy(buf).to_string());
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// OAuth2State::new 构造完成时的结构性告警（T032）：refresh grant 可用
    /// （db-sqlite）但 RefreshTokenRotation 未注入 → 构造期输出结构化 warn
    /// （含重放检测不可用后果与修复指引），探针 has_refresh_rotation 为 false。
    #[cfg(feature = "db-sqlite")]
    #[test]
    #[serial_test::serial]
    fn oauth2_state_new_without_rotation_warns_at_construction() {
        use tracing_subscriber::layer::SubscriberExt;
        use tracing_subscriber::util::SubscriberInitExt;

        let capture = LogCapture(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_ansi(false)
                .with_writer(capture.clone()),
        );

        let _guard = subscriber.set_default();
        // interest 缓存是进程级全局态：并行非订阅者测试可能抢先首次注册告警
        // callsite 并缓存 Interest::never（事件被宏直接剔除），须显式重建
        tracing::callsite::rebuild_interest_cache();

        // 以捕获到告警判断捕获有效，缺失则重建 interest 后重试构造
        let mut logs: Vec<String> = Vec::new();
        for _ in 0..3 {
            let (state, _store) = make_state();
            assert!(
                !state.token_handler.has_refresh_rotation(),
                "OAuth2State::new 默认不注入 rotation，探针应为 false"
            );
            logs = capture.0.lock().expect("日志缓冲锁应可用").clone();
            if logs.iter().any(|l| {
                l.contains("without RefreshTokenRotation") && l.contains("reuse detection")
            }) {
                break;
            }
            tracing::callsite::rebuild_interest_cache();
        }
        assert!(
            logs.iter().any(|l| {
                l.contains("without RefreshTokenRotation") && l.contains("reuse detection")
            }),
            "构造期应输出结构化退化 warn（含 reuse detection 不可用后果），日志: {:?}",
            logs
        );
    }

    /// 创建测试用 OAuth2Client（支持 AuthorizationCode + ClientCredentials）。
    fn make_test_client(id: &str) -> OAuth2Client {
        OAuth2Client::new(
            id,
            "secret-123",
            vec!["https://app.example.com/cb".into()],
            vec![GrantType::AuthorizationCode, GrantType::ClientCredentials],
            vec!["read".into()],
        )
        .unwrap()
    }

    // === OAuth2State 构造测试 ===

    #[test]
    fn test_oauth2_state_construction() {
        let (state, _) = make_state();
        // authorize_handler 被 state + token_handler 共享 → strong_count = 2
        assert_eq!(Arc::strong_count(&state.authorize_handler), 2);
        // token_handler 被 state + revoke_handler + introspect_handler 共享 → strong_count = 3
        assert_eq!(Arc::strong_count(&state.token_handler), 3);
        // revoke_handler / introspect_handler 仅被 state 持有 → strong_count = 1
        assert_eq!(Arc::strong_count(&state.revoke_handler), 1);
        assert_eq!(Arc::strong_count(&state.introspect_handler), 1);
    }

    // === 路由存在性测试 ===

    #[tokio::test]
    async fn test_oauth2_external_router_has_authorize_route() {
        let (state, store) = make_state();
        store.create(make_test_client("route-auth")).await.unwrap();
        let app = oauth2_external_router(state);
        // 无 query string → Query 提取失败 → 400（非 404 证明路由存在）
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/oauth2/authorize")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_oauth2_external_router_has_token_route() {
        let (state, _) = make_state();
        let app = oauth2_external_router(state);
        // 表单 body 缺字段 → 400（非 404 证明路由存在）
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("grant_type=client_credentials"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_oauth2_external_router_has_revoke_route() {
        let (state, _) = make_state();
        let app = oauth2_external_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/revoke")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("token=x&client_id=c&client_secret=s"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_ne!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_oauth2_internal_router_has_introspect_route() {
        let (state, store) = make_state();
        store.create(make_test_client("route-int")).await.unwrap();
        let app = oauth2_internal_router(state);
        let body = "token=nonexistent&client_id=route-int&client_secret=secret-123";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/introspect")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // token 不存在 → active=false，但返回 200 OK
        assert_eq!(resp.status(), StatusCode::OK);
    }

    /// resume 缺 ticket → 400 + `invalid_request`，message 经 Fluent i18n：
    /// zh locale 下返回 `oauth2-resume-ticket-missing` 的中文翻译
    /// （与英文 fallback 文案可区分，命中即证明响应体未硬编码英文）。
    #[tokio::test]
    async fn test_authorize_resume_missing_ticket_message_is_localized() {
        let (state, _) = make_state();
        let app = oauth2_external_router(state);
        let _guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/oauth2/authorize/resume")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        // RFC 6749 协议 token 保持不变，仅 message 走 i18n
        assert_eq!(json["error"], "invalid_request");
        assert!(
            json["message"].as_str().unwrap().contains("参数缺失"),
            "zh locale 应返回 Fluent 翻译，实际: {}",
            json["message"]
        );
    }

    // === 端点行为测试 ===

    #[tokio::test]
    async fn test_authorize_endpoint_redirects_when_not_logged_in() {
        let (state, store) = make_state();
        store.create(make_test_client("auth-redir")).await.unwrap();
        let app = oauth2_external_router(state);
        let uri = "/oauth2/authorize?response_type=code&client_id=auth-redir&redirect_uri=https://app.example.com/cb&code_challenge=test-challenge&code_challenge_method=S256";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp
            .headers()
            .get("Location")
            .expect("Location header 必须存在")
            .to_str()
            .unwrap();
        assert!(
            location.starts_with("https://auth.example.com/login"),
            "应重定向到登录页，实际: {location}"
        );
    }

    /// 有 GarrisonPrincipal（Extension）时 authorize 端点返回 Redirect 含 code。
    /// principal.login_id = "1001" → user_id = Some(1001) → 授权成功 → Redirect。
    #[tokio::test]
    async fn test_authorize_endpoint_returns_redirect_with_code_when_principal_present() {
        let (state, store) = make_state();
        store
            .create(make_test_client("auth-principal"))
            .await
            .unwrap();
        let app = oauth2_external_router(state).layer(Extension(GarrisonPrincipal {
            login_id: "1001".to_string(),
        }));
        let uri = "/oauth2/authorize?response_type=code&client_id=auth-principal&redirect_uri=https://app.example.com/cb&code_challenge=test-challenge&code_challenge_method=S256";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp
            .headers()
            .get("Location")
            .expect("Location header 必须存在")
            .to_str()
            .unwrap();
        assert!(
            location.starts_with("https://app.example.com/cb?code="),
            "有 principal 时应重定向到 redirect_uri 含 code，实际: {location}"
        );
    }

    /// 无 GarrisonPrincipal（Extension 缺失）时 authorize 端点返回 LoginRequired。
    #[tokio::test]
    async fn test_authorize_endpoint_returns_login_required_when_no_principal() {
        let (state, store) = make_state();
        store
            .create(make_test_client("auth-no-principal"))
            .await
            .unwrap();
        // 无 .layer(Extension(...)) → principal 提取为 None
        let app = oauth2_external_router(state);
        let uri = "/oauth2/authorize?response_type=code&client_id=auth-no-principal&redirect_uri=https://app.example.com/cb&code_challenge=test-challenge&code_challenge_method=S256";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri(uri)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::FOUND);
        let location = resp
            .headers()
            .get("Location")
            .expect("Location header 必须存在")
            .to_str()
            .unwrap();
        assert!(
            location.starts_with("https://auth.example.com/login"),
            "无 principal 应重定向到登录页，实际: {location}"
        );
    }

    #[tokio::test]
    async fn test_token_endpoint_returns_bad_request_on_invalid_client() {
        let (state, _) = make_state();
        let app = oauth2_external_router(state);
        let body = "grant_type=client_credentials&client_id=no-such-client&client_secret=secret";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// token 端点成功响应必须含 Cache-Control: no-store + Pragma: no-cache（RFC 6749 §5.1）。
    #[tokio::test]
    async fn test_token_endpoint_returns_cache_control_no_store_header() {
        let (state, store) = make_state();
        store.create(make_test_client("cc-cid")).await.unwrap();
        let app = oauth2_external_router(state);
        let body = "grant_type=client_credentials&client_id=cc-cid&client_secret=secret-123";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        // RFC 6749 §5.1 — 必须含 Cache-Control: no-store
        let cache_control = resp
            .headers()
            .get("cache-control")
            .expect("Cache-Control 头必须存在");
        assert_eq!(
            cache_control.to_str().unwrap(),
            "no-store",
            "Cache-Control 必须为 no-store"
        );
        // RFC 6749 §5.1 — 必须含 Pragma: no-cache
        let pragma = resp.headers().get("pragma").expect("Pragma 头必须存在");
        assert_eq!(
            pragma.to_str().unwrap(),
            "no-cache",
            "Pragma 必须为 no-cache"
        );
    }

    /// token 端点接受 HTTP Basic Auth 头认证客户端（RFC 6749 §2.3.1）。
    #[tokio::test]
    async fn test_token_endpoint_accepts_basic_auth_header() {
        use base64::engine::general_purpose::STANDARD;
        use base64::Engine;
        let (state, store) = make_state();
        store.create(make_test_client("basic-cid")).await.unwrap();
        let app = oauth2_external_router(state);
        // "basic-cid:secret-123" → base64
        let credentials = STANDARD.encode("basic-cid:secret-123");
        let auth_header = format!("Basic {}", credentials);
        let body = "grant_type=client_credentials";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .header("authorization", &auth_header)
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "Basic Auth 认证应成功，body 留空"
        );
    }

    #[tokio::test]
    async fn test_revoke_endpoint_returns_no_content_on_success() {
        let (state, store) = make_state();
        store.create(make_test_client("rev-ok")).await.unwrap();
        let app = oauth2_external_router(state);

        // 1. 先通过 client_credentials 签发 token
        let issue_body = "grant_type=client_credentials&client_id=rev-ok&client_secret=secret-123";
        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(issue_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let token_resp: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let token = token_resp["access_token"].as_str().expect("access_token");

        // 2. 撤销 token（RFC 7009 §2.1 表单格式）
        let revoke_body = format!("token={}&client_id=rev-ok&client_secret=secret-123", token);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/revoke")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(revoke_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    }

    // === /token 端点速率限制测试（B5）===

    /// /token 端点超速率限制时返回 429 Too Many Requests（RFC 6585 §4）。
    ///
    /// 注入 `TokenRateLimiter`（client_max=1），第 2 次请求应返回 429 + `RATE_LIMIT_EXCEEDED`。
    #[tokio::test]
    async fn test_token_endpoint_returns_429_on_rate_limit_exceeded() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
        let store: Arc<dyn OAuth2ClientStore> = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
        let authorize_handler = Arc::new(AuthorizeHandler::new(
            store.clone(),
            dao.clone(),
            "https://auth.example.com/login".to_string(),
        ));
        let token_handler = Arc::new(TokenHandler::new(
            store.clone(),
            dao.clone(),
            authorize_handler.clone(),
            Arc::new(PasswordRateLimiter::new(1000, 300)),
            Arc::new(TokenRateLimiter::with_limits(1, 60, 100, 60)),
        ));
        let revoke_handler = Arc::new(RevokeHandler::new(store.clone(), token_handler.clone()));
        let introspect_handler =
            Arc::new(IntrospectHandler::new(store.clone(), token_handler.clone()));
        let state = Arc::new(OAuth2State {
            authorize_handler,
            token_handler,
            revoke_handler,
            introspect_handler,
            client_store: store.clone(),
            jwks_source: None,
            issuer: None,
            jwks_keystore: None,
            oidc_discovery_enabled: false,
            password_grant_advertised: false,
            scopes_cache: tokio::sync::RwLock::new(None),
            jwks_doc_cache: tokio::sync::Mutex::new(None),
            jwks_retention_secs: crate::config::DEFAULT_JWKS_RETENTION_SECS,
        });

        store.create(make_test_client("rl-429")).await.unwrap();
        let app = oauth2_external_router(state);

        let body = "grant_type=client_credentials&client_id=rl-429&client_secret=secret-123";

        let resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // 第 2 次被限速（429 Too Many Requests）
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "超速率限制应返回 429"
        );

        // R04 统一错误模型：429 必须携带 Retry-After 头（rate_limited 错误桥接
        // RateLimited 后经 with_retry_after 输出）。值为限流器配置窗口上界的
        // 保守提示：本测试 PasswordRateLimiter 窗口 300s、TokenRateLimiter
        // 双窗口 60s → 上界 300。
        assert_eq!(
            resp.headers()
                .get("retry-after")
                .and_then(|v| v.to_str().ok()),
            Some("300"),
            "429 响应必须携带 Retry-After 头"
        );

        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(
            resp_json["error"].as_str().unwrap(),
            "RATE_LIMIT_EXCEEDED",
            "error code 应为 RATE_LIMIT_EXCEEDED"
        );
    }

    /// /token 端点非 rate_limited 错误返回 400（与限速 429 区分）。
    #[tokio::test]
    async fn test_token_endpoint_returns_400_on_non_rate_limited_error() {
        let (state, store) = make_state();
        store.create(make_test_client("nrl-400")).await.unwrap();
        let app = oauth2_external_router(state);

        // 用错误 client_secret 触发 OAuth2 错误（非 rate_limited）
        let body = "grant_type=client_credentials&client_id=nrl-400&client_secret=wrong-secret";

        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        // 非 rate_limited 错误应返回 400（非 429）
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    /// 限流错误桥接（H1）：`rate_limited` 前缀的 OAuth2 错误映射为 RateLimited
    /// （Retry-After 秒数可达），其余 OAuth2 错误原样保留。
    #[test]
    fn bridge_rate_limited_error_maps_prefix_and_preserves_others() {
        use crate::error::GarrisonError;

        let bridged = bridge_rate_limited_error(
            GarrisonError::OAuth2("rate_limited: client requests too frequent".to_string()),
            300,
        );
        assert!(
            matches!(bridged, GarrisonError::RateLimited { .. }),
            "rate_limited 前缀错误应桥接为 RateLimited，实际: {bridged:?}"
        );
        assert_eq!(
            bridged.retry_after_secs(),
            Some(300),
            "桥接后 Retry-After 秒数必须可达"
        );

        let passthrough = bridge_rate_limited_error(
            GarrisonError::OAuth2("invalid_client: nope".to_string()),
            300,
        );
        assert!(
            matches!(passthrough, GarrisonError::OAuth2(_)),
            "非 rate_limited 前缀错误不得被改写: {passthrough:?}"
        );
        assert_eq!(passthrough.retry_after_secs(), None);
    }

    // === 表单格式（RFC 6749 §3.2）+ 错误响应 no-store 测试 ===

    /// token 端点接受 application/x-www-form-urlencoded 请求体（RFC 6749 §3.2）。
    #[tokio::test]
    async fn test_token_endpoint_accepts_form_urlencoded() {
        let (state, store) = make_state();
        store.create(make_test_client("form-tok")).await.unwrap();
        let app = oauth2_external_router(state);
        let body = "grant_type=client_credentials&client_id=form-tok&client_secret=secret-123";
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header(
                        "content-type",
                        "application/x-www-form-urlencoded;charset=UTF-8",
                    )
                    .body(Body::from(body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "表单编码的 token 请求应被接受（RFC 6749 §3.2）"
        );
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(resp_json["access_token"].as_str().is_some());
    }

    /// token 端点表单体支持 percent-encoding 与 `+` 空格。
    #[test]
    fn parse_form_body_decodes_percent_and_plus() {
        let value =
            parse_form_body(b"grant_type=password&username=a%40b.com+cd%26x&code=%E4%B8%AD")
                .unwrap();
        assert_eq!(value["username"], "a@b.com cd&x");
        assert_eq!(value["code"], "中");
    }

    /// 畸形请求体返回 400 + invalid_request（不再 panic / 500）。
    #[tokio::test]
    async fn test_token_endpoint_malformed_body_returns_400_invalid_request() {
        let (state, _) = make_state();
        let app = oauth2_external_router(state);
        // 空字段名 → parse_form_body 解析失败
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/x-www-form-urlencoded")
                    .body(Body::from("grant_type=a&=b"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
        let cache_control = resp
            .headers()
            .get("cache-control")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let pragma = resp
            .headers()
            .get("pragma")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(resp_json["error"], "invalid_request");
        // 错误响应同样必须 no-store（RFC 6749 §5.1）
        assert_eq!(cache_control.as_deref(), Some("no-store"));
        assert_eq!(pragma.as_deref(), Some("no-cache"));
    }

    /// Content-Type 缺失时返回 415 Unsupported Media Type（RFC 6749 §3.2 唯一格式）。
    #[tokio::test]
    async fn test_token_endpoint_missing_content_type_returns_415() {
        let (state, _) = make_state();
        let app = oauth2_external_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .body(Body::from(
                        "grant_type=client_credentials&client_id=x&client_secret=y",
                    ))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("no-store")
        );
    }

    /// Content-Type 为 `application/json` 时返回 415（JSON 已不再被接受）。
    #[tokio::test]
    async fn test_token_endpoint_json_content_type_returns_415() {
        let (state, _) = make_state();
        let app = oauth2_external_router(state);
        let resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/oauth2/token")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"grant_type":"client_credentials"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let resp_json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(resp_json["error"], "invalid_request");
    }
}

#[cfg(test)]
mod jwks_tests {
    use super::*;
    use crate::dao::{GarrisonDao, InMemoryDao};
    use crate::oauth2_server::client::{DaoOAuth2ClientStore, OAuth2ClientStore};
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// 测试专用 RSA 2048 私钥（非真实凭证）。
    // nosemgrep: generic.secrets.security.detected-private-key.detected-private-key —— CI 已验证的测试夹具 PEM（假钥，非真实凭证）
    const JWKS_TEST_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDMQoXOvmvs4kpj
nYshns5CYyNziLt/xBQBZtlkzY3KUuHtJMz9zK0TTz0DbhCnDCWF8tpWqxHBTtON
pMnnC6bTN4Wg/PWDn67hub23b4xAKq5qH45RmWn4a0TGTUyQktebjlCiWBlMCo43
j7FLyvGrOx3SmyUUaI5vh02Pf5Swg2CCQ69ht3L58jM6lp+jILJ4gEjNC2hmaWgH
bbYhTX5qCaPgZTndfgPXX9wkDG8jhpgRpfwmSuJ4aRiRrjvgycWuPccryX7aXiBU
c5H8rdKVgnjPTzSL8h3P/2tpZkNj5OFBZKTgmdPuwF87Mjlbr7Oi2xpCIpNpnyF1
L8G/mIIRAgMBAAECggEAY2vnzIOEbceRtN4cuC8fr1GpElXWCfELWclRfI7O+tGP
9YlpnAmxnsn9ZTuAMIcphoL4QqI+4Kw5LeMtgV/7AikuyncGG9ywV1+819ocVqlP
vwkAEXjOi2PPFITQhThsaOODHRorqgcjRSkUf9NXAWUjdX0dtcrUtbWSi4vqeGWC
O0Ni/9iWJYFjAgHu+XJgYXZtn7sJGe30PuIFmiKHfHuuM9alo6SubQ3UU80B+hQm
N4VVuYN+dYmGsekp+Ofj65mq2+WAyvHE2V9OB92L+yVY0uKZ428eXdN9ydp8kVqh
yOW2yLTq6sBNBOi/F/DMim6QrIzn6zpp0hXyc97d1wKBgQD+2qQOQ+urTE1ymdXT
C/os5kMrjsYd/rfcMaBbl4XmDE/PjlJg1Z6yVBGMmvM/shjTslcV8kgKyKf+aHm1
b3ckgu9PLtoYGX0yjeHbYCidwkjJPz8sy5pIFHslY/bGhV5RqsSPJo1aX2En0c4R
3cJHGGGn2YguQuWSOU94VTKgowKBgQDNLaS9Q08j/tiozEY23oH9i5p5iSwxc3It
hS/UwLYNFad6byRiDgVlvx+sVHZfLBsmNMlHEY+oMGocctqGAC8+a0pvtaLnU12/
GI61axWfAlCJrYs3CBOKwOH3hBM04mqPUb2ySHdlzPawpIr55jMkohuXXyw/22je
pK7iIPHZuwKBgQC+/Gi/TAUbjQXpIQHNtAcaiMDDrq4nolB00jfjC81LVeSlnXl8
mfngmAHCxggOrs/OLbL3fmagtji2/eJfppW5penjBDBqqQda0Fr2xLwLZaKYNi6I
ylfnNnoGzkAMC7xgJUJCKNj7ZcjwR1lPqElEcDAW0n0sdfOGvi4g9nAHUwKBgGIB
E1dz9zFyYXr/V+qNjfnV3QuAgiN8yWUE4Tv2cP7/AOhyfiZ4HAvlpvNhxMjhAHbX
b+0KblwgBA9irQ6kt+xQw1VopU9perX0vPXbGJDDQkUBKCY5LVxxlX3tEF+KZuve
V4X5J07xAESP0/JaCsPMyvEa/L/jxcvTTdWlduBRAoGBAPx2MMqUGXa+UZ+a0cyF
tW0xGglEWCX+e2vSNf31v4FyoGxNi6h2ap2OWEddpGttS+UbOzO9BlzcCtYJvPwW
lRVGEQXEoVyslCUwTlV8LmtrJS6Xl9YwRHmmajJMH6GJTk/CToOLIvj2bOMxHW5A
dzWfBsm+KAfTJuqbV7VnJL3G
-----END PRIVATE KEY-----
";

    // nosemgrep: generic.secrets.security.detected-private-key.detected-private-key —— CI 已验证的测试夹具 PEM（假钥，非真实凭证）
    const JWKS_TEST_RSA_PEM_ALT: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC751S0Pf/oKnCq
AvE+iD2TB3fvkUXTiHfGgVHXfuFrVnam2DV9rPAWtzj78N/n4SzwIojGGzPFZtpd
Kw+VMWOEf0y5kTwOYEIAGJel6MPZBm8r2BqkgiDUw4usrI9BCRy9zRuDighMWoo0
r23RtOglWjwh6YbEXkg+dlaaFzuwZbtd7zOokVcd7MlXV51PRGT3HHbLekMJqKjM
+L+cN7NSoR6CsWHSqx8HlEJ8VQyNizsO1wKFo6gUSzGPeMH1uNMVxguI2OOzM8NS
8iEJmvMtVbcUxdYgIgFCol8ibBXYBsRQ02/arulEts3DoNJ/dOqt3uWaHv/+SVpc
CjdCgxdXAgMBAAECggEABSHWYG3pFXBDT4FxEWIrPF7R2cs/+v0ZOGTD1XzzrzjX
WMtC+sHEdPpgJhF4LB8sWQq4baDEkzmx8SWB8XM94pqPf+oFl+btJo+FZNSstLrG
Qo5Oe/vJ5cXJhNfZuc8D5/M4MymL/HnkmHfKKhYk2RBT4CE+uxJQKtSUnPTRfonc
v74IXU9mgrEWyhRnRLDCQTDS+MiFx+ca+Q2j3A3VXb6mLngi7+MlCTHesOrNi/h4
Krh6gXQDE3xw4oWlSy59zRXswrThFeNePbtN5suqHrGfhAJqvcVTuJRNPBL1OhYL
z9Fw+i5ypa0IFiiWmzIdTf6Z8fWAIRa16Gi7HofgYQKBgQDyasNqMmH2SJZ0X5Sk
RNsrHXlCVHdofP7B/w1mRXdXQN7bEdt+TkgHBOqO+005kHqcpjnm8GfKwaTVo9UK
cpYYDg11mBTULFn8BFKMH+MEzYTjKrHjA62DlM9PfdmKjPDXqJceWG1bp6Z2d+Rd
U0TfkTQLKmWihLYTUn2+c/gIWQKBgQDGbqAv9KU/7SKiUNVfSMMw/YYBm2jjEdQb
++IQuugzg0/cTwm+5sVbdzwqqt0jihO+2KWDbEHLqRndEeRjA5hvk+qp316MaeV8
x/dySeNG/lCnobiY+9ZjF14Zmaz1jGe+oAwmqGF4beoL5hkF77tFKUQtBRzkZgFC
A7yXzdQnLwKBgQCUu/Cd7b+xLiQxzpsSlrSqJXFKwyxoTZi5SlXcU+6++CxD2RcE
zd7ff6Kyi3l8QisYhdys1v+3pUwPUG/b8yYoKCcV6XOOIpArUjObiczuG3LXNlDi
alVBkEIKEbsxiPwUNXpSwgqG27wEn9bbc8WkLiDyYNbu+eIExO4ltl2OMQKBgHYk
KTVEGBruab9wFwmq/aOuXdmZGKKQ29NpbRf+3/7DgImveSLyrLAfVnAk2JKvQ8BN
poWPr8C8xkxLucmFu306+Oz4s4cwCVT4jYe7HBkJkyWq8IgM8ICAyiK9zy9G0AG7
smBVwep8rms1LNLO/5VW02NmduQ5IyiVpvROtLA7AoGBALycmaxr5wjzgTiw0oyh
/SSBunDWL23NnXrjjnLZ9BsmglkQUvhtkaA9AquuGJA4RiVxznoQQ6iXgZV80+Ui
j3MTO7dWRoAlfHi/NMU1BNA7zXLA2xPP/ekmHfb3PwCt5AhZTl43dEL+8V3xNlxp
HxmxsMlpmvvbydfhRl3OoqMR
-----END PRIVATE KEY-----
    ";

    fn make_state() -> OAuth2State {
        let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
        let store: Arc<dyn OAuth2ClientStore> = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
        OAuth2State::new(store, dao, "http://localhost/login".into())
    }

    /// 未配置非对称签名密钥：404（fail-closed）。
    #[tokio::test]
    async fn jwks_endpoint_returns_404_without_source() {
        let app = oauth2_external_router(Arc::new(make_state()));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/oauth2/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// 多 kid 密钥库：JWKS 输出含 Active ∪ Passive 两把钥。
    #[tokio::test]
    async fn jwks_endpoint_serves_keystore_with_multiple_kids() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
        let keystore = Arc::new(crate::oauth2_server::jwks::JwksKeystore::new(dao.clone()));
        // 时间戳取真实时钟相对值（端点按当前时刻应用 retention，合成小时间戳
        // 会被判超期）。旧钥 5000s 前轮换、retention 10_000 → 仍 Passive 在发布面。
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        keystore
            .rotate("RS256", JWKS_TEST_RSA_PEM, now - 5_000, 10_000)
            .await
            .unwrap();
        keystore
            .rotate("RS256", JWKS_TEST_RSA_PEM_ALT, now - 1_000, 10_000)
            .await
            .unwrap();
        let state = make_state()
            .with_issuer("https://auth.example.com")
            .with_jwks_keystore(keystore)
            .with_jwks_retention_secs(10_000);
        let app = oauth2_external_router(Arc::new(state));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/oauth2/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let keys = json["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2, "Active + Passive 两把钥都必须发布");
        assert_ne!(keys[0]["kid"], keys[1]["kid"]);
        assert!(!json.to_string().contains("PRIVATE KEY"));
    }

    /// retention 退役：超期 Passive 从 JWKS 输出移除（服务视图即时生效）。
    #[tokio::test]
    async fn jwks_endpoint_excludes_retired_kid() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
        let keystore = Arc::new(crate::oauth2_server::jwks::JwksKeystore::new(dao.clone()));
        // retention 计时基准是 Passive 转换时刻（token 签发持续到该时刻）：
        // kid1 在 30_000s 前激活、15_000s 前被轮换转 Passive，超 retention 10_000
        // → retire_expired 落库 Disabled，端点按当前时刻将其移出发布面
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i64;
        let first = keystore
            .rotate("RS256", JWKS_TEST_RSA_PEM, now - 30_000, 10_000)
            .await
            .unwrap();
        keystore
            .rotate("RS256", JWKS_TEST_RSA_PEM_ALT, now - 15_000, 10_000)
            .await
            .unwrap();
        let retired = keystore.retire_expired(now, 10_000).await.unwrap();
        assert_eq!(
            retired,
            vec![first.activated_kid.clone()],
            "超期 Passive 必须落库退役"
        );
        let state = make_state()
            .with_issuer("https://auth.example.com")
            .with_jwks_keystore(keystore)
            .with_jwks_retention_secs(10_000);
        let app = oauth2_external_router(Arc::new(state));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/oauth2/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["keys"].as_array().unwrap().len(),
            1,
            "退役钥必须移出 JWKS"
        );
    }

    /// Cache-Control max-age 按 jwks_retention_secs 动态计算（retention 的一半，
    /// 保证客户端在最早可能退役前重取 JWKS）。
    #[tokio::test]
    async fn jwks_endpoint_cache_control_derives_from_retention() {
        let build = |retention: u64| async move {
            let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
            let keystore = Arc::new(crate::oauth2_server::jwks::JwksKeystore::new(dao.clone()));
            // 空库 404（fail-closed）：先轮换入钥保证发布面非空
            keystore
                .rotate("RS256", JWKS_TEST_RSA_PEM, 1_000, retention)
                .await
                .unwrap();
            let state = make_state()
                .with_issuer("https://auth.example.com")
                .with_jwks_keystore(keystore)
                .with_jwks_retention_secs(retention);
            oauth2_external_router(Arc::new(state))
        };
        let app = build(7_200).await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/oauth2/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("public, max-age=3600"),
            "retention 7200 → max-age 3600"
        );
        let app = build(3_600).await;
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/oauth2/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(
            resp.headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("public, max-age=1800"),
            "retention 3600 → max-age 1800（动态派生非静态值）"
        );
    }

    /// 配置 RS256 签名密钥：200 + 合法 JWK Set JSON（含 kid/n/e，无私钥成分）。
    #[tokio::test]
    async fn jwks_endpoint_returns_200_with_rsa_source() {
        let app = oauth2_external_router(Arc::new(
            make_state().with_jwks_source("RS256", JWKS_TEST_RSA_PEM),
        ));
        let resp = app
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/oauth2/jwks.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let keys = json["keys"].as_array().unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kty"], "RSA");
        assert_eq!(keys[0]["use"], "sig");
        assert!(keys[0]["kid"].as_str().unwrap().len() > 20);
        assert!(keys[0]["n"].as_str().is_some() && keys[0]["e"].as_str().is_some());
        assert!(!json.to_string().contains("PRIVATE KEY"));
    }
}

#[cfg(test)]
mod discovery_tests {
    use super::*;
    use crate::dao::{GarrisonDao, InMemoryDao};
    use crate::oauth2_server::client::{
        DaoOAuth2ClientStore, GrantType, OAuth2Client, OAuth2ClientStore,
    };
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// 创建带 issuer 的测试 state（可选注册客户端派生 scopes_supported）。
    async fn make_discovery_state(register_client: bool) -> Arc<OAuth2State> {
        let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
        let store: Arc<dyn OAuth2ClientStore> = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
        if register_client {
            let client = OAuth2Client::new(
                "disc-client",
                "secret-123",
                vec!["https://app.example.com/cb".into()],
                vec![GrantType::AuthorizationCode, GrantType::ClientCredentials],
                vec!["read".into(), "profile".into()],
            )
            .unwrap();
            store.create(client).await.unwrap();
        }
        Arc::new(
            OAuth2State::new(store, dao, "https://auth.example.com/login".to_string())
                .with_issuer("https://auth.example.com")
                // 显式开启：默认跟随 protocol-oidc feature，production 门禁
                // 无该 feature 时默认关闭，测试不依赖 feature 派生默认
                .with_oidc_discovery_enabled(true),
        )
    }

    async fn get(app: Router, uri: &str) -> axum::response::Response {
        app.oneshot(
            Request::builder()
                .method("GET")
                .uri(uri)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    }

    /// OIDC discovery：200 + 关键字段正确（issuer/端点/grant_types/response_types/
    /// scopes 从注册客户端派生）。
    #[tokio::test]
    async fn openid_configuration_returns_200_with_derived_metadata() {
        let app = oauth2_external_router(make_discovery_state(true).await);
        let resp = get(app, "/.well-known/openid-configuration").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["issuer"], "https://auth.example.com");
        assert_eq!(
            json["authorization_endpoint"],
            "https://auth.example.com/oauth2/authorize"
        );
        assert_eq!(
            json["token_endpoint"],
            "https://auth.example.com/oauth2/token"
        );
        assert_eq!(
            json["revocation_endpoint"],
            "https://auth.example.com/oauth2/revoke"
        );
        // introspection 端点仅内网可达，不进外网 discovery 元数据
        assert!(json.get("introspection_endpoint").is_none());
        // grant_types 从实际可用能力派生：password 需显式宣告（未注入 verifier 不宣告）
        let grants: Vec<&str> = json["grant_types_supported"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(grants.contains(&"authorization_code"));
        assert!(grants.contains(&"refresh_token"));
        assert!(grants.contains(&"client_credentials"));
        assert!(
            !grants.contains(&"password"),
            "未宣告的 password grant 不得出现"
        );
        assert_eq!(
            json["response_types_supported"],
            serde_json::json!(["code"])
        );
        // scopes 从注册客户端实际 scope 派生（非静态模板）
        let scopes: Vec<&str> = json["scopes_supported"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(scopes.contains(&"read") && scopes.contains(&"profile"));
        // PKCE 强制 → S256 宣告
        assert_eq!(
            json["code_challenge_methods_supported"],
            serde_json::json!(["S256"])
        );
        // 无 JWKS 密钥库：不宣告 jwks_uri（避免死链误导客户端）
        assert!(json.get("jwks_uri").is_none());
    }

    /// 派生非静态证明：显式宣告 password grant 后元数据才包含它。
    #[tokio::test]
    async fn openid_configuration_password_grant_follows_advertised_flag() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
        let store: Arc<dyn OAuth2ClientStore> = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
        let state = Arc::new(
            OAuth2State::new(store, dao, "https://auth.example.com/login".to_string())
                .with_issuer("https://auth.example.com")
                .with_oidc_discovery_enabled(true)
                .with_password_grant_advertised(true),
        );
        let app = oauth2_external_router(state);
        let resp = get(app, "/.well-known/openid-configuration").await;
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let grants: Vec<&str> = json["grant_types_supported"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(
            grants.contains(&"password"),
            "宣告后 password grant 必须出现在元数据"
        );
    }

    /// protocol-oidc 关闭（运行时旗标关闭）：openid-configuration 404；
    /// RFC 8414 端点不受 OIDC 旗标影响（属 OAuth2 面）。
    #[tokio::test]
    async fn openid_configuration_returns_404_when_oidc_disabled() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
        let store: Arc<dyn OAuth2ClientStore> = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
        let state = Arc::new(
            OAuth2State::new(store, dao, "https://auth.example.com/login".to_string())
                .with_issuer("https://auth.example.com")
                .with_oidc_discovery_enabled(false),
        );
        let app = oauth2_external_router(state);
        let resp = get(app, "/.well-known/openid-configuration").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// issuer 未配置：discovery 404（fail-closed，空 issuer 的元数据无效）。
    #[tokio::test]
    async fn discovery_returns_404_without_issuer() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
        let store: Arc<dyn OAuth2ClientStore> = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
        let state = Arc::new(OAuth2State::new(
            store,
            dao,
            "https://auth.example.com/login".to_string(),
        ));
        let app = oauth2_external_router(state);
        let resp = get(app.clone(), "/.well-known/openid-configuration").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
        let resp = get(app, "/.well-known/oauth-authorization-server").await;
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    /// RFC 8414：/.well-known/oauth-authorization-server 200 + 关键字段；
    /// 与 OIDC 旗标解耦（oidc 关闭时仍可用）。
    #[tokio::test]
    async fn rfc8414_metadata_returns_200_independent_of_oidc_flag() {
        let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
        let store: Arc<dyn OAuth2ClientStore> = Arc::new(DaoOAuth2ClientStore::new(dao.clone()));
        let state = Arc::new(
            OAuth2State::new(store, dao, "https://auth.example.com/login".to_string())
                .with_issuer("https://auth.example.com")
                .with_oidc_discovery_enabled(false),
        );
        let app = oauth2_external_router(state);
        let resp = get(app, "/.well-known/oauth-authorization-server").await;
        assert_eq!(resp.status(), StatusCode::OK);
        let body = BodyExt::collect(resp.into_body()).await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["issuer"], "https://auth.example.com");
        assert_eq!(
            json["response_types_supported"],
            serde_json::json!(["code"])
        );
        let grants: Vec<&str> = json["grant_types_supported"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(grants.contains(&"authorization_code"));
        // token_endpoint_auth_methods_supported 与 token 端点实际接受的两种认证一致
        let auth_methods: Vec<&str> = json["token_endpoint_auth_methods_supported"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap())
            .collect();
        assert!(auth_methods.contains(&"client_secret_basic"));
        assert!(auth_methods.contains(&"client_secret_post"));
    }
}
