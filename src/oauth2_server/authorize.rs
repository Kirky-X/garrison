//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! /oauth2/authorize 端点 — 授权码流程 + PKCE 强制。
//!
//! 处理 RFC 6749 §4.1 授权码流程，强制 PKCE（RFC 7636 S256 方法）。
//!
//! ## 流程
//!
//! 1. 校验 client_id（存在性）
//! 2. 校验 redirect_uri（白名单精确匹配）
//! 3. 校验 response_type=code
//! 4. 校验 PKCE（code_challenge + code_challenge_method=S256）
//! 5. 检查用户登录状态（未登录 → 重定向到登录页）
//! 6. 生成授权码（32 字节随机数 → BASE64URL）
//! 7. 存储授权码（10 分钟 TTL，一次性使用）
//! 8. 重定向到 redirect_uri?code=xxx&state=xxx

use crate::constants::DaoKeyPrefix;
use crate::dao::GarrisonDao;
use crate::error::{GarrisonError, GarrisonResult};
use crate::oauth2_server::client::OAuth2ClientStore;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use percent_encoding::{utf8_percent_encode, AsciiSet};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::sync::Arc;

/// 授权码有效期（10 分钟，RFC 6749 §4.1.2 建议 ≤ 10 分钟）。
const AUTH_CODE_TTL_SECONDS: u64 = 600;

/// code_verifier 最小长度（RFC 7636 §4.1）。
const CODE_VERIFIER_MIN_LEN: usize = 43;
/// code_verifier 最大长度（RFC 7636 §4.1）。
const CODE_VERIFIER_MAX_LEN: usize = 128;

/// S256 code_challenge 固定长度（BASE64URL_NO_PAD(SHA256(32B)) = 43 字符，RFC 7636 §4.2）。
///
/// 用于在 `verify_pkce` 入口校验 `code_challenge` 长度，防止外部传入超长字符串
/// 触发常量时间循环被放大成 CPU DoS（CWE-400）。
const S256_CHALLENGE_LEN: usize = 43;

/// URL 查询参数值编码集。
///
/// 编码控制字符 + 保留字符 + 不安全字符，防止参数注入和 URL 解析歧义。
/// `&` / `=` / `#` / `+` / `%` 等保留字符被编码，避免在查询参数值中被误解析。
const QUERY_VALUE_ENCODE_SET: &AsciiSet = &percent_encoding::CONTROLS
    .add(b' ')
    .add(b'!')
    .add(b'"')
    .add(b'#')
    .add(b'$')
    .add(b'&')
    .add(b'\'')
    .add(b'(')
    .add(b')')
    .add(b'*')
    .add(b'+')
    .add(b',')
    .add(b'/')
    .add(b':')
    .add(b';')
    .add(b'<')
    .add(b'=')
    .add(b'>')
    .add(b'?')
    .add(b'@')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}')
    .add(b'%');

/// /oauth2/authorize 请求参数（query string）。
#[derive(Debug, Clone, Deserialize)]
pub struct AuthorizeRequest {
    /// 授权类型（必须为 "code"）。
    pub response_type: String,
    /// 客户端 ID。
    pub client_id: String,
    /// 重定向 URI（必须在客户端白名单中）。
    pub redirect_uri: String,
    /// 请求的 scope（空格分隔，可选）。
    pub scope: Option<String>,
    /// 客户端状态（原样回传，防 CSRF）。
    pub state: Option<String>,
    /// PKCE code_challenge（S256 方法：BASE64URL(SHA256(code_verifier))）。
    pub code_challenge: String,
    /// PKCE code_challenge_method（必须为 "S256"）。
    pub code_challenge_method: String,
}

/// /oauth2/authorize 响应。
#[derive(Debug, Clone, PartialEq)]
pub enum AuthorizeResponse {
    /// 成功：重定向到 redirect_uri?code=xxx&state=xxx。
    Redirect {
        /// 重定向目标 URL（含 code 和 state 参数）。
        location: String,
    },
    /// 未登录：重定向到登录页面（附带 return_to 参数）。
    LoginRequired {
        /// 登录页面 URL（含 return_to 参数）。
        login_url: String,
    },
}

/// 授权码记录（存储在 DAO 中，10 分钟 TTL，一次性使用）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizationCode {
    /// 授权码字符串（BASE64URL 编码的 32 字节随机数）。
    pub code: String,
    /// 关联的客户端 ID。
    pub client_id: String,
    /// 关联的 redirect_uri。
    pub redirect_uri: String,
    /// 授权的 scope 列表。
    pub scopes: Vec<String>,
    /// 授权用户 ID。
    pub user_id: i64,
    /// PKCE code_challenge（token 交换时验证 code_verifier）。
    pub code_challenge: String,
}

/// Authorize handler，处理授权码流程。
pub struct AuthorizeHandler {
    store: Arc<dyn OAuth2ClientStore>,
    dao: Arc<dyn GarrisonDao>,
    login_url: String,
}

impl AuthorizeHandler {
    /// 创建 handler。
    ///
    /// # 参数
    /// - `store`：OAuth2 客户端存储
    /// - `dao`：DAO（用于存储授权码）
    /// - `login_url`：未登录时重定向的登录页面 URL
    pub fn new(
        store: Arc<dyn OAuth2ClientStore>,
        dao: Arc<dyn GarrisonDao>,
        login_url: String,
    ) -> Self {
        Self {
            store,
            dao,
            login_url,
        }
    }

    /// 处理 authorize 请求。
    ///
    /// # 参数
    /// - `req`：请求参数
    /// - `user_id`：已登录用户 ID（None 表示未登录）
    ///
    /// # 返回
    /// - `Ok(AuthorizeResponse::Redirect)`：授权成功，重定向到 redirect_uri
    /// - `Ok(AuthorizeResponse::LoginRequired)`：未登录，重定向到登录页
    /// - `Err`：请求参数错误（client_id 无效 / redirect_uri 不匹配 / PKCE 校验失败等）
    pub async fn authorize(
        &self,
        req: &AuthorizeRequest,
        user_id: Option<i64>,
    ) -> GarrisonResult<AuthorizeResponse> {
        // 1. 校验 response_type
        if req.response_type != "code" {
            return Err(GarrisonError::OAuth2(format!(
                "oauth2-server-authorize-unsupported-response-type::{}",
                req.response_type
            )));
        }

        // 2. 校验 PKCE code_challenge_method
        if req.code_challenge_method != "S256" {
            return Err(GarrisonError::OAuth2(format!(
                "oauth2-server-authorize-unsupported-code-challenge-method::{}",
                req.code_challenge_method
            )));
        }

        // 3. 校验 code_challenge 非空
        if req.code_challenge.is_empty() {
            return Err(GarrisonError::OAuth2(
                "oauth2-server-authorize-code-challenge-empty".into(),
            ));
        }

        // 4. 校验 client_id
        let client = self.store.get(&req.client_id).await?.ok_or_else(|| {
            GarrisonError::OAuth2(format!("invalid client_id: {}", req.client_id))
        })?;

        // 5. 校验 redirect_uri 白名单
        if !client.is_redirect_uri_allowed(&req.redirect_uri) {
            return Err(GarrisonError::OAuth2(format!(
                "oauth2-server-authorize-redirect-uri-not-allowed::{}",
                req.redirect_uri
            )));
        }

        // 6. 检查用户登录状态
        let user_id = match user_id {
            Some(id) => id,
            None => {
                // return_to 中所有参数值必须百分号编码，
                // 防止 redirect_uri/state 含特殊字符导致参数注入或解析歧义。
                let return_to = format!(
                    "/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&code_challenge={}&code_challenge_method=S256",
                    utf8_percent_encode(&req.client_id, QUERY_VALUE_ENCODE_SET),
                    utf8_percent_encode(&req.redirect_uri, QUERY_VALUE_ENCODE_SET),
                    utf8_percent_encode(&req.code_challenge, QUERY_VALUE_ENCODE_SET),
                );
                let login_url = format!(
                    "{}?return_to={}",
                    self.login_url,
                    utf8_percent_encode(&return_to, QUERY_VALUE_ENCODE_SET)
                );
                return Ok(AuthorizeResponse::LoginRequired { login_url });
            },
        };

        // 7. 解析 scope
        let scopes: Vec<String> = req
            .scope
            .as_ref()
            .map(|s| s.split_whitespace().map(|x| x.to_string()).collect())
            .unwrap_or_default();

        // 存储前校验 scope 是否在客户端 allowed_scopes 内
        client.validate_scopes(&scopes)?;

        // 8. 生成授权码
        let code = generate_authorization_code();
        let auth_code = AuthorizationCode {
            code: code.clone(),
            client_id: req.client_id.clone(),
            redirect_uri: req.redirect_uri.clone(),
            scopes,
            user_id,
            code_challenge: req.code_challenge.clone(),
        };

        // 9. 存储授权码（10 分钟 TTL）
        let key = DaoKeyPrefix::OAuth2AuthCode.build_key(&code);
        let json = serde_json::to_string(&auth_code).map_err(|e| {
            GarrisonError::Internal(format!("oauth2-server-authorize-serialize::{}", e))
        })?;
        self.dao.set(&key, &json, AUTH_CODE_TTL_SECONDS).await?;

        // 10. 构造重定向 URL
        // state 参数必须百分号编码，防止含 & = # 等特殊字符导致解析歧义。
        // code 为 base64url 编码（仅含 [A-Za-z0-9_-]），无需额外编码。
        let mut location = format!("{}?code={}", req.redirect_uri, code);
        if let Some(state) = &req.state {
            location.push_str("&state=");
            location.push_str(&utf8_percent_encode(state, QUERY_VALUE_ENCODE_SET).to_string());
        }
        Ok(AuthorizeResponse::Redirect { location })
    }

    /// 消费授权码（一次性使用，消费后立即删除）。
    ///
    /// 供 /oauth2/token 端点调用：授权码交换 access_token。
    ///
    /// # 返回
    /// - `Ok(Some(code))`：授权码有效，返回关联数据
    /// - `Ok(None)`：授权码不存在或已过期
    pub async fn consume_code(&self, code: &str) -> GarrisonResult<Option<AuthorizationCode>> {
        let key = DaoKeyPrefix::OAuth2AuthCode.build_key(code);
        let json = self.dao.get(&key).await?;
        match json {
            Some(json) => {
                // 一次性使用：立即删除
                self.dao.delete(&key).await?;
                let auth_code: AuthorizationCode = serde_json::from_str(&json).map_err(|e| {
                    GarrisonError::Internal(format!("oauth2-server-authorize-deserialize::{}", e))
                })?;
                Ok(Some(auth_code))
            },
            None => Ok(None),
        }
    }
}

// ============================================================================
// PKCE 工具函数
// ============================================================================

/// 生成授权码（32 字节随机数 → BASE64URL 编码）。
fn generate_authorization_code() -> String {
    let mut bytes = [0u8; 32];
    // OsRng 每次直接读 OS CSPRNG（系统调用），无用户态 DRBG 缓冲，
    // 相比 thread_rng 性能略低（~100-300ns vs ~10-30ns/调用），但消除 reseed 状态机攻击面。
    // 授权码生成非高频路径（每次用户授权一次），安全优先于性能。
    // 与项目其余模块（src/web/csrf.rs / src/account/credential/password.rs 等）规范一致。
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// 从 code_verifier 生成 code_challenge（S256 方法）。
///
/// `code_challenge = BASE64URL(SHA256(code_verifier))`
pub fn generate_code_challenge(code_verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(code_verifier.as_bytes());
    let digest = hasher.finalize();
    URL_SAFE_NO_PAD.encode(digest)
}

/// 校验 code_verifier 长度（RFC 7636 §4.1：43-128 字符）。
pub fn is_valid_code_verifier_len(code_verifier: &str) -> bool {
    (CODE_VERIFIER_MIN_LEN..=CODE_VERIFIER_MAX_LEN).contains(&code_verifier.len())
}

/// 校验 code_verifier 与 code_challenge 是否匹配（S256 方法）。
///
/// 1. 校验 code_verifier 长度（43-128 字符）
/// 2. 校验 code_challenge 长度（S256 固定 43 字符，防止 DoS）
/// 3. 计算 SHA256(code_verifier) → BASE64URL
/// 4. 与 code_challenge 常量时间比对（CWE-208 防御）
pub fn verify_pkce(code_verifier: &str, code_challenge: &str) -> GarrisonResult<bool> {
    if !is_valid_code_verifier_len(code_verifier) {
        return Err(GarrisonError::OAuth2(format!(
            "oauth2-server-authorize-code-verifier-invalid-length::{}",
            code_verifier.len()
        )));
    }
    // 长度校验：S256 challenge = BASE64URL_NO_PAD(SHA256) 固定 43 字符。
    // 异常长度直接判失败（Ok(false)），避免进入常量时间循环被超长输入放大成 CPU DoS。
    if code_challenge.len() != S256_CHALLENGE_LEN {
        return Ok(false);
    }
    let computed = generate_code_challenge(code_verifier);
    // 纵深防御：常量时间比较，与代码库其余签名比较保持一致（CWE-208）。
    Ok(crate::secure::ct_eq::constant_time_eq(
        computed.as_bytes(),
        code_challenge.as_bytes(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::MockDao;
    use crate::oauth2_server::client::{GrantType, OAuth2Client};

    /// 创建测试用 OAuth2Client。
    fn make_test_client(id: &str) -> OAuth2Client {
        OAuth2Client::new(
            id,
            "secret-123",
            vec!["https://app.example.com/cb".into()],
            vec![GrantType::AuthorizationCode],
            vec!["read".into()],
        )
        .unwrap()
    }

    /// 创建测试用 AuthorizeHandler。
    fn make_handler() -> (AuthorizeHandler, Arc<MockDao>) {
        let dao = Arc::new(MockDao::new());
        let store = Arc::new(crate::oauth2_server::client::DaoOAuth2ClientStore::new(
            dao.clone(),
        ));
        let handler =
            AuthorizeHandler::new(store, dao.clone(), "https://auth.example.com/login".into());
        (handler, dao)
    }

    /// 创建测试用 AuthorizeRequest。
    fn make_request(client_id: &str, code_challenge: &str) -> AuthorizeRequest {
        AuthorizeRequest {
            response_type: "code".into(),
            client_id: client_id.into(),
            redirect_uri: "https://app.example.com/cb".into(),
            scope: Some("read".into()),
            state: Some("xyz".into()),
            code_challenge: code_challenge.into(),
            code_challenge_method: "S256".into(),
        }
    }

    // === PKCE 工具函数测试 ===

    #[test]
    fn generate_code_challenge_matches_rfc7636_example() {
        // RFC 7636 Appendix B 测试向量
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        assert_eq!(generate_code_challenge(verifier), expected);
    }

    #[test]
    fn verify_pkce_matches() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        assert!(verify_pkce(verifier, &challenge).unwrap());
    }

    #[test]
    fn verify_pkce_mismatch() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let wrong_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        // 使用不同的 verifier 生成 challenge
        let other = generate_code_challenge("other-verifier-other-verifier-other-verifier");
        assert!(!verify_pkce(verifier, &other).unwrap());
        let _ = wrong_challenge;
    }

    #[test]
    fn verify_pkce_rejects_short_verifier() {
        let err = verify_pkce("short", "challenge").unwrap_err();
        assert!(matches!(err, GarrisonError::OAuth2(_)));
    }

    #[test]
    fn verify_pkce_rejects_long_verifier() {
        let verifier = "a".repeat(129);
        let err = verify_pkce(&verifier, "challenge").unwrap_err();
        assert!(matches!(err, GarrisonError::OAuth2(_)));
    }

    #[test]
    fn is_valid_code_verifier_len_boundary() {
        assert!(!is_valid_code_verifier_len(&"a".repeat(42)));
        assert!(is_valid_code_verifier_len(&"a".repeat(43)));
        assert!(is_valid_code_verifier_len(&"a".repeat(128)));
        assert!(!is_valid_code_verifier_len(&"a".repeat(129)));
    }

    // === authorize handler 测试 ===

    #[tokio::test]
    async fn authorize_success() {
        let (handler, _) = make_handler();
        let client = make_test_client("auth-001");
        handler.store.create(client).await.unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let req = make_request("auth-001", &challenge);

        let resp = handler.authorize(&req, Some(1001)).await.expect("授权");
        match resp {
            AuthorizeResponse::Redirect { location } => {
                assert!(location.starts_with("https://app.example.com/cb?code="));
                assert!(location.contains("state=xyz"));
            },
            _ => panic!("期望 Redirect"),
        }
    }

    #[tokio::test]
    async fn authorize_unlogged_redirects_to_login() {
        let (handler, _) = make_handler();
        let client = make_test_client("auth-002");
        handler.store.create(client).await.unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let req = make_request("auth-002", &challenge);

        let resp = handler.authorize(&req, None).await.expect("授权");
        match resp {
            AuthorizeResponse::LoginRequired { login_url } => {
                assert!(login_url.starts_with("https://auth.example.com/login?return_to="));
            },
            _ => panic!("期望 LoginRequired"),
        }
    }

    #[tokio::test]
    async fn authorize_invalid_client_id() {
        let (handler, _) = make_handler();
        let req = make_request("no-such-client", "challenge");
        let err = handler.authorize(&req, Some(1)).await.unwrap_err();
        assert!(matches!(err, GarrisonError::OAuth2(_)));
    }

    #[tokio::test]
    async fn authorize_invalid_redirect_uri() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("auth-003"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let mut req = make_request("auth-003", &challenge);
        req.redirect_uri = "https://evil.example.com/cb".into();

        let err = handler.authorize(&req, Some(1)).await.unwrap_err();
        assert!(matches!(err, GarrisonError::OAuth2(_)));
    }

    #[tokio::test]
    async fn authorize_unsupported_response_type() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("auth-004"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let mut req = make_request("auth-004", &challenge);
        req.response_type = "token".into();

        let err = handler.authorize(&req, Some(1)).await.unwrap_err();
        assert!(matches!(err, GarrisonError::OAuth2(_)));
    }

    #[tokio::test]
    async fn authorize_unsupported_code_challenge_method() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("auth-005"))
            .await
            .unwrap();

        let req = make_request("auth-005", "challenge");
        // 修改 method 为 plain
        let mut req = req;
        req.code_challenge_method = "plain".into();

        let err = handler.authorize(&req, Some(1)).await.unwrap_err();
        assert!(matches!(err, GarrisonError::OAuth2(_)));
    }

    #[tokio::test]
    async fn authorize_empty_code_challenge() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("auth-006"))
            .await
            .unwrap();

        let req = make_request("auth-006", "");
        let err = handler.authorize(&req, Some(1)).await.unwrap_err();
        assert!(matches!(err, GarrisonError::OAuth2(_)));
    }

    #[tokio::test]
    async fn authorize_without_state() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("auth-007"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let mut req = make_request("auth-007", &challenge);
        req.state = None;

        let resp = handler.authorize(&req, Some(1)).await.unwrap();
        match resp {
            AuthorizeResponse::Redirect { location } => {
                assert!(!location.contains("state="));
            },
            _ => panic!("期望 Redirect"),
        }
    }

    /// authorize 端点 return_to 参数必须对 redirect_uri 进行百分号编码。
    /// redirect_uri 含 `&` 时，未编码会导致 return_to 被截断/解析错误（参数注入）。
    #[tokio::test]
    async fn authorize_return_to_encodes_redirect_uri_with_ampersand() {
        let (handler, _) = make_handler();
        // 注册一个允许特殊 redirect_uri 的客户端
        let client = OAuth2Client::new(
            "auth-encode-001",
            "secret-123",
            vec!["https://app.example.com/cb?existing=param".into()],
            vec![GrantType::AuthorizationCode],
            vec!["read".into()],
        )
        .unwrap();
        handler.store.create(client).await.unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let req = AuthorizeRequest {
            response_type: "code".into(),
            client_id: "auth-encode-001".into(),
            redirect_uri: "https://app.example.com/cb?existing=param".into(),
            scope: Some("read".into()),
            state: Some("state&with&amps".into()),
            code_challenge: challenge,
            code_challenge_method: "S256".into(),
        };

        let resp = handler
            .authorize(&req, None)
            .await
            .expect("应返回 LoginRequired");
        match resp {
            AuthorizeResponse::LoginRequired { login_url } => {
                // return_to 必须被整体百分号编码，
                // 原始 URL 中的 & = ? / 等保留字符不能以字面形式出现在 login_url 查询参数中。
                // 验证：return_to= 后的值中不应出现未编码的 & 或 =（来自原始 URL 结构）
                let return_to_part = login_url
                    .split("return_to=")
                    .nth(1)
                    .expect("应包含 return_to 参数");
                // 未编码的 & 会导致 return_to 值被截断，产生参数注入
                assert!(
                    !return_to_part.contains("redirect_uri=https"),
                    "return_to 中 redirect_uri 的 = 或值未编码，存在参数注入风险: {}",
                    login_url
                );
                assert!(
                    !return_to_part.contains("state&with&amps"),
                    "state 中的 & 未被编码: {}",
                    login_url
                );
                // 编码后的 return_to 应包含 %26（编码后的 &）或 %2526（双重编码后的 &）
                assert!(
                    return_to_part.contains("%26") || return_to_part.contains("%2526"),
                    "return_to 应包含编码后的 & 字符: {}",
                    login_url
                );
            },
            _ => panic!("期望 LoginRequired"),
        }
    }

    /// redirect URL 中的 state 参数必须百分号编码。
    #[tokio::test]
    async fn authorize_redirect_url_encodes_state() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("auth-encode-002"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let req = AuthorizeRequest {
            response_type: "code".into(),
            client_id: "auth-encode-002".into(),
            redirect_uri: "https://app.example.com/cb".into(),
            scope: Some("read".into()),
            state: Some("state&with=special#chars".into()),
            code_challenge: challenge,
            code_challenge_method: "S256".into(),
        };

        let resp = handler.authorize(&req, Some(1001)).await.expect("授权");
        match resp {
            AuthorizeResponse::Redirect { location } => {
                // state 中的特殊字符必须被编码，不能直接出现
                assert!(
                    !location.contains("state&with=special#chars"),
                    "state 中的特殊字符未被编码: {}",
                    location
                );
                // 应包含编码后的 state
                assert!(location.contains("state="), "应有 state 参数: {}", location);
            },
            _ => panic!("期望 Redirect"),
        }
    }

    /// authorize 端点请求超出 allowed_scopes 的 scope 返回 invalid_scope。
    /// make_test_client 的 allowed_scopes = ["read"]，请求 "admin" 应被拒绝。
    #[tokio::test]
    async fn authorize_scope_not_allowed() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("auth-scope-001"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let mut req = make_request("auth-scope-001", &challenge);
        req.scope = Some("admin".into());

        let err = handler.authorize(&req, Some(1)).await.unwrap_err();
        assert!(
            err.to_string()
                .contains("oauth2-server-client-invalid-scope"),
            "期望 invalid_scope 错误，实际: {}",
            err
        );
    }

    /// authorize 端点请求合法 scope 正常通过。
    #[tokio::test]
    async fn authorize_scope_allowed() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("auth-scope-002"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let mut req = make_request("auth-scope-002", &challenge);
        req.scope = Some("read".into());

        let resp = handler.authorize(&req, Some(1)).await.unwrap();
        assert!(matches!(resp, AuthorizeResponse::Redirect { .. }));
    }

    // === consume_code 测试 ===

    #[tokio::test]
    async fn consume_code_returns_auth_data() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("consume-001"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let req = make_request("consume-001", &challenge);
        let resp = handler.authorize(&req, Some(2001)).await.unwrap();
        let location = match resp {
            AuthorizeResponse::Redirect { location } => location,
            _ => panic!("期望 Redirect"),
        };
        let code = location
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();

        let auth_code = handler.consume_code(code).await.unwrap().expect("应存在");
        assert_eq!(auth_code.client_id, "consume-001");
        assert_eq!(auth_code.user_id, 2001);
        assert_eq!(auth_code.code_challenge, challenge);
    }

    #[tokio::test]
    async fn consume_code_one_time_use() {
        let (handler, _) = make_handler();
        handler
            .store
            .create(make_test_client("consume-002"))
            .await
            .unwrap();

        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = generate_code_challenge(verifier);
        let req = make_request("consume-002", &challenge);
        let resp = handler.authorize(&req, Some(2002)).await.unwrap();
        let location = match resp {
            AuthorizeResponse::Redirect { location } => location,
            _ => panic!("期望 Redirect"),
        };
        let code = location
            .split("code=")
            .nth(1)
            .unwrap()
            .split('&')
            .next()
            .unwrap();

        // 第一次消费：成功
        assert!(handler.consume_code(code).await.unwrap().is_some());
        // 第二次消费：已删除
        assert!(handler.consume_code(code).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn consume_code_nonexistent_returns_none() {
        let (handler, _) = make_handler();
        let result = handler.consume_code("nonexistent-code").await.unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn generate_authorization_code_produces_unique() {
        let code1 = generate_authorization_code();
        let code2 = generate_authorization_code();
        assert_ne!(code1, code2);
        assert!(code1.len() >= 43); // 32 bytes → 43 base64url chars
    }
}
