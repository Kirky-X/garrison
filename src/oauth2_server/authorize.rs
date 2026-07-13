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
use crate::dao::BulwarkDao;
use crate::error::{BulwarkError, BulwarkResult};
use crate::oauth2_server::client::OAuth2ClientStore;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
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
    dao: Arc<dyn BulwarkDao>,
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
        dao: Arc<dyn BulwarkDao>,
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
    ) -> BulwarkResult<AuthorizeResponse> {
        // 1. 校验 response_type
        if req.response_type != "code" {
            return Err(BulwarkError::OAuth2(format!(
                "unsupported response_type: {}（仅支持 code）",
                req.response_type
            )));
        }

        // 2. 校验 PKCE code_challenge_method
        if req.code_challenge_method != "S256" {
            return Err(BulwarkError::OAuth2(format!(
                "unsupported code_challenge_method: {}（仅支持 S256）",
                req.code_challenge_method
            )));
        }

        // 3. 校验 code_challenge 非空
        if req.code_challenge.is_empty() {
            return Err(BulwarkError::OAuth2(
                "code_challenge 不能为空（PKCE 强制）".into(),
            ));
        }

        // 4. 校验 client_id
        let client =
            self.store.get(&req.client_id).await?.ok_or_else(|| {
                BulwarkError::OAuth2(format!("invalid client_id: {}", req.client_id))
            })?;

        // 5. 校验 redirect_uri 白名单
        if !client.is_redirect_uri_allowed(&req.redirect_uri) {
            return Err(BulwarkError::OAuth2(format!(
                "redirect_uri 不在白名单中: {}",
                req.redirect_uri
            )));
        }

        // 6. 检查用户登录状态
        let user_id = match user_id {
            Some(id) => id,
            None => {
                let return_to = format!(
                    "/oauth2/authorize?client_id={}&redirect_uri={}&response_type=code&code_challenge={}&code_challenge_method=S256",
                    req.client_id, req.redirect_uri, req.code_challenge
                );
                let login_url = format!("{}?return_to={}", self.login_url, return_to);
                return Ok(AuthorizeResponse::LoginRequired { login_url });
            },
        };

        // 7. 解析 scope
        let scopes: Vec<String> = req
            .scope
            .as_ref()
            .map(|s| s.split_whitespace().map(|x| x.to_string()).collect())
            .unwrap_or_default();

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
        let json = serde_json::to_string(&auth_code)
            .map_err(|e| BulwarkError::Internal(format!("AuthorizationCode 序列化失败: {e}")))?;
        self.dao.set(&key, &json, AUTH_CODE_TTL_SECONDS).await?;

        // 10. 构造重定向 URL
        let mut location = format!("{}?code={}", req.redirect_uri, code);
        if let Some(state) = &req.state {
            location.push_str("&state=");
            location.push_str(state);
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
    pub async fn consume_code(&self, code: &str) -> BulwarkResult<Option<AuthorizationCode>> {
        let key = DaoKeyPrefix::OAuth2AuthCode.build_key(code);
        let json = self.dao.get(&key).await?;
        match json {
            Some(json) => {
                // 一次性使用：立即删除
                self.dao.delete(&key).await?;
                let auth_code: AuthorizationCode = serde_json::from_str(&json).map_err(|e| {
                    BulwarkError::Internal(format!("AuthorizationCode 反序列化失败: {e}"))
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
    rand::thread_rng().fill_bytes(&mut bytes);
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
/// 2. 计算 SHA256(code_verifier) → BASE64URL
/// 3. 与 code_challenge 比对
pub fn verify_pkce(code_verifier: &str, code_challenge: &str) -> BulwarkResult<bool> {
    if !is_valid_code_verifier_len(code_verifier) {
        return Err(BulwarkError::OAuth2(format!(
            "code_verifier 长度无效: {}（要求 {CODE_VERIFIER_MIN_LEN}-{CODE_VERIFIER_MAX_LEN} 字符）",
            code_verifier.len()
        )));
    }
    let computed = generate_code_challenge(code_verifier);
    Ok(computed == code_challenge)
}

// ============================================================================
// 测试
// ============================================================================

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
        assert!(matches!(err, BulwarkError::OAuth2(_)));
    }

    #[test]
    fn verify_pkce_rejects_long_verifier() {
        let verifier = "a".repeat(129);
        let err = verify_pkce(&verifier, "challenge").unwrap_err();
        assert!(matches!(err, BulwarkError::OAuth2(_)));
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
        assert!(matches!(err, BulwarkError::OAuth2(_)));
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
        assert!(matches!(err, BulwarkError::OAuth2(_)));
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
        assert!(matches!(err, BulwarkError::OAuth2(_)));
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
        assert!(matches!(err, BulwarkError::OAuth2(_)));
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
        assert!(matches!(err, BulwarkError::OAuth2(_)));
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
