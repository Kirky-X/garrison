//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

use super::mock::make_client;
use super::*;
use crate::error::BulwarkError;
use crate::BulwarkResult;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ========================================================================
// OAuth2Client 构造测试
// ========================================================================

/// 构造 OAuth2Client，字段正确填充（spec Scenario）。
#[test]
fn new_populates_fields() {
    let client = OAuth2Client::new(
        "cid",
        "secret",
        "https://example.com/cb",
        "https://example.com/auth",
        "https://example.com/token",
    )
    .expect("创建失败");
    assert_eq!(client.auth_url(), "https://example.com/auth");
    assert_eq!(client.token_url(), "https://example.com/token");
    assert_eq!(client.user_info_url(), None);
}

/// client_id 为空返回 Config 错误（spec Scenario）。
#[test]
fn new_empty_client_id_returns_config_error() {
    let result = OAuth2Client::new("", "secret", "redirect", "auth", "token");
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::Config(_)) => {},
        other => panic!("期望 Config 错误，实际: {:?}", other),
    }
}

/// with_user_info_url 设置用户信息端点（spec Scenario）。
#[test]
fn with_user_info_url_sets_url() {
    let client = OAuth2Client::new("cid", "secret", "https://example.com/cb", "auth", "token")
        .unwrap()
        .with_user_info_url("https://example.com/userinfo");
    assert_eq!(client.user_info_url(), Some("https://example.com/userinfo"));
}

/// redirect_uri 非 https 且非 localhost 应返回 InvalidParam 错误（spec P2.3）。
///
/// 仅允许 https:// 或 http://localhost / http://127.0.0.1（开发环境例外）。
/// http://evil.com 等明文 HTTP 回调应被拒绝，避免授权码被中间人截获。
#[test]
fn redirect_uri_rejects_http_in_production() {
    // http://evil.com 应拒绝（明文 HTTP 回调到公网域名）
    let result = OAuth2Client::new("cid", "sec", "http://evil.com/cb", "auth_url", "token_url");
    assert!(
        matches!(result, Err(BulwarkError::InvalidParam(_))),
        "http://evil.com 回调应被拒绝，实际 err: {:?}",
        result.err()
    );

    // https://example.com 应允许
    let result = OAuth2Client::new(
        "cid",
        "sec",
        "https://example.com/cb",
        "auth_url",
        "token_url",
    );
    assert!(
        result.is_ok(),
        "https 回调应允许，实际 err: {:?}",
        result.err()
    );

    // http://localhost 应允许（开发环境例外）
    let result = OAuth2Client::new(
        "cid",
        "sec",
        "http://localhost:8080/cb",
        "auth_url",
        "token_url",
    );
    assert!(
        result.is_ok(),
        "http://localhost 回调应允许（开发环境例外），实际 err: {:?}",
        result.err()
    );

    // http://127.0.0.1 应允许（开发环境例外）
    let result = OAuth2Client::new(
        "cid",
        "sec",
        "http://127.0.0.1:8080/cb",
        "auth_url",
        "token_url",
    );
    assert!(
        result.is_ok(),
        "http://127.0.0.1 回调应允许（开发环境例外），实际 err: {:?}",
        result.err()
    );
}

// ========================================================================
// get_auth_url 测试
// ========================================================================

/// 构造标准授权 URL（spec Scenario）。
#[test]
#[allow(deprecated)]
fn get_auth_url_contains_required_params() {
    let client = OAuth2Client::new(
        "my-client",
        "secret",
        "https://example.com/callback",
        "https://auth.example.com/authorize",
        "https://token.example.com/token",
    )
    .unwrap();
    let url = client.get_auth_url("xyz-state");
    assert!(url.starts_with("https://auth.example.com/authorize?"));
    assert!(url.contains("response_type=code"));
    assert!(url.contains("client_id=my-client"));
    assert!(url.contains("state=xyz-state"));
    assert!(url.contains("redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"));
}

/// state 为空时仍包含 state 参数（spec Scenario）。
#[test]
#[allow(deprecated)]
fn get_auth_url_empty_state_still_includes_state() {
    let client =
        OAuth2Client::new("cid", "secret", "https://example.com/cb", "auth", "token").unwrap();
    let url = client.get_auth_url("");
    assert!(url.contains("state="));
}

// ========================================================================
// TokenResponse 解析测试
// ========================================================================

/// 完整 JSON 解析（spec Scenario）。
#[test]
fn token_response_full_json_parse() {
    let json = r#"{"access_token":"abc","token_type":"Bearer","expires_in":3600,"refresh_token":"r1","scope":"read"}"#;
    let tr: TokenResponse = serde_json::from_str(json).unwrap();
    assert_eq!(tr.access_token, "abc");
    assert_eq!(tr.token_type, "Bearer");
    assert_eq!(tr.expires_in, Some(3600));
    assert_eq!(tr.refresh_token, Some("r1".to_string()));
    assert_eq!(tr.scope, Some("read".to_string()));
}

/// 省略可选字段解析（spec Scenario）。
#[test]
fn token_response_omit_optional_fields() {
    let json = r#"{"access_token":"abc","token_type":"Bearer"}"#;
    let tr: TokenResponse = serde_json::from_str(json).unwrap();
    assert_eq!(tr.access_token, "abc");
    assert_eq!(tr.expires_in, None);
    assert_eq!(tr.refresh_token, None);
    assert_eq!(tr.scope, None);
}

/// 缺少必填字段返回反序列化错误（spec Scenario）。
#[test]
fn token_response_missing_required_field_errors() {
    let json = r#"{"token_type":"Bearer"}"#;
    let result: Result<TokenResponse, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

// ========================================================================
// exchange_code 集成测试
// ========================================================================

/// 成功换取令牌（spec Scenario）。
#[tokio::test]
#[allow(deprecated)]
async fn exchange_code_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "abc123",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "r1",
            "scope": "read"
        })))
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    let token = client.exchange_code("valid-code", "state").await.unwrap();
    assert_eq!(token.access_token, "abc123");
    assert_eq!(token.token_type, "Bearer");
    assert_eq!(token.expires_in, Some(3600));
    assert_eq!(token.refresh_token, Some("r1".to_string()));
    assert_eq!(token.scope, Some("read".to_string()));
}

/// code 无效返回 OAuth2 错误（spec Scenario）。
#[tokio::test]
#[allow(deprecated)]
async fn exchange_code_invalid_code_returns_oauth2_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "Invalid authorization code"
        })))
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    let result = client.exchange_code("invalid-code", "state").await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::OAuth2(_)) => {},
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

// ========================================================================
// get_client_credentials_token 集成测试
// ========================================================================

/// 成功获取 client credentials token（spec Scenario）。
#[tokio::test]
async fn client_credentials_with_scope_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "cc-token",
            "token_type": "Bearer",
            "expires_in": 1800,
            "scope": "read write"
        })))
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    let token = client
        .get_client_credentials_token(Some("read write"))
        .await
        .unwrap();
    assert_eq!(token.access_token, "cc-token");
    assert_eq!(token.scope, Some("read write".to_string()));
}

/// 不带 scope 成功获取 token（spec Scenario）。
#[tokio::test]
async fn client_credentials_without_scope_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "cc-token",
            "token_type": "Bearer"
        })))
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    let token = client.get_client_credentials_token(None).await.unwrap();
    assert_eq!(token.access_token, "cc-token");
    assert_eq!(token.scope, None);
}

/// client_secret 错误返回 OAuth2 错误（spec Scenario）。
#[tokio::test]
async fn client_credentials_wrong_secret_returns_oauth2_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "invalid_client"
        })))
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    let result = client.get_client_credentials_token(None).await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::OAuth2(_)) => {},
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

// ========================================================================
// get_password_token 集成测试
// ========================================================================

/// 成功获取 password token（spec Scenario）。
#[tokio::test]
async fn password_token_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "pwd-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "read"
        })))
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    let token = client
        .get_password_token("alice", "pwd123", Some("read"))
        .await
        .unwrap();
    assert_eq!(token.access_token, "pwd-token");
}

/// 凭据错误返回 OAuth2 错误（spec Scenario）。
#[tokio::test]
async fn password_token_wrong_credentials_returns_oauth2_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(401).set_body_json(serde_json::json!({
            "error": "invalid_grant"
        })))
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    let result = client.get_password_token("alice", "wrong-pwd", None).await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::OAuth2(_)) => {},
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

/// 用户名为空返回 InvalidParam 错误（spec Scenario）。
#[tokio::test]
async fn password_token_empty_username_returns_invalid_param() {
    let server = MockServer::start().await;
    let client = make_client(&server).await;
    let result = client.get_password_token("", "pwd", None).await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::InvalidParam(_)) => {},
        other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
    }
}

// ========================================================================
// refresh_access_token 集成测试
// ========================================================================

/// 成功使用 refresh_token 换取新 access_token（spec Scenario: refresh_access_token 成功）。
#[tokio::test]
async fn refresh_access_token_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "new-access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "new-refresh-token",
            "scope": "openid profile"
        })))
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    let token = client
        .refresh_access_token("old-refresh-token", None)
        .await
        .unwrap();
    assert_eq!(token.access_token, "new-access-token");
    assert_eq!(token.token_type, "Bearer");
    assert_eq!(token.expires_in, Some(3600));
    assert_eq!(token.refresh_token, Some("new-refresh-token".to_string()));
    assert_eq!(token.scope, Some("openid profile".to_string()));
}

/// 带 scope 参数成功换取新 token（spec Scenario: refresh_access_token 成功）。
#[tokio::test]
async fn refresh_access_token_with_scope_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "scoped-token",
            "token_type": "Bearer",
            "expires_in": 1800,
            "scope": "admin"
        })))
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    let token = client
        .refresh_access_token("old-refresh", Some("admin"))
        .await
        .unwrap();
    assert_eq!(token.access_token, "scoped-token");
    assert_eq!(token.scope, Some("admin".to_string()));
}

/// token_endpoint 返回 HTTP 400 错误响应（spec Scenario: refresh_access_token 错误响应）。
#[tokio::test]
async fn refresh_access_token_error_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "The refresh token is invalid or expired."
        })))
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    let result = client
        .refresh_access_token("expired-refresh-token", None)
        .await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::OAuth2(msg)) => {
            assert!(msg.contains("400"), "错误消息应包含 HTTP 状态码 400");
        },
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

/// refresh_token 为空返回 InvalidParam 错误（spec Scenario: refresh_access_token 参数校验）。
#[tokio::test]
async fn refresh_access_token_empty_token_returns_invalid_param() {
    let server = MockServer::start().await;
    let client = make_client(&server).await;
    let result = client.refresh_access_token("", None).await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::InvalidParam(_)) => {},
        other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
    }
}

// ========================================================================
// PKCE (RFC 7636 / OAuth 2.1) 测试
// ========================================================================
// 注：URL 编码单元测试已迁移至 `client.rs` 的 `tests` 模块，与 `url_encode` 实现并置。

/// RFC 7636 Appendix B 测试向量：验证 S256 code_challenge 计算正确（spec R-oauth-2-1-002 硬性要求）。
///
/// code_verifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" (43 字符)
/// code_challenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
#[test]
fn pkce_challenge_rfc_7636_test_vector() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let challenge =
        OAuth2Client::generate_pkce_challenge(verifier).expect("RFC 7636 测试向量应成功");
    assert_eq!(challenge, expected);
}

/// code_verifier < 43 字符返回 InvalidParam 错误（spec R-oauth-2-1-002）。
#[test]
fn pkce_challenge_short_verifier_returns_error() {
    let verifier = "a".repeat(42);
    let result = OAuth2Client::generate_pkce_challenge(&verifier);
    assert!(result.is_err(), "42 字符的 verifier 应返回错误");
    match result.err() {
        Some(BulwarkError::InvalidParam(_)) => {},
        other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
    }
}

/// code_verifier > 128 字符返回 InvalidParam 错误（spec R-oauth-2-1-002）。
#[test]
fn pkce_challenge_long_verifier_returns_error() {
    let verifier = "a".repeat(129);
    let result = OAuth2Client::generate_pkce_challenge(&verifier);
    assert!(result.is_err(), "129 字符的 verifier 应返回错误");
    match result.err() {
        Some(BulwarkError::InvalidParam(_)) => {},
        other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
    }
}

/// code_verifier 含非法字符返回 InvalidParam 错误（spec R-oauth-2-1-002）。
///
/// 合法字符集：[A-Z]/[a-z]/[0-9]/-/./_/~。空格、!、@、# 均为非法。
#[test]
fn pkce_challenge_invalid_chars_returns_error() {
    let test_cases = [
        format!("{}{}", "a".repeat(42), " "),
        format!("{}{}", "a".repeat(42), "!"),
        format!("{}{}", "a".repeat(42), "@"),
        format!("{}{}", "a".repeat(42), "#"),
    ];
    for verifier in &test_cases {
        let result = OAuth2Client::generate_pkce_challenge(verifier);
        assert!(
            result.is_err(),
            "含非法字符的 verifier 应返回错误: {}",
            verifier
        );
        match result.err() {
            Some(BulwarkError::InvalidParam(_)) => {},
            other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
        }
    }
}

/// 43-128 字符的合法 verifier 返回 43 字符的 challenge（spec R-oauth-2-1-002）。
///
/// S256: SHA-256 输出 32 字节 → base64url 无填充编码 = 43 字符。
#[test]
fn pkce_challenge_valid_verifier_returns_correct_length() {
    for &len in &[43usize, 64, 128] {
        let verifier = "a".repeat(len);
        let challenge = OAuth2Client::generate_pkce_challenge(&verifier)
            .unwrap_or_else(|e| panic!("长度 {} 的 verifier 应成功: {}", len, e));
        assert_eq!(
            challenge.len(),
            43,
            "S256 challenge 应为 43 字符（32 字节 base64url 无填充），verifier 长度 {}",
            len
        );
    }
}

/// get_auth_url_with_pkce 返回的 URL 包含 code_challenge 和 code_challenge_method=S256（spec R-oauth-2-1-001）。
#[test]
fn get_auth_url_with_pkce_returns_url_and_challenge() {
    let client = OAuth2Client::new(
        "my-client",
        "secret",
        "https://example.com/callback",
        "https://auth.example.com/authorize",
        "https://token.example.com/token",
    )
    .unwrap();
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let (url, challenge) = client
        .get_auth_url_with_pkce("xyz-state", verifier)
        .expect("get_auth_url_with_pkce 应成功");
    assert!(url.starts_with("https://auth.example.com/authorize?"));
    assert!(url.contains("response_type=code"));
    assert!(url.contains("client_id=my-client"));
    assert!(url.contains("state=xyz-state"));
    assert!(url.contains("code_challenge_method=S256"));
    assert!(url.contains("code_challenge="));
    // 返回的 challenge 与 RFC 7636 测试向量一致
    assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    assert!(url.contains(&format!("code_challenge={}", challenge)));
}

/// exchange_code_with_pkce 请求体包含 code_verifier 字段（spec R-oauth-2-1-001）。
#[tokio::test]
async fn exchange_code_with_pkce_includes_code_verifier_in_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "pkce-token",
            "token_type": "Bearer"
        })))
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    let code_verifier = "a".repeat(43);
    let token = client
        .exchange_code_with_pkce("auth-code", "state", "state", &code_verifier)
        .await
        .expect("exchange_code_with_pkce 应成功");
    assert_eq!(token.access_token, "pkce-token");

    // 验证请求体包含 code_verifier 字段
    let received = server.received_requests().await.expect("应收到请求");
    assert_eq!(received.len(), 1, "应只收到 1 个请求");
    let body = std::str::from_utf8(&received[0].body).expect("body 应为 UTF-8");
    assert!(
        body.contains("code_verifier="),
        "请求体应包含 code_verifier 字段，实际: {}",
        body
    );
}

/// exchange_code_with_pkce 在 state 不匹配时返回 OAuth2 错误（CSRF 防护）。
#[tokio::test]
async fn exchange_code_with_pkce_state_mismatch_returns_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "should-not-reach",
            "token_type": "Bearer"
        })))
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    let code_verifier = "a".repeat(43);
    let result = client
        .exchange_code_with_pkce(
            "auth-code",
            "expected-state",
            "actual-state",
            &code_verifier,
        )
        .await;
    assert!(result.is_err(), "state 不匹配应返回错误");
    let err = result.err().unwrap();
    assert!(
        matches!(err, BulwarkError::OAuth2(_)),
        "应返回 OAuth2 错误，实际: {:?}",
        err
    );
    // 确保未发送 HTTP 请求（CSRF 校验在 HTTP 调用前拦截）
    let received = server.received_requests().await.expect("应可获取请求");
    assert_eq!(received.len(), 0, "state 不匹配时不应发送 HTTP 请求");
}

/// 旧 get_auth_url 标记 deprecated 后仍可工作（向后兼容，spec R-oauth-2-1-003）。
#[test]
#[allow(deprecated)]
fn deprecated_get_auth_url_still_works() {
    let client = OAuth2Client::new(
        "cid",
        "secret",
        "https://example.com/cb",
        "https://auth.example.com/authorize",
        "https://token.example.com/token",
    )
    .unwrap();
    let url = client.get_auth_url("state");
    assert!(url.contains("response_type=code"));
    assert!(url.contains("client_id=cid"));
    assert!(url.contains("state=state"));
}

// ========================================================================
// OAuth2Client + ScopeRegistry 集成测试
// ========================================================================

/// 测试用 ScopeHandler：根据 allowed 字段返回结果。
#[cfg(feature = "oauth2-scope-handler")]
struct StubScopeHandler {
    allowed: bool,
}

#[cfg(feature = "oauth2-scope-handler")]
impl scope::ScopeHandler for StubScopeHandler {
    fn validate(&self, _scope: &str, _login_id: i64) -> BulwarkResult<bool> {
        Ok(self.allowed)
    }
}

/// 未注入 ScopeRegistry 时跳过校验（spec Scenario: 未注入跳过）。
/// 既有 client_credentials_without_scope_success 等测试已覆盖此场景（未调用 with_scope_registry）。
/// 这里追加验证：注入 registry 但 scope 为 None 时也跳过校验。
#[tokio::test]
#[cfg(feature = "oauth2-scope-handler")]
async fn scope_registry_injected_but_none_scope_skips_validation() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "tok", "token_type": "Bearer"
        })))
        .mount(&server)
        .await;

    let registry = std::sync::Arc::new(scope::ScopeRegistry::new());
    // 注册一个始终拒绝的 handler，但 scope=None 时不应触发
    registry.register(
        "blocked",
        std::sync::Arc::new(StubScopeHandler { allowed: false }),
    );
    let client = make_client(&server).await.with_scope_registry(registry);
    let token = client.get_client_credentials_token(None).await.unwrap();
    assert_eq!(token.access_token, "tok");
}

/// 注入 ScopeRegistry 后校验失败返回 OAuth2 错误，不发送 HTTP 请求（spec Scenario）。
#[tokio::test]
#[cfg(feature = "oauth2-scope-handler")]
async fn scope_registry_rejects_scope_returns_oauth2_error() {
    let server = MockServer::start().await;
    // 不挂载任何 mock → 若发送 HTTP 请求会因无匹配 mock 返回 404（但被 reqwest 接收为 response）
    // 我们断言根本不会执行到 HTTP 调用阶段：validate_scope 失败时立即返回

    let registry = std::sync::Arc::new(scope::ScopeRegistry::new());
    registry.register(
        "admin",
        std::sync::Arc::new(StubScopeHandler { allowed: false }),
    );
    let client = make_client(&server).await.with_scope_registry(registry);

    let result = client
        .get_password_token("user", "pass", Some("admin"))
        .await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::OAuth2(msg)) => {
            assert!(msg.contains("scope validation failed: admin"))
        },
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

/// 注入 ScopeRegistry 后校验通过发送 HTTP 请求（spec Scenario 反向验证）。
#[tokio::test]
#[cfg(feature = "oauth2-scope-handler")]
async fn scope_registry_allows_scope_proceeds_to_http() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "ok", "token_type": "Bearer"
        })))
        .mount(&server)
        .await;

    let registry = std::sync::Arc::new(scope::ScopeRegistry::new());
    registry.register(
        "read",
        std::sync::Arc::new(StubScopeHandler { allowed: true }),
    );
    let client = make_client(&server).await.with_scope_registry(registry);

    let token = client
        .get_client_credentials_token(Some("read"))
        .await
        .unwrap();
    assert_eq!(token.access_token, "ok");
}

/// ScopeHandler 返回错误时向上传播（Fail Loud），不发送 HTTP 请求。
#[tokio::test]
#[cfg(feature = "oauth2-scope-handler")]
async fn scope_handler_error_propagates_without_http() {
    use crate::error::BulwarkError;

    struct ErrScopeHandler;
    impl scope::ScopeHandler for ErrScopeHandler {
        fn validate(&self, _scope: &str, _login_id: i64) -> BulwarkResult<bool> {
            Err(BulwarkError::Internal("handler failure".to_string()))
        }
    }

    let server = MockServer::start().await;
    let registry = std::sync::Arc::new(scope::ScopeRegistry::new());
    registry.register("bad", std::sync::Arc::new(ErrScopeHandler));
    let client = make_client(&server).await.with_scope_registry(registry);

    let result = client.refresh_access_token("rtok", Some("bad")).await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::Internal(msg)) => assert!(msg.contains("handler failure")),
        other => panic!("期望 Internal 错误，实际: {:?}", other),
    }
}

/// 未注册的 scope 返回 OAuth2 错误，不发送 HTTP 请求。
#[tokio::test]
#[cfg(feature = "oauth2-scope-handler")]
async fn unregistered_scope_returns_oauth2_error_without_http() {
    let server = MockServer::start().await;
    let registry = std::sync::Arc::new(scope::ScopeRegistry::new());
    // 不注册任何 handler
    let client = make_client(&server).await.with_scope_registry(registry);

    let result = client
        .get_password_token("user", "pass", Some("unregistered"))
        .await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::OAuth2(msg)) => {
            assert!(msg.contains("scope handler not registered: unregistered"))
        },
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

// ========================================================================
// Token Introspection (RFC 7662) 测试
// ========================================================================

/// 完整 introspection 响应解析：active=true 时所有字段正确解析（spec R-token-introspection-002/003）。
#[tokio::test]
async fn introspect_active_token_returns_full_response() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "active": true,
            "scope": "read write",
            "client_id": "test-client-id",
            "username": "alice",
            "token_type": "Bearer",
            "exp": 1700000000,
            "iat": 1690000000,
            "nbf": 1695000000,
            "sub": "user-123",
            "aud": "aud-1",
            "iss": "https://issuer.example.com",
            "jti": "token-jti-001"
        })))
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    let resp = client
        .introspect_token("active-token")
        .await
        .expect("introspect_token 应成功");
    assert!(resp.active);
    assert_eq!(resp.scope.as_deref(), Some("read write"));
    assert_eq!(resp.client_id.as_deref(), Some("test-client-id"));
    assert_eq!(resp.username.as_deref(), Some("alice"));
    assert_eq!(resp.token_type.as_deref(), Some("Bearer"));
    assert_eq!(resp.exp, Some(1700000000));
    assert_eq!(resp.iat, Some(1690000000));
    assert_eq!(resp.nbf, Some(1695000000));
    assert_eq!(resp.sub.as_deref(), Some("user-123"));
    assert_eq!(resp.aud.as_deref(), Some("aud-1"));
    assert_eq!(resp.iss.as_deref(), Some("https://issuer.example.com"));
    assert_eq!(resp.jti.as_deref(), Some("token-jti-001"));
}

/// 无效 token 返回 active=false，其他字段为 None（spec R-token-introspection-003）。
#[tokio::test]
async fn introspect_inactive_token_returns_active_false() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!({"active": false})),
        )
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    let resp = client
        .introspect_token("revoked-token")
        .await
        .expect("introspect_token 应成功");
    assert!(!resp.active);
    assert_eq!(resp.scope, None);
    assert_eq!(resp.client_id, None);
    assert_eq!(resp.username, None);
    assert_eq!(resp.token_type, None);
    assert_eq!(resp.exp, None);
    assert_eq!(resp.iat, None);
    assert_eq!(resp.nbf, None);
    assert_eq!(resp.sub, None);
    assert_eq!(resp.aud, None);
    assert_eq!(resp.iss, None);
    assert_eq!(resp.jti, None);
}

/// 服务器返回 HTTP 500 时返回 OAuth2 错误（spec R-token-introspection-001 错误处理）。
#[tokio::test]
async fn introspect_token_server_error_returns_oauth2_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(500).set_body_string("internal server error"))
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    let result = client.introspect_token("any-token").await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::OAuth2(msg)) => {
            assert!(msg.contains("500"), "错误消息应包含状态码 500: {}", msg);
        },
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

/// 授权服务器不可达返回 Network 错误（spec R-token-introspection-003）。
///
/// 端口 1 通常未启用，reqwest 连接会立即失败（connection refused）→ 触发 Network 错误。
#[tokio::test]
async fn introspect_token_network_error_returns_network_error() {
    let client = OAuth2Client::new(
        "cid",
        "secret",
        "https://example.com/cb",
        "http://127.0.0.1:1/auth",
        "http://127.0.0.1:1/token",
    )
    .unwrap()
    .with_introspect_url("http://127.0.0.1:1/introspect");

    let result = client.introspect_token("any-token").await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::Network(_)) => {},
        other => panic!("期望 Network 错误，实际: {:?}", other),
    }
}

/// 请求体包含 token + client_id + client_secret 字段，Content-Type 为 form-urlencoded（spec R-token-introspection-001）。
#[tokio::test]
async fn introspect_token_sends_token_and_client_credentials_in_body() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"active": true})))
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    client.introspect_token("my-token").await.unwrap();

    let received = server.received_requests().await.expect("应收到请求");
    assert_eq!(received.len(), 1);
    let req = &received[0];
    // 验证 Content-Type 为 application/x-www-form-urlencoded
    let content_type = req
        .headers
        .get("content-type")
        .expect("应有 Content-Type header")
        .to_str()
        .unwrap();
    assert!(
        content_type.contains("application/x-www-form-urlencoded"),
        "Content-Type 应为 application/x-www-form-urlencoded，实际: {}",
        content_type
    );
    // 验证请求体字段
    let body = std::str::from_utf8(&req.body).expect("body 应为 UTF-8");
    assert!(
        body.contains("token=my-token"),
        "请求体应包含 token=my-token: {}",
        body
    );
    assert!(
        body.contains("client_id=test-client-id"),
        "请求体应包含 client_id: {}",
        body
    );
    assert!(
        body.contains("client_secret=test-client-secret"),
        "请求体应包含 client_secret: {}",
        body
    );
}

/// with_introspect_url 覆盖默认 URL，请求发到自定义端点（spec 设计决策 1）。
#[tokio::test]
async fn introspect_token_custom_url_uses_provided_endpoint() {
    let server = MockServer::start().await;
    // 仅挂载 /custom-introspect 路径，验证请求确实发到了自定义 URL
    Mock::given(method("POST"))
        .and(path("/custom-introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"active": true})))
        .mount(&server)
        .await;

    let client = make_client(&server)
        .await
        .with_introspect_url(format!("{}/custom-introspect", server.uri()));
    let resp = client.introspect_token("any").await.expect("应成功");
    assert!(resp.active);
}

/// 默认 introspect URL 从 token_url 推导（token_url 末尾为 /token 时替换为 /introspect）（spec 设计决策 1）。
#[tokio::test]
async fn introspect_token_default_url_derived_from_token_url() {
    let server = MockServer::start().await;
    // 仅挂载 /introspect 路径，验证默认推导逻辑
    // make_client 创建的 token_url = `{base}/token`，默认 introspect_url 应推导为 `{base}/introspect`
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"active": true})))
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    let resp = client.introspect_token("any").await.expect("应成功");
    assert!(resp.active);
}

/// TokenIntrospectionResponse 派生 Debug/Clone/Serialize/Deserialize（spec R-token-introspection-002）。
#[test]
fn token_introspection_response_derives_debug_clone_serde() {
    let resp = TokenIntrospectionResponse {
        active: true,
        scope: Some("read".to_string()),
        client_id: Some("cid".to_string()),
        username: Some("alice".to_string()),
        token_type: Some("Bearer".to_string()),
        exp: Some(1700000000),
        iat: Some(1690000000),
        nbf: Some(1695000000),
        sub: Some("user-123".to_string()),
        aud: Some("aud".to_string()),
        iss: Some("https://issuer.example.com".to_string()),
        jti: Some("jti-1".to_string()),
    };

    // Debug
    let _debug_str = format!("{:?}", resp);
    // Clone
    let cloned = resp.clone();
    assert_eq!(cloned.active, resp.active);
    // Serialize
    let json = serde_json::to_string(&resp).expect("Serialize 应成功");
    assert!(json.contains("\"active\":true"));
    // Deserialize
    let parsed: TokenIntrospectionResponse =
        serde_json::from_str(&json).expect("Deserialize 应成功");
    assert_eq!(parsed.active, resp.active);
    assert_eq!(parsed.scope, resp.scope);
}

// ========================================================================
// H1 安全加固：错误处理不泄露 client_secret / code_verifier（v0.5.1 specmark H1）
// ========================================================================

/// post_token_request 错误处理不泄露 client_secret / code_verifier（H1）。
///
/// 模拟恶意/配置错误的 token 端点在 401 响应体中回显请求参数（含 client_secret / code_verifier）。
/// 修复前，错误消息 `format!("HTTP {}: {}", status, body)` 会原样包含响应体，
/// 若服务器回显请求参数则 secret 泄露到日志/上层调用方。
/// 修复后，错误消息只包含 HTTP status + token_url，不包含响应体或请求参数。
#[tokio::test]
async fn post_token_request_error_does_not_leak_secret() {
    let server = MockServer::start().await;
    // 模拟恶意服务器在 401 响应体中回显请求参数
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(401).set_body_string(
            "invalid client_secret=leak-me-secret or code_verifier=leak-me-verifier",
        ))
        .mount(&server)
        .await;

    let base = server.uri();
    let client = OAuth2Client::new(
        "test-client-id",
        "leak-me-secret", // client_secret 值
        "https://example.com/callback",
        format!("{}/auth", base),
        format!("{}/token", base),
    )
    .expect("创建 OAuth2Client 失败");

    // code_verifier 需 43-128 字符（RFC 7636），pad 到 43+
    let code_verifier = "leak-me-verifier-value-padded-to-43-characters-or-more";
    assert!(
        code_verifier.len() >= 43 && code_verifier.len() <= 128,
        "code_verifier 长度应在 43-128 之间，实际: {}",
        code_verifier.len()
    );

    let result = client
        .exchange_code_with_pkce("auth-code", "state", "state", code_verifier)
        .await;

    assert!(result.is_err(), "应返回错误");
    let err_msg = result.err().unwrap().to_string();
    assert!(
        !err_msg.contains("leak-me-secret"),
        "错误消息不应包含 client_secret 值，实际: {}",
        err_msg
    );
    assert!(
        !err_msg.contains("leak-me-verifier"),
        "错误消息不应包含 code_verifier 值，实际: {}",
        err_msg
    );
}

/// introspect_token 错误处理不泄露响应体（H1 同类漏洞修复）。
///
/// 与 post_token_request 同类问题：修复前 `format!("HTTP {}: {}", status, body)`
/// 会原样包含响应体。模拟恶意 introspect 端点在 500 响应体中回显请求参数
/// （含 client_secret），断言错误消息不包含敏感值。
#[tokio::test]
async fn introspect_token_error_does_not_leak_response_body() {
    let server = MockServer::start().await;
    // 模拟恶意服务器在 500 响应体中回显请求参数（含 client_secret）
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(
            ResponseTemplate::new(500)
                .set_body_string("internal error, received client_secret=leak-introspect-secret"),
        )
        .mount(&server)
        .await;

    let base = server.uri();
    let client = OAuth2Client::new(
        "test-client-id",
        "leak-introspect-secret", // client_secret 值
        "https://example.com/callback",
        format!("{}/auth", base),
        format!("{}/token", base),
    )
    .expect("创建 OAuth2Client 失败");

    let result = client.introspect_token("some-token").await;

    assert!(result.is_err(), "应返回错误");
    let err_msg = result.err().unwrap().to_string();
    assert!(
        !err_msg.contains("leak-introspect-secret"),
        "错误消息不应包含 client_secret 值，实际: {}",
        err_msg
    );
    assert!(
        !err_msg.contains("internal error, received"),
        "错误消息不应包含响应体内容，实际: {}",
        err_msg
    );
}
