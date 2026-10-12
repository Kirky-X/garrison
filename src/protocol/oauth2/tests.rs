// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

use super::mock::make_client;
use super::*;
use crate::error::GarrisonError;
#[cfg(feature = "oauth2-scope-handler")]
use crate::GarrisonResult;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// OAuth2Client 构造测试

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

#[test]
fn new_empty_client_id_returns_config_error() {
    let result = OAuth2Client::new("", "secret", "redirect", "auth", "token");
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::Config(_)) => {},
        other => panic!("期望 Config 错误，实际: {:?}", other),
    }
}

#[test]
fn with_user_info_url_sets_url() {
    let client = OAuth2Client::new(
        "cid",
        "secret",
        "https://example.com/cb",
        "https://auth.example.com/authorize",
        "https://auth.example.com/token",
    )
    .unwrap()
    .with_user_info_url("https://example.com/userinfo");
    assert_eq!(client.user_info_url(), Some("https://example.com/userinfo"));
}

/// redirect_uri 仅允许 https:// 或 http://localhost / http://127.0.0.1（开发例外）；明文 HTTP 回调可被中间人截获授权码。
#[test]
fn redirect_uri_rejects_http_in_production() {
    // http://evil.com 应拒绝（明文 HTTP 回调到公网域名）
    let result = OAuth2Client::new(
        "cid",
        "sec",
        "http://evil.com/cb",
        "https://auth.example.com/authorize",
        "https://auth.example.com/token",
    );
    assert!(
        matches!(result, Err(GarrisonError::InvalidParam(_))),
        "http://evil.com 回调应被拒绝，实际 err: {:?}",
        result.err()
    );

    // https://example.com 应允许
    let result = OAuth2Client::new(
        "cid",
        "sec",
        "https://example.com/cb",
        "https://auth.example.com/authorize",
        "https://auth.example.com/token",
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
        "https://auth.example.com/authorize",
        "https://auth.example.com/token",
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
        "https://auth.example.com/authorize",
        "https://auth.example.com/token",
    );
    assert!(
        result.is_ok(),
        "http://127.0.0.1 回调应允许（开发环境例外），实际 err: {:?}",
        result.err()
    );
}

// TokenResponse 解析测试

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

#[test]
fn token_response_omit_optional_fields() {
    let json = r#"{"access_token":"abc","token_type":"Bearer"}"#;
    let tr: TokenResponse = serde_json::from_str(json).unwrap();
    assert_eq!(tr.access_token, "abc");
    assert_eq!(tr.expires_in, None);
    assert_eq!(tr.refresh_token, None);
    assert_eq!(tr.scope, None);
}

#[test]
fn token_response_missing_required_field_errors() {
    let json = r#"{"token_type":"Bearer"}"#;
    let result: Result<TokenResponse, _> = serde_json::from_str(json);
    assert!(result.is_err());
}

// get_client_credentials_token 集成测试

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
        Some(GarrisonError::OAuth2(_)) => {},
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

// get_password_token 集成测试

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
        Some(GarrisonError::OAuth2(_)) => {},
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

#[tokio::test]
async fn password_token_empty_username_returns_invalid_param() {
    let server = MockServer::start().await;
    let client = make_client(&server).await;
    let result = client.get_password_token("", "pwd", None).await;
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::InvalidParam(_)) => {},
        other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
    }
}

// refresh_access_token 集成测试

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
        Some(GarrisonError::OAuth2(msg)) => {
            assert!(msg.contains("400"), "错误消息应包含 HTTP 状态码 400");
        },
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

#[tokio::test]
async fn refresh_access_token_empty_token_returns_invalid_param() {
    let server = MockServer::start().await;
    let client = make_client(&server).await;
    let result = client.refresh_access_token("", None).await;
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::InvalidParam(_)) => {},
        other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
    }
}

// PKCE (RFC 7636 / OAuth 2.1) 测试

/// RFC 7636 Appendix B 测试向量：验证 S256 code_challenge 计算正确（硬性要求）。
#[test]
fn pkce_challenge_rfc_7636_test_vector() {
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
    let challenge =
        OAuth2Client::generate_pkce_challenge(verifier).expect("RFC 7636 测试向量应成功");
    assert_eq!(challenge, expected);
}

#[test]
fn pkce_challenge_short_verifier_returns_error() {
    let verifier = "a".repeat(42);
    let result = OAuth2Client::generate_pkce_challenge(&verifier);
    assert!(result.is_err(), "42 字符的 verifier 应返回错误");
    match result.err() {
        Some(GarrisonError::InvalidParam(_)) => {},
        other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
    }
}

#[test]
fn pkce_challenge_long_verifier_returns_error() {
    let verifier = "a".repeat(129);
    let result = OAuth2Client::generate_pkce_challenge(&verifier);
    assert!(result.is_err(), "129 字符的 verifier 应返回错误");
    match result.err() {
        Some(GarrisonError::InvalidParam(_)) => {},
        other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
    }
}

/// 合法字符集 [A-Za-z0-9-._~]（RFC 7636 §4.1）；空格、!、@、# 均为非法。
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
            Some(GarrisonError::InvalidParam(_)) => {},
            other => panic!("期望 InvalidParam 错误，实际: {:?}", other),
        }
    }
}

/// S256 输出 32 字节 → base64url 无填充 = 43 字符（与 verifier 长度无关）。
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

    let received = server.received_requests().await.expect("应收到请求");
    assert_eq!(received.len(), 1, "应只收到 1 个请求");
    let body = std::str::from_utf8(&received[0].body).expect("body 应为 UTF-8");
    assert!(
        body.contains("code_verifier="),
        "请求体应包含 code_verifier 字段，实际: {}",
        body
    );
}

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
        matches!(err, GarrisonError::OAuth2(_)),
        "应返回 OAuth2 错误，实际: {:?}",
        err
    );
    // 确保未发送 HTTP 请求（CSRF 校验在 HTTP 调用前拦截）
    let received = server.received_requests().await.expect("应可获取请求");
    assert_eq!(received.len(), 0, "state 不匹配时不应发送 HTTP 请求");
}

// OAuth2Client + ScopeRegistry 集成测试

/// 测试用 ScopeHandler：根据 allowed 字段返回结果。
#[cfg(feature = "oauth2-scope-handler")]
struct StubScopeHandler {
    allowed: bool,
}

#[cfg(feature = "oauth2-scope-handler")]
impl scope::ScopeHandler for StubScopeHandler {
    fn validate(&self, _scope: &str, _login_id: i64) -> GarrisonResult<bool> {
        Ok(self.allowed)
    }
}

/// 注入 registry 但 scope 为 None 时跳过校验（未注入场景由 client_credentials_without_scope_success 覆盖）。
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

#[tokio::test]
#[cfg(feature = "oauth2-scope-handler")]
async fn scope_registry_rejects_scope_returns_oauth2_error() {
    let server = MockServer::start().await;
    // 不挂 mock：validate_scope 失败应立即返回、不进 HTTP；wiremock 无匹配 mock 会返回 404 响应而非报错

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
        Some(GarrisonError::OAuth2(msg)) => {
            assert!(msg.contains("scope validation failed: admin"))
        },
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

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
    use crate::error::GarrisonError;

    struct ErrScopeHandler;
    impl scope::ScopeHandler for ErrScopeHandler {
        fn validate(&self, _scope: &str, _login_id: i64) -> GarrisonResult<bool> {
            Err(GarrisonError::Internal("handler failure".to_string()))
        }
    }

    let server = MockServer::start().await;
    let registry = std::sync::Arc::new(scope::ScopeRegistry::new());
    registry.register("bad", std::sync::Arc::new(ErrScopeHandler));
    let client = make_client(&server).await.with_scope_registry(registry);

    let result = client.refresh_access_token("rtok", Some("bad")).await;
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::Internal(msg)) => assert!(msg.contains("handler failure")),
        other => panic!("期望 Internal 错误，实际: {:?}", other),
    }
}

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
        Some(GarrisonError::OAuth2(msg)) => {
            assert!(msg.contains("oauth2-scope-handler-not-registered::unregistered"))
        },
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

// Token Introspection (RFC 7662) 测试

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
        Some(GarrisonError::OAuth2(msg)) => {
            assert!(msg.contains("500"), "错误消息应包含状态码 500: {}", msg);
        },
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

/// 不可达端点用 RFC 2606 保留 TLD `.invalid` 保证 NXDOMAIN（走 Network 分支）；勿用「未监听端口」模拟——
/// Docker Desktop 的 WSL 回环代理对未绑定端口返回 503，连接拒绝语义不可靠。
#[tokio::test]
async fn introspect_token_network_error_returns_network_error() {
    let client = OAuth2Client::new(
        "cid",
        "secret",
        "https://example.com/cb",
        "https://oauth2-auth.invalid/auth",
        "https://oauth2-token.invalid/token",
    )
    .unwrap()
    .with_introspect_url("https://oauth2-introspect.invalid/introspect");

    let result = client.introspect_token("any-token").await;
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::Network(_)) => {},
        other => panic!("期望 Network 错误，实际: {:?}", other),
    }
}

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

#[tokio::test]
async fn introspect_token_default_url_derived_from_token_url() {
    let server = MockServer::start().await;
    // 仅挂 /introspect：make_client 的 token_url={base}/token，默认推导 introspect_url={base}/introspect
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({"active": true})))
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    let resp = client.introspect_token("any").await.expect("应成功");
    assert!(resp.active);
}

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

    let _debug_str = format!("{:?}", resp);
    let cloned = resp.clone();
    assert_eq!(cloned.active, resp.active);
    let json = serde_json::to_string(&resp).expect("Serialize 应成功");
    assert!(json.contains("\"active\":true"));
    let parsed: TokenIntrospectionResponse =
        serde_json::from_str(&json).expect("Deserialize 应成功");
    assert_eq!(parsed.active, resp.active);
    assert_eq!(parsed.scope, resp.scope);
}

// 安全加固：错误处理不泄露 client_secret / code_verifier

/// 错误消息只含 HTTP status + token_url，不回显响应体（防恶意 token 端点回显 client_secret / code_verifier）。
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

/// 错误消息只含 HTTP status + token_url，不回显响应体（防 introspect 端点回显 client_secret）。
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

// 验收层下沉的响应解析 / 请求体边界（真实服务器语义见 tests/acceptance/protocol_oauth2.rs）

/// `expires_in=0` 解析为 `Some(0)`——协议层只解析不判定过期，判定权在业务方（`expires_in <= 0` 视为立即过期）。
#[tokio::test]
async fn expires_in_zero_parsed_as_immediate_expiry() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "zero-expiry-token",
            "token_type": "Bearer",
            "expires_in": 0
        })))
        .mount(&server)
        .await;

    let client = make_client(&server).await;
    let resp = client
        .get_client_credentials_token(None)
        .await
        .expect("请求应成功");

    assert_eq!(
        resp.expires_in,
        Some(0),
        "expires_in=0 应解析为 Some(0)，表示立即过期"
    );
    assert!(
        resp.expires_in.map(|e| e <= 0).unwrap_or(true),
        "业务方应判定 expires_in=0 为立即过期"
    );
}

/// `scope=Some("")` 携带 `scope=` 参数、`scope=None` 不携带：两个互斥 mock 分别命中，证明差异在请求体层面。
#[tokio::test]
async fn scope_empty_string_vs_none_body_differs() {
    use wiremock::matchers::body_string_contains;

    let server = MockServer::start().await;

    // Mock 1：body 含 "scope=" → token-empty-scope（仅消费一次）
    Mock::given(method("POST"))
        .and(path("/token"))
        .and(body_string_contains("scope="))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "token-empty-scope",
            "token_type": "Bearer"
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Mock 2：其余 POST（不含 "scope="）→ token-no-scope（仅消费一次）
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "token-no-scope",
            "token_type": "Bearer"
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    let client = make_client(&server).await;

    let resp_empty = client
        .get_client_credentials_token(Some(""))
        .await
        .expect("scope=Some(\"\") 应成功");
    assert_eq!(
        resp_empty.access_token, "token-empty-scope",
        "scope=Some(\"\") 应触发含 scope= 的请求"
    );

    let resp_none = client
        .get_client_credentials_token(None)
        .await
        .expect("scope=None 应成功");
    assert_eq!(
        resp_none.access_token, "token-no-scope",
        "scope=None 应触发不含 scope= 的请求"
    );

    assert_ne!(
        resp_empty.access_token, resp_none.access_token,
        "scope=\"\" 与 scope=None 应产生不同行为"
    );
}
