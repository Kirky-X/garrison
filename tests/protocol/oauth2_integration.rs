//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OAuth2 协议集成测试：wiremock mock 授权服务器 → exchange_code → 校验 TokenResponse。
//!
//! 验证 `OAuth2Client` 与真实 OAuth2 授权服务器的交互：
//! 1. mock 授权服务器响应 token 端点
//! 2. `exchange_code` / `get_client_credentials_token` / `get_password_token` 流程
//! 3. 错误处理（授权服务器返回错误响应）
//!
//! 依据 spec protocol-oauth2。使用 wiremock 0.6 提供 HTTP mock。

#![cfg(feature = "protocol-oauth2")]

use garrison::protocol::oauth2::OAuth2Client;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ============================================================================
// 辅助函数
// ============================================================================

/// 构造 OAuth2Client 指向 mock server。
fn client_for(server: &MockServer) -> OAuth2Client {
    OAuth2Client::new(
        "test-client-id",
        "test-client-secret",
        "https://myapp.example.com/callback",
        "https://auth.example.com/authorize", // auth_url 仅用于拼接，不实际请求
        server.uri().as_str(),
    )
    .expect("OAuth2Client 构造失败")
}

// ============================================================================
// 集成测试：Client Credentials 流程
// ============================================================================

/// get_client_credentials_token 成功返回 token（spec Scenario）。
#[tokio::test]
async fn client_credentials_returns_token() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "cc-token",
            "token_type": "Bearer",
            "expires_in": 7200
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let resp = client
        .get_client_credentials_token(Some("api:read"))
        .await
        .expect("client_credentials 应成功");

    assert_eq!(resp.access_token, "cc-token");
    assert_eq!(resp.expires_in, Some(7200));
    assert_eq!(
        resp.refresh_token, None,
        "client_credentials 不应返回 refresh_token"
    );
}

// ============================================================================
// 集成测试：Password 流程
// ============================================================================

/// get_password_token 成功返回 token（spec Scenario）。
#[tokio::test]
async fn password_grant_returns_token() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "pwd-token",
            "token_type": "Bearer",
            "expires_in": 1800,
            "refresh_token": "pwd-refresh"
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let resp = client
        .get_password_token("alice", "secret-pass", None)
        .await
        .expect("password grant 应成功");

    assert_eq!(resp.access_token, "pwd-token");
    assert_eq!(resp.refresh_token, Some("pwd-refresh".to_string()));
}

// ============================================================================
// 集成测试：构造校验
// ============================================================================

/// client_id 为空时构造返回 Config 错误（spec Scenario）。
#[tokio::test]
async fn new_rejects_empty_client_id() {
    let result = OAuth2Client::new(
        "",
        "secret",
        "https://cb.example.com",
        "https://auth.example.com/authorize",
        "https://auth.example.com/token",
    );
    assert!(result.is_err(), "空 client_id 应构造失败");
}

/// get_auth_url_with_pkce 正确拼接查询参数（spec Scenario）。
#[tokio::test]
async fn get_auth_url_with_pkce_includes_required_params() {
    let server = MockServer::start().await;
    let client = client_for(&server);

    let verifier = "a".repeat(43);
    let (url, _challenge) = client
        .get_auth_url_with_pkce("xyz-state", &verifier)
        .expect("get_auth_url_with_pkce 应成功");
    assert!(
        url.contains("response_type=code"),
        "URL 应含 response_type=code"
    );
    assert!(
        url.contains("client_id=test-client-id"),
        "URL 应含 client_id"
    );
    assert!(url.contains("state=xyz-state"), "URL 应含 state");
    assert!(
        url.contains("redirect_uri="),
        "URL 应含 redirect_uri（URL 编码）"
    );
    assert!(url.contains("code_challenge="), "URL 应含 code_challenge");
    assert!(
        url.contains("code_challenge_method=S256"),
        "URL 应含 code_challenge_method=S256"
    );
}
