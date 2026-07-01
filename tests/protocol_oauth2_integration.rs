//! OAuth2 协议集成测试：wiremock mock 授权服务器 → exchange_code → 校验 TokenResponse。
//!
//! 验证 `OAuth2Client` 与真实 OAuth2 授权服务器的交互：
//! 1. mock 授权服务器响应 token 端点
//! 2. `exchange_code` / `get_client_credentials_token` / `get_password_token` 流程
//! 3. 错误处理（授权服务器返回错误响应）
//!
//! 依据 spec protocol-oauth2。使用 wiremock 0.6 提供 HTTP mock。

#![cfg(feature = "protocol-oauth2")]

use bulwark::protocol::oauth2::OAuth2Client;
use wiremock::matchers::{header, method, path};
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

/// 标准 token 响应 JSON（含全部字段）。
fn full_token_response_json() -> serde_json::Value {
    serde_json::json!({
        "access_token": "abc123access",
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "def456refresh",
        "scope": "read write"
    })
}

// ============================================================================
// 集成测试：Authorization Code 流程
// ============================================================================

/// exchange_code 成功返回完整 TokenResponse（spec Scenario）。
#[tokio::test]
async fn exchange_code_returns_full_token_response() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(header("content-type", "application/x-www-form-urlencoded"))
        .respond_with(ResponseTemplate::new(200).set_body_json(full_token_response_json()))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let resp = client
        .exchange_code("auth-code-123", "state-abc")
        .await
        .expect("exchange_code 应成功");

    assert_eq!(resp.access_token, "abc123access");
    assert_eq!(resp.token_type, "Bearer");
    assert_eq!(resp.expires_in, Some(3600));
    assert_eq!(resp.refresh_token, Some("def456refresh".to_string()));
    assert_eq!(resp.scope, Some("read write".to_string()));
}

/// exchange_code 仅返回必填字段（access_token + token_type），可选字段为 None。
#[tokio::test]
async fn exchange_code_handles_minimal_response() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "min-token",
            "token_type": "Bearer"
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let resp = client
        .exchange_code("code", "state")
        .await
        .expect("exchange_code 应成功");

    assert_eq!(resp.access_token, "min-token");
    assert_eq!(resp.token_type, "Bearer");
    assert_eq!(resp.expires_in, None);
    assert_eq!(resp.refresh_token, None);
    assert_eq!(resp.scope, None);
}

/// 授权服务器返回 4xx 错误时 exchange_code 返回 Err。
#[tokio::test]
async fn exchange_code_returns_error_on_4xx() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "The authorization code is invalid."
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let result = client.exchange_code("bad-code", "state").await;
    assert!(result.is_err(), "4xx 响应应返回错误");
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

/// get_auth_url 正确拼接查询参数（spec Scenario）。
#[tokio::test]
async fn get_auth_url_includes_required_params() {
    let server = MockServer::start().await;
    let client = client_for(&server);

    let url = client.get_auth_url("xyz-state");
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
}
