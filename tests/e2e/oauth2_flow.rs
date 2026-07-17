//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OAuth2 全流程 E2E 测试——client_credentials grant / introspect / revoke。
//!
//! 通过 HTTP 调用真实 BulwarkAuthServer + BackendEmbedded + OAuth2State，
//! 测试 OAuth2 完整流程：注册客户端、签发 token、内省 token、撤销 token。

use super::{
    default_tenant_headers, make_client, register_oauth2_client, start_e2e_server_with_oauth2,
};
use bulwark::oauth2_server::client::{GrantType, OAuth2Client};
use serial_test::serial;

/// 创建不跟随重定向的 reqwest 客户端。
///
/// 复用 `super::default_tenant_headers()` 保证与 `make_client()` 一致的
/// `X-Tenant-Id` 默认 header（DRY），仅额外禁用重定向。
fn make_no_redirect_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .default_headers(default_tenant_headers())
        .build()
        .expect("构造不重定向 reqwest 客户端失败")
}

/// 创建测试用 OAuth2Client（支持 ClientCredentials grant）。
fn make_test_client(id: &str) -> OAuth2Client {
    OAuth2Client::new(
        id,
        "secret-123",
        vec!["https://app.example.com/cb".into()],
        vec![GrantType::ClientCredentials],
        vec!["read".into()],
    )
    .unwrap()
}

/// 注册 OAuth2Client，client_credentials grant 签发 token。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_oauth2_register_client_and_get_token() {
    let (external_url, _internal_url, _handle, store) =
        start_e2e_server_with_oauth2(100, "test-key").await;
    let client = make_client();

    register_oauth2_client(&*store, make_test_client("e2e-cc")).await;

    let resp = client
        .post(format!("{}/oauth2/token", external_url))
        .json(&serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": "e2e-cc",
            "client_secret": "secret-123"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "client_credentials grant 应返回 200");
    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["access_token"].as_str().expect("应返回 access_token");
    assert!(!token.is_empty(), "access_token 不能为空");
    assert_eq!(body["token_type"], "Bearer", "token_type 应为 Bearer");
}

/// introspect 已签发 token 返回 active=true。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_oauth2_introspect_active_token() {
    let (external_url, internal_url, _handle, store) =
        start_e2e_server_with_oauth2(100, "test-key").await;
    let client = make_client();

    register_oauth2_client(&*store, make_test_client("e2e-introspect")).await;

    // 签发 token
    let resp = client
        .post(format!("{}/oauth2/token", external_url))
        .json(&serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": "e2e-introspect",
            "client_secret": "secret-123"
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["access_token"].as_str().unwrap().to_string();

    // introspect token
    let resp = client
        .post(format!("{}/oauth2/introspect", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "token": token,
            "client_id": "e2e-introspect",
            "client_secret": "secret-123"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["active"], true,
        "已签发 token introspect 应返回 active=true"
    );
    assert_eq!(body["client_id"], "e2e-introspect");
    assert_eq!(body["token_type"], "Bearer");
}

/// introspect 不存在 token 返回 active=false。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_oauth2_introspect_unknown_token_inactive() {
    let (_external_url, internal_url, _handle, store) =
        start_e2e_server_with_oauth2(100, "test-key").await;
    let client = make_client();

    register_oauth2_client(&*store, make_test_client("e2e-unknown")).await;

    let resp = client
        .post(format!("{}/oauth2/introspect", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "token": "nonexistent-token-xyz",
            "client_id": "e2e-unknown",
            "client_secret": "secret-123"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["active"], false,
        "不存在 token introspect 应返回 active=false"
    );
}

/// 签发 token 后 revoke，再 introspect 返回 active=false。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_oauth2_revoke_token_succeeds() {
    let (external_url, internal_url, _handle, store) =
        start_e2e_server_with_oauth2(100, "test-key").await;
    let client = make_client();

    register_oauth2_client(&*store, make_test_client("e2e-revoke")).await;

    // 签发 token
    let resp = client
        .post(format!("{}/oauth2/token", external_url))
        .json(&serde_json::json!({
            "grant_type": "client_credentials",
            "client_id": "e2e-revoke",
            "client_secret": "secret-123"
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["access_token"].as_str().unwrap().to_string();

    // revoke token
    let resp = client
        .post(format!("{}/oauth2/revoke", external_url))
        .json(&serde_json::json!({
            "token": token,
            "client_id": "e2e-revoke",
            "client_secret": "secret-123"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204, "revoke 成功应返回 204 No Content");

    // introspect 应返回 active=false
    let resp = client
        .post(format!("{}/oauth2/introspect", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "token": token,
            "client_id": "e2e-revoke",
            "client_secret": "secret-123"
        }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["active"], false,
        "revoke 后 introspect 应返回 active=false"
    );
}

/// 未登录时 /oauth2/authorize 重定向到登录页。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_oauth2_authorize_redirects_to_login_when_not_logged_in() {
    let (external_url, _internal_url, _handle, store) =
        start_e2e_server_with_oauth2(100, "test-key").await;
    let client = make_no_redirect_client();

    // 注册 OAuth2Client（支持 authorization_code grant）
    register_oauth2_client(
        &*store,
        OAuth2Client::new(
            "auth-e2e-login",
            "secret-123",
            vec!["https://app.example.com/cb".into()],
            vec![GrantType::AuthorizationCode],
            vec!["read".into()],
        )
        .unwrap(),
    )
    .await;

    let resp = client
        .get(format!(
            "{}/oauth2/authorize?response_type=code&client_id=auth-e2e-login&redirect_uri=https://app.example.com/cb&code_challenge=test-challenge&code_challenge_method=S256",
            external_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 302, "未登录应返回 302 重定向");
    let location = resp
        .headers()
        .get("location")
        .expect("Location header 必须存在")
        .to_str()
        .unwrap();
    assert!(
        location.contains("return_to="),
        "未登录应重定向到登录页含 return_to，实际: {location}"
    );
}

/// 已登录时 /oauth2/authorize 重定向到 redirect_uri 含 code。
///
/// 通过 `/api/v1/auth/login` 获取 token，携带 `Authorization: Bearer <token>` header
/// 调用 authorize 端点。`principal_inject_middleware` 从 header 提取 token、验证后
/// 注入 `BulwarkPrincipal` extension，authorize handler 走授权码签发路径。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_oauth2_authorize_redirects_with_code_when_logged_in() {
    let (external_url, _internal_url, _handle, store) =
        start_e2e_server_with_oauth2(100, "test-key").await;
    let client = make_no_redirect_client();

    // 注册 OAuth2Client（支持 authorization_code grant）
    register_oauth2_client(
        &*store,
        OAuth2Client::new(
            "auth-e2e-code",
            "secret-123",
            vec!["https://app.example.com/cb".into()],
            vec![GrantType::AuthorizationCode],
            vec!["read".into()],
        )
        .unwrap(),
    )
    .await;

    // 登录获取 token
    let token = super::http_login(&client, &external_url, "1001").await;

    // 携带 Bearer token 调用 authorize，应重定向到 redirect_uri?code=xxx
    let resp = client
        .get(format!(
            "{}/oauth2/authorize?response_type=code&client_id=auth-e2e-code&redirect_uri=https://app.example.com/cb&code_challenge=test-challenge-abc123&code_challenge_method=S256&state=xyz",
            external_url
        ))
        .header("authorization", format!("Bearer {}", token))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 302, "已登录应返回 302 重定向到 redirect_uri");
    let location = resp
        .headers()
        .get("location")
        .expect("Location header 必须存在")
        .to_str()
        .unwrap();
    assert!(
        location.starts_with("https://app.example.com/cb?code="),
        "已登录应重定向到 redirect_uri 含 code，实际: {location}"
    );
    assert!(
        location.contains("state=xyz"),
        "应原样回传 state 参数，实际: {location}"
    );
}

/// /oauth2/authorize 非法 client_id 返回 400。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_oauth2_authorize_invalid_client_returns_400() {
    let (external_url, _internal_url, _handle, _store) =
        start_e2e_server_with_oauth2(100, "test-key").await;
    let client = make_no_redirect_client();

    let resp = client
        .get(format!(
            "{}/oauth2/authorize?response_type=code&client_id=nonexistent-client&redirect_uri=https://app.example.com/cb&code_challenge=test-challenge&code_challenge_method=S256",
            external_url
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400, "无效 client_id 应返回 400");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["error"], "OAUTH2_ERROR",
        "应返回 OAUTH2_ERROR，实际: {:?}",
        body
    );
}
