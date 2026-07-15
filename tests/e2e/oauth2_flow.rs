//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OAuth2 全流程 E2E 测试——client_credentials grant / introspect / revoke。
//!
//! 通过 HTTP 调用真实 BulwarkAuthServer + BackendEmbedded + OAuth2State，
//! 测试 OAuth2 完整流程：注册客户端、签发 token、内省 token、撤销 token。

use super::{make_client, start_e2e_server_with_oauth2};
use bulwark::oauth2_server::client::{GrantType, OAuth2Client};
use serial_test::serial;

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

    store.create(make_test_client("e2e-cc")).await.unwrap();

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

    store
        .create(make_test_client("e2e-introspect"))
        .await
        .unwrap();

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

    store.create(make_test_client("e2e-unknown")).await.unwrap();

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

    store.create(make_test_client("e2e-revoke")).await.unwrap();

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
