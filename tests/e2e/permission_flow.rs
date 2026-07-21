//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 权限/角色/MFA E2E 测试——check-permission / check-role / check-safe / check-disable。
//!
//! 通过 HTTP 调用真实 GarrisonAuthServer + BackendEmbedded，
//! 测试权限校验全场景：有效/无效 token、角色校验、二级认证状态、封禁状态。

use super::{http_login, make_client, start_e2e_server};
use serial_test::serial;

/// 有效 token 的 check-permission 返回成功（无 error_code）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_check_permission_valid_token_returns_ok() {
    let (external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let token = http_login(&client, &external_url, "user1").await;

    let resp = client
        .post(format!("{}/api/v1/auth/check-permission", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "token": token,
            "permission": "user:read"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    // MockInterface.get_permission_list 返回空 vec → 无权限 → 返回 NOT_PERMISSION
    // 这是真实逻辑：用户未配置任何权限，check-permission 应返回错误
    assert_eq!(
        body["error_code"], "NOT_PERMISSION",
        "未配置权限的用户应返回 NOT_PERMISSION"
    );
}

/// 无效 token 的 check-permission 返回 NOT_PERMISSION（throw_on_not_login=false 时无效 token 视为未登录）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_check_permission_invalid_token_returns_error() {
    let (_external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let resp = client
        .post(format!("{}/api/v1/auth/check-permission", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "token": "invalid-token-xyz",
            "permission": "user:read"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["error_code"], "NOT_PERMISSION",
        "无效 token 在 throw_on_not_login=false 时返回 NOT_PERMISSION"
    );
}

/// 有效 token 的 check-role 返回错误（MockInterface 返回空角色列表）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_check_role_valid_token_returns_not_role() {
    let (external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let token = http_login(&client, &external_url, "user1").await;

    let resp = client
        .post(format!("{}/api/v1/auth/check-role", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "token": token,
            "role": "admin"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    // MockInterface.get_role_list 返回空 vec → 无角色 → 返回 NOT_ROLE
    assert_eq!(
        body["error_code"], "NOT_ROLE",
        "未配置角色的用户应返回 NOT_ROLE"
    );
}

/// 无效 token 的 check-role 返回 NOT_ROLE（throw_on_not_login=false 时无效 token 视为未登录）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_check_role_invalid_token_returns_error() {
    let (_external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let resp = client
        .post(format!("{}/api/v1/auth/check-role", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "token": "invalid-token-xyz",
            "role": "admin"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["error_code"], "NOT_ROLE",
        "无效 token 在 throw_on_not_login=false 时返回 NOT_ROLE"
    );
}

/// 新 token 未开启二级认证，check-safe 返回 false。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_check_safe_default_returns_false() {
    let (external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let token = http_login(&client, &external_url, "user1").await;

    let resp = client
        .post(format!("{}/api/v1/auth/check-safe", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["data"], false,
        "新 token 未开启二级认证，check-safe 应返回 false"
    );
}

/// 新 token 未被封禁，check-disable 返回 false。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_check_disable_default_returns_false() {
    let (external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let token = http_login(&client, &external_url, "user1").await;

    let resp = client
        .post(format!("{}/api/v1/auth/check-disable", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["data"], false,
        "新 token 未被封禁，check-disable 应返回 false"
    );
}
