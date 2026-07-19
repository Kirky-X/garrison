//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 认证全流程 E2E 测试——login / logout / refresh。
//!
//! 通过 HTTP 调用真实 BulwarkAuthServer + BackendEmbedded，
//! 测试认证核心场景：登录获取 token、登出失效 token、刷新获取新 token。

use super::{http_login, make_client, start_e2e_server};
use bulwark::backend::types::LoginParams;
use serial_test::serial;

/// 登录返回非空 token，且 token 可通过 check-login 校验。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_login_returns_valid_token() {
    let (external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let token = http_login(&client, &external_url, "user1").await;
    assert!(!token.is_empty(), "token 不能为空");

    // 通过内网端口校验 token 有效
    let resp = client
        .post(format!("{}/api/v1/auth/check-login", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"], true, "有效 token check-login 应返回 true");
}

/// 登出后 token 失效，check-login 返回 false。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_logout_invalidates_token() {
    let (external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let token = http_login(&client, &external_url, "user1").await;

    // 登出
    let resp = client
        .post(format!("{}/api/v1/auth/logout", external_url))
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 校验 token 已失效
    let resp = client
        .post(format!("{}/api/v1/auth/check-login", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"], false, "登出后 check-login 应返回 false");
}

/// refresh 端点返回新 token，且旧 token 失效、新 token 有效。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_refresh_returns_new_token() {
    let (external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let old_token = http_login(&client, &external_url, "user1").await;

    // 刷新 token
    let resp = client
        .post(format!("{}/api/v1/auth/refresh", external_url))
        .json(&serde_json::json!({ "token": old_token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let new_token = body["data"].as_str().unwrap().to_string();
    assert_ne!(old_token, new_token, "新 token 必须与旧 token 不同");

    // 旧 token 应失效
    let resp = client
        .post(format!("{}/api/v1/auth/check-login", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": old_token }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"], false, "旧 token 刷新后应失效");

    // 新 token 应有效
    let resp = client
        .post(format!("{}/api/v1/auth/check-login", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": new_token }))
        .send()
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"], true, "新 token 应有效");
}

/// 登录时携带 device/ip/ua，get-session 返回对应字段。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_login_with_device_ip_ua() {
    let (external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let params = LoginParams {
        device: Some("iPhone 15".to_string()),
        ip: Some("192.168.1.100".to_string()),
        user_agent: Some("Mozilla/5.0".to_string()),
        ..Default::default()
    };

    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&serde_json::json!({
            "login_id": "user-device",
            "params": params
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    let token = body["data"].as_str().unwrap().to_string();

    // 获取 session 验证 device/ip/ua
    let resp = client
        .post(format!("{}/api/v1/auth/get-session", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": token, "caller_login_id": "user-device" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["device"], "iPhone 15");
    assert_eq!(body["data"]["ip"], "192.168.1.100");
    assert_eq!(body["data"]["user_agent"], "Mozilla/5.0");
}

/// 默认 MockInterface 允许任意 login_id 登录（不抛错）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_login_invalid_login_id_still_succeeds() {
    let (external_url, _internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    // MockInterface 不校验 login_id 有效性，任意 login_id 都能登录
    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&serde_json::json!({
            "login_id": "nonexistent-user-xyz",
            "params": LoginParams::default()
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        200,
        "默认 MockInterface 应允许任意 login_id 登录"
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["data"].as_str().is_some(), "应返回 token 字符串");
}

/// 无效 token 的 check-login 返回 false（非错误响应）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_check_login_invalid_token_returns_false() {
    let (_external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let resp = client
        .post(format!("{}/api/v1/auth/check-login", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": "invalid-token-xyz" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"], false, "无效 token 应返回 false 而非错误");
    assert!(body.get("error_code").is_none() || body["error_code"].is_null());
}
