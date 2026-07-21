//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 会话管理 E2E 测试——get-token-info / get-session / kickout / switch-to / renew。
//!
//! 通过 HTTP 调用真实 GarrisonAuthServer + BackendEmbedded，
//! 测试会话生命周期：查询 token 信息、查询 session、踢出、切换、续期。

use super::{http_login, make_client, start_e2e_server};
use serial_test::serial;

/// get-token-info 返回 token、created_at、last_active_at 字段。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_get_token_info_returns_correct_data() {
    let (external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let token = http_login(&client, &external_url, "user1").await;

    let resp = client
        .post(format!("{}/api/v1/auth/get-token-info", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"]["token"], token, "token 字段应匹配");
    assert!(
        body["data"]["created_at"].as_i64().unwrap() > 0,
        "created_at 应为正整数"
    );
    assert!(
        body["data"]["last_active_at"].as_i64().unwrap() > 0,
        "last_active_at 应为正整数"
    );
}

/// get-session 返回 login_id 与登录时一致。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_get_session_returns_login_id() {
    let (external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let token = http_login(&client, &external_url, "session-user").await;

    let resp = client
        .post(format!("{}/api/v1/auth/get-session", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["data"]["login_id"], "session-user",
        "login_id 应与登录时一致"
    );
    assert_eq!(body["data"]["token"], token, "session 中的 token 应匹配");
}

/// 同一 login_id 多次登录，kickout 后所有 token 失效。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_kickout_invalidates_all_sessions() {
    let (external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    // 同一 login_id 登录两次
    let t1 = http_login(&client, &external_url, "kickout-user").await;
    let t2 = http_login(&client, &external_url, "kickout-user").await;
    assert_ne!(t1, t2, "两次登录应生成不同 token");

    // 踢出 kickout-user
    let resp = client
        .post(format!("{}/api/v1/auth/kickout", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "login_id": "kickout-user", "caller_login_id": "kickout-user" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    // 两个 token 都应失效
    for token in [t1, t2] {
        let resp = client
            .post(format!("{}/api/v1/auth/check-login", internal_url))
            .header("x-api-key", "test-key")
            .json(&serde_json::json!({ "token": token }))
            .send()
            .await
            .unwrap();
        let body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(body["data"], false, "kickout 后所有 token 应失效");
    }
}

/// 默认 DenyAllSwitchToGuard 拒绝切换，返回 NOT_PERMISSION。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_switch_to_default_denies() {
    let (external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let token = http_login(&client, &external_url, "user1").await;

    let resp = client
        .post(format!("{}/api/v1/auth/switch-to", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "token": token,
            "target_login_id": "user2"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    // 默认 DenyAllSwitchToGuard 拒绝所有切换（安全默认）
    assert_eq!(body["error_code"], "NOT_PERMISSION", "默认应拒绝 switch-to");
}

/// renew-to-equivalent 返回新 token，旧 token 失效。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_renew_to_equivalent_returns_new_token() {
    let (external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let old_token = http_login(&client, &external_url, "renew-user").await;

    let resp = client
        .post(format!("{}/api/v1/auth/renew-to-equivalent", internal_url))
        .header("x-api-key", "test-key")
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
    assert_eq!(body["data"], false, "旧 token 续期后应失效");

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
