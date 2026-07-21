//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 异常场景 E2E 测试——限速 / 无效 token / 无 API Key / 路径过滤。
//!
//! 通过 HTTP 调用真实 GarrisonAuthServer + BackendEmbedded，
//! 测试异常场景：限速 429、无 API Key 401、错误 API Key 401、外网访问内网路径 404、内网访问外网路径 404。

use super::{make_client, start_e2e_server};
use garrison::backend::types::LoginParams;
use serial_test::serial;

/// 限速 2 req/s，第 3 个请求返回 429。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_rate_limit_returns_429() {
    let (external_url, _internal_url, _handle) = start_e2e_server(2, "test-key").await;
    let client = make_client();

    let body = serde_json::json!({
        "login_id": "user1",
        "params": LoginParams::default()
    });

    // 前 2 个请求成功
    for _ in 0..2 {
        let resp = client
            .post(format!("{}/api/v1/auth/login", external_url))
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(resp.status(), 200);
    }

    // 第 3 个请求被限速
    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 429, "超过限速应返回 429");
}

/// 内网请求无 X-API-Key 头返回 401。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_internal_missing_api_key_returns_401() {
    let (_external_url, internal_url, _handle) = start_e2e_server(100, "secret-key").await;
    let client = make_client();

    let resp = client
        .get(format!("{}/api/v1/auth/health", internal_url))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "无 X-API-Key 应返回 401");
}

/// 内网请求错误 X-API-Key 返回 401。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_internal_wrong_api_key_returns_401() {
    let (_external_url, internal_url, _handle) = start_e2e_server(100, "secret-key").await;
    let client = make_client();

    let resp = client
        .get(format!("{}/api/v1/auth/health", internal_url))
        .header("x-api-key", "wrong-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 401, "错误 X-API-Key 应返回 401");
}

/// 外网访问内网路径 check-login 返回 404（path_filter 拦截）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_external_rejects_internal_path() {
    let (external_url, _internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let resp = client
        .post(format!("{}/api/v1/auth/check-login", external_url))
        .json(&serde_json::json!({ "token": "any" }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "外网访问内网路径应返回 404");
}

/// 内网访问外网路径 login 返回 404（path_filter 拦截）。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_internal_rejects_external_path() {
    let (_external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let resp = client
        .post(format!("{}/api/v1/auth/login", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "login_id": "user1",
            "params": LoginParams::default()
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404, "内网访问外网路径应返回 404");
}

/// check-api-key 无效 key 返回 INVALID_TOKEN。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_check_api_key_invalid_returns_error() {
    let (_external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let resp = client
        .post(format!("{}/api/v1/auth/check-api-key", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "api_key": "nonexistent-api-key",
            "namespace": "default"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["error_code"], "INVALID_TOKEN",
        "无效 API Key 应返回 INVALID_TOKEN，实际: {:?}",
        body
    );
}

/// check-api-key 空 key 返回 INVALID_TOKEN。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_check_api_key_empty_returns_error() {
    let (_external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let resp = client
        .post(format!("{}/api/v1/auth/check-api-key", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({
            "api_key": "",
            "namespace": "default"
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["error_code"], "INVALID_TOKEN",
        "空 API Key 应返回 INVALID_TOKEN，实际: {:?}",
        body
    );
}
