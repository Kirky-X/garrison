//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 中间件 E2E 测试——audit_log / health / metrics。
//!
//! 通过 HTTP 调用真实 GarrisonAuthServer + BackendEmbedded，
//! 测试中间件行为：审计日志不影响正常请求、health 端点、metrics 端点。

use super::{http_login, make_client, start_e2e_server};
use serial_test::serial;

/// 审计日志中间件不影响正常请求流程。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_audit_log_middleware_does_not_break_flow() {
    let (external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    // 登录（触发 audit_log 中间件记录）
    let token = http_login(&client, &external_url, "audit-user").await;
    assert!(!token.is_empty(), "审计日志中间件不应阻断登录");

    // 内网校验（触发 audit_log 中间件记录）
    let resp = client
        .post(format!("{}/api/v1/auth/check-login", internal_url))
        .header("x-api-key", "test-key")
        .json(&serde_json::json!({ "token": token }))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "审计日志中间件不应阻断内网请求");
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"], true, "审计日志下 check-login 应正常返回 true");
}

/// health 端点返回 200 + "ok"。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_health_endpoint_returns_ok() {
    let (_external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let resp = client
        .get(format!("{}/api/v1/auth/health", internal_url))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["data"], "ok", "health 端点应返回 ok");
}

/// metrics 端点返回 200 + Prometheus 格式（feature = "metrics-prometheus"）。
#[cfg(feature = "metrics-prometheus")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_e2e_metrics_endpoint_with_prometheus() {
    let (_external_url, internal_url, _handle) = start_e2e_server(100, "test-key").await;
    let client = make_client();

    let resp = client
        .get(format!("{}/api/v1/metrics", internal_url))
        .header("x-api-key", "test-key")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200, "metrics 端点应返回 200");
    // #[forge] 宏用 Json(value) 包装返回值，响应 body 为 JSON 序列化的字符串
    let body: String = resp.json().await.unwrap();
    // 可能没有指标注册，但端点不应 panic
    assert!(
        body.contains("garrison_") || body.is_empty(),
        "metrics 应包含 garrison_ 前缀或为空"
    );
}
