//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OAuth2 协议边界场景测试（TG6，0.2.1 patch release）。
//!
//! 验证 `OAuth2Client` 在边界条件下的行为：
//! - 6.2 无效/过期 refresh_token 等价物（invalid code）返回错误
//! - 6.3 scope="" 与 scope=None 产生不同的请求体
//! - 6.4 同一 authorization_code 重放被拒绝（服务端拒绝）
//! - 6.5 expires_in=0 表示立即过期（解析为 Some(0)）
//!
//! 依据 spec protocol-oauth2。使用 wiremock 0.6 提供 HTTP mock。

#![cfg(feature = "protocol-oauth2")]

use bulwark::error::BulwarkError;
use bulwark::protocol::oauth2::OAuth2Client;
use wiremock::matchers::{body_string_contains, method, path};
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
        "https://auth.example.com/authorize",
        server.uri().as_str(),
    )
    .expect("OAuth2Client 构造失败")
}

// ============================================================================
// 边界场景测试
// ============================================================================

/// 6.2 refresh_token_invalid_returns_error
///
/// OAuth2 模块按设计决策（见 oauth2/mod.rs 文档："仅实现三种授权流程，不实现 Refresh Token"）
/// 未提供 `refresh_token` 方法。此测试用 `exchange_code` + 无效 code 验证等价的错误返回边界：
/// 当授权服务器返回 4xx 错误时，客户端应返回 `BulwarkError::OAuth2`。
#[tokio::test]
#[allow(deprecated)]
async fn refresh_token_invalid_returns_error() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "The authorization code is invalid or expired."
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let result = client
        .exchange_code("invalid-or-expired-code", "state")
        .await;
    assert!(result.is_err(), "无效/过期的 code 应返回错误");
    match result.err() {
        Some(BulwarkError::OAuth2(_)) => {},
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

/// 6.3 scope_empty_string_vs_none_behavior_differs
///
/// 验证 `scope=Some("")` 与 `scope=None` 产生不同的 HTTP 请求体：
/// - `scope=Some("")` → 请求体包含 `scope=`（空值参数）
/// - `scope=None` → 请求体不包含 `scope` 参数
///
/// 通过两个不同的 mock（基于 body_string_contains 匹配）返回不同的 token，
/// 以验证两种调用确实产生了不同的请求。
#[tokio::test]
async fn scope_empty_string_vs_none_behavior_differs() {
    let server = MockServer::start().await;

    // Mock 1：匹配 body 包含 "scope=" → 返回 token-empty
    // 注意：up_to_n_times 确保匹配一次后让位给后续 mock
    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("scope="))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "token-empty-scope",
            "token_type": "Bearer"
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Mock 2：匹配所有其他 POST（不含 "scope="）→ 返回 token-no-scope
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "token-no-scope",
            "token_type": "Bearer"
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    let client = client_for(&server);

    // scope=Some("") → 请求体含 "scope=" → 应得到 token-empty-scope
    let resp_empty = client
        .get_client_credentials_token(Some(""))
        .await
        .expect("scope=Some(\"\") 应成功");
    assert_eq!(
        resp_empty.access_token, "token-empty-scope",
        "scope=Some(\"\") 应触发含 scope= 的请求"
    );

    // scope=None → 请求体不含 "scope=" → 应得到 token-no-scope
    let resp_none = client
        .get_client_credentials_token(None)
        .await
        .expect("scope=None 应成功");
    assert_eq!(
        resp_none.access_token, "token-no-scope",
        "scope=None 应触发不含 scope= 的请求"
    );

    // 两种调用产生不同的 access_token，证明行为不同
    assert_ne!(
        resp_empty.access_token, resp_none.access_token,
        "scope=\"\" 与 scope=None 应产生不同行为"
    );
}

/// 6.4 authorization_code_replay_rejected
///
/// 验证同一 authorization_code 被使用两次时，第二次被拒绝。
///
/// 注意：OAuth2 客户端本身不跟踪已使用的 code（这是授权服务器的职责）。
/// 此测试通过 mock 服务器模拟服务器端的重放检测：
/// - 第一次请求返回 200（成功）
/// - 第二次请求返回 400（invalid_grant，code 已被使用）
#[tokio::test]
#[allow(deprecated)]
async fn authorization_code_replay_rejected() {
    let server = MockServer::start().await;

    // Mock 1：第一次请求返回成功（up_to_n_times(1)）
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "first-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // Mock 2：后续请求返回 400（code 重放被拒绝）
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "The authorization code has been used."
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let code = "same-auth-code";

    // 第一次使用 code：成功
    let first = client.exchange_code(code, "state").await;
    assert!(first.is_ok(), "首次使用 code 应成功");
    assert_eq!(first.unwrap().access_token, "first-token");

    // 第二次使用同一 code：被拒绝
    let second = client.exchange_code(code, "state").await;
    assert!(second.is_err(), "重放同一 code 应被拒绝");
    match second.err() {
        Some(BulwarkError::OAuth2(msg)) => {
            assert!(
                msg.contains("400") || msg.contains("invalid_grant"),
                "错误消息应包含 HTTP 状态码或错误码: {}",
                msg
            );
        },
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

/// 6.5 expires_in_zero_means_immediate_expiry
///
/// 验证 `expires_in=0` 被解析为 `Some(0)`，表示 token 立即过期。
///
/// OAuth2 协议层只负责解析 `TokenResponse`，不主动判断过期（由业务方根据
/// `expires_in` 计算过期时间）。`expires_in=0` 表示 token 在签发瞬间即过期，
/// 业务方应将其视为无效。
#[tokio::test]
async fn expires_in_zero_means_immediate_expiry() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "zero-expiry-token",
            "token_type": "Bearer",
            "expires_in": 0
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let resp = client
        .get_client_credentials_token(None)
        .await
        .expect("请求应成功");

    // expires_in=0 被解析为 Some(0)，业务方应视为立即过期
    assert_eq!(
        resp.expires_in,
        Some(0),
        "expires_in=0 应解析为 Some(0)，表示立即过期"
    );

    // 业务方边界判断：expires_in <= 0 意味着 token 已过期或无效
    let is_immediately_expired = resp.expires_in.map(|e| e <= 0).unwrap_or(true);
    assert!(
        is_immediately_expired,
        "expires_in=0 应被业务方判定为立即过期"
    );
}
