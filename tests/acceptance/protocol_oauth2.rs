//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! oauth2 域验收（spec `acceptance-matrix` R-acceptance-matrix-001，任务 T024）。
//! `OAuth2Client` 客户端侧四种授权流程（authorization_code+PKCE / client_credentials /
//! password / refresh_token）+ Token Introspection，以及授权码重放 / 错误 client_secret /
//! 错误 redirect_uri / PKCE verifier 不匹配 / 无效 refresh token / scope 越权
//! 等异常路径，「正常 + 异常」成对覆盖，场景编号 `ACC-OAUTH2-NNN`。
//!
//! 全部场景经 wiremock 0.6（dev-deps）mock 授权服务器响应，每测试自建 MockServer
//! + `#[serial]` 串行守卫；本域为纯协议客户端，不依赖 `GarrisonTestHarness`
//! （与 tests/protocol/oauth2_*.rs 同构；oauth2_server 服务端端点见 server.rs
//! ACC-SRV-013..018 与 tests/e2e/oauth2_flow.rs，本文件不重复）。
//!
//! ACC-OAUTH2-013..015 吸收 tests/protocol/oauth2_integration.rs（授权 URL
//! redirect_uri 参数、空 client_id 构造拒绝）与 oauth2_edge_cases.rs（scope
//! 空串 vs None 请求体差异、expires_in=0），Phase 4 迁移追溯。
//!
//! # API 偏差记录
//!
//! - `OAuth2Client` 不提供 revoke 方法（RFC 7009 撤销属授权服务器职责，客户端库
//!   无此 API）。ACC-OAUTH2-006 以「撤销后 introspection 返回 active=false」的
//!   客户端可观测语义覆盖撤销路径。
//! - 授权码重放检测同样是授权服务器的职责（客户端无状态），ACC-OAUTH2-007 经
//!   wiremock 模拟服务端拒绝重放（首次 200 / 二次 400）。

#![cfg(feature = "protocol-oauth2")]

use garrison::error::GarrisonError;
use garrison::protocol::oauth2::OAuth2Client;
use serial_test::serial;
use wiremock::matchers::{body_string_contains, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

// ============================================================================
// 辅助函数
// ============================================================================

/// 构造指向 mock 授权服务器的 OAuth2Client（默认正确 client_secret）。
fn client_for(server: &MockServer) -> OAuth2Client {
    OAuth2Client::new(
        "acc-client-id",
        "acc-client-secret",
        "https://app.example.com/callback",
        "https://auth.example.com/authorize", // auth_url 仅用于拼接，不实际请求
        server.uri().as_str(),
    )
    .expect("OAuth2Client 构造失败")
}

/// 构造指定 client_secret 的 OAuth2Client（错误密钥场景）。
fn client_with_secret(server: &MockServer, client_secret: &str) -> OAuth2Client {
    OAuth2Client::new(
        "acc-client-id",
        client_secret,
        "https://app.example.com/callback",
        "https://auth.example.com/authorize",
        server.uri().as_str(),
    )
    .expect("OAuth2Client 构造失败")
}

/// 标准 token 端点成功响应。
fn token_response(access_token: &str) -> serde_json::Value {
    serde_json::json!({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
        "refresh_token": "acc-refresh",
        "scope": "read"
    })
}

/// 断言错误类型为 `GarrisonError::OAuth2` 且消息包含 `needle`。
fn assert_oauth2_err(
    result: &garrison::error::GarrisonResult<garrison::protocol::oauth2::TokenResponse>,
    needle: &str,
) {
    match result.as_ref().err() {
        Some(GarrisonError::OAuth2(msg)) => assert!(
            msg.contains(needle),
            "OAuth2 错误消息应包含 {}，实际: {}",
            needle,
            msg
        ),
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

// ============================================================================
// ACC-OAUTH2-001..005：四种授权流程 + introspection（正常）
// ============================================================================

/// ACC-OAUTH2-001（正常）：authorization_code + PKCE 全流程——授权 URL 参数齐全、
/// code_challenge 符合 RFC 7636 测试向量、token 交换成功且请求体确含 code_verifier。
#[tokio::test]
#[serial]
async fn acc_oauth2_001_authorization_code_with_pkce_full_flow() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("grant_type=authorization_code"))
        .and(body_string_contains("code_verifier="))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_response("ac-token")))
        .mount(&server)
        .await;

    let client = client_for(&server);
    // RFC 7636 Appendix B 测试向量（43 字符合法 verifier）
    let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

    // 1) 授权 URL：含 PKCE 所需全部参数
    let (auth_url, challenge) = client
        .get_auth_url_with_pkce("acc-state", verifier)
        .expect("get_auth_url_with_pkce 应成功");
    assert_eq!(
        challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        "code_challenge 应符合 RFC 7636 B.2 测试向量"
    );
    assert!(
        auth_url.contains("response_type=code"),
        "URL 应含 response_type=code"
    );
    assert!(
        auth_url.contains("client_id=acc-client-id"),
        "URL 应含 client_id"
    );
    assert!(auth_url.contains("state=acc-state"), "URL 应含 state");
    assert!(
        auth_url.contains("code_challenge="),
        "URL 应含 code_challenge"
    );
    assert!(
        auth_url.contains("code_challenge_method=S256"),
        "URL 应含 code_challenge_method=S256"
    );

    // 2) 授权码 + verifier 交换 token
    let token = client
        .exchange_code_with_pkce("auth-code-1", "acc-state", "acc-state", verifier)
        .await
        .expect("PKCE 交换应成功");
    assert_eq!(token.access_token, "ac-token");
    assert_eq!(token.token_type, "Bearer");
    assert_eq!(token.expires_in, Some(3600));
    assert_eq!(token.refresh_token.as_deref(), Some("acc-refresh"));
    assert_eq!(token.scope.as_deref(), Some("read"));

    // 3) 请求体确含 code_verifier（PKCE 实际随交换请求发送，而非仅拼 URL）
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "应恰好发送 1 次 token 请求");
    let body = String::from_utf8_lossy(&requests[0].body).to_string();
    assert!(
        body.contains("code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
        "交换请求体应携带 code_verifier，实际: {}",
        body
    );
    assert!(body.contains("code=auth-code-1"), "交换请求体应携带授权码");
}

/// ACC-OAUTH2-002（正常）：client_credentials 流程——请求体含 grant_type + scope，
/// 响应解析正确且不含 refresh_token。
#[tokio::test]
#[serial]
async fn acc_oauth2_002_client_credentials_flow() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("grant_type=client_credentials"))
        .and(body_string_contains("scope="))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "cc-token",
            "token_type": "Bearer",
            "expires_in": 7200
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let token = client
        .get_client_credentials_token(Some("api:read"))
        .await
        .expect("client_credentials 应成功");
    assert_eq!(token.access_token, "cc-token");
    assert_eq!(token.expires_in, Some(7200));
    assert_eq!(
        token.refresh_token, None,
        "client_credentials 响应不应含 refresh_token"
    );

    // 请求体确实携带了 scope（而非被丢弃）
    let requests = server.received_requests().await.unwrap();
    let body = String::from_utf8_lossy(&requests[0].body).to_string();
    assert!(
        body.contains("scope="),
        "请求体应含 scope 参数，实际: {}",
        body
    );
    assert!(
        body.contains("client_secret=acc-client-secret"),
        "请求体应含 client_secret"
    );
}

/// ACC-OAUTH2-003（正常+异常）：password grant——正确凭证换 token（含 refresh_token）；
/// 空 username 客户端预校验拒绝（InvalidParam，不发 HTTP）。
#[tokio::test]
#[serial]
async fn acc_oauth2_003_password_grant_flow() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("grant_type=password"))
        .and(body_string_contains("username=alice"))
        .and(body_string_contains("password=secret-pass"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_response("pwd-token")))
        .mount(&server)
        .await;

    let client = client_for(&server);

    // 正常：正确用户名密码 → token + refresh_token
    let token = client
        .get_password_token("alice", "secret-pass", None)
        .await
        .expect("password grant 应成功");
    assert_eq!(token.access_token, "pwd-token");
    assert_eq!(token.refresh_token.as_deref(), Some("acc-refresh"));
    assert_eq!(token.scope.as_deref(), Some("read"));

    // 异常：空 username 客户端预校验拒绝（不发起 HTTP）
    let err = client
        .get_password_token("", "secret-pass", None)
        .await
        .unwrap_err();
    match err {
        GarrisonError::InvalidParam(msg) => assert!(msg.contains("username"), "实际: {}", msg),
        other => panic!("期望 InvalidParam，实际: {:?}", other),
    }
    assert!(
        server.received_requests().await.unwrap().len() <= 1,
        "空 username 不应额外发起 HTTP 请求"
    );
}

/// ACC-OAUTH2-004（正常+异常）：refresh_token 换新 access_token；空 refresh_token
/// 客户端预校验拒绝（InvalidParam）。
#[tokio::test]
#[serial]
async fn acc_oauth2_004_refresh_token_flow() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("grant_type=refresh_token"))
        .and(body_string_contains("refresh_token=acc-refresh"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "rotated-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);

    // 正常：刷新成功且 access_token 轮换
    let token = client
        .refresh_access_token("acc-refresh", None)
        .await
        .expect("refresh_token 应成功");
    assert_eq!(token.access_token, "rotated-token");
    assert_eq!(
        token.refresh_token, None,
        "刷新响应未强制携带新 refresh_token"
    );

    // 异常：空 refresh_token → InvalidParam
    let err = client.refresh_access_token("", None).await.unwrap_err();
    match err {
        GarrisonError::InvalidParam(_) => {},
        other => panic!("期望 InvalidParam，实际: {:?}", other),
    }
}

/// ACC-OAUTH2-005（正常）：introspect（RFC 7662）——active=true 的完整 claims 正确解析，
/// 查询请求 POST 至 introspection 端点并携带 token。
#[tokio::test]
#[serial]
async fn acc_oauth2_005_introspect_active_token() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/introspect"))
        .and(body_string_contains("token=acc-access-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "active": true,
            "scope": "read write",
            "client_id": "acc-client-id",
            "username": "alice",
            "token_type": "Bearer",
            "exp": 1_700_000_100,
            "sub": "user-42",
            "aud": "api",
            "iss": "https://auth.example.com",
            "jti": "jti-1"
        })))
        .mount(&server)
        .await;

    let client = client_for(&server).with_introspect_url(format!("{}/introspect", server.uri()));
    let info = client
        .introspect_token("acc-access-token")
        .await
        .expect("introspect 应成功");
    assert!(info.active, "token 应为 active");
    assert_eq!(info.scope.as_deref(), Some("read write"));
    assert_eq!(info.client_id.as_deref(), Some("acc-client-id"));
    assert_eq!(info.username.as_deref(), Some("alice"));
    assert_eq!(info.sub.as_deref(), Some("user-42"));
    assert_eq!(info.exp, Some(1_700_000_100));
    assert_eq!(info.jti.as_deref(), Some("jti-1"));
}

// ============================================================================
// ACC-OAUTH2-006：撤销后的 introspection（异常侧，客户端可观测语义）
// ============================================================================

/// ACC-OAUTH2-006（异常）：token 被撤销后 introspection 返回 active=false——
/// 经 wiremock 模拟授权服务器撤销后的状态变化（首次 active=true → 撤销 → false），
/// 验证客户端正确解析撤销结果。
/// 注：OAuth2Client 无 revoke API（RFC 7009 属授权服务器职责），见文件头偏差记录。
#[tokio::test]
#[serial]
async fn acc_oauth2_006_revoked_token_introspects_inactive() {
    let server = MockServer::start().await;

    // 撤销前：active=true（仅命中一次）
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "active": true,
            "username": "alice"
        })))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // 撤销后：active=false
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "active": false
        })))
        .mount(&server)
        .await;

    let client = client_for(&server).with_introspect_url(format!("{}/introspect", server.uri()));

    let before = client
        .introspect_token("acc-token")
        .await
        .expect("撤销前 introspect 应成功");
    assert!(before.active, "撤销前 token 应 active");
    assert_eq!(before.username.as_deref(), Some("alice"));

    let after = client
        .introspect_token("acc-token")
        .await
        .expect("撤销后 introspect 应成功");
    assert!(!after.active, "撤销后 token 应 inactive");
    assert_eq!(after.username, None, "inactive 响应不应携带 username");
}

// ============================================================================
// ACC-OAUTH2-007..012：异常路径
// ============================================================================

/// ACC-OAUTH2-007（异常）：授权码重放被拒——首次交换 200 成功，同一 code 二次
/// 交换被授权服务器拒绝（400），客户端返回 OAuth2 错误。
#[tokio::test]
#[serial]
async fn acc_oauth2_007_authorization_code_replay_rejected() {
    let server = MockServer::start().await;

    // 首次：成功（仅消费一次）
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_response("first-token")))
        .up_to_n_times(1)
        .mount(&server)
        .await;

    // 重放：invalid_grant
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "The authorization code has been used."
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let verifier = "a".repeat(43);

    let first = client
        .exchange_code_with_pkce("same-auth-code", "state", "state", &verifier)
        .await;
    assert!(first.is_ok(), "首次使用 code 应成功");
    assert_eq!(first.unwrap().access_token, "first-token");

    let second = client
        .exchange_code_with_pkce("same-auth-code", "state", "state", &verifier)
        .await;
    assert!(second.is_err(), "重放同一 code 应被拒绝");
    match second.err() {
        Some(GarrisonError::OAuth2(msg)) => {
            assert!(msg.contains("400"), "应报告 400 状态，实际: {}", msg);
        },
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
}

/// ACC-OAUTH2-008（异常）：错误 client_secret——请求体携带错误密钥，授权服务器
/// 拒绝（400），客户端返回 OAuth2 错误；断言实际传输的正是错误密钥。
#[tokio::test]
#[serial]
async fn acc_oauth2_008_wrong_client_secret_rejected() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("client_secret=wrong-secret"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_client",
            "error_description": "Invalid client credentials."
        })))
        .mount(&server)
        .await;

    let client = client_with_secret(&server, "wrong-secret");
    let result = client.get_client_credentials_token(None).await;
    let err = result.expect_err("错误 client_secret 应被拒绝");
    match err {
        GarrisonError::OAuth2(msg) => assert!(msg.contains("400"), "实际: {}", msg),
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }

    // 证据：请求体确实携带了错误密钥（而非正确密钥）
    let requests = server.received_requests().await.unwrap();
    let body = String::from_utf8_lossy(&requests[0].body).to_string();
    assert!(
        body.contains("client_secret=wrong-secret"),
        "请求体应携带错误 client_secret，实际: {}",
        body
    );
    assert!(
        !body.contains("client_secret=acc-client-secret"),
        "请求体不应携带正确 client_secret"
    );
}

/// ACC-OAUTH2-009（异常）：错误 redirect_uri——构造期拒绝非 https/localhost 回调
/// （spec P2.3 客户端侧校验）；授权服务器对未知回调返回 400 时客户端报 OAuth2 错误，
/// 且请求体携带的是配置的回调地址。
#[tokio::test]
#[serial]
async fn acc_oauth2_009_wrong_redirect_uri_rejected() {
    // 1) 构造期：明文 HTTP + 公网域名回调被拒绝（P2.3）
    // OAuth2Client 无 Debug，unwrap_err 不可用，用 match 解构
    let err = match OAuth2Client::new(
        "acc-client-id",
        "acc-client-secret",
        "http://evil.example.com/callback",
        "https://auth.example.com/authorize",
        "https://auth.example.com/token",
    ) {
        Ok(_) => panic!("http://evil.example.com 回调应被构造期拒绝"),
        Err(e) => e,
    };
    match err {
        GarrisonError::InvalidParam(msg) => assert!(msg.contains("redirect_uri"), "实际: {}", msg),
        other => panic!("期望 InvalidParam，实际: {:?}", other),
    }
    // localhost 开发例外放行
    assert!(
        OAuth2Client::new(
            "acc-client-id",
            "acc-client-secret",
            "http://localhost:8080/cb",
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
        )
        .is_ok(),
        "localhost 回调应放行"
    );

    // 2) 授权服务器侧：注册回调不匹配 → 400 invalid_request
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_request",
            "error_description": "redirect_uri does not match the registered callback."
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let verifier = "a".repeat(43);
    let result = client
        .exchange_code_with_pkce("code-x", "state", "state", &verifier)
        .await;
    assert_oauth2_err(&result, "400");

    // 证据：交换请求携带配置的回调地址
    let requests = server.received_requests().await.unwrap();
    let body = String::from_utf8_lossy(&requests[0].body).to_string();
    assert!(
        body.contains("redirect_uri="),
        "交换请求应携带 redirect_uri，实际: {}",
        body
    );
}

/// ACC-OAUTH2-010（异常）：PKCE verifier 不匹配——客户端预校验非法 verifier
/// （InvalidParam，不发 HTTP）；state 不匹配（CSRF 防护，不发 HTTP）；授权服务器
/// 端 verifier 与 challenge 不一致返回 400 invalid_grant。
#[tokio::test]
#[serial]
async fn acc_oauth2_010_pkce_verifier_mismatch_rejected() {
    // 1) 非法 verifier（长度 < 43）：客户端预校验拒绝，不发 HTTP
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_response("unexpected")))
        .mount(&server)
        .await;
    let client = client_for(&server);

    let err = client
        .exchange_code_with_pkce("code-x", "state", "state", "too-short")
        .await
        .unwrap_err();
    match err {
        GarrisonError::InvalidParam(msg) => {
            assert!(msg.contains("code_verifier"), "实际: {}", msg)
        },
        other => panic!("期望 InvalidParam，实际: {:?}", other),
    }
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "非法 verifier 不应发起 HTTP 请求"
    );

    // 2) state 不匹配：CSRF 防护在客户端拦截，不发 HTTP
    let verifier = "a".repeat(43);
    let err = client
        .exchange_code_with_pkce("code-x", "expected-state", "attacker-state", &verifier)
        .await
        .unwrap_err();
    match err {
        GarrisonError::OAuth2(msg) => assert!(msg.contains("state"), "实际: {}", msg),
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "state 不匹配不应发起 HTTP 请求"
    );

    // 3) 授权服务器端：verifier 与授权请求的 challenge 不一致 → 400 invalid_grant
    let server2 = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "code_verifier does not match the code_challenge."
        })))
        .mount(&server2)
        .await;
    let client2 = client_for(&server2);
    let result = client2
        .exchange_code_with_pkce("code-x", "state", "state", &verifier)
        .await;
    assert_oauth2_err(&result, "400");
}

/// ACC-OAUTH2-011（异常）：无效 refresh_token——授权服务器返回 400 invalid_grant，
/// 客户端返回 OAuth2 错误；请求体确实携带该 refresh_token。
#[tokio::test]
#[serial]
async fn acc_oauth2_011_invalid_refresh_token_rejected() {
    let server = MockServer::start().await;

    Mock::given(method("POST"))
        .and(path("/"))
        .and(body_string_contains("refresh_token=stolen-or-expired"))
        .respond_with(ResponseTemplate::new(400).set_body_json(serde_json::json!({
            "error": "invalid_grant",
            "error_description": "The refresh token is invalid or expired."
        })))
        .mount(&server)
        .await;

    let client = client_for(&server);
    let result = client.refresh_access_token("stolen-or-expired", None).await;
    assert_oauth2_err(&result, "400");

    // 证据：请求体确实携带该 refresh_token（而非其他）
    let requests = server.received_requests().await.unwrap();
    let body = String::from_utf8_lossy(&requests[0].body).to_string();
    assert!(
        body.contains("refresh_token=stolen-or-expired")
            && body.contains("grant_type=refresh_token"),
        "请求体应携带 refresh_token + grant_type，实际: {}",
        body
    );
}

/// ACC-OAUTH2-012（异常）：scope 越权——client 注入 ScopeRegistry（oauth2-scope-handler）
/// 后，请求未授权 scope 在发送 HTTP 前被拦截（OAuth2 错误，零网络请求）；
/// 授权 scope 正常放行。经 wiremock + received_requests 证明拦截发生在客户端侧。
#[cfg(feature = "oauth2-scope-handler")]
#[tokio::test]
#[serial]
async fn acc_oauth2_012_scope_privilege_escalation_blocked_client_side() {
    use garrison::protocol::oauth2::scope::{ScopeHandler, ScopeRegistry};
    use std::sync::Arc;

    struct ReadOnlyScope;
    impl ScopeHandler for ReadOnlyScope {
        fn validate(&self, scope: &str, _login_id: i64) -> garrison::error::GarrisonResult<bool> {
            Ok(scope == "read")
        }
    }

    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_json(token_response("ok-token")))
        .mount(&server)
        .await;

    let registry = ScopeRegistry::new();
    registry.register("read", Arc::new(ReadOnlyScope));
    registry.register("admin", Arc::new(ReadOnlyScope)); // admin → handler 拒绝（越权）
    let client = client_for(&server).with_scope_registry(Arc::new(registry));

    // 越权 scope（handler 显式拒绝）：客户端侧拦截（OAuth2 错误），零 HTTP 请求
    let err = client
        .get_client_credentials_token(Some("admin"))
        .await
        .unwrap_err();
    match err {
        GarrisonError::OAuth2(msg) => {
            assert!(msg.contains("scope validation failed"), "实际: {}", msg)
        },
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "越权 scope 应在发送 HTTP 请求前被拦截"
    );

    // 未注册 scope：同样客户端侧拦截（fail-loud，不静默放行）
    let err = client
        .get_client_credentials_token(Some("write"))
        .await
        .unwrap_err();
    match err {
        GarrisonError::OAuth2(msg) => {
            assert!(
                msg.contains("scope handler not registered"),
                "实际: {}",
                msg
            )
        },
        other => panic!("期望 OAuth2 错误，实际: {:?}", other),
    }
    assert!(
        server.received_requests().await.unwrap().is_empty(),
        "未注册 scope 也应客户端侧拦截"
    );

    // 授权 scope：正常放行
    let token = client
        .get_client_credentials_token(Some("read"))
        .await
        .expect("授权 scope 应放行");
    assert_eq!(token.access_token, "ok-token");
}

// ============================================================================
// ACC-OAUTH2-013..015：构造校验与边界（迁自 tests/protocol/oauth2_*.rs）
// ============================================================================

/// ACC-OAUTH2-013（正常+异常）：授权 URL 构造——`redirect_uri` 以 URL 编码
/// 查询参数出现（其余必填参数已由 ACC-OAUTH2-001 覆盖）；空 client_id 构造期
/// 拒绝（`Config("oauth2-client-id-empty")`，src/protocol/oauth2/client.rs:178）。
/// 迁自 tests/protocol/oauth2_integration.rs::get_auth_url_with_pkce_includes_required_params
/// 与 new_rejects_empty_client_id（2 例合并）
#[tokio::test]
#[serial]
async fn acc_oauth2_013_auth_url_redirect_uri_and_empty_client_id_rejected() {
    // 正常：授权 URL 含 URL 编码的 redirect_uri 参数
    let server = MockServer::start().await;
    let client = client_for(&server);
    let verifier = "a".repeat(43);
    let (url, _challenge) = client
        .get_auth_url_with_pkce("xyz-state", &verifier)
        .expect("get_auth_url_with_pkce 应成功");
    assert!(
        url.contains("redirect_uri="),
        "URL 应含 redirect_uri（URL 编码），实际: {}",
        url
    );

    // 异常：空 client_id → 构造期拒绝
    let err = match OAuth2Client::new(
        "",
        "secret",
        "https://cb.example.com",
        "https://auth.example.com/authorize",
        "https://auth.example.com/token",
    ) {
        Ok(_) => panic!("空 client_id 应构造失败"),
        Err(e) => e,
    };
    match err {
        GarrisonError::Config(msg) => {
            assert!(msg.contains("client-id-empty"), "实际: {}", msg)
        },
        other => panic!("期望 Config（client-id-empty），实际: {:?}", other),
    }
}

/// ACC-OAUTH2-014（正常）：`scope=Some("")` 与 `scope=None` 产生不同的请求体
/// ——空串携带 `scope=` 参数、None 不携带；两个互斥 mock 分别命中并返回不同
/// token，证明行为差异真实发生在请求体层面（而非客户端内部状态）。
/// 迁自 tests/protocol/oauth2_edge_cases.rs::scope_empty_string_vs_none_behavior_differs
#[tokio::test]
#[serial]
async fn acc_oauth2_014_empty_scope_vs_none_body_differs() {
    let server = MockServer::start().await;

    // Mock 1：body 含 "scope=" → token-empty-scope（仅消费一次）
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

    // Mock 2：其余 POST（不含 "scope="）→ token-no-scope（仅消费一次）
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

    let resp_empty = client
        .get_client_credentials_token(Some(""))
        .await
        .expect("scope=Some(\"\") 应成功");
    assert_eq!(
        resp_empty.access_token, "token-empty-scope",
        "scope=Some(\"\") 应触发含 scope= 的请求"
    );

    let resp_none = client
        .get_client_credentials_token(None)
        .await
        .expect("scope=None 应成功");
    assert_eq!(
        resp_none.access_token, "token-no-scope",
        "scope=None 应触发不含 scope= 的请求"
    );

    assert_ne!(
        resp_empty.access_token, resp_none.access_token,
        "scope=\"\" 与 scope=None 应产生不同行为"
    );
}

/// ACC-OAUTH2-015（异常）：`expires_in=0` 解析为 `Some(0)`——协议层只解析
/// 不判定过期（判定权在业务方），业务方应据 `expires_in <= 0` 视为立即过期。
/// 迁自 tests/protocol/oauth2_edge_cases.rs::expires_in_zero_means_immediate_expiry
#[tokio::test]
#[serial]
async fn acc_oauth2_015_expires_in_zero_parsed_as_immediate_expiry() {
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

    assert_eq!(
        resp.expires_in,
        Some(0),
        "expires_in=0 应解析为 Some(0)，表示立即过期"
    );
    assert!(
        resp.expires_in.map(|e| e <= 0).unwrap_or(true),
        "业务方应判定 expires_in=0 为立即过期"
    );
}

// ============================================================================
// ACC-OAUTH2-016：Keycloak OIDC RP 完整流程（T041 迁移自
// tests/integration/keycloak_oidc.rs，`keycloak-oidc` 门控）
// ============================================================================

/// ACC-OAUTH2-016（正常）：Keycloak OIDC RP 完整授权码流程端到端——
/// wiremock 模拟 Keycloak 的 discovery / JWKS / token 端点，验证
/// `discover` → `exchange_code` → `verify_id_token`（RSA 签名的 id_token 含
/// sub / preferred_username / email / realm_access.roles / resource_access /
/// tenant_id claim 全部正确解析）。
#[cfg(all(
    feature = "keycloak-oidc",
    feature = "db-sqlite",
    feature = "cache-memory"
))]
#[tokio::test(flavor = "multi_thread")]
async fn acc_oauth2_016_keycloak_oidc_rp_full_flow_e2e() {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;
    use garrison::dao::GarrisonDaoOxcache;
    use garrison::{KeycloakConfig, KeycloakProvider};
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    use rand::rngs::OsRng;
    use rsa::pkcs1::EncodeRsaPrivateKey;
    use rsa::traits::PublicKeyParts;
    use rsa::RsaPrivateKey;
    use serde::Serialize;
    use std::sync::Arc;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    #[derive(Serialize)]
    struct TestIdTokenClaims {
        iss: String,
        sub: String,
        aud: String,
        exp: i64,
        iat: i64,
        preferred_username: String,
        email: String,
        realm_access: serde_json::Value,
        resource_access: serde_json::Value,
        tenant_id: i64,
    }

    let server = MockServer::start().await;

    let mut rng = OsRng;
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("生成 RSA 私钥应成功");
    let public_key = rsa::RsaPublicKey::from(&private_key);

    let n_bytes = public_key.n().to_bytes_be();
    let e_bytes = public_key.e().to_bytes_be();
    let n_b64 = URL_SAFE_NO_PAD.encode(n_bytes);
    let e_b64 = URL_SAFE_NO_PAD.encode(e_bytes);
    let kid = "key1";

    let issuer = server.uri();
    let token_endpoint = format!("{}/protocol/openid-connect/token", server.uri());
    let jwks_uri = format!("{}/protocol/openid-connect/certs", server.uri());

    // Mock: discovery endpoint
    Mock::given(method("GET"))
        .and(path("/.well-known/openid-configuration"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{}/protocol/openid-connect/auth", server.uri()),
            "token_endpoint": token_endpoint,
            "jwks_uri": jwks_uri,
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        })))
        .mount(&server)
        .await;

    // Mock: JWKS endpoint
    Mock::given(method("GET"))
        .and(path("/protocol/openid-connect/certs"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "keys": [{
                "kid": kid,
                "kty": "RSA",
                "alg": "RS256",
                "use": "sig",
                "n": n_b64,
                "e": e_b64
            }]
        })))
        .mount(&server)
        .await;

    // 生成 id_token
    let sub = "user-123";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    let claims = TestIdTokenClaims {
        iss: issuer.clone(),
        sub: sub.into(),
        aud: "garrison-rp".into(),
        exp: now + 3600,
        iat: now,
        preferred_username: "testuser".into(),
        email: "test@example.com".into(),
        realm_access: serde_json::json!({ "roles": ["admin", "user"] }),
        resource_access: serde_json::json!({
            "account": { "roles": ["manage-account"] }
        }),
        tenant_id: 42,
    };

    let der = private_key.to_pkcs1_der().expect("转 PKCS#1 DER 应成功");
    let encoding_key = EncodingKey::from_rsa_der(der.as_bytes());
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_string());
    let id_token = encode(&header, &claims, &encoding_key).expect("签发 JWT 应成功");

    // Mock: token endpoint
    Mock::given(method("POST"))
        .and(path("/protocol/openid-connect/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "access-token-abc",
            "refresh_token": "refresh-token-xyz",
            "id_token": id_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "scope": "openid profile email"
        })))
        .mount(&server)
        .await;

    let config = KeycloakConfig {
        base_url: server.uri(),
        client_id: "garrison-rp".into(),
        client_secret: Some("client-secret-123".into()),
        redirect_uri: "https://app.example.com/cb".into(),
        expected_iss: server.uri(),
    };
    let provider = KeycloakProvider::new(config)
        .expect("KeycloakProvider::new 应成功")
        .with_dao(Arc::new(
            GarrisonDaoOxcache::new()
                .await
                .expect("构造 GarrisonDaoOxcache 应成功"),
        ));

    // Step 1: discover
    let metadata = provider.discover().await.expect("discover 应成功");
    assert_eq!(metadata.issuer, issuer);
    assert_eq!(metadata.token_endpoint, token_endpoint);
    assert_eq!(metadata.jwks_uri, jwks_uri);

    // Step 2: exchange_code
    let token_set = provider
        .exchange_code("auth-code-xyz")
        .await
        .expect("exchange_code 应成功");
    assert!(!token_set.access_token.is_empty(), "access_token 应非空");
    assert!(!token_set.refresh_token.is_empty(), "refresh_token 应非空");
    assert!(!token_set.id_token.is_empty(), "id_token 应非空");
    assert_eq!(token_set.expires_in, 3600);

    // Step 3: verify_id_token
    let keycloak_claims = provider
        .verify_id_token(&token_set.id_token)
        .await
        .expect("verify_id_token 应成功");
    assert_eq!(keycloak_claims.sub, sub, "claims.sub 应匹配");
    assert_eq!(
        keycloak_claims.preferred_username.as_deref(),
        Some("testuser"),
        "preferred_username 应匹配"
    );
    assert_eq!(
        keycloak_claims.email.as_deref(),
        Some("test@example.com"),
        "email 应匹配"
    );
    assert_eq!(
        keycloak_claims.realm_access.roles,
        vec!["admin", "user"],
        "realm_access.roles 应匹配"
    );
    assert_eq!(
        keycloak_claims.tenant_id,
        Some(42),
        "tenant_id claim 应正确解析"
    );
    assert!(
        keycloak_claims.resource_access.contains_key("account"),
        "resource_access 应包含 account，实际: {:?}",
        keycloak_claims.resource_access
    );
}
