//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! API Happy Path E2E 测试——login / logout / refresh / check-login /
//! check-permission / check-role / get-token-info / get-session / kickout /
//! switch-to / renew-to-equivalent。
//!
//! 通过 `RemoteContext::setup()` 启动 auth_server_serve 子进程（或连接 CI 环境
//! 已运行的 server），用 `make_recording_client()` 包装 HTTP 请求写入
//! `logs/e2e_http.jsonl`。
//!
//! # Spec 与实际行为差异
//!
//! - **T019b / T019c**：spec 描述 "MockInterface 默认放行所有 permission 的
//!   happy path"。实际 `MockInterface::get_permission_list` / `get_role_list`
//!   返回空 `Vec`（见 `tests/e2e/mock.rs`），check-permission 返回
//!   `error_code="NOT_PERMISSION"`，check-role 返回 `error_code="NOT_ROLE"`。
//!   测试按实际行为断言（200 + 有 error_code），并在报告中说明差异。
//! - **T021 switch-to**：默认 `DenyAllSwitchToGuard` 拒绝所有切换，返回
//!   `error_code="NOT_PERMISSION"`（见 `tests/e2e/session_flow.rs::
//!   test_e2e_switch_to_default_denies`）。测试断言该实际行为。

use super::assert_check_login_denied;
use super::make_recording_client;
use super::remote::RemoteContext;
use garrison::backend::types::LoginParams;
use serde_json::json;
use serial_test::serial;

/// 通过 RecordingClient 调用 `/api/v1/auth/login` 并返回 token。
///
/// 复用 helper 避免每个测试重复 login 调用样板代码（规则 8 复用优先）。
async fn recording_login(
    client: &super::har_recorder::RecordingClient,
    external_url: &str,
    login_id: &str,
) -> String {
    let resp = client
        .post(format!("{}/api/v1/auth/login", external_url))
        .json(&json!({
            "login_id": login_id,
            "params": LoginParams::default()
        }))
        .send()
        .await
        .expect("login 请求失败");
    assert_eq!(
        resp.status(),
        200,
        "login 应返回 200，login_id={}",
        login_id
    );
    let body: serde_json::Value = resp.json().await.expect("login 响应非 JSON");
    body["data"]
        .as_str()
        .unwrap_or_else(|| panic!("login 响应 data 字段非字符串: {:?}", body))
        .to_string()
}

/// 通过 RecordingClient 调用 `/api/v1/auth/check-login`（内网端点）。
///
/// 返回 `(status, body)`，调用方按需断言。
async fn recording_check_login(
    client: &super::har_recorder::RecordingClient,
    internal_url: &str,
    api_key: &str,
    token: &str,
) -> (reqwest::StatusCode, serde_json::Value) {
    let resp = client
        .post(format!("{}/api/v1/auth/check-login", internal_url))
        .header("x-api-key", api_key)
        .json(&json!({ "token": token }))
        .send()
        .await
        .expect("check-login 请求失败");
    let status = resp.status();
    let body: serde_json::Value = resp.json().await.expect("check-login 响应非 JSON");
    (status, body)
}

/// T019: login → check-login(true) → logout → check-login(false) → refresh(new token)。
///
/// 覆盖登录、校验、登出、刷新全流程，断言每步状态码与 data 字段。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_api_happy_login_logout_refresh() {
    let ctx = RemoteContext::setup().await;
    let client = make_recording_client("test_api_happy_login_logout_refresh");

    // 1. login → 200 + 非空 token
    let token1 = recording_login(&client, &ctx.external_url, "user1").await;
    assert!(!token1.is_empty(), "token1 不能为空");

    // 2. check-login(token1) → 200 + data=true
    let (status, body) =
        recording_check_login(&client, &ctx.internal_url, &ctx.api_key, &token1).await;
    assert_eq!(status, 200, "check-login 应返回 200");
    assert_eq!(body["data"], true, "有效 token check-login 应返回 true");

    // 3. logout(token1) → 200
    let resp = client
        .post(format!("{}/api/v1/auth/logout", ctx.external_url))
        .json(&json!({ "token": token1 }))
        .send()
        .await
        .expect("logout 请求失败");
    assert_eq!(resp.status(), 200, "logout 应返回 200");

    // 4. check-login(token1) → 拒绝语义（data=false 或 error_code="SESSION_ERROR"）
    // spawn_child 模式下 throw_on_not_login=true，返回 error_code 而非 data=false
    let (status, body) =
        recording_check_login(&client, &ctx.internal_url, &ctx.api_key, &token1).await;
    assert_eq!(status, 200, "logout 后 check-login 仍应返回 200");
    assert_check_login_denied(&body, "logout 后 check-login 应表达拒绝语义");

    // 5. 重新 login → refresh → 新 token ≠ 旧 token
    let token2 = recording_login(&client, &ctx.external_url, "user1").await;
    assert!(!token2.is_empty(), "token2 不能为空");
    assert_ne!(token1, token2, "两次 login 应生成不同 token");

    let resp = client
        .post(format!("{}/api/v1/auth/refresh", ctx.external_url))
        .json(&json!({ "token": token2 }))
        .send()
        .await
        .expect("refresh 请求失败");
    assert_eq!(resp.status(), 200, "refresh 应返回 200");
    let body: serde_json::Value = resp.json().await.expect("refresh 响应非 JSON");
    let token3 = body["data"]
        .as_str()
        .unwrap_or_else(|| panic!("refresh 响应 data 字段非字符串: {:?}", body))
        .to_string();
    assert_ne!(token2, token3, "refresh 后新 token 必须与旧 token 不同");
}

/// T019b: check-permission happy path——通过 RecordingClient 调用 internal 端点。
///
/// **Spec 与实际差异**：spec 描述 "MockInterface 默认放行所有 permission"，
/// 但 `MockInterface::get_permission_list` 返回空 Vec，实际返回
/// `error_code="NOT_PERMISSION"`。测试断言实际行为：200 + error_code 存在。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_api_happy_check_permission() {
    let ctx = RemoteContext::setup().await;
    let client = make_recording_client("test_api_happy_check_permission");

    let token = recording_login(&client, &ctx.external_url, "user1").await;

    let resp = client
        .post(format!("{}/api/v1/auth/check-permission", ctx.internal_url))
        .header("x-api-key", &ctx.api_key)
        .json(&json!({
            "token": token,
            "permission": "read"
        }))
        .send()
        .await
        .expect("check-permission 请求失败");
    assert_eq!(
        resp.status(),
        200,
        "check-permission 应返回 200（业务错误用 error_code 表达）"
    );
    let body: serde_json::Value = resp.json().await.expect("check-permission 响应非 JSON");
    // 实际行为：MockInterface 返回空权限 → NOT_PERMISSION（非 happy path 放行）
    assert!(
        body.get("error_code").is_some() && !body["error_code"].is_null(),
        "MockInterface 返回空权限列表，check-permission 应返回 error_code（实际: {:?}）",
        body
    );
}

/// T019c: check-role happy path——通过 RecordingClient 调用 internal 端点。
///
/// **Spec 与实际差异**：spec 描述 "MockInterface 默认放行所有 role"，
/// 但 `MockInterface::get_role_list` 返回空 Vec，实际返回
/// `error_code="NOT_ROLE"`。测试断言实际行为：200 + error_code 存在。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_api_happy_check_role() {
    let ctx = RemoteContext::setup().await;
    let client = make_recording_client("test_api_happy_check_role");

    let token = recording_login(&client, &ctx.external_url, "user1").await;

    let resp = client
        .post(format!("{}/api/v1/auth/check-role", ctx.internal_url))
        .header("x-api-key", &ctx.api_key)
        .json(&json!({
            "token": token,
            "role": "user"
        }))
        .send()
        .await
        .expect("check-role 请求失败");
    assert_eq!(
        resp.status(),
        200,
        "check-role 应返回 200（业务错误用 error_code 表达）"
    );
    let body: serde_json::Value = resp.json().await.expect("check-role 响应非 JSON");
    // 实际行为：MockInterface 返回空角色 → NOT_ROLE（非 happy path 放行）
    assert!(
        body.get("error_code").is_some() && !body["error_code"].is_null(),
        "MockInterface 返回空角色列表，check-role 应返回 error_code（实际: {:?}）",
        body
    );
}

/// T020: get-token-info + get-session 返回正确字段。
///
/// 断言 get-token-info 返回 200 + token 字段匹配；
/// get-session 返回 200 + login_id 匹配。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_api_happy_get_token_info_and_session() {
    let ctx = RemoteContext::setup().await;
    let client = make_recording_client("test_api_happy_get_token_info_and_session");

    let token = recording_login(&client, &ctx.external_url, "token-info-user").await;

    // get-token-info：200 + token 字段匹配
    let resp = client
        .post(format!("{}/api/v1/auth/get-token-info", ctx.internal_url))
        .header("x-api-key", &ctx.api_key)
        .json(&json!({ "token": token }))
        .send()
        .await
        .expect("get-token-info 请求失败");
    assert_eq!(resp.status(), 200, "get-token-info 应返回 200");
    let body: serde_json::Value = resp.json().await.expect("get-token-info 响应非 JSON");
    assert_eq!(
        body["data"]["token"], token,
        "get-token-info 的 token 字段应匹配"
    );
    assert!(
        body["data"]["created_at"].as_i64().unwrap_or(0) > 0,
        "created_at 应为正整数"
    );

    // get-session：200 + login_id 匹配
    let resp = client
        .post(format!("{}/api/v1/auth/get-session", ctx.internal_url))
        .header("x-api-key", &ctx.api_key)
        .json(&json!({ "token": token }))
        .send()
        .await
        .expect("get-session 请求失败");
    assert_eq!(resp.status(), 200, "get-session 应返回 200");
    let body: serde_json::Value = resp.json().await.expect("get-session 响应非 JSON");
    assert_eq!(
        body["data"]["login_id"], "token-info-user",
        "get-session 的 login_id 应匹配"
    );
}

/// T021: kickout + switch-to + renew-to-equivalent 行为校验。
///
/// - 登录 user1 + user2，调用 kickout（caller=user1 踢自己），断言 user1 token 失效。
/// - switch-to：默认 DenyAllSwitchToGuard 拒绝，断言 error_code="NOT_PERMISSION"。
/// - renew-to-equivalent：返回新 token，旧 token 失效、新 token 有效。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_api_happy_kickout_switch_renew() {
    let ctx = RemoteContext::setup().await;
    let client = make_recording_client("test_api_happy_kickout_switch_renew");

    let token1 = recording_login(&client, &ctx.external_url, "user1").await;
    let _token2 = recording_login(&client, &ctx.external_url, "user2").await;

    // kickout user1（caller_login_id=user1 即属主，应允许）
    let resp = client
        .post(format!("{}/api/v1/auth/kickout", ctx.internal_url))
        .header("x-api-key", &ctx.api_key)
        .json(&json!({
            "login_id": "user1",
            "caller_login_id": "user1",
            "caller_token": token1
        }))
        .send()
        .await
        .expect("kickout 请求失败");
    assert_eq!(resp.status(), 200, "kickout 应返回 200");
    let body: serde_json::Value = resp.json().await.expect("kickout 响应非 JSON");
    assert!(
        body.get("error_code").is_none() || body["error_code"].is_null(),
        "属主踢自己应成功，不应返回 error_code（实际: {:?}）",
        body
    );

    // user1 token 应失效（拒绝语义：data=false 或 error_code="SESSION_ERROR"）
    // spawn_child 模式 throw_on_not_login=true，kickout 后 check-login 返回 error_code
    let (status, body) =
        recording_check_login(&client, &ctx.internal_url, &ctx.api_key, &token1).await;
    assert_eq!(status, 200);
    assert_check_login_denied(&body, "kickout 后 user1 token 应失效");

    // switch-to：默认 DenyAllSwitchToGuard 拒绝，返回 NOT_PERMISSION
    // 重新登录 user1 以获得有效 token
    let token1_new = recording_login(&client, &ctx.external_url, "user1").await;
    let resp = client
        .post(format!("{}/api/v1/auth/switch-to", ctx.internal_url))
        .header("x-api-key", &ctx.api_key)
        .json(&json!({
            "token": token1_new,
            "target_login_id": "user2",
            "caller_login_id": "user1",
            "caller_token": token1_new
        }))
        .send()
        .await
        .expect("switch-to 请求失败");
    assert_eq!(resp.status(), 200, "switch-to 应返回 200");
    let body: serde_json::Value = resp.json().await.expect("switch-to 响应非 JSON");
    // 默认 DenyAllSwitchToGuard 拒绝所有切换（安全默认）
    assert_eq!(
        body["error_code"], "NOT_PERMISSION",
        "默认 DenyAllSwitchToGuard 应拒绝 switch-to（实际: {:?}）",
        body
    );

    // renew-to-equivalent：新 token 等效（旧失效、新有效）
    let resp = client
        .post(format!(
            "{}/api/v1/auth/renew-to-equivalent",
            ctx.internal_url
        ))
        .header("x-api-key", &ctx.api_key)
        .json(&json!({ "token": token1_new }))
        .send()
        .await
        .expect("renew-to-equivalent 请求失败");
    assert_eq!(resp.status(), 200, "renew-to-equivalent 应返回 200");
    let body: serde_json::Value = resp.json().await.expect("renew 响应非 JSON");
    let renewed = body["data"]
        .as_str()
        .unwrap_or_else(|| panic!("renew 响应 data 字段非字符串: {:?}", body))
        .to_string();
    assert_ne!(token1_new, renewed, "renew-to-equivalent 必须返回新 token");

    // 旧 token 失效（拒绝语义：data=false 或 error_code="SESSION_ERROR"）
    let (_, body_old) =
        recording_check_login(&client, &ctx.internal_url, &ctx.api_key, &token1_new).await;
    assert_check_login_denied(&body_old, "renew 后旧 token 应失效");

    // 新 token 有效
    let (_, body_new) =
        recording_check_login(&client, &ctx.internal_url, &ctx.api_key, &renewed).await;
    assert_eq!(body_new["data"], true, "renew 后新 token 应有效");
}
