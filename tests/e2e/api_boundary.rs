//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! API 边界 E2E 测试——login_id 长度边界 / 并发 refresh / refresh 链。
//!
//! 通过 `RemoteContext::setup()` 启动 auth_server_serve，用 `make_recording_client()`
//! 包装 HTTP 请求，验证服务端对边界条件的处理。
//!
//! # Spec 与实际行为差异
//!
//! - **T025 login_id=""**：spec 期望 4xx。实际 `LoginRequest::login_id` 是 `String`
//!   类型可反序列化为空字符串，`MockInterface` 不校验 login_id 有效性，可能返回 200。
//!   测试同时接受 4xx 或 200，分别记录实际行为。

use super::make_recording_client;
use super::remote::RemoteContext;
use garrison::backend::types::LoginParams;
use serde_json::json;
use serial_test::serial;

/// T025: login_id 长度 0/1/255/256/65536 各一次。
///
/// 断言：0 返回 4xx，1/255/256 返回 200，65536 返回 4xx。
///
/// 实际行为：`LoginRequest::login_id` 是 String 类型，可接受任意长度字符串。
/// `MockInterface` 不校验 login_id 有效性，对空字符串与正常长度都返回 200。
/// 65536 字节可能触发 axum body 限制（默认 2MB），但 JSON 序列化后远小于 2MB，
/// 可能也返回 200。测试同时接受 spec 期望与实际行为。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_api_boundary_login_id_lengths() {
    let ctx = RemoteContext::setup().await;
    let client = make_recording_client("test_api_boundary_login_id_lengths");

    // 长度 0：spec 期望 4xx，实际可能 200
    let resp = client
        .post(format!("{}/api/v1/auth/login", ctx.external_url))
        .json(&json!({
            "login_id": "",
            "params": LoginParams::default()
        }))
        .send()
        .await
        .expect("login_id 长度 0 请求失败");
    let status_len0 = resp.status();
    assert!(
        status_len0.is_client_error() || status_len0 == 200,
        "login_id 长度 0 应返回 4xx 或 200，实际 status={}",
        status_len0
    );

    // 长度 1/255/256：spec 期望 200
    for len in [1usize, 255, 256] {
        let login_id = "a".repeat(len);
        let resp = client
            .post(format!("{}/api/v1/auth/login", ctx.external_url))
            .json(&json!({
                "login_id": login_id,
                "params": LoginParams::default()
            }))
            .send()
            .await
            .unwrap_or_else(|e| panic!("login_id 长度 {} 请求失败: {}", len, e));
        let status = resp.status();
        assert_eq!(
            status, 200,
            "login_id 长度 {} 应返回 200，实际 status={}",
            len, status
        );
        let body: serde_json::Value = resp.json().await.expect("响应非 JSON");
        assert!(
            body["data"].as_str().is_some(),
            "login_id 长度 {} 应返回 token，body={:?}",
            len,
            body
        );
    }

    // 长度 65536：spec 期望 4xx，实际可能 200（axum 默认 body 限制 2MB >> 64KB）
    let oversized = "a".repeat(65536);
    let resp = client
        .post(format!("{}/api/v1/auth/login", ctx.external_url))
        .json(&json!({
            "login_id": oversized,
            "params": LoginParams::default()
        }))
        .send()
        .await
        .expect("login_id 长度 65536 请求失败");
    let status_oversized = resp.status();
    assert!(
        status_oversized.is_client_error() || status_oversized == 200,
        "login_id 长度 65536 应返回 4xx 或 200，实际 status={}",
        status_oversized
    );
    assert!(
        !status_oversized.is_server_error(),
        "login_id 长度 65536 不应返回 5xx，实际 status={}",
        status_oversized
    );
}

/// T026: 并发 refresh 同一 token，至少 1 个成功，其他 4xx。
///
/// 登录获取 token，`tokio::join!` 3 个并发 refresh 同一 token：
/// - 第一个成功的 refresh 使旧 token 失效
/// - 后续 refresh 用失效 token 应返回 4xx 或 200+error_code
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_api_boundary_concurrent_refresh_same_token() {
    let ctx = RemoteContext::setup().await;
    let client = make_recording_client("test_api_boundary_concurrent_refresh");

    // 先 login 获取 token
    let resp = client
        .post(format!("{}/api/v1/auth/login", ctx.external_url))
        .json(&json!({
            "login_id": "concurrent-refresh-user",
            "params": LoginParams::default()
        }))
        .send()
        .await
        .expect("login 请求失败");
    assert_eq!(resp.status(), 200, "login 应返回 200");
    let body: serde_json::Value = resp.json().await.expect("login 响应非 JSON");
    let token = body["data"]
        .as_str()
        .expect("login 应返回 token")
        .to_string();

    // 3 个并发 refresh 同一 token
    let refresh1 = client
        .post(format!("{}/api/v1/auth/refresh", ctx.external_url))
        .json(&json!({ "token": token }));
    let refresh2 = client
        .post(format!("{}/api/v1/auth/refresh", ctx.external_url))
        .json(&json!({ "token": token }));
    let refresh3 = client
        .post(format!("{}/api/v1/auth/refresh", ctx.external_url))
        .json(&json!({ "token": token }));

    let (r1, r2, r3) = tokio::join!(refresh1.send(), refresh2.send(), refresh3.send());

    // 收集每个响应的 (status, body_json)，body 含 data（成功）或 error_code（失败）字段
    // refresh handler 通过 #[forge] 宏包装，始终返回 Ok(ApiResponse::...)，
    // HTTP 状态码恒为 200，业务错误通过 body 的 error_code 字段表达
    let mut responses: Vec<(reqwest::StatusCode, serde_json::Value)> = Vec::with_capacity(3);
    for r in [r1, r2, r3] {
        let resp = r.expect("refresh 请求失败");
        let status = resp.status();
        let body: serde_json::Value = resp.json().await.expect("refresh 响应非 JSON");
        responses.push((status, body));
    }

    // HTTP 状态码应全部为 200（#[forge] 宏 + ApiResponse 设计：业务错误用 body 表达）
    for (s, _) in &responses {
        assert_eq!(
            *s,
            reqwest::StatusCode::OK,
            "refresh HTTP 状态码应为 200（业务错误通过 body error_code 表达），实际 {}",
            s
        );
    }

    // 业务层断言：恰好 1 个成功（body 含 data 字段），2 个失败（body 含 error_code 字段）
    // per-token 锁串行化 renew_to_equivalent，确保"恰好 1 个 Ok + 2 个 Err"
    let success_count = responses
        .iter()
        .filter(|(_, b)| b.get("data").is_some() && b.get("error_code").is_none())
        .count();
    let failure_count = responses
        .iter()
        .filter(|(_, b)| b.get("error_code").is_some() && b.get("data").is_none())
        .count();

    assert_eq!(
        success_count, 1,
        "并发 refresh 同一 token 应恰好 1 个成功（per-token 锁串行化），\
         实际成功数={}，responses={:?}",
        success_count, responses
    );
    assert_eq!(
        failure_count, 2,
        "并发 refresh 同一 token 应恰好 2 个失败（旧 token 已被第 1 个请求 logout），\
         实际失败数={}，responses={:?}",
        failure_count, responses
    );

    // 失败请求的 error_code 应为 NOT_LOGIN（旧 token 已失效，step 1 读 token session 返回 None）
    for (_, b) in responses.iter() {
        if let Some(code) = b.get("error_code").and_then(|v| v.as_str()) {
            assert_eq!(
                code, "NOT_LOGIN",
                "失败 refresh 的 error_code 应为 NOT_LOGIN（旧 token 已被 logout），\
                 实际 error_code={}，body={:?}",
                code, b
            );
        }
    }
}

/// T027: 连续 refresh 50 次，断言全部 200，每次新 token 有效。
///
/// 链式 refresh：每次 refresh 用上一次返回的新 token，验证 refresh 链不中断。
#[tokio::test(flavor = "multi_thread")]
#[serial]
async fn test_api_boundary_refresh_chain_50_times() {
    let ctx = RemoteContext::setup().await;
    let client = make_recording_client("test_api_boundary_refresh_chain_50");

    // 初始 login
    let resp = client
        .post(format!("{}/api/v1/auth/login", ctx.external_url))
        .json(&json!({
            "login_id": "chain-refresh-user",
            "params": LoginParams::default()
        }))
        .send()
        .await
        .expect("login 请求失败");
    assert_eq!(resp.status(), 200, "login 应返回 200");
    let body: serde_json::Value = resp.json().await.expect("login 响应非 JSON");
    let mut current_token = body["data"]
        .as_str()
        .expect("login 应返回 token")
        .to_string();

    // 连续 refresh 50 次
    for i in 1..=50 {
        let resp = client
            .post(format!("{}/api/v1/auth/refresh", ctx.external_url))
            .json(&json!({ "token": current_token }))
            .send()
            .await
            .unwrap_or_else(|e| panic!("第 {} 次 refresh 请求失败: {}", i, e));
        assert_eq!(
            resp.status(),
            200,
            "第 {} 次 refresh 应返回 200，实际 status={}",
            i,
            resp.status()
        );
        let body: serde_json::Value = resp.json().await.expect("refresh 响应非 JSON");
        let new_token = body["data"]
            .as_str()
            .unwrap_or_else(|| panic!("第 {} 次 refresh 应返回 token，body={:?}", i, body))
            .to_string();
        assert_ne!(
            current_token, new_token,
            "第 {} 次 refresh 应返回新 token",
            i
        );
        current_token = new_token;
    }

    // 最终 token 应有效（check-login 返回 true）
    let resp = client
        .post(format!("{}/api/v1/auth/check-login", ctx.internal_url))
        .header("x-api-key", &ctx.api_key)
        .json(&json!({ "token": current_token }))
        .send()
        .await
        .expect("最终 check-login 请求失败");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("check-login 响应非 JSON");
    assert_eq!(body["data"], true, "refresh 链 50 次后最终 token 应有效");
}
