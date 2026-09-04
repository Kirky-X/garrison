//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Web 三框架冒烟验收（ACC-WEB-SMOKE-NNN，spec test-harness R-test-harness-002）。
//!
//! 每框架用 `common::harness` 的同构辅助函数启动最小受保护服务器
//! （`spawn_axum` / `spawn_actix` / `spawn_warp`），验证 CheckLogin 语义：
//! 未登录 401 + 统一 `error_code`/`message` JSON；有效 token 200。
//! `GarrisonManager` 为进程级全局单例，全部用例以 `#[serial]` 串行。
//!
//! 场景编号约定：`ACC-<域>-NNN（正常|异常）`，本域为 `web-smoke`。

use crate::common::harness::{web_test_config, GarrisonTestHarness, SpawnedServer};
use garrison::stp::GarrisonUtil;
use serial_test::serial;

/// 三框架共用的 CheckLogin 语义断言：
/// （a）无 token 请求 `/protected` 返回 401，且 body 含 `error_code` 与 `message`
/// （统一错误 JSON，文案受 i18n 影响，只断言键存在不硬编码内容）；
/// （b）带 `Authorization: Bearer <token>` 请求返回 200。
async fn assert_protected_semantics(server: &SpawnedServer, token: &str) {
    let client = reqwest::Client::new();
    let url = format!("http://{}/protected", server.addr());

    // （a）未登录 → 401 + 统一错误 JSON
    let resp = client.get(&url).send().await.expect("请求应送达测试服务器");
    let status = resp.status();
    let body_text = resp.text().await.unwrap_or_default();
    assert_eq!(
        status, 401,
        "未登录访问受保护路由应返回 401，实际响应体: {body_text}"
    );
    let body: serde_json::Value =
        serde_json::from_str(&body_text).expect("401 响应体应为统一错误 JSON（三框架一致）");
    assert!(
        body.get("error_code").is_some(),
        "401 body 应含 error_code 字段（三框架一致），实际: {body}"
    );
    assert!(
        body.get("message").is_some(),
        "401 body 应含 message 字段（三框架一致），实际: {body}"
    );

    // （b）已登录 → 200
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {token}"))
        .send()
        .await
        .expect("请求应送达测试服务器");
    assert_eq!(resp.status(), 200, "有效 token 访问受保护路由应放行 200");
}

/// ACC-WEB-SMOKE-001（正常+异常）：axum 冒烟 —— 未登录 401 + 统一错误 JSON、
/// 有效 token 200（经 `GarrisonRouter` middleware）。
#[cfg(feature = "web-axum")]
#[tokio::test]
#[serial]
async fn acc_smoke_axum_001() {
    let _harness = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");

    let server = crate::common::harness::spawn_axum().await;
    assert_protected_semantics(&server, &token).await;
    server.shutdown().await;
}

/// ACC-WEB-SMOKE-002（正常+异常）：actix-web 冒烟 —— 未登录 401 + 统一错误 JSON、
/// 有效 token 200（经 `GarrisonRouter::into_middleware()`，actix 运行时跑在专属线程）。
#[cfg(feature = "web-actix")]
#[tokio::test]
#[serial]
async fn acc_smoke_actix_001() {
    let _harness = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");

    let server = crate::common::harness::spawn_actix().await;
    assert_protected_semantics(&server, &token).await;
    server.shutdown().await;
}

/// ACC-WEB-SMOKE-003（正常+异常）：warp 冒烟 —— 未登录 401 + 统一错误 JSON、
/// 有效 token 200（经 `check_login` filter + `.recover(garrison_recover)`）。
#[cfg(feature = "web-warp")]
#[tokio::test]
#[serial]
async fn acc_smoke_warp_001() {
    let _harness = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");

    let server = crate::common::harness::spawn_warp().await;
    assert_protected_semantics(&server, &token).await;
    server.shutdown().await;
}
