//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! warp 域验收（ACC-WARP-NNN，spec acceptance-matrix R-acceptance-matrix-001，
//! 任务 T029，补盲）。
//!
//! 与 `web_smoke`（spawn_warp 冒烟、CheckLogin 基线）区分，本域覆盖：
//! - 001-003 guard Filter 矩阵：`check_login` / `check_role` / `check_permission`
//!   通过与拒绝（`warp::test::request().filter()`，拒绝统一为 `GarrisonRejection`）；
//! - 004 `garrison_principal` value Filter：从 token 解析 `login_id`；
//! - 005 `tenant_context` value Filter（`tenant-isolation` 门控，X-Tenant-Id 解析）；
//! - 006 `GarrisonRejection` 一致性：`.recover(garrison_recover)` 后响应含
//!   `error_code` / `message` JSON，状态码与 `response_parts()` 对齐、
//!   body 与 `to_json_body()` 全等（401 / 200 / 403 三态）。
//!
//! 场景编号约定：`ACC-<域>-NNN（正常|异常）`，本域 `warp`。
//! 涉及 `GarrisonManager` 全局单例的用例一律 `#[serial]`。

#![cfg(feature = "web-warp")]

use crate::common::harness::{web_test_config, GarrisonTestHarness, MockInterface};
use garrison::error::GarrisonError;
use garrison::stp::GarrisonUtil;
use garrison::web_warp::{
    check_login, check_permission, check_role, garrison_principal, garrison_recover,
    GarrisonRejection,
};
use serial_test::serial;
use warp::Filter;

#[cfg(feature = "tenant-isolation")]
use garrison::context::tenant::TenantSource;
#[cfg(feature = "tenant-isolation")]
use garrison::web_warp::tenant_context;

// ============================================================================
// 通用辅助
// ============================================================================

/// 设置默认 TENANT scope（tenant_id=0）：`tenant-isolation` 启用时权限/角色查询
/// fail-closed（`ctx-tenant-context-missing`），需进入租户上下文。
/// src 版本被 `cfg(any(test, feature = "testing"))` 门控，集成测试按既有惯例
/// 内置本地副本（src/web_warp/tests.rs 同构）。
async fn with_default_tenant<F, R>(f: F) -> R
where
    F: std::future::Future<Output = R>,
{
    use garrison::{TenantContext, TenantSource, TENANT};
    let ctx = TenantContext {
        tenant_id: 0,
        resolved_from: TenantSource::Header,
    };
    TENANT.scope(ctx, f).await
}

/// warp 错误响应与 `response_parts()` / `to_json_body()` 对齐断言
/// （三框架一致性基准：状态码对齐 + body JSON 全等）。
/// 泛型 body：`warp::test::request().reply()` 返回 `http::Response<Bytes>`，
/// 统一以 `AsRef<[u8]>` 读取。
async fn assert_warp_error_aligned<R>(resp: &warp::http::Response<R>, err: &GarrisonError)
where
    R: AsRef<[u8]>,
{
    let (status, _, _, _) = err.response_parts();
    assert_eq!(
        resp.status().as_u16(),
        status,
        "状态码应与 response_parts() 对齐"
    );
    let body: serde_json::Value =
        serde_json::from_slice(resp.body().as_ref()).expect("错误响应体应为 JSON");
    assert_eq!(body, err.to_json_body(), "响应体应与 to_json_body() 对齐");
}

/// 断言拒绝链中含有 `GarrisonRejection`（warp 拒绝统一包装点）。
fn assert_garrison_rejection(err: warp::Rejection, ctx: &str) {
    assert!(
        err.find::<GarrisonRejection>().is_some(),
        "{ctx}：拒绝应为 GarrisonRejection，实际: {err:?}"
    );
}

// ============================================================================
// ACC-WARP-001..003：guard Filter 矩阵
// ============================================================================

/// ACC-WARP-001（正常+异常）：`check_login` guard Filter——有效 token 通过
/// （Extract=()`）；无 token 拒绝为 `GarrisonRejection`。
#[tokio::test]
#[serial]
async fn acc_warp_001_guard_check_login_pass_and_reject() {
    let _h = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");

    let filter = check_login(web_test_config());

    // 正常：有效 token → 通过
    let result = warp::test::request()
        .header("authorization", format!("Bearer {token}"))
        .filter(&filter)
        .await;
    assert!(result.is_ok(), "有效 token 应通过 check_login guard");

    // 异常：无 token → GarrisonRejection
    let result = warp::test::request().filter(&filter).await;
    assert_garrison_rejection(
        result.expect_err("无 token 应被拒绝"),
        "check_login 无 token",
    );
}

/// ACC-WARP-002（正常+异常）：`check_role("admin")` guard Filter——持有
/// `admin` 角色通过；无角色拒绝为 `GarrisonRejection`。
/// `tenant-isolation` 下角色查询 fail-closed，包 `with_default_tenant`。
#[tokio::test]
#[serial]
async fn acc_warp_002_guard_check_role_pass_and_reject() {
    let interface = MockInterface::new();
    interface.allow("1001", &[], &["admin"]);
    let _h = GarrisonTestHarness::builder()
        .interface(interface.clone())
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");
    let token_no_role = GarrisonUtil::login_simple("1002")
        .await
        .expect("login_simple 应签发 token");

    let filter = check_role(web_test_config(), "admin".to_string());

    // 正常：持有 admin → 通过
    let result = with_default_tenant(async {
        warp::test::request()
            .header("authorization", format!("Bearer {token}"))
            .filter(&filter)
            .await
    })
    .await;
    assert!(result.is_ok(), "持有 admin 角色应通过 check_role guard");

    // 异常：无角色 → GarrisonRejection
    let result = with_default_tenant(async {
        warp::test::request()
            .header("authorization", format!("Bearer {token_no_role}"))
            .filter(&filter)
            .await
    })
    .await;
    assert_garrison_rejection(result.expect_err("无角色应被拒绝"), "check_role 无角色");
}

/// ACC-WARP-003（正常+异常）：`check_permission("user:read")` guard Filter——
/// 持有 `user:read` 权限通过；无权限拒绝为 `GarrisonRejection`。
#[tokio::test]
#[serial]
async fn acc_warp_003_guard_check_permission_pass_and_reject() {
    let interface = MockInterface::new();
    interface.allow("1001", &["user:read"], &[]);
    let _h = GarrisonTestHarness::builder()
        .interface(interface.clone())
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");
    let token_no_perm = GarrisonUtil::login_simple("1002")
        .await
        .expect("login_simple 应签发 token");

    let filter = check_permission(web_test_config(), "user:read".to_string());

    // 正常：持有 user:read → 通过
    let result = with_default_tenant(async {
        warp::test::request()
            .header("authorization", format!("Bearer {token}"))
            .filter(&filter)
            .await
    })
    .await;
    assert!(
        result.is_ok(),
        "持有 user:read 应通过 check_permission guard"
    );

    // 异常：无权限 → GarrisonRejection
    let result = with_default_tenant(async {
        warp::test::request()
            .header("authorization", format!("Bearer {token_no_perm}"))
            .filter(&filter)
            .await
    })
    .await;
    assert_garrison_rejection(
        result.expect_err("无权限应被拒绝"),
        "check_permission 无权限",
    );
}

// ============================================================================
// ACC-WARP-004..005：value Filter（garrison_principal / tenant_context）
// ============================================================================

/// ACC-WARP-004（正常+异常）：`garrison_principal` value Filter——
/// 从 `Authorization: Bearer` token 解析 `login_id`（Extract=`GarrisonPrincipal`）；
/// 无 token 拒绝为 `GarrisonRejection`。
#[tokio::test]
#[serial]
async fn acc_warp_004_value_garrison_principal_resolves_login_id() {
    let _h = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");

    let filter = garrison_principal(web_test_config());

    // 正常：解析 login_id
    let principal = warp::test::request()
        .header("authorization", format!("Bearer {token}"))
        .filter(&filter)
        .await
        .expect("有效 token 应解析出 GarrisonPrincipal");
    assert_eq!(
        principal.login_id, "1001",
        "garrison_principal 应解析出登录主体 1001"
    );

    // 异常：无 token → GarrisonRejection
    let result = warp::test::request().filter(&filter).await;
    assert_garrison_rejection(
        result.expect_err("无 token 应被拒绝"),
        "garrison_principal 无 token",
    );
}

/// ACC-WARP-005（正常+异常）：`tenant_context` value Filter（`tenant-isolation`）——
/// `X-Tenant-Id: 42` 解析出 `tenant_id=42` + `TenantSource::Header`；
/// 缺失 header / 非数字 header 拒绝为 `GarrisonRejection`（fail-closed，
/// 不默认 0、不吞错）。
#[cfg(feature = "tenant-isolation")]
#[tokio::test]
#[serial]
async fn acc_warp_005_value_tenant_context_resolves_tenant_id() {
    let _h = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");

    let filter = tenant_context();

    // 正常：解析 X-Tenant-Id
    let ctx = warp::test::request()
        .header("X-Tenant-Id", "42")
        .filter(&filter)
        .await
        .expect("X-Tenant-Id 应成功解析");
    assert_eq!(ctx.tenant_id, 42, "tenant_id 应为 42");
    assert_eq!(
        ctx.resolved_from,
        TenantSource::Header,
        "解析来源应为 TenantSource::Header"
    );

    // 异常：缺失 header → GarrisonRejection
    let result = warp::test::request().filter(&filter).await;
    assert_garrison_rejection(
        result.expect_err("缺失 X-Tenant-Id 应被拒绝"),
        "tenant_context 缺失 header",
    );

    // 异常：非数字 tenant_id → GarrisonRejection
    let result = warp::test::request()
        .header("X-Tenant-Id", "not-a-number")
        .filter(&filter)
        .await;
    assert_garrison_rejection(
        result.expect_err("非数字 X-Tenant-Id 应被拒绝"),
        "tenant_context 非数字",
    );
}

// ============================================================================
// ACC-WARP-006：GarrisonRejection 一致性（recover 后三框架统一 JSON）
// ============================================================================

/// ACC-WARP-006（正常+异常）：`.recover(garrison_recover)` 后——
/// （a）无 token 访问 CheckLogin 路由 → 401，body 与 `NotLogin` 基准全等；
/// （b）有效 token → 200 放行；
/// （c）有效 token 但无权限访问 CheckPermission 路由 → 403，body 与
/// `NotPermission` 基准全等。warp 拒绝链必须显式挂 `garrison_recover`
/// 才能产出与 axum/actix 一致的 `error_code`/`message` JSON（三框架一致性）。
#[tokio::test]
#[serial]
async fn acc_warp_006_rejection_recover_status_and_body_alignment() {
    let _h = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");

    let protected = warp::get()
        .and(warp::path("protected"))
        .and(warp::path::end())
        .and(check_login(web_test_config()))
        .map(|()| "ok");
    let admin = warp::get()
        .and(warp::path("admin"))
        .and(warp::path::end())
        .and(check_permission(web_test_config(), "user:read".to_string()))
        .map(|()| "admin_ok");
    let routes = protected.or(admin).recover(garrison_recover);

    // （a）异常：无 token → 401 + NOT_LOGIN（与基准对齐）
    let resp = warp::test::request()
        .path("/protected")
        .reply(&routes)
        .await;
    assert_warp_error_aligned(&resp, &GarrisonError::NotLogin("web-not-login".to_string())).await;

    // （b）正常：有效 token → 200
    let resp = warp::test::request()
        .path("/protected")
        .header("authorization", format!("Bearer {token}"))
        .reply(&routes)
        .await;
    assert_eq!(resp.status().as_u16(), 200, "有效 token 应放行 200");

    // （c）异常：有效 token 但无权限 → 403 + NOT_PERMISSION（与基准对齐）
    let resp = with_default_tenant(async {
        warp::test::request()
            .path("/admin")
            .header("authorization", format!("Bearer {token}"))
            .reply(&routes)
            .await
    })
    .await;
    assert_eq!(resp.status().as_u16(), 403, "无权限应拒绝 403");
    assert_warp_error_aligned(
        &resp,
        &GarrisonError::NotPermission("web-not-permission".to_string()),
    )
    .await;
}
