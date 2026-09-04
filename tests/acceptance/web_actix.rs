//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! actix-web 域验收（ACC-ACTX-NNN，spec acceptance-matrix R-acceptance-matrix-001，
//! 任务 T028，补盲）。
//!
//! 与 `web_smoke`（spawn_actix 冒烟、CheckLogin 基线）区分，本域覆盖：
//! - 001 `GarrisonRouter::into_middleware()` middleware 矩阵：无 token 401 /
//!   有效 token 200 / 权限不足 403（`test::init_service` + `TestRequest` 直连）；
//! - 002-005 per-handler extractor 矩阵：`GarrisonPrincipal`（login_id 解析）/
//!   `CheckLogin` / `CheckRole` / `CheckPermission` 通过与拒绝（401/403）；
//! - 006 `TenantContext` extractor 服务链（`tenant-isolation` 门控，X-Tenant-Id 解析 +
//!   fail-closed 拒绝路径）；
//! - 007 `TenantContext` extractor 值语义（`FromRequest` 直连：tenant_id /
//!   `TenantSource::Header` / 非数字拒绝）；
//! - 008 三框架一致性：`GarrisonError` 经 actix `ResponseError` 的状态码 +
//!   error_code/message body，与 `response_parts()` / `to_json_body()` 对齐
//!   （NotLogin / NotPermission / Internal 三例）。
//!
//! 错误断言统一锚定 `GarrisonError::response_parts()` / `to_json_body()`
//! （src/error.rs，三框架一致性基准）。
//!
//! 场景编号约定：`ACC-<域>-NNN（正常|异常）`，本域 `actx`。
//! 涉及 `GarrisonManager` 全局单例的用例一律 `#[serial]`；008 纯 trait 断言
//! 不触碰单例，可并行。

#![cfg(feature = "web-actix")]

use crate::common::harness::{web_test_config, GarrisonTestHarness, MockInterface};
use actix_web::body::to_bytes;
use actix_web::web;
use actix_web::{test, App};
use garrison::annotation::Annotation;
use garrison::error::GarrisonError;
use garrison::stp::GarrisonUtil;
use garrison::web_actix::{
    CheckLogin, CheckPermission, CheckRole, GarrisonPrincipal, GarrisonRouter, RequiredPermission,
    RequiredRole,
};
use serial_test::serial;

#[cfg(feature = "tenant-isolation")]
use garrison::context::tenant::TenantSource;

// ============================================================================
// 通用辅助
// ============================================================================

/// 设置默认 TENANT scope（tenant_id=0）：`tenant-isolation` 启用时权限/角色查询
/// fail-closed（`ctx-tenant-context-missing`），需进入租户上下文。
/// src 版本被 `cfg(any(test, feature = "testing"))` 门控，集成测试按既有惯例
/// 内置本地副本（src/web_actix/tests.rs 同构）。
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

/// actix 错误响应与 `response_parts()` / `to_json_body()` 对齐断言
/// （三框架一致性基准：状态码对齐 + body JSON 全等）。
/// 泛型 body：middleware 包装链产出 `ServiceResponse<EitherBody<BoxBody>>`，
/// 统一约束 `MessageBody`。
async fn assert_actix_error_aligned<B>(
    resp: actix_web::dev::ServiceResponse<B>,
    err: &GarrisonError,
) where
    B: actix_web::body::MessageBody + 'static,
{
    let (status, _, _, _) = err.response_parts();
    assert_eq!(
        resp.status().as_u16(),
        status,
        "状态码应与 response_parts() 对齐"
    );
    let bytes = to_bytes(resp.into_body())
        .await
        .map_err(std::convert::Into::into)
        .expect("actix body read");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("错误响应体应为 JSON");
    assert_eq!(body, err.to_json_body(), "响应体应与 to_json_body() 对齐");
}

// ============================================================================
// ACC-ACTX-001：GarrisonRouter::into_middleware() 矩阵
// ============================================================================

/// ACC-ACTX-001（正常+异常）：middleware 矩阵（`GarrisonRouter::into_middleware()` +
/// `with_header_tenant()` 生产路径）——
/// （a）无 token 访问 CheckLogin 路径 → 401（body 与 `NotLogin` 基准对齐）；
/// （b）有效 token → 200；持有 `admin:read` 权限访问 `CheckPermission` 路径 → 200；
/// （c）有效 token 但无权限（`deny_all` 收回）→ 403（body 与 `NotPermission` 基准对齐）。
///
/// `tenant-isolation` 启用时权限查询 fail-closed（无租户上下文返回
/// `ctx-tenant-context-missing` → 500），故经 `with_header_tenant()` 配置
/// `HeaderTenantResolver`，请求携带 `X-Tenant-Id` 进入生产链路（src/web_actix
/// tests.rs 同构装配）。
#[tokio::test]
#[serial]
async fn acc_actx_001_middleware_into_middleware_matrix() {
    let interface = MockInterface::new();
    interface.allow("1001", &["admin:read"], &[]);
    let _h = GarrisonTestHarness::builder()
        .interface(interface.clone())
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");

    let middleware = GarrisonRouter::new(web_test_config())
        .with_header_tenant()
        .route_protected("/protected", Annotation::CheckLogin)
        .route_protected(
            "/admin",
            Annotation::CheckPermission("admin:read".to_string()),
        )
        .into_middleware();
    let app = test::init_service(
        App::new()
            .wrap(middleware)
            .route("/protected", web::get().to(|| async { "ok" }))
            .route("/admin", web::get().to(|| async { "admin_ok" })),
    )
    .await;

    // （a）无 token → 401
    let req = test::TestRequest::get()
        .uri("/protected")
        .insert_header(("X-Tenant-Id", "42"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_actix_error_aligned(
        resp,
        &GarrisonError::NotLogin("router-not-login".to_string()),
    )
    .await;

    // （b1）有效 token → 200（CheckLogin 路径）
    let req = test::TestRequest::get()
        .uri("/protected")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("X-Tenant-Id", "42"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "有效 token 应放行 200");

    // （b2）有效 token + 持有权限 + 租户头 → 200（CheckPermission 路径）
    let req = test::TestRequest::get()
        .uri("/admin")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("X-Tenant-Id", "42"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        200,
        "持有 admin:read 应放行 200，实际: {}",
        resp.status()
    );

    // （c）有效 token 但无权限（deny_all 收回后）→ 403
    interface.deny_all();
    let req = test::TestRequest::get()
        .uri("/admin")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .insert_header(("X-Tenant-Id", "42"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_actix_error_aligned(
        resp,
        &GarrisonError::NotPermission("router-not-permission".to_string()),
    )
    .await;
}

// ============================================================================
// ACC-ACTX-002..005：extractor 矩阵
// ============================================================================

/// `GarrisonPrincipal` extractor 的 handler：回显当前登录主体。
async fn actx_principal_handler(principal: GarrisonPrincipal) -> String {
    format!("login_id={}", principal.login_id)
}

/// `CheckLogin` extractor 的 handler。
async fn actx_check_login_handler(_auth: CheckLogin) -> &'static str {
    "ok"
}

/// `CheckRole` extractor 的 handler。
async fn actx_check_role_handler(_auth: CheckRole) -> &'static str {
    "ok"
}

/// `CheckPermission` extractor 的 handler。
async fn actx_check_permission_handler(_auth: CheckPermission) -> &'static str {
    "ok"
}

/// ACC-ACTX-002（正常+异常）：`GarrisonPrincipal` extractor——
/// 从 `Authorization: Bearer` header 解析登录主体并回显 `login_id`（200）；
/// 无 token 时 extractor 拒绝，经 `ResponseError` 映射为 401（与基准对齐）。
#[tokio::test]
#[serial]
async fn acc_actx_002_extractor_garrison_principal_pass_and_401() {
    let _h = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(web_test_config()))
            .route("/whoami", web::get().to(actx_principal_handler)),
    )
    .await;

    // 正常：header 携带有效 token → 200 + login_id
    let req = test::TestRequest::get()
        .uri("/whoami")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "有效 token 应解析 login_id");
    let bytes = to_bytes(resp.into_body()).await.expect("actix body read");
    assert_eq!(
        String::from_utf8(bytes.to_vec()).unwrap(),
        "login_id=1001",
        "handler 应回显已解析的 login_id"
    );

    // 异常：无 token → 401
    let req = test::TestRequest::get().uri("/whoami").to_request();
    let resp = test::call_service(&app, req).await;
    assert_actix_error_aligned(resp, &GarrisonError::NotLogin("web-not-login".to_string())).await;
}

/// ACC-ACTX-003（正常+异常）：`CheckLogin` extractor——有效 token 放行 200；
/// 无 token 拒绝 401（与基准对齐）。
#[tokio::test]
#[serial]
async fn acc_actx_003_extractor_check_login_pass_and_401() {
    let _h = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(web_test_config()))
            .route("/login", web::get().to(actx_check_login_handler)),
    )
    .await;

    // 正常
    let req = test::TestRequest::get()
        .uri("/login")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "有效 token 应通过 CheckLogin");

    // 异常
    let req = test::TestRequest::get().uri("/login").to_request();
    let resp = test::call_service(&app, req).await;
    assert_actix_error_aligned(resp, &GarrisonError::NotLogin("web-not-login".to_string())).await;
}

/// ACC-ACTX-004（正常+异常）：`CheckRole` extractor（角色经 `web::Data<RequiredRole>`
/// 服务端配置，CRITICAL-12）——持有 `admin` 角色放行 200；无角色拒绝 403
/// （body 与 `NotRole` 基准对齐）。
#[tokio::test]
#[serial]
async fn acc_actx_004_extractor_check_role_pass_and_403() {
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

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(web_test_config()))
            .app_data(web::Data::new(RequiredRole("admin".to_string())))
            .route("/role", web::get().to(actx_check_role_handler)),
    )
    .await;

    // 正常：持有 admin → 200
    let req = test::TestRequest::get()
        .uri("/role")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = with_default_tenant(async { test::call_service(&app, req).await }).await;
    assert_eq!(resp.status().as_u16(), 200, "持有 admin 角色应放行 200");

    // 异常：无角色 → 403
    let req = test::TestRequest::get()
        .uri("/role")
        .insert_header(("Authorization", format!("Bearer {token_no_role}")))
        .to_request();
    let resp = with_default_tenant(async { test::call_service(&app, req).await }).await;
    assert_actix_error_aligned(resp, &GarrisonError::NotRole("web-not-role".to_string())).await;
}

/// ACC-ACTX-005（正常+异常）：`CheckPermission` extractor（权限经
/// `web::Data<RequiredPermission>` 服务端配置，CRITICAL-12）——持有 `user:read`
/// 放行 200；无权限拒绝 403（body 与 `NotPermission` 基准对齐）。
#[tokio::test]
#[serial]
async fn acc_actx_005_extractor_check_permission_pass_and_403() {
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

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(web_test_config()))
            .app_data(web::Data::new(RequiredPermission("user:read".to_string())))
            .route("/perm", web::get().to(actx_check_permission_handler)),
    )
    .await;

    // 正常：持有 user:read → 200
    let req = test::TestRequest::get()
        .uri("/perm")
        .insert_header(("Authorization", format!("Bearer {token}")))
        .to_request();
    let resp = with_default_tenant(async { test::call_service(&app, req).await }).await;
    assert_eq!(resp.status().as_u16(), 200, "持有 user:read 应放行 200");

    // 异常：无权限 → 403
    let req = test::TestRequest::get()
        .uri("/perm")
        .insert_header(("Authorization", format!("Bearer {token_no_perm}")))
        .to_request();
    let resp = with_default_tenant(async { test::call_service(&app, req).await }).await;
    assert_actix_error_aligned(
        resp,
        &GarrisonError::NotPermission("web-not-permission".to_string()),
    )
    .await;
}

// ============================================================================
// ACC-ACTX-006..007：TenantContext extractor（tenant-isolation 门控）
// ============================================================================

/// `TenantContext` extractor 的 handler：回显租户解析结果。
#[cfg(feature = "tenant-isolation")]
async fn actx_tenant_handler(ctx: garrison::context::tenant::TenantContext) -> String {
    format!("tenant_id={}", ctx.tenant_id)
}

/// ACC-ACTX-006（正常+异常）：`TenantContext` extractor（`tenant-isolation`）——
/// `X-Tenant-Id: 42` 经服务链解析出 `tenant_id=42`（200）；缺失 header 时
/// extractor 显性拒绝（fail-closed，不默认 0），经 `ResponseError` 映射为
/// 500 CONFIG_ERROR。
#[cfg(feature = "tenant-isolation")]
#[tokio::test]
#[serial]
async fn acc_actx_006_extractor_tenant_context_pass_and_reject() {
    let _h = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");

    let app =
        test::init_service(App::new().route("/tenant", web::get().to(actx_tenant_handler))).await;

    // 正常：X-Tenant-Id 解析
    let req = test::TestRequest::get()
        .uri("/tenant")
        .insert_header(("X-Tenant-Id", "42"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status().as_u16(), 200, "X-Tenant-Id 应成功解析");
    let bytes = to_bytes(resp.into_body()).await.expect("actix body read");
    assert_eq!(
        String::from_utf8(bytes.to_vec()).unwrap(),
        "tenant_id=42",
        "handler 应回显解析的 tenant_id"
    );

    // 异常：缺失 header → fail-closed（500 CONFIG_ERROR，不默认 0）
    let req = test::TestRequest::get().uri("/tenant").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(
        resp.status().as_u16(),
        500,
        "缺失 X-Tenant-Id 应显性失败（fail-closed）"
    );
    let bytes = to_bytes(resp.into_body()).await.expect("actix body read");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("错误响应体应为 JSON");
    assert_eq!(body["error_code"], "CONFIG_ERROR", "应返回 CONFIG_ERROR");
}

/// ACC-ACTX-007（正常+异常）：`TenantContext` extractor 值语义（`tenant-isolation`）——
/// 直接经 `FromRequest` 验证：`X-Tenant-Id: 42` → `tenant_id=42` +
/// `resolved_from=TenantSource::Header`；非数字 header 显性拒绝（不默认 0、
/// 不吞错，Rule 12 失败显性化）。
#[cfg(feature = "tenant-isolation")]
#[tokio::test]
#[serial]
async fn acc_actx_007_tenant_context_from_request_value() {
    use actix_web::FromRequest;

    let _h = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");

    // 正常：解析 X-Tenant-Id
    let req = test::TestRequest::get()
        .uri("/tenant")
        .insert_header(("X-Tenant-Id", "42"))
        .to_http_request();
    let mut payload = actix_web::dev::Payload::None;
    let ctx = garrison::context::tenant::TenantContext::from_request(&req, &mut payload)
        .await
        .expect("X-Tenant-Id 应成功解析");
    assert_eq!(ctx.tenant_id, 42, "tenant_id 应为 42");
    assert_eq!(
        ctx.resolved_from,
        TenantSource::Header,
        "解析来源应为 TenantSource::Header"
    );

    // 异常：非数字 tenant_id → 显性 Err（Config）
    let req = test::TestRequest::get()
        .uri("/tenant")
        .insert_header(("X-Tenant-Id", "not-a-number"))
        .to_http_request();
    let mut payload = actix_web::dev::Payload::None;
    let result = garrison::context::tenant::TenantContext::from_request(&req, &mut payload).await;
    assert!(
        result.is_err(),
        "非数字 X-Tenant-Id 应显性失败，实际: {:?}",
        result
    );
}

// ============================================================================
// ACC-ACTX-008：三框架一致性（ResponseError vs response_parts/to_json_body）
// ============================================================================

/// ACC-ACTX-008（正常）：`GarrisonError` 经 actix `ResponseError` 的状态码 +
/// error_code/message body 与 `response_parts()` / `to_json_body()` 对齐——
/// `NotLogin`(401/NOT_LOGIN)、`NotPermission`(403/NOT_PERMISSION)、
/// `Internal`(500/INTERNAL_ERROR) 三例（三框架一致性基准，纯 trait 断言不触碰单例）。
#[tokio::test]
async fn acc_actx_008_error_response_parts_alignment() {
    use actix_web::ResponseError;

    let cases: [(GarrisonError, u16); 3] = [
        (GarrisonError::NotLogin("test".to_string()), 401),
        (GarrisonError::NotPermission("test".to_string()), 403),
        (GarrisonError::Internal("test".to_string()), 500),
    ];

    for (err, expected_status) in cases {
        // 基准
        let (status, error_code, _, _) = err.response_parts();
        assert_eq!(status, expected_status, "response_parts 状态码基准");
        let expected_body = err.to_json_body();

        // actix 适配
        assert_eq!(
            err.status_code().as_u16(),
            status,
            "actix status_code 应与 response_parts() 对齐"
        );
        let resp = err.error_response();
        assert_eq!(
            resp.status().as_u16(),
            status,
            "actix error_response 状态码应与 response_parts() 对齐"
        );
        let bytes = to_bytes(resp.into_body()).await.expect("actix body read");
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("响应体应为 JSON");
        assert_eq!(body, expected_body, "actix body 应与 to_json_body() 对齐");

        // error_code 显式校验（NOT_LOGIN / NOT_PERMISSION / INTERNAL_ERROR）
        assert_eq!(
            body["error_code"].as_str().unwrap(),
            error_code,
            "error_code 应与 response_parts 同源"
        );
    }
}
