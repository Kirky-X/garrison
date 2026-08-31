//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! axum 域深度验收矩阵（ACC-WAX-NNN，spec acceptance-matrix R-acceptance-matrix-001，
//! 任务 T027）。
//!
//! 在 `web_smoke` 的 CheckLogin 冒烟基线（spawn_axum 全链路）之上做深度矩阵：
//! - 001-002 中间件 token 来源矩阵：Authorization header / Cookie（`garrison_token`）/
//!   header 优先于 cookie（oneshot 直连 `GarrisonRouter`）；
//! - 003-005 per-handler extractor 矩阵：`CheckLogin` / `CheckPermission` / `CheckRole`
//!   通过与 401/403（`PermissionName` / `RoleName` 类型化 marker）；
//! - 006-008 注解宏 `#[check_login]` / `#[check_permission]` / `#[check_role]`
//!   包装 handler 的编译与运行（`annotation-macros` 门控）；
//! - 009-012 Web 安全件：WAF（`firewall-waf`，原 `web-waf` 已废弃合并）、CORS、
//!   CSRF、安全响应头——正常放行 + 异常拦截。
//!
//! 错误断言统一锚定 `GarrisonError::response_parts()` / `to_json_body()`
//! （src/error.rs，三框架一致性基准）：状态码对齐 `response_parts().0`，
//! 响应体 JSON 与 `to_json_body()` 全等。
//!
//! 场景编号约定：`ACC-<域>-NNN（正常|异常）`，本域 `wax`，自 001 起独立计数。
//! 涉及 `GarrisonManager` 全局单例的用例一律 `#[serial]`（common/harness 约束）；
//! 纯中间件用例（009-012）不触碰单例，可并行。

#![cfg(feature = "web-axum")]

use crate::common::harness::{web_test_config, GarrisonTestHarness, MockInterface};
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::response::Response;
use axum::routing::get;
use axum::Router;
use garrison::annotation::{Annotation, CheckLogin, CheckPermission, CheckRole, Ignore};
use garrison::annotation::{PermissionName, RoleName};
use garrison::error::GarrisonError;
use garrison::router::GarrisonRouter;
use garrison::stp::GarrisonUtil;
use http_body_util::BodyExt;
use serial_test::serial;
use std::sync::Arc;
use tower::ServiceExt;

#[cfg(all(feature = "annotation-macros", feature = "abac"))]
use garrison::check_abac;
#[cfg(feature = "annotation-macros")]
use garrison::stp::with_current_token;
#[cfg(feature = "annotation-macros")]
use garrison::{check_access_token, check_client_token, check_mfa, check_temp_token};
#[cfg(feature = "annotation-macros")]
use garrison::{check_login, check_permission, check_role};

// ============================================================================
// 通用辅助
// ============================================================================

/// 设置默认 TENANT scope（tenant_id=0）：`tenant-isolation` 启用时权限/角色查询
/// fail-closed（`ctx-tenant-context-missing`），需进入租户上下文。
/// src 版本被 `cfg(any(test, feature = "testing"))` 门控，集成测试按既有惯例
/// 内置本地副本（tests/integration/axum.rs 同构）。
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

/// 读取 axum 响应体为 UTF-8 字符串。
async fn axum_body(resp: Response) -> String {
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("axum body collect")
        .to_bytes();
    String::from_utf8(bytes.to_vec()).expect("响应体应为 UTF-8")
}

/// 构建 GET 请求（可选 `Authorization: Bearer <token>` header）。
fn get_request(path: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(path);
    if let Some(t) = token {
        builder = builder.header("Authorization", format!("Bearer {t}"));
    }
    builder.body(Body::empty()).unwrap()
}

/// 统一错误断言（三框架一致性基准）：状态码对齐 `response_parts().0`，
/// 响应体 JSON 与 `to_json_body()` 全等。
async fn assert_error_aligned(resp: Response, err: &GarrisonError) {
    let (status, _, _, _) = err.response_parts();
    assert_eq!(
        resp.status().as_u16(),
        status,
        "状态码应与 response_parts() 对齐"
    );
    let body: serde_json::Value =
        serde_json::from_str(&axum_body(resp).await).expect("错误响应体应为 JSON");
    assert_eq!(body, err.to_json_body(), "响应体应与 to_json_body() 对齐");
}

// ============================================================================
// ACC-WAX-001..002：middleware token 来源矩阵（GarrisonRouter + oneshot）
// ============================================================================

/// ACC-WAX-001（正常+异常）：middleware 从 `Authorization: Bearer` header 提取 token——
/// 有效 token 放行 200；无 token 返回 401，且响应体与 `NotLogin` 基准全等
/// （与 `web_smoke` 的 spawn 冒烟场景区分：此处为 oneshot 直连 + body 级断言）。
#[tokio::test]
#[serial]
async fn acc_wax_001_middleware_bearer_header_pass_and_reject() {
    let _h = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");

    let app = GarrisonRouter::new(web_test_config())
        .route_protected("/protected", || async { "ok" }, Annotation::CheckLogin)
        .build();

    // 正常：header 携带有效 token → 200
    let resp = app
        .clone()
        .oneshot(get_request("/protected", Some(&token)))
        .await
        .expect("请求应送达 app");
    assert_eq!(resp.status(), StatusCode::OK, "有效 token 应放行 200");

    // 异常：无 token → 401 + 统一错误 body（与基准对齐）
    let resp = app
        .oneshot(get_request("/protected", None))
        .await
        .expect("请求应送达 app");
    assert_error_aligned(
        resp,
        &GarrisonError::NotLogin("router-not-login".to_string()),
    )
    .await;
}

/// ACC-WAX-002（正常+异常）：middleware token 来源矩阵——
/// （a）token 仅经 `Cookie: garrison_token=<token>` 携带 → 200；
/// （b）cookie 内为伪造 token → 401（与基准对齐）；
/// （c）header 与 cookie 并存时 header 优先：header 有效 + cookie 伪造 → 200
/// （与 src/context/token_extract.rs 提取顺序语义一致）。
#[tokio::test]
#[serial]
async fn acc_wax_002_middleware_cookie_source_and_header_priority() {
    let _h = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");

    let app = GarrisonRouter::new(web_test_config())
        .route_protected("/protected", || async { "ok" }, Annotation::CheckLogin)
        .build();

    // （a）cookie 来源 → 200
    let req = Request::builder()
        .method("GET")
        .uri("/protected")
        .header("Cookie", format!("garrison_token={token}"))
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "cookie 提取 token 后应放行 200"
    );

    // （b）cookie 伪造 → 401
    let req = Request::builder()
        .method("GET")
        .uri("/protected")
        .header("Cookie", "garrison_token=forged-cookie-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_error_aligned(
        resp,
        &GarrisonError::NotLogin("router-not-login".to_string()),
    )
    .await;

    // （c）header 优先于 cookie → 200
    let req = Request::builder()
        .method("GET")
        .uri("/protected")
        .header("Authorization", format!("Bearer {token}"))
        .header("Cookie", "garrison_token=forged-cookie-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "header 应优先于 cookie 提取（RFC 风格提取顺序）"
    );
}

// ============================================================================
// ACC-WAX-003..005：extractor 矩阵（per-handler 鉴权）
// ============================================================================

/// ACC-WAX-003（正常+异常）：`CheckLogin` extractor——有效 token 放行 200 且
/// handler body 原样返回；无 token 拒绝 401（NOT_LOGIN，与基准对齐）。
#[tokio::test]
#[serial]
async fn acc_wax_003_extractor_check_login_pass_and_401() {
    let _h = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");

    let app = Router::new().route("/login", get(|_: CheckLogin| async { "login_ok" }));

    // 正常
    let resp = app
        .clone()
        .oneshot(get_request("/login", Some(&token)))
        .await
        .unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "有效 token 应通过 CheckLogin"
    );
    assert_eq!(axum_body(resp).await, "login_ok", "handler body 应原样返回");

    // 异常：无 token → 401
    let resp = app.oneshot(get_request("/login", None)).await.unwrap();
    assert_error_aligned(
        resp,
        &GarrisonError::NotLogin("annotation-not-login".to_string()),
    )
    .await;
}

/// `user:read` 权限 marker（PermissionName trait，extractor 类型化参数）。
struct UserRead;
impl PermissionName for UserRead {
    const NAME: &'static str = "user:read";
}

/// ACC-WAX-004（正常+异常）：`CheckPermission<UserRead>` extractor——
/// 持有 `user:read` 权限放行 200；未持有权限拒绝 403（NOT_PERMISSION，与基准对齐）。
/// `tenant-isolation` 启用时权限查询 fail-closed，故包 `with_default_tenant`。
#[tokio::test]
#[serial]
async fn acc_wax_004_extractor_check_permission_pass_and_403() {
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

    let app = Router::new().route(
        "/users",
        get(|_: CheckPermission<UserRead>| async { "users_ok" }),
    );

    // 正常：持有权限 → 200
    let resp = with_default_tenant(async {
        app.clone()
            .oneshot(get_request("/users", Some(&token)))
            .await
            .unwrap()
    })
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "持有权限应放行 200");
    assert_eq!(axum_body(resp).await, "users_ok");

    // 异常：无权限主体 → 403
    let resp = with_default_tenant(async {
        app.oneshot(get_request("/users", Some(&token_no_perm)))
            .await
            .unwrap()
    })
    .await;
    assert_error_aligned(
        resp,
        &GarrisonError::NotPermission("annotation-not-permission".to_string()),
    )
    .await;
}

/// `admin` 角色 marker（RoleName trait，extractor 类型化参数）。
struct AdminRole;
impl RoleName for AdminRole {
    const NAME: &'static str = "admin";
}

/// ACC-WAX-005（正常+异常）：`CheckRole<AdminRole>` extractor——
/// 持有 `admin` 角色放行 200；未持有角色拒绝 403（NOT_ROLE，与基准对齐）。
#[tokio::test]
#[serial]
async fn acc_wax_005_extractor_check_role_pass_and_403() {
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

    let app = Router::new().route(
        "/admin",
        get(|_: CheckRole<AdminRole>| async { "admin_ok" }),
    );

    // 正常：持有角色 → 200
    let resp = with_default_tenant(async {
        app.clone()
            .oneshot(get_request("/admin", Some(&token)))
            .await
            .unwrap()
    })
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "持有角色应放行 200");
    assert_eq!(axum_body(resp).await, "admin_ok");

    // 异常：无角色主体 → 403
    let resp = with_default_tenant(async {
        app.oneshot(get_request("/admin", Some(&token_no_role)))
            .await
            .unwrap()
    })
    .await;
    assert_error_aligned(
        resp,
        &GarrisonError::NotRole("annotation-not-role".to_string()),
    )
    .await;
}

// ============================================================================
// ACC-WAX-006..008：注解宏包装 handler（annotation-macros 门控）
// ============================================================================

/// `#[check_login]` 包装的 handler：编译期验证宏展开，运行期返回纯文本。
#[cfg(feature = "annotation-macros")]
#[check_login]
async fn wax_check_login_handler() -> &'static str {
    "wax_login_ok"
}

/// `#[check_permission("user:read")]` 包装的 handler。
#[cfg(feature = "annotation-macros")]
#[check_permission("user:read")]
async fn wax_check_perm_handler() -> &'static str {
    "wax_perm_ok"
}

/// `#[check_role("admin")]` 包装的 handler。
#[cfg(feature = "annotation-macros")]
#[check_role("admin")]
async fn wax_check_role_handler() -> &'static str {
    "wax_role_ok"
}

/// `#[check_permission("user:read", "user:write")]` 多权限 AND 语义 handler。
#[cfg(feature = "annotation-macros")]
#[check_permission("user:read", "user:write")]
async fn wax_perm_and_handler() -> &'static str {
    "wax_perm_and_ok"
}

/// `#[check_role("admin", "superadmin")]` 多角色 AND 语义 handler。
#[cfg(feature = "annotation-macros")]
#[check_role("admin", "superadmin")]
async fn wax_role_and_handler() -> &'static str {
    "wax_role_and_ok"
}

/// `#[check_access_token]` 类型校验 handler（spec annotation-macros P2）。
#[cfg(feature = "annotation-macros")]
#[check_access_token]
async fn wax_access_token_handler() -> &'static str {
    "wax_access_token_ok"
}

/// `#[check_client_token]` 类型校验 handler（spec annotation-macros P2）。
#[cfg(feature = "annotation-macros")]
#[check_client_token]
async fn wax_client_token_handler() -> &'static str {
    "wax_client_token_ok"
}

/// `#[check_temp_token]` 类型校验 handler（spec annotation-macros P2）。
#[cfg(feature = "annotation-macros")]
#[check_temp_token]
async fn wax_temp_token_handler() -> &'static str {
    "wax_temp_token_ok"
}

/// `#[check_mfa]` 二级认证校验 handler（spec annotation-macros R-anno-004）。
#[cfg(feature = "annotation-macros")]
#[check_mfa]
async fn wax_mfa_handler() -> &'static str {
    "wax_mfa_ok"
}

/// `#[check_abac]` ABAC 策略校验 handler（allow：`principal == principal` 恒真）。
#[cfg(all(feature = "annotation-macros", feature = "abac"))]
#[check_abac(
    action = "access",
    resource = "Resource::\"default\"",
    abac = "principal == principal"
)]
async fn wax_abac_allow_handler() -> &'static str {
    "wax_abac_ok"
}

/// `#[check_abac]` ABAC 策略校验 handler（deny：`principal != principal` 恒假）。
#[cfg(all(feature = "annotation-macros", feature = "abac"))]
#[check_abac(
    action = "access",
    resource = "Resource::\"default\"",
    abac = "principal != principal"
)]
async fn wax_abac_deny_handler() -> &'static str {
    "wax_abac_deny"
}

/// strict 模式配置（`throw_on_not_login = true`）：未登录走 `Err(Session)` → 500
///（与 integration/annotation_macros.rs 的 `make_config_strict` 惯例一致）。
fn strict_test_config() -> Arc<garrison::config::GarrisonConfig> {
    let mut config = garrison::config::GarrisonConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = true;
    Arc::new(config)
}

/// ACC-WAX-006（正常+异常）：`#[check_login]` 宏包装 handler 编译并运行——
/// 有效 token 放行 200 + 原 body；伪造 token 拒绝 401（loose 模式下宏把
/// `Ok(false)` 转为 `NotLogin` → 401，与 integration/annotation_macros.rs 语义一致）。
#[cfg(feature = "annotation-macros")]
#[tokio::test]
#[serial]
async fn acc_wax_006_macro_check_login_compile_and_run() {
    let _h = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");

    // 正常
    let resp = with_current_token(token, async { wax_check_login_handler().await }).await;
    assert_eq!(resp.status(), StatusCode::OK, "宏包装 handler 应放行 200");
    assert_eq!(
        axum_body(resp).await,
        "wax_login_ok",
        "handler body 应原样返回"
    );

    // 异常：伪造 token → 401 + NOT_LOGIN
    let resp = with_current_token("forged-token".to_string(), async {
        wax_check_login_handler().await
    })
    .await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "伪造 token 应被宏转为 401，实际: {}",
        resp.status()
    );
    let body: serde_json::Value =
        serde_json::from_str(&axum_body(resp).await).expect("401 响应体应为 JSON");
    assert_eq!(body["error_code"], "NOT_LOGIN", "应返回 NOT_LOGIN 错误码");
}

/// ACC-WAX-007（正常+异常）：`#[check_permission("user:read")]` 宏包装 handler——
/// 持有权限放行 200 + 原 body；无权限主体拒绝 403 + NOT_PERMISSION。
#[cfg(feature = "annotation-macros")]
#[tokio::test]
#[serial]
async fn acc_wax_007_macro_check_permission_compile_and_run() {
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

    // 正常：持有 user:read → 200
    let resp = with_default_tenant(async {
        with_current_token(token, async { wax_check_perm_handler().await }).await
    })
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "持有权限应放行 200");
    assert_eq!(axum_body(resp).await, "wax_perm_ok");

    // 异常：无权限 → 403 + NOT_PERMISSION
    let resp = with_default_tenant(async {
        with_current_token(token_no_perm, async { wax_check_perm_handler().await }).await
    })
    .await;
    assert_eq!(resp.status().as_u16(), 403, "无权限应拒绝 403");
    let body: serde_json::Value =
        serde_json::from_str(&axum_body(resp).await).expect("403 响应体应为 JSON");
    assert_eq!(
        body["error_code"], "NOT_PERMISSION",
        "应返回 NOT_PERMISSION 错误码"
    );
}

/// ACC-WAX-008（正常+异常）：`#[check_role("admin")]` 宏包装 handler——
/// 持有角色放行 200 + 原 body；无角色主体拒绝 403 + NOT_ROLE。
#[cfg(feature = "annotation-macros")]
#[tokio::test]
#[serial]
async fn acc_wax_008_macro_check_role_compile_and_run() {
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

    // 正常：持有 admin → 200
    let resp = with_default_tenant(async {
        with_current_token(token, async { wax_check_role_handler().await }).await
    })
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "持有角色应放行 200");
    assert_eq!(axum_body(resp).await, "wax_role_ok");

    // 异常：无角色 → 403 + NOT_ROLE
    let resp = with_default_tenant(async {
        with_current_token(token_no_role, async { wax_check_role_handler().await }).await
    })
    .await;
    assert_eq!(resp.status().as_u16(), 403, "无角色应拒绝 403");
    let body: serde_json::Value =
        serde_json::from_str(&axum_body(resp).await).expect("403 响应体应为 JSON");
    assert_eq!(body["error_code"], "NOT_ROLE", "应返回 NOT_ROLE 错误码");
}

// ============================================================================
// ACC-WAX-009..012：Web 安全件（WAF / CORS / CSRF / 安全响应头）
// ============================================================================

/// ACC-WAX-009（正常+异常）：WAF 中间件（`firewall-waf`，`waf_middleware`）——
/// 干净路径放行 200；命中 `BlackPathHook` 黑名单的路径拦截 403，错误 JSON 含
/// `error=firewall_blocked` / `hook=black_path` / `reason`。
///
/// API 偏差备注：任务书提及的 `web-waf` feature 已于 v0.9.0 废弃（Cargo.toml
/// 「web-waf 已废弃（与 firewall-waf 功能 100% 重叠）」），统一走 `firewall-waf`；
/// 该 feature 包含于 `full`，门控等价满足。
#[cfg(feature = "firewall-waf")]
#[tokio::test]
async fn acc_wax_009_waf_block_and_allow() {
    use garrison::strategy::firewall::{BlackPathHook, WafHookChain};
    use garrison::web::axum::waf::waf_middleware;

    let mut chain = WafHookChain::new();
    chain.register(Box::new(BlackPathHook::new(vec!["/admin".to_string()])));
    let app = Router::new()
        .route("/api/test", get(|| async { "ok" }))
        .route("/admin/test", get(|| async { "ok" }))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(chain),
            waf_middleware,
        ));

    // 正常：未命中黑名单 → 200
    let resp = app
        .clone()
        .oneshot(get_request("/api/test", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "WAF 应放行干净请求");

    // 异常：命中黑名单前缀 → 403 + 结构化错误
    let resp = app.oneshot(get_request("/admin/test", None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "WAF 应拦截黑名单路径");
    let body: serde_json::Value =
        serde_json::from_str(&axum_body(resp).await).expect("WAF 拦截响应体应为 JSON");
    assert_eq!(body["error"], "firewall_blocked", "应含 error 标记");
    assert_eq!(body["hook"], "black_path", "应指明命中 hook");
    assert!(
        body["reason"].as_str().unwrap_or("").contains("/admin"),
        "reason 应包含命中路径，实际: {}",
        body["reason"]
    );
}

/// ACC-WAX-010（正常+异常）：CORS 中间件（`web-cors`，`garrison_cors_middleware`）
/// ——（a）OPTIONS 预检：匹配 Origin → 204 + `Access-Control-Allow-Origin`；
/// （b）预检不匹配 Origin → 204 且不带 CORS 头（异常拦截语义：跨域不获授权头）；
/// （c）实际请求：匹配 Origin 回显 `Access-Control-Allow-Origin`。
#[cfg(feature = "web-cors")]
#[tokio::test]
async fn acc_wax_010_cors_preflight_and_actual_request() {
    use garrison::web::cors::{garrison_cors_middleware, CorsConfig};

    let config = CorsConfig {
        allowed_origins: vec!["https://example.com".to_string()],
        ..Default::default()
    };
    let app = Router::new().route("/api", get(|| async { "ok" })).layer(
        axum::middleware::from_fn_with_state(Arc::new(config), garrison_cors_middleware),
    );

    // （a）预检：匹配 Origin → 204 + Allow-Origin
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/api")
        .header("origin", "https://example.com")
        .header("access-control-request-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT, "预检应短路 204");
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        "https://example.com",
        "匹配 Origin 时应注入 Allow-Origin"
    );

    // （b）预检：不匹配 Origin → 204 且不带 CORS 授权头
    let req = Request::builder()
        .method("OPTIONS")
        .uri("/api")
        .header("origin", "https://evil.com")
        .header("access-control-request-method", "GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::NO_CONTENT);
    assert!(
        resp.headers().get("access-control-allow-origin").is_none(),
        "不匹配 Origin 时不应注入 CORS 授权头"
    );

    // （c）实际请求：匹配 Origin → 200 + Allow-Origin 回显
    let req = Request::builder()
        .method("GET")
        .uri("/api")
        .header("origin", "https://example.com")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "实际请求应正常放行");
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        "https://example.com",
        "实际请求应回显 Allow-Origin"
    );
}

/// ACC-WAX-011（正常+异常）：CSRF 防护（`web-csrf`，`garrison_csrf_middleware`，
/// Double-Submit Cookie）——（a）token 原语：生成/常量时间校验自洽、伪造拒绝；
/// （b）安全方法 GET 懒生成 `garrison_csrf_token` cookie；
/// （c）受保护 POST 同源 + cookie/header token 匹配 → 放行 200；
/// （d）受保护 POST 缺 token / token 不匹配 → 403 拦截。
#[cfg(feature = "web-csrf")]
#[tokio::test]
async fn acc_wax_011_csrf_double_submit_protection() {
    use garrison::web::csrf::{
        garrison_csrf_middleware, generate_csrf_token, validate_csrf_token, CsrfConfig,
    };

    // （a）token 原语（T011：generate + 常量时间校验）
    let tok = generate_csrf_token().expect("generate_csrf_token 应成功");
    assert!(validate_csrf_token(&tok, &tok), "自身校验应通过");
    assert!(
        !validate_csrf_token(&tok, "forged-token"),
        "伪造 token 应被拒绝"
    );

    let app = Router::new()
        .route("/submit", axum::routing::post(|| async { "submitted_ok" }))
        .route("/read", get(|| async { "read_ok" }))
        .layer(axum::middleware::from_fn_with_state(
            Arc::new(CsrfConfig::default()),
            garrison_csrf_middleware,
        ));

    // （b）安全方法：GET 懒生成 CSRF cookie
    let resp = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/read")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "GET 应放行");
    let set_cookie = resp
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(
        set_cookie.contains("garrison_csrf_token="),
        "GET 应懒生成 CSRF cookie，实际: {set_cookie}"
    );

    // （c）受保护 POST：同源（Host/Origin 一致）+ cookie/header token 匹配 → 200
    let req = Request::builder()
        .method("POST")
        .uri("/submit")
        .header("host", "example.com")
        .header("origin", "http://example.com")
        .header("cookie", format!("garrison_csrf_token={tok}"))
        .header("x-csrf-token", &tok)
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK, "token 匹配应放行 POST");
    assert_eq!(axum_body(resp).await, "submitted_ok");

    // （d1）受保护 POST：完全缺 token → 403
    let req = Request::builder()
        .method("POST")
        .uri("/submit")
        .header("host", "example.com")
        .header("origin", "http://example.com")
        .body(Body::empty())
        .unwrap();
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN, "缺 token 应拦截 403");

    // （d2）受保护 POST：cookie/header token 不匹配 → 403
    let req = Request::builder()
        .method("POST")
        .uri("/submit")
        .header("host", "example.com")
        .header("origin", "http://example.com")
        .header("cookie", format!("garrison_csrf_token={tok}"))
        .header("x-csrf-token", "mismatched-token")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "token 不匹配应拦截 403"
    );
}

/// ACC-WAX-012（正常+异常）：安全响应头中间件（`web-security-headers`，
/// `security_headers_middleware`）——正常响应注入 `X-Content-Type-Options: nosniff`、
/// `X-Frame-Options: DENY`、`Cache-Control: no-store`、`Pragma: no-cache`；
/// 错误响应（404）同样携带安全头（异常路径不放空）。
#[cfg(feature = "web-security-headers")]
#[tokio::test]
async fn acc_wax_012_security_headers_on_success_and_error() {
    use garrison::web::security_headers::security_headers_middleware;

    let app = Router::new()
        .route("/ping", get(|| async { "ok" }))
        .layer(axum::middleware::from_fn(security_headers_middleware));

    // 正常：200 + 四项基础安全头
    let resp = app
        .clone()
        .oneshot(get_request("/ping", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let headers = resp.headers();
    assert_eq!(
        headers.get("x-content-type-options").unwrap(),
        "nosniff",
        "应设置 X-Content-Type-Options: nosniff"
    );
    assert_eq!(
        headers.get("x-frame-options").unwrap(),
        "DENY",
        "应设置 X-Frame-Options: DENY"
    );
    assert_eq!(
        headers.get("cache-control").unwrap(),
        "no-store",
        "应设置 Cache-Control: no-store"
    );
    assert_eq!(
        headers.get("pragma").unwrap(),
        "no-cache",
        "应设置 Pragma: no-cache"
    );

    // 异常路径（404）同样携带安全头
    let resp = app
        .oneshot(get_request("/nonexistent", None))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        resp.headers().get("x-content-type-options").unwrap(),
        "nosniff",
        "错误响应也应携带安全头"
    );
    assert_eq!(resp.headers().get("x-frame-options").unwrap(), "DENY");
}

// ============================================================================
// ACC-WAX-013..014：Ignore 匿名访问 / 无效 token 拒绝（T041 迁移自
// tests/integration/axum.rs + annotation.rs 的既有边界）
// ============================================================================

/// ACC-WAX-013（正常）：`Ignore` 注解与 `Ignore` extractor 均允许匿名访问——
/// （a）`Annotation::Ignore` 经 `GarrisonRouter::route_protected` 放行无 token 请求 200；
/// （b）`Ignore` extractor 挂载于普通 Router 放行匿名请求 200（原
/// `ignore_allows_anonymous_access` / `public_without_token_returns_200`）。
#[tokio::test]
#[serial]
async fn acc_wax_013_ignore_annotation_and_extractor_allow_anonymous() {
    let _h = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");

    // （a）Annotation::Ignore（GarrisonRouter 中间件路径）
    let app = GarrisonRouter::new(web_test_config())
        .route_protected("/public", || async { "public ok" }, Annotation::Ignore)
        .build();
    let resp = app
        .oneshot(get_request("/public", None))
        .await
        .expect("请求应送达 app");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Ignore 注解路由应放行匿名访问"
    );
    assert_eq!(
        axum_body(resp).await,
        "public ok",
        "handler body 应原样返回"
    );

    // （b）Ignore extractor（per-handler 路径）
    let app2 = Router::new().route("/pub", get(|_: Ignore| async { "pub ok" }));
    let resp = app2.oneshot(get_request("/pub", None)).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "Ignore extractor 应放行匿名访问"
    );
    assert_eq!(axum_body(resp).await, "pub ok");
}

/// ACC-WAX-014（异常）：无效 token 被拒绝 401——（a）middleware（GarrisonRouter
/// Bearer）与（b）extractor（`CheckLogin`）两路径均返回 401 + 与 `NotLogin` 基准
/// 全等的错误体；（c）响应体不泄漏内部细节（codebase-hardening：不出现
/// `GarrisonManager`）。原 `check_login_with_invalid_token_returns_401` /
/// `protected_with_invalid_token_returns_401`。
#[tokio::test]
#[serial]
async fn acc_wax_014_invalid_token_rejected_by_middleware_and_extractor() {
    let _h = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");

    // （a）middleware：Bearer 携带无效 token → 401 + 统一错误体
    let app = GarrisonRouter::new(web_test_config())
        .route_protected("/protected", || async { "ok" }, Annotation::CheckLogin)
        .build();
    let resp = app
        .clone()
        .oneshot(get_request("/protected", Some("invalid-token")))
        .await
        .expect("请求应送达 app");
    assert_error_aligned(
        resp,
        &GarrisonError::NotLogin("router-not-login".to_string()),
    )
    .await;

    // （b）extractor：`CheckLogin` 拒绝无效 token → 401 + 统一错误体
    let app2 = Router::new().route("/login", get(|_: CheckLogin| async { "login_ok" }));
    let resp = app2
        .oneshot(get_request("/login", Some("invalid-token")))
        .await
        .unwrap();
    assert_error_aligned(
        resp,
        &GarrisonError::NotLogin("annotation-not-login".to_string()),
    )
    .await;

    // （c）响应体不泄漏内部细节（原 unauthorized_response_body_contains_error_json）
    let resp = app
        .oneshot(get_request("/protected", Some("invalid-token")))
        .await
        .expect("请求应送达 app");
    let body = axum_body(resp).await;
    assert!(
        !body.contains("GarrisonManager"),
        "响应体不应泄漏内部细节: {}",
        body
    );
}

// ============================================================================
// ACC-WAX-015..021：注解宏 loose/strict 模式与类型化变体（T041 迁移自
// tests/integration/annotation_macros.rs；001/006-008 已覆盖的合格路径去重）
// ============================================================================

/// ACC-WAX-015（异常）：`#[check_login]` strict 模式错误转发——`throw_on_not_login
/// = true` 时未登录为 `Err(Session("未登录"))` → 500（框架既有行为，宏正确转发
/// 不吞错不篡改），且 fn body 不执行（响应体不含 handler 输出）。
#[cfg(feature = "annotation-macros")]
#[tokio::test]
#[serial]
async fn acc_wax_015_macro_check_login_strict_forwards_error() {
    let _h = GarrisonTestHarness::builder()
        .config(strict_test_config())
        .init()
        .await
        .expect("harness init 应成功");

    let response = with_current_token("invalid-token".to_string(), async {
        wax_check_login_handler().await
    })
    .await;
    assert_eq!(
        response.status().as_u16(),
        500,
        "strict 模式未登录应为 Session 错误 → 500，实际: {}",
        response.status()
    );
    let body = axum_body(response).await;
    assert!(
        !body.contains("wax_login_ok"),
        "fn body 不应执行：响应体不得包含 handler 输出"
    );
}

/// ACC-WAX-016（正常+异常）：`#[check_permission]` 多参数 AND 语义——
/// 同时持有 `user:read` + `user:write` 放行 200 + 原 body；仅持部分权限拒绝 403
/// + NOT_PERMISSION（原 `check_permission_and_all/partial_returns_*`）。
#[cfg(feature = "annotation-macros")]
#[tokio::test]
#[serial]
async fn acc_wax_016_macro_check_permission_and_semantics() {
    let interface = MockInterface::new();
    interface.allow("1001", &["user:read", "user:write"], &[]);
    let _h = GarrisonTestHarness::builder()
        .interface(interface.clone())
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");
    let token_partial = GarrisonUtil::login_simple("1002")
        .await
        .expect("login_simple 应签发 token");

    // AND 全部持有 → 200 + 原 body
    let resp = with_default_tenant(async {
        with_current_token(token, async { wax_perm_and_handler().await }).await
    })
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "AND 全持有应放行 200");
    assert_eq!(axum_body(resp).await, "wax_perm_and_ok");

    // AND 部分持有（缺 user:write）→ 403 + NOT_PERMISSION
    let resp = with_default_tenant(async {
        with_current_token(token_partial, async { wax_perm_and_handler().await }).await
    })
    .await;
    assert_eq!(resp.status().as_u16(), 403, "AND 缺任一权限应拒绝 403");
    let body: serde_json::Value =
        serde_json::from_str(&axum_body(resp).await).expect("403 响应体应为 JSON");
    assert_eq!(
        body["error_code"], "NOT_PERMISSION",
        "AND 缺权限应返回 NOT_PERMISSION"
    );
}

/// ACC-WAX-017（正常+异常）：`#[check_role]` 多角色 AND 语义——
/// 同时持有 `admin` + `superadmin` 放行 200 + 原 body；仅持部分角色拒绝 403
/// + NOT_ROLE（原 `check_role_and_all/partial_returns_*`）。
#[cfg(feature = "annotation-macros")]
#[tokio::test]
#[serial]
async fn acc_wax_017_macro_check_role_and_semantics() {
    let interface = MockInterface::new();
    interface.allow("1001", &[], &["admin", "superadmin"]);
    let _h = GarrisonTestHarness::builder()
        .interface(interface.clone())
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");
    let token_partial = GarrisonUtil::login_simple("1002")
        .await
        .expect("login_simple 应签发 token");

    // AND 全部持有 → 200 + 原 body
    let resp = with_default_tenant(async {
        with_current_token(token, async { wax_role_and_handler().await }).await
    })
    .await;
    assert_eq!(resp.status(), StatusCode::OK, "AND 全持有应放行 200");
    assert_eq!(axum_body(resp).await, "wax_role_and_ok");

    // AND 部分持有（缺 superadmin）→ 403 + NOT_ROLE
    let resp = with_default_tenant(async {
        with_current_token(token_partial, async { wax_role_and_handler().await }).await
    })
    .await;
    assert_eq!(resp.status().as_u16(), 403, "AND 缺任一角色应拒绝 403");
    let body: serde_json::Value =
        serde_json::from_str(&axum_body(resp).await).expect("403 响应体应为 JSON");
    assert_eq!(body["error_code"], "NOT_ROLE", "AND 缺角色应返回 NOT_ROLE");
}

/// ACC-WAX-018（正常+异常）：`#[check_access_token]` 宏展开为包装器（loose 配置）——
/// 伪造 token 拒绝 401（宏把 `Ok(false)` 转为 NotLogin → 401）；有效 token 放行
/// 200 + 原 body。单次 harness（loose）内覆盖原两条测试
///（`check_access_token_expands_to_wrapper` / `_with_valid_token_returns_200`）。
#[cfg(feature = "annotation-macros")]
#[tokio::test]
#[serial]
async fn acc_wax_018_macro_check_access_token_loose_and_valid() {
    let _h = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");

    // 异常：伪造 token → 401（expands_to_wrapper 语义）
    let resp = with_current_token("invalid-token".to_string(), async {
        wax_access_token_handler().await
    })
    .await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "伪造 token 应拒绝 401，实际: {}",
        resp.status()
    );

    // 正常：有效 token → 200 + 原 body
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");
    let resp = with_current_token(token, async { wax_access_token_handler().await }).await;
    assert_eq!(resp.status(), StatusCode::OK, "有效 token 应放行 200");
    assert_eq!(axum_body(resp).await, "wax_access_token_ok");
}

/// ACC-WAX-019（正常+异常）：`#[check_client_token]` 宏展开为包装器（loose 配置）——
/// 伪造 token 拒绝 401；有效 token 放行 200 + 原 body（原
/// `check_client_token_expands_to_wrapper` / `_with_valid_token_returns_200`）。
#[cfg(feature = "annotation-macros")]
#[tokio::test]
#[serial]
async fn acc_wax_019_macro_check_client_token_loose_and_valid() {
    let _h = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");

    // 异常：伪造 token → 401
    let resp = with_current_token("invalid-token".to_string(), async {
        wax_client_token_handler().await
    })
    .await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "伪造 token 应拒绝 401，实际: {}",
        resp.status()
    );

    // 正常：有效 token → 200 + 原 body
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");
    let resp = with_current_token(token, async { wax_client_token_handler().await }).await;
    assert_eq!(resp.status(), StatusCode::OK, "有效 token 应放行 200");
    assert_eq!(axum_body(resp).await, "wax_client_token_ok");
}

/// ACC-WAX-020（正常+异常）：`#[check_temp_token]` 宏展开为包装器（loose 配置）——
/// 伪造 token 拒绝 401；有效 token 放行 200 + 原 body（原
/// `check_temp_token_expands_to_wrapper` / `_with_valid_token_returns_200`）。
#[cfg(feature = "annotation-macros")]
#[tokio::test]
#[serial]
async fn acc_wax_020_macro_check_temp_token_loose_and_valid() {
    let _h = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");

    // 异常：伪造 token → 401
    let resp = with_current_token("invalid-token".to_string(), async {
        wax_temp_token_handler().await
    })
    .await;
    assert_eq!(
        resp.status().as_u16(),
        401,
        "伪造 token 应拒绝 401，实际: {}",
        resp.status()
    );

    // 正常：有效 token → 200 + 原 body
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");
    let resp = with_current_token(token, async { wax_temp_token_handler().await }).await;
    assert_eq!(resp.status(), StatusCode::OK, "有效 token 应放行 200");
    assert_eq!(axum_body(resp).await, "wax_temp_token_ok");
}

/// ACC-WAX-021（正常）：宏包装 handler 可挂载进 axum `Router`——经
/// `with_current_token` 包裹 `oneshot` 调用，`#[check_login]` /
/// `#[check_permission]` / `#[check_role]` 三路由均放行 200
///（强化：原 `handler_works_with_axum_router` 仅断言 /login）。
#[cfg(feature = "annotation-macros")]
#[tokio::test]
#[serial]
async fn acc_wax_021_macro_handlers_mount_into_axum_router() {
    let interface = MockInterface::new();
    interface.allow("1001", &["user:read"], &["admin"]);
    let _h = GarrisonTestHarness::builder()
        .interface(interface.clone())
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");

    let app = Router::new()
        .route("/login", get(wax_check_login_handler))
        .route("/perm", get(wax_check_perm_handler))
        .route("/role", get(wax_check_role_handler));

    with_default_tenant(async {
        let response = with_current_token(token.clone(), async {
            app.clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/login")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
        })
        .await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "宏 handler 挂载 Router 后 /login 应 200"
        );

        let response = with_current_token(token.clone(), async {
            app.clone()
                .oneshot(
                    Request::builder()
                        .method("GET")
                        .uri("/perm")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap()
        })
        .await;
        assert_eq!(response.status(), StatusCode::OK, "/perm 应 200");

        let response = with_current_token(token, async {
            app.oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/role")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap()
        })
        .await;
        assert_eq!(response.status(), StatusCode::OK, "/role 应 200");
    })
    .await;
}

// ============================================================================
// ACC-WAX-022..023：`#[check_mfa]`（正常 + 异常，R-anno-004）
// ============================================================================

/// ACC-WAX-022（正常）：`#[check_mfa]` 已登录 + 已开启二级认证 → 200 + 原 body。
/// `check_safe` 依赖 `TokenSession.safe_services`，仅 `login_simple` 不足以通过，
/// 需先调用 `GarrisonLogicDefault::open_safe("default", ...)` 开启二级认证标记
///（仅 `security-extra` 启用时需要；无该 feature 时 `is_safe` 默认 `Ok(true)`）。
#[cfg(feature = "annotation-macros")]
#[tokio::test]
#[serial]
async fn acc_wax_022_macro_check_mfa_with_valid_token() {
    let _h = GarrisonTestHarness::builder()
        .config(web_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");

    #[cfg(feature = "security-extra")]
    {
        let logic = garrison::GarrisonManager::logic().expect("logic init");
        garrison::stp::with_current_token(token.clone(), async {
            logic.open_safe("default", 3600).await.expect("open_safe");
        })
        .await;
    }

    let response = with_current_token(token, async { wax_mfa_handler().await }).await;
    assert_eq!(response.status(), StatusCode::OK, "MFA 已开启应放行 200");
    assert_eq!(axum_body(response).await, "wax_mfa_ok");
}

/// ACC-WAX-023（异常）：`#[check_mfa]` 未登录 → `check_safe` 依赖 session 失败，
/// 响应不是 200（框架拒绝 MFA 校验，仅 `security-extra` 下有效——无该 feature
/// 时 `is_safe` 默认 `Ok(true)` 为 no-op 不拦截）。
#[cfg(all(feature = "annotation-macros", feature = "security-extra"))]
#[tokio::test]
#[serial]
async fn acc_wax_023_macro_check_mfa_without_token_forwards_error() {
    let _h = GarrisonTestHarness::builder()
        .config(strict_test_config())
        .init()
        .await
        .expect("harness init 应成功");

    let response = with_current_token("invalid-token".to_string(), async {
        wax_mfa_handler().await
    })
    .await;
    assert_ne!(
        response.status(),
        StatusCode::OK,
        "MFA 校验在未登录时必须失败（非 200）"
    );
}

// ============================================================================
// ACC-WAX-024..025：`#[check_abac]`（无引擎 fail-closed / 引擎 Allow+Deny，
// R-anno-005）
// ============================================================================

/// ACC-WAX-024（异常）：`#[check_abac]` ABAC 引擎未初始化时 fail-closed——
/// 已登录（a）与未登录（b）均返回 500（`check_abac_with_policy` 返回
/// `Err(Config)`，即使未登录也优先返回 ABAC 错误，不执行 fn body）。
#[cfg(all(feature = "annotation-macros", feature = "abac"))]
#[tokio::test]
#[serial]
async fn acc_wax_024_macro_check_abac_without_engine_fail_closed() {
    // reset_abac_for_test 需要 testing 特性（spec 约束：testing 严禁在
    // full/production 之外的构造中启用）；与 ACC-WAX-025 之间恢复无引擎态。
    #[cfg(feature = "testing")]
    {
        garrison::abac::reset_abac_for_test();
    }
    let _h = GarrisonTestHarness::builder()
        .config(strict_test_config())
        .init()
        .await
        .expect("harness init 应成功");
    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");

    // （a）已登录 + 无引擎 → fail-closed 500
    let response = with_current_token(token, async { wax_abac_allow_handler().await }).await;
    assert_eq!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "无 ABAC 引擎时应 fail-closed 500"
    );

    // （b）未登录 + 无引擎 → 同样 fail-closed 500（ABAC 优先于登录态）
    let response = with_current_token("invalid-token".to_string(), async {
        wax_abac_allow_handler().await
    })
    .await;
    assert_eq!(
        response.status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "未登录时同样优先返回 ABAC 错误（fail-closed）"
    );
}

/// ACC-WAX-025（正常+异常）：`#[check_abac]` 引擎已初始化——Allow 策略
///（`principal == principal`）放行 200 + 原 body；Deny 策略（`principal !=
/// principal`）拒绝 403。schema / `EmptyEntityLoader` 装配
///（原 `check_abac_engine_initialized_allow/deny_returns_*`，同场景合并）。
#[cfg(all(feature = "annotation-macros", feature = "abac", feature = "testing"))]
#[tokio::test]
#[serial]
async fn acc_wax_025_macro_check_abac_engine_allow_and_deny() {
    use garrison::abac::{init_abac_engine, reset_abac_for_test, AbacEngine, EmptyEntityLoader};

    reset_abac_for_test();
    let _h = GarrisonTestHarness::builder()
        .config(strict_test_config())
        .init()
        .await
        .expect("harness init 应成功");

    let schema_json = r#"{"":{"entityTypes":{"User":{"shape":{"type":"Record","attributes":{}}},"Resource":{"shape":{"type":"Record","attributes":{}}}},"actions":{"access":{"appliesTo":{"principalTypes":["User"],"resourceTypes":["Resource"]}}}}}"#;
    let engine = AbacEngine::new(schema_json, Arc::new(EmptyEntityLoader))
        .await
        .expect("schema valid");
    init_abac_engine(engine).expect("init_abac_engine");

    let token = GarrisonUtil::login_simple("1001")
        .await
        .expect("login_simple 应签发 token");

    // Allow 策略 → 200 + 原 body
    let response =
        with_current_token(token.clone(), async { wax_abac_allow_handler().await }).await;
    assert_eq!(response.status(), StatusCode::OK, "ABAC Allow 应放行 200");
    assert_eq!(axum_body(response).await, "wax_abac_ok");

    // Deny 策略 → 403
    let response = with_current_token(token, async { wax_abac_deny_handler().await }).await;
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "ABAC Deny 应拒绝 403"
    );

    reset_abac_for_test();
}
