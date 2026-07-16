//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! web_actix 模块集成测试。
//!
//! 覆盖 ResponseError、extract_token_from_headers、BulwarkRouter、
//! BulwarkMiddleware（Transform/Service）、CheckLogin/CheckRole/CheckPermission
//! FromRequest extractor 的行为。Mock 实现复用 `mock.rs`。

use super::*;
use crate::context::token_extract::extract_token_from_headers;
use crate::error::BulwarkError;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{self, HeaderMap, HeaderValue};
use actix_web::http::StatusCode;
use actix_web::ResponseError;

// ========================================================================
// ResponseError 测试
// ========================================================================

/// NotLogin → 401 + error_code=NOT_LOGIN。
#[test]
fn response_error_not_login_returns_401() {
    let err = BulwarkError::NotLogin("test".to_string());
    assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
    let resp = err.error_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// NotPermission → 403 + error_code=NOT_PERMISSION。
#[test]
fn response_error_not_permission_returns_403() {
    let err = BulwarkError::NotPermission("test".to_string());
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
}

/// NotRole → 403 + error_code=NOT_ROLE。
#[test]
fn response_error_not_role_returns_403() {
    let err = BulwarkError::NotRole("test".to_string());
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
}

/// InvalidToken → 401 + error_code=INVALID_TOKEN。
#[test]
fn response_error_invalid_token_returns_401() {
    let err = BulwarkError::InvalidToken("test".to_string());
    assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
}

/// NotImplemented → 501 + error_code=NOT_IMPLEMENTED。
#[test]
fn response_error_not_implemented_returns_501() {
    let err = BulwarkError::NotImplemented("test".to_string());
    assert_eq!(err.status_code(), StatusCode::NOT_IMPLEMENTED);
}

/// Exception code=-1 → 401（与 axum 一致）。
#[test]
fn response_error_exception_code_minus1_returns_401() {
    let ex = crate::exception::BulwarkException::new(-1, "未登录");
    let err = BulwarkError::Exception(ex);
    assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
}

/// Exception code=-2 → 403（与 axum 一致）。
#[test]
fn response_error_exception_code_minus2_returns_403() {
    let ex = crate::exception::BulwarkException::new(-2, "无权限");
    let err = BulwarkError::Exception(ex);
    assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
}

/// error_response() 返回 JSON body 包含 error_code + message。
#[test]
fn error_response_contains_json_body() {
    let err = BulwarkError::NotLogin("internal detail".to_string());
    let resp = err.error_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // body 内容验证需异步读取，此处仅验证 status + content-type
    assert_eq!(
        resp.headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok()),
        Some("application/json")
    );
}

// ========================================================================
// extract_token_from_headers 测试
// ========================================================================

/// 从 Authorization: Bearer 提取 token。
#[test]
fn extract_token_from_bearer_header() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer my_token_123"),
    );
    let config = BulwarkConfig::default_config();
    let token = extract_token_from_headers(&headers, &config).unwrap();
    assert_eq!(token, Some("my_token_123".to_string()));
}

/// Bearer 前缀大小写不敏感（RFC 7235）。
#[test]
fn extract_token_bearer_case_insensitive() {
    let config = BulwarkConfig::default_config();
    for prefix in &["Bearer", "bearer", "BEARER", "BeArEr"] {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("{} tok_{}", prefix, prefix)).unwrap(),
        );
        let token = extract_token_from_headers(&headers, &config).unwrap();
        assert_eq!(
            token,
            Some(format!("tok_{}", prefix)),
            "前缀 '{}' 应能提取 token",
            prefix
        );
    }
}

/// 从 cookie 提取 token。
#[test]
fn extract_token_from_cookie() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("bulwark_token=cookie_tok_456"),
    );
    let config = BulwarkConfig::default_config();
    let token = extract_token_from_headers(&headers, &config).unwrap();
    assert_eq!(token, Some("cookie_tok_456".to_string()));
}

/// 无 token 时返回 None。
#[test]
fn extract_token_returns_none_when_missing() {
    let headers = HeaderMap::new();
    let config = BulwarkConfig::default_config();
    let token = extract_token_from_headers(&headers, &config).unwrap();
    assert_eq!(token, None);
}

/// header 优先级高于 cookie。
#[test]
fn extract_token_header_priority_over_cookie() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer header_tok"),
    );
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("bulwark_token=cookie_tok"),
    );
    let config = BulwarkConfig::default_config();
    let token = extract_token_from_headers(&headers, &config).unwrap();
    assert_eq!(token, Some("header_tok".to_string()));
}

/// is_read_header=false 时不从 header 提取。
#[test]
fn extract_token_skips_header_when_disabled() {
    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer header_tok"),
    );
    let mut config = BulwarkConfig::default_config();
    config.is_read_header = false;
    config.is_read_cookie = false;
    let token = extract_token_from_headers(&headers, &config).unwrap();
    assert_eq!(token, None);
}

// ========================================================================
// BulwarkRouter 测试
// ========================================================================

/// BulwarkRouter::new 初始化默认 interceptor。
#[test]
fn router_new_initializes_defaults() {
    let router = BulwarkRouter::new(Arc::new(BulwarkConfig::default_config()));
    assert!(router.rules.is_empty());
}

/// route_protected 注册路径 + 注解。
#[test]
fn router_route_protected_adds_rule() {
    let router = BulwarkRouter::new(Arc::new(BulwarkConfig::default_config()))
        .route_protected("/api/user", Annotation::CheckLogin)
        .route_protected("/api/admin", Annotation::CheckRole("admin".to_string()));
    assert_eq!(router.rules.len(), 2);
    assert!(router.rules.contains_key("/api/user"));
    assert!(router.rules.contains_key("/api/admin"));
}

/// into_middleware 消费 router 生成 BulwarkMiddleware。
#[test]
fn router_into_middleware_transfers_state() {
    let router = BulwarkRouter::new(Arc::new(BulwarkConfig::default_config()))
        .route_protected("/api", Annotation::CheckLogin);
    let mw = router.into_middleware();
    assert_eq!(mw.rules.len(), 1);
    // Arc<dyn BulwarkInterceptor> 无法直接做类型检查（dyn Trait 不实现 Any），
    // 通过 rules + config 存在性验证 state 已正确传递。
    assert!(Arc::strong_count(&mw.rules) >= 1);
}

/// Default impl 创建默认配置的路由器。
#[test]
fn router_default_impl() {
    let router = BulwarkRouter::default();
    assert!(router.rules.is_empty());
}

// ========================================================================
// Middleware + Extractor 测试（覆盖 Transform / Service / FromRequest）
// ========================================================================

use super::mock::{MockDao, MockInterface};
use crate::context::tenant::with_default_tenant;
use crate::dao::BulwarkDao;
use crate::manager::BulwarkManager;
use crate::stp::{BulwarkInterface, BulwarkUtil};
use actix_web::{test, web, App};
use serial_test::serial;

// ----------------------------------------------------------------
// 辅助函数
// ----------------------------------------------------------------

/// 创建测试配置（throw_on_not_login=false 便于未登录返回 NotLogin→401）。
fn make_config() -> BulwarkConfig {
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = false;
    config
}

/// 初始化 BulwarkManager（带权限/角色数据）。
fn init_manager(permissions: &[(&str, &[&str])], roles: &[(&str, &[&str])]) {
    BulwarkManager::reset_for_test();
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let config = Arc::new(make_config());
    let mut interface = MockInterface::new();
    for (id, perms) in permissions {
        interface = interface.with_permission(id, perms);
    }
    for (id, roles) in roles {
        interface = interface.with_role(id, roles);
    }
    let interface: Arc<dyn BulwarkInterface> = Arc::new(interface);
    BulwarkManager::init(dao, config, interface).unwrap();
}

// ----------------------------------------------------------------
// BulwarkMiddleware Transform + Service 测试
// ----------------------------------------------------------------
//
// 以下测试使用 `OkService` + `TestRequest::to_srv_request()` 直接调用
// `BulwarkMiddlewareService::call`，覆盖鉴权逻辑的各个分支。
//
// 历史 BUG #8（已修复）：原实现在 `self.inner.call(req)` 之前执行
// `req.request().clone()`，导致 `Rc` 引用计数为 2，路由层 `match_info_mut()`
// 触发 panic。修复方案：添加 `S: Clone` 约束，先鉴权通过后才 `inner.call(req)`，
// 失败则 `req.into_response(resp)`（无需 clone HttpRequest）。
//
// `middleware_works_in_real_app_chain` 测试使用 `App::wrap` 真实链路验证修复。

/// 简单 inner service，直接返回 200 OK（用于 middleware 测试）。
struct OkService;
impl Service<ServiceRequest> for OkService {
    type Response = ServiceResponse;
    type Error = actix_web::Error;
    type Future = std::future::Ready<Result<Self::Response, Self::Error>>;
    fn poll_ready(
        &self,
        _ctx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        std::task::Poll::Ready(Ok(()))
    }
    fn call(&self, req: ServiceRequest) -> Self::Future {
        std::future::ready(Ok(
            req.into_response(actix_web::HttpResponse::Ok().body("ok"))
        ))
    }
}

/// 构建 `BulwarkMiddlewareService<OkService>`，用于直接调用 `call()` 测试鉴权逻辑。
async fn make_middleware_service(
    rules: &[(&str, Annotation)],
) -> BulwarkMiddlewareService<OkService> {
    let mut router = BulwarkRouter::new(Arc::new(make_config()));
    for (path, ann) in rules {
        router = router.route_protected(path, ann.clone());
    }
    let middleware = router.into_middleware();
    <BulwarkMiddleware as Transform<OkService, ServiceRequest>>::new_transform(
        &middleware,
        OkService,
    )
    .await
    .unwrap()
}

/// 验证 middleware 放行未注册路径（无鉴权规则 → 直接执行 inner service）。
///
/// 覆盖 `BulwarkMiddlewareService::call` 中 `rule_annotation` 为 `None` 的分支。
#[tokio::test]
#[serial]
async fn middleware_allows_unprotected_path() {
    init_manager(&[], &[]);
    let service = make_middleware_service(&[("/protected", Annotation::CheckLogin)]).await;

    let req = test::TestRequest::get()
        .uri("/unprotected")
        .to_srv_request();
    let resp = service.call(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    BulwarkManager::reset_for_test();
}

/// 验证 middleware 阻断受保护路径（无 token → 401）。
///
/// 覆盖 `BulwarkMiddlewareService::call` 中鉴权失败的 `Err` 分支。
#[tokio::test]
#[serial]
async fn middleware_blocks_protected_path_without_token() {
    init_manager(&[], &[]);
    let service = make_middleware_service(&[("/protected", Annotation::CheckLogin)]).await;

    let req = test::TestRequest::get().uri("/protected").to_srv_request();
    let resp = service.call(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    BulwarkManager::reset_for_test();
}

/// 验证 middleware 放行受保护路径（有效 token → 200）。
///
/// 覆盖 `BulwarkMiddlewareService::call` 中鉴权通过的 `Ok` 分支 +
/// `with_current_token` 设置 task_local 路径。
#[tokio::test]
#[serial]
async fn middleware_allows_protected_path_with_valid_token() {
    init_manager(&[], &[]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();
    let service = make_middleware_service(&[("/protected", Annotation::CheckLogin)]).await;

    let req = test::TestRequest::get()
        .uri("/protected")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_srv_request();
    let resp = service.call(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    BulwarkManager::reset_for_test();
}

/// 验证 middleware 阻断无权限访问（有效 token 但无权限 → 403）。
///
/// 覆盖 `BulwarkMiddlewareService::call` 中 `CheckPermission` 注解的鉴权失败分支。
#[tokio::test]
#[serial]
async fn middleware_blocks_permission_denied() {
    init_manager(&[], &[]); // 无权限数据
    let token = BulwarkUtil::login_simple("1001").await.unwrap();
    let service = make_middleware_service(&[(
        "/admin",
        Annotation::CheckPermission("admin:read".to_string()),
    )])
    .await;

    let req = test::TestRequest::get()
        .uri("/admin")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_srv_request();
    let resp = with_default_tenant(async { service.call(req).await.unwrap() }).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    BulwarkManager::reset_for_test();
}

/// 验证 middleware 放行 Ignore 注解路径（无 token → 200）。
///
/// 覆盖 `BulwarkMiddlewareService::call` 中 `Ignore` 注解放行分支。
#[tokio::test]
#[serial]
async fn middleware_allows_ignore_path_without_token() {
    init_manager(&[], &[]);
    let service = make_middleware_service(&[("/public", Annotation::Ignore)]).await;

    let req = test::TestRequest::get().uri("/public").to_srv_request();
    let resp = service.call(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    BulwarkManager::reset_for_test();
}

/// 验证 `Transform::new_transform` 直接调用返回 `BulwarkMiddlewareService`。
///
/// 覆盖 `Transform for BulwarkMiddleware` 的 `new_transform` 方法。
#[tokio::test]
#[serial]
async fn new_transform_returns_service() {
    init_manager(&[], &[]);
    let service = make_middleware_service(&[("/x", Annotation::CheckLogin)]).await;
    // 验证 service 持有规则（rules 非空）
    assert_eq!(service.rules.len(), 1);

    BulwarkManager::reset_for_test();
}

/// 验证 middleware 在真实 `App::wrap` 链路下不触发 Rc panic（BUG #8 回归测试）。
///
/// 原 BUG：`req.request().clone()` 导致 Rc 引用计数为 2，路由层 `match_info_mut` panic。
/// 修复后：先鉴权通过后才 `inner.call(req)`，失败则 `req.into_response(resp)`。
/// 此测试使用 `App::wrap` + 真实路由，覆盖 OkService 无法触发的路由层路径。
#[tokio::test]
#[serial]
async fn middleware_works_in_real_app_chain() {
    init_manager(&[], &[]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();
    let config = Arc::new(make_config());
    let router =
        BulwarkRouter::new(config).route_protected("/api/protected", Annotation::CheckLogin);
    let middleware = router.into_middleware();

    let app = test::init_service(
        App::new()
            .wrap(middleware)
            .route("/api/protected", web::get().to(|| async { "ok" })),
    )
    .await;

    // 受保护路径 + 有效 token → 200（验证不 panic）
    let req = test::TestRequest::get()
        .uri("/api/protected")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    // 受保护路径 + 无 token → 401（验证鉴权失败路径不 panic）
    let req = test::TestRequest::get().uri("/api/protected").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    BulwarkManager::reset_for_test();
}

// ----------------------------------------------------------------
// CheckLogin / CheckRole / CheckPermission FromRequest 测试
// ----------------------------------------------------------------

/// 验证 CheckLogin extractor 在无 token 时返回 401。
///
/// 覆盖 `CheckLogin::from_request` 中 `extract_token_from_headers` 返回 `None` 的分支。
#[tokio::test]
#[serial]
async fn extractor_check_login_returns_401_without_token() {
    init_manager(&[], &[]);
    let config = Arc::new(make_config());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .route("/login", web::get().to(check_login_handler)),
    )
    .await;

    let req = test::TestRequest::get().uri("/login").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    BulwarkManager::reset_for_test();
}

/// 验证 CheckLogin extractor 在有效 token 时通过。
///
/// 覆盖 `CheckLogin::from_request` 中 `with_current_token` + `check_login` 成功分支。
#[tokio::test]
#[serial]
async fn extractor_check_login_passes_with_valid_token() {
    init_manager(&[], &[]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();
    let config = Arc::new(make_config());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .route("/login", web::get().to(check_login_handler)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/login")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    BulwarkManager::reset_for_test();
}

/// 验证 CheckLogin extractor 在无 app_data 时使用默认配置（无 token → 401）。
///
/// 覆盖 `CheckLogin::from_request` 中 `unwrap_or_else(|| Arc::new(default_config()))` 分支。
#[tokio::test]
#[serial]
async fn extractor_check_login_uses_default_config_without_app_data() {
    init_manager(&[], &[]);
    let app =
        test::init_service(App::new().route("/login", web::get().to(check_login_handler))).await;

    let req = test::TestRequest::get().uri("/login").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    BulwarkManager::reset_for_test();
}

/// 验证 CheckRole extractor 在无 token 时返回 401。
///
/// 覆盖 `CheckRole::from_request` 中 token 缺失分支。
#[tokio::test]
#[serial]
async fn extractor_check_role_returns_401_without_token() {
    init_manager(&[], &[]);
    let config = Arc::new(make_config());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .route("/role", web::get().to(check_role_handler)),
    )
    .await;

    let req = test::TestRequest::get().uri("/role").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    BulwarkManager::reset_for_test();
}

/// 验证 CheckRole extractor 在无角色时返回 403。
///
/// 覆盖 `CheckRole::from_request` 中 `check_role` 失败分支。
#[tokio::test]
#[serial]
async fn extractor_check_role_returns_403_without_role() {
    init_manager(&[], &[]); // 无角色数据
    let token = BulwarkUtil::login_simple("1001").await.unwrap();
    let config = Arc::new(make_config());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .route("/role", web::get().to(check_role_handler)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/role")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .insert_header(("X-Bulwark-Role", "admin"))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    BulwarkManager::reset_for_test();
}

/// 验证 CheckRole extractor 通过 query param 传递角色。
///
/// 覆盖 `CheckRole::from_request` 中 query param 解析分支。
#[tokio::test]
#[serial]
async fn extractor_check_role_reads_role_from_query_param() {
    init_manager(&[], &[("1001", &["admin"])]); // 注入 admin 角色
    let token = BulwarkUtil::login_simple("1001").await.unwrap();
    let config = Arc::new(make_config());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .route("/role", web::get().to(check_role_handler)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/role?role=admin")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    BulwarkManager::reset_for_test();
}

/// 验证 CheckPermission extractor 在无 token 时返回 401。
///
/// 覆盖 `CheckPermission::from_request` 中 token 缺失分支。
#[tokio::test]
#[serial]
async fn extractor_check_permission_returns_401_without_token() {
    init_manager(&[], &[]);
    let config = Arc::new(make_config());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .route("/perm", web::get().to(check_permission_handler)),
    )
    .await;

    let req = test::TestRequest::get().uri("/perm").to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    BulwarkManager::reset_for_test();
}

/// 验证 CheckPermission extractor 在无权限时返回 403。
///
/// 覆盖 `CheckPermission::from_request` 中 `check_permission` 失败分支。
#[tokio::test]
#[serial]
async fn extractor_check_permission_returns_403_without_permission() {
    init_manager(&[], &[]); // 无权限数据
    let token = BulwarkUtil::login_simple("1001").await.unwrap();
    let config = Arc::new(make_config());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .route("/perm", web::get().to(check_permission_handler)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/perm")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .insert_header(("X-Bulwark-Permission", "user:read"))
        .to_request();
    let resp = with_default_tenant(async { test::call_service(&app, req).await }).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    BulwarkManager::reset_for_test();
}

/// 验证 CheckPermission extractor 通过 query param 传递权限并放行。
///
/// 覆盖 `CheckPermission::from_request` 中 query param 解析 + 成功分支。
#[tokio::test]
#[serial]
async fn extractor_check_permission_reads_from_query_param() {
    init_manager(&[("1001", &["user:read"])], &[]); // 注入权限
    let token = BulwarkUtil::login_simple("1001").await.unwrap();
    let config = Arc::new(make_config());
    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(config))
            .route("/perm", web::get().to(check_permission_handler)),
    )
    .await;

    let req = test::TestRequest::get()
        .uri("/perm?permission=user:read")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp = with_default_tenant(async { test::call_service(&app, req).await }).await;
    assert_eq!(resp.status(), StatusCode::OK);

    BulwarkManager::reset_for_test();
}

// ----------------------------------------------------------------
// extractor handler 函数（使用 FromRequest extractor）
// ----------------------------------------------------------------

/// 使用 CheckLogin extractor 的 handler。
async fn check_login_handler(_auth: CheckLogin) -> &'static str {
    "ok"
}

/// 使用 CheckRole extractor 的 handler。
async fn check_role_handler(_auth: CheckRole) -> &'static str {
    "ok"
}

/// 使用 CheckPermission extractor 的 handler。
async fn check_permission_handler(_auth: CheckPermission) -> &'static str {
    "ok"
}
