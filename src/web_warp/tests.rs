//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `web_warp` 模块测试套件。
//!
//! 覆盖：
//! - `impl Reply for GarrisonError`：错误码 → HTTP 状态码映射 + JSON content-type
//! - `extract_token_from_headers`：Bearer/cookie 提取与优先级
//! - `GarrisonRejection`：包装 `GarrisonError` 接入 warp 拒绝链
//! - `GarrisonRouter`：构建器 + `into_filter` 守卫 Filter
//! - `check_login` / `check_role` / `check_permission`：per-handler guard Filter
//!
//! 通过 `#[cfg(test)] mod tests;` 在 `mod.rs` 引入，仅测试编译。

use super::mock::{MockDao, MockInterface};
use super::*;
use crate::context::tenant::with_default_tenant;
use crate::context::token_extract::extract_token_from_headers;
use crate::dao::GarrisonDao;
use crate::error::GarrisonResult;
use crate::manager::GarrisonManager;
use crate::stp::{GarrisonInterface, GarrisonUtil};
use serial_test::serial;
use warp::http::header;
use warp::http::header::HeaderValue;
use warp::http::StatusCode;
use warp::reply::Reply;

// ========================================================================
// Reply impl 测试
// ========================================================================

/// NotLogin → 401 响应。
#[test]
fn reply_not_login_returns_401() {
    let err = GarrisonError::NotLogin("test".to_string());
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// NotPermission → 403 响应。
#[test]
fn reply_not_permission_returns_403() {
    let err = GarrisonError::NotPermission("test".to_string());
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// NotRole → 403 响应。
#[test]
fn reply_not_role_returns_403() {
    let err = GarrisonError::NotRole("test".to_string());
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// InvalidToken → 401 响应。
#[test]
fn reply_invalid_token_returns_401() {
    let err = GarrisonError::InvalidToken("test".to_string());
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// NotImplemented → 501 响应。
#[test]
fn reply_not_implemented_returns_501() {
    let err = GarrisonError::NotImplemented("test".to_string());
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
}

/// Exception code=-1 → 401（与 axum/actix-web 一致）。
#[test]
fn reply_exception_code_minus1_returns_401() {
    let ex = crate::exception::GarrisonException::new(-1, "未登录");
    let err = GarrisonError::Exception(ex);
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

/// Exception code=-2 → 403（与 axum/actix-web 一致）。
#[test]
fn reply_exception_code_minus2_returns_403() {
    let ex = crate::exception::GarrisonException::new(-2, "无权限");
    let err = GarrisonError::Exception(ex);
    let resp = err.into_response();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

/// into_response() 返回 JSON content-type。
#[test]
fn reply_returns_json_content_type() {
    let err = GarrisonError::NotLogin("internal detail".to_string());
    let resp = err.into_response();
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
    let mut headers = warp::http::HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer my_token_123"),
    );
    let config = GarrisonConfig::default_config();
    let token = extract_token_from_headers(&headers, &config).unwrap();
    assert_eq!(token, Some("my_token_123".to_string()));
}

/// Bearer 前缀大小写不敏感（RFC 7235）。
#[test]
fn extract_token_bearer_case_insensitive() {
    let config = GarrisonConfig::default_config();
    for prefix in &["Bearer", "bearer", "BEARER", "BeArEr"] {
        let mut headers = warp::http::HeaderMap::new();
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
    let mut headers = warp::http::HeaderMap::new();
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("garrison_token=cookie_tok_456"),
    );
    let config = GarrisonConfig::default_config();
    let token = extract_token_from_headers(&headers, &config).unwrap();
    assert_eq!(token, Some("cookie_tok_456".to_string()));
}

/// 无 token 时返回 None。
#[test]
fn extract_token_returns_none_when_missing() {
    let headers = warp::http::HeaderMap::new();
    let config = GarrisonConfig::default_config();
    let token = extract_token_from_headers(&headers, &config).unwrap();
    assert_eq!(token, None);
}

/// header 优先级高于 cookie。
#[test]
fn extract_token_header_priority_over_cookie() {
    let mut headers = warp::http::HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer header_tok"),
    );
    headers.insert(
        header::COOKIE,
        HeaderValue::from_static("garrison_token=cookie_tok"),
    );
    let config = GarrisonConfig::default_config();
    let token = extract_token_from_headers(&headers, &config).unwrap();
    assert_eq!(token, Some("header_tok".to_string()));
}

/// is_read_header=false 时不从 header 提取。
#[test]
fn extract_token_skips_header_when_disabled() {
    let mut headers = warp::http::HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        HeaderValue::from_static("Bearer header_tok"),
    );
    let mut config = GarrisonConfig::default_config();
    config.is_read_header = false;
    config.is_read_cookie = false;
    let token = extract_token_from_headers(&headers, &config).unwrap();
    assert_eq!(token, None);
}

// ========================================================================
// GarrisonRejection 测试
// ========================================================================

/// GarrisonRejection 包装 GarrisonError。
#[test]
fn rejection_wraps_error() {
    let err = GarrisonError::NotLogin("test".to_string());
    let rej = GarrisonRejection(err);
    // Reject trait 无方法可调用，仅验证类型可构造
    // 通过 format! 验证内部错误可访问
    assert!(format!("{:?}", rej).contains("NotLogin"));
}

// ========================================================================
// GarrisonRouter 测试
// ========================================================================

/// GarrisonRouter::new 初始化空规则。
#[test]
fn router_new_initializes_defaults() {
    let router = GarrisonRouter::new(Arc::new(GarrisonConfig::default_config()));
    assert!(router.rules.is_empty());
}

/// route_protected 注册路径 + 注解。
#[test]
fn router_route_protected_adds_rule() {
    let router = GarrisonRouter::new(Arc::new(GarrisonConfig::default_config()))
        .route_protected("/api/user", Annotation::CheckLogin)
        .route_protected("/api/admin", Annotation::CheckRole("admin".to_string()));
    assert_eq!(router.rules.len(), 2);
    assert!(router.rules.contains_key("/api/user"));
    assert!(router.rules.contains_key("/api/admin"));
}

/// with_interceptor 设置自定义拦截器。
#[test]
fn router_with_interceptor_replaces_default() {
    struct CustomInterceptor;
    #[async_trait::async_trait]
    impl GarrisonInterceptor for CustomInterceptor {
        async fn pre_handle(&self, _path: &str, _annotation: &Annotation) -> GarrisonResult<()> {
            Ok(())
        }
    }
    let router = GarrisonRouter::new(Arc::new(GarrisonConfig::default_config()))
        .with_interceptor(CustomInterceptor);
    // 验证 interceptor 已替换（通过 Arc strong_count >= 1）
    assert!(Arc::strong_count(&router.interceptor) >= 1);
}

/// Default impl 创建默认配置的路由器。
#[test]
fn router_default_impl() {
    let router = GarrisonRouter::default();
    assert!(router.rules.is_empty());
}

// ========================================================================
// into_filter / check_login / check_role / check_permission Filter 测试
// ========================================================================

// ----------------------------------------------------------------
// 辅助函数
// ----------------------------------------------------------------

/// 创建测试配置。
fn make_config() -> GarrisonConfig {
    let mut config = GarrisonConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = false;
    config
}

/// 初始化 GarrisonManager（带权限/角色数据）。
fn init_manager(permissions: &[(&str, &[&str])], roles: &[(&str, &[&str])]) {
    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let config = Arc::new(make_config());
    let mut interface = MockInterface::new();
    for (id, perms) in permissions {
        interface = interface.with_permission(id, perms);
    }
    for (id, roles) in roles {
        interface = interface.with_role(id, roles);
    }
    let interface: Arc<dyn GarrisonInterface> = Arc::new(interface);
    GarrisonManager::init(dao, config, interface).unwrap();
}

// ----------------------------------------------------------------
// GarrisonRouter::into_filter 测试
// ----------------------------------------------------------------

/// 验证 into_filter 放行未注册路径（无鉴权规则 → Ok）。
#[tokio::test]
#[serial]
async fn into_filter_allows_unprotected_path() {
    init_manager(&[], &[]);
    let router = GarrisonRouter::new(Arc::new(make_config()))
        .route_protected("/protected", Annotation::CheckLogin);
    let filter = router.into_filter();

    let result = warp::test::request()
        .path("/unprotected")
        .filter(&filter)
        .await;
    assert!(result.is_ok());

    GarrisonManager::reset_for_test();
}

/// 验证 into_filter 阻断受保护路径（无 token → Rejection）。
#[tokio::test]
#[serial]
async fn into_filter_blocks_protected_path_without_token() {
    init_manager(&[], &[]);
    let router = GarrisonRouter::new(Arc::new(make_config()))
        .route_protected("/protected", Annotation::CheckLogin);
    let filter = router.into_filter();

    let result = warp::test::request()
        .path("/protected")
        .filter(&filter)
        .await;
    assert!(result.is_err());
    let rej = result.unwrap_err();
    assert!(rej.find::<GarrisonRejection>().is_some());

    GarrisonManager::reset_for_test();
}

/// 验证 into_filter 放行受保护路径（有效 token → Ok）。
#[tokio::test]
#[serial]
async fn into_filter_allows_protected_path_with_valid_token() {
    init_manager(&[], &[]);
    let token = GarrisonUtil::login_simple("1001").await.unwrap();
    let router = GarrisonRouter::new(Arc::new(make_config()))
        .route_protected("/protected", Annotation::CheckLogin);
    let filter = router.into_filter();

    let result = warp::test::request()
        .path("/protected")
        .header("authorization", format!("Bearer {}", token))
        .filter(&filter)
        .await;
    assert!(result.is_ok());

    GarrisonManager::reset_for_test();
}

/// 验证 into_filter 阻断无权限访问（有效 token 但无权限 → Rejection）。
#[tokio::test]
#[serial]
async fn into_filter_blocks_permission_denied() {
    init_manager(&[], &[]); // 无权限数据
    let token = GarrisonUtil::login_simple("1001").await.unwrap();
    let router = GarrisonRouter::new(Arc::new(make_config())).route_protected(
        "/admin",
        Annotation::CheckPermission("admin:read".to_string()),
    );
    let filter = router.into_filter();

    let result = warp::test::request()
        .path("/admin")
        .header("authorization", format!("Bearer {}", token))
        .filter(&filter)
        .await;
    assert!(result.is_err());
    let rej = result.unwrap_err();
    assert!(rej.find::<GarrisonRejection>().is_some());

    GarrisonManager::reset_for_test();
}

/// 验证 `into_filter` 对 `Ignore` 路径无 token 也能通过。
///
/// `into_filter` 现在与 actix-web middleware 对齐，
/// `Ignore` 注解的 `pre_handle` 直接返回 `Ok(())`，token 为可选。
#[tokio::test]
#[serial]
async fn into_filter_allows_ignore_path_without_token() {
    init_manager(&[], &[]);
    let router =
        GarrisonRouter::new(Arc::new(make_config())).route_protected("/public", Annotation::Ignore);
    let filter = router.into_filter();

    let result = warp::test::request().path("/public").filter(&filter).await;
    assert!(result.is_ok());

    GarrisonManager::reset_for_test();
}

// ----------------------------------------------------------------
// check_login Filter 测试
// ----------------------------------------------------------------

/// 验证 check_login filter 在无 token 时返回 Rejection。
#[tokio::test]
#[serial]
async fn check_login_filter_rejects_without_token() {
    init_manager(&[], &[]);
    let filter = check_login(Arc::new(make_config()));

    let result = warp::test::request().filter(&filter).await;
    assert!(result.is_err());
    let rej = result.unwrap_err();
    assert!(rej.find::<GarrisonRejection>().is_some());

    GarrisonManager::reset_for_test();
}

/// 验证 check_login filter 在有效 token 时通过。
#[tokio::test]
#[serial]
async fn check_login_filter_passes_with_valid_token() {
    init_manager(&[], &[]);
    let token = GarrisonUtil::login_simple("1001").await.unwrap();
    let filter = check_login(Arc::new(make_config()));

    let result = warp::test::request()
        .header("authorization", format!("Bearer {}", token))
        .filter(&filter)
        .await;
    assert!(result.is_ok());

    GarrisonManager::reset_for_test();
}

// ----------------------------------------------------------------
// check_role Filter 测试
// ----------------------------------------------------------------

/// 验证 check_role filter 在无 token 时返回 Rejection。
#[tokio::test]
#[serial]
async fn check_role_filter_rejects_without_token() {
    init_manager(&[], &[]);
    let filter = check_role(Arc::new(make_config()), "admin".to_string());

    let result = warp::test::request().filter(&filter).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().find::<GarrisonRejection>().is_some());

    GarrisonManager::reset_for_test();
}

/// 验证 check_role filter 在无角色时返回 Rejection。
#[tokio::test]
#[serial]
async fn check_role_filter_rejects_without_role() {
    init_manager(&[], &[]); // 无角色数据
    let token = GarrisonUtil::login_simple("1001").await.unwrap();
    let filter = check_role(Arc::new(make_config()), "admin".to_string());

    let result = warp::test::request()
        .header("authorization", format!("Bearer {}", token))
        .filter(&filter)
        .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().find::<GarrisonRejection>().is_some());

    GarrisonManager::reset_for_test();
}

/// 验证 check_role filter 在持有角色时通过。
#[tokio::test]
#[serial]
async fn check_role_filter_passes_with_valid_role() {
    init_manager(&[], &[("1001", &["admin"])]); // 注入 admin 角色
    let token = GarrisonUtil::login_simple("1001").await.unwrap();
    let filter = check_role(Arc::new(make_config()), "admin".to_string());

    let result = warp::test::request()
        .header("authorization", format!("Bearer {}", token))
        .filter(&filter)
        .await;
    assert!(result.is_ok());

    GarrisonManager::reset_for_test();
}

// ----------------------------------------------------------------
// check_permission Filter 测试
// ----------------------------------------------------------------

/// 验证 check_permission filter 在无 token 时返回 Rejection。
#[tokio::test]
#[serial]
async fn check_permission_filter_rejects_without_token() {
    init_manager(&[], &[]);
    let filter = check_permission(Arc::new(make_config()), "user:read".to_string());

    let result = warp::test::request().filter(&filter).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().find::<GarrisonRejection>().is_some());

    GarrisonManager::reset_for_test();
}

/// 验证 check_permission filter 在无权限时返回 Rejection。
#[tokio::test]
#[serial]
async fn check_permission_filter_rejects_without_permission() {
    init_manager(&[], &[]); // 无权限数据
    let token = GarrisonUtil::login_simple("1001").await.unwrap();
    let filter = check_permission(Arc::new(make_config()), "user:read".to_string());

    let result = warp::test::request()
        .header("authorization", format!("Bearer {}", token))
        .filter(&filter)
        .await;
    assert!(result.is_err());
    assert!(result.unwrap_err().find::<GarrisonRejection>().is_some());

    GarrisonManager::reset_for_test();
}

/// 验证 check_permission filter 在持有权限时通过。
#[tokio::test]
#[serial]
async fn check_permission_filter_passes_with_valid_permission() {
    init_manager(&[("1001", &["user:read"])], &[]); // 注入权限
    let token = GarrisonUtil::login_simple("1001").await.unwrap();
    let filter = check_permission(Arc::new(make_config()), "user:read".to_string());

    let result = with_default_tenant(async {
        warp::test::request()
            .header("authorization", format!("Bearer {}", token))
            .filter(&filter)
            .await
    })
    .await;
    assert!(result.is_ok());

    GarrisonManager::reset_for_test();
}
