//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! router 模块测试（从 mod.rs 迁移，Rule 25 合规）。

use super::mock::{MockDao, MockInterface};
use super::*;
use crate::annotation::Annotation;
use crate::config::BulwarkConfig;
use crate::context::tenant::with_default_tenant;
use crate::dao::BulwarkDao;
use crate::error::BulwarkError;
use crate::manager::BulwarkManager;
use crate::stp::context::set_renewed_token;
use crate::stp::{BulwarkInterface, BulwarkUtil};
use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use serial_test::serial;
use std::sync::Arc;
use tower::ServiceExt;

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

/// 初始化 BulwarkManager 并返回 MockDao 引用（用于 API Key 测试等需共享 DAO 的场景）。
#[cfg_attr(not(feature = "protocol-apikey"), allow(dead_code))]
fn init_manager_with_dao() -> Arc<MockDao> {
    BulwarkManager::reset_for_test();
    let dao = Arc::new(MockDao::new());
    let config = Arc::new(make_config());
    let interface: Arc<dyn BulwarkInterface> = Arc::new(MockInterface::new());
    BulwarkManager::init(dao.clone() as Arc<dyn BulwarkDao>, config, interface).unwrap();
    dao
}

/// 构建 GET 请求（带可选 Authorization header）。
fn make_request(path: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(path);
    if let Some(t) = token {
        builder = builder.header("Authorization", format!("Bearer {}", t));
    }
    builder.body(Body::empty()).unwrap()
}

/// 构建 BulwarkRouter（含 CheckLogin 路由 + CheckRole + CheckPermission）。
fn make_router() -> BulwarkRouter {
    BulwarkRouter::new(Arc::new(make_config()))
        .route_protected("/protected", || async { "ok" }, Annotation::CheckLogin)
        .route_protected(
            "/admin",
            || async { "admin ok" },
            Annotation::CheckRole("admin".to_string()),
        )
        .route_protected(
            "/users",
            || async { "users ok" },
            Annotation::CheckPermission("user:read".to_string()),
        )
        .route_protected("/public", || async { "public ok" }, Annotation::Ignore)
}

// ----------------------------------------------------------------
// route_protected + build 基础测试
// ----------------------------------------------------------------

/// route_protected 注册规则后，build() 返回的 Router 可处理请求。
#[tokio::test]
#[serial]
async fn route_protected_build_handles_request() {
    init_manager(&[], &[]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let app = make_router().build();
    let response = app
        .oneshot(make_request("/protected", Some(&token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    BulwarkManager::reset_for_test();
}

// ----------------------------------------------------------------
// 未登录 / 已登录测试
// ----------------------------------------------------------------

/// 未登录访问受保护路由 → 401。
#[tokio::test]
#[serial]
async fn protected_without_token_returns_401() {
    init_manager(&[], &[]);

    let app = make_router().build();
    let response = app.oneshot(make_request("/protected", None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    BulwarkManager::reset_for_test();
}

/// 已登录访问受保护路由 → 200。
#[tokio::test]
#[serial]
async fn protected_with_valid_token_returns_200() {
    init_manager(&[], &[]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let app = make_router().build();
    let response = app
        .oneshot(make_request("/protected", Some(&token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    BulwarkManager::reset_for_test();
}

/// 无效 token 访问受保护路由 → 401。
#[tokio::test]
#[serial]
async fn protected_with_invalid_token_returns_401() {
    init_manager(&[], &[]);

    let app = make_router().build();
    let response = app
        .oneshot(make_request("/protected", Some("invalid-token")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    BulwarkManager::reset_for_test();
}

// ----------------------------------------------------------------
// 权限/角色测试
// ----------------------------------------------------------------

/// 无权限访问 → 403。
#[tokio::test]
#[serial]
async fn permission_denied_returns_403() {
    init_manager(&[], &[]); // 无权限数据
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let app = make_router().build();
    let response = with_default_tenant(async {
        app.oneshot(make_request("/users", Some(&token)))
            .await
            .unwrap()
    })
    .await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    BulwarkManager::reset_for_test();
}

/// 持有权限访问 → 200。
#[tokio::test]
#[serial]
async fn permission_granted_returns_200() {
    init_manager(&[("1001", &["user:read"])], &[]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let app = make_router().build();
    let response = with_default_tenant(async {
        app.oneshot(make_request("/users", Some(&token)))
            .await
            .unwrap()
    })
    .await;
    assert_eq!(response.status(), StatusCode::OK);

    BulwarkManager::reset_for_test();
}

/// 未持有角色访问 → 403。
#[tokio::test]
#[serial]
async fn role_denied_returns_403() {
    init_manager(&[], &[]); // 无角色数据
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let app = make_router().build();
    let response = app
        .oneshot(make_request("/admin", Some(&token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    BulwarkManager::reset_for_test();
}

/// 持有角色访问 → 200。
#[tokio::test]
#[serial]
async fn role_granted_returns_200() {
    init_manager(&[], &[("1001", &["admin"])]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let app = make_router().build();
    let response = app
        .oneshot(make_request("/admin", Some(&token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    BulwarkManager::reset_for_test();
}

// ----------------------------------------------------------------
// Ignore 注解测试
// ----------------------------------------------------------------

/// Ignore 注解允许匿名访问 → 200。
#[tokio::test]
#[serial]
async fn ignore_allows_anonymous_access() {
    init_manager(&[], &[]);

    let app = make_router().build();
    let response = app.oneshot(make_request("/public", None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    BulwarkManager::reset_for_test();
}

// ----------------------------------------------------------------
// middleware 自动从 header/cookie 提取 token
// ----------------------------------------------------------------

/// middleware 自动从 Authorization: Bearer header 提取 token。
#[tokio::test]
#[serial]
async fn middleware_extracts_token_from_bearer_header() {
    init_manager(&[], &[]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let app = make_router().build();
    let response = app
        .oneshot(make_request("/protected", Some(&token)))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Bearer header 提取 token 后应通过鉴权"
    );

    BulwarkManager::reset_for_test();
}

/// middleware 自动从自定义 token_name header 提取 token。
#[tokio::test]
#[serial]
async fn middleware_extracts_token_from_custom_header() {
    init_manager(&[], &[]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/protected")
        .header("bulwark_token", &token)
        .body(Body::empty())
        .unwrap();

    let app = make_router().build();
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "自定义 token_name header 提取 token 后应通过鉴权"
    );

    BulwarkManager::reset_for_test();
}

/// middleware 自动从 cookie 提取 token。
#[tokio::test]
#[serial]
async fn middleware_extracts_token_from_cookie() {
    init_manager(&[], &[]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let req = Request::builder()
        .method("GET")
        .uri("/protected")
        .header("Cookie", format!("bulwark_token={}", token))
        .body(Body::empty())
        .unwrap();

    let app = make_router().build();
    let response = app.oneshot(req).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "cookie 提取 token 后应通过鉴权"
    );

    BulwarkManager::reset_for_test();
}

// ----------------------------------------------------------------
// DefaultBulwarkInterceptor.pre_handle 测试
// ----------------------------------------------------------------

/// DefaultBulwarkInterceptor.pre_handle(CheckLogin) 已登录返回 Ok。
#[tokio::test]
#[serial]
async fn default_interceptor_check_login_logged_in_ok() {
    init_manager(&[], &[]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let interceptor = DefaultBulwarkInterceptor;
    let result = crate::stp::with_current_token(
        token,
        interceptor.pre_handle("/x", &Annotation::CheckLogin),
    )
    .await;
    assert!(result.is_ok(), "已登录 pre_handle(CheckLogin) 应返回 Ok");

    BulwarkManager::reset_for_test();
}

/// DefaultBulwarkInterceptor.pre_handle(CheckLogin) 未登录返回 NotLogin。
#[tokio::test]
#[serial]
async fn default_interceptor_check_login_not_logged_in_err() {
    init_manager(&[], &[]);
    let interceptor = DefaultBulwarkInterceptor;
    let result = interceptor.pre_handle("/x", &Annotation::CheckLogin).await;
    assert!(
        matches!(result, Err(BulwarkError::NotLogin(_))),
        "未登录 pre_handle(CheckLogin) 应返回 Err(NotLogin)"
    );

    BulwarkManager::reset_for_test();
}

/// DefaultBulwarkInterceptor.pre_handle(CheckRole) 持有角色返回 Ok。
#[tokio::test]
#[serial]
async fn default_interceptor_check_role_held_ok() {
    init_manager(&[], &[("1001", &["admin"])]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let interceptor = DefaultBulwarkInterceptor;
    let result = crate::stp::with_current_token(
        token,
        interceptor.pre_handle("/x", &Annotation::CheckRole("admin".to_string())),
    )
    .await;
    assert!(result.is_ok(), "持有角色 pre_handle(CheckRole) 应返回 Ok");

    BulwarkManager::reset_for_test();
}

/// DefaultBulwarkInterceptor.pre_handle(CheckPermission) 未持有权限返回 NotPermission。
#[tokio::test]
#[serial]
async fn default_interceptor_check_permission_not_held_err() {
    init_manager(&[], &[]); // 无权限
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let interceptor = DefaultBulwarkInterceptor;
    let result = crate::stp::with_current_token(
        token,
        with_default_tenant(async {
            interceptor
                .pre_handle("/x", &Annotation::CheckPermission("user:read".to_string()))
                .await
        }),
    )
    .await;
    assert!(
        matches!(result, Err(BulwarkError::NotPermission(_))),
        "未持有权限 pre_handle(CheckPermission) 应返回 Err(NotPermission)"
    );

    BulwarkManager::reset_for_test();
}

/// DefaultBulwarkInterceptor.pre_handle(Ignore) 直接返回 Ok。
#[tokio::test]
#[serial]
async fn default_interceptor_ignore_returns_ok() {
    init_manager(&[], &[]);
    let interceptor = DefaultBulwarkInterceptor;
    let result = interceptor.pre_handle("/x", &Annotation::Ignore).await;
    assert!(result.is_ok(), "pre_handle(Ignore) 应返回 Ok");

    BulwarkManager::reset_for_test();
}

// ----------------------------------------------------------------
// DefaultBulwarkInterceptor 其他注解变体测试（catch-all 分支）
// ----------------------------------------------------------------

/// DefaultBulwarkInterceptor.pre_handle 对逻辑组合注解（CheckOr / CheckAnd / CheckNot）
/// 直接放行返回 Ok（实际组合逻辑由注解处理器在编译期或路由配置层处理）。
///
/// 覆盖 `match annotation { ... _ => Ok(()) }` 的 catch-all 分支。
#[tokio::test]
#[serial]
async fn default_interceptor_logical_combinator_annotations_returns_ok() {
    init_manager(&[], &[]);
    let interceptor = DefaultBulwarkInterceptor;
    let combinators = [
        Annotation::CheckOr,
        Annotation::CheckAnd,
        Annotation::CheckNot,
    ];
    for ann in &combinators {
        let result = interceptor.pre_handle("/x", ann).await;
        assert!(
            result.is_ok(),
            "pre_handle({:?}) 逻辑组合注解应通过 catch-all 分支返回 Ok",
            ann
        );
    }

    BulwarkManager::reset_for_test();
}

// ----------------------------------------------------------------
// CheckSafe / CheckDisable / CheckBasicAuth / CheckDigestAuth / CheckSign 测试
// ----------------------------------------------------------------

/// DefaultBulwarkInterceptor.pre_handle(CheckSafe) 默认行为随 `safe-auth` feature 变化。
///
/// - 未启用 `safe-auth`：`is_safe` trait default 返回 `Ok(true)`，pre_handle 返回 `Ok`。
/// - 启用 `safe-auth`：未登录时 `is_safe` 返回 `Ok(false)`，pre_handle 返回 `Err(NotSafe)`。
#[tokio::test]
#[serial]
async fn default_interceptor_check_safe_returns_ok_by_default() {
    init_manager(&[], &[]);
    let interceptor = DefaultBulwarkInterceptor;
    let result = interceptor.pre_handle("/x", &Annotation::CheckSafe).await;

    #[cfg(feature = "safe-auth")]
    {
        assert!(
            matches!(result, Err(BulwarkError::NotSafe { .. })),
            "启用 safe-auth 时未登录，pre_handle(CheckSafe) 应返回 Err(NotSafe)，实际: {:?}",
            result
        );
    }
    #[cfg(not(feature = "safe-auth"))]
    {
        assert!(
            result.is_ok(),
            "未启用 safe-auth 时 pre_handle(CheckSafe) 应返回 Ok，实际: {:?}",
            result
        );
    }

    BulwarkManager::reset_for_test();
}

/// DefaultBulwarkInterceptor.pre_handle(CheckDisable) 默认实现返回 Ok（未禁用）。
#[tokio::test]
#[serial]
async fn default_interceptor_check_disable_returns_ok_by_default() {
    init_manager(&[], &[]);
    let interceptor = DefaultBulwarkInterceptor;
    let result = interceptor
        .pre_handle("/x", &Annotation::CheckDisable)
        .await;
    assert!(result.is_ok(), "默认 check_disable（未禁用账号）应返回 Ok");
    BulwarkManager::reset_for_test();
}

/// DefaultBulwarkInterceptor.pre_handle(CheckBasicAuth) 返回 NotImplemented（需 HTTP 请求上下文）。
#[tokio::test]
#[serial]
async fn default_interceptor_check_basic_auth_returns_not_implemented() {
    init_manager(&[], &[]);
    let interceptor = DefaultBulwarkInterceptor;
    let result = interceptor
        .pre_handle("/x", &Annotation::CheckBasicAuth)
        .await;
    assert!(
        matches!(result, Err(BulwarkError::NotImplemented(_))),
        "CheckBasicAuth 应返回 NotImplemented（pre_handle 缺少 HTTP 请求上下文）"
    );
    BulwarkManager::reset_for_test();
}

/// DefaultBulwarkInterceptor.pre_handle(CheckDigestAuth) 返回 NotImplemented（需 HTTP 请求上下文）。
#[tokio::test]
#[serial]
async fn default_interceptor_check_digest_auth_returns_not_implemented() {
    init_manager(&[], &[]);
    let interceptor = DefaultBulwarkInterceptor;
    let result = interceptor
        .pre_handle("/x", &Annotation::CheckDigestAuth)
        .await;
    assert!(
        matches!(result, Err(BulwarkError::NotImplemented(_))),
        "CheckDigestAuth 应返回 NotImplemented（pre_handle 缺少 HTTP 请求上下文）"
    );
    BulwarkManager::reset_for_test();
}

/// DefaultBulwarkInterceptor.pre_handle(CheckSign) 返回 NotImplemented（需 HTTP 请求上下文）。
#[tokio::test]
#[serial]
async fn default_interceptor_check_sign_returns_not_implemented() {
    init_manager(&[], &[]);
    let interceptor = DefaultBulwarkInterceptor;
    let result = interceptor.pre_handle("/x", &Annotation::CheckSign).await;
    assert!(
        matches!(result, Err(BulwarkError::NotImplemented(_))),
        "CheckSign 应返回 NotImplemented（pre_handle 缺少 HTTP 请求上下文）"
    );
    BulwarkManager::reset_for_test();
}

/// NotImplemented 错误消息包含使用建议（指示用户使用 secure 模块或 extractor）。
#[tokio::test]
#[serial]
async fn default_interceptor_check_basic_auth_error_message_contains_guidance() {
    init_manager(&[], &[]);
    let interceptor = DefaultBulwarkInterceptor;
    let result = interceptor
        .pre_handle("/x", &Annotation::CheckBasicAuth)
        .await;
    if let Err(BulwarkError::NotImplemented(msg)) = result {
        assert!(
            msg.contains("router-check-basic-auth-need-http-context"),
            "错误消息应包含使用建议，实际: {}",
            msg
        );
    }
    BulwarkManager::reset_for_test();
}

/// DefaultBulwarkInterceptor.pre_handle(CheckAccessToken) 返回 NotImplemented
///（无 OAuth2Handler 注册）。
#[tokio::test]
#[serial]
async fn default_interceptor_check_access_token_returns_not_implemented() {
    init_manager(&[], &[]);
    let interceptor = DefaultBulwarkInterceptor;
    let result = interceptor
        .pre_handle("/x", &Annotation::CheckAccessToken)
        .await;
    assert!(
        matches!(result, Err(BulwarkError::NotImplemented(_))),
        "CheckAccessToken 无 OAuth2Handler 时应返回 NotImplemented，实际: {:?}",
        result
    );
    BulwarkManager::reset_for_test();
}

/// DefaultBulwarkInterceptor.pre_handle(CheckClientToken) 返回 NotImplemented
///（无 OAuth2Handler 注册）。
#[tokio::test]
#[serial]
async fn default_interceptor_check_client_token_returns_not_implemented() {
    init_manager(&[], &[]);
    let interceptor = DefaultBulwarkInterceptor;
    let result = interceptor
        .pre_handle("/x", &Annotation::CheckClientToken)
        .await;
    assert!(
        matches!(result, Err(BulwarkError::NotImplemented(_))),
        "CheckClientToken 无 OAuth2Handler 时应返回 NotImplemented，实际: {:?}",
        result
    );
    BulwarkManager::reset_for_test();
}

/// CheckAccessToken NotImplemented 错误消息包含使用建议。
#[tokio::test]
#[serial]
async fn default_interceptor_check_access_token_error_contains_guidance() {
    init_manager(&[], &[]);
    let interceptor = DefaultBulwarkInterceptor;
    let result = interceptor
        .pre_handle("/x", &Annotation::CheckAccessToken)
        .await;
    if let Err(BulwarkError::NotImplemented(msg)) = result {
        assert!(
            msg.contains("router-check-access-token-need-oauth2"),
            "错误消息应包含 OAuth2 使用建议，实际: {}",
            msg
        );
    }
    BulwarkManager::reset_for_test();
}

// ----------------------------------------------------------------
// BulwarkRouter::with_interceptor / Default 测试
// ----------------------------------------------------------------

/// 自定义拦截器：记录调用次数，用于验证 with_interceptor 注入。
struct CountingInterceptor {
    count: std::sync::atomic::AtomicU32,
}

impl CountingInterceptor {
    fn new() -> Self {
        Self {
            count: std::sync::atomic::AtomicU32::new(0),
        }
    }

    fn get(&self) -> u32 {
        self.count.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait]
impl BulwarkInterceptor for CountingInterceptor {
    async fn pre_handle(&self, _path: &str, _annotation: &Annotation) -> BulwarkResult<()> {
        self.count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        Ok(())
    }
}

/// 验证 `BulwarkRouter::with_interceptor` 注入自定义拦截器后，
/// middleware 会调用自定义拦截器的 pre_handle。
///
/// 覆盖 `with_interceptor` 方法体（设置 self.interceptor）。
#[tokio::test]
#[serial]
async fn with_interceptor_uses_custom_interceptor() {
    init_manager(&[], &[]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let interceptor = CountingInterceptor::new();
    let count_ptr = interceptor.get();
    assert_eq!(count_ptr, 0, "初始调用次数应为 0");

    let app = BulwarkRouter::new(Arc::new(make_config()))
        .with_interceptor(interceptor)
        .route_protected("/protected", || async { "ok" }, Annotation::CheckLogin)
        .build();

    let response = app
        .oneshot(make_request("/protected", Some(&token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    BulwarkManager::reset_for_test();
}

/// 验证 `BulwarkRouter::default()` 使用 `BulwarkConfig::default_config()`
/// 创建路由器，拦截器为 `DefaultBulwarkInterceptor`。
///
/// 覆盖 `impl Default for BulwarkRouter` 的 `default()` 方法。
#[tokio::test]
#[serial]
async fn default_router_handles_request() {
    init_manager(&[], &[]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let app = BulwarkRouter::default()
        .route_protected("/protected", || async { "ok" }, Annotation::CheckLogin)
        .build();
    let response = app
        .oneshot(make_request("/protected", Some(&token)))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Default 创建的 router 应能正常处理请求"
    );

    BulwarkManager::reset_for_test();
}

// ----------------------------------------------------------------
// tenant_resolution_middleware 测试
// ----------------------------------------------------------------

/// R-tenant-isolation-005: tenant_resolution_middleware 从 `X-Tenant-Id` header
/// 解析租户上下文，在 `TENANT` task_local scope 内执行下游 handler。
///
/// 验证：
/// 1. 请求带 `X-Tenant-Id: 42` header
/// 2. handler 内 `TENANT.try_get()` 返回 `Ok(ctx)` 且 `ctx.tenant_id == 42`
/// 3. 响应 body 含 `tenant:42`
#[cfg(feature = "tenant-isolation")]
#[tokio::test]
async fn tenant_resolution_middleware_sets_tenant_context() {
    use crate::context::tenant::{HeaderTenantResolver, TenantResolver, TENANT};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    async fn handler() -> String {
        match TENANT.try_get() {
            Ok(ctx) => format!("tenant:{}", ctx.tenant_id),
            Err(_) => "no-tenant".to_string(),
        }
    }

    let resolver: Arc<dyn TenantResolver> = Arc::new(HeaderTenantResolver);
    let app =
        Router::new()
            .route("/test", get(handler))
            .layer(axum::middleware::from_fn_with_state(
                resolver,
                super::tenant_resolution_middleware,
            ));

    let req = Request::builder()
        .method("GET")
        .uri("/test")
        .header("X-Tenant-Id", "42")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert_eq!(
        body_str, "tenant:42",
        "middleware 应设置 TENANT 上下文，handler 应读到 tenant_id=42"
    );
}

/// R-tenant-isolation-005: 缺失 `X-Tenant-Id` header 时 middleware 返回 400 Bad Request。
///
/// 验证：请求不带 `X-Tenant-Id` header，middleware 调用 `resolver.resolve()` 失败，
/// 返回 `StatusCode::BAD_REQUEST`，不执行 handler。
#[cfg(feature = "tenant-isolation")]
#[tokio::test]
async fn tenant_resolution_middleware_missing_header_returns_400() {
    use crate::context::tenant::{HeaderTenantResolver, TenantResolver};
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    async fn handler() -> &'static str {
        "should-not-reach"
    }

    let resolver: Arc<dyn TenantResolver> = Arc::new(HeaderTenantResolver);
    let app =
        Router::new()
            .route("/test", get(handler))
            .layer(axum::middleware::from_fn_with_state(
                resolver,
                super::tenant_resolution_middleware,
            ));

    let req = Request::builder()
        .method("GET")
        .uri("/test")
        .body(Body::empty())
        .unwrap();

    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(
        resp.status(),
        StatusCode::BAD_REQUEST,
        "缺失 X-Tenant-Id header 应返回 400 Bad Request"
    );
}

// ----------------------------------------------------------------
// CheckApiKey 注解分发测试
// ----------------------------------------------------------------

#[cfg(feature = "protocol-apikey")]
/// CheckApiKey 注解：有效 API Key → 200。
#[tokio::test]
#[serial]
async fn check_api_key_with_valid_key_returns_200() {
    use crate::protocol::apikey::ApiKeyHandler;

    let dao = init_manager_with_dao();
    let handler = ApiKeyHandler::new(dao.clone() as Arc<dyn BulwarkDao>);
    let key = handler
        .generate_with_namespace("user1", "ns1", vec![], 3600)
        .await
        .unwrap();

    let app = BulwarkRouter::new(Arc::new(make_config()))
        .route_protected(
            "/api",
            || async { "api ok" },
            Annotation::CheckApiKey {
                namespace: Some("ns1".to_string()),
            },
        )
        .build();

    let response = app.oneshot(make_request("/api", Some(&key))).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "有效 API Key + 正确 namespace 应返回 200"
    );

    BulwarkManager::reset_for_test();
}

#[cfg(feature = "protocol-apikey")]
/// CheckApiKey 注解：无 API Key → 401。
#[tokio::test]
#[serial]
async fn check_api_key_without_key_returns_401() {
    init_manager_with_dao();

    let app = BulwarkRouter::new(Arc::new(make_config()))
        .route_protected(
            "/api",
            || async { "api ok" },
            Annotation::CheckApiKey {
                namespace: Some("ns1".to_string()),
            },
        )
        .build();

    let response = app.oneshot(make_request("/api", None)).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "无 API Key 应返回 401"
    );

    BulwarkManager::reset_for_test();
}

#[cfg(feature = "protocol-apikey")]
/// CheckApiKey 注解：namespace 不匹配 → 401。
#[tokio::test]
#[serial]
async fn check_api_key_namespace_mismatch_returns_401() {
    use crate::protocol::apikey::ApiKeyHandler;

    let dao = init_manager_with_dao();
    let handler = ApiKeyHandler::new(dao.clone() as Arc<dyn BulwarkDao>);
    // 为 ns1 生成 key
    let key = handler
        .generate_with_namespace("user1", "ns1", vec![], 3600)
        .await
        .unwrap();

    // 用 ns1 的 key 访问要求 ns2 的路由 → 应失败
    let app = BulwarkRouter::new(Arc::new(make_config()))
        .route_protected(
            "/api",
            || async { "api ok" },
            Annotation::CheckApiKey {
                namespace: Some("ns2".to_string()),
            },
        )
        .build();

    let response = app.oneshot(make_request("/api", Some(&key))).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::UNAUTHORIZED,
        "ns1 key 访问 ns2 路由应返回 401（namespace 隔离）"
    );

    BulwarkManager::reset_for_test();
}

#[cfg(feature = "protocol-apikey")]
/// CheckApiKey 注解：namespace 为 None 时使用默认命名空间 "default"。
#[tokio::test]
#[serial]
async fn check_api_key_none_namespace_uses_default() {
    use crate::protocol::apikey::ApiKeyHandler;

    let dao = init_manager_with_dao();
    let handler = ApiKeyHandler::new(dao.clone() as Arc<dyn BulwarkDao>);
    // generate（不带 namespace）使用默认命名空间 "default"
    let key = handler.generate("user1", vec![], 3600).await.unwrap();

    let app = BulwarkRouter::new(Arc::new(make_config()))
        .route_protected(
            "/api",
            || async { "api ok" },
            Annotation::CheckApiKey { namespace: None },
        )
        .build();

    let response = app.oneshot(make_request("/api", Some(&key))).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "namespace=None 应使用默认命名空间 default，有效 key 应返回 200"
    );

    BulwarkManager::reset_for_test();
}

/// Mode 注解在 pre_handle 中为 no-op（不执行任何检查，直接放行）。
#[tokio::test]
#[serial]
async fn mode_annotation_is_noop_in_pre_handle() {
    use crate::annotation::AnnotationMode;

    init_manager(&[], &[]);

    let app = BulwarkRouter::new(Arc::new(make_config()))
        .route_protected(
            "/mode",
            || async { "mode ok" },
            Annotation::Mode(AnnotationMode::And),
        )
        .build();

    // Mode 是配置注解，pre_handle 中 no-op，不需要登录即可访问
    let response = app.oneshot(make_request("/mode", None)).await.unwrap();
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "Mode 注解 pre_handle 为 no-op，应直接放行"
    );

    BulwarkManager::reset_for_test();
}

// ----------------------------------------------------------------
// group 方法测试
// ----------------------------------------------------------------

/// R-router-group-001/002/004: group 为子路由附加前缀，
/// RouteRule 同步包含完整前缀路径，middleware 据此执行鉴权。
#[tokio::test]
#[serial]
async fn group_applies_prefix_to_sub_routes() {
    init_manager(&[], &[]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let app = BulwarkRouter::new(Arc::new(make_config()))
        .group("/api/v1", Annotation::CheckLogin, |r| {
            r.route_protected("/users", || async { "users ok" }, Annotation::CheckLogin)
        })
        .build();

    // 已登录 → 200（RouteRule.path="/api/v1/users" 匹配，pre_handle(CheckLogin) 通过）
    let response = app
        .clone()
        .oneshot(make_request("/api/v1/users", Some(&token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // 未登录 → 401（RouteRule.path="/api/v1/users" 匹配，pre_handle(CheckLogin) 失败）
    let response = app
        .oneshot(make_request("/api/v1/users", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    BulwarkManager::reset_for_test();
}

/// R-router-group-003: group 注解为 Ignore 时覆盖路由自身注解（跳过鉴权）。
#[tokio::test]
#[serial]
async fn group_with_ignore_annotation_overrides_route_annotation() {
    init_manager(&[], &[]);

    let app = BulwarkRouter::new(Arc::new(make_config()))
        .group("/public", Annotation::Ignore, |r| {
            r.route_protected("/data", || async { "data ok" }, Annotation::CheckLogin)
        })
        .build();

    // 未登录 → 200（Ignore 覆盖 CheckLogin，跳过鉴权）
    let response = app
        .oneshot(make_request("/public/data", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    BulwarkManager::reset_for_test();
}

/// R-router-group-003: group 注解非 Ignore 时保留路由自身注解。
/// group 注解 CheckLogin + 路由注解 CheckRole("admin") → 路由保留 CheckRole("admin")。
/// 验证：已登录但无 admin 角色的用户访问 → 403（若被覆盖为 CheckLogin 则应 200）。
#[tokio::test]
#[serial]
async fn group_non_ignore_annotation_preserves_route_annotation() {
    init_manager(&[], &[]); // 无角色数据
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let app = BulwarkRouter::new(Arc::new(make_config()))
        .group("/api", Annotation::CheckLogin, |r| {
            r.route_protected(
                "/admin",
                || async { "admin ok" },
                Annotation::CheckRole("admin".to_string()),
            )
        })
        .build();

    // 已登录但无 admin 角色 → 403（CheckRole 保留，未被 CheckLogin 覆盖）
    let response = app
        .oneshot(make_request("/api/admin", Some(&token)))
        .await
        .unwrap();
    assert_eq!(
        response.status(),
        StatusCode::FORBIDDEN,
        "group 非 Ignore 注解应保留路由自身注解（CheckRole），已登录但无角色应 403"
    );

    BulwarkManager::reset_for_test();
}

/// R-router-group-002: 嵌套 group 正确合并前缀
/// /api + /v1 + /users = /api/v1/users
///
/// 注：group 注解非 Ignore 时保留路由自身注解。
/// 此处两层 group 均使用 CheckLogin（非 Ignore），路由注解 CheckLogin 被保留。
#[tokio::test]
#[serial]
async fn group_nested_merges_prefixes() {
    init_manager(&[], &[]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let app = BulwarkRouter::new(Arc::new(make_config()))
        .group("/api", Annotation::CheckLogin, |r| {
            r.group("/v1", Annotation::CheckLogin, |r| {
                r.route_protected("/users", || async { "users ok" }, Annotation::CheckLogin)
            })
        })
        .build();

    // 已登录 → 200
    let response = app
        .clone()
        .oneshot(make_request("/api/v1/users", Some(&token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // 未登录 → 401（路由注解 CheckLogin 保留）
    let response = app
        .oneshot(make_request("/api/v1/users", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    BulwarkManager::reset_for_test();
}

/// R-router-group-001: 空前缀 panic。
#[test]
#[should_panic(expected = "prefix must not be empty")]
fn group_empty_prefix_panics() {
    let _ = BulwarkRouter::new(Arc::new(make_config())).group("", Annotation::Ignore, |r| r);
}

/// R-router-group-002: 尾部 / 自动 trim（/api/v1/ 等价于 /api/v1）。
#[tokio::test]
#[serial]
async fn group_trailing_slash_trimmed() {
    init_manager(&[], &[]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    // prefix = "/api/v1/" → trimmed = "/api/v1" → 完整路径 = "/api/v1/users"
    let app = BulwarkRouter::new(Arc::new(make_config()))
        .group("/api/v1/", Annotation::CheckLogin, |r| {
            r.route_protected("/users", || async { "users ok" }, Annotation::CheckLogin)
        })
        .build();

    // 请求 /api/v1/users → 200（trimmed 后前缀正确拼接）
    let response = app
        .oneshot(make_request("/api/v1/users", Some(&token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    BulwarkManager::reset_for_test();
}

/// R-router-group-002: 多个 group 可链式调用，各自注册独立前缀。
#[tokio::test]
#[serial]
async fn group_chained_calls_register_separate_prefixes() {
    init_manager(&[], &[]);

    let app = BulwarkRouter::new(Arc::new(make_config()))
        .group("/api/v1", Annotation::Ignore, |r| {
            r.route_protected("/users", || async { "v1 users" }, Annotation::Ignore)
        })
        .group("/api/v2", Annotation::Ignore, |r| {
            r.route_protected("/users", || async { "v2 users" }, Annotation::Ignore)
        })
        .build();

    // /api/v1/users → 200
    let response = app
        .clone()
        .oneshot(make_request("/api/v1/users", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    // /api/v2/users → 200
    let response = app
        .oneshot(make_request("/api/v2/users", None))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    BulwarkManager::reset_for_test();
}

// ----------------------------------------------------------------
// T017: 续签 Token 写入响应测试
// ----------------------------------------------------------------

/// 模拟续签的拦截器：pre_handle 时设置 renewed token。
struct RenewingInterceptor {
    new_token: String,
}

#[async_trait]
impl BulwarkInterceptor for RenewingInterceptor {
    async fn pre_handle(&self, _path: &str, _annotation: &Annotation) -> BulwarkResult<()> {
        set_renewed_token(self.new_token.clone());
        Ok(())
    }
}

/// T017-1: 续签 Token → 写入 header（is_write_header=true）。
#[tokio::test]
#[serial]
async fn renewed_token_written_to_header() {
    init_manager(&[], &[]);
    let mut config = make_config();
    config.is_write_header = true;
    config.is_write_cookie = false;

    let app = BulwarkRouter::new(Arc::new(config))
        .with_interceptor(RenewingInterceptor {
            new_token: "renewed-header-token".to_string(),
        })
        .route_protected("/test", || async { "ok" }, Annotation::Ignore)
        .build();

    let response = app.oneshot(make_request("/test", None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let header = response
        .headers()
        .get("bulwark_token")
        .expect("is_write_header=true 时响应应包含续签 header");
    assert_eq!(
        header.to_str().unwrap(),
        "renewed-header-token",
        "header 值应为续签 token"
    );

    BulwarkManager::reset_for_test();
}

/// T017-2: 续签 Token → 写入 cookie（is_write_cookie=true）。
#[tokio::test]
#[serial]
async fn renewed_token_written_to_cookie() {
    init_manager(&[], &[]);
    let mut config = make_config();
    config.is_write_header = false;
    config.is_write_cookie = true;

    let app = BulwarkRouter::new(Arc::new(config))
        .with_interceptor(RenewingInterceptor {
            new_token: "renewed-cookie-token".to_string(),
        })
        .route_protected("/test", || async { "ok" }, Annotation::Ignore)
        .build();

    let response = app.oneshot(make_request("/test", None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let cookie = response
        .headers()
        .get("set-cookie")
        .expect("is_write_cookie=true 时响应应包含 Set-Cookie");
    let cookie_str = cookie.to_str().unwrap();
    assert!(
        cookie_str.contains("bulwark_token=renewed-cookie-token"),
        "Set-Cookie 应包含续签 token，实际: {}",
        cookie_str
    );

    BulwarkManager::reset_for_test();
}

/// T017-3: 续签 Token → 两者均 false 时不写入。
#[tokio::test]
#[serial]
async fn renewed_token_not_written_when_both_disabled() {
    init_manager(&[], &[]);
    let mut config = make_config();
    config.is_write_header = false;
    config.is_write_cookie = false;

    let app = BulwarkRouter::new(Arc::new(config))
        .with_interceptor(RenewingInterceptor {
            new_token: "should-not-appear".to_string(),
        })
        .route_protected("/test", || async { "ok" }, Annotation::Ignore)
        .build();

    let response = app.oneshot(make_request("/test", None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get("bulwark_token").is_none(),
        "is_write_header=false 时不应有续签 header"
    );
    assert!(
        response.headers().get("set-cookie").is_none(),
        "is_write_cookie=false 时不应有 Set-Cookie"
    );

    BulwarkManager::reset_for_test();
}

/// T017-4: 续签 Token → 同时写入 header 和 cookie（两者均 true）。
#[tokio::test]
#[serial]
async fn renewed_token_written_to_both_header_and_cookie() {
    init_manager(&[], &[]);
    let mut config = make_config();
    config.is_write_header = true;
    config.is_write_cookie = true;

    let app = BulwarkRouter::new(Arc::new(config))
        .with_interceptor(RenewingInterceptor {
            new_token: "dual-token".to_string(),
        })
        .route_protected("/test", || async { "ok" }, Annotation::Ignore)
        .build();

    let response = app.oneshot(make_request("/test", None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let header = response
        .headers()
        .get("bulwark_token")
        .expect("is_write_header=true 时应有续签 header");
    assert_eq!(header.to_str().unwrap(), "dual-token");

    let cookie = response
        .headers()
        .get("set-cookie")
        .expect("is_write_cookie=true 时应有 Set-Cookie");
    assert!(
        cookie
            .to_str()
            .unwrap()
            .contains("bulwark_token=dual-token"),
        "Set-Cookie 应包含续签 token"
    );

    BulwarkManager::reset_for_test();
}

/// T017-5: 无续签 Token → 响应无额外 header/cookie。
#[tokio::test]
#[serial]
async fn no_renewed_token_nothing_written() {
    init_manager(&[], &[]);
    let mut config = make_config();
    config.is_write_header = true;
    config.is_write_cookie = true;

    // 使用 DefaultBulwarkInterceptor（Annotation::Ignore 为 no-op，不触发续签）
    let app = BulwarkRouter::new(Arc::new(config))
        .route_protected("/test", || async { "ok" }, Annotation::Ignore)
        .build();

    let response = app.oneshot(make_request("/test", None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response.headers().get("bulwark_token").is_none(),
        "无续签时不应有续签 header"
    );
    assert!(
        response.headers().get("set-cookie").is_none(),
        "无续签时不应有 Set-Cookie"
    );

    BulwarkManager::reset_for_test();
}

/// T017-6: clear_renewed_token 后后续请求无续签 Token。
#[tokio::test]
#[serial]
async fn clear_renewed_token_prevents_leak() {
    init_manager(&[], &[]);
    let mut config = make_config();
    config.is_write_header = true;
    config.is_write_cookie = false;

    // 第一次请求：触发续签
    let app1 = BulwarkRouter::new(Arc::new(config.clone()))
        .with_interceptor(RenewingInterceptor {
            new_token: "first-renewal".to_string(),
        })
        .route_protected("/test", || async { "ok" }, Annotation::Ignore)
        .build();

    let resp1 = app1.oneshot(make_request("/test", None)).await.unwrap();
    assert_eq!(resp1.status(), StatusCode::OK);
    assert!(
        resp1.headers().get("bulwark_token").is_some(),
        "第一次请求应有续签 header"
    );

    // 第二次请求：不触发续签（DefaultBulwarkInterceptor + Ignore = no-op）
    let app2 = BulwarkRouter::new(Arc::new(config))
        .route_protected("/test", || async { "ok" }, Annotation::Ignore)
        .build();

    let resp2 = app2.oneshot(make_request("/test", None)).await.unwrap();
    assert_eq!(resp2.status(), StatusCode::OK);
    assert!(
        resp2.headers().get("bulwark_token").is_none(),
        "第二次请求不应有续签 header（clear_renewed_token 已清除）"
    );

    BulwarkManager::reset_for_test();
}

/// T017-7: 配置中的 token_name 用作 header 名。
#[tokio::test]
#[serial]
async fn token_name_used_as_header_name() {
    init_manager(&[], &[]);
    let mut config = make_config();
    config.token_name = "custom_auth_token".to_string();
    config.is_write_header = true;
    config.is_write_cookie = false;

    let app = BulwarkRouter::new(Arc::new(config))
        .with_interceptor(RenewingInterceptor {
            new_token: "custom-name-token".to_string(),
        })
        .route_protected("/test", || async { "ok" }, Annotation::Ignore)
        .build();

    let response = app.oneshot(make_request("/test", None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let header = response
        .headers()
        .get("custom_auth_token")
        .expect("应使用 config.token_name 作为 header 名");
    assert_eq!(header.to_str().unwrap(), "custom-name-token");
    assert!(
        response.headers().get("bulwark_token").is_none(),
        "不应使用默认 token_name"
    );

    BulwarkManager::reset_for_test();
}

/// T017-8: Cookie 包含正确属性（HttpOnly, Path=/, SameSite=Lax）。
#[tokio::test]
#[serial]
async fn cookie_has_correct_attributes() {
    init_manager(&[], &[]);
    let mut config = make_config();
    config.is_write_header = false;
    config.is_write_cookie = true;

    let app = BulwarkRouter::new(Arc::new(config))
        .with_interceptor(RenewingInterceptor {
            new_token: "attr-check-token".to_string(),
        })
        .route_protected("/test", || async { "ok" }, Annotation::Ignore)
        .build();

    let response = app.oneshot(make_request("/test", None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);

    let cookie = response
        .headers()
        .get("set-cookie")
        .expect("应有 Set-Cookie header");
    let cookie_str = cookie.to_str().unwrap();
    assert!(
        cookie_str.contains("HttpOnly"),
        "Cookie 应包含 HttpOnly，实际: {}",
        cookie_str
    );
    assert!(
        cookie_str.contains("Path=/"),
        "Cookie 应包含 Path=/，实际: {}",
        cookie_str
    );
    assert!(
        cookie_str.contains("SameSite=Lax"),
        "Cookie 应包含 SameSite=Lax，实际: {}",
        cookie_str
    );
    assert!(
        cookie_str.contains("bulwark_token=attr-check-token"),
        "Cookie 应包含续签 token，实际: {}",
        cookie_str
    );

    BulwarkManager::reset_for_test();
}
