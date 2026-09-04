//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 注解系统集成测试：完整 axum app + extractor + 鉴权 + 401/403 响应。
//!
//! 验证 `CheckLogin` / `CheckRole` / `CheckPermission` extractor 在完整 axum 应用中的行为。
//!
//! # production-mock-purge (T024)
//!
//! - `MockDao` 已替换为产品 `InMemoryDao`（src/dao/in_memory.rs）。
//! - NEEDS CLARIFICATION: 无产品 GarrisonInterface 实现，待库层补实现后真实化
//!   （框架设计为业务方实现 `GarrisonInterface` 回调，库层未提供默认实现，
//!   本文件 `MockInterface` 替身保留）。

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use garrison::annotation::{
    CheckLogin, CheckPermission, CheckRole, Ignore, PermissionName, RoleName,
};
use garrison::config::GarrisonConfig;
use garrison::dao::{GarrisonDao, InMemoryDao};
use garrison::error::GarrisonError;
use garrison::manager::GarrisonManager;
use garrison::stp::{GarrisonInterface, GarrisonUtil};
use http_body_util::BodyExt;
use serial_test::serial;
use std::collections::HashMap;
use std::sync::Arc;
use tower::ServiceExt;

// ============================================================================
// MockInterface（权限/角色数据回调）
// ============================================================================

struct MockInterface {
    permissions: HashMap<String, Vec<String>>,
    roles: HashMap<String, Vec<String>>,
}

impl MockInterface {
    fn new() -> Self {
        Self {
            permissions: HashMap::new(),
            roles: HashMap::new(),
        }
    }

    fn with_permission(mut self, login_id: &str, perms: &[&str]) -> Self {
        self.permissions.insert(
            login_id.to_string(),
            perms.iter().map(|s| s.to_string()).collect(),
        );
        self
    }

    fn with_role(mut self, login_id: &str, roles: &[&str]) -> Self {
        self.roles.insert(
            login_id.to_string(),
            roles.iter().map(|s| s.to_string()).collect(),
        );
        self
    }
}

#[async_trait]
impl GarrisonInterface for MockInterface {
    async fn get_permission_list(&self, login_id: &str) -> Result<Vec<String>, GarrisonError> {
        Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
    }

    async fn get_role_list(&self, login_id: &str) -> Result<Vec<String>, GarrisonError> {
        Ok(self.roles.get(login_id).cloned().unwrap_or_default())
    }
}

// ============================================================================
// 测试用 marker 类型
// ============================================================================

struct AdminRole;
impl RoleName for AdminRole {
    const NAME: &'static str = "admin";
}

struct UserRead;
impl PermissionName for UserRead {
    const NAME: &'static str = "user:read";
}

// ============================================================================
// 辅助函数
// ============================================================================

/// 创建测试配置（throw_on_not_login=false 以便未登录返回 NotLogin→401）。
fn make_config() -> GarrisonConfig {
    let mut config = GarrisonConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = false;
    config
}

/// 初始化 GarrisonManager（带权限/角色数据）。
async fn init_manager(permissions: &[(&str, &[&str])], roles: &[(&str, &[&str])]) {
    let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
    let config = Arc::new(make_config());
    let mut interface = MockInterface::new();
    for (id, perms) in permissions {
        interface = interface.with_permission(id, perms);
    }
    for (id, roles) in roles {
        interface = interface.with_role(id, roles);
    }
    let interface: Arc<dyn GarrisonInterface> = Arc::new(interface);
    GarrisonManager::builder()
        .dao(dao)
        .config(config)
        .interface(interface)
        .build()
        .await
        .unwrap();
}

/// 构建 axum app：包含 /protected（CheckLogin）、/admin（CheckRole<AdminRole>）、
/// /users（CheckPermission<UserRead>）、/public（Ignore）路由。
fn make_app() -> Router {
    Router::new()
        .route("/protected", get(|_: CheckLogin| async { "ok" }))
        .route(
            "/admin",
            get(|_: CheckRole<AdminRole>| async { "admin ok" }),
        )
        .route(
            "/users",
            get(|_: CheckPermission<UserRead>| async { "users ok" }),
        )
        .route("/public", get(|_: Ignore| async { "public ok" }))
}

/// 构建 GET 请求（带可选 Authorization header）。
fn make_request(path: &str, token: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method("GET").uri(path);
    if let Some(t) = token {
        builder = builder.header("Authorization", format!("Bearer {}", t));
    }
    builder.body(Body::empty()).unwrap()
}

/// 设置默认 TENANT scope（tenant_id=0），避免 tenant-isolation feature 启用时
/// `current_tenant_id_or_error()` 返回 Err(Config) 导致权限校验提前失败。
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

// ============================================================================
// 集成测试
// ============================================================================

/// 已登录（带有效 token header）访问 /protected → 200。
#[tokio::test]
#[serial]
async fn protected_with_valid_token_returns_200() {
    init_manager(&[], &[]).await;
    let token = GarrisonUtil::login_simple("1001").await.unwrap();

    let app = make_app();
    let response = app
        .oneshot(make_request("/protected", Some(&token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// 未登录（无 token）访问 /protected → 401。
#[tokio::test]
#[serial]
async fn protected_without_token_returns_401() {
    init_manager(&[], &[]).await;

    let app = make_app();
    let response = app.oneshot(make_request("/protected", None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 验证响应体包含错误信息
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        body_str.contains("error"),
        "响应体应包含 error 字段: {}",
        body_str
    );
}

/// 无效 token 访问 /protected → 401。
#[tokio::test]
#[serial]
async fn protected_with_invalid_token_returns_401() {
    init_manager(&[], &[]).await;

    let app = make_app();
    let response = app
        .oneshot(make_request("/protected", Some("invalid-token")))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

/// 持有 admin 角色访问 /admin → 200。
#[tokio::test]
#[serial]
async fn admin_with_admin_role_returns_200() {
    with_default_tenant(async {
        init_manager(&[], &[("1001", &["admin"])]).await;
        let token = GarrisonUtil::login_simple("1001").await.unwrap();

        let app = make_app();
        let response = app
            .oneshot(make_request("/admin", Some(&token)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    })
    .await
}

/// 未持有 admin 角色访问 /admin → 403。
#[tokio::test]
#[serial]
async fn admin_without_admin_role_returns_403() {
    with_default_tenant(async {
        init_manager(&[], &[]).await; // 无角色数据
        let token = GarrisonUtil::login_simple("1001").await.unwrap();

        let app = make_app();
        let response = app
            .oneshot(make_request("/admin", Some(&token)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    })
    .await
}

/// 持有 user:read 权限访问 /users → 200。
#[tokio::test]
#[serial]
async fn users_with_user_read_permission_returns_200() {
    with_default_tenant(async {
        init_manager(&[("1001", &["user:read"])], &[]).await;
        let token = GarrisonUtil::login_simple("1001").await.unwrap();

        let app = make_app();
        let response = app
            .oneshot(make_request("/users", Some(&token)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    })
    .await
}

/// 未持有 user:read 权限访问 /users → 403。
#[tokio::test]
#[serial]
async fn users_without_user_read_permission_returns_403() {
    with_default_tenant(async {
        init_manager(&[], &[]).await; // 无权限数据
        let token = GarrisonUtil::login_simple("1001").await.unwrap();

        let app = make_app();
        let response = app
            .oneshot(make_request("/users", Some(&token)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    })
    .await
}

/// Ignore extractor 允许匿名访问 /public → 200。
#[tokio::test]
#[serial]
async fn public_without_token_returns_200() {
    init_manager(&[], &[]).await;

    let app = make_app();
    let response = app.oneshot(make_request("/public", None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// 验证 401 响应体包含结构化 JSON 错误（不泄漏内部细节，依据 codebase-hardening Task 0.4）。
#[tokio::test]
#[serial]
async fn unauthorized_response_body_contains_error_json() {
    init_manager(&[], &[]).await;

    let app = make_app();
    let response = app.oneshot(make_request("/protected", None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body_str = String::from_utf8(body.to_vec()).unwrap();
    assert!(
        body_str.contains("\"error_code\":\"NOT_LOGIN\""),
        "响应体应是 JSON 且包含 error_code 字段: {}",
        body_str
    );
    assert!(
        body_str.contains("\"message\":\"未登录\""),
        "响应体应包含 '未登录' 通用消息: {}",
        body_str
    );
    // 不应包含内部错误细节（如 "GarrisonManager 未初始化" 等实现细节）
    assert!(
        !body_str.contains("GarrisonManager"),
        "响应体不应泄漏 GarrisonManager 内部细节: {}",
        body_str
    );
}
