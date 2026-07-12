//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 注解系统集成测试：完整 axum app + extractor + 鉴权 + 401/403 响应。
//!
//! 验证 `CheckLogin` / `CheckRole` / `CheckPermission` extractor 在完整 axum 应用中的行为。

#![cfg(feature = "web-axum")]

use async_trait::async_trait;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use axum::Router;
use bulwark::annotation::{
    CheckLogin, CheckPermission, CheckRole, Ignore, PermissionName, RoleName,
};
use bulwark::config::BulwarkConfig;
use bulwark::dao::BulwarkDao;
use bulwark::error::BulwarkError;
use bulwark::manager::BulwarkManager;
use bulwark::stp::{BulwarkInterface, BulwarkUtil};
use http_body_util::BodyExt;
use parking_lot::Mutex;
use serial_test::serial;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower::ServiceExt;

// ============================================================================
// MockDao（HashMap + Instant 模拟 TTL）
// ============================================================================

struct MockDao {
    store: Mutex<HashMap<String, (String, Option<Instant>)>>,
}

impl MockDao {
    fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

#[async_trait]
impl BulwarkDao for MockDao {
    async fn get(&self, key: &str) -> Result<Option<String>, BulwarkError> {
        let mut store = self.store.lock();
        match store.get(key) {
            Some((value, expire_at)) => {
                if let Some(deadline) = expire_at {
                    if Instant::now() >= *deadline {
                        store.remove(key);
                        return Ok(None);
                    }
                }
                Ok(Some(value.clone()))
            },
            None => Ok(None),
        }
    }

    async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> Result<(), BulwarkError> {
        let expire_at = if ttl_seconds == 0 {
            None
        } else {
            Some(Instant::now() + Duration::from_secs(ttl_seconds))
        };
        self.store
            .lock()
            .insert(key.to_string(), (value.to_string(), expire_at));
        Ok(())
    }

    async fn update(&self, key: &str, value: &str) -> Result<(), BulwarkError> {
        let mut store = self.store.lock();
        match store.get_mut(key) {
            Some((existing, _)) => {
                *existing = value.to_string();
                Ok(())
            },
            None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
        }
    }

    async fn expire(&self, key: &str, seconds: u64) -> Result<(), BulwarkError> {
        let mut store = self.store.lock();
        match store.get_mut(key) {
            Some((_, expire_at)) => {
                *expire_at = if seconds == 0 {
                    None
                } else {
                    Some(Instant::now() + Duration::from_secs(seconds))
                };
                Ok(())
            },
            None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
        }
    }

    async fn delete(&self, key: &str) -> Result<(), BulwarkError> {
        self.store.lock().remove(key);
        Ok(())
    }
}

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
impl BulwarkInterface for MockInterface {
    async fn get_permission_list(&self, login_id: &str) -> Result<Vec<String>, BulwarkError> {
        Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
    }

    async fn get_role_list(&self, login_id: &str) -> Result<Vec<String>, BulwarkError> {
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
fn make_config() -> BulwarkConfig {
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = false;
    config
}

/// 初始化 BulwarkManager（带权限/角色数据）。
fn init_manager(permissions: &[(&str, &[&str])], roles: &[(&str, &[&str])]) {
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

// ============================================================================
// 集成测试
// ============================================================================

/// 已登录（带有效 token header）访问 /protected → 200。
#[tokio::test]
#[serial]
async fn protected_with_valid_token_returns_200() {
    init_manager(&[], &[]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

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
    init_manager(&[], &[]);

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
    init_manager(&[], &[]);

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
    init_manager(&[], &[("1001", &["admin"])]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let app = make_app();
    let response = app
        .oneshot(make_request("/admin", Some(&token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// 未持有 admin 角色访问 /admin → 403。
#[tokio::test]
#[serial]
async fn admin_without_admin_role_returns_403() {
    init_manager(&[], &[]); // 无角色数据
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let app = make_app();
    let response = app
        .oneshot(make_request("/admin", Some(&token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// 持有 user:read 权限访问 /users → 200。
#[tokio::test]
#[serial]
async fn users_with_user_read_permission_returns_200() {
    init_manager(&[("1001", &["user:read"])], &[]);
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let app = make_app();
    let response = app
        .oneshot(make_request("/users", Some(&token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// 未持有 user:read 权限访问 /users → 403。
#[tokio::test]
#[serial]
async fn users_without_user_read_permission_returns_403() {
    init_manager(&[], &[]); // 无权限数据
    let token = BulwarkUtil::login_simple("1001").await.unwrap();

    let app = make_app();
    let response = app
        .oneshot(make_request("/users", Some(&token)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// Ignore extractor 允许匿名访问 /public → 200。
#[tokio::test]
#[serial]
async fn public_without_token_returns_200() {
    init_manager(&[], &[]);

    let app = make_app();
    let response = app.oneshot(make_request("/public", None)).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

/// 验证 401 响应体包含结构化 JSON 错误（不泄漏内部细节，依据 codebase-hardening Task 0.4）。
#[tokio::test]
#[serial]
async fn unauthorized_response_body_contains_error_json() {
    init_manager(&[], &[]);

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
    // 不应包含内部错误细节（如 "BulwarkManager 未初始化" 等实现细节）
    assert!(
        !body_str.contains("BulwarkManager"),
        "响应体不应泄漏 BulwarkManager 内部细节: {}",
        body_str
    );
}
