//! 过程宏注解集成测试：`#[check_login]` / `#[check_permission]` / `#[check_role]`。
//!
//! 验证 spec annotation-macros R-002 ~ R-004：
//! - 宏标注的 async fn 编译通过
//! - 已登录/已授权请求正常执行 fn body
//! - 未登录请求返回 401（不执行 fn body）
//! - 无权限/无角色请求返回 403
//! - 多参数 AND 语义
//!
//! 测试策略：
//! 1. MockDao + MockInterface + BulwarkManager::init 初始化全局单例
//! 2. `BulwarkUtil::login(id)` 生成 token
//! 3. `with_current_token(token, async { handler().await })` 设置 task_local 上下文
//! 4. 直接调用宏标注的 handler，断言 Response 状态码与 body

#![cfg(feature = "annotation-macros")]

use async_trait::async_trait;
use axum::body::Body;
use axum::http::StatusCode;
use bulwark::{
    check_login, check_permission, check_role, BulwarkConfig, BulwarkDao, BulwarkError,
    BulwarkInterface, BulwarkManager, BulwarkUtil,
};
use http_body_util::BodyExt;
use parking_lot::Mutex;
use serial_test::serial;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ============================================================================
// 宏标注的 handler（模块级定义）
// ============================================================================

/// 登录校验 handler：返回纯文本。
#[check_login]
async fn login_handler() -> &'static str {
    "login_ok"
}

/// 单权限校验 handler。
#[check_permission("user:read")]
async fn perm_handler() -> &'static str {
    "perm_ok"
}

/// 多权限 AND 语义 handler：需同时持有 user:read 和 user:write。
#[check_permission("user:read", "user:write")]
async fn perm_and_handler() -> &'static str {
    "perm_and_ok"
}

/// 单角色校验 handler。
#[check_role("admin")]
async fn role_handler() -> &'static str {
    "role_ok"
}

/// 多角色 AND 语义 handler：需同时持有 admin 和 superadmin。
#[check_role("admin", "superadmin")]
async fn role_and_handler() -> &'static str {
    "role_and_ok"
}

// ============================================================================
// MockDao（HashMap + Instant 模拟 TTL，复用 axum_integration 模式）
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
    permissions: HashMap<i64, Vec<String>>,
    roles: HashMap<i64, Vec<String>>,
}

impl MockInterface {
    fn new() -> Self {
        Self {
            permissions: HashMap::new(),
            roles: HashMap::new(),
        }
    }

    fn with_permission(mut self, login_id: i64, perms: &[&str]) -> Self {
        self.permissions
            .insert(login_id, perms.iter().map(|s| s.to_string()).collect());
        self
    }

    fn with_role(mut self, login_id: i64, roles: &[&str]) -> Self {
        self.roles
            .insert(login_id, roles.iter().map(|s| s.to_string()).collect());
        self
    }
}

#[async_trait]
impl BulwarkInterface for MockInterface {
    async fn get_permission_list(&self, login_id: i64) -> Result<Vec<String>, BulwarkError> {
        Ok(self.permissions.get(&login_id).cloned().unwrap_or_default())
    }

    async fn get_role_list(&self, login_id: i64) -> Result<Vec<String>, BulwarkError> {
        Ok(self.roles.get(&login_id).cloned().unwrap_or_default())
    }
}

// ============================================================================
// 辅助函数
// ============================================================================

/// 创建测试配置（throw_on_not_login=true，未登录直接抛异常走 Err 路径）。
fn make_config_strict() -> BulwarkConfig {
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = true;
    config
}

/// 创建宽松配置（throw_on_not_login=false，未登录返回 Ok(false) 走宏的 Ok(false) 分支）。
fn make_config_loose() -> BulwarkConfig {
    let mut config = BulwarkConfig::default_config();
    config.timeout = 3600;
    config.active_timeout = -1;
    config.throw_on_not_login = false;
    config
}

/// 初始化 BulwarkManager（覆盖式更新，带权限/角色数据）。
fn init_manager(config: BulwarkConfig, permissions: &[(i64, &[&str])], roles: &[(i64, &[&str])]) {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let config = Arc::new(config);
    let mut interface = MockInterface::new();
    for (id, perms) in permissions {
        interface = interface.with_permission(*id, perms);
    }
    for (id, roles) in roles {
        interface = interface.with_role(*id, roles);
    }
    let interface: Arc<dyn BulwarkInterface> = Arc::new(interface);
    BulwarkManager::init(dao, config, interface).unwrap();
}

/// 读取 Response body 为 String。
async fn read_body(response: axum::response::Response) -> String {
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body collect")
        .to_bytes();
    String::from_utf8(bytes.to_vec()).expect("utf8 body")
}

// ============================================================================
// #[check_login] 测试
// ============================================================================

/// 已登录 → 200 + 原 body。
#[tokio::test]
#[serial]
async fn check_login_with_valid_token_returns_200_and_body() {
    init_manager(make_config_strict(), &[], &[]);
    let token = BulwarkUtil::login(1001).await.unwrap();

    let response = bulwark::stp::with_current_token(token, async { login_handler().await }).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    assert_eq!(body, "login_ok");
}

/// 未登录（无 token，throw_on_not_login=true）→ 框架返回 `Err(Session("未登录"))`，
/// 映射到 500（非 401）。这是框架已有行为：`check_login_simple` 在 strict 模式下
/// 返回 `Session` 而非 `NotLogin` 变体。宏正确转发错误，状态码由框架决定。
///
/// 此测试验证宏在 strict 模式下正确转发错误（不吞掉、不篡改）。
#[tokio::test]
#[serial]
async fn check_login_without_token_strict_forwards_error() {
    init_manager(make_config_strict(), &[], &[]);
    // 不调用 login，直接以无效 token 调用 handler
    let response = bulwark::stp::with_current_token("invalid-token".to_string(), async {
        login_handler().await
    })
    .await;
    // 框架返回 Session 错误 → 500（非 401，因为 check_login_simple 用 Session 而非 NotLogin）
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let body = read_body(response).await;
    // body 不应包含 handler 的输出（fn body 未执行）
    assert!(!body.contains("login_ok"));
}

/// 未登录（throw_on_not_login=false）→ 401（宏将 Ok(false) 转为 NotLogin → 401）。
///
/// 此测试验证宏正确处理 `Ok(false)` 路径：将"未登录但不报错"转为 401 响应。
#[tokio::test]
#[serial]
async fn check_login_without_token_loose_returns_401() {
    init_manager(make_config_loose(), &[], &[]);
    // loose 模式下未登录返回 Ok(false)，宏应将其转为 401
    let response = bulwark::stp::with_current_token("invalid-token".to_string(), async {
        login_handler().await
    })
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
}

// ============================================================================
// #[check_permission] 测试
// ============================================================================

/// 持有权限 → 200 + body。
#[tokio::test]
#[serial]
async fn check_permission_with_permission_returns_200() {
    init_manager(make_config_strict(), &[(1001, &["user:read"])], &[]);
    let token = BulwarkUtil::login(1001).await.unwrap();

    let response = bulwark::stp::with_current_token(token, async { perm_handler().await }).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    assert_eq!(body, "perm_ok");
}

/// 无权限 → 403。
#[tokio::test]
#[serial]
async fn check_permission_without_permission_returns_403() {
    init_manager(make_config_strict(), &[], &[]); // 无权限数据
    let token = BulwarkUtil::login(1001).await.unwrap();

    let response = bulwark::stp::with_current_token(token, async { perm_handler().await }).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// AND 语义：仅持有部分权限 → 403。
#[tokio::test]
#[serial]
async fn check_permission_and_partial_returns_403() {
    init_manager(make_config_strict(), &[(1001, &["user:read"])], &[]); // 缺 user:write
    let token = BulwarkUtil::login(1001).await.unwrap();

    let response =
        bulwark::stp::with_current_token(token, async { perm_and_handler().await }).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// AND 语义：持有全部权限 → 200。
#[tokio::test]
#[serial]
async fn check_permission_and_all_returns_200() {
    init_manager(
        make_config_strict(),
        &[(1001, &["user:read", "user:write"])],
        &[],
    );
    let token = BulwarkUtil::login(1001).await.unwrap();

    let response =
        bulwark::stp::with_current_token(token, async { perm_and_handler().await }).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    assert_eq!(body, "perm_and_ok");
}

// ============================================================================
// #[check_role] 测试
// ============================================================================

/// 持有角色 → 200 + body。
#[tokio::test]
#[serial]
async fn check_role_with_role_returns_200() {
    init_manager(make_config_strict(), &[], &[(1001, &["admin"])]);
    let token = BulwarkUtil::login(1001).await.unwrap();

    let response = bulwark::stp::with_current_token(token, async { role_handler().await }).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    assert_eq!(body, "role_ok");
}

/// 无角色 → 403。
#[tokio::test]
#[serial]
async fn check_role_without_role_returns_403() {
    init_manager(make_config_strict(), &[], &[]); // 无角色数据
    let token = BulwarkUtil::login(1001).await.unwrap();

    let response = bulwark::stp::with_current_token(token, async { role_handler().await }).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// AND 语义：仅持有部分角色 → 403。
#[tokio::test]
#[serial]
async fn check_role_and_partial_returns_403() {
    init_manager(make_config_strict(), &[], &[(1001, &["admin"])]); // 缺 superadmin
    let token = BulwarkUtil::login(1001).await.unwrap();

    let response =
        bulwark::stp::with_current_token(token, async { role_and_handler().await }).await;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
}

/// AND 语义：持有全部角色 → 200。
#[tokio::test]
#[serial]
async fn check_role_and_all_returns_200() {
    init_manager(
        make_config_strict(),
        &[],
        &[(1001, &["admin", "superadmin"])],
    );
    let token = BulwarkUtil::login(1001).await.unwrap();

    let response =
        bulwark::stp::with_current_token(token, async { role_and_handler().await }).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = read_body(response).await;
    assert_eq!(body, "role_and_ok");
}

// ============================================================================
// 宏展开行为验证（编译期 + 类型层面）
// ============================================================================

/// 验证宏展开后的函数返回类型为 `axum::response::Response`（非原类型）。
/// 这是一个编译期类型检查：如果宏展开错误导致返回类型不是 Response，编译会失败。
#[tokio::test]
#[serial]
async fn macro_expands_to_response_return_type() {
    init_manager(make_config_strict(), &[], &[]);
    let token = BulwarkUtil::login(1001).await.unwrap();

    let response: axum::response::Response =
        bulwark::stp::with_current_token(token, async { login_handler().await }).await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// 验证 handler 可作为 axum Router 的 handler（IntoResponse 兼容性 + 运行时调用）。
///
/// 宏标注的 handler 返回 `axum::response::Response`，可直接作为 axum handler。
/// 通过 `with_current_token` 包裹 `oneshot` 调用，使 handler 内部能读取 task_local token。
#[tokio::test]
#[serial]
async fn handler_works_with_axum_router() {
    use axum::routing::get;
    use tower::ServiceExt;

    init_manager(
        make_config_strict(),
        &[(1001, &["user:read"])],
        &[(1001, &["admin"])],
    );
    let token = BulwarkUtil::login(1001).await.unwrap();

    // 构建 axum Router，挂载宏标注的 handler
    let app = axum::Router::new()
        .route("/login", get(login_handler))
        .route("/perm", get(perm_handler))
        .route("/role", get(role_handler));

    // 通过 with_current_token 设置 task_local，使 handler 内部 check_login 能读取 token
    let response = bulwark::stp::with_current_token(token.clone(), async {
        app.oneshot(
            axum::http::Request::builder()
                .method("GET")
                .uri("/login")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
    })
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}
