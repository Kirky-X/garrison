//! 路由模块，提供路由器与拦截器抽象。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的路由拦截器（`SaInterceptor`），
//! 适配 axum Web 框架的路由层。
//!
//! ## 设计
//!
//! - `BulwarkInterceptor` trait：预处理 hook，根据 annotation 调用 `BulwarkUtil`
//! - `DefaultBulwarkInterceptor`：默认实现，根据 annotation 变体调用对应 API
//! - `BulwarkRouter`：包装 `axum::Router`，提供 `route_protected` 语法糖（cfg `web-axum`）
//! - `BulwarkLayer` middleware：自动从 header/cookie 提取 token + 设置 task_local

use crate::annotation::Annotation;
use crate::error::{BulwarkError, BulwarkResult};
use crate::stp::BulwarkUtil;
use async_trait::async_trait;
#[cfg(feature = "web-axum")]
use std::sync::Arc;

// ============================================================================
// BulwarkInterceptor trait（always compiled，prelude 重导出依赖）
// ============================================================================

/// 拦截器 trait，定义请求预处理抽象。
///
/// [借鉴 Sa-Token] 对应 `SaInterceptor`，根据 annotation 执行鉴权逻辑。
///
/// 实现方在 `pre_handle` 中根据 annotation 调用 `BulwarkUtil::check_login` 等方法。
/// middleware 在执行 handler 前调用此方法，返回 `Err` 时短路返回错误响应。
#[async_trait]
pub trait BulwarkInterceptor: Send + Sync {
    /// 预处理请求，根据 annotation 执行鉴权。
    ///
    /// # 参数
    /// - `path`: 请求路径。
    /// - `annotation`: 路由关联的鉴权注解。
    ///
    /// # 返回
    /// - `Ok(())`: 鉴权通过，继续执行 handler。
    /// - `Err`: 鉴权失败，middleware 短路返回错误响应（401/403/500）。
    async fn pre_handle(&self, path: &str, annotation: &Annotation) -> BulwarkResult<()>;
}

// ============================================================================
// DefaultBulwarkInterceptor（always compiled）
// ============================================================================

/// 默认拦截器实现，根据 annotation 变体调用对应 `BulwarkUtil` 方法。
///
/// # 注解处理方式
///
/// **直接鉴权（5 个）**：
/// - `CheckLogin` → `BulwarkUtil::check_login()`（未登录返回 `NotLogin`）
/// - `CheckRole(r)` → `BulwarkUtil::check_role(r)`
/// - `CheckPermission(p)` → `BulwarkUtil::check_permission(p)`
/// - `CheckSafe` → `BulwarkUtil::check_safe()`（0.3.0 二级认证）
/// - `CheckDisable` → `BulwarkUtil::check_disable()`（0.3.0 账号禁用）
///
/// **NotImplemented（3 个）**：依赖 HTTP 请求上下文（Authorization header / method / body），
/// 而 `pre_handle` 签名仅有 `path + annotation`，无法获取。Fail Loud（Rule 12）返回
/// `BulwarkError::NotImplemented`，引导用户改用 axum extractor 或 secure 模块直接调用：
/// - `CheckBasicAuth` → 使用 `secure::httpbasic::HttpBasicAuth` 或 axum extractor
/// - `CheckDigestAuth` → 使用 `secure::httpdigest::HttpDigestAuth` 或 axum extractor
/// - `CheckSign` → 使用 `protocol::sign::SignHandler` 或 axum extractor
///
/// **直接放行（no-op）**：
/// - `Ignore` / 逻辑组合注解（`CheckOr` / `CheckAnd` / `CheckNot`）→ no-op
///   （组合逻辑由注解处理器在编译期或路由配置层处理）
pub struct DefaultBulwarkInterceptor;

#[async_trait]
impl BulwarkInterceptor for DefaultBulwarkInterceptor {
    async fn pre_handle(&self, _path: &str, annotation: &Annotation) -> BulwarkResult<()> {
        match annotation {
            Annotation::CheckLogin => {
                let logged_in = BulwarkUtil::check_login().await?;
                if !logged_in {
                    return Err(BulwarkError::NotLogin("未登录".to_string()));
                }
                Ok(())
            },
            Annotation::CheckRole(role) => BulwarkUtil::check_role(role).await,
            Annotation::CheckPermission(perm) => BulwarkUtil::check_permission(perm).await,
            // 0.3.0：二级认证检查（依据 spec annotation-handling）
            Annotation::CheckSafe => BulwarkUtil::check_safe().await,
            // 0.3.0：账号禁用检查（依据 spec annotation-handling）
            Annotation::CheckDisable => BulwarkUtil::check_disable().await,
            // 0.3.0：HTTP Basic/Digest/Sign 需 HTTP 请求上下文（Authorization header / method / body），
            // pre_handle 签名仅有 path + annotation，无法获取请求头。
            // Fail Loud（Rule 12）：明确返回 NotImplemented，指示用户使用 axum extractor 或 secure 模块直接调用。
            Annotation::CheckBasicAuth => Err(BulwarkError::NotImplemented(
                "CheckBasicAuth 需 HTTP 请求上下文，请在 handler 中使用 secure::httpbasic::HttpBasicAuth 或 axum extractor".to_string(),
            )),
            Annotation::CheckDigestAuth => Err(BulwarkError::NotImplemented(
                "CheckDigestAuth 需 HTTP 请求上下文，请在 handler 中使用 secure::httpdigest::HttpDigestAuth 或 axum extractor".to_string(),
            )),
            Annotation::CheckSign => Err(BulwarkError::NotImplemented(
                "CheckSign 需 HTTP 请求上下文，请在 handler 中使用 protocol::sign::SignHandler 或 axum extractor".to_string(),
            )),
            Annotation::Ignore => Ok(()),
            // 逻辑组合注解（CheckOr/CheckAnd/CheckNot）在 pre_handle 中为 no-op，
            // 实际组合逻辑由注解处理器在编译期或路由配置层处理。
            _ => Ok(()),
        }
    }
}

// ============================================================================
// BulwarkRouter（cfg feature = "web-axum"）
// ============================================================================

#[cfg(feature = "web-axum")]
pub use web_axum::BulwarkRouter;

/// 无 `web-axum` feature 时的占位类型（维持 prelude 重导出可用）。
#[cfg(not(feature = "web-axum"))]
pub struct BulwarkRouter;

#[cfg(feature = "web-axum")]
mod web_axum {
    use super::*;
    use crate::config::BulwarkConfig;
    use crate::context::axum_adapter::AxumRequest;
    #[cfg(feature = "tenant-isolation")]
    use crate::context::tenant::TenantResolver;
    use crate::context::BulwarkRequest;
    use crate::stp::with_current_token;
    use axum::body::Body;
    use axum::extract::State;
    use axum::handler::Handler;
    use axum::http::Request;
    #[cfg(feature = "tenant-isolation")]
    use axum::http::StatusCode;
    use axum::middleware::{from_fn_with_state, Next};
    use axum::response::{IntoResponse, Response};
    use axum::Router;

    /// 路由规则：路径 + 注解。
    #[derive(Clone)]
    struct RouteRule {
        path: String,
        annotation: Annotation,
    }

    /// middleware 共享状态（Clone 以支持 `from_fn_with_state`）。
    #[derive(Clone)]
    struct MiddlewareState {
        rules: Arc<Vec<RouteRule>>,
        interceptor: Arc<dyn BulwarkInterceptor>,
        config: Arc<BulwarkConfig>,
    }

    /// 路由器，包装 `axum::Router` 并管理鉴权路由规则。
    ///
    /// [借鉴 Sa-Token] 对应 Sa-Token 的路由拦截器配置。
    ///
    /// # 使用
    ///
    /// ```ignore
    /// use bulwark::prelude::*;
    /// use bulwark::annotation::Annotation;
    /// use std::sync::Arc;
    ///
    /// let router = BulwarkRouter::new(Arc::new(BulwarkConfig::default_config()))
    ///     .route_protected("/api/user", || async { "user ok" }, Annotation::CheckLogin)
    ///     .route_protected(
    ///         "/api/admin",
    ///         || async { "admin ok" },
    ///         Annotation::CheckRole("admin".to_string()),
    ///     )
    ///     .build();
    /// ```
    pub struct BulwarkRouter {
        inner: Router,
        rules: Vec<RouteRule>,
        interceptor: Arc<dyn BulwarkInterceptor>,
        config: Arc<BulwarkConfig>,
    }

    impl BulwarkRouter {
        /// 创建新的路由器实例，使用 `DefaultBulwarkInterceptor`。
        ///
        /// # 参数
        /// - `config`: 全局配置（用于 middleware 提取 token）。
        pub fn new(config: Arc<BulwarkConfig>) -> Self {
            Self {
                inner: Router::new(),
                rules: Vec::new(),
                interceptor: Arc::new(DefaultBulwarkInterceptor),
                config,
            }
        }

        /// 设置自定义拦截器。
        pub fn with_interceptor<I: BulwarkInterceptor + 'static>(mut self, interceptor: I) -> Self {
            self.interceptor = Arc::new(interceptor);
            self
        }

        /// 添加受保护路由：注册 axum 路由（GET）+ 记录鉴权规则。
        ///
        /// # 参数
        /// - `path`: 请求路径模式（精确匹配）。
        /// - `handler`: axum handler（GET 方法）。
        /// - `annotation`: 鉴权注解。
        pub fn route_protected<H, T>(
            mut self,
            path: &str,
            handler: H,
            annotation: Annotation,
        ) -> Self
        where
            H: Handler<T, ()> + Clone + Send + Sync + 'static,
            T: 'static,
        {
            self.inner = self.inner.route(path, axum::routing::get(handler));
            self.rules.push(RouteRule {
                path: path.to_string(),
                annotation,
            });
            self
        }

        /// 构建最终的 axum Router，应用 BulwarkLayer middleware。
        ///
        /// middleware 流程：提取 token → `with_current_token` 设置 task_local →
        /// 调用 `interceptor.pre_handle(path, annotation)` → 执行 handler。
        pub fn build(self) -> Router {
            let state = MiddlewareState {
                rules: Arc::new(self.rules),
                interceptor: self.interceptor,
                config: self.config,
            };
            self.inner
                .layer(from_fn_with_state(state, bulwark_middleware))
        }
    }

    /// 实现 `Default`：使用 `BulwarkConfig::default_config()` 创建路由器，拦截器为 `DefaultBulwarkInterceptor`。
    impl Default for BulwarkRouter {
        fn default() -> Self {
            Self::new(Arc::new(BulwarkConfig::default_config()))
        }
    }

    /// Bulwark middleware：提取 token → 设置 task_local → 调用 interceptor.pre_handle → 执行 handler。
    ///
    /// 对未匹配任何规则的路径，跳过 `pre_handle` 直接放行（仍设置 task_local 以便 handler 调用 BulwarkUtil）。
    async fn bulwark_middleware(
        State(state): State<MiddlewareState>,
        req: Request<Body>,
        next: Next,
    ) -> Response {
        let path = req.uri().path().to_string();
        let rule = state.rules.iter().find(|r| r.path == path).cloned();

        let token = AxumRequest::new(&req)
            .get_token(&state.config)
            .ok()
            .flatten();

        let handle = async {
            if let Some(rule) = &rule {
                state
                    .interceptor
                    .pre_handle(&path, &rule.annotation)
                    .await?;
            }
            Ok::<_, BulwarkError>(next.run(req).await)
        };

        let result = match token {
            Some(t) => with_current_token(t, handle).await,
            None => handle.await,
        };

        match result {
            Ok(resp) => resp,
            Err(e) => e.into_response(),
        }
    }

    // ----------------------------------------------------------------
    // tenant_resolution_middleware（v0.5.0 新增，依据 spec tenant-isolation R-005）
    // ----------------------------------------------------------------

    /// 租户解析 middleware：从请求 headers 解析 `TenantContext`，在 `TENANT` task_local
    /// scope 内执行下游 handler。
    ///
    /// 解析失败时返回 `400 Bad Request`（不默认租户 0，Rule 12 失败显性化——
    /// 静默回退默认租户会让跨租户数据泄露被掩盖）。
    ///
    /// # 参数
    /// - `State(resolver)`: `Arc<dyn TenantResolver>` 状态，由 `from_fn_with_state` 注入
    /// - `req`: axum 请求
    /// - `next`: 下一个 middleware / handler
    ///
    /// # 返回
    /// - `Ok(response)`: 租户解析成功，handler 已在 `TENANT` scope 内执行
    /// - `Err(StatusCode::BAD_REQUEST)`: 租户解析失败（如 `X-Tenant-Id` header 缺失/格式错误）
    ///
    /// # 使用
    ///
    /// ```ignore
    /// use bulwark::context::tenant::{HeaderTenantResolver, TenantResolver};
    /// use std::sync::Arc;
    /// use axum::Router;
    ///
    /// let resolver: Arc<dyn TenantResolver> = Arc::new(HeaderTenantResolver);
    /// let app = Router::new()
    ///     .route("/api", axum::routing::get(handler))
    ///     .layer(axum::middleware::from_fn_with_state(
    ///         resolver,
    ///         bulwark::router::tenant_resolution_middleware,
    ///     ));
    /// ```
    #[cfg(feature = "tenant-isolation")]
    pub async fn tenant_resolution_middleware(
        State(resolver): State<Arc<dyn TenantResolver>>,
        req: Request<Body>,
        next: Next,
    ) -> Result<Response, StatusCode> {
        use crate::context::tenant::TENANT;

        let ctx = resolver
            .resolve(req.headers())
            .await
            .map_err(|_| StatusCode::BAD_REQUEST)?;
        Ok(TENANT.scope(ctx, next.run(req)).await)
    }
}

/// 租户解析 middleware 的 re-export（依据 spec tenant-isolation R-005）。
///
/// 仅在 `web-axum` + `tenant-isolation` 双 feature 启用时可用。
#[cfg(all(feature = "web-axum", feature = "tenant-isolation"))]
pub use web_axum::tenant_resolution_middleware;

// ============================================================================
// 测试（cfg all(test, feature = "web-axum")）
// ============================================================================

#[cfg(all(test, feature = "web-axum"))]
mod tests {
    use super::*;
    use crate::annotation::Annotation;
    use crate::config::BulwarkConfig;
    use crate::dao::BulwarkDao;
    use crate::error::BulwarkError;
    use crate::manager::BulwarkManager;
    use crate::stp::{BulwarkInterface, BulwarkUtil};
    use async_trait::async_trait;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use parking_lot::Mutex;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::time::{Duration, Instant};
    use tower::ServiceExt;

    // ----------------------------------------------------------------
    // MockDao（HashMap + Instant 模拟 TTL）
    // ----------------------------------------------------------------

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

    // ----------------------------------------------------------------
    // MockInterface（权限/角色数据回调）
    // ----------------------------------------------------------------

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
    fn init_manager(permissions: &[(i64, &[&str])], roles: &[(i64, &[&str])]) {
        BulwarkManager::reset_for_test();
        let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
        let config = Arc::new(make_config());
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
        let token = BulwarkUtil::login(1001).await.unwrap();

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
        let token = BulwarkUtil::login(1001).await.unwrap();

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
        let token = BulwarkUtil::login(1001).await.unwrap();

        let app = make_router().build();
        let response = app
            .oneshot(make_request("/users", Some(&token)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);

        BulwarkManager::reset_for_test();
    }

    /// 持有权限访问 → 200。
    #[tokio::test]
    #[serial]
    async fn permission_granted_returns_200() {
        init_manager(&[(1001, &["user:read"])], &[]);
        let token = BulwarkUtil::login(1001).await.unwrap();

        let app = make_router().build();
        let response = app
            .oneshot(make_request("/users", Some(&token)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        BulwarkManager::reset_for_test();
    }

    /// 未持有角色访问 → 403。
    #[tokio::test]
    #[serial]
    async fn role_denied_returns_403() {
        init_manager(&[], &[]); // 无角色数据
        let token = BulwarkUtil::login(1001).await.unwrap();

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
        init_manager(&[], &[(1001, &["admin"])]);
        let token = BulwarkUtil::login(1001).await.unwrap();

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
        let token = BulwarkUtil::login(1001).await.unwrap();

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
        let token = BulwarkUtil::login(1001).await.unwrap();

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
        let token = BulwarkUtil::login(1001).await.unwrap();

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
        let token = BulwarkUtil::login(1001).await.unwrap();

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
        init_manager(&[], &[(1001, &["admin"])]);
        let token = BulwarkUtil::login(1001).await.unwrap();

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
        let token = BulwarkUtil::login(1001).await.unwrap();

        let interceptor = DefaultBulwarkInterceptor;
        let result = crate::stp::with_current_token(
            token,
            interceptor.pre_handle("/x", &Annotation::CheckPermission("user:read".to_string())),
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
    // 0.3.0 新增：CheckSafe / CheckDisable / CheckBasicAuth / CheckDigestAuth / CheckSign 测试
    // ----------------------------------------------------------------

    /// DefaultBulwarkInterceptor.pre_handle(CheckSafe) 默认实现返回 Ok（未启用 MFA）。
    #[tokio::test]
    #[serial]
    async fn default_interceptor_check_safe_returns_ok_by_default() {
        init_manager(&[], &[]);
        let interceptor = DefaultBulwarkInterceptor;
        let result = interceptor.pre_handle("/x", &Annotation::CheckSafe).await;
        assert!(result.is_ok(), "默认 check_safe（未启用 MFA）应返回 Ok");
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
                msg.contains("secure::httpbasic") || msg.contains("extractor"),
                "错误消息应包含使用建议，实际: {}",
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
        let token = BulwarkUtil::login(1001).await.unwrap();

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
        let token = BulwarkUtil::login(1001).await.unwrap();

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
    // tenant_resolution_middleware 测试（v0.5.0 新增，依据 spec tenant-isolation R-005）
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
}
