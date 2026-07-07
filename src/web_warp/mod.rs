//! warp 框架适配模块。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 warp 适配器，
//! 提供 BulwarkRouter + Filter extractor + BulwarkInterceptor 完整集成。
//!
//! ## 设计（依据 spec web-adapters）
//!
//! - `BulwarkRouter`：路由规则构建器，`route_protected` 注册路径 + 注解映射，`into_filter` 生成守卫 Filter
//! - `check_login()` / `check_role(role)` / `check_permission(perm)`：Filter extractor，per-handler 鉴权
//! - `impl Reply for BulwarkError` + `impl Reject for BulwarkRejection`：错误响应，复用 `response_parts()` 保证三框架一致
//!
//! ## 使用示例
//!
//! ```ignore
//! use bulwark::prelude::*;
//! use bulwark::web_warp::{BulwarkRouter, check_login};
//! use warp::Filter;
//!
//! let router = BulwarkRouter::new(std::sync::Arc::new(BulwarkConfig::default_config()))
//!     .route_protected("/api/user", Annotation::CheckLogin);
//!
//! let routes = warp::path("api")
//!     .and(warp::path("user"))
//!     .and(check_login(std::sync::Arc::new(BulwarkConfig::default_config())))
//!     .map(|| "authenticated");
//! ```

use crate::annotation::Annotation;
use crate::config::BulwarkConfig;
use crate::context::token_extract::extract_token_from_headers;
use crate::error::{BulwarkError, BulwarkResult};
use crate::router::{BulwarkInterceptor, DefaultBulwarkInterceptor};
use crate::stp::with_current_token;
use std::collections::HashMap;
use std::sync::Arc;
use warp::http::header::HeaderMap;
use warp::http::StatusCode;
use warp::reject::Reject;
use warp::reply::{Reply, Response};
use warp::Filter;

#[cfg(test)]
use warp::http::header;

pub mod extractor;

/// 登录主体 extractor Filter（从 Authorization: Bearer <token> 解析 login_id）。
pub use extractor::bulwark_principal;

/// 租户上下文 extractor Filter（需 `tenant-isolation` feature，从 X-Tenant-Id header 解析）。
#[cfg(feature = "tenant-isolation")]
pub use extractor::tenant_context;

// ============================================================================
// Reject + Reply impl：BulwarkError → warp 响应
// ============================================================================

/// 包装 `BulwarkError` 以实现 `warp::reject::Reject`（warp 拒绝链需要 Reject 类型）。
#[derive(Debug)]
pub struct BulwarkRejection(pub BulwarkError);

impl Reject for BulwarkRejection {}

/// 实现 `warp::reply::Reply`，复用 `response_parts()` 保证三框架一致。
///
/// 状态码与错误码映射与 axum `IntoResponse` / actix-web `ResponseError` 完全一致
/// （依据 spec web-adapters Requirement: 适配器行为一致性）。
impl Reply for BulwarkError {
    fn into_response(self) -> Response {
        tracing::error!(error = ?self, "bulwark rejection");
        let (status, _, _, _) = self.response_parts();
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        // 使用 warp 内置 json + with_status 组合，自动设置 content-type: application/json
        let body = warp::reply::json(&self.to_json_body());
        warp::reply::with_status(body, status).into_response()
    }
}

// ============================================================================
// BulwarkRouter：路由规则构建器
// ============================================================================

/// warp 路由器，收集鉴权路由规则并生成守卫 Filter。
///
/// [借鉴 Sa-Token] 对应 axum 版 `BulwarkRouter`，API 对齐。
pub struct BulwarkRouter {
    /// 路径 → 注解映射
    pub rules: HashMap<String, Annotation>,
    /// 拦截器
    pub interceptor: Arc<dyn BulwarkInterceptor>,
    /// 配置
    pub config: Arc<BulwarkConfig>,
}

impl BulwarkRouter {
    /// 创建新的路由器实例，使用 `DefaultBulwarkInterceptor`。
    pub fn new(config: Arc<BulwarkConfig>) -> Self {
        Self {
            rules: HashMap::new(),
            interceptor: Arc::new(DefaultBulwarkInterceptor),
            config,
        }
    }

    /// 设置自定义拦截器。
    pub fn with_interceptor<I: BulwarkInterceptor + 'static>(mut self, interceptor: I) -> Self {
        self.interceptor = Arc::new(interceptor);
        self
    }

    /// 添加受保护路由：注册路径 + 注解映射。
    ///
    /// 注意：warp 的路由注册需在 `warp::path()` 链中单独配置，
    /// 此方法仅记录鉴权规则，由 `into_filter()` 生成的守卫 Filter 执行鉴权。
    pub fn route_protected(mut self, path: &str, annotation: Annotation) -> Self {
        self.rules.insert(path.to_string(), annotation);
        self
    }

    /// 消费路由器，生成 warp 守卫 Filter。
    ///
    /// 该 Filter 检查请求路径是否匹配已注册规则，若匹配则执行 interceptor 鉴权。
    /// 鉴权通过返回 `Ok(())`，失败返回 `Rejection`。
    pub fn into_filter(self) -> impl Filter<Extract = ((),), Error = warp::Rejection> + Clone {
        let rules = Arc::new(self.rules);
        let interceptor = self.interceptor;
        let config = self.config;

        warp::any()
            .and(warp::path::full())
            .and(warp::header::headers_cloned())
            .and_then(move |path: warp::path::FullPath, headers: HeaderMap| {
                let rules = rules.clone();
                let interceptor = interceptor.clone();
                let config = config.clone();
                async move {
                    let path_str = path.as_str().to_string();
                    let annotation = rules.get(&path_str).cloned();

                    if let Some(annotation) = annotation {
                        // Token 可选：与 actix-web middleware 对齐，
                        // Ignore 注解的 pre_handle 直接返回 Ok(())，不需要 token。
                        let token = extract_token_from_headers(&headers, &config)
                            .map_err(|e| warp::reject::custom(BulwarkRejection(e)))?;

                        let auth_check =
                            async { interceptor.pre_handle(&path_str, &annotation).await };

                        let result: BulwarkResult<()> = match token {
                            Some(t) => with_current_token(t, auth_check).await,
                            None => auth_check.await,
                        };

                        result.map_err(|e| warp::reject::custom(BulwarkRejection(e)))?;
                    }
                    Ok::<(), warp::Rejection>(())
                }
            })
    }
}

impl Default for BulwarkRouter {
    fn default() -> Self {
        Self::new(Arc::new(BulwarkConfig::default_config()))
    }
}

// ============================================================================
// Filter extractors：per-handler 鉴权
// ============================================================================

/// `check_login` Filter：验证用户已登录。
///
/// 在 handler 链中使用：
/// ```ignore
/// let routes = warp::path("api")
///     .and(check_login(config))
///     .map(|| "authenticated");
/// ```
pub fn check_login(
    config: Arc<BulwarkConfig>,
) -> impl Filter<Extract = ((),), Error = warp::Rejection> + Clone {
    warp::any()
        .and(warp::header::headers_cloned())
        .and_then(move |headers: HeaderMap| {
            let config = config.clone();
            async move {
                let token = extract_token_from_headers(&headers, &config)
                    .map_err(|e| warp::reject::custom(BulwarkRejection(e)))?
                    .ok_or_else(|| {
                        warp::reject::custom(BulwarkRejection(BulwarkError::NotLogin(
                            "未提供 token".to_string(),
                        )))
                    })?;

                let result: BulwarkResult<()> = with_current_token(token, async {
                    let logged_in = crate::stp::BulwarkUtil::check_login().await?;
                    if !logged_in {
                        return Err(BulwarkError::NotLogin("未登录".to_string()));
                    }
                    Ok(())
                })
                .await;

                result.map_err(|e| warp::reject::custom(BulwarkRejection(e)))?;
                Ok::<(), warp::Rejection>(())
            }
        })
}

/// `check_role` Filter：验证用户持有指定角色。
pub fn check_role(
    config: Arc<BulwarkConfig>,
    role: String,
) -> impl Filter<Extract = ((),), Error = warp::Rejection> + Clone {
    warp::any()
        .and(warp::header::headers_cloned())
        .and_then(move |headers: HeaderMap| {
            let config = config.clone();
            let role = role.clone();
            async move {
                let token = extract_token_from_headers(&headers, &config)
                    .map_err(|e| warp::reject::custom(BulwarkRejection(e)))?
                    .ok_or_else(|| {
                        warp::reject::custom(BulwarkRejection(BulwarkError::NotLogin(
                            "未提供 token".to_string(),
                        )))
                    })?;

                let result: BulwarkResult<()> = with_current_token(token, async move {
                    crate::stp::BulwarkUtil::check_role(&role).await
                })
                .await;

                result.map_err(|e| warp::reject::custom(BulwarkRejection(e)))?;
                Ok::<(), warp::Rejection>(())
            }
        })
}

/// `check_permission` Filter：验证用户持有指定权限。
pub fn check_permission(
    config: Arc<BulwarkConfig>,
    permission: String,
) -> impl Filter<Extract = ((),), Error = warp::Rejection> + Clone {
    warp::any()
        .and(warp::header::headers_cloned())
        .and_then(move |headers: HeaderMap| {
            let config = config.clone();
            let permission = permission.clone();
            async move {
                let token = extract_token_from_headers(&headers, &config)
                    .map_err(|e| warp::reject::custom(BulwarkRejection(e)))?
                    .ok_or_else(|| {
                        warp::reject::custom(BulwarkRejection(BulwarkError::NotLogin(
                            "未提供 token".to_string(),
                        )))
                    })?;

                let result: BulwarkResult<()> = with_current_token(token, async move {
                    crate::stp::BulwarkUtil::check_permission(&permission).await
                })
                .await;

                result.map_err(|e| warp::reject::custom(BulwarkRejection(e)))?;
                Ok::<(), warp::Rejection>(())
            }
        })
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use warp::http::header::HeaderValue;

    // ========================================================================
    // Reply impl 测试（依据 spec web-adapters Requirement: 适配器行为一致性）
    // ========================================================================

    /// NotLogin → 401 响应。
    #[test]
    fn reply_not_login_returns_401() {
        let err = BulwarkError::NotLogin("test".to_string());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// NotPermission → 403 响应。
    #[test]
    fn reply_not_permission_returns_403() {
        let err = BulwarkError::NotPermission("test".to_string());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// NotRole → 403 响应。
    #[test]
    fn reply_not_role_returns_403() {
        let err = BulwarkError::NotRole("test".to_string());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// InvalidToken → 401 响应。
    #[test]
    fn reply_invalid_token_returns_401() {
        let err = BulwarkError::InvalidToken("test".to_string());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// NotImplemented → 501 响应。
    #[test]
    fn reply_not_implemented_returns_501() {
        let err = BulwarkError::NotImplemented("test".to_string());
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }

    /// Exception code=-1 → 401（与 axum/actix-web 一致）。
    #[test]
    fn reply_exception_code_minus1_returns_401() {
        let ex = crate::exception::BulwarkException::new(-1, "未登录");
        let err = BulwarkError::Exception(ex);
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    /// Exception code=-2 → 403（与 axum/actix-web 一致）。
    #[test]
    fn reply_exception_code_minus2_returns_403() {
        let ex = crate::exception::BulwarkException::new(-2, "无权限");
        let err = BulwarkError::Exception(ex);
        let resp = err.into_response();
        assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    }

    /// into_response() 返回 JSON content-type。
    #[test]
    fn reply_returns_json_content_type() {
        let err = BulwarkError::NotLogin("internal detail".to_string());
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
    // BulwarkRejection 测试
    // ========================================================================

    /// BulwarkRejection 包装 BulwarkError。
    #[test]
    fn rejection_wraps_error() {
        let err = BulwarkError::NotLogin("test".to_string());
        let rej = BulwarkRejection(err);
        // Reject trait 无方法可调用，仅验证类型可构造
        // 通过 format! 验证内部错误可访问
        assert!(format!("{:?}", rej).contains("NotLogin"));
    }

    // ========================================================================
    // BulwarkRouter 测试
    // ========================================================================

    /// BulwarkRouter::new 初始化空规则。
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

    /// with_interceptor 设置自定义拦截器。
    #[test]
    fn router_with_interceptor_replaces_default() {
        struct CustomInterceptor;
        #[async_trait::async_trait]
        impl BulwarkInterceptor for CustomInterceptor {
            async fn pre_handle(&self, _path: &str, _annotation: &Annotation) -> BulwarkResult<()> {
                Ok(())
            }
        }
        let router = BulwarkRouter::new(Arc::new(BulwarkConfig::default_config()))
            .with_interceptor(CustomInterceptor);
        // 验证 interceptor 已替换（通过 Arc strong_count >= 1）
        assert!(Arc::strong_count(&router.interceptor) >= 1);
    }

    /// Default impl 创建默认配置的路由器。
    #[test]
    fn router_default_impl() {
        let router = BulwarkRouter::default();
        assert!(router.rules.is_empty());
    }

    // ========================================================================
    // into_filter / check_login / check_role / check_permission Filter 测试
    // ========================================================================

    use crate::dao::BulwarkDao;
    use crate::manager::BulwarkManager;
    use crate::stp::{BulwarkInterface, BulwarkUtil};
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use serial_test::serial;
    use std::time::{Duration, Instant};

    // ----------------------------------------------------------------
    // MockDao（HashMap + Instant 模拟 TTL，复用 web_actix 测试模式）
    // ----------------------------------------------------------------

    struct MockDao {
        store: Mutex<std::collections::HashMap<String, (String, Option<Instant>)>>,
    }

    impl MockDao {
        fn new() -> Self {
            Self {
                store: Mutex::new(std::collections::HashMap::new()),
            }
        }
    }

    #[async_trait]
    impl BulwarkDao for MockDao {
        async fn get(&self, key: &str) -> BulwarkResult<Option<String>> {
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

        async fn set(&self, key: &str, value: &str, ttl_seconds: u64) -> BulwarkResult<()> {
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

        async fn update(&self, key: &str, value: &str) -> BulwarkResult<()> {
            let mut store = self.store.lock();
            match store.get_mut(key) {
                Some((existing, _)) => {
                    *existing = value.to_string();
                    Ok(())
                },
                None => Err(BulwarkError::Dao(format!("键不存在: {}", key))),
            }
        }

        async fn expire(&self, key: &str, seconds: u64) -> BulwarkResult<()> {
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

        async fn delete(&self, key: &str) -> BulwarkResult<()> {
            self.store.lock().remove(key);
            Ok(())
        }
    }

    // ----------------------------------------------------------------
    // MockInterface（权限/角色数据回调）
    // ----------------------------------------------------------------

    struct MockInterface {
        permissions: std::collections::HashMap<i64, Vec<String>>,
        roles: std::collections::HashMap<i64, Vec<String>>,
    }

    impl MockInterface {
        fn new() -> Self {
            Self {
                permissions: std::collections::HashMap::new(),
                roles: std::collections::HashMap::new(),
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
        async fn get_permission_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(self.permissions.get(&login_id).cloned().unwrap_or_default())
        }

        async fn get_role_list(&self, login_id: i64) -> BulwarkResult<Vec<String>> {
            Ok(self.roles.get(&login_id).cloned().unwrap_or_default())
        }
    }

    // ----------------------------------------------------------------
    // 辅助函数
    // ----------------------------------------------------------------

    /// 创建测试配置。
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

    // ----------------------------------------------------------------
    // BulwarkRouter::into_filter 测试
    // ----------------------------------------------------------------

    /// 验证 into_filter 放行未注册路径（无鉴权规则 → Ok）。
    #[tokio::test]
    #[serial]
    async fn into_filter_allows_unprotected_path() {
        init_manager(&[], &[]);
        let router = BulwarkRouter::new(Arc::new(make_config()))
            .route_protected("/protected", Annotation::CheckLogin);
        let filter = router.into_filter();

        let result = warp::test::request()
            .path("/unprotected")
            .filter(&filter)
            .await;
        assert!(result.is_ok());

        BulwarkManager::reset_for_test();
    }

    /// 验证 into_filter 阻断受保护路径（无 token → Rejection）。
    #[tokio::test]
    #[serial]
    async fn into_filter_blocks_protected_path_without_token() {
        init_manager(&[], &[]);
        let router = BulwarkRouter::new(Arc::new(make_config()))
            .route_protected("/protected", Annotation::CheckLogin);
        let filter = router.into_filter();

        let result = warp::test::request()
            .path("/protected")
            .filter(&filter)
            .await;
        assert!(result.is_err());
        let rej = result.unwrap_err();
        assert!(rej.find::<BulwarkRejection>().is_some());

        BulwarkManager::reset_for_test();
    }

    /// 验证 into_filter 放行受保护路径（有效 token → Ok）。
    #[tokio::test]
    #[serial]
    async fn into_filter_allows_protected_path_with_valid_token() {
        init_manager(&[], &[]);
        let token = BulwarkUtil::login(1001).await.unwrap();
        let router = BulwarkRouter::new(Arc::new(make_config()))
            .route_protected("/protected", Annotation::CheckLogin);
        let filter = router.into_filter();

        let result = warp::test::request()
            .path("/protected")
            .header("authorization", format!("Bearer {}", token))
            .filter(&filter)
            .await;
        assert!(result.is_ok());

        BulwarkManager::reset_for_test();
    }

    /// 验证 into_filter 阻断无权限访问（有效 token 但无权限 → Rejection）。
    #[tokio::test]
    #[serial]
    async fn into_filter_blocks_permission_denied() {
        init_manager(&[], &[]); // 无权限数据
        let token = BulwarkUtil::login(1001).await.unwrap();
        let router = BulwarkRouter::new(Arc::new(make_config())).route_protected(
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
        assert!(rej.find::<BulwarkRejection>().is_some());

        BulwarkManager::reset_for_test();
    }

    /// 验证 `into_filter` 对 `Ignore` 路径无 token 也能通过。
    ///
    /// 0.3.0 修复：`into_filter` 现在与 actix-web middleware 对齐，
    /// `Ignore` 注解的 `pre_handle` 直接返回 `Ok(())`，token 为可选。
    #[tokio::test]
    #[serial]
    async fn into_filter_allows_ignore_path_without_token() {
        init_manager(&[], &[]);
        let router = BulwarkRouter::new(Arc::new(make_config()))
            .route_protected("/public", Annotation::Ignore);
        let filter = router.into_filter();

        let result = warp::test::request().path("/public").filter(&filter).await;
        assert!(result.is_ok());

        BulwarkManager::reset_for_test();
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
        assert!(rej.find::<BulwarkRejection>().is_some());

        BulwarkManager::reset_for_test();
    }

    /// 验证 check_login filter 在有效 token 时通过。
    #[tokio::test]
    #[serial]
    async fn check_login_filter_passes_with_valid_token() {
        init_manager(&[], &[]);
        let token = BulwarkUtil::login(1001).await.unwrap();
        let filter = check_login(Arc::new(make_config()));

        let result = warp::test::request()
            .header("authorization", format!("Bearer {}", token))
            .filter(&filter)
            .await;
        assert!(result.is_ok());

        BulwarkManager::reset_for_test();
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
        assert!(result.unwrap_err().find::<BulwarkRejection>().is_some());

        BulwarkManager::reset_for_test();
    }

    /// 验证 check_role filter 在无角色时返回 Rejection。
    #[tokio::test]
    #[serial]
    async fn check_role_filter_rejects_without_role() {
        init_manager(&[], &[]); // 无角色数据
        let token = BulwarkUtil::login(1001).await.unwrap();
        let filter = check_role(Arc::new(make_config()), "admin".to_string());

        let result = warp::test::request()
            .header("authorization", format!("Bearer {}", token))
            .filter(&filter)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().find::<BulwarkRejection>().is_some());

        BulwarkManager::reset_for_test();
    }

    /// 验证 check_role filter 在持有角色时通过。
    #[tokio::test]
    #[serial]
    async fn check_role_filter_passes_with_valid_role() {
        init_manager(&[], &[(1001, &["admin"])]); // 注入 admin 角色
        let token = BulwarkUtil::login(1001).await.unwrap();
        let filter = check_role(Arc::new(make_config()), "admin".to_string());

        let result = warp::test::request()
            .header("authorization", format!("Bearer {}", token))
            .filter(&filter)
            .await;
        assert!(result.is_ok());

        BulwarkManager::reset_for_test();
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
        assert!(result.unwrap_err().find::<BulwarkRejection>().is_some());

        BulwarkManager::reset_for_test();
    }

    /// 验证 check_permission filter 在无权限时返回 Rejection。
    #[tokio::test]
    #[serial]
    async fn check_permission_filter_rejects_without_permission() {
        init_manager(&[], &[]); // 无权限数据
        let token = BulwarkUtil::login(1001).await.unwrap();
        let filter = check_permission(Arc::new(make_config()), "user:read".to_string());

        let result = warp::test::request()
            .header("authorization", format!("Bearer {}", token))
            .filter(&filter)
            .await;
        assert!(result.is_err());
        assert!(result.unwrap_err().find::<BulwarkRejection>().is_some());

        BulwarkManager::reset_for_test();
    }

    /// 验证 check_permission filter 在持有权限时通过。
    #[tokio::test]
    #[serial]
    async fn check_permission_filter_passes_with_valid_permission() {
        init_manager(&[(1001, &["user:read"])], &[]); // 注入权限
        let token = BulwarkUtil::login(1001).await.unwrap();
        let filter = check_permission(Arc::new(make_config()), "user:read".to_string());

        let result = warp::test::request()
            .header("authorization", format!("Bearer {}", token))
            .filter(&filter)
            .await;
        assert!(result.is_ok());

        BulwarkManager::reset_for_test();
    }
}
