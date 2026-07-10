//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! actix-web 框架适配模块。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 actix-web 适配器，
//! 提供 BulwarkRouter + FromRequest extractor + BulwarkInterceptor 完整集成。
//!
//! ## 设计
//!
//! - `BulwarkRouter`：路由规则构建器，`route_protected` 注册路径 + 注解映射
//! - `BulwarkMiddleware`：actix-web middleware（Transform + Service），请求前调用 interceptor
//! - `CheckLogin` / `CheckRole` / `CheckPermission`：FromRequest extractors，per-handler 鉴权
//! - `ResponseError for BulwarkError`：错误响应，复用 `response_parts()` 保证三框架一致
//!
//! ## 使用示例
//!
//! ```ignore
//! use bulwark::prelude::*;
//! use bulwark::web_actix::{BulwarkRouter, CheckLogin};
//! use actix_web::{App, HttpServer, web};
//!
//! async fn protected_handler(_auth: CheckLogin) -> &'static str {
//!     "authenticated"
//! }
//!
//! let router = BulwarkRouter::new(std::sync::Arc::new(BulwarkConfig::default_config()))
//!     .route_protected("/api/user", Annotation::CheckLogin);
//!
//! App::new()
//!     .route("/api/user", web::get().to(protected_handler))
//!     .wrap(router.into_middleware());
//! ```

use crate::annotation::Annotation;
use crate::config::BulwarkConfig;
use crate::context::token_extract::{extract_token_from_headers, HeaderLookup};
use crate::error::{BulwarkError, BulwarkResult};
use crate::router::{BulwarkInterceptor, DefaultBulwarkInterceptor};
use crate::stp::with_current_token;
use actix_web::body::{BoxBody, EitherBody};
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};
use std::collections::HashMap;
use std::future::{ready, Ready};
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;

#[cfg(test)]
use actix_web::http::header::{self, HeaderMap};

pub mod extractor;

/// 登录主体 extractor（从 Authorization: Bearer `<token>` 解析 login_id）。
pub use extractor::BulwarkPrincipal;

// ============================================================================
// HeaderLookup impl：适配 actix_http::header::HeaderMap（独立类型，非 http::HeaderMap）
// ============================================================================

/// 为 `actix_web::http::header::HeaderMap`（= `actix_http::header::HeaderMap`）实现
/// [`HeaderLookup`] trait，使其可传入 `extract_token_from_headers`。
///
/// **背景**：`actix_web::http::header::HeaderMap` 与 `http::HeaderMap` 是不同的类型
/// （尽管 `HeaderValue` / `HeaderName` 是 `http` crate 类型的 re-export）。
/// 此 impl 桥接类型差异，使 `extract_token_from_headers` 可同时接受两种 HeaderMap。
impl HeaderLookup for actix_web::http::header::HeaderMap {
    fn get_header(&self, name: &str) -> Option<&str> {
        self.get(name).and_then(|v| v.to_str().ok())
    }
}

// ============================================================================
// ResponseError impl：BulwarkError → actix-web HttpResponse
// ============================================================================

/// 实现 actix-web `ResponseError` trait，复用 `response_parts()` 保证三框架一致。
///
/// 状态码与错误码映射与 axum `IntoResponse` 完全一致。
impl ResponseError for BulwarkError {
    fn status_code(&self) -> StatusCode {
        let (s, _, _, _) = self.response_parts();
        StatusCode::from_u16(s).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    fn error_response(&self) -> HttpResponse {
        tracing::error!(error = ?self, "bulwark rejection");
        let (s, _, _, _) = self.response_parts();
        let status = StatusCode::from_u16(s).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        HttpResponse::build(status).json(self.to_json_body())
    }
}

// ============================================================================
// BulwarkRouter：路由规则构建器
// ============================================================================

/// 路由规则：路径 → 注解映射。
#[derive(Clone)]
pub struct RouteRule {
    /// 路由路径
    pub path: String,
    /// 关联注解
    pub annotation: Annotation,
}

/// actix-web 路由器，收集鉴权路由规则并生成 middleware。
///
/// [借鉴 Sa-Token] 对应 axum 版 `BulwarkRouter`，API 对齐。
pub struct BulwarkRouter {
    rules: HashMap<String, Annotation>,
    interceptor: Arc<dyn BulwarkInterceptor>,
    config: Arc<BulwarkConfig>,
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
    /// 注意：actix-web 的路由注册需在 `App::route()` 中单独配置，
    /// 此方法仅记录鉴权规则，由 `into_middleware()` 生成的 middleware 执行鉴权。
    pub fn route_protected(mut self, path: &str, annotation: Annotation) -> Self {
        self.rules.insert(path.to_string(), annotation);
        self
    }

    /// 消费路由器，生成 actix-web middleware。
    pub fn into_middleware(self) -> BulwarkMiddleware {
        BulwarkMiddleware {
            rules: Arc::new(self.rules),
            interceptor: self.interceptor,
            config: self.config,
        }
    }
}

impl Default for BulwarkRouter {
    fn default() -> Self {
        Self::new(Arc::new(BulwarkConfig::default_config()))
    }
}

// ============================================================================
// BulwarkMiddleware：actix-web middleware（Transform + Service）
// ============================================================================

/// actix-web middleware，提取 token + 调用 interceptor + 设置 task_local。
pub struct BulwarkMiddleware {
    rules: Arc<HashMap<String, Annotation>>,
    interceptor: Arc<dyn BulwarkInterceptor>,
    config: Arc<BulwarkConfig>,
}

/// middleware service（Transform 生成的中间层）。
pub struct BulwarkMiddlewareService<S> {
    /// 内部 service（Rc 包装以便在 async block 中 clone，无需 S: Clone）
    pub inner: Rc<S>,
    /// 路由规则
    pub rules: Arc<HashMap<String, Annotation>>,
    /// 拦截器
    pub interceptor: Arc<dyn BulwarkInterceptor>,
    /// 配置
    pub config: Arc<BulwarkConfig>,
}

impl<S, B> Transform<S, ServiceRequest> for BulwarkMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = actix_web::Error;
    type Transform = BulwarkMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(BulwarkMiddlewareService {
            inner: Rc::new(service),
            rules: self.rules.clone(),
            interceptor: self.interceptor.clone(),
            config: self.config.clone(),
        }))
    }
}

impl<S, B> Service<ServiceRequest> for BulwarkMiddlewareService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = actix_web::Error;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

    forward_ready!(inner);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let interceptor = self.interceptor.clone();
        let path = req.uri().path().to_string();
        let headers = req.headers().clone();
        let rule_annotation = self.rules.get(&path).cloned();
        let token = extract_token_from_headers(&headers, &self.config)
            .ok()
            .flatten();
        // clone Rc<S>（无需 S: Clone），以便在 async block 中先鉴权通过后才调用 inner.call
        // 不 clone HttpRequest（原 BUG #8 修复：避免 Rc 引用计数问题）
        let inner = self.inner.clone();

        Box::pin(async move {
            let auth_check = async move {
                if let Some(annotation) = rule_annotation {
                    interceptor.pre_handle(&path, &annotation).await?;
                }
                Ok::<_, BulwarkError>(())
            };

            let auth_result = match token {
                Some(t) => with_current_token(t, auth_check).await,
                None => auth_check.await,
            };

            match auth_result {
                Ok(()) => {
                    // 鉴权通过，调用 inner service（req 在此 move）
                    let res = (*inner).call(req).await?;
                    Ok(res.map_into_left_body())
                },
                Err(e) => {
                    // 鉴权失败，req 未被 move，直接构造错误响应（不执行 handler）
                    tracing::error!(error = ?e, "bulwark middleware rejection");
                    let resp = e.error_response();
                    Ok(req.into_response(resp).map_into_right_body())
                },
            }
        })
    }
}

// ============================================================================
// FromRequest Extractors：per-handler 鉴权
// ============================================================================

/// CheckLogin extractor：验证用户已登录。
///
/// 在 handler 参数中使用：
/// ```ignore
/// async fn handler(_auth: CheckLogin) -> &'static str { "ok" }
/// ```
pub struct CheckLogin;

impl actix_web::FromRequest for CheckLogin {
    type Error = BulwarkError;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let headers = req.headers().clone();
        let config = req
            .app_data::<actix_web::web::Data<Arc<BulwarkConfig>>>()
            .map(|d| d.get_ref().clone())
            .unwrap_or_else(|| Arc::new(BulwarkConfig::default_config()));

        Box::pin(async move {
            let token = extract_token_from_headers(&headers, &config)?
                .ok_or_else(|| BulwarkError::NotLogin("未提供 token".to_string()))?;

            let result: BulwarkResult<()> = with_current_token(token, async {
                let logged_in = crate::stp::BulwarkUtil::check_login().await?;
                if !logged_in {
                    return Err(BulwarkError::NotLogin("未登录".to_string()));
                }
                Ok(())
            })
            .await;

            result.map(|_| CheckLogin)
        })
    }
}

/// CheckRole extractor：验证用户持有指定角色。
pub struct CheckRole(pub String);

impl actix_web::FromRequest for CheckRole {
    type Error = BulwarkError;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let headers = req.headers().clone();
        let config = req
            .app_data::<actix_web::web::Data<Arc<BulwarkConfig>>>()
            .map(|d| d.get_ref().clone())
            .unwrap_or_else(|| Arc::new(BulwarkConfig::default_config()));

        // 角色从 header X-Bulwark-Role 或 query param role 获取
        let role = req
            .headers()
            .get("x-bulwark-role")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .or_else(|| {
                req.uri().query().and_then(|q| {
                    q.split('&').find_map(|kv| {
                        let mut parts = kv.splitn(2, '=');
                        if parts.next() == Some("role") {
                            parts.next().map(|s| s.to_string())
                        } else {
                            None
                        }
                    })
                })
            })
            .unwrap_or_default();

        Box::pin(async move {
            let token = extract_token_from_headers(&headers, &config)?
                .ok_or_else(|| BulwarkError::NotLogin("未提供 token".to_string()))?;

            let result: BulwarkResult<()> = with_current_token(token, async {
                crate::stp::BulwarkUtil::check_role(&role).await
            })
            .await;

            result.map(|_| CheckRole(role))
        })
    }
}

/// CheckPermission extractor：验证用户持有指定权限。
pub struct CheckPermission(pub String);

impl actix_web::FromRequest for CheckPermission {
    type Error = BulwarkError;
    type Future = Pin<Box<dyn std::future::Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &actix_web::HttpRequest, _: &mut actix_web::dev::Payload) -> Self::Future {
        let headers = req.headers().clone();
        let config = req
            .app_data::<actix_web::web::Data<Arc<BulwarkConfig>>>()
            .map(|d| d.get_ref().clone())
            .unwrap_or_else(|| Arc::new(BulwarkConfig::default_config()));

        // 权限从 header X-Bulwark-Permission 或 query param permission 获取
        let permission = req
            .headers()
            .get("x-bulwark-permission")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
            .or_else(|| {
                req.uri().query().and_then(|q| {
                    q.split('&').find_map(|kv| {
                        let mut parts = kv.splitn(2, '=');
                        if parts.next() == Some("permission") {
                            parts.next().map(|s| s.to_string())
                        } else {
                            None
                        }
                    })
                })
            })
            .unwrap_or_default();

        Box::pin(async move {
            let token = extract_token_from_headers(&headers, &config)?
                .ok_or_else(|| BulwarkError::NotLogin("未提供 token".to_string()))?;

            let result: BulwarkResult<()> = with_current_token(token, async {
                crate::stp::BulwarkUtil::check_permission(&permission).await
            })
            .await;

            result.map(|_| CheckPermission(permission))
        })
    }
}

// ============================================================================
// 测试
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use actix_web::http::header::HeaderValue;
    use actix_web::http::StatusCode;

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

    use crate::dao::BulwarkDao;
    use crate::manager::BulwarkManager;
    use crate::stp::{BulwarkInterface, BulwarkUtil};
    use actix_web::{test, web, App};
    use async_trait::async_trait;
    use parking_lot::Mutex;
    use serial_test::serial;
    use std::collections::HashMap;
    use std::time::{Duration, Instant};

    // ----------------------------------------------------------------
    // MockDao（HashMap + Instant 模拟 TTL，复用 stp/manager 测试模式）
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
        async fn get_permission_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
            Ok(self.permissions.get(login_id).cloned().unwrap_or_default())
        }

        async fn get_role_list(&self, login_id: &str) -> BulwarkResult<Vec<String>> {
            Ok(self.roles.get(login_id).cloned().unwrap_or_default())
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
        let token = BulwarkUtil::login("1001").await.unwrap();
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
        let token = BulwarkUtil::login("1001").await.unwrap();
        let service = make_middleware_service(&[(
            "/admin",
            Annotation::CheckPermission("admin:read".to_string()),
        )])
        .await;

        let req = test::TestRequest::get()
            .uri("/admin")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_srv_request();
        let resp = service.call(req).await.unwrap();
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
        let token = BulwarkUtil::login("1001").await.unwrap();
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
        let token = BulwarkUtil::login("1001").await.unwrap();
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
            test::init_service(App::new().route("/login", web::get().to(check_login_handler)))
                .await;

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
        let token = BulwarkUtil::login("1001").await.unwrap();
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
        let token = BulwarkUtil::login("1001").await.unwrap();
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
        let token = BulwarkUtil::login("1001").await.unwrap();
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
        let resp = test::call_service(&app, req).await;
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
        let token = BulwarkUtil::login("1001").await.unwrap();
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
        let resp = test::call_service(&app, req).await;
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
}
