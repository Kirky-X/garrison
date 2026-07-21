//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `GarrisonRouter`：axum Web 框架适配的路由器，包装 `axum::Router` 并管理鉴权路由规则。
//!
//! 通过 `route_protected` 注册路由 + 注解，`build` 时应用 `garrison_middleware`：
//! 提取 token → `with_current_token` 设置 task_local → 调用 `interceptor.pre_handle`
//! → 执行 handler。

use super::{DefaultGarrisonInterceptor, GarrisonInterceptor};
use crate::annotation::Annotation;
use crate::config::GarrisonConfig;
use crate::context::axum_adapter::AxumRequest;
#[cfg(feature = "tenant-isolation")]
use crate::context::tenant::TenantResolver;
use crate::context::GarrisonRequest;
use crate::error::GarrisonError;
use crate::stp::context::{clear_renewed_token, get_renewed_token, with_renewed_token_scope};
use crate::stp::with_current_token;
use axum::body::Body;
use axum::extract::State;
use axum::handler::Handler;
use axum::http::header::SET_COOKIE;
#[cfg(feature = "tenant-isolation")]
use axum::http::StatusCode;
use axum::http::{HeaderName, HeaderValue, Request};
use axum::middleware::{from_fn_with_state, Next};
use axum::response::{IntoResponse, Response};
use axum::Router;
use std::sync::Arc;

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
    interceptor: Arc<dyn GarrisonInterceptor>,
    config: Arc<GarrisonConfig>,
}

/// 路由器，包装 `axum::Router` 并管理鉴权路由规则。
///
/// 对应 路由拦截器配置。
///
/// # 使用
///
/// ```ignore
/// use garrison::prelude::*;
/// use garrison::annotation::Annotation;
/// use std::sync::Arc;
///
/// let router = GarrisonRouter::new(Arc::new(GarrisonConfig::default_config()))
///     .route_protected("/api/user", || async { "user ok" }, Annotation::CheckLogin)
///     .route_protected(
///         "/api/admin",
///         || async { "admin ok" },
///         Annotation::CheckRole("admin".to_string()),
///     )
///     .build();
/// ```
pub struct GarrisonRouter {
    inner: Router,
    rules: Vec<RouteRule>,
    interceptor: Arc<dyn GarrisonInterceptor>,
    config: Arc<GarrisonConfig>,
}

impl GarrisonRouter {
    /// 创建新的路由器实例，使用 `DefaultGarrisonInterceptor`。
    ///
    /// # 参数
    /// - `config`: 全局配置（用于 middleware 提取 token）。
    pub fn new(config: Arc<GarrisonConfig>) -> Self {
        Self {
            inner: Router::new(),
            rules: Vec::new(),
            interceptor: Arc::new(DefaultGarrisonInterceptor),
            config,
        }
    }

    /// 设置自定义拦截器。
    pub fn with_interceptor<I: GarrisonInterceptor + 'static>(mut self, interceptor: I) -> Self {
        self.interceptor = Arc::new(interceptor);
        self
    }

    /// 添加受保护路由：注册 axum 路由（GET）+ 记录鉴权规则。
    ///
    /// # 参数
    /// - `path`: 请求路径模式（精确匹配）。
    /// - `handler`: axum handler（GET 方法）。
    /// - `annotation`: 鉴权注解。
    pub fn route_protected<H, T>(mut self, path: &str, handler: H, annotation: Annotation) -> Self
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

    /// 路由分组：通过闭包注册一组带公共前缀和公共注解的路由。
    ///
    /// # 参数
    /// - `prefix`: 路由前缀（如 `/api/v1`），必须非空，以 `/` 开头。
    ///   尾部 `/` 自动 trim（`/api/v1/` → `/api/v1`）。
    /// - `annotation`: 组级公共注解。`Annotation::Ignore` 时组内所有路由跳过注解校验。
    /// - `f`: 闭包，接收子 `GarrisonRouter`，返回注册完路由后的 `GarrisonRouter`。
    ///
    /// # Panics
    /// `prefix` 为空字符串时 panic。
    ///
    /// # 示例
    /// ```ignore
    /// router.group("/api/v1", Annotation::CheckLogin, |r| {
    ///     r.route_protected("/users", || async { "users" }, Annotation::CheckLogin)
    /// })
    /// ```
    pub fn group<F>(self, prefix: &str, annotation: Annotation, f: F) -> Self
    where
        F: FnOnce(GarrisonRouter) -> GarrisonRouter,
    {
        assert!(!prefix.is_empty(), "prefix must not be empty");

        // R-router-group-002: 尾部 / 自动 trim
        let trimmed = prefix.trim_end_matches('/');

        // 创建子 router，继承父 router 的 interceptor 和 config
        let child = GarrisonRouter {
            inner: Router::new(),
            rules: Vec::new(),
            interceptor: self.interceptor.clone(),
            config: self.config.clone(),
        };

        // 执行闭包，在子 router 上注册路由
        let child = f(child);

        // R-router-group-004: 合并子 router 的 rules 到父 router（附加前缀 + 注解处理）
        let mut parent = self;
        for rule in child.rules {
            let merged_path = format!("{}{}", trimmed, rule.path);
            // R-router-group-003: group 注解为 Ignore 时覆盖路由注解；否则保留路由自身注解
            let merged_annotation = if annotation == Annotation::Ignore {
                Annotation::Ignore
            } else {
                rule.annotation
            };
            parent.rules.push(RouteRule {
                path: merged_path,
                annotation: merged_annotation,
            });
        }

        // 合并子 router 的 axum Router 到父 router
        if trimmed.is_empty() {
            // 根前缀 "/"，直接 merge 不嵌套
            parent.inner = parent.inner.merge(child.inner);
        } else {
            parent.inner = parent.inner.nest(trimmed, child.inner);
        }

        parent
    }

    /// 构建最终的 axum Router，应用 GarrisonLayer middleware。
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
            .layer(from_fn_with_state(state, garrison_middleware))
    }
}

/// 实现 `Default`：使用 `GarrisonConfig::default_config()` 创建路由器，拦截器为 `DefaultGarrisonInterceptor`。
impl Default for GarrisonRouter {
    fn default() -> Self {
        Self::new(Arc::new(GarrisonConfig::default_config()))
    }
}

/// Garrison middleware：提取 token → 设置 task_local → 调用 interceptor.pre_handle → 执行 handler。
///
/// 对未匹配任何规则的路径，跳过 `pre_handle` 直接放行（仍设置 task_local 以便 handler 调用 GarrisonUtil）。
///
/// 请求结束后，若 `CURRENT_RENEWED_TOKEN` 有值（check_login 自动续签触发），
/// 根据 `is_write_header` / `is_write_cookie` 配置将续签 Token 写入响应。
async fn garrison_middleware(
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
        Ok::<_, GarrisonError>(next.run(req).await)
    };

    let config = state.config.clone();

    with_renewed_token_scope(async {
        let result = match token {
            Some(t) => with_current_token(t, handle).await,
            None => handle.await,
        };

        let mut resp = match result {
            Ok(resp) => resp,
            Err(e) => e.into_response(),
        };

        // 检查是否有续签 Token，写入响应
        if let Some(renewed_token) = get_renewed_token() {
            if config.is_write_header {
                if let Ok(name) = HeaderName::from_bytes(config.token_name.as_bytes()) {
                    if let Ok(value) = HeaderValue::from_str(&renewed_token) {
                        resp.headers_mut().insert(name, value);
                    }
                }
            }
            if config.is_write_cookie {
                let secure_flag = if config.cookie_secure { "; Secure" } else { "" };
                let cookie = format!(
                    "{}={}; HttpOnly; Path=/; SameSite={}{}",
                    config.token_name, renewed_token, config.cookie_same_site, secure_flag
                );
                if let Ok(value) = HeaderValue::from_str(&cookie) {
                    resp.headers_mut().append(SET_COOKIE, value);
                }
            }
            clear_renewed_token();
        }

        resp
    })
    .await
}

// ----------------------------------------------------------------
// tenant_resolution_middleware
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
/// use garrison::context::tenant::{HeaderTenantResolver, TenantResolver};
/// use std::sync::Arc;
/// use axum::Router;
///
/// let resolver: Arc<dyn TenantResolver> = Arc::new(HeaderTenantResolver);
/// let app = Router::new()
///     .route("/api", axum::routing::get(handler))
///     .layer(axum::middleware::from_fn_with_state(
///         resolver,
///         garrison::router::tenant_resolution_middleware,
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
