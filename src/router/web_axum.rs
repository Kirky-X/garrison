// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `GarrisonRouter`：axum Web 框架适配的路由器，包装 `axum::Router` 并管理鉴权路由规则
//! （`route_protected` 注册路由 + 注解，`build` 应用 `garrison_middleware`）。

use super::{DefaultGarrisonInterceptor, GarrisonInterceptor};
use crate::annotation::Annotation;
use crate::config::GarrisonConfig;
use crate::context::axum_adapter::AxumRequest;
#[cfg(feature = "tenant-isolation")]
use crate::context::tenant::TenantResolver;
use crate::context::GarrisonRequest;
use crate::context::{build_set_cookie_value, CookieType};
use crate::error::GarrisonError;
use crate::stp::context::{clear_renewed_token, get_renewed_token, with_renewed_token_scope};
use crate::stp::{with_current_token, with_login_id_scope};
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
/// # 使用
///
/// ```ignore
/// use garrison::prelude::*;
/// use garrison::annotation::Annotation;
/// use std::sync::Arc;
///
/// let router = GarrisonRouter::new(Arc::new(GarrisonConfig::default_config()))
/// .route_protected("/api/user", || async { "user ok" }, Annotation::CheckLogin)
/// .route_protected(
/// "/api/admin",
/// || async { "admin ok" },
/// Annotation::CheckRole("admin".to_string()),
/// )
/// .build();
/// ```
pub struct GarrisonRouter {
    inner: Router,
    rules: Vec<RouteRule>,
    interceptor: Arc<dyn GarrisonInterceptor>,
    config: Arc<GarrisonConfig>,
}

impl GarrisonRouter {
    /// 创建路由器（使用 `DefaultGarrisonInterceptor`）；`config` 供 middleware 提取 token。
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

    /// 添加受保护路由：注册 axum GET 路由 + 记录鉴权规则（路径匹配语义见 `route_matches`）。
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

    /// 路由分组：为子 router 注册一组带公共前缀与组级注解的路由。
    ///
    /// `prefix` 必须非空且以 `/` 开头，尾部 `/` 自动 trim（为空时 panic）；`annotation` 为 `Ignore`
    /// 时组内所有路由跳过注解校验。
    ///
    /// # 示例
    /// ```ignore
    /// router.group("/api/v1", Annotation::CheckLogin, |r| {
    /// r.route_protected("/users", || async { "users" }, Annotation::CheckLogin)
    /// })
    /// ```
    pub fn group<F>(self, prefix: &str, annotation: Annotation, f: F) -> Self
    where
        F: FnOnce(GarrisonRouter) -> GarrisonRouter,
    {
        assert!(!prefix.is_empty(), "prefix must not be empty");

        // 尾部 / 自动 trim
        let trimmed = prefix.trim_end_matches('/');

        let child = GarrisonRouter {
            inner: Router::new(),
            rules: Vec::new(),
            interceptor: self.interceptor.clone(),
            config: self.config.clone(),
        };

        let child = f(child);

        // 合并子 router 的 rules 到父 router（附加前缀 + 注解处理）
        let mut parent = self;
        for rule in child.rules {
            let merged_path = format!("{}{}", trimmed, rule.path);
            // group 注解为 Ignore 时覆盖路由注解；否则保留路由自身注解
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

    /// 构建最终 axum Router，应用 `garrison_middleware`（流程见该函数）。
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

/// 路由模式匹配（按 `/` 分段）：静态段精确相等，`:param`/`{param}` 匹配任意非空单段，
/// `{*wildcard}` 匹配剩余所有段（含零段，如 `/api/{*rest}` 覆盖 `/api` 与 `/api/a/b`）；未命中规则时
/// middleware 跳过 `pre_handle`（fail-closed 由注册侧保证：需保护的路径必须注册，通配段可显式声明前缀保护）。
fn route_matches(pattern: &str, path: &str) -> bool {
    let mut pi = pattern.split('/');
    let mut ri = path.split('/');
    loop {
        match (pi.next(), ri.next()) {
            (None, None) => return true,
            // pattern 段数多于 path：仅尾部通配可命中
            (Some(seg), None) => return is_wildcard_segment(seg),
            (Some(seg), Some(part)) => {
                if is_wildcard_segment(seg) {
                    return true;
                }
                if is_param_segment(seg) {
                    if part.is_empty() {
                        return false;
                    }
                } else if seg != part {
                    return false;
                }
            },
            // path 段数多于 pattern：不匹配（fail-closed）
            (None, Some(_)) => return false,
        }
    }
}

/// 参数段：`:xxx`（旧语法）或 `{xxx}`（axum 语法，空 `{}` 不算参数）。
fn is_param_segment(seg: &str) -> bool {
    seg.starts_with(':') || (seg.starts_with('{') && seg.ends_with('}') && seg.len() > 2)
}

/// 尾部通配段：`{*xxx}`（axum 语法，最短 `{*x}` 为 4 字节）。
fn is_wildcard_segment(seg: &str) -> bool {
    seg.len() > 3 && seg.starts_with("{*") && seg.ends_with('}')
}

/// 默认使用 `GarrisonConfig::default_config()` 与 `DefaultGarrisonInterceptor`。
impl Default for GarrisonRouter {
    fn default() -> Self {
        Self::new(Arc::new(GarrisonConfig::default_config()))
    }
}

/// Garrison middleware：提取 token → 设置 task_local → 调用 `interceptor.pre_handle` → 执行 handler。
///
/// 未匹配规则的路径跳过 `pre_handle` 直接放行（仍设置 task_local 供 handler 调用 `GarrisonUtil`）；
/// 请求结束后若有续签 Token，按 `is_write_header`/`is_write_cookie` 配置写入响应。
async fn garrison_middleware(
    State(state): State<MiddlewareState>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();
    let rule = state
        .rules
        .iter()
        .find(|r| route_matches(&r.path, &path))
        .cloned();

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
            // 登录身份缓存作用域覆盖 middleware 鉴权 + handler 处理期：
            // check_login 写入 (token, login_id) 后，handler 内 get_login_id 免 DAO 读取
            Some(t) => with_login_id_scope(with_current_token(t, handle)).await,
            None => handle.await,
        };

        let mut resp = match result {
            Ok(resp) => resp,
            Err(e) => e.into_response(),
        };

        // 有续签 Token 时按配置写入 header / cookie
        if let Some(renewed_token) = get_renewed_token() {
            if config.is_write_header {
                // header 构造失败记 debug 日志（排查续签 token 丢失的线索）
                match (
                    HeaderName::from_bytes(config.token_name.as_bytes()),
                    HeaderValue::from_str(&renewed_token),
                ) {
                    (Ok(name), Ok(value)) => {
                        resp.headers_mut().insert(name, value);
                    },
                    (Err(e), _) => {
                        tracing::debug!(
                            error = %e,
                            token_name = %config.token_name,
                            "{}",
                            crate::i18n::translate_detail(
                                "logs-renewed-token-header-name-invalid",
                                &[]
                            )
                        );
                    },
                    (_, Err(e)) => {
                        tracing::debug!(
                            error = %e,
                            "{}",
                            crate::i18n::translate_detail(
                                "logs-renewed-token-header-value-invalid",
                                &[]
                            )
                        );
                    },
                }
            }
            if config.is_write_cookie {
                // 单一构建点：注入校验（续签 token 含 `;` 等注入字符时拒绝写入）、same_site
                // 白名单 fail-fast 与 None→Lax 降级，失败显性 warn（静默丢 cookie = 用户掉线）。
                match CookieType::token(&config)
                    .and_then(|c| build_set_cookie_value(&c, &renewed_token, config.cookie_secure))
                {
                    Ok(cookie) => match HeaderValue::from_str(&cookie) {
                        Ok(value) => {
                            resp.headers_mut().append(SET_COOKIE, value);
                        },
                        Err(e) => {
                            tracing::warn!(
                                error = %e,
                                "{}",
                                crate::i18n::translate_detail(
                                    "logs-renewed-token-cookie-value-invalid",
                                    &[]
                                )
                            );
                        },
                    },
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "{}",
                            crate::i18n::translate_detail(
                                "logs-renewed-token-cookie-build-rejected",
                                &[]
                            )
                        );
                    },
                }
            }
            clear_renewed_token();
        }

        resp
    })
    .await
}

// tenant_resolution_middleware

/// 租户解析 middleware：从请求 headers 解析 `TenantContext`，在 `TENANT` task_local scope 内
/// 执行下游 handler；解析失败返回 `400 Bad Request`（不默认租户 0——静默回退默认租户会让
/// 跨租户数据泄露被掩盖）。
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
/// .route("/api", axum::routing::get(handler))
/// .layer(axum::middleware::from_fn_with_state(
/// resolver,
/// garrison::router::tenant_resolution_middleware,
/// ));
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

#[cfg(test)]
mod tests {
    use super::*;

    /// 精确路径匹配 — 静态路径应仅匹配完全相同的路径。
    #[test]
    fn route_matches_exact_static_path() {
        assert!(route_matches("/admin", "/admin"));
        assert!(!route_matches("/admin", "/other"));
    }

    /// 参数化路由 `:id` 应匹配任意非空段。
    #[test]
    fn route_matches_param_segment() {
        assert!(route_matches("/users/:id", "/users/123"));
        assert!(route_matches("/users/:id", "/users/abc"));
        assert!(!route_matches("/users/:id", "/users/")); // 空段不匹配
    }

    /// 参数化路由应匹配多段路径中的中间参数。
    #[test]
    fn route_matches_mixed_static_and_param() {
        assert!(route_matches("/api/:version/users/:id", "/api/v1/users/42"));
        assert!(!route_matches("/api/:version/users/:id", "/api/v1/users/"));
        assert!(!route_matches(
            "/api/:version/users/:id",
            "/api/v1/items/42"
        ));
    }

    /// 段数不匹配时应返回 false。
    #[test]
    fn route_matches_segment_count_mismatch() {
        assert!(!route_matches("/users/:id", "/users/123/extra"));
        assert!(!route_matches("/users/:id/extra", "/users/123"));
    }

    /// axum `{param}` 语法应与 `:param` 语义一致（匹配任意非空单段）。
    #[test]
    fn route_matches_axum_brace_param() {
        assert!(route_matches("/users/{id}", "/users/123"));
        assert!(!route_matches("/users/{id}", "/users/")); // 空段不匹配
        assert!(!route_matches("/users/{id}", "/users/123/extra"));
        // 混合新旧语法与静态段
        assert!(route_matches(
            "/api/{version}/users/:id",
            "/api/v1/users/42"
        ));
        assert!(!route_matches(
            "/api/{version}/users/:id",
            "/api/v1/items/42"
        ));
    }

    /// axum `{*wildcard}` 通配段匹配剩余所有段（含零段，前缀保护语义）。
    #[test]
    fn route_matches_axum_wildcard_suffix() {
        assert!(route_matches("/api/{*rest}", "/api"));
        assert!(route_matches("/api/{*rest}", "/api/users/42"));
        assert!(route_matches("/api/{*rest}", "/api/a/b/c"));
        assert!(!route_matches("/api/{*rest}", "/others/x"));
        // 静态前缀不一致不匹配
        assert!(!route_matches("/api/users/{*rest}", "/api/others/x"));
    }
}
