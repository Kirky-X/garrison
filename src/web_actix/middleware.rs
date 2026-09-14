//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! actix-web middleware 实现：Transform + Service trait 实现。
//!
//! `GarrisonMiddleware` 作为 actix-web middleware 装饰器，在请求到达 handler 前
//! 执行鉴权（pre_handle），失败则直接构造错误响应。struct 声明位于 `mod.rs`。
//!
//! ## 历史 BUG #8（已修复）
//!
//! 原实现在 `self.inner.call(req)` 之前执行 `req.request().clone()`，导致 `Rc`
//! 引用计数为 2，路由层 `match_info_mut()` 触发 panic。修复方案：先鉴权通过后
//! 才 `inner.call(req)`，失败则 `req.into_response(resp)`（无需 clone HttpRequest）。

use crate::context::tenant::TENANT;
use crate::context::token_extract::extract_token_from_headers;
use crate::error::GarrisonError;
use crate::stp::with_current_token;
use actix_web::body::{BoxBody, EitherBody};
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::ResponseError;
use std::future::{ready, Ready};
use std::pin::Pin;
use std::rc::Rc;

use super::{GarrisonMiddleware, GarrisonMiddlewareService};

/// 将 actix 的 `HeaderMap` 桥接为框架无关的 `http::HeaderMap`（`TenantResolver::resolve` 输入）。
///
/// 仅保留值可见 ASCII 的 header（`to_str()` 成功的项）；非法值跳过（不 panic）。
/// actix-web 4.x 使用 actix-http 的 `HeaderMap`（独立类型），`TenantResolver`
/// trait 统一接收 `http::HeaderMap`（v1），此处做一次值拷贝桥接。
fn actix_headers_to_http(headers: &actix_web::http::header::HeaderMap) -> http::HeaderMap {
    let mut out = http::HeaderMap::new();
    for (name, value) in headers.iter() {
        let Ok(value_str) = value.to_str() else {
            continue;
        };
        let Ok(name) = http::HeaderName::from_bytes(name.as_str().as_bytes()) else {
            continue;
        };
        if let Ok(value) = http::HeaderValue::from_str(value_str) {
            out.append(name, value);
        }
    }
    out
}

/// 尾斜杠归一化（根路径 `/` 除外）：`/api/users/` 与 `/api/users` 等价匹配。
fn normalize_route_path(path: &str) -> &str {
    if path.len() > 1 {
        path.trim_end_matches('/')
    } else {
        path
    }
}

/// 路由规则匹配：支持精确匹配、单段参数与尾部通配。
///
/// - 精确段：逐段相等比较（尾斜杠归一化后）
/// - `{param}` / `:param`：匹配任意非空单段（与 axum/actix 参数语义对齐）
/// - `*` / `{*rest}`：匹配剩余所有段（零段或多段，前缀保护语义）
///
/// 返回 true 表示 `pattern` 覆盖请求 `path`。
fn route_matches_rule(pattern: &str, path: &str) -> bool {
    let pattern = normalize_route_path(pattern);
    let path = normalize_route_path(path);
    let mut p = pattern.split('/');
    let mut s = path.split('/');
    loop {
        match (p.next(), s.next()) {
            (None, None) => return true,
            // 参数段缺失（pattern 段数多于 path）→ 不匹配
            (Some(seg), None) => return seg == "*" || seg == "{*wildcard}" || is_wild_brace(seg),
            (Some(seg), Some(part)) => {
                if seg == "*" || seg == "{*wildcard}" || is_wild_brace(seg) {
                    // 尾部通配：吞掉剩余所有段（含零段）
                    return true;
                }
                if is_param_segment(seg) {
                    // 单段参数：匹配任意非空段
                    if part.is_empty() {
                        return false;
                    }
                } else if seg != part {
                    return false;
                }
            },
            (None, Some(_)) => return false,
        }
    }
}

/// `{xxx}` 形式的单段参数（actix / axum0.8 风格）。
fn is_param_segment(seg: &str) -> bool {
    seg.starts_with(':') || (seg.starts_with('{') && seg.ends_with('}') && seg.len() > 2)
}

/// `{*xxx}` 形式的尾部通配段。
fn is_wild_brace(seg: &str) -> bool {
    seg.len() > 3 && seg.starts_with("{*") && seg.ends_with('}')
}

impl<S, B> Transform<S, ServiceRequest> for GarrisonMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = actix_web::Error;
    type Transform = GarrisonMiddlewareService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(GarrisonMiddlewareService {
            inner: Rc::new(service),
            rules: self.rules.clone(),
            interceptor: self.interceptor.clone(),
            config: self.config.clone(),
            tenant_resolver: self.tenant_resolver.clone(),
            handler_timeout: self.handler_timeout,
        }))
    }
}

impl<S, B> Service<ServiceRequest> for GarrisonMiddlewareService<S>
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
        // 规则匹配支持参数段（{id}/:id）与尾部通配（*/{*rest}），
        // 参数化路径不再因精确匹配失败而静默跳过鉴权；尾斜杠归一化对齐。
        let rule_annotation = self
            .rules
            .iter()
            .find(|(pattern, _)| route_matches_rule(pattern, &path))
            .map(|(_, annotation)| annotation.clone());
        let token = extract_token_from_headers(&headers, &self.config)
            .ok()
            .flatten();
        let tenant_resolver = self.tenant_resolver.clone();
        // clone Rc<S>（无需 S: Clone），以便在 async block 中先鉴权通过后才调用 inner.call
        // 不 clone HttpRequest（原 BUG #8 修复：避免 Rc 引用计数问题）
        let inner = self.inner.clone();
        let handler_timeout = self.handler_timeout;

        Box::pin(async move {
            let auth_check = async move {
                if let Some(annotation) = rule_annotation {
                    interceptor.pre_handle(&path, &annotation).await?;
                }
                Ok::<_, GarrisonError>(())
            };

            // 配置了 TenantResolver 时，先解析租户并进入 TENANT.scope 再执行鉴权，
            // 使 tenant-isolation 下 check_permission/check_role 获得租户上下文；
            // resolve 失败透传 GarrisonError（fail-closed，映射为错误响应）。
            // 未配置时保持旧行为（不提取租户）。
            let auth_result: Result<(), GarrisonError> = async {
                let tenant_ctx = match &tenant_resolver {
                    Some(resolver) => {
                        let http_headers = actix_headers_to_http(&headers);
                        Some(resolver.resolve(&http_headers).await?)
                    },
                    None => None,
                };
                match (tenant_ctx, token) {
                    (Some(ctx), Some(t)) => {
                        TENANT
                            .scope(ctx, async move { with_current_token(t, auth_check).await })
                            .await
                    },
                    (Some(ctx), None) => TENANT.scope(ctx, auth_check).await,
                    (None, Some(t)) => with_current_token(t, auth_check).await,
                    (None, None) => auth_check.await,
                }
            }
            .await;

            match auth_result {
                Ok(()) => {
                    // 鉴权通过，调用 inner service（req 在此 move）。
                    // 配置了 handler_timeout 时以 tokio::time::timeout 包裹
                    // 内层调用，超时返回 504，防止挂起 handler 无限占用连接；
                    // 未配置（默认）保持历史行为。
                    let result = match handler_timeout {
                        Some(timeout) => {
                            match tokio::time::timeout(timeout, (*inner).call(req)).await {
                                Ok(res) => res,
                                // 超时：req 已随 future 被 drop，此处以 Err 交给 actix
                                // 渲染 504 错误响应（ResponseError 机制）
                                Err(_elapsed) => {
                                    tracing::warn!(
                                        timeout_secs = timeout.as_secs_f64(),
                                        "garrison middleware: inner handler timed out"
                                    );
                                    return Err(actix_web::error::ErrorGatewayTimeout(
                                        "gateway timeout",
                                    ));
                                },
                            }
                        },
                        None => (*inner).call(req).await,
                    };
                    let res = result?;
                    Ok(res.map_into_left_body())
                },
                Err(e) => {
                    // 鉴权失败，req 未被 move，直接构造错误响应（不执行 handler）
                    tracing::error!(error = ?e, "garrison middleware rejection");
                    let resp = e.error_response();
                    Ok(req.into_response(resp).map_into_right_body())
                },
            }
        })
    }
}

#[cfg(test)]
mod route_match_tests {
    use super::*;

    /// 精确路径匹配（含尾斜杠归一化）。
    #[test]
    fn route_matches_rule_exact() {
        assert!(route_matches_rule("/api/users", "/api/users"));
        assert!(!route_matches_rule("/api/users", "/api/other"));
        // 尾斜杠归一化
        assert!(route_matches_rule("/api/users", "/api/users/"));
        assert!(route_matches_rule("/api/users/", "/api/users"));
    }

    /// 单段参数匹配：{id} / :id。
    #[test]
    fn route_matches_rule_param_segment() {
        assert!(route_matches_rule("/api/users/{id}", "/api/users/42"));
        assert!(route_matches_rule("/api/users/:id", "/api/users/42"));
        // 空段不匹配参数
        assert!(!route_matches_rule("/api/users/{id}", "/api/users/"));
        // 段数不一致不匹配
        assert!(!route_matches_rule(
            "/api/users/{id}",
            "/api/users/42/extra"
        ));
    }

    /// 尾部通配匹配：* / {*rest}（含零段）。
    #[test]
    fn route_matches_rule_wildcard_suffix() {
        assert!(route_matches_rule("/api/*", "/api"));
        assert!(route_matches_rule("/api/*", "/api/users/42"));
        assert!(route_matches_rule("/api/users/{*rest}", "/api/users/a/b"));
        assert!(!route_matches_rule("/api/users/{*rest}", "/api/others/x"));
    }

    /// 静态段与参数段混合。
    #[test]
    fn route_matches_rule_mixed() {
        assert!(route_matches_rule(
            "/api/{version}/users/:id",
            "/api/v1/users/42"
        ));
        assert!(!route_matches_rule(
            "/api/{version}/users/:id",
            "/api/v1/items/42"
        ));
    }
}
