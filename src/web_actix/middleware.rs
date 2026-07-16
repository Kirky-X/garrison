//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! actix-web middleware 实现：Transform + Service trait 实现。
//!
//! `BulwarkMiddleware` 作为 actix-web middleware 装饰器，在请求到达 handler 前
//! 执行鉴权（pre_handle），失败则直接构造错误响应。struct 声明位于 `mod.rs`。
//!
//! ## 历史 BUG #8（已修复）
//!
//! 原实现在 `self.inner.call(req)` 之前执行 `req.request().clone()`，导致 `Rc`
//! 引用计数为 2，路由层 `match_info_mut()` 触发 panic。修复方案：先鉴权通过后
//! 才 `inner.call(req)`，失败则 `req.into_response(resp)`（无需 clone HttpRequest）。

use crate::context::token_extract::extract_token_from_headers;
use crate::error::BulwarkError;
use crate::stp::with_current_token;
use actix_web::body::{BoxBody, EitherBody};
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::ResponseError;
use std::future::{ready, Ready};
use std::pin::Pin;
use std::rc::Rc;

use super::{BulwarkMiddleware, BulwarkMiddlewareService};

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
