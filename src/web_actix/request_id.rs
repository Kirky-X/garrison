// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! X-Request-ID 中间件（actix-web）：提取 / 生成 / 回传请求标识。
//!
//! Transform / Service 结构与 [`super::GarrisonMiddleware`] 一致：
//! 请求入口提取（合法原样传播，非法丢弃重新生成 UUID v4）→
//! `req.extensions_mut()` 注入 [`RequestId`] → 内层 service future 包在
//! request id task-local scope → `ServiceResponse` 回填 `X-Request-ID`
//! 响应头，并以 tracing span（`request_id` 字段）instrument。
//!
//! # 错误响应的渲染位置（三框架一致性约束）
//!
//! actix 框架在 dispatch 层（scope 外）渲染 `Err(actix_web::Error)`，若直接
//! 传播 Err，统一错误体的 `request_id` 字段将缺失。因此本 service 在 scope 内
//! 自行调用 `Error::error_response()` 渲染为 `Ok(ServiceResponse)`：
//! 错误体与 `X-Request-ID` 头在同一 scope 内产出，与 axum / warp 行为一致。
//!
//! 头名 `X-Request-ID` 为固定常量（[`REQUEST_ID_HEADER`]），非配置项。

use crate::context::request_id::{propagate_or_generate, scope, RequestId, REQUEST_ID_HEADER};
use actix_web::body::{BoxBody, EitherBody};
use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::HttpMessage;
use std::future::{ready, Ready};
use std::pin::Pin;
use std::rc::Rc;
use tracing::Instrument;

/// `x-request-id` 头名（小写静态形式）。
const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// request id 中间件装饰器（actix Transform，`wrap()` 挂载）。
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestIdMiddleware;

impl<S, B> Transform<S, ServiceRequest> for RequestIdMiddleware
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = actix_web::Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<EitherBody<B, BoxBody>>;
    type Error = actix_web::Error;
    type Transform = RequestIdService<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(RequestIdService {
            inner: Rc::new(service),
        }))
    }
}

/// request id 中间件 service（[`RequestIdMiddleware`] 的 Transform 产物）。
pub struct RequestIdService<S> {
    inner: Rc<S>,
}

impl<S, B> Service<ServiceRequest> for RequestIdService<S>
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
        let inbound = req
            .headers()
            .get(REQUEST_ID_HEADER)
            .and_then(|v| v.to_str().ok());
        let id = propagate_or_generate(inbound);
        req.extensions_mut().insert(RequestId(id.clone()));

        // Err 分支需在 scope 内渲染错误响应（见模块文档），req 将随 inner.call
        // 被 move，提前留存 HttpRequest 供 ServiceResponse 构造。actix-web 4 的
        // HttpRequest 是 Arc 包装的官方廉价 clone；历史 BUG #8（Rc 引用计数 panic）
        // 属 actix 3.x 的 match_info_mut 时代，4.12 不适用。
        let http_req = req.request().clone();

        let span = tracing::info_span!("request_id", request_id = %id);
        let fut = self.inner.call(req);
        Box::pin(
            scope(id.clone(), async move {
                match fut.await {
                    Ok(res) => {
                        let mut res = res.map_into_left_body();
                        // 结构化日志：请求完成事件携带 request_id（scope 内发出；
                        // debug 级避免与 server::audit_log_middleware 的每请求
                        // info 访问日志重复）
                        tracing::debug!(
                            request_id = %id,
                            status = res.status().as_u16(),
                            "request_id_middleware: request completed"
                        );
                        if let Ok(value) = HeaderValue::from_str(id.as_ref()) {
                            res.headers_mut().insert(X_REQUEST_ID, value);
                        }
                        Ok(res)
                    },
                    Err(err) => {
                        // scope 内渲染统一错误响应：error_response() 经
                        // GarrisonError 的 ResponseError impl 读取 task-local，
                        // 错误体携带 request_id 字段，与 axum / warp 输出一致；
                        // 错误日志由 error_response() 侧统一发出，此处不重复
                        let mut res = ServiceResponse::new(http_req, err.error_response())
                            .map_into_right_body();
                        if let Ok(value) = HeaderValue::from_str(id.as_ref()) {
                            res.headers_mut().insert(X_REQUEST_ID, value);
                        }
                        Ok(res)
                    },
                }
            })
            .instrument(span),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GarrisonError;
    use actix_web::http::StatusCode;
    use actix_web::test::{self, TestRequest};
    use actix_web::HttpResponse;
    use serial_test::serial;
    use std::task::{Context, Poll};
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    /// 内层 service 桩：回显 extensions 中的 RequestId（200），或按 mode 返回错误。
    struct EchoService {
        fail: bool,
    }

    impl EchoService {
        fn ok() -> Self {
            Self { fail: false }
        }
        fn failing() -> Self {
            Self { fail: true }
        }
    }

    impl Service<ServiceRequest> for EchoService {
        type Response = ServiceResponse<BoxBody>;
        type Error = actix_web::Error;
        type Future =
            Pin<Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>>>>;

        fn poll_ready(&self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn call(&self, req: ServiceRequest) -> Self::Future {
            if self.fail {
                let (http_req, _payload) = req.into_parts();
                let err = GarrisonError::NotLogin("web-not-login::".to_string());
                // 错误响应在 EchoService 内（即 request id scope 内）渲染，
                // 与真实链路中 ResponseError 由 scope 内渲染的行为对齐
                return Box::pin(async move {
                    use actix_web::ResponseError;
                    Ok(ServiceResponse::new(http_req, err.error_response()))
                });
            }
            let req_id = req
                .extensions()
                .get::<RequestId>()
                .map(|r| r.0.to_string())
                .unwrap_or_default();
            let (http_req, _payload) = req.into_parts();
            let res = HttpResponse::Ok().body(req_id);
            Box::pin(async move { Ok(ServiceResponse::new(http_req, res)) })
        }
    }

    async fn run_call(
        fail: bool,
        header: Option<(&str, &str)>,
    ) -> ServiceResponse<EitherBody<BoxBody, BoxBody>> {
        let mut builder = TestRequest::get().uri("/ping");
        if let Some((name, value)) = header {
            builder = builder.insert_header((name, value));
        }
        let req = builder.to_srv_request();
        let middleware = RequestIdMiddleware;
        let service = middleware
            .new_transform(if fail {
                EchoService::failing()
            } else {
                EchoService::ok()
            })
            .await
            .expect("transform 初始化应成功");
        service
            .call(req)
            .await
            .expect("request_id service 不应向外传播 Err")
    }

    /// 入站合法 id 原样回传，且内层经 extensions 取到同值。
    #[tokio::test]
    async fn valid_inbound_id_echoed_and_injected() {
        let res = run_call(false, Some(("X-Request-ID", "actix-corr-001"))).await;
        assert_eq!(res.status(), StatusCode::OK);
        let header = res
            .headers()
            .get(X_REQUEST_ID.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(header, "actix-corr-001");
        let body = test::read_body(res).await;
        assert_eq!(String::from_utf8_lossy(&body), "actix-corr-001");
    }

    /// 超长入站值（> 128 字节，http 层可构造的唯一非法类）重新生成合法 UUID。
    /// CRLF / 非 ASCII 的注入防护由 http 框架头解析与
    /// `context::request_id::propagate_or_generate` 纯函数测试覆盖。
    #[tokio::test]
    async fn invalid_inbound_id_regenerated() {
        for bad in ["a".repeat(129), format!("{}tail", "b".repeat(200))] {
            let res = run_call(false, Some(("X-Request-ID", bad.as_str()))).await;
            let value = res
                .headers()
                .get(X_REQUEST_ID.as_str())
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default()
                .to_string();
            assert_ne!(value, bad, "非法入站 id 不应被回传");
            assert!(
                uuid::Uuid::parse_str(&value).is_ok(),
                "重新生成的 id 应为合法 UUID: {value}"
            );
        }
    }

    /// 无头时生成 UUID v4。
    #[tokio::test]
    async fn missing_header_generates_uuid_v4() {
        let res = run_call(false, None).await;
        let value = res
            .headers()
            .get(X_REQUEST_ID.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let parsed = uuid::Uuid::parse_str(&value).expect("无头时应生成合法 UUID");
        assert_eq!(parsed.get_version_num(), 4);
    }

    /// 错误响应在 scope 内渲染：X-Request-ID 头与 body.request_id 一致，
    /// 状态码与统一体字段（error_code / error_id / code）正确。
    #[tokio::test]
    async fn error_response_header_matches_body_request_id() {
        let res = run_call(true, Some(("X-Request-ID", "actix-err-corr-001"))).await;
        assert_eq!(res.status(), StatusCode::UNAUTHORIZED);
        let header = res
            .headers()
            .get(X_REQUEST_ID.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(header, "actix-err-corr-001");
        let body_json: serde_json::Value =
            serde_json::from_slice(&test::read_body(res).await).unwrap();
        assert_eq!(body_json["request_id"], "actix-err-corr-001");
        assert_eq!(body_json["error_code"], "NOT_LOGIN");
        assert_eq!(body_json["error_id"], "auth.not_login");
    }

    /// 进程内 tracing 捕获层：记录 (级别, 事件字段渲染)。
    struct CollectLayer(std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>);

    impl<S> tracing_subscriber::layer::Layer<S> for CollectLayer
    where
        S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    {
        fn on_event(
            &self,
            event: &tracing::Event<'_>,
            _ctx: tracing_subscriber::layer::Context<'_, S>,
        ) {
            let level = event.metadata().level().to_string();
            let mut rendered = String::new();
            event.record(
                &mut |field: &tracing::field::Field, value: &dyn std::fmt::Debug| {
                    rendered.push_str(&format!("{}={:?} ", field.name(), value));
                },
            );
            self.0
                .lock()
                .expect("日志缓冲锁应可用")
                .push((level, rendered));
        }
    }

    /// 初始化线程局部捕获订阅者并重建 callsite interest 缓存。
    ///
    /// tracing 的 interest 缓存是进程级全局态：并行运行的非订阅者测试可能抢先
    /// 首次注册事件 callsite 并缓存 `Interest::never`（事件被宏直接剔除，与本
    /// 线程订阅者无关），故 set_default 后必须显式重建，捕获缺失时重试。
    fn init_capture(
        logs: &std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>>,
    ) -> tracing::subscriber::DefaultGuard {
        let guard = tracing_subscriber::registry()
            .with(CollectLayer(logs.clone()))
            .set_default();
        tracing::callsite::rebuild_interest_cache();
        guard
    }

    /// tracing 捕获断言：完成事件为 debug 级（避免与 audit_log_middleware 的
    /// info 访问日志重复）且携带 request_id 字段。
    #[tokio::test]
    #[serial]
    async fn tracing_event_carries_request_id_field() {
        let logs: std::sync::Arc<std::sync::Mutex<Vec<(String, String)>>> =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let _guard = init_capture(&logs);

        let mut lines: Vec<(String, String)> = Vec::new();
        for _ in 0..3 {
            let _ = run_call(false, Some(("X-Request-ID", "actix-span-id"))).await;
            lines = logs.lock().expect("日志缓冲锁应可用").clone();
            if lines
                .iter()
                .any(|(level, msg)| level == "DEBUG" && msg.contains("actix-span-id"))
            {
                break;
            }
            tracing::callsite::rebuild_interest_cache();
        }
        assert!(
            lines
                .iter()
                .any(|(level, msg)| level == "DEBUG" && msg.contains("actix-span-id")),
            "完成事件应为 debug 级且携带 request_id 字段值 actix-span-id，实际: {lines:?}"
        );
    }
}
