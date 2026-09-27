// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! X-Request-ID 中间件（axum）：提取 / 生成 / 回传请求标识。
//!
//! 处理顺序（与 [`crate::stp`] 的 token task-local 同层机制）：
//!
//! 1. 从请求头提取入站 `X-Request-ID`，经 [`propagate_or_generate`] 校验
//!    （合法原样传播，非法丢弃重新生成 UUID v4——入站 id 是不可信输入）；
//! 2. 将 [`RequestId`] 注入 `request.extensions()`（handler 经
//!    `Extension<RequestId>` 读取），并在
//!    [`scope`] 内执行内层服务——统一错误响应体（`request_id` 字段）与
//!    `X-Request-ID` 响应头均从该 task-local 读取，保证 body 与 header 一致；
//! 3. 以 `tracing` span（`request_id` 字段）instrument 内层 future，日志可关联；
//! 4. 响应设置 `X-Request-ID` 头回传调用方。
//!
//! # 挂载
//!
//! ```ignore
//! let app = Router::new()
//!     .route("/api", get(handler))
//!     .layer(axum::middleware::from_fn(garrison::web::request_id::request_id_middleware));
//! ```
//!
//! 头名 `X-Request-ID` 为固定常量（[`REQUEST_ID_HEADER`]），非配置项。

use crate::context::request_id::{propagate_or_generate, scope, RequestId, REQUEST_ID_HEADER};
use axum::extract::Request;
use axum::http::header::HeaderName;
use axum::http::HeaderValue;
use axum::middleware::Next;
use axum::response::Response;
use tracing::Instrument;

/// `x-request-id` 头名（小写静态形式，const 构造零运行时开销）。
const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// request id 中间件 — 提取 / 生成 `X-Request-ID` 并在 task-local scope 内执行内层服务。
///
/// 成功与错误响应均回传 `X-Request-ID` 响应头；错误响应体经
/// [`crate::error::GarrisonError::to_json_body`] 携带 `request_id` 字段。
pub async fn request_id_middleware(mut req: Request, next: Next) -> Response {
    let inbound = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok());
    let id = propagate_or_generate(inbound);
    req.extensions_mut().insert(RequestId(id.clone()));

    let span = tracing::info_span!("request_id", request_id = %id);
    let block_id = id.clone();
    let mut response = scope(id.clone(), async move {
        let response = next.run(req).await;
        // 结构化日志：请求完成事件携带 request_id（span 上下文内发出，与
        // actix / warp 路径一致；debug 级避免与 server::audit_log_middleware
        // 的每请求 info 访问日志重复）
        tracing::debug!(
            request_id = %block_id,
            status = response.status().as_u16(),
            "request_id_middleware: request completed"
        );
        response
    })
    .instrument(span)
    .await;

    if let Ok(value) = HeaderValue::from_str(id.as_ref()) {
        response.headers_mut().insert(X_REQUEST_ID, value);
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::request_id::current;
    use crate::error::GarrisonError;
    use axum::body::Body;
    use axum::http::{Request as HttpRequest, StatusCode};
    use axum::routing::get;
    use axum::{Extension, Router};
    use serial_test::serial;
    use tower::ServiceExt;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    /// 构建挂载 request_id 中间件的测试路由。
    ///
    /// `/ping` 返回自身经 Extension 读到的 request id；`/boom` 返回统一错误。
    fn test_router() -> Router {
        Router::new()
            .route(
                "/ping",
                get(|req_id: Extension<RequestId>| async move { req_id.0 .0.to_string() }),
            )
            .route(
                "/boom",
                get(|| async { GarrisonError::NotLogin("web-not-login::".to_string()) }),
            )
            .layer(axum::middleware::from_fn(request_id_middleware))
    }

    /// 入站合法 X-Request-ID 原样回传（成功响应也有头）。
    #[tokio::test]
    async fn valid_inbound_id_echoed_on_success_response() {
        let response = test_router()
            .oneshot(
                HttpRequest::builder()
                    .uri("/ping")
                    .header(REQUEST_ID_HEADER, "client-trace-001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        let value = response
            .headers()
            .get(X_REQUEST_ID.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(value, "client-trace-001");
        // handler 经 Extension 取到同一 id
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "client-trace-001");
    }

    /// 超长入站值（> 128 字节，http 层可构造的唯一非法类）被丢弃，重新生成合法 UUID 回传。
    /// CRLF / 非 ASCII 的注入防护由 http 框架头解析与
    /// `context::request_id::propagate_or_generate` 纯函数测试覆盖。
    #[tokio::test]
    async fn invalid_inbound_id_regenerated() {
        for bad in ["a".repeat(129), format!("{}tail", "b".repeat(200))] {
            let response = test_router()
                .oneshot(
                    HttpRequest::builder()
                        .uri("/ping")
                        .header(REQUEST_ID_HEADER, bad.as_str())
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            let value = response
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

    /// 无 X-Request-ID 头时生成 UUID v4。
    #[tokio::test]
    async fn missing_header_generates_uuid_v4() {
        let response = test_router()
            .oneshot(
                HttpRequest::builder()
                    .uri("/ping")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let value = response
            .headers()
            .get(X_REQUEST_ID.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let parsed = uuid::Uuid::parse_str(&value).expect("无头时应生成合法 UUID");
        assert_eq!(parsed.get_version_num(), 4);
    }

    /// 错误响应：X-Request-ID 头与 body.request_id 一致。
    #[tokio::test]
    async fn error_response_header_matches_body_request_id() {
        let response = test_router()
            .oneshot(
                HttpRequest::builder()
                    .uri("/boom")
                    .header(REQUEST_ID_HEADER, "err-corr-001")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        let header_value = response
            .headers()
            .get(X_REQUEST_ID.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert_eq!(header_value, "err-corr-001");
        let body_json: serde_json::Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert_eq!(body_json["request_id"], "err-corr-001");
        assert_eq!(body_json["error_id"], "auth.not_login");
        assert_eq!(body_json["error_code"], "NOT_LOGIN");
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
            let _ = test_router()
                .oneshot(
                    HttpRequest::builder()
                        .uri("/ping")
                        .header(REQUEST_ID_HEADER, "span-field-id")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap();
            lines = logs.lock().expect("日志缓冲锁应可用").clone();
            if lines
                .iter()
                .any(|(level, msg)| level == "DEBUG" && msg.contains("span-field-id"))
            {
                break;
            }
            tracing::callsite::rebuild_interest_cache();
        }
        assert!(
            lines
                .iter()
                .any(|(level, msg)| level == "DEBUG" && msg.contains("span-field-id")),
            "完成事件应为 debug 级且携带 request_id 字段值 span-field-id，实际: {lines:?}"
        );
    }

    /// scope 内 current() 与中间件注入的 Extension<RequestId> 同值（一致性）。
    #[tokio::test]
    async fn task_local_and_extension_agree() {
        let app = Router::new()
            .route(
                "/consistency",
                get(|req_id: Extension<RequestId>| async move {
                    let tl = current().map(|id| id.to_string()).unwrap_or_default();
                    (tl == req_id.0 .0.to_string()).to_string()
                }),
            )
            .layer(axum::middleware::from_fn(request_id_middleware));
        let response = app
            .oneshot(
                HttpRequest::builder()
                    .uri("/consistency")
                    .header(REQUEST_ID_HEADER, "agree-check")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        assert_eq!(std::str::from_utf8(&body).unwrap(), "true");
    }
}
