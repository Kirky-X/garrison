// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! X-Request-ID 中间件（warp）：提取 / 生成 / 回传请求标识。
//!
//! # warp 机制差异（与 axum / actix 对比，详见 ADR-0004）
//!
//! warp 的 `wrap_fn` 只能组合 Filter，无法用自有 future 包住内层 filter 的
//! 执行——handler（错误体渲染）必然运行在 request id task-local scope 之外。
//! 因此 warp 路径采用后置回填：
//!
//! 1. `and_then` 内生成 / 校验 id，`scope` 包住**后置处理**；
//! 2. 后置处理设置 `X-Request-ID` 响应头；对 4xx/5xx 且 JSON 响应体，
//!    收集 bytes 解析为 JSON 后经 [`inject_request_id_into_error_body`]
//!    注入 `request_id` 字段再重组（axum / actix 为前置渲染直接读取，
//!    三框架终态输出形状一致）；
//! 3. 以 tracing span（`request_id` 字段）instrument。
//!
//! 成功响应与非 JSON 错误响应零缓冲透传（仅补 `X-Request-ID` 头）。
//!
//! # 用法
//!
//! ```ignore
//! let routes = routes.with(warp::wrap_fn(
//!     garrison::web_warp::request_id::with_request_id,
//! ));
//! ```
//!
//! 头名 `X-Request-ID` 为固定常量（[`REQUEST_ID_HEADER`]），非配置项。

use crate::context::request_id::{
    inject_request_id_into_error_body, propagate_or_generate, scope, REQUEST_ID_HEADER,
};
use http_body_util::BodyExt;
use std::sync::Arc;
use tracing::Instrument;
use warp::http::header::{HeaderName, HeaderValue, CONTENT_LENGTH, CONTENT_TYPE};
use warp::reply::{Reply as _, Response};
use warp::Filter;

/// `x-request-id` 头名（小写静态形式）。
const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// request id 包装 Filter：组合到任意 `Extract = (impl Reply,)` 的路由外层。
///
/// 经 `warp::wrap_fn(with_request_id)` 挂载（签名与 `wrap_fn` 的
/// `Fn(T) -> U` 约束兼容）。
pub fn with_request_id<T, R>(
    route: T,
) -> impl Filter<Extract = (Response,), Error = warp::Rejection> + Clone
where
    T: Filter<Extract = (R,), Error = warp::Rejection> + Clone + Send + Sync + 'static,
    R: warp::reply::Reply + Send + 'static,
{
    warp::any()
        .and(warp::header::optional::<String>(REQUEST_ID_HEADER))
        .and(route)
        .and_then(|inbound: Option<String>, reply: R| async move {
            let id = propagate_or_generate(inbound.as_deref());
            let span = tracing::info_span!("request_id", request_id = %id);
            let response = scope(id.clone(), async move {
                post_process(id, reply.into_response()).await
            })
            .instrument(span)
            .await;
            Ok::<_, warp::Rejection>(response)
        })
}

/// 后置处理：回传 `X-Request-ID` 头；错误 JSON 体在 scope 内回填 `request_id`。
async fn post_process(id: Arc<str>, mut response: Response) -> Response {
    if let Ok(value) = HeaderValue::from_str(id.as_ref()) {
        response.headers_mut().insert(X_REQUEST_ID, value);
    }
    // 结构化日志：请求完成事件携带 request_id（scope 内发出；debug 级避免与
    // server::audit_log_middleware 的每请求 info 访问日志重复）
    tracing::debug!(
        request_id = %id,
        status = response.status().as_u16(),
        "request_id_middleware: request completed"
    );

    let status = response.status();
    let is_error = status.is_client_error() || status.is_server_error();
    let is_json = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.starts_with("application/json"));
    if !(is_error && is_json) {
        return response;
    }

    let (mut parts, body) = response.into_parts();
    let bytes = match BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            // 失败显性化：原始 body 已消费不可恢复，仅替换 body 为统一错误体；
            // 原状态码与响应头（含 Retry-After / X-Request-ID）保留透传，不吞语义
            tracing::error!(error = %e, "warp request_id: error body collect failed");
            let fallback =
                crate::error::GarrisonError::Internal("warp-body-collect-failed::".to_string());
            let mut rebuilt =
                warp::reply::with_status(warp::reply::json(&fallback.to_json_body()), parts.status)
                    .into_response();
            parts.headers.remove(CONTENT_LENGTH);
            *rebuilt.headers_mut() = parts.headers;
            return rebuilt;
        },
    };

    // 防御护栏：超大错误体跳过回填、原样透传（与 axum IntoResponse 4KB 截断
    // 阈值一致；统一错误体本身远小于该阈值，超限只可能是业务自建体）
    if bytes.len() > MAX_INJECT_BODY_SIZE {
        return pass_through_original(parts, bytes.to_vec());
    }
    let mut json = match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(v) => v,
        Err(_) => {
            // 非 JSON body（防御路径）：原样透传，状态码与原始响应头保留
            return pass_through_original(parts, bytes.to_vec());
        },
    };
    inject_request_id_into_error_body(&mut json);

    parts.headers.remove(CONTENT_LENGTH);
    let mut rebuilt = warp::reply::with_status(warp::reply::json(&json), status).into_response();
    for (name, value) in parts.headers.iter() {
        if name != CONTENT_TYPE {
            rebuilt.headers_mut().append(name, value.clone());
        }
    }
    rebuilt
}

/// 统一体回填的 body 大小上限（与 axum IntoResponse 的 4KB 截断阈值一致）。
const MAX_INJECT_BODY_SIZE: usize = 4096;

/// 防御路径透传：body 未改动，状态码与原始响应头整体回填（单一 Content-Type
/// 无重复头，Retry-After / X-Request-ID 原值保留）。
fn pass_through_original(parts: warp::http::response::Parts, body: Vec<u8>) -> Response {
    let mut rebuilt = warp::reply::Reply::into_response(body);
    *rebuilt.status_mut() = parts.status;
    *rebuilt.headers_mut() = parts.headers;
    rebuilt
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GarrisonError;
    use serial_test::serial;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use warp::test::request;

    /// 统一错误 handler（Reply for GarrisonError 路径，与业务用法一致）。
    fn error_routes() -> impl Filter<Extract = (GarrisonError,), Error = warp::Rejection> + Clone {
        warp::path("boom").map(|| GarrisonError::NotLogin("web-not-login::".to_string()))
    }

    /// 限流错误 handler：RateLimited → 429 + Retry-After。
    fn rate_limited_routes(
    ) -> impl Filter<Extract = (GarrisonError,), Error = warp::Rejection> + Clone {
        warp::path("limited").map(|| GarrisonError::RateLimited {
            retry_after_secs: 30,
        })
    }

    /// 成功 handler：回显自身处理结果。
    fn ok_routes() -> impl Filter<Extract = (&'static str,), Error = warp::Rejection> + Clone {
        warp::path("ping").map(|| "pong")
    }

    /// 入站合法 id 原样回传（成功响应也有头）。
    #[tokio::test]
    async fn valid_inbound_id_echoed_on_success_response() {
        let routes = ok_routes().with(warp::wrap_fn(with_request_id));
        let res = request()
            .path("/ping")
            .header(REQUEST_ID_HEADER, "warp-corr-001")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 200);
        let value = res
            .headers()
            .get(X_REQUEST_ID.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(value, "warp-corr-001");
    }

    /// 超长入站值（> 128 字节，http 层可构造的唯一非法类）重新生成合法 UUID。
    /// CRLF / 非 ASCII 的注入防护由 http 框架头解析与
    /// `context::request_id::propagate_or_generate` 纯函数测试覆盖。
    #[tokio::test]
    async fn invalid_inbound_id_regenerated() {
        let routes = ok_routes().with(warp::wrap_fn(with_request_id));
        for bad in ["a".repeat(129), format!("{}tail", "b".repeat(200))] {
            let res = request()
                .path("/ping")
                .header(REQUEST_ID_HEADER, bad.as_str())
                .reply(&routes)
                .await;
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
        let routes = ok_routes().with(warp::wrap_fn(with_request_id));
        let res = request().path("/ping").reply(&routes).await;
        let value = res
            .headers()
            .get(X_REQUEST_ID.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let parsed = uuid::Uuid::parse_str(&value).expect("无头时应生成合法 UUID");
        assert_eq!(parsed.get_version_num(), 4);
    }

    /// 错误体后置回填：body.request_id == X-Request-ID 头（warp 后置回填机制）。
    #[tokio::test]
    async fn error_body_request_id_backfilled_matching_header() {
        let routes = error_routes().with(warp::wrap_fn(with_request_id));
        let res = request()
            .path("/boom")
            .header(REQUEST_ID_HEADER, "warp-err-corr-001")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 401);
        let header = res
            .headers()
            .get(X_REQUEST_ID.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(header, "warp-err-corr-001");
        let body_json: serde_json::Value = serde_json::from_slice(res.body()).unwrap();
        assert_eq!(body_json["request_id"], "warp-err-corr-001");
        assert_eq!(body_json["error_code"], "NOT_LOGIN");
        assert_eq!(body_json["error_id"], "auth.not_login");
    }

    /// 无头时错误体携带生成的 UUID request_id。
    #[tokio::test]
    async fn error_body_request_id_generated_when_missing() {
        let routes = error_routes().with(warp::wrap_fn(with_request_id));
        let res = request().path("/boom").reply(&routes).await;
        let header = res
            .headers()
            .get(X_REQUEST_ID.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        let body_json: serde_json::Value = serde_json::from_slice(res.body()).unwrap();
        assert_eq!(
            body_json["request_id"].as_str().unwrap(),
            header,
            "错误体 request_id 应与响应头一致"
        );
        assert!(uuid::Uuid::parse_str(&header).is_ok());
    }

    /// Retry-After 头（RateLimited → 30）在 warp 路径正确输出。
    #[tokio::test]
    async fn rate_limited_retry_after_header() {
        let routes = rate_limited_routes().with(warp::wrap_fn(with_request_id));
        let res = request().path("/limited").reply(&routes).await;
        assert_eq!(res.status(), 429);
        let value = res
            .headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(value, "30");
        let body_json: serde_json::Value = serde_json::from_slice(res.body()).unwrap();
        assert_eq!(body_json["error_id"], "ratelimit.rate_limited");
    }

    /// 非 JSON 错误响应不被回填（零缓冲透传，仅补头）。
    #[tokio::test]
    async fn non_json_error_response_not_backfilled() {
        let routes = warp::path("raw")
            .map(|| warp::http::StatusCode::FORBIDDEN)
            .with(warp::wrap_fn(with_request_id));
        let res = request()
            .path("/raw")
            .header(REQUEST_ID_HEADER, "warp-nonjson-001")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 403);
        let value = res
            .headers()
            .get(X_REQUEST_ID.as_str())
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default();
        assert_eq!(value, "warp-nonjson-001");
        // 非 JSON：无 request_id 字段可回填，body 保持空
        assert!(res.body().is_empty());
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

        let routes = ok_routes().with(warp::wrap_fn(with_request_id));
        let mut lines: Vec<(String, String)> = Vec::new();
        for _ in 0..3 {
            let _ = request()
                .path("/ping")
                .header(REQUEST_ID_HEADER, "warp-span-id")
                .reply(&routes)
                .await;
            lines = logs.lock().expect("日志缓冲锁应可用").clone();
            if lines
                .iter()
                .any(|(level, msg)| level == "DEBUG" && msg.contains("warp-span-id"))
            {
                break;
            }
            tracing::callsite::rebuild_interest_cache();
        }
        assert!(
            lines
                .iter()
                .any(|(level, msg)| level == "DEBUG" && msg.contains("warp-span-id")),
            "完成事件应为 debug 级且携带 request_id 字段值 warp-span-id，实际: {lines:?}"
        );
    }

    /// 自建 Reply：application/json 标签 + 任意 body（构造后置回填的防御路径）。
    struct JsonLabeledRaw(Vec<u8>);

    impl warp::reply::Reply for JsonLabeledRaw {
        fn into_response(self) -> Response {
            let mut res = warp::reply::Reply::into_response(self.0);
            res.headers_mut()
                .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
            *res.status_mut() = warp::http::StatusCode::FORBIDDEN;
            res
        }
    }

    /// 非 JSON body（防御路径）：原样透传——状态码、body 与单一 Content-Type 保持，
    /// 不得出现双 Content-Type，也不得注入 request_id。
    #[tokio::test]
    async fn non_json_body_with_json_label_passthrough_single_content_type() {
        let routes = warp::path("raw")
            .map(|| JsonLabeledRaw(b"not-json-body{".to_vec()))
            .with(warp::wrap_fn(with_request_id));
        let res = request()
            .path("/raw")
            .header(REQUEST_ID_HEADER, "warp-nonjson-002")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 403);
        assert_eq!(res.body().as_ref(), b"not-json-body{", "body 应原样透传");
        let content_types: Vec<_> = res
            .headers()
            .get_all(CONTENT_TYPE.as_str())
            .iter()
            .collect();
        assert_eq!(
            content_types.len(),
            1,
            "Content-Type 不得重复，实际: {content_types:?}"
        );
        assert!(res.headers().get(X_REQUEST_ID.as_str()).is_some());
        let body_str = String::from_utf8_lossy(res.body());
        assert!(
            !body_str.contains("request_id"),
            "透传体不得被注入 request_id 字段: {body_str}"
        );
    }

    /// 超大错误体（> 4KB，与 axum IntoResponse 截断阈值一致）跳过回填、原样透传。
    #[tokio::test]
    async fn oversized_error_body_skips_injection_and_passthrough() {
        let oversized = serde_json::json!({ "pad": "x".repeat(8 * 1024) }).to_string();
        let expected_len = oversized.len();
        let routes = warp::path("big")
            .map(move || JsonLabeledRaw(oversized.clone().into_bytes()))
            .with(warp::wrap_fn(with_request_id));
        let res = request()
            .path("/big")
            .header(REQUEST_ID_HEADER, "warp-oversize-001")
            .reply(&routes)
            .await;
        assert_eq!(res.status(), 403);
        assert_eq!(
            res.body().len(),
            expected_len,
            "超大 body 应原样透传（长度不变）"
        );
        let body_str = String::from_utf8_lossy(res.body());
        assert!(
            !body_str.contains("request_id"),
            "超大错误体不得被注入 request_id 字段"
        );
        assert!(res.headers().get(X_REQUEST_ID.as_str()).is_some());
        let content_types: Vec<_> = res
            .headers()
            .get_all(CONTENT_TYPE.as_str())
            .iter()
            .collect();
        assert_eq!(
            content_types.len(),
            1,
            "Content-Type 不得重复，实际: {content_types:?}"
        );
    }
}
