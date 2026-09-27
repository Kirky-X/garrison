// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! actix-web 错误适配实现。
//!
//! 包含两类 impl：
//! - `HeaderLookup for actix_web::http::header::HeaderMap`：桥接 actix HeaderMap 与
//!   `extract_token_from_headers`，使 token 提取逻辑可同时接受 `http::HeaderMap`
//!   和 `actix_web::http::header::HeaderMap` 两种类型。
//! - `ResponseError for GarrisonError`：将 GarrisonError 映射为 actix-web HttpResponse，
//!   复用 `response_parts()` 保证与 axum/warp 三框架响应一致。

use crate::context::token_extract::HeaderLookup;
use crate::error::GarrisonError;
use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};

/// `x-request-id` 头名（小写静态形式）。
const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// `retry-after` 头名（小写静态形式）。
const RETRY_AFTER: HeaderName = HeaderName::from_static("retry-after");

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

/// 实现 actix-web `ResponseError` trait，复用 `response_parts_i18n()` 保证三框架一致。
///
/// 状态码与错误码映射与 axum `IntoResponse` 完全一致。
impl ResponseError for GarrisonError {
    fn status_code(&self) -> StatusCode {
        let (s, _, _, _) = self.response_parts();
        StatusCode::from_u16(s).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    fn error_response(&self) -> HttpResponse {
        // 完整错误记录到日志（不返回给客户端）；限流拒绝降级 warn（日志洪水防护）
        self.log_rejection();
        // 统一体单一事实来源：error_code + error_id + message（+ code / request_id，
        // request_id 在 request id task-local scope 内渲染时携带，无则省略）
        let body = self.to_json_body();
        let status = self.status_code();
        let mut builder = HttpResponse::build(status);
        if let Some(id) = crate::context::request_id::current() {
            if let Ok(value) = HeaderValue::from_str(id.as_ref()) {
                builder.insert_header((X_REQUEST_ID, value));
            }
        }
        if let Some(secs) = self.retry_after_secs() {
            builder.insert_header((RETRY_AFTER, HeaderValue::from(secs)));
        }
        builder.json(body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::GarrisonError;

    /// RateLimited → 429 + Retry-After 头等于秒数（对齐 axum IntoResponse 行为）。
    #[test]
    fn rate_limited_error_response_sets_retry_after_header() {
        let resp = GarrisonError::RateLimited {
            retry_after_secs: 30,
        }
        .error_response();
        assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(
            resp.headers()
                .get(RETRY_AFTER.as_str())
                .and_then(|v| v.to_str().ok()),
            Some("30"),
            "Retry-After 头必须等于秒数"
        );
    }

    /// 非限流变体不携带 Retry-After 头。
    #[test]
    fn non_rate_limited_error_response_has_no_retry_after_header() {
        let resp = GarrisonError::NotLogin("x".to_string()).error_response();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        assert!(resp.headers().get(RETRY_AFTER.as_str()).is_none());
    }

    /// request id scope 内渲染：X-Request-ID 头与 Retry-After 同时输出。
    #[tokio::test]
    async fn rate_limited_error_response_sets_x_request_id_within_scope() {
        let resp =
            crate::context::request_id::scope(std::sync::Arc::from("actix-rl-req-id"), async {
                GarrisonError::RateLimited {
                    retry_after_secs: 30,
                }
                .error_response()
            })
            .await;
        assert_eq!(
            resp.headers()
                .get(X_REQUEST_ID.as_str())
                .and_then(|v| v.to_str().ok()),
            Some("actix-rl-req-id"),
            "scope 内必须回传 X-Request-ID 头"
        );
        assert_eq!(
            resp.headers()
                .get(RETRY_AFTER.as_str())
                .and_then(|v| v.to_str().ok()),
            Some("30")
        );
    }
}
