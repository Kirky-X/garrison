//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! actix-web 错误适配实现。
//!
//! 包含两类 impl：
//! - `HeaderLookup for actix_web::http::header::HeaderMap`：桥接 actix HeaderMap 与
//!   `extract_token_from_headers`，使 token 提取逻辑可同时接受 `http::HeaderMap`
//!   和 `actix_web::http::header::HeaderMap` 两种类型。
//! - `ResponseError for BulwarkError`：将 BulwarkError 映射为 actix-web HttpResponse，
//!   复用 `response_parts()` 保证与 axum/warp 三框架响应一致。

use crate::context::token_extract::HeaderLookup;
use crate::error::BulwarkError;
use actix_web::http::StatusCode;
use actix_web::{HttpResponse, ResponseError};

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
impl ResponseError for BulwarkError {
    fn status_code(&self) -> StatusCode {
        let (s, _, _, _) = self.response_parts();
        StatusCode::from_u16(s).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    fn error_response(&self) -> HttpResponse {
        tracing::error!(error = ?self, "bulwark rejection");
        // 单次调用 response_parts_i18n() 获取所有字段（M2：消除冗余调用）
        let (s, error_code, message, ex_code) = self.response_parts_i18n();
        let status = StatusCode::from_u16(s).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = if let Some(code) = ex_code {
            serde_json::json!({
                "error_code": error_code,
                "message": message,
                "code": code,
            })
        } else {
            serde_json::json!({
                "error_code": error_code,
                "message": message,
            })
        };
        HttpResponse::build(status).json(body)
    }
}
