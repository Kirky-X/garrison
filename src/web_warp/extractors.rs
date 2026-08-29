//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! warp 错误响应 impl 与 per-handler 鉴权 Filter。
//!
//! 承接 `mod.rs` 的 `GarrisonRejection` / `GarrisonError` warp 适配：
//! - `impl Reject for GarrisonRejection`：接入 warp 拒绝链
//! - `impl Reply for GarrisonError`：错误 → HTTP 响应，复用 `response_parts()` 保证三框架一致
//! - `check_login` / `check_role` / `check_permission`：guard Filter，per-handler 鉴权
//!
//! value-extracting Filter（`garrison_principal` / `tenant_context`）见 [`super::extractor`]。

use crate::config::GarrisonConfig;
use crate::context::token_extract::extract_token_from_headers;
use crate::error::{GarrisonError, GarrisonResult};
use crate::stp::with_current_token;
use std::sync::Arc;
use warp::http::HeaderMap;
use warp::http::StatusCode;
use warp::reject::Reject;
use warp::reply::{Reply, Response};
use warp::Filter;

// ============================================================================
// Reject + Reply impl：GarrisonError → warp 响应
// ============================================================================

/// `impl Reject for GarrisonRejection`：接入 warp 拒绝链（空 impl，仅需 Reject marker）。
impl Reject for super::GarrisonRejection {}

/// `GarrisonRejection` 的 `Display`：委托内部 `GarrisonError`，便于日志与排障。
impl std::fmt::Display for super::GarrisonRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// 统一错误响应构建：与 axum `IntoResponse` / actix-web `ResponseError` 的
/// 状态码及 body（`error_code` / `message` / 可选 `code`）完全一致。
///
/// [`Reply for GarrisonError`]、[`Reply for GarrisonRejection`] 与 [`garrison_recover`]
/// 共用，单一事实来源，确保三框架响应同一形态。
fn unified_error_reply(err: &GarrisonError) -> Response {
    // 单次调用 response_parts_i18n() 获取所有字段（M2：消除冗余调用）
    let (status, error_code, message, ex_code) = err.response_parts_i18n();
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
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
    // warp 内置 json + with_status 组合，自动设置 content-type: application/json
    warp::reply::with_status(warp::reply::json(&body), status).into_response()
}

/// `impl Reply for GarrisonError`：复用 [`unified_error_reply`] 保证三框架一致。
///
/// 状态码与错误码映射与 axum `IntoResponse` / actix-web `ResponseError` 完全一致。
impl Reply for GarrisonError {
    fn into_response(self) -> Response {
        tracing::error!(error = ?self, "garrison rejection");
        unified_error_reply(&self)
    }
}

/// `impl Reply for GarrisonRejection`：委托内部 `GarrisonError` 的统一响应。
impl Reply for super::GarrisonRejection {
    fn into_response(self) -> Response {
        self.0.into_response()
    }
}

/// `.recover()` 守卫映射处理器：把 `GarrisonRejection` 转为与三框架一致的
/// `error_code` / `message` JSON（状态码对齐）；非 `GarrisonRejection` 原样返回。
///
/// 用法：`warp::serve(routes.recover(garrison_recover))`。warp 的拒绝链不会自动
/// 调用 `impl Reply`，必须显式挂本处理器，否则未登录等拒绝会退化为 warp 默认
/// 400 非 JSON 响应（三框架一致承诺失效）。
pub async fn garrison_recover(err: warp::Rejection) -> Result<Response, warp::Rejection> {
    if let Some(rej) = err.find::<super::GarrisonRejection>() {
        return Ok(unified_error_reply(&rej.0));
    }
    Err(err)
}

// ============================================================================
// guard Filter extractors：per-handler 鉴权
// ============================================================================

/// `check_login` Filter：验证用户已登录。
///
/// 在 handler 链中使用：
/// ```ignore
/// let routes = warp::path("api")
///     .and(check_login(config))
///     .map(|| "authenticated");
/// ```
pub fn check_login(
    config: Arc<GarrisonConfig>,
) -> impl Filter<Extract = ((),), Error = warp::Rejection> + Clone {
    warp::any()
        .and(warp::header::headers_cloned())
        .and_then(move |headers: HeaderMap| {
            let config = config.clone();
            async move {
                let token = extract_token_from_headers(&headers, &config)
                    .map_err(|e| warp::reject::custom(super::GarrisonRejection(e)))?
                    .ok_or_else(|| {
                        warp::reject::custom(super::GarrisonRejection(GarrisonError::NotLogin(
                            "web-not-login".to_string(),
                        )))
                    })?;

                let result: GarrisonResult<()> = with_current_token(token, async {
                    let logged_in = crate::stp::GarrisonUtil::check_login().await?;
                    if !logged_in {
                        return Err(GarrisonError::NotLogin("web-not-login".to_string()));
                    }
                    Ok(())
                })
                .await;

                result.map_err(|e| warp::reject::custom(super::GarrisonRejection(e)))?;
                Ok::<(), warp::Rejection>(())
            }
        })
}

/// `check_role` Filter：验证用户持有指定角色。
pub fn check_role(
    config: Arc<GarrisonConfig>,
    role: String,
) -> impl Filter<Extract = ((),), Error = warp::Rejection> + Clone {
    warp::any()
        .and(warp::header::headers_cloned())
        .and_then(move |headers: HeaderMap| {
            let config = config.clone();
            let role = role.clone();
            async move {
                let token = extract_token_from_headers(&headers, &config)
                    .map_err(|e| warp::reject::custom(super::GarrisonRejection(e)))?
                    .ok_or_else(|| {
                        warp::reject::custom(super::GarrisonRejection(GarrisonError::NotLogin(
                            "web-not-login".to_string(),
                        )))
                    })?;

                let result: GarrisonResult<()> = with_current_token(token, async move {
                    crate::stp::GarrisonUtil::check_role(&role).await
                })
                .await;

                result.map_err(|e| warp::reject::custom(super::GarrisonRejection(e)))?;
                Ok::<(), warp::Rejection>(())
            }
        })
}

/// `check_permission` Filter：验证用户持有指定权限。
pub fn check_permission(
    config: Arc<GarrisonConfig>,
    permission: String,
) -> impl Filter<Extract = ((),), Error = warp::Rejection> + Clone {
    warp::any()
        .and(warp::header::headers_cloned())
        .and_then(move |headers: HeaderMap| {
            let config = config.clone();
            let permission = permission.clone();
            async move {
                let token = extract_token_from_headers(&headers, &config)
                    .map_err(|e| warp::reject::custom(super::GarrisonRejection(e)))?
                    .ok_or_else(|| {
                        warp::reject::custom(super::GarrisonRejection(GarrisonError::NotLogin(
                            "web-not-login".to_string(),
                        )))
                    })?;

                let result: GarrisonResult<()> = with_current_token(token, async move {
                    crate::stp::GarrisonUtil::check_permission(&permission).await
                })
                .await;

                result.map_err(|e| warp::reject::custom(super::GarrisonRejection(e)))?;
                Ok::<(), warp::Rejection>(())
            }
        })
}
