//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! warp 错误响应 impl 与 per-handler 鉴权 Filter。
//!
//! 承接 `mod.rs` 的 `BulwarkRejection` / `BulwarkError` warp 适配：
//! - `impl Reject for BulwarkRejection`：接入 warp 拒绝链
//! - `impl Reply for BulwarkError`：错误 → HTTP 响应，复用 `response_parts()` 保证三框架一致
//! - `check_login` / `check_role` / `check_permission`：guard Filter，per-handler 鉴权
//!
//! value-extracting Filter（`bulwark_principal` / `tenant_context`）见 [`super::extractor`]。

use crate::config::BulwarkConfig;
use crate::context::token_extract::extract_token_from_headers;
use crate::error::{BulwarkError, BulwarkResult};
use crate::stp::with_current_token;
use std::sync::Arc;
use warp::http::HeaderMap;
use warp::http::StatusCode;
use warp::reject::Reject;
use warp::reply::{Reply, Response};
use warp::Filter;

// ============================================================================
// Reject + Reply impl：BulwarkError → warp 响应
// ============================================================================

/// `impl Reject for BulwarkRejection`：接入 warp 拒绝链（空 impl，仅需 Reject marker）。
impl Reject for super::BulwarkRejection {}

/// `impl Reply for BulwarkError`：复用 `response_parts()` 保证三框架一致。
///
/// 状态码与错误码映射与 axum `IntoResponse` / actix-web `ResponseError` 完全一致。
impl Reply for BulwarkError {
    fn into_response(self) -> Response {
        tracing::error!(error = ?self, "bulwark rejection");
        let (status, _, _, _) = self.response_parts();
        let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        // warp 内置 json + with_status 组合，自动设置 content-type: application/json
        let body = warp::reply::json(&self.to_json_body());
        warp::reply::with_status(body, status).into_response()
    }
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
    config: Arc<BulwarkConfig>,
) -> impl Filter<Extract = ((),), Error = warp::Rejection> + Clone {
    warp::any()
        .and(warp::header::headers_cloned())
        .and_then(move |headers: HeaderMap| {
            let config = config.clone();
            async move {
                let token = extract_token_from_headers(&headers, &config)
                    .map_err(|e| warp::reject::custom(super::BulwarkRejection(e)))?
                    .ok_or_else(|| {
                        warp::reject::custom(super::BulwarkRejection(BulwarkError::NotLogin(
                            "web-not-login".to_string(),
                        )))
                    })?;

                let result: BulwarkResult<()> = with_current_token(token, async {
                    let logged_in = crate::stp::BulwarkUtil::check_login().await?;
                    if !logged_in {
                        return Err(BulwarkError::NotLogin("web-not-login".to_string()));
                    }
                    Ok(())
                })
                .await;

                result.map_err(|e| warp::reject::custom(super::BulwarkRejection(e)))?;
                Ok::<(), warp::Rejection>(())
            }
        })
}

/// `check_role` Filter：验证用户持有指定角色。
pub fn check_role(
    config: Arc<BulwarkConfig>,
    role: String,
) -> impl Filter<Extract = ((),), Error = warp::Rejection> + Clone {
    warp::any()
        .and(warp::header::headers_cloned())
        .and_then(move |headers: HeaderMap| {
            let config = config.clone();
            let role = role.clone();
            async move {
                let token = extract_token_from_headers(&headers, &config)
                    .map_err(|e| warp::reject::custom(super::BulwarkRejection(e)))?
                    .ok_or_else(|| {
                        warp::reject::custom(super::BulwarkRejection(BulwarkError::NotLogin(
                            "web-not-login".to_string(),
                        )))
                    })?;

                let result: BulwarkResult<()> = with_current_token(token, async move {
                    crate::stp::BulwarkUtil::check_role(&role).await
                })
                .await;

                result.map_err(|e| warp::reject::custom(super::BulwarkRejection(e)))?;
                Ok::<(), warp::Rejection>(())
            }
        })
}

/// `check_permission` Filter：验证用户持有指定权限。
pub fn check_permission(
    config: Arc<BulwarkConfig>,
    permission: String,
) -> impl Filter<Extract = ((),), Error = warp::Rejection> + Clone {
    warp::any()
        .and(warp::header::headers_cloned())
        .and_then(move |headers: HeaderMap| {
            let config = config.clone();
            let permission = permission.clone();
            async move {
                let token = extract_token_from_headers(&headers, &config)
                    .map_err(|e| warp::reject::custom(super::BulwarkRejection(e)))?
                    .ok_or_else(|| {
                        warp::reject::custom(super::BulwarkRejection(BulwarkError::NotLogin(
                            "web-not-login".to_string(),
                        )))
                    })?;

                let result: BulwarkResult<()> = with_current_token(token, async move {
                    crate::stp::BulwarkUtil::check_permission(&permission).await
                })
                .await;

                result.map_err(|e| warp::reject::custom(super::BulwarkRejection(e)))?;
                Ok::<(), warp::Rejection>(())
            }
        })
}
