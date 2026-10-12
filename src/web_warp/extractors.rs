// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! warp 错误响应 impl 与 per-handler 鉴权 Filter：`impl Reject for GarrisonRejection`、
//! `impl Reply for GarrisonError`（复用 `response_parts()` 保证三框架一致）、
//! `check_login`/`check_role`/`check_permission` guard Filter；value-extracting Filter 见 [`super::extractor`]。

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

// Reject + Reply impl：GarrisonError → warp 响应

/// `impl Reject for GarrisonRejection`：接入 warp 拒绝链（空 impl，仅需 Reject marker）。
impl Reject for super::GarrisonRejection {}

/// `GarrisonRejection` 的 `Display`：委托内部 `GarrisonError`，便于日志与排障。
impl std::fmt::Display for super::GarrisonRejection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(&self.0, f)
    }
}

/// 统一错误响应构建：状态码与 body（`error_code`/`error_id`/`message`/可选 `code`）与 axum/actix 完全一致，
/// body 经 [`GarrisonError::to_json_body`] 构造；[`Reply for GarrisonError`]、[`Reply for GarrisonRejection`]
/// 与 [`garrison_recover`] 共用此单一事实来源（`request_id` 由 [`super::request_id`] 中间件后置回填）。
pub(crate) fn unified_error_reply(err: &GarrisonError) -> Response {
    let body = err.to_json_body();
    // 状态码无需 i18n 分片（to_json_body 内已翻译，避免双重翻译；与 actix ResponseError 路径对齐）
    let (status, _, _, _) = err.response_parts();
    let status = StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let mut response = warp::reply::with_status(warp::reply::json(&body), status).into_response();
    // Retry-After：delta-seconds 整数秒（下限 1），仅限流变体（不依赖 task-local）
    if let Some(secs) = err.retry_after_secs() {
        response.headers_mut().insert(
            warp::http::header::HeaderName::from_static("retry-after"),
            warp::http::HeaderValue::from(secs),
        );
    }
    // X-Request-ID：request id task-local scope 内回传（warp 中间件 scope 包住后置处理）
    if let Some(id) = crate::context::request_id::current() {
        if let Ok(value) = warp::http::HeaderValue::from_str(id.as_ref()) {
            response.headers_mut().insert(
                warp::http::header::HeaderName::from_static("x-request-id"),
                value,
            );
        }
    }
    response
}

/// `impl Reply for GarrisonError`：复用 `unified_error_reply`，状态码与错误码映射与 axum/actix 一致。
impl Reply for GarrisonError {
    fn into_response(self) -> Response {
        // 完整错误记录到日志（不返回给客户端）；限流拒绝降级 warn（日志洪水防护）
        self.log_rejection();
        unified_error_reply(&self)
    }
}

/// `impl Reply for GarrisonRejection`：委托内部 `GarrisonError` 的统一响应。
impl Reply for super::GarrisonRejection {
    fn into_response(self) -> Response {
        self.0.into_response()
    }
}

/// `.recover()` 守卫：把 `GarrisonRejection` 转为三框架一致的 JSON（状态码对齐），其他 Rejection 原样返回。
///
/// 用法 `routes.recover(garrison_recover)`——warp 拒绝链不会自动调用 `impl Reply`，漏挂会退化为
/// warp 默认 400 非 JSON 响应（三框架一致承诺失效）。
pub async fn garrison_recover(err: warp::Rejection) -> Result<Response, warp::Rejection> {
    if let Some(rej) = err.find::<super::GarrisonRejection>() {
        // 与 axum/actix 对齐：每次错误必落日志（限流拒绝 warn）
        rej.0.log_rejection();
        return Ok(unified_error_reply(&rej.0));
    }
    Err(err)
}

// guard Filter extractors：per-handler 鉴权

/// `check_login` Filter：验证用户已登录。
///
/// 在 handler 链中使用：
/// ```ignore
/// let routes = warp::path("api")
/// .and(check_login(config))
/// .map(|| "authenticated");
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
                            "web-not-login::".to_string(),
                        )))
                    })?;

                let result: GarrisonResult<()> = with_current_token(token, async {
                    let logged_in = crate::stp::GarrisonUtil::check_login().await?;
                    if !logged_in {
                        return Err(GarrisonError::NotLogin("web-not-login::".to_string()));
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
                            "web-not-login::".to_string(),
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
                            "web-not-login::".to_string(),
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
