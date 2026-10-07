// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 扫码登录 HTTP 端点路由（feature = "protocol-qrlogin"）。
//!
//! 将 `QrLoginService` 暴露为 4 个 HTTP 端点，集成到 GarrisonAuthServer
//!（外网路由，与 sdforge_routes / oauth2_routes 互补，axum Router::merge 集成）。
//!
//! # 端点与认证语义
//!
//! - `POST /qrlogin/create`：匿名（Web 端创建扫码会话，响应含 qr_id + bind_token）
//! - `POST /qrlogin/poll`：匿名（双票轮询：qr_id + bind_token；Confirmed 时原子
//!   消费 bind_token 兑换并签发会话 token）
//! - `POST /qrlogin/scan`：**Bearer App 会话 token**（handler 内解析校验，失败 401）
//! - `POST /qrlogin/confirm`：**Bearer App 会话 token**（同上；确认者必须就是扫码者）
//!
//! # 中间件覆盖
//!
//! axum merge 不继承 layer：本 router 在 `external_router()` 中 merge 前**自带**
//! 与主栈同构的 TrustedProxies / inject_client_ip / inject_user_agent /
//! rate_limit / audit_log（见 server_impl.rs），不依赖主栈、也不受
//! external_path_filter 白名单管辖。已知取舍：`web-security-headers` feature
//! 的安全头层仅挂主栈（JSON API 响应头影响有限，未随本 router 重复挂载）。
//!
//! # 安全要点
//!
//! - scan/confirm 必须持有效 App 会话：扫码 ≠ 确认，确认凭据仅在扫码后颁发
//! - poll 的 Confirmed 分支以服务端存储的确认者 login_id 签发会话，不信任请求体
//! - create 的 IP/UA 待登录端上下文仅落入会话（供确认页脱敏摘要），不回显给匿名方

#![cfg(feature = "protocol-qrlogin")]

use std::sync::Arc;

use async_trait::async_trait;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use chrono::Utc;
use serde::Deserialize;
use serde_json::json;

use crate::error::{GarrisonError, GarrisonResult};
use crate::loc;
use crate::manager::GarrisonManager;
use crate::protocol::qrlogin::{
    QrLoginAction, QrLoginPollOutcome, QrLoginService, QrLoginSessionIssuer, QrLoginWebContext,
};
use crate::stp::session::SessionLogic;
use crate::stp::with_current_token;
use crate::stp::LoginParams;

/// 扫码登录路由共享状态。
pub struct QrLoginHttpState {
    /// 扫码登录服务（票据状态机）。
    pub service: Arc<QrLoginService>,
    /// 会话签发端口（App token 解析 + 确认者会话签发）。
    pub issuer: Arc<dyn QrLoginSessionIssuer>,
}

/// 基于 Stp 的默认会话签发端口实现。
///
/// `resolve_app_login_id`：task_local 上下文内调 `get_login_id`；
/// `issue_session`：走 `SessionLogic::login`（与密码登录同路径，device 固定 "qrlogin"），
/// 使扫码登录会话继承权限/踢下线/续期/hijack 检测/审计等全部下游能力。
pub struct StpQrLoginIssuer;

#[async_trait]
impl QrLoginSessionIssuer for StpQrLoginIssuer {
    async fn resolve_app_login_id(&self, app_token: &str) -> GarrisonResult<String> {
        let logic = GarrisonManager::logic()?;
        let login_id =
            with_current_token(app_token.to_string(), async { logic.get_login_id().await }).await?;
        login_id.ok_or_else(|| {
            GarrisonError::InvalidToken(loc!(
                "qrlogin-app-unauthorized",
                "QR login requires a valid app session token".to_string()
            ))
        })
    }

    async fn issue_session(&self, login_id: &str) -> GarrisonResult<String> {
        let logic = GarrisonManager::logic()?;
        let params = LoginParams {
            device: Some("qrlogin".to_string()),
            ..Default::default()
        };
        logic.login(login_id, &params).await
    }
}

/// 构建外网扫码登录路由（create/poll/scan/confirm）。
pub fn qrlogin_external_router(state: Arc<QrLoginHttpState>) -> Router {
    Router::new()
        .route("/qrlogin/create", post(create_endpoint))
        .route("/qrlogin/poll", post(poll_endpoint))
        .route("/qrlogin/scan", post(scan_endpoint))
        .route("/qrlogin/confirm", post(confirm_endpoint))
        .with_state(state)
}

// ============================================================================
// 请求体
// ============================================================================

/// poll 请求体。
#[derive(Deserialize)]
pub struct QrLoginPollRequest {
    /// create 返回的会话随机标识。
    pub qr_id: String,
    /// create 返回的轮询第二票（仅下发给 Web 端本人；缺失/错误一律 expired）。
    pub bind_token: String,
}

/// scan 请求体（App 端提交扫到的完整二维码内容）。
#[derive(Deserialize)]
pub struct QrLoginScanRequest {
    /// 扫码得到的 qr_content URL（含 t 参数签名票据）。
    pub qr_content: String,
}

/// confirm 请求体。
#[derive(Deserialize)]
pub struct QrLoginConfirmRequest {
    /// scan 返回的一次性确认凭据。
    pub confirm_token: String,
    /// 确认动作：`"confirm"` 或 `"cancel"`。
    pub action: String,
}

// ============================================================================
// HTTP 端点（薄包装，错误统一映射）
// ============================================================================

/// POST /qrlogin/create — 创建扫码会话（匿名）。
///
/// IP 取自 `inject_client_ip` 注入的 `Extension<ClientIp>`（rightmost-untrusted
/// 解析在中间件统一完成）；扩展缺失（如裸路由测试）时为 None，不自行解析 XFF。
async fn create_endpoint(
    State(state): State<Arc<QrLoginHttpState>>,
    ip_ext: Option<axum::Extension<crate::server::middleware::ClientIp>>,
    headers: HeaderMap,
) -> Response {
    let ip = ip_ext
        .map(|axum::Extension(c)| c.0)
        .filter(|s| !s.is_empty() && s != "unknown");
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    let web = QrLoginWebContext {
        ip,
        user_agent,
        created_at_ms: Utc::now().timestamp_millis(),
    };
    match state.service.create_session(web).await {
        Ok(created) => (
            StatusCode::OK,
            Json(json!({
                "qr_id": created.qr_id,
                "bind_token": created.bind_token,
                "qr_content": created.qr_content,
                "expires_in_secs": created.expires_in_secs,
            })),
        )
            .into_response(),
        Err(e) => error_response(e),
    }
}

/// POST /qrlogin/poll — 轮询状态；Confirmed 时原子兑换并签发会话 token。
async fn poll_endpoint(
    State(state): State<Arc<QrLoginHttpState>>,
    Json(req): Json<QrLoginPollRequest>,
) -> Response {
    match state.service.poll(&req.qr_id, &req.bind_token).await {
        Ok(outcome) => match outcome {
            QrLoginPollOutcome::Pending => ok_json(json!({ "status": "pending" })),
            QrLoginPollOutcome::Scanned => ok_json(json!({ "status": "scanned" })),
            QrLoginPollOutcome::Cancelled => ok_json(json!({ "status": "cancelled" })),
            QrLoginPollOutcome::Expired => ok_json(json!({ "status": "expired" })),
            QrLoginPollOutcome::Confirmed { login_id, .. } => {
                // 会话归属取自服务端存储的确认者，不信任请求体；
                // login_id 不回显给匿名轮询方
                match state.issuer.issue_session(&login_id).await {
                    Ok(token) => ok_json(json!({ "status": "confirmed", "token": token })),
                    Err(e) => error_response(GarrisonError::Internal(loc!(
                        "qrlogin-issuer-failed",
                        format!("QR login session issuance failed: {}", e),
                        ("detail", &format!("{}", e))
                    ))),
                }
            },
        },
        Err(e) => error_response(e),
    }
}

/// 采集 App 端请求上下文（ip, ua）：事件审计用，采集失败不阻断主流程。
fn app_context(
    ip_ext: Option<axum::Extension<crate::server::middleware::ClientIp>>,
    headers: &HeaderMap,
) -> Option<(String, String)> {
    let ip = ip_ext
        .map(|axum::Extension(c)| c.0)
        .filter(|s| !s.is_empty() && s != "unknown")?;
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())?;
    Some((ip, user_agent))
}

/// POST /qrlogin/scan — App 端扫码（Bearer 认证必需）。
async fn scan_endpoint(
    State(state): State<Arc<QrLoginHttpState>>,
    ip_ext: Option<axum::Extension<crate::server::middleware::ClientIp>>,
    headers: HeaderMap,
    Json(req): Json<QrLoginScanRequest>,
) -> Response {
    let app_token = match bearer_token(&headers) {
        Some(token) => token,
        None => return unauthorized(),
    };
    let app_login_id = match state.issuer.resolve_app_login_id(&app_token).await {
        Ok(id) => id,
        Err(_) => return unauthorized(),
    };
    match state
        .service
        .scan(
            &req.qr_content,
            &app_login_id,
            app_context(ip_ext, &headers),
        )
        .await
    {
        Ok(view) => ok_json(json!({
            "confirm_token": view.confirm_token,
            "web_device_label": view.web_device_label,
            "web_created_at_ms": view.web_created_at_ms,
            "expires_in_secs": view.expires_in_secs,
        })),
        Err(e) => error_response(e),
    }
}

/// POST /qrlogin/confirm — App 端确认/取消（Bearer 认证必需）。
async fn confirm_endpoint(
    State(state): State<Arc<QrLoginHttpState>>,
    ip_ext: Option<axum::Extension<crate::server::middleware::ClientIp>>,
    headers: HeaderMap,
    Json(req): Json<QrLoginConfirmRequest>,
) -> Response {
    let app_token = match bearer_token(&headers) {
        Some(token) => token,
        None => return unauthorized(),
    };
    // 身份绑定：确认者 login_id 传入 service 与 scan 锁定值比对（不再仅做 401 判断）
    let app_login_id = match state.issuer.resolve_app_login_id(&app_token).await {
        Ok(id) => id,
        Err(_) => return unauthorized(),
    };
    let action = match req.action.as_str() {
        "confirm" => QrLoginAction::Confirm,
        "cancel" => QrLoginAction::Cancel,
        _ => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": loc!(
                    "qrlogin-action-invalid",
                    "action must be \"confirm\" or \"cancel\"".to_string()
                ) })),
            )
                .into_response()
        },
    };
    match state
        .service
        .confirm(
            &req.confirm_token,
            &app_login_id,
            action,
            app_context(ip_ext, &headers),
        )
        .await
    {
        Ok(status) => {
            let status_str = if status == crate::protocol::qrlogin::QrLoginStatus::Confirmed {
                "confirmed"
            } else {
                "cancelled"
            };
            ok_json(json!({ "status": status_str }))
        },
        Err(e) => error_response(e),
    }
}

// ============================================================================
// 工具
// ============================================================================

/// 200 JSON 响应。
fn ok_json(value: serde_json::Value) -> Response {
    (StatusCode::OK, Json(value)).into_response()
}

/// 401 未授权响应（App 会话 token 缺失/无效）。
fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(json!({ "error": loc!(
            "qrlogin-app-unauthorized",
            "QR login requires a valid app session token".to_string()
        ) })),
    )
        .into_response()
}

/// `GarrisonError` → HTTP 响应映射。
///
/// InvalidParam / InvalidToken（票据与状态类错误，qrlogin 服务层全部归入此两族）
/// → 400；其余（Manager 未初始化 / DAO / 内部错误）→ 500。
fn error_response(e: GarrisonError) -> Response {
    let status = match &e {
        GarrisonError::InvalidParam(_) | GarrisonError::InvalidToken(_) => StatusCode::BAD_REQUEST,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(json!({ "error": format!("{}", e) }))).into_response()
}

/// 从 `Authorization: Bearer <token>` 提取 token。
fn bearer_token(headers: &HeaderMap) -> Option<String> {
    let value = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?;
    let token = token.trim();
    if token.is_empty() {
        None
    } else {
        Some(token.to_string())
    }
}

// ============================================================================
// 路由测试（MockIssuer 驱动，不初始化 GarrisonManager）
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dao::{GarrisonDao, InMemoryDao};
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    /// 测试用会话签发端口：token "valid-app-token" → user-1；签发返回固定 token。
    struct MockIssuer;

    #[async_trait]
    impl QrLoginSessionIssuer for MockIssuer {
        async fn resolve_app_login_id(&self, app_token: &str) -> GarrisonResult<String> {
            match app_token {
                "valid-app-token" => Ok("user-1".to_string()),
                "valid-app-token-2" => Ok("user-2".to_string()),
                _ => Err(GarrisonError::InvalidToken(
                    "mock-invalid-token".to_string(),
                )),
            }
        }

        async fn issue_session(&self, _login_id: &str) -> GarrisonResult<String> {
            Ok("issued-session-token".to_string())
        }
    }

    /// 构造测试路由。
    fn make_app() -> Router {
        let dao: Arc<dyn GarrisonDao> = Arc::new(InMemoryDao::new());
        let service = Arc::new(
            QrLoginService::new(dao, "test-secret-key-0123456789abcdef-0123456789abcdef").unwrap(),
        );
        let state = Arc::new(QrLoginHttpState {
            service,
            issuer: Arc::new(MockIssuer),
        });
        qrlogin_external_router(state)
    }

    /// 发送 POST JSON 请求（可带 Bearer）。
    async fn post_json(
        app: Router,
        path: &str,
        body: serde_json::Value,
        bearer: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut builder = Request::builder()
            .method("POST")
            .uri(path)
            .header("content-type", "application/json");
        if let Some(token) = bearer {
            builder = builder.header("authorization", format!("Bearer {token}"));
        }
        let response = app
            .oneshot(
                builder
                    .body(Body::from(body.to_string()))
                    .expect("request build should succeed"),
            )
            .await
            .expect("oneshot should succeed");
        let status = response.status();
        let bytes = response.into_body().collect().await.unwrap().to_bytes();
        let json = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
        };
        (status, json)
    }

    /// 创建扫码会话，返回 (qr_id, bind_token, qr_content)。
    async fn create_session(app: Router) -> (String, String, String) {
        let (status, json) = post_json(app, "/qrlogin/create", json!({}), None).await;
        assert_eq!(status, StatusCode::OK);
        (
            json["qr_id"].as_str().unwrap().to_string(),
            json["bind_token"].as_str().unwrap().to_string(),
            json["qr_content"].as_str().unwrap().to_string(),
        )
    }

    /// create → 200 且响应含 qr_id/qr_content/expires_in_secs。
    #[tokio::test]
    async fn create_returns_qr_id_and_content() {
        let app = make_app();
        let (status, json) = post_json(app, "/qrlogin/create", json!({}), None).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["qr_id"].as_str().unwrap().len(), 64);
        assert!(json["qr_content"].as_str().unwrap().contains("t="));
        assert_eq!(json["expires_in_secs"].as_u64(), Some(120));
    }

    /// create → poll 返回 pending。
    #[tokio::test]
    async fn poll_pending_after_create() {
        let app = make_app();
        let (qr_id, bind_token, _) = create_session(app.clone()).await;
        let (status, json) = post_json(
            app,
            "/qrlogin/poll",
            json!({ "qr_id": qr_id, "bind_token": bind_token }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(json["status"], "pending");
    }

    /// scan 无 Bearer → 401 且错误含 app session token 语义。
    #[tokio::test]
    async fn scan_without_bearer_is_401() {
        let app = make_app();
        let (_, _bind_token, qr_content) = create_session(app.clone()).await;
        let (status, json) = post_json(
            app,
            "/qrlogin/scan",
            json!({ "qr_content": qr_content }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(
            json["error"]
                .as_str()
                .unwrap()
                .contains("app session token"),
            "错误应含 app session token 语义，实际: {}",
            json["error"]
        );
    }

    /// scan 带 Bearer → 200 返回 confirm_token 与脱敏摘要。
    #[tokio::test]
    async fn scan_with_bearer_returns_confirm_token() {
        let app = make_app();
        let (_, _bind_token, qr_content) = create_session(app.clone()).await;
        let (status, json) = post_json(
            app,
            "/qrlogin/scan",
            json!({ "qr_content": qr_content }),
            Some("valid-app-token"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!json["confirm_token"].as_str().unwrap().is_empty());
        assert_eq!(json["web_device_label"], "Unknown device");
        assert_eq!(json["expires_in_secs"], 60);
    }

    /// 全链路：create → scan → poll(scanned) → confirm → poll 返回 confirmed + token。
    #[tokio::test]
    async fn full_flow_confirm_and_exchange() {
        let app = make_app();
        let (qr_id, bind_token, qr_content) = create_session(app.clone()).await;

        let (status, scan_json) = post_json(
            app.clone(),
            "/qrlogin/scan",
            json!({ "qr_content": qr_content }),
            Some("valid-app-token"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let confirm_token = scan_json["confirm_token"].as_str().unwrap().to_string();

        let (_, poll_json) = post_json(
            app.clone(),
            "/qrlogin/poll",
            json!({ "qr_id": qr_id, "bind_token": bind_token }),
            None,
        )
        .await;
        assert_eq!(poll_json["status"], "scanned");

        let (status, confirm_json) = post_json(
            app.clone(),
            "/qrlogin/confirm",
            json!({ "confirm_token": confirm_token, "action": "confirm" }),
            Some("valid-app-token"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(confirm_json["status"], "confirmed");

        let (status, poll_json) = post_json(
            app,
            "/qrlogin/poll",
            json!({ "qr_id": qr_id, "bind_token": bind_token }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(poll_json["status"], "confirmed");
        assert_eq!(poll_json["token"], "issued-session-token");
    }

    /// confirm 取消动作 → status cancelled；后续 poll 返回 cancelled。
    #[tokio::test]
    async fn confirm_cancel_flow() {
        let app = make_app();
        let (qr_id, bind_token, qr_content) = create_session(app.clone()).await;
        let (_, scan_json) = post_json(
            app.clone(),
            "/qrlogin/scan",
            json!({ "qr_content": qr_content }),
            Some("valid-app-token"),
        )
        .await;
        let confirm_token = scan_json["confirm_token"].as_str().unwrap().to_string();

        let (status, confirm_json) = post_json(
            app.clone(),
            "/qrlogin/confirm",
            json!({ "confirm_token": confirm_token, "action": "cancel" }),
            Some("valid-app-token"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(confirm_json["status"], "cancelled");

        let (_, poll_json) = post_json(
            app,
            "/qrlogin/poll",
            json!({ "qr_id": qr_id, "bind_token": bind_token }),
            None,
        )
        .await;
        assert_eq!(poll_json["status"], "cancelled");
    }

    /// 伪造票据 scan（持有效 Bearer）→ 400。
    #[tokio::test]
    async fn scan_forged_ticket_is_400() {
        let app = make_app();
        let (status, json) = post_json(
            app,
            "/qrlogin/scan",
            json!({ "qr_content": "garrison://qrlogin?t=forged.bad_sig" }),
            Some("valid-app-token"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(json["error"].as_str().unwrap().contains("signature"));
    }

    /// 非法 action → 400。
    #[tokio::test]
    async fn confirm_invalid_action_is_400() {
        let app = make_app();
        let (_, _bind_token, qr_content) = create_session(app.clone()).await;
        let (_, scan_json) = post_json(
            app.clone(),
            "/qrlogin/scan",
            json!({ "qr_content": qr_content }),
            Some("valid-app-token"),
        )
        .await;
        let confirm_token = scan_json["confirm_token"].as_str().unwrap().to_string();
        let (status, _) = post_json(
            app,
            "/qrlogin/confirm",
            json!({ "confirm_token": confirm_token, "action": "hack" }),
            Some("valid-app-token"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    /// 非法 action 的 400 错误消息走 Fluent i18n：zh locale 下返回
    /// `qrlogin-action-invalid` 的中文翻译（与英文 fallback 文案可区分，
    /// 命中即证明响应体未硬编码英文）。
    #[tokio::test]
    async fn confirm_invalid_action_message_is_localized() {
        let app = make_app();
        let _guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
        let (status, json) = post_json(
            app,
            "/qrlogin/confirm",
            json!({ "confirm_token": "whatever", "action": "hack" }),
            Some("valid-app-token"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            json["error"].as_str().unwrap().contains("必须为"),
            "zh locale 应返回 Fluent 翻译，实际: {}",
            json["error"]
        );
    }

    /// 身份绑定：Bearer 用户 B（user-2）确认 A（user-1）的扫码 → 400。
    #[tokio::test]
    async fn confirm_by_other_user_is_400() {
        let app = make_app();
        let (_, _bind_token, qr_content) = create_session(app.clone()).await;
        let (_, scan_json) = post_json(
            app.clone(),
            "/qrlogin/scan",
            json!({ "qr_content": qr_content }),
            Some("valid-app-token"),
        )
        .await;
        let confirm_token = scan_json["confirm_token"].as_str().unwrap().to_string();
        let (status, json) = post_json(
            app,
            "/qrlogin/confirm",
            json!({ "confirm_token": confirm_token, "action": "confirm" }),
            Some("valid-app-token-2"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            json["error"].as_str().unwrap().contains("confirm token"),
            "错误应与 token 无效同族（无区分度），实际: {}",
            json["error"]
        );
    }
}
