// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! K8s 健康探针最小实现（GAR-14）。
//!
//! sdforge 的 `healthz_handler` / `readyz_handler` 不可配置：前者恒回显
//! sdforge 依赖版本号（利于 CVE 指纹匹配），后者原样透传业务注册检查的
//! `checks[].details`（可能含内部依赖拓扑）。故此处以自定义最小 handler 包装：
//!
//! - `/healthz`（liveness）：仅 `{"status":"healthy"}`，无任何版本/环境细节
//! - `/readyz`（readiness）：复用 sdforge 的就绪检查注册表
//!   （`sdforge::health::register_readiness_check_fn`）与 200/503 判定，
//!   但 `checks[].details` 仅在 `AuthServerConfig.health_details_enabled`
//!   （`GARRISON_HEALTH_DETAILS=true`）时透传，默认剥离仅保留 name/healthy

#![cfg(feature = "server-health-check")]

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

/// readiness details 透传开关（来自 `AuthServerConfig.health_details_enabled`）。
#[derive(Debug, Clone, Copy)]
pub struct HealthDetailsEnabled(pub bool);

/// `GET /healthz` — liveness 探针（最小语义：进程存活即 200）。
///
/// 不回显版本号：healthz 挂载在认证层之外，版本细节仅服务于 CVE 指纹。
pub async fn liveness_handler() -> Response {
    Json(json!({ "status": "healthy" })).into_response()
}

/// `GET /readyz` — readiness 探针（200 全部检查通过 / 503 任一失败）。
///
/// 复用 `sdforge::health::readyz_handler` 跑全部已注册就绪检查（含 kit 健康
/// 源），按其状态码返回；响应体在透传前按 `HealthDetailsEnabled` 剥离
/// `checks[].details`（默认剥离，显式 opt-in 才输出）。
pub async fn readiness_handler(State(enabled): State<HealthDetailsEnabled>) -> Response {
    let upstream = sdforge::health::readyz_handler().await;
    let status = upstream.status();
    let bytes = match axum::body::to_bytes(upstream.into_body(), 256 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            tracing::warn!(error = %e, "readiness probe: upstream body read failed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "unknown" })),
            )
                .into_response();
        },
    };
    let mut value: serde_json::Value = match serde_json::from_slice(&bytes) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "readiness probe: upstream body is not valid JSON");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "status": "unknown" })),
            )
                .into_response();
        },
    };

    if !enabled.0 {
        if let Some(checks) = value.get_mut("checks").and_then(|c| c.as_array_mut()) {
            for check in checks {
                if let Some(obj) = check.as_object_mut() {
                    obj.remove("details");
                }
            }
        }
    }

    (status, Json(value)).into_response()
}
