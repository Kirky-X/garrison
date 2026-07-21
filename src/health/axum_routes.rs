//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! axum 框架的健康检查路由集成。
//!
//! 从 `mod.rs` 迁移而出（规则 25：mod.rs 接口隔离）。
//! 提供 `/health/live` 与 `/health/ready` 端点。

use super::HealthRegistry;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Json;
use std::sync::Arc;

/// Liveness 探针 handler——进程存活即返回 200。
pub async fn live() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({"status": "healthy"})),
    )
}

/// Readiness 探针 handler——检查依赖项就绪状态。
pub async fn ready(
    axum::extract::State(registry): axum::extract::State<Arc<HealthRegistry>>,
) -> Response {
    let report = registry.check_all().await;
    let status = match report.overall {
        super::HealthStatus::Healthy | super::HealthStatus::Degraded => StatusCode::OK,
        super::HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };
    (status, Json(report)).into_response()
}

/// 创建健康检查路由，挂载到 axum Router。
///
/// # 示例
///
/// ```ignore
/// use garrison::health::axum_routes::health_routes;
/// use garrison::health::HealthRegistry;
/// use std::sync::Arc;
///
/// let registry = Arc::new(HealthRegistry::new());
/// let app = axum::Router::new()
///     .merge(health_routes(registry));
/// ```
pub fn health_routes(registry: Arc<HealthRegistry>) -> axum::Router {
    axum::Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .with_state(registry)
}
