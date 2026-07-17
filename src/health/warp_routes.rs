//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! warp 框架的健康检查路由集成。
//!
//! 从 `mod.rs` 迁移而出（规则 25：mod.rs 接口隔离）。
//! 提供 `/health/live` 与 `/health/ready` filters。

use super::{HealthRegistry, HealthStatus};
use std::sync::Arc;
use warp::http::StatusCode;
use warp::reply::json;
use warp::{Filter, Reply};

/// Liveness 探针 filter。
pub fn live_filter() -> impl Filter<Extract = (impl Reply,), Error = warp::Rejection> + Clone {
    warp::path!("health" / "live").and(warp::get()).map(|| {
        warp::reply::with_status(
            json(&serde_json::json!({"status": "healthy"})),
            StatusCode::OK,
        )
    })
}

/// Readiness 探针 filter。
pub fn ready_filter(
    registry: Arc<HealthRegistry>,
) -> impl Filter<Extract = (impl Reply,), Error = warp::Rejection> + Clone {
    let registry = warp::any().map(move || registry.clone());
    warp::path!("health" / "ready")
        .and(warp::get())
        .and(registry)
        .and_then(|registry: Arc<HealthRegistry>| async move {
            let report = registry.check_all().await;
            let status = match report.overall {
                HealthStatus::Healthy | HealthStatus::Degraded => StatusCode::OK,
                HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
            };
            Ok::<_, std::convert::Infallible>(warp::reply::with_status(json(&report), status))
        })
}

/// 合并 liveness + readiness filters。
pub fn health_filters(
    registry: Arc<HealthRegistry>,
) -> impl Filter<Extract = (impl Reply,), Error = warp::Rejection> + Clone {
    live_filter().or(ready_filter(registry))
}
