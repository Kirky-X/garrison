//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! actix-web 框架的健康检查路由集成。
//!
//! 从 `mod.rs` 迁移而出（规则 25：mod.rs 接口隔离）。
//! 提供 `/health/live` 与 `/health/ready` 端点。

use super::{HealthRegistry, HealthStatus};
use actix_web::http::StatusCode;
use actix_web::{web, HttpResponse, Responder};
use std::sync::Arc;

/// Liveness 探针 handler。
pub async fn live() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({"status": "healthy"}))
}

/// Readiness 探针 handler。
pub async fn ready(registry: web::Data<Arc<HealthRegistry>>) -> HttpResponse {
    let report = registry.check_all().await;
    let status = match report.overall {
        HealthStatus::Healthy | HealthStatus::Degraded => StatusCode::OK,
        HealthStatus::Unhealthy => StatusCode::SERVICE_UNAVAILABLE,
    };
    HttpResponse::build(status).json(report)
}

/// 注册健康检查路由到 actix-web App。
///
/// # 示例
///
/// ```ignore
/// use bulwark::health::actix_routes::configure_health_routes;
/// use bulwark::health::HealthRegistry;
/// use std::sync::Arc;
///
/// let registry = Arc::new(HealthRegistry::new());
/// let app = actix_web::App::new()
///     .app_data(actix_web::web::Data::new(registry))
///     .configure(configure_health_routes);
/// ```
pub fn configure_health_routes(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/health/live").route(web::get().to(live)));
    cfg.service(web::resource("/health/ready").route(web::get().to(ready)));
}
