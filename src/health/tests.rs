//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 健康检查模块单元测试。
//!
//! 通过 `mod.rs` 中的 `#[cfg(test)] mod tests;` 引入。

use super::mock::{AlwaysDegraded, AlwaysHealthy, AlwaysUnhealthy};
use super::*;
use crate::config::GarrisonConfig;
use std::sync::Arc;

// ============================================================================
// HealthStatus 测试
// ============================================================================

#[test]
fn health_status_serializes_to_lowercase() {
    assert_eq!(
        serde_json::to_string(&HealthStatus::Healthy).unwrap(),
        "\"healthy\""
    );
    assert_eq!(
        serde_json::to_string(&HealthStatus::Degraded).unwrap(),
        "\"degraded\""
    );
    assert_eq!(
        serde_json::to_string(&HealthStatus::Unhealthy).unwrap(),
        "\"unhealthy\""
    );
}

#[test]
fn health_status_deserializes_from_lowercase() {
    let s: HealthStatus = serde_json::from_str("\"healthy\"").unwrap();
    assert_eq!(s, HealthStatus::Healthy);
    let s: HealthStatus = serde_json::from_str("\"degraded\"").unwrap();
    assert_eq!(s, HealthStatus::Degraded);
    let s: HealthStatus = serde_json::from_str("\"unhealthy\"").unwrap();
    assert_eq!(s, HealthStatus::Unhealthy);
}

#[test]
fn health_status_equality() {
    assert_ne!(HealthStatus::Healthy, HealthStatus::Unhealthy);
    assert_eq!(HealthStatus::Healthy, HealthStatus::Healthy);
}

// ============================================================================
// HealthRegistry 测试
// ============================================================================

#[tokio::test]
async fn empty_registry_returns_healthy() {
    let registry = HealthRegistry::new();
    let report = registry.check_all().await;
    assert_eq!(report.overall, HealthStatus::Healthy);
    assert!(report.checks.is_empty());
}

#[tokio::test]
async fn registry_all_healthy_returns_healthy() {
    let mut registry = HealthRegistry::new();
    registry.register(Box::new(AlwaysHealthy));
    let report = registry.check_all().await;
    assert_eq!(report.overall, HealthStatus::Healthy);
    assert_eq!(report.checks.len(), 1);
    assert_eq!(report.checks[0].name, "always-healthy");
    assert_eq!(report.checks[0].status, HealthStatus::Healthy);
}

#[tokio::test]
async fn registry_with_unhealthy_returns_unhealthy() {
    let mut registry = HealthRegistry::new();
    registry.register(Box::new(AlwaysHealthy));
    registry.register(Box::new(AlwaysUnhealthy));
    let report = registry.check_all().await;
    assert_eq!(report.overall, HealthStatus::Unhealthy);
    assert_eq!(report.checks.len(), 2);
    // 找到 unhealthy 的检查项
    let unhealthy_check = report
        .checks
        .iter()
        .find(|c| c.name == "always-unhealthy")
        .expect("should have always-unhealthy check");
    assert_eq!(unhealthy_check.status, HealthStatus::Unhealthy);
    assert!(unhealthy_check.message.is_some());
}

#[tokio::test]
async fn registry_with_degraded_and_no_unhealthy_returns_degraded() {
    let mut registry = HealthRegistry::new();
    registry.register(Box::new(AlwaysHealthy));
    registry.register(Box::new(AlwaysDegraded));
    let report = registry.check_all().await;
    assert_eq!(report.overall, HealthStatus::Degraded);
}

#[tokio::test]
async fn registry_unhealthy_overrides_degraded() {
    let mut registry = HealthRegistry::new();
    registry.register(Box::new(AlwaysDegraded));
    registry.register(Box::new(AlwaysUnhealthy));
    let report = registry.check_all().await;
    assert_eq!(report.overall, HealthStatus::Unhealthy);
}

// ============================================================================
// ConfigHealthCheck 测试
// ============================================================================

#[tokio::test]
async fn config_health_check_returns_healthy_for_valid_config() {
    let config = Arc::new(GarrisonConfig::default_config());
    let checker = ConfigHealthCheck::new(config);
    assert_eq!(checker.name(), "config");
    let result = checker.check().await.unwrap();
    assert_eq!(result, HealthStatus::Healthy);
}

#[tokio::test]
async fn config_health_check_returns_unhealthy_for_invalid_config() {
    let mut config = GarrisonConfig::default_config();
    config.timeout = -1; // 非法值
    let checker = ConfigHealthCheck::new(Arc::new(config));
    let result = checker.check().await;
    assert!(result.is_err());
}

// ============================================================================
// CacheHealthCheck 测试（feature-gated）
// ============================================================================

#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
#[tokio::test]
async fn cache_health_check_returns_healthy() {
    let checker = CacheHealthCheck::new();
    assert_eq!(checker.name(), "cache");
    let result = checker.check().await.unwrap();
    assert_eq!(result, HealthStatus::Healthy);
}

// ============================================================================
// DbHealthCheck 测试（feature-gated）
// ============================================================================

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
#[tokio::test]
async fn db_health_check_returns_healthy() {
    let checker = DbHealthCheck::new();
    assert_eq!(checker.name(), "database");
    let result = checker.check().await.unwrap();
    assert_eq!(result, HealthStatus::Healthy);
}

// ============================================================================
// HealthReport 序列化测试
// ============================================================================

#[test]
fn health_report_serializes_correctly() {
    let report = HealthReport {
        overall: HealthStatus::Degraded,
        checks: vec![CheckResult {
            name: "cache".to_string(),
            status: HealthStatus::Degraded,
            message: Some("high latency".to_string()),
        }],
    };
    let json = serde_json::to_string(&report).unwrap();
    assert!(json.contains("\"overall\":\"degraded\""));
    assert!(json.contains("\"name\":\"cache\""));
    assert!(json.contains("\"status\":\"degraded\""));
    assert!(json.contains("\"message\":\"high latency\""));
}

#[test]
fn health_report_skips_none_message() {
    let report = HealthReport {
        overall: HealthStatus::Healthy,
        checks: vec![CheckResult {
            name: "config".to_string(),
            status: HealthStatus::Healthy,
            message: None,
        }],
    };
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("message"));
}

// ============================================================================
// axum_routes 测试（feature = "web-axum"）
// ============================================================================

/// 测试 axum liveness 探针始终返回 200。
#[cfg(feature = "web-axum")]
#[tokio::test]
async fn test_axum_live_returns_200() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let registry = Arc::new(HealthRegistry::new());
    let app = super::axum_routes::health_routes(registry);
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health/live")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// 测试 axum readiness 探针在所有检查健康时返回 200。
#[cfg(feature = "web-axum")]
#[tokio::test]
async fn test_axum_ready_returns_200_when_healthy() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let mut registry = HealthRegistry::new();
    registry.register(Box::new(AlwaysHealthy));
    let app = super::axum_routes::health_routes(Arc::new(registry));
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// 测试 axum readiness 探针在 Degraded 状态时返回 200（降级但可用）。
#[cfg(feature = "web-axum")]
#[tokio::test]
async fn test_axum_ready_returns_200_when_degraded() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let mut registry = HealthRegistry::new();
    registry.register(Box::new(AlwaysDegraded));
    let app = super::axum_routes::health_routes(Arc::new(registry));
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
}

/// 测试 axum readiness 探针在 Unhealthy 状态时返回 503。
#[cfg(feature = "web-axum")]
#[tokio::test]
async fn test_axum_ready_returns_503_when_unhealthy() {
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;

    let mut registry = HealthRegistry::new();
    registry.register(Box::new(AlwaysUnhealthy));
    let app = super::axum_routes::health_routes(Arc::new(registry));
    let resp = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/health/ready")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// ============================================================================
// warp_routes 测试（feature = "web-warp"）
// ============================================================================

/// 测试 warp liveness 探针返回 200。
#[cfg(feature = "web-warp")]
#[tokio::test]
async fn test_warp_live_filter_returns_200() {
    use super::warp_routes::live_filter;
    use warp::http::StatusCode;

    let resp = warp::test::request()
        .method("GET")
        .path("/health/live")
        .reply(&live_filter())
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// 测试 warp readiness 探针在健康时返回 200。
#[cfg(feature = "web-warp")]
#[tokio::test]
async fn test_warp_ready_filter_returns_200_when_healthy() {
    use super::warp_routes::ready_filter;
    use warp::http::StatusCode;

    let mut registry = HealthRegistry::new();
    registry.register(Box::new(AlwaysHealthy));
    let filter = ready_filter(Arc::new(registry));
    let resp = warp::test::request()
        .method("GET")
        .path("/health/ready")
        .reply(&filter)
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// 测试 warp readiness 探针在 Unhealthy 时返回 503。
#[cfg(feature = "web-warp")]
#[tokio::test]
async fn test_warp_ready_filter_returns_503_when_unhealthy() {
    use super::warp_routes::ready_filter;
    use warp::http::StatusCode;

    let mut registry = HealthRegistry::new();
    registry.register(Box::new(AlwaysUnhealthy));
    let filter = ready_filter(Arc::new(registry));
    let resp = warp::test::request()
        .method("GET")
        .path("/health/ready")
        .reply(&filter)
        .await;
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
}

// ============================================================================
// HealthRegistry Default / register 链式调用测试
// ============================================================================

/// 测试 HealthRegistry 的 Default 实现返回空 registry。
#[tokio::test]
async fn test_health_registry_default() {
    let registry = HealthRegistry::default();
    let report = registry.check_all().await;
    assert_eq!(report.overall, HealthStatus::Healthy);
    assert!(report.checks.is_empty());
}

/// 测试 HealthReport::empty() 返回空报告且整体状态为 Healthy。
#[test]
fn test_health_report_empty() {
    let report = HealthReport::empty();
    assert_eq!(report.overall, HealthStatus::Healthy);
    assert!(report.checks.is_empty());
}

/// 测试 HealthRegistry::register 链式调用（返回 &mut Self）。
#[tokio::test]
async fn test_health_registry_register_chain() {
    let mut registry = HealthRegistry::new();
    registry
        .register(Box::new(AlwaysHealthy))
        .register(Box::new(AlwaysDegraded));
    let report = registry.check_all().await;
    assert_eq!(report.checks.len(), 2);
    assert_eq!(report.overall, HealthStatus::Degraded);
}
