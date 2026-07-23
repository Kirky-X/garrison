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
// 测试 fixture：HangDao（探测路径超时测试共享）
// ============================================================================

/// Hang DAO：`get` 调用时 sleep 10s（远超 `HEALTH_PROBE_TIMEOUT` 的 2s），
/// 模拟数据库/Redis 后端网络不可达。
///
/// 其他方法返回 `Ok` 以保证 `GarrisonManager::init` 不触发非预期错误路径。
///
/// 仅在探测路径（db-postgres / db-mysql / cache-redis）feature 启用时编译。
#[cfg(any(feature = "db-postgres", feature = "db-mysql", feature = "cache-redis"))]
struct HangDao;

#[cfg(any(feature = "db-postgres", feature = "db-mysql", feature = "cache-redis"))]
#[async_trait::async_trait]
impl crate::dao::GarrisonDao for HangDao {
    async fn get(&self, _key: &str) -> crate::error::GarrisonResult<Option<String>> {
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;
        Ok(None)
    }
    async fn set(
        &self,
        _key: &str,
        _value: &str,
        _ttl_seconds: u64,
    ) -> crate::error::GarrisonResult<()> {
        Ok(())
    }
    async fn update(&self, _key: &str, _value: &str) -> crate::error::GarrisonResult<()> {
        Ok(())
    }
    async fn expire(&self, _key: &str, _seconds: u64) -> crate::error::GarrisonResult<()> {
        Ok(())
    }
    async fn delete(&self, _key: &str) -> crate::error::GarrisonResult<()> {
        Ok(())
    }
}

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

/// 快路径下（仅 `cache-memory`，未启用 `cache-redis`）：进程存活即 Healthy。
///
/// `cache-memory` 后端为 oxcache 内存缓存，无网络 I/O，无需探测。
/// 此测试仅在快路径下编译；探测路径（`cache-redis` 启用）下行为不同，
/// 由 `cache_health_check_returns_unhealthy_on_probe_timeout`（超时）和
/// `cache_health_check_unhealthy_when_manager_uninitialized`（manager 未初始化）覆盖。
#[cfg(all(feature = "cache-memory", not(feature = "cache-redis")))]
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

/// 快路径下（仅 `db-sqlite`，未启用 `db-postgres`/`db-mysql`）：进程存活即 Healthy。
///
/// SQLite 嵌入式数据库无独立服务进程，进程存活即数据库可用，无需探测。
/// 此测试仅在快路径下编译；探测路径（`db-postgres`/`db-mysql` 启用）下行为不同，
/// 由 `db_health_check_unhealthy_when_manager_uninitialized`（manager 未初始化）和
/// `db_health_check_returns_unhealthy_on_probe_timeout`（超时）覆盖。
#[cfg(all(
    feature = "db-sqlite",
    not(any(feature = "db-postgres", feature = "db-mysql"))
))]
#[tokio::test]
async fn db_health_check_returns_healthy() {
    let checker = DbHealthCheck::new();
    assert_eq!(checker.name(), "database");
    let result = checker.check().await.unwrap();
    assert_eq!(result, HealthStatus::Healthy);
}

// ============================================================================
// D4 — 健康检查真实探测 + 超时 测试（W3，探测路径专属）
// ============================================================================

/// 探测路径下，`GarrisonManager` 未初始化时 `DbHealthCheck` 返回 `Unhealthy`。
///
/// 仅在启用 `db-postgres` 或 `db-mysql`（探测路径）时编译。
/// `db-sqlite-only`（快路径）下不适用，因 SQLite 嵌入式数据库进程存活即 Healthy，
/// 不依赖 `GarrisonManager` 初始化。
///
/// # 验证点
/// - 未 init manager 时，`DbHealthCheck::check` 必须返回 `Ok(Unhealthy)`（而非误报 `Healthy`）
/// - 返回 `Ok` 而非 `Err`，避免 `HealthRegistry` 把错误统一转为 "check failed" 通用消息
#[cfg(any(feature = "db-postgres", feature = "db-mysql"))]
#[tokio::test]
#[serial_test::serial]
async fn db_health_check_unhealthy_when_manager_uninitialized() {
    // 确保 manager 未初始化（reset 任何前序测试残留状态）
    crate::manager::GarrisonManager::reset_for_test();
    assert!(
        !crate::manager::GarrisonManager::is_initialized(),
        "测试前置：manager 必须未初始化"
    );

    let checker = DbHealthCheck::new();
    let status = checker.check().await.expect("check 应返回 Ok 而非 Err");
    assert_eq!(
        status,
        HealthStatus::Unhealthy,
        "manager 未初始化时 DbHealthCheck 应返回 Unhealthy（而非误报 Healthy）"
    );
}

/// 探测路径下，`dao.get` hang 时 `CacheHealthCheck` 在 `HEALTH_PROBE_TIMEOUT`（2s）内返回 `Unhealthy`。
///
/// 仅在启用 `cache-redis`（探测路径）时编译。
/// `cache-memory-only`（快路径）下不适用，因 oxcache 内存后端进程存活即 Healthy。
///
/// # 验证点
/// - `dao.get` 长时间不返回时，`CacheHealthCheck::check` 必须在 2s 超时后返回 `Ok(Unhealthy)`
/// - 整体耗时应在 `HEALTH_PROBE_TIMEOUT`（2s）附近，而非等到 dao 返回（10s）
#[cfg(feature = "cache-redis")]
#[tokio::test]
#[serial_test::serial]
async fn cache_health_check_returns_unhealthy_on_probe_timeout() {
    use crate::dao::GarrisonDao;
    use crate::manager::GarrisonManager;
    use crate::stp::GarrisonInterface;
    use std::time::{Duration, Instant};

    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(HangDao);
    let config = Arc::new(GarrisonConfig::default_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(crate::stp::mock::MockInterface);
    GarrisonManager::init(dao, config, interface)
        .expect("init with HangDao 应成功（init 不调用 dao.get）");
    assert!(
        GarrisonManager::is_initialized(),
        "测试前置：manager 必须已初始化"
    );

    let checker = CacheHealthCheck::new();
    let start = Instant::now();
    let status = checker
        .check()
        .await
        .expect("check 应返回 Ok 而非 Err（超时映射为 Unhealthy，不是 Err）");
    let elapsed = start.elapsed();

    assert_eq!(
        status,
        HealthStatus::Unhealthy,
        "dao hang 时 CacheHealthCheck 应在 HEALTH_PROBE_TIMEOUT 内返回 Unhealthy"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "应在 HEALTH_PROBE_TIMEOUT（2s）附近返回，实际耗时: {:?}",
        elapsed
    );

    GarrisonManager::reset_for_test();
}

/// 探测路径下，`GarrisonManager` 未初始化时 `CacheHealthCheck` 返回 `Unhealthy`。
///
/// 仅在启用 `cache-redis`（探测路径）时编译。
/// `cache-memory-only`（快路径）下不适用，因 oxcache 内存后端进程存活即 Healthy，
/// 不依赖 `GarrisonManager` 初始化。
///
/// # 对称性
/// 与 `db_health_check_unhealthy_when_manager_uninitialized` 对称，覆盖 CacheHealthCheck
/// 的 manager 未初始化边界场景，避免未来修改 CacheHealthCheck 时未测试路径 silent regression。
///
/// # 验证点
/// - 未 init manager 时，`CacheHealthCheck::check` 必须返回 `Ok(Unhealthy)`（而非误报 `Healthy`）
/// - 返回 `Ok` 而非 `Err`，避免 `HealthRegistry` 把错误统一转为 "check failed" 通用消息
#[cfg(feature = "cache-redis")]
#[tokio::test]
#[serial_test::serial]
async fn cache_health_check_unhealthy_when_manager_uninitialized() {
    crate::manager::GarrisonManager::reset_for_test();
    assert!(
        !crate::manager::GarrisonManager::is_initialized(),
        "测试前置：manager 必须未初始化"
    );

    let checker = CacheHealthCheck::new();
    let status = checker.check().await.expect("check 应返回 Ok 而非 Err");
    assert_eq!(
        status,
        HealthStatus::Unhealthy,
        "manager 未初始化时 CacheHealthCheck 应返回 Unhealthy（而非误报 Healthy）"
    );
}

/// 探测路径下，`dao.get` hang 时 `DbHealthCheck` 在 `HEALTH_PROBE_TIMEOUT`（2s）内返回 `Unhealthy`。
///
/// 仅在启用 `db-postgres` 或 `db-mysql`（探测路径）时编译。
/// `db-sqlite-only`（快路径）下不适用，因 SQLite 嵌入式数据库进程存活即 Healthy。
///
/// # 对称性
/// 与 `cache_health_check_returns_unhealthy_on_probe_timeout` 对称，覆盖 DbHealthCheck
/// 的探测超时边界场景，避免未来修改 DbHealthCheck 时未测试路径 silent regression。
///
/// # 验证点
/// - `dao.get` 长时间不返回时，`DbHealthCheck::check` 必须在 2s 超时后返回 `Ok(Unhealthy)`
/// - 整体耗时应在 `HEALTH_PROBE_TIMEOUT`（2s）附近，而非等到 dao 返回（10s）
#[cfg(any(feature = "db-postgres", feature = "db-mysql"))]
#[tokio::test]
#[serial_test::serial]
async fn db_health_check_returns_unhealthy_on_probe_timeout() {
    use crate::dao::GarrisonDao;
    use crate::manager::GarrisonManager;
    use crate::stp::GarrisonInterface;
    use std::time::{Duration, Instant};

    GarrisonManager::reset_for_test();
    let dao: Arc<dyn GarrisonDao> = Arc::new(HangDao);
    let config = Arc::new(GarrisonConfig::default_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(crate::stp::mock::MockInterface);
    GarrisonManager::init(dao, config, interface)
        .expect("init with HangDao 应成功（init 不调用 dao.get）");
    assert!(
        GarrisonManager::is_initialized(),
        "测试前置：manager 必须已初始化"
    );

    let checker = DbHealthCheck::new();
    let start = Instant::now();
    let status = checker
        .check()
        .await
        .expect("check 应返回 Ok 而非 Err（超时映射为 Unhealthy，不是 Err）");
    let elapsed = start.elapsed();

    assert_eq!(
        status,
        HealthStatus::Unhealthy,
        "dao hang 时 DbHealthCheck 应在 HEALTH_PROBE_TIMEOUT 内返回 Unhealthy"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "应在 HEALTH_PROBE_TIMEOUT（2s）附近返回，实际耗时: {:?}",
        elapsed
    );

    GarrisonManager::reset_for_test();
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
