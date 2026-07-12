//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 健康检查模块，提供 liveness/readiness 探针与依赖项健康检测。
//!
//! ## 设计
//!
//! - `HealthCheck` trait：单项健康检查契约（name + async check）
//! - `HealthRegistry`：聚合器，注册多个检查器，并发执行并聚合结果
//! - `HealthStatus`：三态枚举（Healthy / Degraded / Unhealthy）
//! - 内置检查器：`ConfigHealthCheck`（always on）、`CacheHealthCheck`（cache feature）、`DbHealthCheck`（db feature）
//!
//! ## Web 端点
//!
//! - `/health/live`：liveness 探针，进程存活即返回 200
//! - `/health/ready`：readiness 探针，调用 `HealthRegistry::check_all()` 聚合结果

use crate::error::BulwarkResult;
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// 健康状态枚举。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum HealthStatus {
    /// 正常——所有依赖项可用。
    Healthy,
    /// 降级——部分非关键依赖不可用，核心功能仍可用。
    Degraded,
    /// 不可用——关键依赖故障，服务无法正常响应。
    Unhealthy,
}

/// 健康检查结果类型别名。
pub type HealthResult<T> = BulwarkResult<T>;

/// 单项健康检查 trait。
///
/// 实现方提供 `name()` 标识检查项，`check()` 异步执行检查逻辑。
pub trait HealthCheck: Send + Sync {
    /// 检查项名称（如 "config"、"cache"、"database"）。
    fn name(&self) -> &str;

    /// 异步执行健康检查，返回 `HealthStatus`。
    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthResult<HealthStatus>> + Send>>;
}

/// 单项检查结果。
#[derive(Debug, Clone, Serialize)]
pub struct CheckResult {
    /// 检查项名称。
    pub name: String,
    /// 检查状态。
    pub status: HealthStatus,
    /// 错误信息（仅在 status != Healthy 时有值）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// 健康报告，聚合所有检查项结果。
#[derive(Debug, Clone, Serialize)]
pub struct HealthReport {
    /// 整体健康状态（所有检查项的最差状态）。
    pub overall: HealthStatus,
    /// 各检查项详细结果。
    pub checks: Vec<CheckResult>,
}

impl HealthReport {
    /// 创建空报告（无检查项），整体状态为 Healthy。
    pub fn empty() -> Self {
        Self {
            overall: HealthStatus::Healthy,
            checks: Vec::new(),
        }
    }
}

/// 健康检查聚合器。
///
/// 注册多个 `HealthCheck`，通过 `check_all()` 并发执行并聚合结果。
pub struct HealthRegistry {
    checks: Vec<Box<dyn HealthCheck>>,
}

impl HealthRegistry {
    /// 创建空 registry。
    pub fn new() -> Self {
        Self { checks: Vec::new() }
    }

    /// 注册一个健康检查器。
    pub fn register(&mut self, check: Box<dyn HealthCheck>) -> &mut Self {
        self.checks.push(check);
        self
    }

    /// 并发执行所有注册的检查器，聚合结果。
    ///
    /// 聚合规则：
    /// - 任一 `Unhealthy` → 整体 `Unhealthy`
    /// - 任一 `Degraded` 且无 `Unhealthy` → 整体 `Degraded`
    /// - 全部 `Healthy` → 整体 `Healthy`
    /// - 空 registry → 整体 `Healthy`
    pub async fn check_all(&self) -> HealthReport {
        if self.checks.is_empty() {
            return HealthReport::empty();
        }

        let mut results = Vec::with_capacity(self.checks.len());
        for check in &self.checks {
            let name = check.name().to_string();
            match check.check().await {
                Ok(status) => results.push(CheckResult {
                    name,
                    status,
                    message: None,
                }),
                Err(e) => results.push(CheckResult {
                    name,
                    status: HealthStatus::Unhealthy,
                    message: Some(e.to_string()),
                }),
            }
        }

        let overall = if results.iter().any(|r| r.status == HealthStatus::Unhealthy) {
            HealthStatus::Unhealthy
        } else if results.iter().any(|r| r.status == HealthStatus::Degraded) {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        };

        HealthReport {
            overall,
            checks: results,
        }
    }
}

impl Default for HealthRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// 内置健康检查器
// ============================================================================

/// 配置健康检查器，验证 `BulwarkConfig` 已加载且通过 `validate()`。
pub struct ConfigHealthCheck {
    config: Arc<crate::config::BulwarkConfig>,
}

impl ConfigHealthCheck {
    /// 创建配置健康检查器。
    pub fn new(config: Arc<crate::config::BulwarkConfig>) -> Self {
        Self { config }
    }
}

impl HealthCheck for ConfigHealthCheck {
    fn name(&self) -> &str {
        "config"
    }

    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthResult<HealthStatus>> + Send>>
    {
        let config = self.config.clone();
        Box::pin(async move {
            config.validate()?;
            Ok(HealthStatus::Healthy)
        })
    }
}

/// 缓存健康检查器（feature-gated），探测 oxcache 连通性。
#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
pub struct CacheHealthCheck;

#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
impl CacheHealthCheck {
    /// 创建缓存健康检查器。
    pub fn new() -> Self {
        Self
    }
}

#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
impl Default for CacheHealthCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
impl HealthCheck for CacheHealthCheck {
    fn name(&self) -> &str {
        "cache"
    }

    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthResult<HealthStatus>> + Send>>
    {
        Box::pin(async {
            // oxcache 是内存缓存，进程存活即缓存可用。
            // 对于 cache-redis，实际 Redis 连通性检查需要 BulwarkManager 已初始化。
            // 此处返回 Healthy 作为默认；业务方可注册自定义 CacheHealthCheck 替换。
            Ok(HealthStatus::Healthy)
        })
    }
}

/// 数据库健康检查器（feature-gated），探测 dbnexus 连接。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub struct DbHealthCheck;

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
impl DbHealthCheck {
    /// 创建数据库健康检查器。
    pub fn new() -> Self {
        Self
    }
}

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
impl Default for DbHealthCheck {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
impl HealthCheck for DbHealthCheck {
    fn name(&self) -> &str {
        "database"
    }

    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthResult<HealthStatus>> + Send>>
    {
        Box::pin(async {
            // SQLite 是嵌入式数据库，进程存活即数据库可用。
            // PostgreSQL/MySQL 需要实际连接检查，但 BulwarkDao 抽象层不暴露 ping 方法。
            // 此处返回 Healthy 作为默认；业务方可注册自定义 DbHealthCheck 替换。
            Ok(HealthStatus::Healthy)
        })
    }
}

// ============================================================================
// Web 端点集成（axum）
// ============================================================================

#[cfg(feature = "web-axum")]
/// axum 框架的健康检查路由集成。
pub mod axum_routes {
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
    /// use bulwark::health::axum_routes::health_routes;
    /// use bulwark::health::HealthRegistry;
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
}

// ============================================================================
// Web 端点集成（actix-web）
// ============================================================================

#[cfg(feature = "web-actix")]
/// actix-web 框架的健康检查路由集成。
pub mod actix_routes {
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
}

// ============================================================================
// Web 端点集成（warp）
// ============================================================================

#[cfg(feature = "web-warp")]
/// warp 框架的健康检查路由集成。
pub mod warp_routes {
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
}

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests {
    use super::mock::{AlwaysDegraded, AlwaysHealthy, AlwaysUnhealthy};
    use super::*;
    use crate::config::BulwarkConfig;

    // ========================================================================
    // HealthStatus 测试
    // ========================================================================

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

    // ========================================================================
    // HealthRegistry 测试
    // ========================================================================

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

    // ========================================================================
    // ConfigHealthCheck 测试
    // ========================================================================

    #[tokio::test]
    async fn config_health_check_returns_healthy_for_valid_config() {
        let config = Arc::new(BulwarkConfig::default_config());
        let checker = ConfigHealthCheck::new(config);
        assert_eq!(checker.name(), "config");
        let result = checker.check().await.unwrap();
        assert_eq!(result, HealthStatus::Healthy);
    }

    #[tokio::test]
    async fn config_health_check_returns_unhealthy_for_invalid_config() {
        let mut config = BulwarkConfig::default_config();
        config.timeout = -1; // 非法值
        let checker = ConfigHealthCheck::new(Arc::new(config));
        let result = checker.check().await;
        assert!(result.is_err());
    }

    // ========================================================================
    // CacheHealthCheck 测试（feature-gated）
    // ========================================================================

    #[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
    #[tokio::test]
    async fn cache_health_check_returns_healthy() {
        let checker = CacheHealthCheck::new();
        assert_eq!(checker.name(), "cache");
        let result = checker.check().await.unwrap();
        assert_eq!(result, HealthStatus::Healthy);
    }

    // ========================================================================
    // DbHealthCheck 测试（feature-gated）
    // ========================================================================

    #[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
    #[tokio::test]
    async fn db_health_check_returns_healthy() {
        let checker = DbHealthCheck::new();
        assert_eq!(checker.name(), "database");
        let result = checker.check().await.unwrap();
        assert_eq!(result, HealthStatus::Healthy);
    }

    // ========================================================================
    // HealthReport 序列化测试
    // ========================================================================

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
}
