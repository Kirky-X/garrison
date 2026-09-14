//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
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
//!
//! ## 子模块
//!
//! - `registry`：`HealthRegistry` impl 块（构造 / 注册 / 并发执行 / 聚合）
//! - `report`：`HealthReport` impl 块
//! - `checks`：内置 `HealthCheck` 实现（ConfigHealthCheck / CacheHealthCheck / DbHealthCheck）
//! - `axum_routes`：axum 框架的健康检查路由集成
//! - `actix_routes`：actix-web 框架的健康检查路由集成
//! - `warp_routes`：warp 框架的健康检查路由集成

use crate::error::GarrisonResult;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

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
pub type HealthResult<T> = GarrisonResult<T>;

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

/// 健康检查聚合器。
///
/// 注册多个 `HealthCheck`，通过 `check_all()` 并发执行并聚合结果。
pub struct HealthRegistry {
    pub(crate) checks: Vec<Box<dyn HealthCheck>>,
    /// 单项检查超时（请求级护栏，默认 5 秒）。
    /// 超时的检查按 `Unhealthy` 聚合，不会无限阻塞 readiness 探针。
    pub(crate) check_timeout: Duration,
}

// ============================================================================
// 内置健康检查器（类型声明；impl 在 checks.rs）
// ============================================================================

/// 配置健康检查器，验证 `GarrisonConfig` 已加载且通过 `validate()`。
pub struct ConfigHealthCheck {
    pub(crate) config: Arc<crate::config::GarrisonConfig>,
}

/// 缓存健康检查器（feature-gated），探测 oxcache 连通性。
#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
pub struct CacheHealthCheck;

/// 数据库健康检查器（feature-gated），探测 dbnexus 连接。
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
pub struct DbHealthCheck {
    /// SQL 连接池句柄（db-postgres / db-mysql 探测路径用）。
    ///
    /// `None`（`new()` 默认）时探测路径返回 `Degraded`——不再误报 `Healthy`
    /// （原实现探测内存 KV DAO，Postgres 宕机 readiness 仍 Healthy，
    /// K8s 摘流失效）。部署方应经 [`DbHealthCheck::with_pool`] 注入真实连接池。
    #[cfg(any(feature = "db-postgres", feature = "db-mysql"))]
    pool: Option<std::sync::Arc<dbnexus::DbPool>>,
    #[cfg(not(any(feature = "db-postgres", feature = "db-mysql")))]
    _priv: (),
}

// ============================================================================
// 子模块（impl 块与路由集成，接口隔离）
// ============================================================================

/// 内置 `HealthCheck` 实现子模块（ConfigHealthCheck / CacheHealthCheck / DbHealthCheck）。
pub mod checks;
/// `HealthRegistry` impl 块子模块。
pub mod registry;
/// `HealthReport` impl 块子模块。
pub mod report;

/// axum 框架的健康检查路由集成。
#[cfg(feature = "web-axum")]
pub mod axum_routes;

/// actix-web 框架的健康检查路由集成。
#[cfg(feature = "web-actix")]
pub mod actix_routes;

/// warp 框架的健康检查路由集成。
#[cfg(feature = "web-warp")]
pub mod warp_routes;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;
