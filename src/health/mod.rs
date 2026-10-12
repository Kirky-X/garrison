// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 健康检查模块，提供 liveness/readiness 探针与依赖项健康检测。
//!
//! `HealthCheck` trait 定义单项检查契约，`HealthRegistry` 并发执行并聚合为 `HealthReport`
//! （overall 取最差状态）；内置 Config/Cache/Db 检查器，Web 端点 `/health/live`（进程存活
//! 即 200）与 `/health/ready`（聚合结果）由 `axum_routes` / `actix_routes` / `warp_routes`
//! 按 feature 提供，impl 拆分在 `registry` / `report` / `checks` 子模块。

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
    /// 单项检查超时（默认 5 秒）：超时的检查按 `Unhealthy` 聚合，不会无限阻塞 readiness 探针。
    pub(crate) check_timeout: Duration,
}

// 内置健康检查器（类型声明；impl 在 checks.rs）

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
    /// SQL 连接池句柄（db-postgres / db-mysql 探测路径用）；`None`（`new()` 默认）时探测
    /// 返回 `Degraded`——不误报 `Healthy`，部署方应经 [`DbHealthCheck::with_pool`] 注入真实连接池。
    #[cfg(any(feature = "db-postgres", feature = "db-mysql"))]
    pool: Option<std::sync::Arc<dbnexus::DbPool>>,
    #[cfg(not(any(feature = "db-postgres", feature = "db-mysql")))]
    _priv: (),
}

// 子模块（impl 块与路由集成，接口隔离）

/// 内置 `HealthCheck` 实现子模块（ConfigHealthCheck / CacheHealthCheck / DbHealthCheck）。
pub mod checks;
/// 容器探针与 CLI 共用的 liveness 探测逻辑（纯 std，零外部依赖）。
pub mod probe;
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
