//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 内置健康检查器实现：`ConfigHealthCheck`、`CacheHealthCheck`、`DbHealthCheck`。
//!
//! 类型声明保留在 `mod.rs`，本文件承载构造方法、`Default` 与 `HealthCheck` trait 实现。

#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
use super::CacheHealthCheck;
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
use super::DbHealthCheck;
use super::{ConfigHealthCheck, HealthCheck, HealthResult, HealthStatus};
use crate::config::GarrisonConfig;
// 探测路径（db-postgres / db-mysql / cache-redis）专用 import：
// 快路径下不调用 GarrisonManager / dao.get，避免 dead_code 警告
#[cfg(any(feature = "db-postgres", feature = "db-mysql", feature = "cache-redis"))]
use crate::dao::GarrisonDao;
#[cfg(any(feature = "db-postgres", feature = "db-mysql", feature = "cache-redis"))]
use crate::manager::GarrisonManager;
use std::sync::Arc;
#[cfg(any(feature = "db-postgres", feature = "db-mysql", feature = "cache-redis"))]
use std::time::Duration;

/// 健康探测超时阈值（2 秒）。
///
/// 用于 `DbHealthCheck` / `CacheHealthCheck` 的真实探测调用包裹。
/// 超过此阈值的依赖视为不可用（`Unhealthy`），避免 readiness 探针 hang 导致 kubelet
/// 误杀 Pod（CWE-400 资源耗尽 + readiness gate 失效）。
///
/// # 选值依据
///
/// - 2s 留足正常网络往返余量（PG/MySQL ping 通常 < 100ms，Redis PING < 10ms）
/// - 低于 kubelet 默认 `failureThreshold*periodSeconds`（通常 10s）避免级联超时
/// - 与 industry default（Spring Boot Actuator 2s、Kubernetes readiness 默认）对齐
#[cfg(any(feature = "db-postgres", feature = "db-mysql", feature = "cache-redis"))]
const HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// 健康探测用的 key（不存在也无妨，仅触发底层 dao.get 网络往返）。
#[cfg(any(feature = "db-postgres", feature = "db-mysql", feature = "cache-redis"))]
const HEALTH_PROBE_KEY: &str = "__garrison_health_probe__";

// ============================================================================
// ConfigHealthCheck：配置健康检查（always on）
// ============================================================================

impl ConfigHealthCheck {
    /// 创建配置健康检查器。
    pub fn new(config: Arc<GarrisonConfig>) -> Self {
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

// ============================================================================
// CacheHealthCheck：缓存健康检查（feature-gated）
// ============================================================================

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

// -------------------- 快路径：仅 cache-memory（无 cache-redis） --------------------
//
// oxcache 内存后端无网络 I/O，进程存活即缓存可用，跳过探测避免无谓开销。
#[cfg(all(feature = "cache-memory", not(feature = "cache-redis")))]
impl HealthCheck for CacheHealthCheck {
    fn name(&self) -> &str {
        "cache"
    }

    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthResult<HealthStatus>> + Send>>
    {
        Box::pin(async { Ok(HealthStatus::Healthy) })
    }
}

// -------------------- 探测路径：cache-redis 启用 --------------------
//
// cache-redis 后端通过网络连接 Redis，必须执行真实探测以发现连接断开 / 网络分区。
// 通过 `GarrisonManager` 获取 dao 句柄，执行 `dao.get` 最小查询（与 design.md Alternative
// Considered 决策一致：不修改 GarrisonDao trait，复用现有查询能力做探测）。
#[cfg(feature = "cache-redis")]
impl HealthCheck for CacheHealthCheck {
    fn name(&self) -> &str {
        "cache"
    }

    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthResult<HealthStatus>> + Send>>
    {
        Box::pin(async {
            // manager 未初始化时返回 Unhealthy（而非 Err / 误报 Healthy）
            // 避免被 HealthRegistry 转为通用 "check failed" 消息，保留明确语义
            let logic = match GarrisonManager::logic() {
                Ok(l) => l,
                Err(_) => return Ok(HealthStatus::Unhealthy),
            };
            let dao: Arc<dyn GarrisonDao> = Arc::clone(logic.session.dao());
            // 探测：执行 dao.get 包裹 timeout
            // Ok(_)（含 Ok(None)）→ 后端可达 → Healthy
            // Err 或超时 → 后端不可达 → Unhealthy
            match tokio::time::timeout(HEALTH_PROBE_TIMEOUT, dao.get(HEALTH_PROBE_KEY)).await {
                Ok(Ok(_)) => Ok(HealthStatus::Healthy),
                Ok(Err(_)) => Ok(HealthStatus::Unhealthy),
                Err(_) => Ok(HealthStatus::Unhealthy),
            }
        })
    }
}

// ============================================================================
// DbHealthCheck：数据库健康检查（feature-gated）
// ============================================================================

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

// -------------------- 快路径：仅 db-sqlite（无 db-postgres / db-mysql） --------------------
//
// SQLite 是嵌入式数据库，进程存活即数据库可用，无需探测。
#[cfg(all(
    feature = "db-sqlite",
    not(any(feature = "db-postgres", feature = "db-mysql"))
))]
impl HealthCheck for DbHealthCheck {
    fn name(&self) -> &str {
        "database"
    }

    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthResult<HealthStatus>> + Send>>
    {
        Box::pin(async { Ok(HealthStatus::Healthy) })
    }
}

// -------------------- 探测路径：db-postgres 或 db-mysql 启用 --------------------
//
// PG/MySQL 后端通过网络连接数据库，必须执行真实探测以发现连接断开 / 池耗尽 / 网络分区。
// 通过 `GarrisonManager` 获取 dao 句柄，执行 `dao.get` 最小查询（design.md Alternative
// Considered 决策：不修改 GarrisonDao trait）。
#[cfg(any(feature = "db-postgres", feature = "db-mysql"))]
impl HealthCheck for DbHealthCheck {
    fn name(&self) -> &str {
        "database"
    }

    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthResult<HealthStatus>> + Send>>
    {
        Box::pin(async {
            // manager 未初始化时返回 Unhealthy（而非 Err / 误报 Healthy）
            let logic = match GarrisonManager::logic() {
                Ok(l) => l,
                Err(_) => return Ok(HealthStatus::Unhealthy),
            };
            let dao: Arc<dyn GarrisonDao> = Arc::clone(logic.session.dao());
            // 探测：执行 dao.get 包裹 timeout
            // Ok(_)（含 Ok(None)）→ 后端可达 → Healthy
            // Err 或超时 → 后端不可达 → Unhealthy
            match tokio::time::timeout(HEALTH_PROBE_TIMEOUT, dao.get(HEALTH_PROBE_KEY)).await {
                Ok(Ok(_)) => Ok(HealthStatus::Healthy),
                Ok(Err(_)) => Ok(HealthStatus::Unhealthy),
                Err(_) => Ok(HealthStatus::Unhealthy),
            }
        })
    }
}
