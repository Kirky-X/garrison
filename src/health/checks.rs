// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 内置健康检查器实现：`ConfigHealthCheck`、`CacheHealthCheck`、`DbHealthCheck`。
//!
//! 类型声明保留在 `mod.rs`，本文件承载构造方法、`Default` 与 `HealthCheck` trait 实现。

#[cfg(any(feature = "cache-memory", feature = "cache-redis"))]
use super::CacheHealthCheck;
#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
use super::DbHealthCheck;
use super::{ConfigHealthCheck, HealthCheck, HealthResult, HealthStatus};
use crate::config::GarrisonConfig;
// 探测路径（cache-redis）专用 import：db 探测改用 pool ping 后不再使用 GarrisonDao
#[cfg(feature = "cache-redis")]
use crate::dao::GarrisonDao;
#[cfg(any(feature = "db-postgres", feature = "db-mysql", feature = "cache-redis"))]
use crate::manager::GarrisonManager;
use std::sync::Arc;
#[cfg(any(feature = "db-postgres", feature = "db-mysql", feature = "cache-redis"))]
use std::time::Duration;

/// 健康探测超时阈值（2 秒）：DbHealthCheck / CacheHealthCheck 探测超时按 `Unhealthy`
/// 聚合，避免 readiness 探针 hang 导致 kubelet 误杀 Pod（CWE-400 + readiness gate
/// 失效）；2s 留足 PG/MySQL/Redis ping 余量，低于 kubelet 默认超时构成。
#[cfg(any(feature = "db-postgres", feature = "db-mysql", feature = "cache-redis"))]
const HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(2);

/// 健康探测用的 key（不存在也无妨，仅触发底层 dao.get 网络往返）。
#[cfg(feature = "cache-redis")]
const HEALTH_PROBE_KEY: &str = "__garrison_health_probe__";

// ConfigHealthCheck：配置健康检查（always on）

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

// CacheHealthCheck：缓存健康检查（feature-gated）

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

// 快路径：仅 cache-memory（无 cache-redis）
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

// 探测路径：cache-redis 启用
// cache-redis 经网络连接 Redis，必须真实探测以发现连接断开 / 网络分区；经 `GarrisonManager`
// 取 dao 句柄执行 `dao.get` 最小查询（不修改 GarrisonDao trait，复用现有查询能力）。
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
            // manager 未初始化时返回 Unhealthy（而非 Err / 误报 Healthy），避免被转为通用 "check failed" 消息
            let logic = match GarrisonManager::logic() {
                Ok(l) => l,
                Err(_) => return Ok(HealthStatus::Unhealthy),
            };
            let dao: Arc<dyn GarrisonDao> = Arc::clone(logic.session.dao());
            // 探测：dao.get 包裹 timeout，Ok(_)（含 Ok(None)）→ Healthy，Err / 超时 → Unhealthy
            match tokio::time::timeout(HEALTH_PROBE_TIMEOUT, dao.get(HEALTH_PROBE_KEY)).await {
                Ok(Ok(_)) => Ok(HealthStatus::Healthy),
                Ok(Err(_)) => Ok(HealthStatus::Unhealthy),
                Err(_) => Ok(HealthStatus::Unhealthy),
            }
        })
    }
}

// DbHealthCheck：数据库健康检查（feature-gated）

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
impl DbHealthCheck {
    /// 创建数据库健康检查器（未注入连接池）；db-postgres / db-mysql 探测路径下未注入
    /// 连接池时探测返回 `Degraded`（不误报 `Healthy`），生产部署请配合 `with_pool` 注入。
    pub fn new() -> Self {
        #[cfg(any(feature = "db-postgres", feature = "db-mysql"))]
        {
            Self { pool: None }
        }
        #[cfg(not(any(feature = "db-postgres", feature = "db-mysql")))]
        {
            Self { _priv: () }
        }
    }

    /// 注入 SQL 连接池（db-postgres / db-mysql 探测路径）；注入后 readiness 探测执行
    /// 真实 pool ping，数据库宕机 / 连接池耗尽 / 网络分区时返回 `Unhealthy`，K8s 可正确摘流。
    #[cfg(any(feature = "db-postgres", feature = "db-mysql"))]
    pub fn with_pool(pool: dbnexus::DbPool) -> Self {
        Self {
            pool: Some(std::sync::Arc::new(pool)),
        }
    }
}

#[cfg(any(feature = "db-sqlite", feature = "db-postgres", feature = "db-mysql"))]
impl Default for DbHealthCheck {
    fn default() -> Self {
        Self::new()
    }
}

// 快路径：仅 db-sqlite（无 db-postgres / db-mysql）
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

// 探测路径：db-postgres 或 db-mysql 启用
// PG/MySQL 经网络连接数据库，必须真实探测以发现连接断开 / 池耗尽 / 网络分区；未注入
// 连接池时返回 `Degraded`（诚实降级，不误报 `Healthy`）。
#[cfg(any(feature = "db-postgres", feature = "db-mysql"))]
impl HealthCheck for DbHealthCheck {
    fn name(&self) -> &str {
        "database"
    }

    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthResult<HealthStatus>> + Send>>
    {
        // 克隆句柄（Arc）以脱离 &self 生命周期，满足 'static future 约束
        #[cfg(any(feature = "db-postgres", feature = "db-mysql"))]
        let pool = self.pool.clone();
        Box::pin(async move {
            // manager 未初始化时返回 Unhealthy（保持既有语义，而非 Err / 误报 Healthy）
            if GarrisonManager::logic().is_err() {
                return Ok(HealthStatus::Unhealthy);
            }
            // 未注入连接池 → 无法确证数据库可达，诚实降级
            let Some(pool) = pool.as_ref() else {
                tracing::warn!(
                    "DbHealthCheck: no pool injected (use DbHealthCheck::with_pool); \
                     reporting Degraded instead of Healthy"
                );
                return Ok(HealthStatus::Degraded);
            };
            // 探测：get_session + SELECT 1 真实往返包裹 timeout（相比 as_sea_orm 仅部分后端
            // cfg 可用，get_session 在 server-side 与 embedded 后端均可用，探测路径跨 feature
            // 组合一致）；Ok → Healthy，Err / 超时 → Unhealthy
            let ping = async {
                match pool.get_session("admin").await {
                    Ok(session) => session.execute_raw("SELECT 1").await.is_ok(),
                    Err(_) => false,
                }
            };
            match tokio::time::timeout(HEALTH_PROBE_TIMEOUT, ping).await {
                Ok(true) => Ok(HealthStatus::Healthy),
                _ => Ok(HealthStatus::Unhealthy),
            }
        })
    }
}
