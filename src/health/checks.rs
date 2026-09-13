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
// 探测路径（cache-redis）专用 import：db-postgres/db-mysql 探测改为 pool ping 后
// 不再使用 GarrisonDao（T010），避免未使用导入告警
#[cfg(feature = "cache-redis")]
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
#[cfg(feature = "cache-redis")]
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
    /// 创建数据库健康检查器（未注入连接池）。
    ///
    /// db-postgres / db-mysql 探测路径下，未注入连接池时探测返回 `Degraded`
    /// （T010：不误报 `Healthy`）。生产部署请配合 `DbHealthCheck::with_pool`
    /// 注入连接池使用。
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

    /// 注入 SQL 连接池（db-postgres / db-mysql 探测路径，T010）。
    ///
    /// 注入后 readiness 探测执行真实 pool ping（SELECT 1 语义）：
    /// 数据库宕机 / 连接池耗尽 / 网络分区时返回 `Unhealthy`，K8s 可正确摘流。
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
// T010：探测目标从内存 KV DAO（dao.get 委托进程内存储，无法反映数据库状态）
// 改为注入连接池的真实 ping（`DbPool::as_sea_orm` → `DatabaseConnection::ping`）。
// 未注入连接池时返回 `Degraded`（诚实降级，不误报 `Healthy`）。
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
            // T010: 未注入连接池 → 无法确证数据库可达，诚实降级
            let Some(pool) = pool.as_ref() else {
                tracing::warn!(
                    "DbHealthCheck: no pool injected (use DbHealthCheck::with_pool); \
                     reporting Degraded instead of Healthy"
                );
                return Ok(HealthStatus::Degraded);
            };
            // 探测：真实 SQL 往返（get_session + SELECT 1）包裹 timeout。
            // 相比 as_sea_orm（仅部分后端 cfg 可用），get_session/execute_raw
            // 在 server-side 与 embedded 后端均可用，探测路径跨 feature 组合一致。
            // Ok → 数据库可达 → Healthy；Err / 超时 → 不可达 → Unhealthy
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
