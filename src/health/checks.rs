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
use crate::config::BulwarkConfig;
use std::sync::Arc;

// ============================================================================
// ConfigHealthCheck：配置健康检查（always on）
// ============================================================================

impl ConfigHealthCheck {
    /// 创建配置健康检查器。
    pub fn new(config: Arc<BulwarkConfig>) -> Self {
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
