//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 健康检查层测试 mock 实现。
//!
//! 本模块仅在 `cfg(test)` 下编译（通过 `mod.rs` 中的 `#[cfg(test)] mod mock;` 声明），
//! 提供 `AlwaysHealthy` / `AlwaysUnhealthy` / `AlwaysDegraded` 三个固定状态的 HealthCheck mock，
//! 供 `health::tests` HealthRegistry 聚合测试复用。

use super::{HealthCheck, HealthResult, HealthStatus};
use crate::error::GarrisonError;

/// 始终返回 Healthy 的 HealthCheck mock。
pub struct AlwaysHealthy;

impl HealthCheck for AlwaysHealthy {
    fn name(&self) -> &str {
        "always-healthy"
    }

    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthResult<HealthStatus>> + Send>>
    {
        Box::pin(async { Ok(HealthStatus::Healthy) })
    }
}

/// 始终返回 Err 的 HealthCheck mock（聚合状态为 Unhealthy）。
pub struct AlwaysUnhealthy;

impl HealthCheck for AlwaysUnhealthy {
    fn name(&self) -> &str {
        "always-unhealthy"
    }

    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthResult<HealthStatus>> + Send>>
    {
        Box::pin(async {
            Err(GarrisonError::Internal(
                "dependency unavailable".to_string(),
            ))
        })
    }
}

/// 始终返回 Degraded 的 HealthCheck mock。
pub struct AlwaysDegraded;

impl HealthCheck for AlwaysDegraded {
    fn name(&self) -> &str {
        "always-degraded"
    }

    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthResult<HealthStatus>> + Send>>
    {
        Box::pin(async { Ok(HealthStatus::Degraded) })
    }
}
