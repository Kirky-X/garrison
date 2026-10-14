// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 健康检查层测试 mock 实现（`cfg(test)`）：`AlwaysHealthy` / `AlwaysUnhealthy` /
//! `AlwaysDegraded` 三个固定状态的 HealthCheck mock，供 `health::tests` 聚合测试复用。

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

/// 检查体 panic 的 HealthCheck mock（验证 `check_all` 的 panic 隔离）。
pub struct PanickingCheck;

impl HealthCheck for PanickingCheck {
    fn name(&self) -> &str {
        "panicking"
    }

    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthResult<HealthStatus>> + Send>>
    {
        Box::pin(async { panic!("probe blew up") })
    }
}

/// 检查体长时间挂起的 HealthCheck mock（验证 `check_all` 的超时护栏）。
pub struct HangingCheck;

impl HealthCheck for HangingCheck {
    fn name(&self) -> &str {
        "hanging"
    }

    fn check(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = HealthResult<HealthStatus>> + Send>>
    {
        Box::pin(async {
            tokio::time::sleep(std::time::Duration::from_secs(30)).await;
            Ok(HealthStatus::Healthy)
        })
    }
}
