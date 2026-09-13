//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `HealthRegistry` 实现：构造、注册、并发执行与状态聚合。

use super::{CheckResult, HealthCheck, HealthRegistry, HealthReport, HealthStatus};
use crate::error::GarrisonError;
use futures::FutureExt;
use std::panic::AssertUnwindSafe;
use std::time::Duration;

/// 单项健康检查默认超时（秒）。
const DEFAULT_CHECK_TIMEOUT_SECS: u64 = 5;

impl HealthRegistry {
    /// 创建空 registry（单项检查超时默认 5 秒，可用 [`Self::with_check_timeout`] 调整）。
    pub fn new() -> Self {
        Self {
            checks: Vec::new(),
            check_timeout: Duration::from_secs(DEFAULT_CHECK_TIMEOUT_SECS),
        }
    }

    /// 设置单项健康检查的超时阈值（ocr #5514/5515/5358/5362）。
    ///
    /// 超时的检查按 `Unhealthy` 聚合，不会拖住整个 readiness 请求。
    pub fn with_check_timeout(mut self, timeout: Duration) -> Self {
        self.check_timeout = timeout;
        self
    }

    /// 注册一个健康检查器。
    pub fn register(&mut self, check: Box<dyn HealthCheck>) -> &mut Self {
        self.checks.push(check);
        self
    }

    /// 并发执行所有注册的检查器，聚合结果。
    ///
    /// 使用 `futures::future::join_all` 并发调度，避免单检查阻塞 readiness 探针热路径
    /// 导致 kubelet 超时和 Pod 重启。
    ///
    /// 每项检查均有两级护栏（ocr #5514/5515/5358/5362、#6596）：
    /// - **超时**：单项检查超过 `check_timeout`（默认 5 秒，可用
    ///   [`Self::with_check_timeout`] 配置）按 `Unhealthy` 聚合，不会无限阻塞请求；
    /// - **panic 隔离**：单个检查 panic 被 `catch_unwind` 捕获并降级为该检查
    ///   `Unhealthy`，不再中止整个 `check_all()`。注意 release profile 配置
    ///   `panic = "abort"` 时此隔离退化为进程终止（见 Cargo.toml 说明）。
    ///
    /// 聚合规则：
    /// - 任一 `Unhealthy`（含超时/panic/返回 Err）→ 整体 `Unhealthy`
    /// - 任一 `Degraded` 且无 `Unhealthy` → 整体 `Degraded`
    /// - 全部 `Healthy` → 整体 `Healthy`
    /// - 空 registry → 整体 `Healthy`
    pub async fn check_all(&self) -> HealthReport {
        if self.checks.is_empty() {
            return HealthReport::empty();
        }

        // 并发调度：所有 check() 同时执行，join_all 等待全部完成
        let futures: Vec<_> = self
            .checks
            .iter()
            .map(|check| {
                let name = check.name().to_string();
                let timeout = self.check_timeout;
                async move {
                    // panic 隔离（AssertUnwindSafe：dyn HealthCheck 不承诺 UnwindSafe，
                    // 此处仅隔离 panic 不重入检查器，跨 catch_unwind 使用安全）
                    let checked = AssertUnwindSafe(check.check()).catch_unwind();
                    match tokio::time::timeout(timeout, checked).await {
                        Ok(Ok(Ok(status))) => (name, Ok(status)),
                        Ok(Ok(Err(e))) => (name, Err(e)),
                        Ok(Err(panic_payload)) => {
                            let msg = panic_payload
                                .downcast_ref::<&str>()
                                .map(|s| (*s).to_string())
                                .or_else(|| panic_payload.downcast_ref::<String>().cloned())
                                .unwrap_or_else(|| "unknown panic".to_string());
                            tracing::warn!(check = %name, panic = %msg, "health check panicked");
                            (
                                name,
                                Err(GarrisonError::Internal("health-check-panicked".to_string())),
                            )
                        },
                        Err(_elapsed) => {
                            tracing::warn!(
                                check = %name,
                                timeout_secs = timeout.as_secs(),
                                "health check timed out"
                            );
                            (
                                name,
                                Err(GarrisonError::Internal(format!(
                                    "health-check-timeout::{}s",
                                    timeout.as_secs()
                                ))),
                            )
                        },
                    }
                }
            })
            .collect();

        let raw_results = futures::future::join_all(futures).await;

        // 聚合：错误信息仅记录通用描述（不泄漏内部细节到 /health/ready 响应）
        let mut results = Vec::with_capacity(raw_results.len());
        for (name, result) in raw_results {
            match result {
                Ok(status) => results.push(CheckResult {
                    name,
                    status,
                    message: None,
                }),
                Err(e) => {
                    // 完整错误用 tracing::warn! 记录到日志（运维可见），不通过 HTTP 响应暴露
                    tracing::warn!(
                        check = %name,
                        error = %e,
                        "health check failed"
                    );
                    results.push(CheckResult {
                        name,
                        status: HealthStatus::Unhealthy,
                        message: Some("check failed".to_string()),
                    });
                },
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
