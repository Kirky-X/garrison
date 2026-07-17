//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `HealthRegistry` 实现：构造、注册、并发执行与状态聚合。

use super::{CheckResult, HealthCheck, HealthRegistry, HealthReport, HealthStatus};

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
    /// 使用 `futures::future::join_all` 并发调度，避免单检查阻塞 readiness 探针热路径
    /// 导致 kubelet 超时和 Pod 重启。
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

        // 并发调度：所有 check() 同时执行，join_all 等待全部完成
        let futures: Vec<_> = self
            .checks
            .iter()
            .map(|check| {
                let name = check.name().to_string();
                async move {
                    let result = check.check().await;
                    (name, result)
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
