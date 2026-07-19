//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! BulwarkMetrics 实现块（从 mod.rs 迁移）。

#[cfg(feature = "metrics-prometheus")]
use super::BulwarkMetrics;
#[cfg(feature = "metrics-prometheus")]
use std::time::Duration;

#[cfg(feature = "metrics-prometheus")]
impl BulwarkMetrics {
    /// 创建新的指标集合，注册到默认 registry。
    ///
    /// # 错误
    /// 若指标已注册（如多次调用 `new`），返回注册错误。生产环境建议使用 [`Self::register_to`]
    /// 注册到自定义 registry。
    pub fn new() -> Self {
        Self::register_to(prometheus::default_registry())
            .expect("BulwarkMetrics 注册到 default registry 失败：可能已注册")
    }

    /// 创建并注册到指定 registry（用于自定义 registry 场景）。
    ///
    /// # 错误
    /// - 指标已注册：返回 `Err(prometheus::Error::AlreadyReg)`。
    pub fn register_to(registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        let login_total = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "bulwark_login_total",
                "Total number of login attempts (success|failure)",
            ),
            &["result"],
        )?;
        let token_validation_duration = prometheus::Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "bulwark_token_validation_duration_seconds",
                "Token validation duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
        )?;
        let permission_query_total = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "bulwark_permission_query_total",
                "Total number of permission queries (allow|deny)",
            ),
            &["result"],
        )?;
        let role_query_total = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "bulwark_role_query_total",
                "Total number of role queries (allow|deny)",
            ),
            &["result"],
        )?;
        registry.register(Box::new(login_total.clone()))?;
        registry.register(Box::new(token_validation_duration.clone()))?;
        registry.register(Box::new(permission_query_total.clone()))?;
        registry.register(Box::new(role_query_total.clone()))?;
        Ok(Self {
            login_total,
            token_validation_duration,
            permission_query_total,
            role_query_total,
        })
    }

    /// 记录一次登录尝试。
    ///
    /// # 参数
    /// - `success`: `true` 成功，`false` 失败。
    pub fn record_login(&self, success: bool) {
        let label = if success { "success" } else { "failure" };
        self.login_total.with_label_values(&[label]).inc();
    }

    /// 观测一次 Token 验证的耗时。
    ///
    /// # 参数
    /// - `duration`: 验证耗时。
    pub fn observe_token_validation(&self, duration: Duration) {
        self.token_validation_duration
            .observe(duration.as_secs_f64());
    }

    /// 记录一次权限查询。
    ///
    /// # 参数
    /// - `allowed`: `true` 允许，`false` 拒绝。
    pub fn record_permission_query(&self, allowed: bool) {
        let label = if allowed { "allow" } else { "deny" };
        self.permission_query_total
            .with_label_values(&[label])
            .inc();
    }

    /// 记录一次角色查询。
    ///
    /// # 参数
    /// - `allowed`: `true` 允许，`false` 拒绝。
    pub fn record_role_query(&self, allowed: bool) {
        let label = if allowed { "allow" } else { "deny" };
        self.role_query_total.with_label_values(&[label]).inc();
    }

    /// 收集所有指标为 Prometheus 文本格式。
    ///
    /// 用于暴露给 `/metrics` 端点供 Prometheus 抓取。
    pub fn gather(&self) -> String {
        use prometheus::Encoder;
        let mut buffer = Vec::new();
        let encoder = prometheus::TextEncoder::new();
        // 收集 default registry（包含 BulwarkMetrics 注册的所有指标）
        let metric_families = prometheus::gather();
        // Rule 12：编码失败显式记录 warn（不中断主流程，但禁止静默吞掉）
        if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
            tracing::warn!(error = %e, "BulwarkMetrics::gather prometheus encode failed");
        }
        String::from_utf8_lossy(&buffer).into_owned()
    }
}

#[cfg(feature = "metrics-prometheus")]
impl Default for BulwarkMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "metrics-prometheus")]
impl std::fmt::Debug for BulwarkMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BulwarkMetrics")
            .field("login_total", &"CounterVec")
            .field("token_validation_duration", &"Histogram")
            .field("permission_query_total", &"CounterVec")
            .field("role_query_total", &"CounterVec")
            .finish()
    }
}
