//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! GarrisonMetrics 实现块（从 mod.rs 迁移）。

#[cfg(feature = "metrics-prometheus")]
use super::GarrisonMetrics;
#[cfg(feature = "metrics-prometheus")]
use std::time::Duration;

#[cfg(feature = "metrics-prometheus")]
impl GarrisonMetrics {
    /// 创建新的指标集合，注册到默认 registry（进程级单例，OnceLock 缓存）。
    ///
    /// # Panics
    ///
    /// 本方法**不会 panic**（ocr #6780/6923）：若默认 registry 已存在同名指标
    /// （重复调用 `new` / 与 `register_to(default_registry)` 混用），以
    /// `tracing::warn` 记录后返回一个未注册的本地实例（`record_*` / `gather()`
    /// 均可用，仅默认 registry 不再新增采集——已注册实例不受影响）。
    /// 生产环境建议使用 [`Self::register_to`] 注册到自定义 registry。
    pub fn new() -> Self {
        use std::sync::OnceLock;
        static INSTANCE: OnceLock<GarrisonMetrics> = OnceLock::new();
        INSTANCE.get_or_init(Self::init_default).clone()
    }

    /// `new()` 的单例初始化：注册默认 registry，冲突时 warn + 回退本地实例
    /// （与 `account::metrics::AccountMetrics::new` / `credit::metrics::CreditMetrics::new`
    /// 修复方式一致）。
    fn init_default() -> Self {
        match Self::register_to(prometheus::default_registry()) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "GarrisonMetrics 已注册到 prometheus 默认 registry（重复 new 或与 \
                     register_to 混用），返回未注册的本地实例；已注册实例不受影响"
                );
                // build() 仅在指标名/帮助文本非法时失败——静态字面量下不可达
                Self::build().expect("GarrisonMetrics: static metric opts are valid (unreachable)")
            },
        }
    }

    /// 创建并注册到指定 registry（用于自定义 registry 场景）。
    ///
    /// # 错误
    /// - 指标已注册：返回 `Err(prometheus::Error::AlreadyReg)`。
    pub fn register_to(registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        let metrics = Self::build()?;
        registry.register(Box::new(metrics.login_total.clone()))?;
        registry.register(Box::new(metrics.token_validation_duration.clone()))?;
        registry.register(Box::new(metrics.permission_query_total.clone()))?;
        registry.register(Box::new(metrics.role_query_total.clone()))?;
        Ok(metrics)
    }

    /// 构建指标集合（不注册到任何 registry；registry 字段暂存默认 registry 引用）。
    fn build() -> Result<Self, prometheus::Error> {
        let login_total = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "garrison_login_total",
                "Total number of login attempts (success|failure)",
            ),
            &["result"],
        )?;
        let token_validation_duration = prometheus::Histogram::with_opts(
            prometheus::HistogramOpts::new(
                "garrison_token_validation_duration_seconds",
                "Token validation duration in seconds",
            )
            .buckets(vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]),
        )?;
        let permission_query_total = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "garrison_permission_query_total",
                "Total number of permission queries (allow|deny)",
            ),
            &["result"],
        )?;
        let role_query_total = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "garrison_role_query_total",
                "Total number of role queries (allow|deny)",
            ),
            &["result"],
        )?;
        Ok(Self {
            login_total,
            token_validation_duration,
            permission_query_total,
            role_query_total,
            registry: prometheus::default_registry().clone(),
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
        // 从实例级 registry 收集（而非全局 default registry），保证自定义 registry 场景正确
        let metric_families = self.registry.gather();
        // Rule 12：编码失败显式记录 warn（不中断主流程，但禁止静默吞掉）
        if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
            tracing::warn!(error = %e, "GarrisonMetrics::gather prometheus encode failed");
        }
        String::from_utf8_lossy(&buffer).into_owned()
    }
}

#[cfg(feature = "metrics-prometheus")]
impl Default for GarrisonMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "metrics-prometheus")]
impl std::fmt::Debug for GarrisonMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GarrisonMetrics")
            .field("login_total", &"CounterVec")
            .field("token_validation_duration", &"Histogram")
            .field("permission_query_total", &"CounterVec")
            .field("role_query_total", &"CounterVec")
            .finish()
    }
}
