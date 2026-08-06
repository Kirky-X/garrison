//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Credit 计量 Prometheus 指标。
//!
//! 启用 `metrics-prometheus` feature 时编译，提供 3 个指标覆盖 credit 消费/剩余/告警。
//! 未启用时 `CreditMetrics` 为 `()` 别名，调用方代码无需条件编译。
//!
//! # 指标清单
//!
//! | 指标名 | 类型 | 标签 | 说明 |
//! |--------|------|------|------|
//! | `garrison_credit_consumed_total` | Counter | `tenant_id`, `resource` | credit 消费总量 |
//! | `garrison_credit_remaining` | Gauge | `tenant_id` | 当前剩余 credit |
//! | `garrison_credit_alerts_total` | Counter | `tenant_id`, `threshold` | 告警触发次数 |
//!
//! # 集成点
//!
//! - `CreditMeter::consume_credit`：消费成功后调用 `record_consumed` + `set_remaining`
//! - `CreditMeter::consume_credit`：告警阈值触发时调用 `record_alert`

// ============================================================================
// CreditMetrics：Credit 计量指标集合（feature = "metrics-prometheus"）
// ============================================================================

/// Credit 计量 Prometheus 指标集合。
///
/// 模式与 `crate::account::metrics::AccountMetrics` 一致：3 个指标注册到指定 registry，
/// 通过 `CreditMeter` 内部持有 `Option<Arc<CreditMetrics>>` 注入。
///
/// # 使用示例
///
/// ```ignore
/// use garrison::credit::metrics::CreditMetrics;
/// use std::sync::Arc;
///
/// let metrics = Arc::new(CreditMetrics::new());
/// metrics.record_consumed("42", "login", 5);
/// metrics.set_remaining("42", 9995);
/// metrics.record_alert("42", 80);
/// ```
#[cfg(feature = "metrics-prometheus")]
#[derive(Clone)]
pub struct CreditMetrics {
    /// credit 消费总量 Counter（标签：tenant_id, resource）。
    consumed_total: prometheus::CounterVec,
    /// 当前剩余 credit Gauge（标签：tenant_id）。
    remaining: prometheus::GaugeVec,
    /// 告警触发次数 Counter（标签：tenant_id, threshold）。
    alerts_total: prometheus::CounterVec,
}

#[cfg(feature = "metrics-prometheus")]
impl CreditMetrics {
    /// 创建新的指标集合，注册到默认 registry。
    ///
    /// # 错误
    /// 若指标已注册（如多次调用 `new`），返回注册错误。生产环境建议使用 [`Self::register_to`]
    /// 注册到自定义 registry。
    pub fn new() -> Self {
        use std::sync::OnceLock;
        static INSTANCE: OnceLock<CreditMetrics> = OnceLock::new();
        INSTANCE
            .get_or_init(|| {
                Self::register_to(prometheus::default_registry())
                    .expect("CreditMetrics 注册到 default registry 失败：可能已注册")
            })
            .clone()
    }

    /// 创建并注册到指定 registry（用于自定义 registry 场景，测试隔离）。
    ///
    /// # 错误
    /// - 指标已注册：返回 `Err(prometheus::Error::AlreadyReg)`。
    pub fn register_to(registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        let consumed_total = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "garrison_credit_consumed_total",
                "Total credit consumed (tenant-level metering)",
            ),
            &["tenant_id", "resource"],
        )?;
        let remaining = prometheus::GaugeVec::new(
            prometheus::Opts::new(
                "garrison_credit_remaining",
                "Current remaining credit for tenant",
            ),
            &["tenant_id"],
        )?;
        let alerts_total = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "garrison_credit_alerts_total",
                "Total credit alert threshold triggers",
            ),
            &["tenant_id", "threshold"],
        )?;

        registry.register(Box::new(consumed_total.clone()))?;
        registry.register(Box::new(remaining.clone()))?;
        registry.register(Box::new(alerts_total.clone()))?;

        Ok(Self {
            consumed_total,
            remaining,
            alerts_total,
        })
    }

    /// 记录一次 credit 消费。
    ///
    /// # 参数
    /// - `tenant_id`: 租户 ID（字符串化标签）。
    /// - `resource`: 消费的资源类型（如 `"login"` / `"api_call"`）。
    /// - `credits`: 本次消耗的 credit 数。
    pub fn record_consumed(&self, tenant_id: &str, resource: &str, credits: u64) {
        self.consumed_total
            .with_label_values(&[tenant_id, resource])
            .inc_by(credits as f64);
    }

    /// 设置当前剩余 credit。
    ///
    /// # 参数
    /// - `tenant_id`: 租户 ID（字符串化标签）。
    /// - `remaining_credits`: 剩余 credit 数。
    pub fn set_remaining(&self, tenant_id: &str, remaining_credits: u64) {
        self.remaining
            .with_label_values(&[tenant_id])
            .set(remaining_credits as f64);
    }

    /// 记录一次告警阈值触发。
    ///
    /// # 参数
    /// - `tenant_id`: 租户 ID（字符串化标签）。
    /// - `threshold`: 触发的告警阈值（百分比，如 `80` / `90` / `100`）。
    pub fn record_alert(&self, tenant_id: &str, threshold: u8) {
        self.alerts_total
            .with_label_values(&[tenant_id, &threshold.to_string()])
            .inc();
    }

    /// 收集所有指标为 Prometheus 文本格式。
    ///
    /// 用于暴露给 `/metrics` 端点供 Prometheus 抓取。
    /// 不依赖外部 registry，直接从字段调用 `Collector::collect`。
    pub fn gather(&self) -> String {
        use prometheus::core::Collector;
        use prometheus::Encoder;
        let mut metric_families = Vec::new();
        metric_families.extend(self.consumed_total.collect());
        metric_families.extend(self.remaining.collect());
        metric_families.extend(self.alerts_total.collect());
        let mut buffer = Vec::new();
        let encoder = prometheus::TextEncoder::new();
        if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
            tracing::warn!(error = %e, "CreditMetrics::gather prometheus encode failed");
        }
        String::from_utf8_lossy(&buffer).into_owned()
    }
}

#[cfg(feature = "metrics-prometheus")]
impl Default for CreditMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "metrics-prometheus")]
impl std::fmt::Debug for CreditMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CreditMetrics")
            .field("consumed_total", &"CounterVec")
            .field("remaining", &"GaugeVec")
            .field("alerts_total", &"CounterVec")
            .finish()
    }
}

// ============================================================================
// 公共 API（feature 未启用时提供 no-op 占位，保证向后兼容）
// ============================================================================

/// 指标集合的 feature-gated 别名。
///
/// - `metrics-prometheus` 启用：解析为 [`CreditMetrics`]
/// - 未启用：解析为 `()` unit type，`Option<Arc<CreditMetrics>>` 仍可编译
#[cfg(not(feature = "metrics-prometheus"))]
pub type CreditMetrics = ();

#[cfg(all(test, feature = "metrics-prometheus"))]
mod tests {
    use super::*;
    use serial_test::serial;

    /// CreditMetrics 注册到自定义 registry 成功，3 个指标名出现在 gather 输出中。
    #[test]
    #[serial]
    fn credit_metrics_register_to_custom_registry() {
        let registry = prometheus::Registry::new();
        let metrics = CreditMetrics::register_to(&registry).expect("注册到自定义 registry 失败");
        metrics.record_consumed("42", "login", 5);
        metrics.set_remaining("42", 9995);
        metrics.record_alert("42", 80);

        let gathered = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        assert!(
            gathered.contains("garrison_credit_consumed_total"),
            "missing credit_consumed_total: {}",
            gathered
        );
        assert!(
            gathered.contains("garrison_credit_remaining"),
            "missing credit_remaining: {}",
            gathered
        );
        assert!(
            gathered.contains("garrison_credit_alerts_total"),
            "missing credit_alerts_total: {}",
            gathered
        );
    }

    /// record_consumed 记录 tenant_id + resource 标签。
    #[test]
    #[serial]
    fn credit_consumed_total_labels() {
        let registry = prometheus::Registry::new();
        let metrics = CreditMetrics::register_to(&registry).unwrap();
        metrics.record_consumed("42", "login", 1);
        metrics.record_consumed("42", "api_call", 5);
        metrics.record_consumed("99", "login", 1);

        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .unwrap();
        assert!(
            output.contains("tenant_id=\"42\"") && output.contains("resource=\"login\""),
            "missing tenant 42 login: {}",
            output
        );
        assert!(
            output.contains("resource=\"api_call\""),
            "missing api_call: {}",
            output
        );
    }

    /// set_remaining 设置 Gauge 值。
    #[test]
    #[serial]
    fn credit_remaining_gauge() {
        let registry = prometheus::Registry::new();
        let metrics = CreditMetrics::register_to(&registry).unwrap();
        metrics.set_remaining("42", 5000);

        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .unwrap();
        assert!(
            output.contains("garrison_credit_remaining{tenant_id=\"42\"} 5000"),
            "remaining should be 5000: {}",
            output
        );
    }

    /// record_alert 记录 threshold 标签。
    #[test]
    #[serial]
    fn credit_alerts_total_labels() {
        let registry = prometheus::Registry::new();
        let metrics = CreditMetrics::register_to(&registry).unwrap();
        metrics.record_alert("42", 80);
        metrics.record_alert("42", 80);
        metrics.record_alert("42", 90);

        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .unwrap();
        assert!(
            output.contains("threshold=\"80\""),
            "missing threshold 80: {}",
            output
        );
        assert!(
            output.contains("threshold=\"90\""),
            "missing threshold 90: {}",
            output
        );
        assert!(
            output.contains("garrison_credit_alerts_total{tenant_id=\"42\",threshold=\"80\"} 2"),
            "threshold 80 count should be 2: {}",
            output
        );
    }

    /// 重复注册返回 AlreadyReg 错误。
    #[test]
    #[serial]
    fn duplicate_register_returns_error() {
        let registry = prometheus::Registry::new();
        let _m1 = CreditMetrics::register_to(&registry).expect("首次注册失败");
        let result = CreditMetrics::register_to(&registry);
        assert!(result.is_err(), "重复注册应返回错误");
        match result {
            Err(prometheus::Error::AlreadyReg) => {},
            Err(e) => panic!("期望 AlreadyReg 错误，实际: {:?}", e),
            Ok(_) => panic!("期望错误，实际成功"),
        }
    }

    /// Clone 共享底层状态。
    #[test]
    #[serial]
    fn clone_shares_state() {
        let registry = prometheus::Registry::new();
        let m1 = CreditMetrics::register_to(&registry).unwrap();
        let m2 = m1.clone();
        m1.record_consumed("1", "login", 3);
        m2.record_consumed("1", "login", 7);

        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .unwrap();
        assert!(
            output
                .contains("garrison_credit_consumed_total{resource=\"login\",tenant_id=\"1\"} 10"),
            "clones should share underlying Counter: {}",
            output
        );
    }

    /// gather() 返回非空字符串。
    #[test]
    #[serial]
    fn gather_non_empty() {
        let registry = prometheus::Registry::new();
        let metrics = CreditMetrics::register_to(&registry).unwrap();
        metrics.record_consumed("1", "login", 1);
        let output = metrics.gather();
        assert!(!output.is_empty(), "gather() 应返回非空字符串");
    }
}

/// 无 feature 时的编译验证测试。
#[cfg(all(test, not(feature = "metrics-prometheus")))]
mod tests_no_feature {
    use super::*;

    /// 未启用 metrics-prometheus 时 CreditMetrics 为 unit type 别名。
    #[test]
    fn no_feature_credit_metrics_is_unit() {
        let _: CreditMetrics = ();
    }
}
