//! 账号安全能力 Prometheus 指标（v0.6.0 新增，依据 spec account-metrics D-001）。
//!
//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.
//!
//! 启用 `metrics-prometheus` feature 时编译，提供 4 个指标覆盖凭证验证 / 策略校验 /
//! 锁定触发 / 认证流程执行。未启用时 `AccountMetrics` 为 unit type 别名。
//!
//! # 指标清单（依据 spec account-metrics D-001）
//!
//! | 指标名 | 类型 | 标签 | 说明 |
//! |--------|------|------|------|
//! | `bulwark_credential_verify_duration_seconds` | Histogram | `credential_type` | 凭证验证耗时 |
//! | `bulwark_policy_validate_duration_seconds` | Histogram | `rule_name` | 密码策略校验耗时 |
//! | `bulwark_lockout_triggered_total` | Counter | `lockout_type=temporary\|permanent` | 锁定触发次数 |
//! | `bulwark_authflow_execute_duration_seconds` | Histogram | `flow_name` | 认证流程执行耗时 |
//!
//! # 集成点
//!
//! - `UserLockoutStrategy::record_failure`：触发锁定时调用 `record_lockout`
//! - `PasswordPolicyEngine::validate`：每条规则校验后调用 `observe_policy_validate`
//! - `AuthExecutor::execute_with_metrics`：流程执行前后计 `observe_authflow_execute`，
//!   Login/Mfa 步骤 `Credential::verify` 前后计 `observe_credential_verify`
//!
//! # Feature 门控
//!
//! 与 [`crate::observability::BulwarkMetrics`] 一致：未启用 `metrics-prometheus` 时
//! `AccountMetrics` 为 `()` 别名，调用方使用 `Option<Arc<AccountMetrics>>` 仍可编译。

#[cfg(feature = "metrics-prometheus")]
use std::time::Duration;

// ============================================================================
// AccountMetrics：账号安全指标集合（feature = "metrics-prometheus"）
// ============================================================================

/// 账号安全能力 Prometheus 指标集合（依据 spec account-metrics D-001）。
///
/// 模式与 [`crate::observability::BulwarkMetrics`] 一致：4 个指标注册到指定 registry，
/// 通过 `with_metrics` builder 注入到 `UserLockoutStrategy` / `PasswordPolicyEngine`，
/// 或作为 `AuthExecutor::execute_with_metrics` 的参数传入（保持 R-008 五字段约束）。
///
/// # 使用示例
///
/// ```ignore
/// use bulwark::account::metrics::AccountMetrics;
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// let metrics = Arc::new(AccountMetrics::new());
/// metrics.observe_credential_verify("password", Duration::from_millis(5));
/// metrics.record_lockout(true);
/// let output = metrics.gather();
/// assert!(output.contains("bulwark_credential_verify_duration_seconds"));
/// ```
#[cfg(feature = "metrics-prometheus")]
#[derive(Clone)]
pub struct AccountMetrics {
    /// 凭证验证耗时 Histogram（标签：credential_type）。
    credential_verify_duration: prometheus::HistogramVec,
    /// 密码策略校验耗时 Histogram（标签：rule_name）。
    policy_validate_duration: prometheus::HistogramVec,
    /// 锁定触发次数 Counter（标签：lockout_type=temporary|permanent）。
    lockout_triggered_total: prometheus::CounterVec,
    /// 认证流程执行耗时 Histogram（标签：flow_name）。
    authflow_execute_duration: prometheus::HistogramVec,
}

#[cfg(feature = "metrics-prometheus")]
impl AccountMetrics {
    /// 创建新的指标集合，注册到默认 registry。
    ///
    /// # 错误
    /// 若指标已注册（如多次调用 `new`），返回注册错误。生产环境建议使用 [`Self::register_to`]
    /// 注册到自定义 registry。
    pub fn new() -> Self {
        Self::register_to(prometheus::default_registry())
            .expect("AccountMetrics 注册到 default registry 失败：可能已注册")
    }

    /// 创建并注册到指定 registry（用于自定义 registry 场景，测试隔离）。
    ///
    /// # 错误
    /// - 指标已注册：返回 `Err(prometheus::Error::AlreadyReg)`。
    pub fn register_to(registry: &prometheus::Registry) -> Result<Self, prometheus::Error> {
        // Histogram buckets 与 BulwarkMetrics 一致
        let buckets = vec![0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0];

        let credential_verify_duration = prometheus::HistogramVec::new(
            prometheus::HistogramOpts::new(
                "bulwark_credential_verify_duration_seconds",
                "Credential verify duration in seconds",
            )
            .buckets(buckets.clone()),
            &["credential_type"],
        )?;
        let policy_validate_duration = prometheus::HistogramVec::new(
            prometheus::HistogramOpts::new(
                "bulwark_policy_validate_duration_seconds",
                "Password policy rule validate duration in seconds",
            )
            .buckets(buckets.clone()),
            &["rule_name"],
        )?;
        let lockout_triggered_total = prometheus::CounterVec::new(
            prometheus::Opts::new(
                "bulwark_lockout_triggered_total",
                "Total number of lockout triggered (temporary|permanent)",
            ),
            &["lockout_type"],
        )?;
        let authflow_execute_duration = prometheus::HistogramVec::new(
            prometheus::HistogramOpts::new(
                "bulwark_authflow_execute_duration_seconds",
                "Authentication flow execute duration in seconds",
            )
            .buckets(buckets),
            &["flow_name"],
        )?;

        registry.register(Box::new(credential_verify_duration.clone()))?;
        registry.register(Box::new(policy_validate_duration.clone()))?;
        registry.register(Box::new(lockout_triggered_total.clone()))?;
        registry.register(Box::new(authflow_execute_duration.clone()))?;

        Ok(Self {
            credential_verify_duration,
            policy_validate_duration,
            lockout_triggered_total,
            authflow_execute_duration,
        })
    }

    /// 观测一次凭证验证耗时。
    ///
    /// # 参数
    /// - `credential_type`: 凭证类型（如 `"password"` / `"totp"`）。
    /// - `duration`: 验证耗时。
    pub fn observe_credential_verify(&self, credential_type: &str, duration: Duration) {
        self.credential_verify_duration
            .with_label_values(&[credential_type])
            .observe(duration.as_secs_f64());
    }

    /// 观测一次密码策略规则校验耗时。
    ///
    /// # 参数
    /// - `rule_name`: 规则名称（如 `"length"` / `"complexity"`）。
    /// - `duration`: 校验耗时。
    pub fn observe_policy_validate(&self, rule_name: &str, duration: Duration) {
        self.policy_validate_duration
            .with_label_values(&[rule_name])
            .observe(duration.as_secs_f64());
    }

    /// 记录一次锁定触发。
    ///
    /// # 参数
    /// - `permanent`: `true` 永久锁定，`false` 临时锁定。
    pub fn record_lockout(&self, permanent: bool) {
        let label = if permanent { "permanent" } else { "temporary" };
        self.lockout_triggered_total
            .with_label_values(&[label])
            .inc();
    }

    /// 观测一次认证流程执行耗时。
    ///
    /// # 参数
    /// - `flow_name`: 流程名称（`AuthenticationFlow::name`）。
    /// - `duration`: 执行耗时。
    pub fn observe_authflow_execute(&self, flow_name: &str, duration: Duration) {
        self.authflow_execute_duration
            .with_label_values(&[flow_name])
            .observe(duration.as_secs_f64());
    }

    /// 收集所有指标为 Prometheus 文本格式。
    ///
    /// 用于暴露给 `/metrics` 端点供 Prometheus 抓取。
    /// 内部调用 `prometheus::gather()` 收集 default registry。
    pub fn gather(&self) -> String {
        use prometheus::Encoder;
        let mut buffer = Vec::new();
        let encoder = prometheus::TextEncoder::new();
        let metric_families = prometheus::gather();
        encoder.encode(&metric_families, &mut buffer).ok();
        String::from_utf8_lossy(&buffer).into_owned()
    }
}

#[cfg(feature = "metrics-prometheus")]
impl Default for AccountMetrics {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "metrics-prometheus")]
impl std::fmt::Debug for AccountMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountMetrics")
            .field("credential_verify_duration", &"HistogramVec")
            .field("policy_validate_duration", &"HistogramVec")
            .field("lockout_triggered_total", &"CounterVec")
            .field("authflow_execute_duration", &"HistogramVec")
            .finish()
    }
}

// ============================================================================
// 公共 API（feature 未启用时提供 no-op 占位，保证向后兼容）
// ============================================================================

/// 指标集合的 feature-gated 别名。
///
/// - `metrics-prometheus` 启用：解析为 [`AccountMetrics`](struct@AccountMetrics)
/// - 未启用：解析为 `()` unit type，调用方使用 `Option<Arc<AccountMetrics>>` 仍可编译
#[cfg(not(feature = "metrics-prometheus"))]
pub type AccountMetrics = ();

// ============================================================================
// 单元测试（依据 spec account-metrics D-001，每个 metric 至少 1 个测试）
// ============================================================================

#[cfg(all(test, feature = "metrics-prometheus"))]
mod tests {
    use super::*;
    use serial_test::serial;

    /// 测试 AccountMetrics 创建并注册到自定义 registry 成功，4 个指标名都出现在 gather 输出中。
    #[test]
    #[serial]
    fn account_metrics_register_to_custom_registry() {
        let registry = prometheus::Registry::new();
        let metrics = AccountMetrics::register_to(&registry).expect("注册到自定义 registry 失败");
        // 先观测/记录一次，确保 HistogramVec/CounterVec 在 gather 输出中可见
        metrics.observe_credential_verify("password", Duration::from_millis(1));
        metrics.observe_policy_validate("length", Duration::from_millis(1));
        metrics.record_lockout(false);
        metrics.observe_authflow_execute("login", Duration::from_millis(1));

        let gathered = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        assert!(
            gathered.contains("bulwark_credential_verify_duration_seconds"),
            "missing credential_verify_duration: {}",
            gathered
        );
        assert!(
            gathered.contains("bulwark_policy_validate_duration_seconds"),
            "missing policy_validate_duration: {}",
            gathered
        );
        assert!(
            gathered.contains("bulwark_lockout_triggered_total"),
            "missing lockout_triggered_total: {}",
            gathered
        );
        assert!(
            gathered.contains("bulwark_authflow_execute_duration_seconds"),
            "missing authflow_execute_duration: {}",
            gathered
        );
    }

    /// 测试 observe_credential_verify 记录 credential_type 标签 + count。
    #[test]
    #[serial]
    fn credential_verify_duration_registered_and_observed() {
        let registry = prometheus::Registry::new();
        let metrics = AccountMetrics::register_to(&registry).unwrap();
        metrics.observe_credential_verify("password", Duration::from_millis(5));
        metrics.observe_credential_verify("password", Duration::from_millis(10));
        metrics.observe_credential_verify("totp", Duration::from_millis(3));

        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .unwrap();
        assert!(
            output.contains("bulwark_credential_verify_duration_seconds"),
            "missing metric name: {}",
            output
        );
        assert!(
            output.contains("credential_type=\"password\""),
            "missing password label: {}",
            output
        );
        assert!(
            output.contains("credential_type=\"totp\""),
            "missing totp label: {}",
            output
        );
        // password 标签应观测 2 次
        assert!(
            output.contains(
                "bulwark_credential_verify_duration_seconds_count{credential_type=\"password\"} 2"
            ),
            "password count should be 2: {}",
            output
        );
    }

    /// 测试 observe_policy_validate 记录 rule_name 标签 + count。
    #[test]
    #[serial]
    fn policy_validate_duration_registered_and_observed() {
        let registry = prometheus::Registry::new();
        let metrics = AccountMetrics::register_to(&registry).unwrap();
        metrics.observe_policy_validate("length", Duration::from_millis(2));
        metrics.observe_policy_validate("complexity", Duration::from_millis(4));

        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .unwrap();
        assert!(
            output.contains("bulwark_policy_validate_duration_seconds"),
            "missing metric name: {}",
            output
        );
        assert!(
            output.contains("rule_name=\"length\""),
            "missing length label: {}",
            output
        );
        assert!(
            output.contains("rule_name=\"complexity\""),
            "missing complexity label: {}",
            output
        );
        assert!(
            output
                .contains("bulwark_policy_validate_duration_seconds_count{rule_name=\"length\"} 1"),
            "length count should be 1: {}",
            output
        );
    }

    /// 测试 record_lockout 分别递增 temporary / permanent 标签。
    #[test]
    #[serial]
    fn lockout_triggered_total_registered_and_recorded() {
        let registry = prometheus::Registry::new();
        let metrics = AccountMetrics::register_to(&registry).unwrap();
        metrics.record_lockout(false); // temporary
        metrics.record_lockout(false); // temporary
        metrics.record_lockout(true); // permanent

        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .unwrap();
        assert!(
            output.contains("bulwark_lockout_triggered_total"),
            "missing metric name: {}",
            output
        );
        assert!(
            output.contains("lockout_type=\"temporary\""),
            "missing temporary label: {}",
            output
        );
        assert!(
            output.contains("lockout_type=\"permanent\""),
            "missing permanent label: {}",
            output
        );
        assert!(
            output.contains("bulwark_lockout_triggered_total{lockout_type=\"temporary\"} 2"),
            "temporary count should be 2: {}",
            output
        );
        assert!(
            output.contains("bulwark_lockout_triggered_total{lockout_type=\"permanent\"} 1"),
            "permanent count should be 1: {}",
            output
        );
    }

    /// 测试 observe_authflow_execute 记录 flow_name 标签 + count。
    #[test]
    #[serial]
    fn authflow_execute_duration_registered_and_observed() {
        let registry = prometheus::Registry::new();
        let metrics = AccountMetrics::register_to(&registry).unwrap();
        metrics.observe_authflow_execute("login", Duration::from_millis(50));
        metrics.observe_authflow_execute("mfa", Duration::from_millis(20));

        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .unwrap();
        assert!(
            output.contains("bulwark_authflow_execute_duration_seconds"),
            "missing metric name: {}",
            output
        );
        assert!(
            output.contains("flow_name=\"login\""),
            "missing login label: {}",
            output
        );
        assert!(
            output.contains("flow_name=\"mfa\""),
            "missing mfa label: {}",
            output
        );
        assert!(
            output
                .contains("bulwark_authflow_execute_duration_seconds_count{flow_name=\"login\"} 1"),
            "login count should be 1: {}",
            output
        );
    }

    /// 测试 register_to 重复注册返回 AlreadyReg 错误。
    #[test]
    #[serial]
    fn duplicate_register_returns_already_reg_error() {
        let registry = prometheus::Registry::new();
        let _m1 = AccountMetrics::register_to(&registry).expect("首次注册失败");
        let result = AccountMetrics::register_to(&registry);
        assert!(result.is_err(), "重复注册应返回错误");
        match result {
            Err(prometheus::Error::AlreadyReg) => {},
            Err(e) => panic!("期望 AlreadyReg 错误，实际: {:?}", e),
            Ok(_) => panic!("期望错误，实际成功"),
        }
    }

    /// 测试 Clone trait（用于 Arc<AccountMetrics> 在多线程共享场景）。
    #[test]
    #[serial]
    fn account_metrics_clone_shared_underlying_state() {
        let registry = prometheus::Registry::new();
        let m1 = AccountMetrics::register_to(&registry).expect("注册失败");
        let m2 = m1.clone();
        m1.record_lockout(false);
        m2.record_lockout(false);
        // 两个 clone 共享底层 Counter，应都记录
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .unwrap();
        assert!(
            output.contains("bulwark_lockout_triggered_total{lockout_type=\"temporary\"} 2"),
            "clone 应共享底层 Counter: {}",
            output
        );
    }

    /// 测试 Debug trait 实现输出字段名与类型名。
    #[test]
    #[serial]
    fn account_metrics_debug_impl() {
        let registry = prometheus::Registry::new();
        let metrics = AccountMetrics::register_to(&registry).expect("注册失败");
        let debug_str = format!("{:?}", metrics);
        assert!(debug_str.contains("AccountMetrics"));
        assert!(debug_str.contains("HistogramVec"));
        assert!(debug_str.contains("CounterVec"));
    }
}

/// 无 feature 时的编译验证测试（确保向后兼容）。
#[cfg(all(test, not(feature = "metrics-prometheus")))]
mod tests_no_feature {
    use super::*;

    /// 未启用 metrics-prometheus 时 AccountMetrics 为 unit type 别名。
    #[test]
    fn no_feature_account_metrics_is_unit() {
        let _: AccountMetrics = ();
    }
}
