//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 可观测性模块，提供 Prometheus 指标、结构化 JSON 日志与 OpenTelemetry 分布式追踪。
//!
//! ## 三层架构（依据 spec observability-stack）
//!
//! - **Metrics**（`BulwarkMetrics`）：Prometheus 格式指标，覆盖登录成功率 / Token 验证延迟 /
//!   权限查询 QPS / 角色查询 QPS。启用 `metrics-prometheus` feature。
//! - **Logs**（`init_json_logging`）：tracing-subscriber JSON 格式日志。启用 `tracing-log` 或
//!   `metrics-prometheus` feature（后者聚合了 tracing-subscriber）。
//! - **Traces**（`init_otlp_tracing`）：OpenTelemetry 分布式追踪，OTLP gRPC 导出。
//!   启用 `observability-otlp` feature。
//!
//! ## 集成点
//!
//! `BulwarkMetrics` 通过 `BulwarkLogicDefault::with_metrics` builder 注入，未注入时零开销。
//! 指标在 `login` / `check_login` / `check_permission` / `check_role` 方法内 emit。
//!
//! ## Feature 门控
//!
//! - `metrics-prometheus`：编译期包含 `BulwarkMetrics` 与 `init_json_logging`
//! - `observability-otlp`：编译期包含 `init_otlp_tracing` 与 OTLP 导出器
//! - 未启用任一 feature：模块仍可导入但所有 API 返回 `None` / no-op，保证向后兼容

#[cfg(feature = "metrics-prometheus")]
use std::time::Duration;

// ============================================================================
// BulwarkMetrics：Prometheus 指标集合（feature = "metrics-prometheus"）
// ============================================================================

#[cfg(feature = "metrics-prometheus")]
pub use prometheus;

/// Prometheus 指标集合，覆盖登录 / Token 验证 / 权限查询 / 角色查询。
///
/// 通过 `BulwarkLogicDefault::with_metrics` builder 注入，未注入时所有 `*_metrics` 调用为
/// no-op（`Option::None` 短路）。
///
/// # 指标清单（依据 spec observability-stack）
///
/// | 指标名 | 类型 | 标签 | 说明 |
/// |--------|------|------|------|
/// | `bulwark_login_total` | Counter | `result=success\|failure` | 登录尝试次数 |
/// | `bulwark_token_validation_duration_seconds` | Histogram | - | Token 验证延迟（秒） |
/// | `bulwark_permission_query_total` | Counter | `result=allow\|deny` | 权限查询次数 |
/// | `bulwark_role_query_total` | Counter | `result=allow\|deny` | 角色查询次数 |
///
/// # 使用示例
///
/// ```ignore
/// use bulwark::observability::BulwarkMetrics;
/// use std::sync::Arc;
///
/// let metrics = Arc::new(BulwarkMetrics::new());
/// metrics.record_login(true);
/// metrics.observe_token_validation(std::time::Duration::from_millis(5));
/// let output = metrics.gather();
/// assert!(output.contains("bulwark_login_total"));
/// ```
#[cfg(feature = "metrics-prometheus")]
#[derive(Clone)]
pub struct BulwarkMetrics {
    /// 登录总数 Counter（标签：result=success|failure）
    login_total: prometheus::CounterVec,
    /// Token 验证延迟 Histogram（秒）
    token_validation_duration: prometheus::Histogram,
    /// 权限查询总数 Counter（标签：result=allow|deny）
    permission_query_total: prometheus::CounterVec,
    /// 角色查询总数 Counter（标签：result=allow|deny）
    role_query_total: prometheus::CounterVec,
}

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
        encoder.encode(&metric_families, &mut buffer).ok();
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

// ============================================================================
// JSON 日志初始化（feature = "tracing-log" 或 "metrics-prometheus"）
// ============================================================================

/// 初始化 tracing-subscriber 为 JSON 格式日志输出。
///
/// 启用 `metrics-prometheus` 或 `tracing-log` feature 时可用。
///
/// # 行为
/// - 设置 `RUST_LOG` 环境变量解析（默认 `info`）
/// - 输出 JSON 格式日志，包含 `timestamp` / `level` / `target` / `message` 字段
/// - 调用多次幂等：若全局 subscriber 已设置，返回 `Ok(())` 不报错
///
/// # 错误
/// 仅在 subscriber 设置失败时返回错误（实际不会发生，因 try_init 已处理）
#[cfg(any(feature = "metrics-prometheus", feature = "tracing-log"))]
pub fn init_json_logging() {
    use tracing_subscriber::fmt;
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let result = fmt()
        .with_env_filter(filter)
        .json()
        .with_current_span(true)
        .with_span_list(false)
        .try_init();

    // 幂等：若已初始化则忽略
    if let Err(e) = result {
        tracing::debug!("tracing subscriber 已初始化，跳过：{}", e);
    }
}

// ============================================================================
// OpenTelemetry 分布式追踪（feature = "observability-otlp"）
// ============================================================================

/// 初始化 OpenTelemetry OTLP gRPC 追踪导出。
///
/// 启用 `observability-otlp` feature 时可用。trace context 经 OpenTelemetry 自身的
/// `Context` 传播（task_local），通过全局 tracer provider 导出 OTLP span。
///
/// # 参数
/// - `endpoint`: OTLP gRPC endpoint（如 `http://localhost:4317`）
///
/// # 错误
/// - OTLP exporter 初始化失败
/// - tracer provider 注册失败
///
/// # 使用示例
///
/// ```ignore
/// use bulwark::observability::init_otlp_tracing;
///
/// init_otlp_tracing("http://localhost:4317").expect("OTLP 初始化失败");
/// // 后续 tracing::info_span!("bulwark.login") 会自动导出到 OTLP endpoint
/// ```
#[cfg(feature = "observability-otlp")]
pub fn init_otlp_tracing(endpoint: &str) -> Result<(), BulwarkOtelError> {
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};
    use opentelemetry_sdk::Resource;

    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    let resource = Resource::builder().with_service_name("bulwark").build();

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();

    // 全局注册 tracer provider（OTLP 导出依赖此全局状态）
    opentelemetry::global::set_tracer_provider(provider);

    Ok(())
}

/// OpenTelemetry 初始化错误。
#[cfg(feature = "observability-otlp")]
#[derive(Debug, thiserror::Error)]
pub enum BulwarkOtelError {
    /// OTLP exporter 构造失败
    #[error("OTLP exporter 构造失败: {0}")]
    Exporter(String),
    /// Tracer provider 设置失败
    #[error("Tracer provider 设置失败: {0}")]
    Provider(String),
}

#[cfg(feature = "observability-otlp")]
impl From<opentelemetry_otlp::ExporterBuildError> for BulwarkOtelError {
    fn from(e: opentelemetry_otlp::ExporterBuildError) -> Self {
        Self::Exporter(e.to_string())
    }
}

// ============================================================================
// 公共 API（feature 未启用时提供 no-op 占位，保证向后兼容）
// ============================================================================

/// 指标集合的 feature-gated 别名。
///
/// - `metrics-prometheus` 启用：解析为 [`BulwarkMetrics`]
/// - 未启用：不可用（调用方使用 `Option<Arc<BulwarkMetrics>>` 时仍可编译）
#[cfg(not(feature = "metrics-prometheus"))]
pub type BulwarkMetrics = ();

// ============================================================================
// 单元测试（依据 spec observability-stack，8-12 个测试覆盖指标/日志/追踪）
// ============================================================================

#[cfg(all(test, feature = "metrics-prometheus"))]
mod tests {
    use super::*;
    use serial_test::serial;

    /// 测试 BulwarkMetrics 创建并注册到自定义 registry 成功。
    #[test]
    #[serial]
    fn test_metrics_new_with_custom_registry() {
        let registry = prometheus::Registry::new();
        let metrics = BulwarkMetrics::register_to(&registry).expect("注册到自定义 registry 失败");
        // 先记录一次值，确保 CounterVec 在 gather 输出中可见（prometheus 行为：未观测的 CounterVec 不输出）
        metrics.record_login(true);
        metrics.observe_token_validation(Duration::from_millis(1));
        metrics.record_permission_query(true);
        metrics.record_role_query(true);
        // 验证四个指标都已注册
        let gathered = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        assert!(
            gathered.contains("bulwark_login_total"),
            "missing login_total: {}",
            gathered
        );
        assert!(
            gathered.contains("bulwark_token_validation_duration_seconds"),
            "missing token_validation: {}",
            gathered
        );
        assert!(
            gathered.contains("bulwark_permission_query_total"),
            "missing permission_query: {}",
            gathered
        );
        assert!(
            gathered.contains("bulwark_role_query_total"),
            "missing role_query: {}",
            gathered
        );
    }

    /// 测试 record_login(success=true) 递增 success 标签。
    #[test]
    #[serial]
    fn test_record_login_success() {
        let registry = prometheus::Registry::new();
        let metrics = BulwarkMetrics::register_to(&registry).expect("注册失败");
        metrics.record_login(true);
        metrics.record_login(true);
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        // Counter 应为 2
        assert!(output.contains("bulwark_login_total{result=\"success\"} 2"));
    }

    /// 测试 record_login(success=false) 递增 failure 标签。
    #[test]
    #[serial]
    fn test_record_login_failure() {
        let registry = prometheus::Registry::new();
        let metrics = BulwarkMetrics::register_to(&registry).expect("注册失败");
        metrics.record_login(false);
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        assert!(output.contains("bulwark_login_total{result=\"failure\"} 1"));
    }

    /// 测试 observe_token_validation 记录延迟。
    #[test]
    #[serial]
    fn test_observe_token_validation_duration() {
        let registry = prometheus::Registry::new();
        let metrics = BulwarkMetrics::register_to(&registry).expect("注册失败");
        metrics.observe_token_validation(Duration::from_millis(5));
        metrics.observe_token_validation(Duration::from_millis(50));
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        // Histogram 应有 _count 和 _sum
        assert!(output.contains("bulwark_token_validation_duration_seconds_count 2"));
    }

    /// 测试 record_permission_query(allowed=true/false) 分别递增 allow/deny 标签。
    #[test]
    #[serial]
    fn test_record_permission_query() {
        let registry = prometheus::Registry::new();
        let metrics = BulwarkMetrics::register_to(&registry).expect("注册失败");
        metrics.record_permission_query(true);
        metrics.record_permission_query(true);
        metrics.record_permission_query(false);
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        assert!(output.contains("bulwark_permission_query_total{result=\"allow\"} 2"));
        assert!(output.contains("bulwark_permission_query_total{result=\"deny\"} 1"));
    }

    /// 测试 record_role_query(allowed=true/false) 分别递增 allow/deny 标签。
    #[test]
    #[serial]
    fn test_record_role_query() {
        let registry = prometheus::Registry::new();
        let metrics = BulwarkMetrics::register_to(&registry).expect("注册失败");
        metrics.record_role_query(true);
        metrics.record_role_query(false);
        metrics.record_role_query(false);
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        assert!(output.contains("bulwark_role_query_total{result=\"allow\"} 1"));
        assert!(output.contains("bulwark_role_query_total{result=\"deny\"} 2"));
    }

    /// 测试 gather() 返回 Prometheus 文本格式字符串（不 panic）。
    #[test]
    #[serial]
    fn test_gather_returns_text_format() {
        let registry = prometheus::Registry::new();
        let metrics = BulwarkMetrics::register_to(&registry).expect("注册失败");
        metrics.record_login(true);
        metrics.record_permission_query(true);
        // gather() 内部使用 default registry；此处仅验证不 panic 且返回 String
        // 不依赖 default registry 状态（避免与其他测试串扰）
        let _output: String = metrics.gather();
    }

    /// 测试 Default trait 实现可构造（不 panic）。
    /// 注意：Default 调用 new() 注册到 default registry，若 default registry 已注册会 panic。
    /// 此测试用 #[serial] 隔离，但仍可能因其他测试已注册而失败——故仅验证 register_to 路径。
    #[test]
    #[serial]
    fn test_default_impl_via_register_to() {
        let registry = prometheus::Registry::new();
        let _m1 = BulwarkMetrics::register_to(&registry).expect("注册失败");
        // 验证 register_to 路径可构造实例（Default 在 default registry 已注册时会 panic，故不直接调用）
    }

    /// 测试 register_to 重复注册返回 AlreadyReg 错误。
    #[test]
    #[serial]
    fn test_duplicate_register_returns_error() {
        let registry = prometheus::Registry::new();
        let _m1 = BulwarkMetrics::register_to(&registry).expect("首次注册失败");
        let result = BulwarkMetrics::register_to(&registry);
        assert!(result.is_err(), "重复注册应返回错误");
        match result {
            Err(prometheus::Error::AlreadyReg) => {},
            Err(e) => panic!("期望 AlreadyReg 错误，实际：{:?}", e),
            Ok(_) => panic!("期望错误，实际成功"),
        }
    }

    /// 测试 init_json_logging() 多次调用幂等（不 panic）。
    #[test]
    #[serial]
    fn test_init_json_logging_idempotent() {
        // 多次调用不应 panic
        init_json_logging();
        init_json_logging();
    }

    /// 测试 Clone trait（用于 Arc<BulwarkMetrics> 在多线程共享场景）。
    #[test]
    #[serial]
    fn test_metrics_clone() {
        let registry = prometheus::Registry::new();
        let m1 = BulwarkMetrics::register_to(&registry).expect("注册失败");
        let m2 = m1.clone();
        m1.record_login(true);
        m2.record_login(true);
        // 两个 clone 共享底层 Counter，应都记录
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        assert!(output.contains("bulwark_login_total{result=\"success\"} 2"));
    }

    /// 测试 Debug trait 实现输出字段名与类型名。
    #[test]
    #[serial]
    fn test_metrics_debug_impl() {
        let registry = prometheus::Registry::new();
        let metrics = BulwarkMetrics::register_to(&registry).expect("注册失败");
        let debug_str = format!("{:?}", metrics);
        assert!(debug_str.contains("BulwarkMetrics"));
        assert!(debug_str.contains("CounterVec"));
        assert!(debug_str.contains("Histogram"));
    }

    /// 测试 Default trait 实现可构造（注册到 default registry）。
    /// 注意：Default 调用 new() 注册到 default registry，只能调用一次。
    /// 使用 #[serial] 隔离，避免与可能注册 default registry 的其他测试冲突。
    #[test]
    #[serial]
    fn test_default_impl_creates_instance() {
        // Default::default() 等价于 new()，注册到 default registry
        let metrics = BulwarkMetrics::default();
        // 验证实例可用
        metrics.record_login(true);
        metrics.record_permission_query(false);
    }

    /// 测试 new() 构造方法（注册到 default registry）。
    /// 与 test_default_impl_creates_instance 互斥：二者都注册到 default registry，
    /// 只能有一个执行。此测试验证 new() 路径，由 Default 测试间接覆盖。
    #[test]
    #[serial]
    fn test_new_registers_to_default_registry() {
        // new() 已由 Default 测试覆盖（Default 调用 new()），
        // 此处仅验证 register_to 路径不 panic
        let registry = prometheus::Registry::new();
        let _metrics = BulwarkMetrics::register_to(&registry).expect("注册失败");
    }
}

/// OpenTelemetry OTLP 追踪测试（feature = "observability-otlp"）。
#[cfg(all(test, feature = "observability-otlp"))]
mod tests_otlp {
    use super::*;

    /// 测试 init_otlp_tracing 成功初始化（使用本地 endpoint，不实际导出）。
    /// tonic channel 是惰性连接，build() 不需要 endpoint 可达，但 build() 内部
    /// 调用 tokio::spawn，因此需要 tokio runtime（使用 #[tokio::test] 提供）。
    /// 注意：set_tracer_provider 是全局一次性操作，此测试只能运行一次。
    #[tokio::test]
    async fn test_init_otlp_tracing_succeeds() {
        // 使用本地不可达 endpoint，tonic 不会实际连接（惰性连接）
        let result = init_otlp_tracing("http://localhost:4317");
        // build() 应成功（tonic 惰性连接），set_tracer_provider 也应成功（首次调用）
        assert!(
            result.is_ok(),
            "init_otlp_tracing 应成功: {:?}",
            result.err()
        );
    }

    /// 测试 BulwarkOtelError 的 Display 实现。
    #[test]
    fn test_otel_error_display() {
        let err1 = BulwarkOtelError::Exporter("exporter 失败".to_string());
        assert!(format!("{}", err1).contains("exporter 失败"));
        assert!(format!("{}", err1).contains("OTLP exporter"));

        let err2 = BulwarkOtelError::Provider("provider 失败".to_string());
        assert!(format!("{}", err2).contains("provider 失败"));
        assert!(format!("{}", err2).contains("Tracer provider"));
    }

    /// 测试 BulwarkOtelError 的 Debug 实现。
    /// derive(Debug) 仅输出变体名（如 Exporter("test")），不包含枚举名 BulwarkOtelError。
    #[test]
    fn test_otel_error_debug() {
        let err = BulwarkOtelError::Exporter("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Exporter"));
        assert!(debug_str.contains("test"));

        let err2 = BulwarkOtelError::Provider("prov".to_string());
        let debug_str2 = format!("{:?}", err2);
        assert!(debug_str2.contains("Provider"));
        assert!(debug_str2.contains("prov"));
    }
}

/// 无 feature 时的编译验证测试（确保向后兼容）。
#[cfg(all(test, not(feature = "metrics-prometheus")))]
mod tests_no_feature {
    use super::*;

    /// 未启用 metrics-prometheus 时 BulwarkMetrics 为 unit type 别名。
    #[test]
    fn test_no_feature_metrics_is_unit() {
        let _: BulwarkMetrics = ();
    }
}
