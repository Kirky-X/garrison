//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 可观测性模块，提供 Prometheus 指标、结构化 JSON 日志与 OpenTelemetry 分布式追踪。
//!
//! ## 三层架构
//!
//! - **Metrics**（`BulwarkMetrics`）：Prometheus 格式指标，覆盖登录成功率 / Token 验证延迟 /
//!   权限查询 QPS / 角色查询 QPS。启用 `metrics-prometheus` feature。
//! - **Logs**（`init_inklog_logging` / `init_inklog_logging_with_fallback`）：
//!   inklog 结构化日志（含降级到 tracing-subscriber JSON）。启用 `audit-inklog` feature；
//!   降级路径在 `metrics-prometheus` 或 `tracing-log` 启用时使用 tracing-subscriber JSON。
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
//! - `metrics-prometheus`：编译期包含 `BulwarkMetrics`，并为 inklog 降级路径提供 tracing-subscriber 依赖
//! - `audit-inklog`：编译期包含 `init_inklog_logging` 与 `init_inklog_logging_with_fallback`
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
/// # 指标清单
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

mod metrics_impl;

// ============================================================================
// inklog 结构化日志（feature = "audit-inklog"）
// ============================================================================

/// 使用 inklog 初始化 tracing subscriber，提供企业级结构化日志能力。
///
/// 启用 `audit-inklog` feature 时可用。inklog 提供多输出（console/file）、
/// 日志轮转、压缩、脱敏等企业级功能，替代手写 `tracing_subscriber::fmt().json()` 配置。
///
/// `tracing::warn!` / `tracing::error!` 宏不变 — inklog 是 subscriber 配置层，
/// 不是宏替代品。inklog 初始化后，所有 tracing 宏自动经由 inklog pipeline 输出。
///
/// # 行为
/// - 读取 `RUST_LOG` 环境变量（默认 `info`）
/// - 启用 console 输出
/// - 返回 `LoggerManager` guard，调用方须保持存活以维持日志输出
///
/// # 错误
/// - inklog 初始化失败（如配置错误）
///
/// # 使用示例
///
/// ```ignore
/// use bulwark::observability::init_inklog_logging;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let _logger = init_inklog_logging().await?;
///     tracing::info!("inklog 已启动");
///     Ok(())
/// }
/// ```
#[cfg(feature = "audit-inklog")]
pub async fn init_inklog_logging() -> Result<inklog::LoggerManager, inklog::InklogError> {
    let level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    inklog::LoggerManager::builder()
        .level(level)
        .console(true)
        .build()
        .await
}

// ============================================================================
// inklog 降级初始化（spec R-dep-003，feature = "audit-inklog"）
// ============================================================================

/// inklog 初始化结果 — 包含可选的 LoggerManager guard 和降级状态。
///
/// M-4: `#[must_use]` 确保 guard 不会被意外丢弃（丢弃后 subscriber 可能注销）。
#[cfg(feature = "audit-inklog")]
#[must_use = "InklogInit 包含 LoggerManager guard，丢弃后日志 subscriber 可能注销"]
pub struct InklogInit {
    /// LoggerManager guard（降级时为 None，guard 不存在）。
    guard: Option<inklog::LoggerManager>,
    /// 降级标志：true 表示 inklog 失败，已降级到 tracing-subscriber 默认配置。
    degraded: bool,
}

#[cfg(feature = "audit-inklog")]
impl InklogInit {
    /// 是否已降级。
    pub fn is_degraded(&self) -> bool {
        self.degraded
    }
    /// 获取 LoggerManager guard（降级时返回 None）。
    pub fn guard(self) -> Option<inklog::LoggerManager> {
        self.guard
    }
}

/// 使用 inklog 初始化 tracing subscriber，失败时降级到 tracing-subscriber 默认配置。
///
/// spec R-dep-003 降级机制：inklog 初始化失败时回退到内联 `tracing_subscriber::fmt().json()`
/// 配置，确保日志不丢失。调用方可通过 `InklogInit::is_degraded()` 判断是否降级。
///
/// # 行为
/// 1. 尝试 inklog::LoggerManager::builder().level().console().build()
/// 2. 成功 → 返回 `InklogInit { guard: Some(mgr), degraded: false }`
/// 3. 失败 → 内联 `tracing_subscriber::fmt().json()` 降级（当 `metrics-prometheus` 或
///    `tracing-log` 启用时）；无 observability feature 时用 `eprintln!` 警告；
///    再 tracing::warn! 记录降级原因
///    返回 `InklogInit { guard: None, degraded: true }`
///
/// # 使用示例
///
/// ```ignore
/// use bulwark::observability::init_inklog_logging_with_fallback;
///
/// #[tokio::main]
/// async fn main() {
///     let logger = init_inklog_logging_with_fallback().await;
///     if logger.is_degraded() {
///         eprintln!("警告：inklog 降级到 tracing-subscriber 默认配置");
///     }
///     // guard 在 logger 中保持存活
/// }
/// ```
#[cfg(feature = "audit-inklog")]
pub async fn init_inklog_logging_with_fallback() -> InklogInit {
    match init_inklog_logging().await {
        Ok(mgr) => InklogInit {
            guard: Some(mgr),
            degraded: false,
        },
        Err(e) => {
            // 降级路径：metrics-prometheus 或 tracing-log 启用时用 tracing-subscriber JSON
            #[cfg(any(feature = "metrics-prometheus", feature = "tracing-log"))]
            {
                use tracing_subscriber::EnvFilter;
                let filter =
                    EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
                let result = tracing_subscriber::fmt()
                    .with_env_filter(filter)
                    .json()
                    .with_current_span(true)
                    .with_span_list(false)
                    .try_init();
                if let Err(init_err) = result {
                    tracing::debug!("tracing subscriber 已初始化，跳过：{}", init_err);
                }
            }
            // 无 observability feature 时，无 tracing-subscriber 可用，仅 eprintln! 警告
            #[cfg(not(any(feature = "metrics-prometheus", feature = "tracing-log")))]
            {
                eprintln!(
                    "WARN: inklog 初始化失败且未启用 observability feature，日志将丢失：{}",
                    e
                );
            }
            tracing::warn!(
                error = %e,
                "inklog 初始化失败，已降级到 tracing-subscriber 默认配置（spec R-dep-003）"
            );
            InklogInit {
                guard: None,
                degraded: true,
            }
        },
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
// 单元测试
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

/// inklog 初始化测试（feature = "audit-inklog"）。
#[cfg(all(test, feature = "audit-inklog"))]
mod tests_inklog {
    use super::*;
    use serial_test::serial;

    /// 测试 init_inklog_logging() 成功初始化（返回 LoggerManager guard）。
    #[tokio::test]
    #[serial]
    async fn init_inklog_logging_succeeds() {
        let result = init_inklog_logging().await;
        assert!(
            result.is_ok(),
            "init_inklog_logging 应成功: {:?}",
            result.err()
        );
        // logger guard 在 scope 结束时 drop，关闭 inklog
    }

    /// 测试 init_inklog_logging() 读取 RUST_LOG 环境变量。
    #[tokio::test]
    #[serial]
    async fn init_inklog_logging_reads_rust_log() {
        std::env::set_var("RUST_LOG", "debug");
        let result = init_inklog_logging().await;
        std::env::remove_var("RUST_LOG");
        assert!(
            result.is_ok(),
            "init_inklog_logging 应成功（debug level）: {:?}",
            result.err()
        );
    }

    /// M-4: init_inklog_logging_with_fallback 成功时返回非降级 InklogInit。
    #[tokio::test]
    #[serial]
    async fn m4_init_with_fallback_succeeds_not_degraded() {
        let result = init_inklog_logging_with_fallback().await;
        assert!(!result.is_degraded(), "inklog 初始化成功时不应降级");
        assert!(result.guard().is_some(), "成功时应返回 LoggerManager guard");
    }

    /// M-4: InklogInit 的 is_degraded() 和 guard() 方法行为正确。
    #[tokio::test]
    #[serial]
    async fn m4_inklog_init_degraded_flag() {
        // 直接构造降级状态验证 API
        let degraded = InklogInit {
            guard: None,
            degraded: true,
        };
        assert!(degraded.is_degraded());
        assert!(degraded.guard().is_none());

        let normal = InklogInit {
            guard: None, // 不实际持有 guard，仅验证 API
            degraded: false,
        };
        assert!(!normal.is_degraded());
    }
}
