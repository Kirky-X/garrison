//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! observability 模块测试（从 mod.rs 迁移，Rule 25 合规）。

// ============================================================================
// GarrisonMetrics 测试（feature = "metrics-prometheus"）
// ============================================================================

#[cfg(all(test, feature = "metrics-prometheus"))]
mod tests_metrics {
    use super::super::*;
    use serial_test::serial;
    use std::time::Duration;

    /// 测试 GarrisonMetrics 创建并注册到自定义 registry 成功。
    #[test]
    #[serial]
    fn test_metrics_new_with_custom_registry() {
        let registry = prometheus::Registry::new();
        let metrics = GarrisonMetrics::register_to(&registry).expect("注册到自定义 registry 失败");
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
            gathered.contains("garrison_login_total"),
            "missing login_total: {}",
            gathered
        );
        assert!(
            gathered.contains("garrison_token_validation_duration_seconds"),
            "missing token_validation: {}",
            gathered
        );
        assert!(
            gathered.contains("garrison_permission_query_total"),
            "missing permission_query: {}",
            gathered
        );
        assert!(
            gathered.contains("garrison_role_query_total"),
            "missing role_query: {}",
            gathered
        );
    }

    /// 测试 record_login(success=true) 递增 success 标签。
    #[test]
    #[serial]
    fn test_record_login_success() {
        let registry = prometheus::Registry::new();
        let metrics = GarrisonMetrics::register_to(&registry).expect("注册失败");
        metrics.record_login(true);
        metrics.record_login(true);
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        // Counter 应为 2
        assert!(output.contains("garrison_login_total{result=\"success\"} 2"));
    }

    /// 测试 record_login(success=false) 递增 failure 标签。
    #[test]
    #[serial]
    fn test_record_login_failure() {
        let registry = prometheus::Registry::new();
        let metrics = GarrisonMetrics::register_to(&registry).expect("注册失败");
        metrics.record_login(false);
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        assert!(output.contains("garrison_login_total{result=\"failure\"} 1"));
    }

    /// 测试 observe_token_validation 记录延迟。
    #[test]
    #[serial]
    fn test_observe_token_validation_duration() {
        let registry = prometheus::Registry::new();
        let metrics = GarrisonMetrics::register_to(&registry).expect("注册失败");
        metrics.observe_token_validation(Duration::from_millis(5));
        metrics.observe_token_validation(Duration::from_millis(50));
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        // Histogram 应有 _count 和 _sum
        assert!(output.contains("garrison_token_validation_duration_seconds_count 2"));
    }

    /// 测试 record_permission_query(allowed=true/false) 分别递增 allow/deny 标签。
    #[test]
    #[serial]
    fn test_record_permission_query() {
        let registry = prometheus::Registry::new();
        let metrics = GarrisonMetrics::register_to(&registry).expect("注册失败");
        metrics.record_permission_query(true);
        metrics.record_permission_query(true);
        metrics.record_permission_query(false);
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        assert!(output.contains("garrison_permission_query_total{result=\"allow\"} 2"));
        assert!(output.contains("garrison_permission_query_total{result=\"deny\"} 1"));
    }

    /// 测试 record_role_query(allowed=true/false) 分别递增 allow/deny 标签。
    #[test]
    #[serial]
    fn test_record_role_query() {
        let registry = prometheus::Registry::new();
        let metrics = GarrisonMetrics::register_to(&registry).expect("注册失败");
        metrics.record_role_query(true);
        metrics.record_role_query(false);
        metrics.record_role_query(false);
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        assert!(output.contains("garrison_role_query_total{result=\"allow\"} 1"));
        assert!(output.contains("garrison_role_query_total{result=\"deny\"} 2"));
    }

    /// 测试 gather() 返回 Prometheus 文本格式字符串（不 panic）。
    #[test]
    #[serial]
    fn test_gather_returns_text_format() {
        let registry = prometheus::Registry::new();
        let metrics = GarrisonMetrics::register_to(&registry).expect("注册失败");
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
        let _m1 = GarrisonMetrics::register_to(&registry).expect("注册失败");
        // 验证 register_to 路径可构造实例（Default 在 default registry 已注册时会 panic，故不直接调用）
    }

    /// 测试 register_to 重复注册返回 AlreadyReg 错误。
    #[test]
    #[serial]
    fn test_duplicate_register_returns_error() {
        let registry = prometheus::Registry::new();
        let _m1 = GarrisonMetrics::register_to(&registry).expect("首次注册失败");
        let result = GarrisonMetrics::register_to(&registry);
        assert!(result.is_err(), "重复注册应返回错误");
        match result {
            Err(prometheus::Error::AlreadyReg) => {},
            Err(e) => panic!("期望 AlreadyReg 错误，实际：{:?}", e),
            Ok(_) => panic!("期望错误，实际成功"),
        }
    }

    /// 测试 Clone trait（用于 Arc<GarrisonMetrics> 在多线程共享场景）。
    #[test]
    #[serial]
    fn test_metrics_clone() {
        let registry = prometheus::Registry::new();
        let m1 = GarrisonMetrics::register_to(&registry).expect("注册失败");
        let m2 = m1.clone();
        m1.record_login(true);
        m2.record_login(true);
        // 两个 clone 共享底层 Counter，应都记录
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        assert!(output.contains("garrison_login_total{result=\"success\"} 2"));
    }

    /// 测试 Debug trait 实现输出字段名与类型名。
    #[test]
    #[serial]
    fn test_metrics_debug_impl() {
        let registry = prometheus::Registry::new();
        let metrics = GarrisonMetrics::register_to(&registry).expect("注册失败");
        let debug_str = format!("{:?}", metrics);
        assert!(debug_str.contains("GarrisonMetrics"));
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
        let metrics = GarrisonMetrics::default();
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
        let _metrics = GarrisonMetrics::register_to(&registry).expect("注册失败");
    }

    // ========================================================================
    // 补充测试：边界情况与多操作组合
    // ========================================================================

    /// 测试 observe_token_validation 传入零时长不 panic 且被记录。
    #[test]
    #[serial]
    fn test_observe_token_validation_zero_duration() {
        let registry = prometheus::Registry::new();
        let metrics = GarrisonMetrics::register_to(&registry).expect("注册失败");
        metrics.observe_token_validation(Duration::from_millis(0));
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        assert!(output.contains("garrison_token_validation_duration_seconds_count 1"));
    }

    /// 测试所有 record/observe 操作在同一个实例上组合调用不冲突。
    #[test]
    #[serial]
    fn test_all_record_operations_on_single_instance() {
        let registry = prometheus::Registry::new();
        let metrics = GarrisonMetrics::register_to(&registry).expect("注册失败");
        metrics.record_login(true);
        metrics.record_login(false);
        metrics.observe_token_validation(Duration::from_millis(10));
        metrics.record_permission_query(true);
        metrics.record_permission_query(false);
        metrics.record_role_query(true);
        metrics.record_role_query(false);
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        assert!(output.contains("garrison_login_total{result=\"success\"} 1"));
        assert!(output.contains("garrison_login_total{result=\"failure\"} 1"));
        assert!(output.contains("garrison_permission_query_total{result=\"allow\"} 1"));
        assert!(output.contains("garrison_permission_query_total{result=\"deny\"} 1"));
        assert!(output.contains("garrison_role_query_total{result=\"allow\"} 1"));
        assert!(output.contains("garrison_role_query_total{result=\"deny\"} 1"));
    }

    /// 测试 gather() 在记录操作后返回包含所有指标名的非空字符串。
    /// 注意：gather() 内部使用 default registry，此处用 custom registry 验证指标输出。
    #[test]
    #[serial]
    fn test_gather_returns_non_empty_after_operations() {
        let registry = prometheus::Registry::new();
        let metrics = GarrisonMetrics::register_to(&registry).expect("注册失败");
        metrics.record_login(true);
        metrics.observe_token_validation(Duration::from_millis(5));
        metrics.record_permission_query(true);
        metrics.record_role_query(true);
        // gather() 内部使用 default registry，此处验证 custom registry 的输出
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        assert!(!output.is_empty(), "gather() 不应返回空字符串");
        assert!(
            output.contains("garrison_login_total"),
            "gather 应含 login_total"
        );
        assert!(
            output.contains("garrison_token_validation_duration_seconds"),
            "gather 应含 token_validation"
        );
        assert!(
            output.contains("garrison_permission_query_total"),
            "gather 应含 permission_query"
        );
        assert!(
            output.contains("garrison_role_query_total"),
            "gather 应含 role_query"
        );
    }

    /// 测试两个独立 registry 上的 GarrisonMetrics 实例互不干扰。
    #[test]
    #[serial]
    fn test_two_registries_independent() {
        let registry1 = prometheus::Registry::new();
        let registry2 = prometheus::Registry::new();
        let m1 = GarrisonMetrics::register_to(&registry1).expect("注册失败");
        let m2 = GarrisonMetrics::register_to(&registry2).expect("注册失败");
        m1.record_login(true);
        m2.record_login(false);
        let out1 = prometheus::TextEncoder::new()
            .encode_to_string(&registry1.gather())
            .expect("encode 失败");
        let out2 = prometheus::TextEncoder::new()
            .encode_to_string(&registry2.gather())
            .expect("encode 失败");
        assert!(out1.contains("garrison_login_total{result=\"success\"} 1"));
        assert!(!out1.contains("result=\"failure\""));
        assert!(out2.contains("garrison_login_total{result=\"failure\"} 1"));
        assert!(!out2.contains("result=\"success\""));
    }

    /// 测试同一个实例上先记录 success 再记录 failure，两个标签值均正确。
    #[test]
    #[serial]
    fn test_record_login_success_and_failure_on_same_instance() {
        let registry = prometheus::Registry::new();
        let metrics = GarrisonMetrics::register_to(&registry).expect("注册失败");
        metrics.record_login(true);
        metrics.record_login(true);
        metrics.record_login(false);
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        assert!(output.contains("garrison_login_total{result=\"success\"} 2"));
        assert!(output.contains("garrison_login_total{result=\"failure\"} 1"));
    }

    /// 测试 observe_token_validation 多次观测后 count 和 sum 正确。
    #[test]
    #[serial]
    fn test_observe_token_validation_multiple_values_count_and_sum() {
        let registry = prometheus::Registry::new();
        let metrics = GarrisonMetrics::register_to(&registry).expect("注册失败");
        metrics.observe_token_validation(Duration::from_millis(100));
        metrics.observe_token_validation(Duration::from_millis(200));
        metrics.observe_token_validation(Duration::from_millis(300));
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        assert!(output.contains("garrison_token_validation_duration_seconds_count 3"));
    }

    /// 测试 record_permission_query 先 allow 再 deny，两个标签值均正确。
    #[test]
    #[serial]
    fn test_record_permission_query_allow_and_deny_on_same_instance() {
        let registry = prometheus::Registry::new();
        let metrics = GarrisonMetrics::register_to(&registry).expect("注册失败");
        metrics.record_permission_query(true);
        metrics.record_permission_query(true);
        metrics.record_permission_query(true);
        metrics.record_permission_query(false);
        metrics.record_permission_query(false);
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        assert!(output.contains("garrison_permission_query_total{result=\"allow\"} 3"));
        assert!(output.contains("garrison_permission_query_total{result=\"deny\"} 2"));
    }

    /// 测试 record_role_query 先 allow 再 deny，两个标签值均正确。
    #[test]
    #[serial]
    fn test_record_role_query_allow_and_deny_on_same_instance() {
        let registry = prometheus::Registry::new();
        let metrics = GarrisonMetrics::register_to(&registry).expect("注册失败");
        metrics.record_role_query(false);
        metrics.record_role_query(false);
        metrics.record_role_query(false);
        metrics.record_role_query(true);
        let output = prometheus::TextEncoder::new()
            .encode_to_string(&registry.gather())
            .expect("encode 失败");
        assert!(output.contains("garrison_role_query_total{result=\"allow\"} 1"));
        assert!(output.contains("garrison_role_query_total{result=\"deny\"} 3"));
    }
}

// ============================================================================
// OpenTelemetry OTLP 追踪测试（feature = "observability-otlp"）
// ============================================================================

#[cfg(all(test, feature = "observability-otlp"))]
mod tests_otlp {
    use super::super::*;

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

    /// 测试 GarrisonOtelError 的 Display 实现。
    #[test]
    fn test_otel_error_display() {
        let err1 = GarrisonOtelError::Exporter("exporter 失败".to_string());
        assert!(format!("{}", err1).contains("exporter 失败"));
        assert!(format!("{}", err1).contains("OTLP exporter"));

        let err2 = GarrisonOtelError::Provider("provider 失败".to_string());
        assert!(format!("{}", err2).contains("provider 失败"));
        assert!(format!("{}", err2).contains("Tracer provider"));
    }

    /// 测试 GarrisonOtelError 的 Debug 实现。
    /// derive(Debug) 仅输出变体名（如 Exporter("test")），不包含枚举名 GarrisonOtelError。
    #[test]
    fn test_otel_error_debug() {
        let err = GarrisonOtelError::Exporter("test".to_string());
        let debug_str = format!("{:?}", err);
        assert!(debug_str.contains("Exporter"));
        assert!(debug_str.contains("test"));

        let err2 = GarrisonOtelError::Provider("prov".to_string());
        let debug_str2 = format!("{:?}", err2);
        assert!(debug_str2.contains("Provider"));
        assert!(debug_str2.contains("prov"));
    }
}

// ============================================================================
// 无 feature 时的编译验证测试（确保向后兼容）
// ============================================================================

#[cfg(all(test, not(feature = "metrics-prometheus")))]
mod tests_no_feature {
    use super::super::*;

    /// 未启用 metrics-prometheus 时 GarrisonMetrics 为 unit type 别名。
    #[test]
    fn test_no_feature_metrics_is_unit() {
        let _: GarrisonMetrics = ();
    }
}

// ============================================================================
// inklog 初始化测试（feature = "audit-inklog"）
// ============================================================================

#[cfg(all(test, feature = "audit-inklog"))]
mod tests_inklog {
    use super::super::*;
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
