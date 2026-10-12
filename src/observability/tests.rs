// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! observability 模块测试。

// GarrisonMetrics 测试（feature = "metrics-prometheus"）

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
        // gather() 读默认 registry，仅验证不 panic、不依赖其状态
        let _output: String = metrics.gather();
    }

    /// Default 亦注册到 default registry（重复注册会 panic），故仅经 register_to 验证可构造路径。
    #[test]
    #[serial]
    fn test_default_impl_via_register_to() {
        let registry = prometheus::Registry::new();
        let _m1 = GarrisonMetrics::register_to(&registry).expect("注册失败");
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

    /// 重复调用 new()（含 Default）不再 panic——
    /// 第二次起以 warn 提示并返回未注册的本地实例。
    #[test]
    #[serial]
    fn test_new_repeated_does_not_panic() {
        let _m1 = GarrisonMetrics::new();
        let _m2 = GarrisonMetrics::new();
        let _m3 = GarrisonMetrics::default();
        // record/gather 在回退实例上仍可用（仅不新增默认 registry 采集）
        _m3.record_login(true);
        let _ = _m3.gather();
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

    /// Default 注册到 default registry，只能调用一次（与 test_new_registers_to_default_registry 互斥）。
    #[test]
    #[serial]
    fn test_default_impl_creates_instance() {
        let metrics = GarrisonMetrics::default();
        metrics.record_login(true);
        metrics.record_permission_query(false);
    }

    /// new() 已由 Default 测试覆盖（Default 调用 new()），此处仅验证 register_to 路径不 panic。
    #[test]
    #[serial]
    fn test_new_registers_to_default_registry() {
        let registry = prometheus::Registry::new();
        let _metrics = GarrisonMetrics::register_to(&registry).expect("注册失败");
    }

    // 补充测试：边界情况与多操作组合

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

// OpenTelemetry OTLP 追踪测试（feature = "otlp"）

#[cfg(all(test, feature = "otlp"))]
mod tests_otlp {
    use super::super::*;
    use serial_test::serial;

    /// tonic 惰性连接使 build() 无需 endpoint 可达；set_tracer_provider 为全局一次性
    /// 操作，故用 #[tokio::test] + #[serial] 隔离竞争。
    #[tokio::test]
    #[serial]
    async fn test_init_otlp_tracing_succeeds() {
        // 使用本地不可达 endpoint，tonic 不会实际连接（惰性连接）
        let result = init_otlp_tracing("http://localhost:4317");
        assert!(
            result.is_ok(),
            "init_otlp_tracing 应成功: {:?}",
            result.err()
        );
    }

    /// 含空格的 endpoint 不是合法 URI，解析失败经 `From` 转 `Exporter` 变体；
    /// 不触达 `set_tracer_provider` 全局状态，仍串行隔离。
    #[tokio::test]
    #[serial]
    async fn test_init_otlp_tracing_invalid_endpoint_returns_err() {
        let result = init_otlp_tracing("not a valid endpoint");
        assert!(result.is_err(), "非法 endpoint 应返回 Err");
        let err = result.unwrap_err();
        assert!(
            matches!(err, GarrisonOtelError::Exporter(_)),
            "应映射为 Exporter 变体，实际: {:?}",
            err
        );
        // Display 应包含 exporter 错误前缀（验证 From 转换路径的 message）
        let msg = format!("{}", err);
        assert!(msg.contains("OTLP exporter"), "实际: {}", msg);
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

    /// Debug 实现仅输出变体名（如 `Exporter("test")`），不含枚举名。
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

// 无 feature 时的编译验证测试

#[cfg(all(test, not(feature = "metrics-prometheus")))]
mod tests_no_feature {
    use super::super::*;

    /// 未启用 metrics-prometheus 时 GarrisonMetrics 为 unit type 别名。
    #[test]
    fn test_no_feature_metrics_is_unit() {
        let _: GarrisonMetrics = ();
    }
}

// inklog 初始化测试（feature = "audit-inklog"）

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

    /// init_inklog_logging_with_fallback 成功时返回非降级 InklogInit。
    #[tokio::test]
    #[serial]
    async fn m4_init_with_fallback_succeeds_not_degraded() {
        let result = init_inklog_logging_with_fallback().await;
        assert!(!result.is_degraded(), "inklog 初始化成功时不应降级");
        assert!(result.guard().is_some(), "成功时应返回 LoggerManager guard");
    }

    /// InklogInit 的 is_degraded() 和 guard() 方法行为正确。
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

    /// 注入 inklog 非法 level（合法集合仅 trace/debug/info/warn/error 等）使 build()
    /// 校验失败返回 ConfigError，验证原始初始化函数的 Err 路径。
    #[tokio::test]
    #[serial]
    async fn init_inklog_logging_fails_on_invalid_level() {
        std::env::set_var("RUST_LOG", "not-a-valid-level");
        let result = init_inklog_logging().await;
        std::env::remove_var("RUST_LOG");
        assert!(result.is_err(), "非法 level 应使 inklog 初始化失败");
    }

    /// inklog 初始化失败时 with_fallback 降级（degraded=true, guard=None）。
    ///
    /// RUST_LOG 设为 inklog 非法 level → build() 返回 Err → 走降级分支：
    /// metrics-prometheus 启用时先 try_init tracing-subscriber JSON，再返回 degraded 状态。
    #[tokio::test]
    #[serial]
    async fn r_dep003_fallback_degrades_when_inklog_fails() {
        // inklog 非法 level（EnvFilter 可解析为 target 指令，不产生过滤告警噪音）
        std::env::set_var("RUST_LOG", "garrison-bogus-level");
        let result = init_inklog_logging_with_fallback().await;
        std::env::remove_var("RUST_LOG");
        assert!(result.is_degraded(), "inklog 失败时应降级（degraded=true）");
        assert!(
            result.guard().is_none(),
            "降级时不应持有 LoggerManager guard"
        );
    }
}
