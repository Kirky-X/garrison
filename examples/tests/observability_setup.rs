//! observability_setup 示例测试（metrics-prometheus + observability-otlp feature）。
//!
//! 验证 BulwarkMetrics 指标记录与收集：
//! - `register_to` 注册到自定义 registry
//! - `record_login` / `record_permission_query` / `record_role_query` 递增计数
//! - `observe_token_validation` 记录延迟
//! - `gather` 输出包含所有指标名
//!
//! 注：`init_otlp_tracing` 为全局一次性操作，且需要 OTLP collector，
//! 此处不实际调用（避免污染全局 tracer provider）。

#![cfg(all(feature = "metrics-prometheus", feature = "observability-otlp"))]

use bulwark::observability::prometheus::Encoder;
use bulwark::observability::BulwarkMetrics;
use serial_test::serial;
use std::time::Duration;

/// 辅助：从 registry 收集指标文本。
fn gather(registry: &bulwark::observability::prometheus::Registry) -> String {
    let mut buffer = Vec::new();
    let encoder = bulwark::observability::prometheus::TextEncoder::new();
    encoder.encode(&registry.gather(), &mut buffer).ok();
    String::from_utf8_lossy(&buffer).into_owned()
}

#[test]
#[serial]
fn test_register_to_custom_registry() {
    let registry = bulwark::observability::prometheus::Registry::new();
    let metrics = BulwarkMetrics::register_to(&registry).expect("注册失败");
    metrics.record_login(true);
    let output = gather(&registry);
    assert!(
        output.contains("bulwark_login_total"),
        "missing login_total: {}",
        output
    );
}

#[test]
#[serial]
fn test_record_login_success_increments() {
    let registry = bulwark::observability::prometheus::Registry::new();
    let metrics = BulwarkMetrics::register_to(&registry).expect("注册失败");
    metrics.record_login(true);
    metrics.record_login(true);
    let output = gather(&registry);
    assert!(
        output.contains("bulwark_login_total{result=\"success\"} 2"),
        "expected count 2: {}",
        output
    );
}

#[test]
#[serial]
fn test_record_login_failure_increments() {
    let registry = bulwark::observability::prometheus::Registry::new();
    let metrics = BulwarkMetrics::register_to(&registry).expect("注册失败");
    metrics.record_login(false);
    let output = gather(&registry);
    assert!(
        output.contains("bulwark_login_total{result=\"failure\"} 1"),
        "expected count 1: {}",
        output
    );
}

#[test]
#[serial]
fn test_observe_token_validation_duration() {
    let registry = bulwark::observability::prometheus::Registry::new();
    let metrics = BulwarkMetrics::register_to(&registry).expect("注册失败");
    metrics.observe_token_validation(Duration::from_millis(5));
    metrics.observe_token_validation(Duration::from_millis(50));
    let output = gather(&registry);
    assert!(
        output.contains("bulwark_token_validation_duration_seconds"),
        "missing token_validation: {}",
        output
    );
}

#[test]
#[serial]
fn test_record_permission_query_allow() {
    let registry = bulwark::observability::prometheus::Registry::new();
    let metrics = BulwarkMetrics::register_to(&registry).expect("注册失败");
    metrics.record_permission_query(true);
    let output = gather(&registry);
    assert!(
        output.contains("bulwark_permission_query_total{result=\"allow\"} 1"),
        "expected allow count 1: {}",
        output
    );
}

#[test]
#[serial]
fn test_record_permission_query_deny() {
    let registry = bulwark::observability::prometheus::Registry::new();
    let metrics = BulwarkMetrics::register_to(&registry).expect("注册失败");
    metrics.record_permission_query(false);
    let output = gather(&registry);
    assert!(
        output.contains("bulwark_permission_query_total{result=\"deny\"} 1"),
        "expected deny count 1: {}",
        output
    );
}

#[test]
#[serial]
fn test_record_role_query_allow_and_deny() {
    let registry = bulwark::observability::prometheus::Registry::new();
    let metrics = BulwarkMetrics::register_to(&registry).expect("注册失败");
    metrics.record_role_query(true);
    metrics.record_role_query(true);
    metrics.record_role_query(false);
    let output = gather(&registry);
    assert!(
        output.contains("bulwark_role_query_total{result=\"allow\"} 2"),
        "expected allow count 2: {}",
        output
    );
    assert!(
        output.contains("bulwark_role_query_total{result=\"deny\"} 1"),
        "expected deny count 1: {}",
        output
    );
}

#[test]
#[serial]
fn test_gather_contains_all_metrics() {
    let registry = bulwark::observability::prometheus::Registry::new();
    let metrics = BulwarkMetrics::register_to(&registry).expect("注册失败");
    metrics.record_login(true);
    metrics.observe_token_validation(Duration::from_millis(1));
    metrics.record_permission_query(true);
    metrics.record_role_query(true);
    let output = gather(&registry);
    assert!(output.contains("bulwark_login_total"));
    assert!(output.contains("bulwark_token_validation_duration_seconds"));
    assert!(output.contains("bulwark_permission_query_total"));
    assert!(output.contains("bulwark_role_query_total"));
}

/// 测试示例的 create_metrics 辅助函数。
#[test]
#[serial]
fn test_create_metrics_helper() {
    let (metrics, registry) =
        bulwark_examples::infrastructure::observability_setup::create_metrics();
    metrics.record_login(true);
    let output = gather(&registry);
    assert!(output.contains("bulwark_login_total"));
}

/// 测试示例的 record_sample_metrics 记录所有指标。
#[test]
#[serial]
fn test_record_sample_metrics() {
    let (metrics, registry) =
        bulwark_examples::infrastructure::observability_setup::create_metrics();
    bulwark_examples::infrastructure::observability_setup::record_sample_metrics(&metrics);
    let output = gather(&registry);
    assert!(output.contains("bulwark_login_total{result=\"success\"}"));
    assert!(output.contains("bulwark_login_total{result=\"failure\"}"));
    assert!(output.contains("bulwark_permission_query_total{result=\"allow\"}"));
    assert!(output.contains("bulwark_permission_query_total{result=\"deny\"}"));
    assert!(output.contains("bulwark_role_query_total{result=\"allow\"}"));
    assert!(output.contains("bulwark_role_query_total{result=\"deny\"}"));
}

/// 测试示例的 gather_metrics 辅助函数返回非空字符串。
#[test]
#[serial]
fn test_gather_metrics_helper() {
    let (metrics, registry) =
        bulwark_examples::infrastructure::observability_setup::create_metrics();
    metrics.record_login(true);
    let output = bulwark_examples::infrastructure::observability_setup::gather_metrics(&registry);
    assert!(!output.is_empty());
    assert!(output.contains("bulwark_login_total"));
}

/// 测试 init_otlp_tracing 函数可访问（不实际调用，避免全局状态污染）。
///
/// OTLP 初始化是全局一次性的，且需要 OTLP collector 运行。
/// 此测试仅验证函数存在于公共 API 中。
#[test]
fn test_init_otlp_tracing_api_exists() {
    // 仅验证函数指针可获取，不实际调用
    let _f: fn(&str) -> Result<(), bulwark::observability::BulwarkOtelError> =
        bulwark::observability::init_otlp_tracing;
}
