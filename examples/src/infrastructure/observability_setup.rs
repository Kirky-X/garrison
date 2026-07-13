//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! observability_setup 示例（metrics-prometheus + observability-otlp feature）。
//!
//! 演示可观测性三层栈配置：
//! 1. `BulwarkMetrics::new()` / `register_to(&registry)` Prometheus 指标注册
//! 2. `record_login` / `observe_token_validation` / `record_permission_query` / `record_role_query` 指标记录
//! 3. `gather()` 收集 Prometheus 文本格式输出
//! 4. `tracing_subscriber` JSON 日志初始化（幂等）
//! 5. `init_otlp_tracing(endpoint)` OpenTelemetry OTLP 追踪初始化（全局一次性）
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin observability_setup --features "metrics-prometheus observability-otlp"
//! ```

use bulwark::observability::BulwarkMetrics;
use std::time::Duration;

/// 创建 BulwarkMetrics 实例并注册到自定义 registry（避免污染 default registry）。
///
/// 生产环境可直接用 `BulwarkMetrics::new()` 注册到 default registry，
/// 但测试/示例中推荐使用 `register_to` 避免多次注册导致 panic。
pub fn create_metrics() -> (BulwarkMetrics, bulwark::observability::prometheus::Registry) {
    let registry = bulwark::observability::prometheus::Registry::new();
    let metrics = BulwarkMetrics::register_to(&registry).expect("BulwarkMetrics 注册失败");
    (metrics, registry)
}

/// 演示记录各类指标（登录 / Token 验证 / 权限查询 / 角色查询）。
///
/// 模拟一次完整的认证流程：
/// 1. 登录成功 → record_login(true)
/// 2. Token 验证耗时 → observe_token_validation
/// 3. 权限查询通过 → record_permission_query(true)
/// 4. 角色查询通过 → record_role_query(true)
/// 5. 登录失败 → record_login(false)
pub fn record_sample_metrics(metrics: &BulwarkMetrics) {
    metrics.record_login(true);
    metrics.observe_token_validation(Duration::from_millis(5));
    metrics.record_permission_query(true);
    metrics.record_role_query(true);

    // 模拟一次失败的登录尝试
    metrics.record_login(false);
    metrics.record_permission_query(false);
    metrics.record_role_query(false);
}

/// 收集指标为 Prometheus 文本格式（用于 `/metrics` 端点）。
///
/// 使用自定义 registry 收集，避免 default registry 的干扰。
pub fn gather_metrics(registry: &bulwark::observability::prometheus::Registry) -> String {
    use bulwark::observability::prometheus::Encoder;
    let mut buffer = Vec::new();
    let encoder = bulwark::observability::prometheus::TextEncoder::new();
    encoder.encode(&registry.gather(), &mut buffer).ok();
    String::from_utf8_lossy(&buffer).into_owned()
}

/// 运行 observability_setup 示例。
///
/// 演示完整的可观测性配置流程：
/// 1. 创建 BulwarkMetrics 并记录样本指标
/// 2. 收集 Prometheus 文本输出
/// 3. 初始化 JSON 日志
/// 4. 初始化 OTLP 追踪（需提供 endpoint）
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Bulwark 可观测性配置示例 ===\n");

    // ----------------------------------------------------------------
    // 1. BulwarkMetrics 创建 + 指标记录
    // ----------------------------------------------------------------
    println!("[Metrics] BulwarkMetrics::register_to(&registry):");
    let (metrics, registry) = create_metrics();
    println!("    创建 BulwarkMetrics 实例（注册到自定义 registry）");
    println!();

    println!("[记录] 模拟认证流程指标:");
    record_sample_metrics(&metrics);
    println!("    record_login(true)               → 登录成功 +1");
    println!("    observe_token_validation(5ms)     → Token 验证延迟 5ms");
    println!("    record_permission_query(true)     → 权限查询通过 +1");
    println!("    record_role_query(true)           → 角色查询通过 +1");
    println!("    record_login(false)               → 登录失败 +1");
    println!("    record_permission_query(false)    → 权限查询拒绝 +1");
    println!("    record_role_query(false)          → 角色查询拒绝 +1");
    println!();

    // ----------------------------------------------------------------
    // 2. gather 收集 Prometheus 文本输出
    // ----------------------------------------------------------------
    println!("[gather] 收集 Prometheus 文本格式输出:");
    let output = gather_metrics(&registry);
    for line in output.lines() {
        if !line.starts_with('#') {
            println!("    {}", line);
        }
    }
    println!();

    // 验证关键指标存在
    assert!(
        output.contains("bulwark_login_total"),
        "应包含 login_total 指标"
    );
    assert!(
        output.contains("bulwark_token_validation_duration_seconds"),
        "应包含 token_validation 指标"
    );
    assert!(
        output.contains("bulwark_permission_query_total"),
        "应包含 permission_query 指标"
    );
    assert!(
        output.contains("bulwark_role_query_total"),
        "应包含 role_query 指标"
    );
    println!("    验证：四个指标均已在输出中 ✓");
    println!();

    // ----------------------------------------------------------------
    // 3. tracing_subscriber JSON 日志（幂等）
    // ----------------------------------------------------------------
    println!("[Logs] tracing_subscriber::fmt().json():");
    tracing_subscriber::fmt().json().try_init().ok();
    println!("    JSON 日志已初始化（幂等，重复调用安全）");
    println!();

    // ----------------------------------------------------------------
    // 4. init_otlp_tracing（全局一次性）
    // ----------------------------------------------------------------
    println!("[Traces] init_otlp_tracing(endpoint):");
    let otlp_endpoint = "http://localhost:4317";
    println!("    endpoint: {}", otlp_endpoint);
    println!("    注：OTLP 追踪初始化是全局一次性的，且需要 OTLP collector 运行");
    println!("    此示例仅展示 API 用法，不实际初始化（避免全局状态污染）");
    println!();
    println!("    生产用法:");
    println!("        init_otlp_tracing(\"http://localhost:4317\")?;");
    println!("        // 后续 tracing::info_span!(\"bulwark.login\") 会自动导出到 OTLP");
    println!();

    println!("=== 示例完成 ===");
    Ok(())
}
