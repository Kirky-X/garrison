//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OpenTelemetry OTLP gRPC 追踪导出初始化（spec R-L7-003）。
//!
//! trace context 经 OpenTelemetry 自身的 `Context` 传播（task_local），
//! 通过全局 tracer provider 导出 OTLP span。

#[cfg(feature = "observability-otlp")]
use super::GarrisonOtelError;

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
/// use garrison::observability::init_otlp_tracing;
///
/// init_otlp_tracing("http://localhost:4317").expect("OTLP 初始化失败");
/// // 后续 tracing::info_span!("garrison.login") 会自动导出到 OTLP endpoint
/// ```
#[cfg(feature = "observability-otlp")]
pub fn init_otlp_tracing(endpoint: &str) -> Result<(), GarrisonOtelError> {
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};
    use opentelemetry_sdk::Resource;

    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    let resource = Resource::builder().with_service_name("garrison").build();

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();

    // 全局注册 tracer provider（OTLP 导出依赖此全局状态）
    opentelemetry::global::set_tracer_provider(provider);

    Ok(())
}
