//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! OpenTelemetry OTLP gRPC 追踪导出初始化（spec R-L7-003）。
//!
//! trace context 经 OpenTelemetry 自身的 `Context` 传播（task_local），
//! 通过全局 tracer provider 导出 OTLP span。
//!
//! # 生命周期（ocr #5340/8374）
//!
//! - [`init_otlp_tracing`] 将 provider 句柄保存在进程级 `OnceLock` 中，
//!   并发/重复调用只初始化一次（`set_tracer_provider` 为 last-writer-wins，
//!   无同步时后调用会静默丢弃先前的 provider）；
//! - 进程退出前应调用 [`shutdown_otlp_tracing`] flush 并关闭 batch exporter，
//!   否则在途 span 会随进程终止静默丢失。

#[cfg(feature = "otlp")]
use super::GarrisonOtelError;

/// 已初始化的全局 tracer provider 句柄（ocr #5340：保存句柄供退出前 shutdown/flush）。
#[cfg(feature = "otlp")]
static TRACER_PROVIDER: std::sync::OnceLock<opentelemetry_sdk::trace::SdkTracerProvider> =
    std::sync::OnceLock::new();

/// 初始化 OpenTelemetry OTLP gRPC 追踪导出。
///
/// 启用 `otlp` feature 时可用。trace context 经 OpenTelemetry 自身的
/// `Context` 传播（task_local），通过全局 tracer provider 导出 OTLP span。
///
/// # 幂等性（ocr #8374）
///
/// 进程级只初始化一次：首次调用生效，后续（含并发）调用返回 `Ok(())`
/// 并以 `tracing::warn` 提示，**不会**覆盖已注册的 provider。
///
/// # 参数
/// - `endpoint`: OTLP gRPC endpoint（如 `http://localhost:4317`）
///
/// # 错误
/// - OTLP exporter 初始化失败
///
/// # 使用示例
///
/// ```ignore
/// use garrison::observability::init_otlp_tracing;
///
/// init_otlp_tracing("http://localhost:4317").expect("OTLP 初始化失败");
/// // 后续 tracing::info_span!("garrison.login") 会自动导出到 OTLP endpoint
/// // 进程退出前：shutdown_otlp_tracing() 刷出在途 span
/// ```
#[cfg(feature = "otlp")]
pub fn init_otlp_tracing(endpoint: &str) -> Result<(), GarrisonOtelError> {
    use opentelemetry_otlp::{SpanExporter, WithExportConfig};
    use opentelemetry_sdk::Resource;

    // 端点合法性先行校验：exporter 构建发生在 OnceLock 检查之前，
    // 保证非法 endpoint 无论是否已初始化都显性返回 Err（而非被幂等早退吞掉）
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    // OnceLock 保证并发/重复调用安全：首个调用完成初始化，其余 no-op（防 last-writer-wins）
    if TRACER_PROVIDER.get().is_some() {
        tracing::warn!(
            "init_otlp_tracing called more than once; keeping the first tracer provider (no-op)"
        );
        drop(exporter); // 丢弃本次多建的 exporter，不构建孤儿 provider
        return Ok(());
    }

    let resource = Resource::builder().with_service_name("garrison").build();

    let provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(resource)
        .build();

    // 保存句柄（ocr #5340）：退出前可经 shutdown_otlp_tracing() flush/shutdown。
    // set 失败说明并发调用抢先注册——保留首个，关闭本次多建的 provider。
    if TRACER_PROVIDER.set(provider.clone()).is_err() {
        tracing::warn!(
            "init_otlp_tracing lost a concurrent init race; keeping the first tracer provider"
        );
        provider.shutdown().ok();
        return Ok(());
    }

    // 全局注册 tracer provider（OTLP 导出依赖此全局状态）
    opentelemetry::global::set_tracer_provider(provider);

    Ok(())
}

/// Flush 并关闭全局 tracer provider（ocr #5340）。
///
/// 进程退出前调用，刷出 batch exporter 中在途 span 并释放导出资源；
/// 未初始化时为 no-op 返回 `Ok(())`。重复调用时第二次返回
/// `GarrisonOtelError::Provider`（SDK `AlreadyShutdown`）。
///
/// # 限制
///
/// 若调用方未在退出前调用本函数（或进程被 SIGKILL），batch exporter
/// 中未导出的 span 会丢失——这是批量导出的固有取舍。
#[cfg(feature = "otlp")]
pub fn shutdown_otlp_tracing() -> Result<(), GarrisonOtelError> {
    match TRACER_PROVIDER.get() {
        None => Ok(()),
        Some(provider) => provider
            .shutdown()
            .map_err(|e| GarrisonOtelError::Provider(format!("otlp-provider-shutdown::{}", e))),
    }
}
