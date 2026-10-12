// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! OpenTelemetry OTLP gRPC 追踪导出初始化。
//!
//! provider 句柄保存在进程级 `OnceLock`，`set_tracer_provider` 为 last-writer-wins，
//! 无同步时后调用会静默丢弃先前 provider；进程退出前须调用 [`shutdown_otlp_tracing`]
//! flush，否则在途 span 随进程终止静默丢失。

#[cfg(feature = "otlp")]
use super::GarrisonOtelError;

/// 已初始化的全局 tracer provider 句柄（保存句柄供退出前 shutdown/flush）。
#[cfg(feature = "otlp")]
static TRACER_PROVIDER: std::sync::OnceLock<opentelemetry_sdk::trace::SdkTracerProvider> =
    std::sync::OnceLock::new();

/// 初始化 OpenTelemetry OTLP gRPC 追踪导出（`otlp` feature）。
///
/// 进程级幂等：首次调用生效，后续（含并发）调用返回 `Ok(())` 并 `tracing::warn` 提示，
/// **不会**覆盖已注册的 provider；exporter 初始化失败返回 `GarrisonOtelError`。
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

    // endpoint 校验先于幂等检查，非法 endpoint 无论是否已初始化都显性返回 Err
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint)
        .build()?;

    // 并发/重复调用只初始化一次，保留首个 provider（防 last-writer-wins 静默覆盖）
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

    // 句柄供退出前 flush；set 失败说明并发调用抢先注册，保留首个并关闭本次多建的
    if TRACER_PROVIDER.set(provider.clone()).is_err() {
        tracing::warn!(
            "init_otlp_tracing lost a concurrent init race; keeping the first tracer provider"
        );
        provider.shutdown().ok();
        return Ok(());
    }

    opentelemetry::global::set_tracer_provider(provider);

    Ok(())
}

/// Flush 并关闭全局 tracer provider。
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
