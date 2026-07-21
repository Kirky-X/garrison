//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 可观测性模块，提供 Prometheus 指标、结构化 JSON 日志与 OpenTelemetry 分布式追踪。
//!
//! ## 三层架构
//!
//! - **Metrics**（`GarrisonMetrics`）：Prometheus 格式指标，覆盖登录成功率 / Token 验证延迟 /
//!   权限查询 QPS / 角色查询 QPS。启用 `metrics-prometheus` feature。
//! - **Logs**（[`init_inklog_logging`](crate::observability::inklog::init_inklog_logging) /
//!   [`init_inklog_logging_with_fallback`](crate::observability::inklog::init_inklog_logging_with_fallback)）：
//!   inklog 结构化日志（含降级到 tracing-subscriber JSON）。启用 `audit-inklog` feature；
//!   降级路径在 `metrics-prometheus` 或 `tracing-log` 启用时使用 tracing-subscriber JSON。
//! - **Traces**（[`init_otlp_tracing`](crate::observability::otlp::init_otlp_tracing)）：
//!   OpenTelemetry 分布式追踪，OTLP gRPC 导出。启用 `observability-otlp` feature。
//!
//! ## 集成点
//!
//! `GarrisonMetrics` 通过 `GarrisonLogicDefault::with_metrics` builder 注入，未注入时零开销。
//!
//! ## Feature 门控
//!
//! - `metrics-prometheus`：编译期包含 `GarrisonMetrics`，并为 inklog 降级路径提供 tracing-subscriber 依赖
//! - `audit-inklog`：编译期包含 inklog 初始化与降级 API
//! - `observability-otlp`：编译期包含 OTLP 导出器
//! - 未启用任一 feature：模块仍可导入但所有 API 返回 `None` / no-op，保证向后兼容

#[cfg(feature = "metrics-prometheus")]
pub use prometheus;

/// Prometheus 指标集合，覆盖登录 / Token 验证 / 权限查询 / 角色查询。
///
/// 通过 `GarrisonLogicDefault::with_metrics` builder 注入，未注入时所有 `*_metrics` 调用为
/// no-op（`Option::None` 短路）。
///
/// # 指标清单
///
/// | 指标名 | 类型 | 标签 | 说明 |
/// |--------|------|------|------|
/// | `garrison_login_total` | Counter | `result=success\|failure` | 登录尝试次数 |
/// | `garrison_token_validation_duration_seconds` | Histogram | - | Token 验证延迟（秒） |
/// | `garrison_permission_query_total` | Counter | `result=allow\|deny` | 权限查询次数 |
/// | `garrison_role_query_total` | Counter | `result=allow\|deny` | 角色查询次数 |
#[cfg(feature = "metrics-prometheus")]
#[derive(Clone)]
pub struct GarrisonMetrics {
    /// 登录总数 Counter（标签：result=success|failure）
    pub(crate) login_total: prometheus::CounterVec,
    /// Token 验证延迟 Histogram（秒）
    pub(crate) token_validation_duration: prometheus::Histogram,
    /// 权限查询总数 Counter（标签：result=allow|deny）
    pub(crate) permission_query_total: prometheus::CounterVec,
    /// 角色查询总数 Counter（标签：result=allow|deny）
    pub(crate) role_query_total: prometheus::CounterVec,
}

/// impl 块子模块（`GarrisonMetrics::new` / `register_to` / `record_*` 等）。
#[cfg(feature = "metrics-prometheus")]
mod metrics_impl;

/// inklog 结构化日志初始化（`init_inklog_logging` / `init_inklog_logging_with_fallback` / `InklogInit`）。
#[cfg(feature = "audit-inklog")]
pub mod inklog;

/// OpenTelemetry OTLP 追踪导出初始化（`init_otlp_tracing`）。
#[cfg(feature = "observability-otlp")]
pub mod otlp;

/// `GarrisonOtelError` 转换实现子模块。
#[cfg(feature = "observability-otlp")]
pub mod errors;

// ============================================================================
// 公共 re-export（保持向后兼容的扁平 API）
// ============================================================================

#[cfg(feature = "audit-inklog")]
pub use inklog::{init_inklog_logging, init_inklog_logging_with_fallback};

#[cfg(feature = "observability-otlp")]
pub use otlp::init_otlp_tracing;

/// inklog 初始化结果 — 包含可选的 LoggerManager guard 和降级状态。
///
/// M-4: `#[must_use]` 确保 guard 不会被意外丢弃（丢弃后 subscriber 可能注销）。
#[cfg(feature = "audit-inklog")]
#[must_use = "InklogInit 包含 LoggerManager guard，丢弃后日志 subscriber 可能注销"]
pub struct InklogInit {
    /// LoggerManager guard（降级时为 None，guard 不存在）。
    pub(crate) guard: Option<::inklog::LoggerManager>,
    /// 降级标志：true 表示 inklog 失败，已降级到 tracing-subscriber 默认配置。
    pub(crate) degraded: bool,
}

/// OpenTelemetry 初始化错误。
#[cfg(feature = "observability-otlp")]
#[derive(Debug, thiserror::Error)]
pub enum GarrisonOtelError {
    /// OTLP exporter 构造失败
    #[error("OTLP exporter 构造失败: {0}")]
    Exporter(String),
    /// Tracer provider 设置失败
    #[error("Tracer provider 设置失败: {0}")]
    Provider(String),
}

/// 指标集合的 feature-gated 别名。
///
/// - `metrics-prometheus` 启用：解析为 [`GarrisonMetrics`]
/// - 未启用：不可用（调用方使用 `Option<Arc<GarrisonMetrics>>` 时仍可编译）
#[cfg(not(feature = "metrics-prometheus"))]
pub type GarrisonMetrics = ();

#[cfg(test)]
mod tests;
