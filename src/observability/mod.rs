// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 可观测性模块，提供 Prometheus 指标、结构化 JSON 日志与 OpenTelemetry 分布式追踪。
//!
//! 三层均为 feature 门控：`metrics-prometheus`（指标，经 `GarrisonLogicDefault::with_metrics`
//! 注入，未注入时 no-op）、`audit-inklog`（inklog 日志，失败降级 tracing-subscriber JSON）、
//! `otlp`（OTLP gRPC 追踪）；未启用任一 feature 时所有 API 返回 `None` / no-op。

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
    /// 实例级 registry 引用：`gather()` 从此 registry 收集，而非全局 default registry
    /// （否则自定义 registry 场景返回空数据）。
    pub(crate) registry: prometheus::Registry,
}

/// impl 块子模块（`GarrisonMetrics::new` / `register_to` / `record_*` 等）。
#[cfg(feature = "metrics-prometheus")]
mod metrics_impl;

/// inklog 结构化日志初始化（`init_inklog_logging` / `init_inklog_logging_with_fallback` / `InklogInit`）。
#[cfg(feature = "audit-inklog")]
pub mod inklog;

/// OpenTelemetry OTLP 追踪导出初始化（`init_otlp_tracing`）。
#[cfg(feature = "otlp")]
pub mod otlp;

/// `GarrisonOtelError` 转换实现子模块。
#[cfg(feature = "otlp")]
pub mod errors;

// 公共 re-export（扁平 API）

#[cfg(feature = "audit-inklog")]
pub use inklog::{init_inklog_logging, init_inklog_logging_with_fallback};

#[cfg(feature = "otlp")]
pub use otlp::init_otlp_tracing;
#[cfg(feature = "otlp")]
pub use otlp::shutdown_otlp_tracing;

/// inklog 初始化结果 — 包含可选的 LoggerManager guard 和降级状态。
///
/// `#[must_use]` 确保 guard 不会被意外丢弃（丢弃后 subscriber 可能注销）。
#[cfg(feature = "audit-inklog")]
#[must_use = "InklogInit holds the LoggerManager guard; dropping it may unregister the log subscriber"]
pub struct InklogInit {
    /// LoggerManager guard（降级时为 None，guard 不存在）。
    pub(crate) guard: Option<::inklog::LoggerManager>,
    /// 降级标志：true 表示 inklog 失败，已降级到 tracing-subscriber 默认配置。
    pub(crate) degraded: bool,
}

/// OpenTelemetry 初始化错误。
#[cfg(feature = "otlp")]
#[derive(Debug, thiserror::Error)]
pub enum GarrisonOtelError {
    /// OTLP exporter 构造失败
    #[error("OTLP exporter construction failed: {0}")]
    Exporter(String),
    /// Tracer provider 设置失败
    #[error("Tracer provider setup failed: {0}")]
    Provider(String),
}

/// 指标集合的 feature-gated 别名：`metrics-prometheus` 启用时解析为 [`GarrisonMetrics`]，
/// 未启用时调用方仍可靠 `Option<Arc<GarrisonMetrics>>` 编译。
#[cfg(not(feature = "metrics-prometheus"))]
pub type GarrisonMetrics = ();

#[cfg(test)]
mod tests;
