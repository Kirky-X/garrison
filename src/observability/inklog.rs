//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! inklog 结构化日志初始化实现（spec R-L7-003）。
//!
//! 包含：
//! - [`InklogInit`] 的 impl 块（构造方法 + guard 访问）
//! - [`init_inklog_logging`] / [`init_inklog_logging_with_fallback`] 顶层函数

#[cfg(feature = "audit-inklog")]
use super::InklogInit;

#[cfg(feature = "audit-inklog")]
impl InklogInit {
    /// 是否已降级。
    pub fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// 获取 LoggerManager guard（降级时返回 None）。
    pub fn guard(self) -> Option<::inklog::LoggerManager> {
        self.guard
    }
}

/// 使用 inklog 初始化 tracing subscriber。
///
/// 启用 `audit-inklog` feature 时可用。inklog 提供多输出（console/file）、
/// 日志轮转、压缩、脱敏等企业级功能，替代手写 `tracing_subscriber::fmt().json()` 配置。
///
/// `tracing::warn!` / `tracing::error!` 宏不变 — inklog 是 subscriber 配置层。
///
/// # 行为
/// - 读取 `RUST_LOG` 环境变量（默认 `info`）
/// - 启用 console 输出
/// - 返回 `LoggerManager` guard，调用方须保持存活以维持日志输出
///
/// # 错误
/// - inklog 初始化失败（如配置错误）
#[cfg(feature = "audit-inklog")]
pub async fn init_inklog_logging() -> Result<::inklog::LoggerManager, ::inklog::InklogError> {
    let level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    ::inklog::LoggerManager::builder()
        .level(level)
        .console(true)
        .build()
        .await
}

/// 使用 inklog 初始化 tracing subscriber，失败时降级到 tracing-subscriber 默认配置。
///
/// spec R-dep-003 降级机制：inklog 初始化失败时回退到内联 `tracing_subscriber::fmt().json()`
/// 配置，确保日志不丢失。调用方可通过 [`InklogInit::is_degraded`] 判断是否降级。
///
/// # 行为
/// 1. 尝试 inklog::LoggerManager::builder().level().console().build()
/// 2. 成功 → 返回 `InklogInit { guard: Some(mgr), degraded: false }`
/// 3. 失败 → 降级路径（当 `metrics-prometheus` 或 `tracing-log` 启用时用 tracing-subscriber
///    JSON；无 observability feature 时用 `eprintln!` 警告）；再 tracing::warn! 记录降级原因，
///    返回 `InklogInit { guard: None, degraded: true }`
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
