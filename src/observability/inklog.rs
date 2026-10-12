// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! inklog 结构化日志初始化实现：`InklogInit` 的 impl 块与两个顶层 init 函数。

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

/// 使用 inklog 初始化 tracing subscriber（`audit-inklog` feature）。
///
/// inklog 是 subscriber 配置层（多输出、轮转、压缩、脱敏），`tracing::warn!` /
/// `tracing::error!` 宏不变；读取 `RUST_LOG`（默认 `info`），启用 console 输出与
/// secret 扫描门（与审计层 `mask_metadata` 双层防御）。
///
/// 显式关闭内置 file 通道：上游 file masker 无 secret-scan 门，未扫描文本落盘与脱敏语义相悖。
///
/// 返回的 `LoggerManager` guard 须由调用方保持存活以维持日志输出；初始化失败返回 `InklogError`。
#[cfg(feature = "audit-inklog")]
pub async fn init_inklog_logging() -> Result<::inklog::LoggerManager, ::inklog::InklogError> {
    let level = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());
    ::inklog::LoggerManager::builder()
        .level(level)
        .console(true)
        .console_secret_scan(true)
        .file_enabled(false)
        .build()
        .await
}

/// 使用 inklog 初始化 tracing subscriber，失败时降级到 tracing-subscriber 默认配置。
///
/// 降级不丢日志：inklog 失败时，`metrics-prometheus` / `tracing-log` 启用走
/// tracing-subscriber JSON，无 observability feature 时仅 `eprintln!` 警告；
/// 调用方经 [`InklogInit::is_degraded`] 判断是否降级。
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
                    // 区分「已初始化」（可安全跳过）与其他失败（降级不可用，须 warn 暴露，不得静默吞掉）
                    let msg = init_err.to_string();
                    if msg.contains("already") {
                        tracing::debug!(
                            "tracing subscriber already initialized, skip: {}",
                            init_err
                        );
                    } else {
                        tracing::warn!(
                            error = %init_err,
                            "tracing subscriber try_init failed (non-already-initialized error); \
                             degraded fallback logging may be unavailable"
                        );
                    }
                }
            }
            // 无 observability feature 时，无 tracing-subscriber 可用，仅 eprintln! 警告
            #[cfg(not(any(feature = "metrics-prometheus", feature = "tracing-log")))]
            {
                eprintln!(
                    "WARN: inklog init failed and no observability feature enabled, logs will be lost: {}",
                    e
                );
            }
            tracing::warn!(
                error = %e,
                "inklog init failed, degraded to tracing-subscriber default config (spec R-dep-003)"
            );
            InklogInit {
                guard: None,
                degraded: true,
            }
        },
    }
}
