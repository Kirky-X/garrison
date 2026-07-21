//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! GarrisonAuthServer 二进制入口。
//!
//! 启动双端口 axum 认证服务器：
//! - 外网端口（默认 8080）：login / logout / refresh
//! - 内网端口（默认 8081）：check-* / get-* / kickout 等（需 X-API-Key）
//!
//! # 环境变量
//!
//! - `GARRISON_EXTERNAL_PORT`：外网端口（默认 8080）
//! - `GARRISON_INTERNAL_PORT`：内网端口（默认 8081）
//! - `GARRISON_RATE_LIMIT`：外网每 IP 限速（默认 100）
//! - `GARRISON_INTERNAL_API_KEY`：内网 API Key（必须配置，无默认值，fail-closed）
//!
//! # 使用
//!
//! ```sh
//! cargo run --features auth-server --bin auth_server
//! ```

use std::sync::Arc;

use garrison::backend::embedded::BackendEmbedded;
use garrison::backend::AuthBackend;
use garrison::error::GarrisonResult;
use garrison::server::GarrisonAuthServer;

#[tokio::main]
async fn main() -> GarrisonResult<()> {
    // 从环境变量读取配置（带默认值）
    let external_port = std::env::var("GARRISON_EXTERNAL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let internal_port = std::env::var("GARRISON_INTERNAL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8081);
    let rate_limit = std::env::var("GARRISON_RATE_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let internal_api_key = std::env::var("GARRISON_INTERNAL_API_KEY").unwrap_or_else(|_| {
        eprintln!(
            "FATAL: GARRISON_INTERNAL_API_KEY 环境变量未配置，拒绝启动（fail-closed，M-SAST-1/M-5）"
        );
        std::process::exit(1);
    });
    if internal_api_key.is_empty() {
        eprintln!("FATAL: GARRISON_INTERNAL_API_KEY 为空字符串，拒绝启动（fail-closed）");
        std::process::exit(1);
    }

    // H-2: 初始化 tracing subscriber，避免所有 tracing::info!/error! 静默丢弃
    #[cfg(feature = "audit-inklog")]
    let _logger = garrison::observability::init_inklog_logging_with_fallback().await;

    // 无 audit-inklog 时，若 metrics-prometheus 或 tracing-log 启用，内联初始化 JSON 日志
    #[cfg(all(
        not(feature = "audit-inklog"),
        any(feature = "metrics-prometheus", feature = "tracing-log")
    ))]
    {
        use tracing_subscriber::EnvFilter;
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
        let result = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .with_current_span(true)
            .with_span_list(false)
            .try_init();
        if let Err(e) = result {
            tracing::debug!("tracing subscriber already initialized, skip: {}", e);
        }
    }

    #[cfg(not(any(
        feature = "audit-inklog",
        feature = "metrics-prometheus",
        feature = "tracing-log"
    )))]
    {
        eprintln!("WARN: 未启用 observability feature，tracing 日志将丢弃。启用 audit-inklog 或 metrics-prometheus 获取结构化日志。");
    }

    // 创建 BackendEmbedded 作为后端
    // 注意：GarrisonManager 需要在使用前通过 GarrisonManager::init() 初始化
    // 这里仅创建 BackendEmbedded 实例，实际部署时需确保 Manager 已初始化
    let backend: Arc<dyn AuthBackend> = Arc::new(BackendEmbedded::new());

    let server = GarrisonAuthServer::new(backend)
        .with_external_port(external_port)
        .with_internal_port(internal_port)
        .with_rate_limit(rate_limit)
        .with_internal_api_key(internal_api_key);

    tracing::info!(external_port, internal_port, "starting GarrisonAuthServer");

    // 启动双端口服务器（阻塞直到任一服务器异常）
    if let Err(e) = server.listen().await {
        tracing::error!(error = %e, "server exited abnormally");
        return Err(e);
    }

    Ok(())
}
