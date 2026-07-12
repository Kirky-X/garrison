//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! BulwarkAuthServer 二进制入口。
//!
//! 启动双端口 axum 认证服务器：
//! - 外网端口（默认 8080）：login / logout / refresh
//! - 内网端口（默认 8081）：check-* / get-* / kickout 等（需 X-API-Key）
//!
//! # 环境变量
//!
//! - `BULWARK_EXTERNAL_PORT`：外网端口（默认 8080）
//! - `BULWARK_INTERNAL_PORT`：内网端口（默认 8081）
//! - `BULWARK_RATE_LIMIT`：外网每 IP 限速（默认 100）
//! - `BULWARK_INTERNAL_API_KEY`：内网 API Key（默认 "bulwark-internal-key"）
//!
//! # 使用
//!
//! ```sh
//! cargo run --features auth-server --bin auth_server
//! ```

use std::sync::Arc;

use bulwark::backend::embedded::BackendEmbedded;
use bulwark::backend::AuthBackend;
use bulwark::error::BulwarkResult;
use bulwark::server::BulwarkAuthServer;

#[tokio::main]
async fn main() -> BulwarkResult<()> {
    // 从环境变量读取配置（带默认值）
    let external_port = std::env::var("BULWARK_EXTERNAL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let internal_port = std::env::var("BULWARK_INTERNAL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8081);
    let rate_limit = std::env::var("BULWARK_RATE_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let internal_api_key = std::env::var("BULWARK_INTERNAL_API_KEY")
        .unwrap_or_else(|_| "bulwark-internal-key".to_string());

    // 创建 BackendEmbedded 作为后端
    // 注意：BulwarkManager 需要在使用前通过 BulwarkManager::init() 初始化
    // 这里仅创建 BackendEmbedded 实例，实际部署时需确保 Manager 已初始化
    let backend: Arc<dyn AuthBackend> = Arc::new(BackendEmbedded::new());

    let server = BulwarkAuthServer::new(backend)
        .with_external_port(external_port)
        .with_internal_port(internal_port)
        .with_rate_limit(rate_limit)
        .with_internal_api_key(internal_api_key);

    tracing::info!(external_port, internal_port, "启动 BulwarkAuthServer");

    // 启动双端口服务器（阻塞直到任一服务器异常）
    if let Err(e) = server.listen().await {
        tracing::error!(error = %e, "服务器异常退出");
        return Err(e);
    }

    Ok(())
}
