//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Auth Server 示例：演示 BulwarkAuthServer 双端口配置。
//!
//! 对应模块：`src/server/mod.rs`（`auth-server` feature 开启时可用）。
//!
//! 运行方式：
//! ```sh
//! cargo run -p bulwark-examples --bin auth_server --features full
//! ```
//!
//! 注意：本示例仅演示服务器配置，不调用 `listen()`（会阻塞）。
//! 实际使用时调用 `server.listen().await?` 启动双端口服务。

use bulwark::backend::{AuthBackend, BackendEmbedded};
use bulwark::server::BulwarkAuthServer;
use std::sync::Arc;

/// 运行 Auth Server 配置示例。
///
/// 演示：
/// 1. 创建 BackendEmbedded（进程内认证后端）
/// 2. 创建 BulwarkAuthServer 并配置端口、限速、API Key
/// 3. 获取 external_router() 和 internal_router()（不调用 listen）
pub async fn run() -> bulwark::error::BulwarkResult<()> {
    println!("=== Bulwark Auth Server 配置示例 ===\n");

    // 1. 创建 BackendEmbedded
    let backend: Arc<dyn AuthBackend> = Arc::new(BackendEmbedded::new());
    println!("[1] BackendEmbedded 创建成功");

    // 2. 从环境变量读取 internal API Key（禁止硬编码，防止泄漏）
    let internal_api_key = std::env::var("EXAMPLE_INTERNAL_API_KEY").unwrap_or_else(|_| {
        eprintln!(
            "⚠️  警告：未设置 EXAMPLE_INTERNAL_API_KEY 环境变量，使用占位值 \"REPLACE_ME\"。\n\
             请通过 `export EXAMPLE_INTERNAL_API_KEY=<your-key>` 设置真实 API Key 后再运行示例。"
        );
        "REPLACE_ME".to_string()
    });

    // 3. 创建 BulwarkAuthServer 并配置
    let server = BulwarkAuthServer::new(backend)
        .with_external_port(8080)
        .with_internal_port(8081)
        .with_rate_limit(100)
        .with_internal_api_key(&internal_api_key);
    println!("[2] BulwarkAuthServer 配置完成:");
    println!("    external_port = 8080（面向用户）");
    println!("    internal_port = 8081（服务间调用）");
    println!("    rate_limit    = 100 req/s per IP");
    println!(
        "    internal_api_key = {}（来源：EXAMPLE_INTERNAL_API_KEY 环境变量）\n",
        internal_api_key
    );

    // 4. 获取路由（不调用 listen，避免阻塞）
    let _external_router = server.external_router();
    println!("[3] external_router() 获取成功（login/logout/refresh 端点）");

    let _internal_router = server.internal_router();
    println!("[4] internal_router() 获取成功（check-*/get-*/kickout 等端点）\n");

    println!("=== Auth server configured successfully ===");
    println!("提示：调用 server.listen().await? 可启动双端口服务。");
    Ok(())
}
