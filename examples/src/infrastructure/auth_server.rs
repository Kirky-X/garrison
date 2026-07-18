//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Auth Server 示例：演示 BulwarkAuthServer 双端口配置与一键启动。
//!
//! 对应模块：`src/server/mod.rs`（`auth-server` feature 开启时可用）。
//!
//! 提供两种运行模式：
//! - `run()`：仅演示配置不调用 `listen()`，对应 `auth_server` bin
//! - `serve()`：从 env 读取配置并阻塞 `listen()`，对应 `auth_server_serve` bin
//!
//! `serve()` 用于 E2E / 性能 / 渗透测试的真实进程部署。
//!
//! 运行方式：
//! ```sh
//! # 演示模式（不启动服务）
//! cargo run -p bulwark-examples --bin auth_server --features full
//!
//! # 服务模式（启动双端口，阻塞监听）
//! EXAMPLE_INTERNAL_API_KEY=test \
//! cargo run -p bulwark-examples --bin auth_server_serve --features full
//! ```

use async_trait::async_trait;
use bulwark::backend::{AuthBackend, BackendEmbedded};
use bulwark::config::BulwarkConfig;
use bulwark::context::tenant::HeaderTenantResolver;
use bulwark::dao::{BulwarkDao, BulwarkDaoOxcache};
use bulwark::error::BulwarkResult;
use bulwark::manager::BulwarkManager;
use bulwark::server::BulwarkAuthServer;
use bulwark::stp::BulwarkInterface;
use std::sync::Arc;

/// 简单的 BulwarkInterface 实现（空权限/空角色）。
///
/// 用于 `auth_server_serve` bin 启动时初始化 BulwarkManager，
/// 不依赖 `testing` feature 中的 MockInterface（生产 bin 不应使用 test-only 代码）。
///
/// 行为：所有 login_id 返回空权限列表 + 空角色列表，
/// 因此 `check_permission` / `check_role` 调用时将拒绝（无任何权限/角色放行）。
/// 真实生产场景应替换为业务方自己的 RBAC 实现。
struct SimpleInterface;

#[async_trait]
impl BulwarkInterface for SimpleInterface {
    async fn get_permission_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: &str) -> BulwarkResult<Vec<String>> {
        Ok(vec![])
    }
}

/// 初始化全局 BulwarkManager（创建 BulwarkDaoOxcache + 默认 Config + SimpleInterface）。
///
/// 供 `run()` 和 `serve()` 共用，确保 BulwarkManager 全局单例正确初始化。
///
/// # 失败处理
/// - `BulwarkDaoOxcache::new()` 失败：返回底层错误（内存不足等）
/// - `BulwarkManager::init()` 失败：返回 `AlreadyInitialized` 错误（单例已初始化）
///
/// # 返回
/// `BackendEmbedded` 实例，委托 BulwarkManager 全局单例处理认证逻辑。
pub async fn setup_bulwark_manager() -> BulwarkResult<BackendEmbedded> {
    let dao: Arc<dyn BulwarkDao> = Arc::new(BulwarkDaoOxcache::new().await?);
    let config = Arc::new(BulwarkConfig::default_config());
    let interface: Arc<dyn BulwarkInterface> = Arc::new(SimpleInterface);
    BulwarkManager::init(dao, config, interface)?;
    Ok(BackendEmbedded::new())
}

/// 运行 Auth Server 配置示例。
///
/// 演示：
/// 1. 创建 BackendEmbedded（进程内认证后端）
/// 2. 创建 BulwarkAuthServer 并配置端口、限速、API Key
/// 3. 获取 external_router() 和 internal_router()（不调用 listen）
pub async fn run() -> BulwarkResult<()> {
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

/// 启动 BulwarkAuthServer 双端口服务（阻塞）。
///
/// 从 env 读取配置：
/// - `BULWARK_EXTERNAL_PORT`（默认 8080）：外网端口（login/logout/refresh）
/// - `BULWARK_INTERNAL_PORT`（默认 8081）：内网端口（check-*/get-*/kickout）
/// - `EXAMPLE_INTERNAL_API_KEY`（必填）：内网 API Key，缺失时 fail-closed 退出码 1
/// - `BULWARK_RATE_LIMIT`（默认 100）：每 IP 限速阈值（req/s）
///
/// 调用 `setup_bulwark_manager()` 初始化全局单例后，构造 `BulwarkAuthServer`
/// 并 `server.listen().await` 阻塞监听双端口。
///
/// # stderr 输出格式
/// 启动后向 stderr 输出 `listening on external=0.0.0.0:PORT internal=0.0.0.0:PORT`，
/// 供测试代码（`tests/e2e/remote.rs`）解析端口。
///
/// # Fail-closed 策略
/// `EXAMPLE_INTERNAL_API_KEY` 缺失时立即 `std::process::exit(1)`，
/// 避免使用默认/空 API Key 启动不安全服务。
pub async fn serve() -> BulwarkResult<()> {
    // 1. 从 env 读取配置（端口/限流使用默认值，API Key 必填）
    let external_port: u16 = std::env::var("BULWARK_EXTERNAL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let internal_port: u16 = std::env::var("BULWARK_INTERNAL_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8081);
    let rate_limit: u32 = std::env::var("BULWARK_RATE_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);
    let internal_api_key = std::env::var("EXAMPLE_INTERNAL_API_KEY").unwrap_or_else(|_| {
        eprintln!(
            "FATAL: EXAMPLE_INTERNAL_API_KEY 未设置，fail-closed 退出。\n\
             请通过 `export EXAMPLE_INTERNAL_API_KEY=<your-key>` 设置真实 API Key 后再启动。"
        );
        std::process::exit(1);
    });

    // 2. 初始化 BulwarkManager 全局单例
    let backend: Arc<dyn AuthBackend> = Arc::new(setup_bulwark_manager().await?);

    // 3. 构造 BulwarkAuthServer 并启动（端口 0.0.0.0:PORT，listen() 内部绑定）
    // tenant-isolation feature 启用时注入 HeaderTenantResolver，使
    // tenant_resolution_middleware 解析 X-Tenant-Id header 进入 TENANT scope。
    // 与 tests/e2e/mod.rs::start_e2e_server 行为保持一致，确保 spawn_child 模式
    // 下跨租户隔离生效（T030 测试依赖此行为）。
    #[cfg(feature = "tenant-isolation")]
    let server = BulwarkAuthServer::new(backend)
        .with_external_port(external_port)
        .with_internal_port(internal_port)
        .with_rate_limit(rate_limit)
        .with_internal_api_key(&internal_api_key)
        .with_tenant_resolver(Some(Arc::new(HeaderTenantResolver)));
    #[cfg(not(feature = "tenant-isolation"))]
    let server = BulwarkAuthServer::new(backend)
        .with_external_port(external_port)
        .with_internal_port(internal_port)
        .with_rate_limit(rate_limit)
        .with_internal_api_key(&internal_api_key);

    eprintln!(
        "[auth_server_serve] listening on external=0.0.0.0:{} internal=0.0.0.0:{}",
        external_port, internal_port
    );

    server.listen().await
}
