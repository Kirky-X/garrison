// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

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
//! - `GARRISON_RATE_LIMIT`：外网每 IP 限速（默认 100，必须 > 0，为 0 时拒绝启动）
//! - `GARRISON_INTERNAL_API_KEY`：内网 API Key（必须配置，无默认值，fail-closed）
//! - `GARRISON_EXTERNAL_LOGIN_ENABLED`：是否启用外网登录端点（默认 **false**）。
//!   框架 login 不校验凭证（Sa-Token 模型：业务层先验密码、框架只签发会话），
//!   业务方注入凭证校验后才应设为 `true`；默认关闭时 `POST /api/v1/auth/login` 返回 404
//! - `GARRISON_WORKER_THREADS`：Tokio worker 线程数（默认 = CPU 核数）
//! - `GARRISON_MAX_BLOCKING_THREADS`：Tokio blocking 线程上限（默认 512）
//!
//! # 使用
//!
//! ```sh
//! cargo run --features auth-server --bin auth_server
//! ```
use std::sync::Arc;

use garrison::backend::embedded::BackendEmbedded;
use garrison::backend::AuthBackend;
use garrison::config::GarrisonConfig;
use garrison::dao::{GarrisonDao, GarrisonDaoOxcache};
use garrison::error::GarrisonResult;
use garrison::manager::GarrisonManager;
use garrison::server::GarrisonAuthServer;
use garrison::stp::GarrisonInterface;
use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// 内网 API 空权限/空角色 interface——生产 bin 不应依赖 test-only mock。
///
/// 行为：所有 login_id 返回空权限列表 + 空角色列表，
/// 因此 `check_permission` / `check_role` 调用时将拒绝（无任何权限/角色放行）。
/// 真实生产场景应替换为业务方自己的 RBAC 实现。
struct SimpleInterface;

#[async_trait::async_trait]
impl GarrisonInterface for SimpleInterface {
    async fn get_permission_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec![])
    }
    async fn get_role_list(&self, _login_id: &str) -> GarrisonResult<Vec<String>> {
        Ok(vec![])
    }
}

/// auth_server 启动引导配置。
///
/// 经 confers 派生宏从 `GARRISON_*` 环境变量加载（env 覆盖 + 默认值），
/// 替代原先逐项手写的 `std::env::var` 解析。字段名按大写映射环境变量：
/// `external_port` → `GARRISON_EXTERNAL_PORT`，以此类推。
///
/// fail-closed 语义：
/// - `internal_api_key` 无默认值——未配置时 `load_sync` 直接报错，拒绝启动；
/// - 空串与 `rate_limit=0` 的防御检查保留在加载之后（见 `async_main`）。
///
/// 与旧手写解析的行为差异：`GARRISON_EXTERNAL_LOGIN_ENABLED` 仅接受
/// `true`/`false`（大小写不敏感），不再接受 `1`；非法值将启动失败而非静默忽略。
#[derive(Debug, Clone, serde::Deserialize, confers::Config)]
#[config(env_prefix = "GARRISON_")]
struct AuthServerBootstrapConfig {
    #[config(default = 8080)]
    external_port: u16,
    #[config(default = 8081)]
    internal_port: u16,
    #[config(default = 100)]
    rate_limit: u32,
    /// 内网 API Key——无默认值，未配置即启动失败（fail-closed, M-SAST-1/M-5）
    internal_api_key: String,
    #[config(default = false)]
    external_login_enabled: bool,
}

/// 初始化全局 GarrisonManager 单例。
///
/// `BackendEmbedded` 委托全局 `GarrisonManager` 单例（零字段结构，不自初始化），
/// 未初始化时所有认证操作返回 `manager-not-init` 错误——因此启动流程必须
/// 先 `GarrisonManager::builder().build().await`（与
/// `examples/src/infrastructure/auth_server.rs::setup_garrison_manager` 一致）。
async fn setup_garrison_manager() -> GarrisonResult<()> {
    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoOxcache::new().await?);
    let config = Arc::new(GarrisonConfig::default_config());
    let interface: Arc<dyn GarrisonInterface> = Arc::new(SimpleInterface);
    GarrisonManager::builder()
        .dao(dao)
        .config(config)
        .interface(interface)
        .build()
        .await?;
    Ok(())
}

fn main() -> GarrisonResult<()> {
    // 显式构建 Tokio runtime，支持通过环境变量调优线程参数
    let worker_threads = std::env::var("GARRISON_WORKER_THREADS")
        .ok()
        .and_then(|s| s.parse().ok());
    let max_blocking_threads = std::env::var("GARRISON_MAX_BLOCKING_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(512);

    let mut runtime_builder = tokio::runtime::Builder::new_multi_thread();
    runtime_builder
        .enable_all()
        .max_blocking_threads(max_blocking_threads);
    if let Some(threads) = worker_threads {
        runtime_builder.worker_threads(threads);
    }

    let runtime = runtime_builder
        .build()
        .expect("failed to build Tokio runtime");

    runtime.block_on(async_main())
}

async fn async_main() -> GarrisonResult<()> {
    // 启动配置：confers 派生宏统一加载（env 覆盖 + 默认值 + 必填缺失即失败）
    let bootstrap = match AuthServerBootstrapConfig::load_sync() {
        Ok(c) => c,
        Err(e) => {
            eprintln!(
                "FATAL: failed to load auth_server bootstrap config from GARRISON_* env vars: {e}"
            );
            std::process::exit(1);
        },
    };
    let external_port = bootstrap.external_port;
    let internal_port = bootstrap.internal_port;
    let rate_limit = bootstrap.rate_limit;
    // 拒绝 0 值——rate_limit=0 会让限速器拒绝所有请求（全部 429）。
    // 负值在解析阶段即失败并启动失败，无需额外校验。
    if rate_limit == 0 {
        eprintln!(
            "FATAL: GARRISON_RATE_LIMIT=0 would reject every request (all 429); \
             set a positive value (e.g. 100), refusing to start"
        );
        std::process::exit(1);
    }
    let internal_api_key = bootstrap.internal_api_key;
    if internal_api_key.is_empty() {
        eprintln!("FATAL: GARRISON_INTERNAL_API_KEY is empty, refusing to start (fail-closed)");
        std::process::exit(1);
    }
    // C-1: 外网登录端点默认关闭（secure-by-default）；业务方注入凭证校验后显式开启
    let external_login_enabled = bootstrap.external_login_enabled;
    if external_login_enabled {
        eprintln!(
            "WARN: external login endpoint ENABLED (GARRISON_EXTERNAL_LOGIN_ENABLED=true); \
             auth_server does NOT verify credentials — ensure the business layer \
             validates credentials before exposing the external port"
        );
    }

    // 初始化 tracing subscriber，避免所有 tracing::info!/error! 静默丢弃
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
        eprintln!("WARN: no observability feature enabled, tracing logs will be dropped. Enable audit-inklog or metrics-prometheus for structured logging.");
    }

    // 创建 BackendEmbedded 作为后端。
    // BackendEmbedded 委托全局 GarrisonManager 单例，
    // 必须先经 GarrisonManager::builder().build().await 初始化，
    // 否则启动后所有认证操作都会报 manager-not-init 错误。
    if let Err(e) = setup_garrison_manager().await {
        tracing::error!(error = %e, "failed to initialize GarrisonManager");
        return Err(e);
    }
    let backend: Arc<dyn AuthBackend> = Arc::new(BackendEmbedded::new());

    let server = GarrisonAuthServer::new(backend)
        .with_external_port(external_port)
        .with_internal_port(internal_port)
        .with_rate_limit(rate_limit)
        .with_external_login_enabled(external_login_enabled)
        .with_internal_api_key(internal_api_key);

    tracing::info!(external_port, internal_port, "starting GarrisonAuthServer");

    // 启动双端口服务器（阻塞直到任一服务器异常）
    if let Err(e) = server.listen().await {
        tracing::error!(error = %e, "server exited abnormally");
        return Err(e);
    }

    Ok(())
}
