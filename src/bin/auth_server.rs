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
//! - `GARRISON_FIELD_ENCRYPTION_KEYS`：落库敏感字段静态加密密钥表
//!   （`field-encryption` feature，逗号分隔 `key_id:hex64`，首项为主钥）；
//!   feature 启用时必填——未配置即拒绝启动（fail-closed）
//! - `GARRISON_FIELD_ENCRYPTION_TENANT`：字段加密 AAD 租户段（默认 "default"）
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
use garrison::error::{GarrisonError, GarrisonResult};
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
/// - 空串与 `rate_limit=0` 的防御检查保留在加载之后（见 `async_main`）；
/// - `field-encryption` feature 启用时 `field_encryption_keys` 为空即拒绝启动
///   （静态加密无钥不运行，见 [`parse_field_encryption_keys`]）。
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
    /// 内网 API Key——无默认值，未配置即启动失败（fail-closed, M-SAST-1）
    internal_api_key: String,
    #[config(default = false)]
    external_login_enabled: bool,
    /// 字段加密密钥表（`field-encryption` feature）：逗号分隔的
    /// `key_id:hex64` 表目（hex64 = 32 字节 AES-256 钥材 hex 编码），
    /// 首项为主钥。feature 启用时必填（fail-closed）。
    /// Option：confers 派生宏对字符串字面量 default 不支持（"Unknown value"），
    /// 缺省语义由装配代码按 None 处理。
    field_encryption_keys: Option<String>,
    /// 字段加密 AAD 租户段（`field-encryption` feature），缺省 "default"。
    field_encryption_tenant: Option<String>,
}

/// 解析 `key_id:hex64` 逗号分隔密钥表为 (key_id, hex) 表目。
///
/// 空串 → 空表目；表目缺 `:` / key_id 或钥材为空 → 显性报错
/// （钥材 hex 合法性由 `FieldCipher::from_key_entries` 装配期校验）。
fn parse_field_encryption_keys(spec: &str) -> GarrisonResult<Vec<(String, String)>> {
    if spec.is_empty() {
        return Ok(vec![]);
    }
    spec.split(',')
        .map(|entry| {
            let (key_id, key_hex) = entry.split_once(':').ok_or_else(|| {
                GarrisonError::Config(format!(
                    "auth-server-field-encryption::entry-missing-colon::{entry}"
                ))
            })?;
            if key_id.is_empty() || key_hex.is_empty() {
                return Err(GarrisonError::Config(format!(
                    "auth-server-field-encryption::entry-empty-part::{entry}"
                )));
            }
            Ok((key_id.to_string(), key_hex.to_string()))
        })
        .collect()
}

/// DAO 装配：`field-encryption` feature 启用时以 `FieldEncryptionDao`
/// 包装底层 DAO（敏感命名空间静态加密 + key 名摘要化），并在启动期构造
/// `FieldCipher` 触发 fail-closed——未配密钥拒绝启动。
async fn setup_garrison_manager(
    field_encryption_keys: &str,
    #[allow(unused_variables)] field_encryption_tenant: &str,
) -> GarrisonResult<()> {
    let dao: Arc<dyn GarrisonDao> = Arc::new(GarrisonDaoOxcache::new().await?);
    #[cfg(feature = "field-encryption")]
    let dao: Arc<dyn GarrisonDao> = {
        let entries = parse_field_encryption_keys(field_encryption_keys)?;
        if entries.is_empty() {
            return Err(GarrisonError::Config(
                "auth-server-field-encryption::no-keys-configured::set \
                 GARRISON_FIELD_ENCRYPTION_KEYS (key_id:hex64,...) or disable \
                 the field-encryption feature"
                    .to_string(),
            ));
        }
        let cipher = garrison::secure::encryption::FieldCipher::from_key_entries(&entries)?;
        let wrapped = garrison::secure::encryption::FieldEncryptionDao::new(
            dao,
            Arc::new(cipher),
            field_encryption_tenant,
        )?;
        Arc::new(wrapped)
    };
    #[cfg(not(feature = "field-encryption"))]
    if !field_encryption_keys.is_empty() {
        eprintln!(
            "WARN: GARRISON_FIELD_ENCRYPTION_KEYS is set but the field-encryption \
             feature is not enabled; the value is ignored"
        );
    }
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
    if let Err(e) = setup_garrison_manager(
        bootstrap.field_encryption_keys.as_deref().unwrap_or(""),
        bootstrap
            .field_encryption_tenant
            .as_deref()
            .unwrap_or("default"),
    )
    .await
    {
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
