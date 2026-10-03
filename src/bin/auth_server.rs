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
//! - `GARRISON_EXTERNAL_BIND`：外网端口绑定地址（IPv4/IPv6 字面量，默认
//!   **127.0.0.1**，secure-by-default，仅本机可达）。容器内须为 `0.0.0.0`
//!   才能被端口映射（镜像已内置该 ENV）；非回环绑定 + 开启外网登录时还须
//!   提供 `GARRISON_EXTERNAL_LOGIN_ACK`。非法值拒绝启动（fail-closed）
//! - `GARRISON_INTERNAL_BIND`：内网端口绑定地址（默认 **127.0.0.1**，语义同上）
//! - `GARRISON_RATE_LIMIT`：外网每 IP 限速（默认 100，必须 > 0，为 0 时拒绝启动）
//! - `GARRISON_INTERNAL_API_KEY`：内网 API Key（必须配置，无默认值，fail-closed；
//!   长度 ≥32 字节，建议 `openssl rand -hex 32` 生成）
//! - `GARRISON_TRUSTED_PROXIES`：可信代理 IP 列表（逗号分隔，默认空）。
//!   仅当部署在可信反代之后才配置；配置后 XFF 解析（限速键 / 客户端 IP）才启用。
//!   仅接受回环/内网地址（与框架 `AuthServerConfig::validate` 同策略），
//!   非法或公网值拒绝启动
//! - `GARRISON_MAX_LOGIN_COUNT`：同账号最大并发会话数（默认 **10**，超出时
//!   踢出最早登录的会话；显式传 0 = 不限制）
//! - `GARRISON_EXTERNAL_LOGIN_ENABLED`：是否启用外网登录端点（默认 **false**）。
//!   框架 login 不校验凭证（Sa-Token 模型：业务层先验密码、框架只签发会话），
//!   业务方注入凭证校验后才应设为 `true`；默认关闭时 `POST /api/v1/auth/login` 返回 404。
//!   **开启前业务层必须已注入凭证校验**；开启且外网绑定为非回环地址时，
//!   还须显式设置 `GARRISON_EXTERNAL_LOGIN_ACK` 才能启动
//! - `GARRISON_EXTERNAL_LOGIN_ACK`：上述场景的显式风险确认，取值必须精确为
//!   `i-understand-no-credential-check`，否则拒绝启动（fail-closed）
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
use std::net::{IpAddr, SocketAddr};
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
/// - `internal_api_key` 长度（GAR-33）、绑定地址与可信代理解析（GAR-30/34）、
///   外网登录暴露确认（GAR-03）在加载之后统一执行（见
///   [`resolve_bootstrap_security`]）；`rate_limit=0` 的防御检查见 `async_main`；
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
    /// 绑定地址（GAR-30）：缺省 127.0.0.1（secure-by-default，仅本机可达）；
    /// 容器部署须显式 0.0.0.0 才能被端口映射（镜像已内置 ENV）。
    /// Option：confers 派生宏不支持字符串字面量 default，
    /// 缺省语义由 [`resolve_bind_addr`] 按 None 处理。
    external_bind: Option<String>,
    internal_bind: Option<String>,
    #[config(default = 100)]
    rate_limit: u32,
    /// 内网 API Key——无默认值，未配置即启动失败（fail-closed, M-SAST-1）；
    /// 长度 ≥32 字节（GAR-33，见 [`validate_internal_api_key`]）
    internal_api_key: String,
    /// 可信代理 IP 列表（GAR-34）：逗号分隔，缺省空（不信任任何 XFF）。
    /// 仅当部署在可信反代之后才配置；配置后 XFF 解析才启用。
    /// Option 语义同 `external_bind`，解析见 [`parse_trusted_proxies`]。
    trusted_proxies: Option<String>,
    #[config(default = false)]
    external_login_enabled: bool,
    /// 外网登录开启且外网绑定为非回环地址时的显式风险确认（GAR-03），
    /// 精确匹配 [`EXTERNAL_LOGIN_ACK`]，否则拒绝启动。
    external_login_ack: Option<String>,
    /// 同账号最大并发会话数（GAR-35）：默认 10（超出踢最早会话），
    /// 覆盖框架 `default_config()` 的 0（不互踢）；显式传 0 = 不限制。
    #[config(default = 10)]
    max_login_count: u32,
    /// 主认证 amr 播种开关（GAR-10）：默认 true 保持框架现状（会话携带
    /// `amr=["pwd"]`/`aal:1`/`auth_time`）；安全敏感部署应显式关闭——
    /// 参考部署 login 不校验凭证，默认播种会把未发生的密码认证写入
    /// 会话因子账本，误导下游 step-up 判定。
    #[config(default = true)]
    seed_primary_amr: bool,
    /// 字段加密密钥表（`field-encryption` feature）：逗号分隔的
    /// `key_id:hex64` 表目（hex64 = 32 字节 AES-256 钥材 hex 编码），
    /// 首项为主钥。feature 启用时必填（fail-closed）。
    /// Option：confers 派生宏对字符串字面量 default 不支持（"Unknown value"），
    /// 缺省语义由装配代码按 None 处理。
    field_encryption_keys: Option<String>,
    /// 字段加密 AAD 租户段（`field-encryption` feature），缺省 "default"。
    field_encryption_tenant: Option<String>,
}

/// 内网管理面唯一凭证的最低字节数（GAR-33）：对齐 jwt_secret HS256 的
/// 32 字节下限——管理面承载 check-*/kickout 等特权端点，短密钥可被爆破。
const MIN_INTERNAL_API_KEY_LEN: usize = 32;

/// 外网登录开启且外网绑定为非回环地址时必须提供的显式风险确认值（GAR-03）：
/// 精确匹配（含大小写）方可启动，杜绝误开。
const EXTERNAL_LOGIN_ACK: &str = "i-understand-no-credential-check";

/// 解析绑定地址（GAR-30）：缺省 127.0.0.1（secure-by-default）；
/// 显式配置必须为合法 IPv4/IPv6 字面量，否则拒绝启动（fail-closed）。
fn resolve_bind_addr(env_name: &str, raw: Option<&str>) -> GarrisonResult<IpAddr> {
    match raw {
        None => Ok(IpAddr::from([127, 0, 0, 1])),
        Some(s) => s.trim().parse::<IpAddr>().map_err(|_| {
            GarrisonError::Config(format!(
                "auth-server-bootstrap::{env_name}-invalid::{s} \
                 (require an IPv4/IPv6 literal, e.g. 127.0.0.1 or 0.0.0.0)"
            ))
        }),
    }
}

/// 可信代理候选地址：仅回环 / RFC 1918 / link-local（IPv4）与
/// 回环 / ULA / link-local（IPv6）——与框架 `AuthServerConfig::validate`
/// 同策略：公网 IP 可被路径中间设备伪造，不得进入 XFF 信任边界。
fn is_internal_proxy_candidate(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local() || v6.is_unicast_link_local(),
    }
}

/// 解析 `GARRISON_TRUSTED_PROXIES`（GAR-34）：逗号分隔 IP 列表，
/// 空/未配置 → 空（不信任任何 XFF）；非法或公网地址拒绝启动（fail-closed）。
fn parse_trusted_proxies(spec: &str) -> GarrisonResult<Vec<IpAddr>> {
    if spec.trim().is_empty() {
        return Ok(vec![]);
    }
    let proxies: Vec<IpAddr> = spec
        .split(',')
        .map(|entry| {
            let raw = entry.trim();
            if raw.is_empty() {
                return Err(GarrisonError::Config(
                    "auth-server-bootstrap::trusted-proxies-empty-entry \
                     (comma-separated IP list, e.g. 10.0.0.1,127.0.0.1)"
                        .to_string(),
                ));
            }
            raw.parse::<IpAddr>().map_err(|_| {
                GarrisonError::Config(format!(
                    "auth-server-bootstrap::trusted-proxies-invalid::{raw} \
                     (require an IPv4/IPv6 literal)"
                ))
            })
        })
        .collect::<GarrisonResult<Vec<_>>>()?;
    if let Some(public) = proxies.iter().find(|ip| !is_internal_proxy_candidate(ip)) {
        return Err(GarrisonError::Config(format!(
            "auth-server-bootstrap::trusted-proxy-not-private::{public} \
             (trusted proxies must be loopback/RFC1918/link-local/IPv6 ULA; \
             public IPs can be spoofed on the path)"
        )));
    }
    Ok(proxies)
}

/// 校验内网 API Key 强度（GAR-33）：管理面唯一凭证，短于 32 字节即拒绝启动。
fn validate_internal_api_key(key: &str) -> GarrisonResult<()> {
    if key.len() < MIN_INTERNAL_API_KEY_LEN {
        return Err(GarrisonError::Config(format!(
            "auth-server-bootstrap::internal-api-key-too-short::{} bytes \
             (minimum {MIN_INTERNAL_API_KEY_LEN}; generate with e.g. `openssl rand -hex 32`)",
            key.len()
        )));
    }
    Ok(())
}

/// 外网登录暴露确认（GAR-03）：登录端点零凭证校验，绑定非回环地址即向
/// 网络暴露任意身份会话铸造——开启且非回环绑定时必须显式确认，否则拒绝启动。
fn ensure_external_login_safety(
    login_enabled: bool,
    external_bind: IpAddr,
    ack: Option<&str>,
) -> GarrisonResult<()> {
    if !login_enabled || external_bind.is_loopback() {
        return Ok(());
    }
    if ack == Some(EXTERNAL_LOGIN_ACK) {
        return Ok(());
    }
    Err(GarrisonError::Config(format!(
        "auth-server-bootstrap::external-login-unacknowledged::{external_bind} \
         (external login does NOT verify credentials; on a non-loopback bind any \
         reachable peer can mint sessions for arbitrary login_id. Set \
         GARRISON_EXTERNAL_LOGIN_ACK={EXTERNAL_LOGIN_ACK} to accept, or keep the \
         default loopback bind / disable external login)"
    )))
}

/// 启动期安全装配（GAR-30/33/34/03）：解析绑定地址与可信代理、校验管理面
/// 密钥强度、复核外网登录暴露确认——任何一项不满足即拒绝启动（fail-closed）。
struct ResolvedSecurity {
    external_bind: IpAddr,
    internal_bind: IpAddr,
    trusted_proxies: Vec<IpAddr>,
}

fn resolve_bootstrap_security(
    bootstrap: &AuthServerBootstrapConfig,
) -> GarrisonResult<ResolvedSecurity> {
    let external_bind =
        resolve_bind_addr("GARRISON_EXTERNAL_BIND", bootstrap.external_bind.as_deref())?;
    let internal_bind =
        resolve_bind_addr("GARRISON_INTERNAL_BIND", bootstrap.internal_bind.as_deref())?;
    let trusted_proxies =
        parse_trusted_proxies(bootstrap.trusted_proxies.as_deref().unwrap_or(""))?;
    validate_internal_api_key(&bootstrap.internal_api_key)?;
    ensure_external_login_safety(
        bootstrap.external_login_enabled,
        external_bind,
        bootstrap.external_login_ack.as_deref(),
    )?;
    Ok(ResolvedSecurity {
        external_bind,
        internal_bind,
        trusted_proxies,
    })
}

/// GAR-35：参考部署的会话策略收口——框架 `default_config()` 的
/// `max_login_count=0`（不互踢）在 bin 层覆盖为 bootstrap 值（默认 10，
/// 超出踢最早会话）；显式传 0 仍表示不限制（保留运维出口）。
/// GAR-10：`seed_primary_amr` 从 bootstrap（env `GARRISON_SEED_PRIMARY_AMR`，
/// 默认 true）接入配置，安全敏感部署可关闭主认证 amr 播种。
fn assemble_garrison_config(max_login_count: u32, seed_primary_amr: bool) -> GarrisonConfig {
    let mut config = GarrisonConfig::default_config();
    config.max_login_count = max_login_count;
    config.seed_primary_amr = seed_primary_amr;
    config
}

///
/// 解析 `key_id:hex64` 逗号分隔密钥表为 (key_id, hex) 表目。
///
/// 空串 → 空表目；表目缺 `:` / key_id 或钥材为空 → 显性报错
/// （钥材 hex 合法性由 `FieldCipher::from_key_entries` 装配期校验）。
#[cfg_attr(not(feature = "field-encryption"), allow(dead_code))]
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
    max_login_count: u32,
    seed_primary_amr: bool,
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
    let config = Arc::new(assemble_garrison_config(max_login_count, seed_primary_amr));
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
    // GAR-30/33/34/03：绑定地址 / 可信代理解析、密钥强度、外网登录暴露确认，
    // 统一 fail-closed——任何一项不满足即拒绝启动
    let security = match resolve_bootstrap_security(&bootstrap) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("FATAL: {e}");
            std::process::exit(1);
        },
    };
    // C-1: 外网登录端点默认关闭（secure-by-default）；业务方注入凭证校验后显式开启
    let external_login_enabled = bootstrap.external_login_enabled;
    if external_login_enabled {
        eprintln!(
            "WARN: external login endpoint ENABLED (GARRISON_EXTERNAL_LOGIN_ENABLED=true); \
             auth_server does NOT verify credentials — ensure the business layer \
             validates credentials before exposing the external port"
        );
    }
    let internal_api_key = bootstrap.internal_api_key;

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
        bootstrap.max_login_count,
        bootstrap.seed_primary_amr,
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
        .with_trusted_proxies(security.trusted_proxies)
        .with_internal_api_key(internal_api_key);

    // GAR-30：框架 GarrisonAuthServer::listen() 将绑定地址硬编码为 0.0.0.0
    // （AuthServerConfig 无绑定地址入口，src/server/ 属框架层不可改），参考部署
    // 在 bin 侧以「自绑定 + axum::serve」收口绑定面：复用 server 的 pub
    // external_router()/internal_router()（限流/审计/API-Key 中间件全量保留），
    // 语义对齐 listen() 的 TCP 明文路径（含优雅停机）。本 bin 未接 with_tls，
    // 需要 TLS 终止时须经框架 listen() 并自行在部署层收口绑定面。
    let external_router = server.external_router();
    let internal_router = server.internal_router();
    let external_listener =
        tokio::net::TcpListener::bind(SocketAddr::new(security.external_bind, external_port))
            .await
            .map_err(|e| GarrisonError::Internal(format!("server-external-bind::{}", e)))?;
    let internal_listener =
        tokio::net::TcpListener::bind(SocketAddr::new(security.internal_bind, internal_port))
            .await
            .map_err(|e| GarrisonError::Internal(format!("server-internal-bind::{}", e)))?;

    tracing::info!(
        external = %external_listener.local_addr().map(|a| a.to_string()).unwrap_or_default(),
        internal = %internal_listener.local_addr().map(|a| a.to_string()).unwrap_or_default(),
        "starting GarrisonAuthServer"
    );

    // 信号监听 → Notify 广播给两个端口 serve future（与框架 listen() 同语义）
    #[cfg(feature = "server-graceful-shutdown")]
    let shutdown_notify = {
        let notify = Arc::new(tokio::sync::Notify::new());
        let n2 = Arc::clone(&notify);
        tokio::spawn(async move {
            shutdown_signal().await;
            n2.notify_waiters();
        });
        notify
    };
    #[cfg(feature = "server-graceful-shutdown")]
    let shutdown_notify_ext = Arc::clone(&shutdown_notify);
    #[cfg(feature = "server-graceful-shutdown")]
    let shutdown_notify_int = Arc::clone(&shutdown_notify);

    let serve_external = async {
        let serve = axum::serve(
            external_listener,
            external_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        );
        #[cfg(feature = "server-graceful-shutdown")]
        let serve = serve.with_graceful_shutdown(async move {
            shutdown_notify_ext.notified().await;
        });
        serve
            .await
            .map_err(|e| GarrisonError::Internal(format!("server-external-server-error::{}", e)))
    };
    let serve_internal = async {
        let serve = axum::serve(
            internal_listener,
            internal_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
        );
        #[cfg(feature = "server-graceful-shutdown")]
        let serve = serve.with_graceful_shutdown(async move {
            shutdown_notify_int.notified().await;
        });
        serve
            .await
            .map_err(|e| GarrisonError::Internal(format!("server-internal-server-error::{}", e)))
    };

    // 双端口并行服务；任一端口异常即整体返回错误（另一端口随之终止）
    if let Err(e) = tokio::try_join!(serve_external, serve_internal) {
        tracing::error!(error = %e, "server exited abnormally");
        return Err(e);
    }

    Ok(())
}

/// 优雅停机信号：SIGTERM / SIGINT 任一到达即返回（与框架 listen() 同语义）。
#[cfg(feature = "server-graceful-shutdown")]
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => {
                sig.recv().await;
            },
            Err(e) => {
                // 信号处理器安装失败（罕见）：不 panic，退化为仅监听 Ctrl-C
                tracing::warn!(error = %e, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            },
        }
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    tracing::info!(
        "shutdown signal received; stopping new connections and draining in-flight requests"
    );
}

#[cfg(test)]
mod bootstrap_tests {
    use super::*;

    /// 32 字节合规测试占位串（非真实凭据）。
    const TEST_KEY: &str = "test-only-not-a-real-key-0123456789abcdef";

    fn secure_defaults() -> AuthServerBootstrapConfig {
        AuthServerBootstrapConfig {
            internal_api_key: TEST_KEY.to_string(),
            ..AuthServerBootstrapConfig::default()
        }
    }

    #[test]
    fn bootstrap_defaults_are_secure_by_default() {
        let b = AuthServerBootstrapConfig::default();
        assert_eq!(b.max_login_count, 10, "默认并发会话上限应为 10（GAR-35）");
        assert_eq!(b.external_bind, None);
        assert_eq!(b.internal_bind, None);
        assert_eq!(b.trusted_proxies, None);

        let resolved =
            resolve_bootstrap_security(&secure_defaults()).expect("默认引导配置应通过安全装配");
        assert_eq!(
            resolved.external_bind,
            IpAddr::from([127, 0, 0, 1]),
            "缺省绑定必须为回环地址（GAR-30 secure-by-default）"
        );
        assert_eq!(resolved.internal_bind, IpAddr::from([127, 0, 0, 1]));
        assert!(resolved.trusted_proxies.is_empty(), "缺省不信任任何代理");
    }

    #[test]
    fn bind_addr_env_overrides_and_rejects_invalid() {
        assert_eq!(
            resolve_bind_addr("GARRISON_EXTERNAL_BIND", Some("0.0.0.0")).unwrap(),
            IpAddr::from([0, 0, 0, 0])
        );
        assert_eq!(
            resolve_bind_addr("GARRISON_INTERNAL_BIND", Some("::1")).unwrap(),
            IpAddr::from([0, 0, 0, 0, 0, 0, 0, 1])
        );
        for bad in ["", "   ", "example.com", "999.1.1.1", "127.0.0.1:8080"] {
            assert!(
                resolve_bind_addr("GARRISON_EXTERNAL_BIND", Some(bad)).is_err(),
                "非法绑定地址应拒绝启动: {bad}"
            );
        }
    }

    #[test]
    fn trusted_proxies_parse_and_private_gate() {
        assert!(parse_trusted_proxies("").unwrap().is_empty());
        assert!(parse_trusted_proxies("   ").unwrap().is_empty());
        assert_eq!(
            parse_trusted_proxies("10.0.0.1, 127.0.0.1").unwrap(),
            vec![IpAddr::from([10, 0, 0, 1]), IpAddr::from([127, 0, 0, 1]),]
        );
        // 非法字面量 / 空表目 → fail-closed
        assert!(parse_trusted_proxies("not-an-ip").is_err());
        assert!(parse_trusted_proxies("10.0.0.1,").is_err());
        // 公网地址不得进入 XFF 信任边界（与框架 validate 同策略）
        assert!(parse_trusted_proxies("8.8.8.8").is_err());
    }

    #[test]
    fn internal_api_key_min_length_enforced() {
        assert!(validate_internal_api_key("").is_err());
        assert!(validate_internal_api_key(&"x".repeat(31)).is_err());
        assert!(validate_internal_api_key(&"x".repeat(32)).is_ok());
        assert!(validate_internal_api_key(TEST_KEY).is_ok());
    }

    #[test]
    fn external_login_ack_gate() {
        let loopback = IpAddr::from([127, 0, 0, 1]);
        let wildcard = IpAddr::from([0, 0, 0, 0]);
        // 关闭登录 / 回环绑定：无需确认
        assert!(ensure_external_login_safety(false, wildcard, None).is_ok());
        assert!(ensure_external_login_safety(true, loopback, None).is_ok());
        // 非回环 + 开启：无确认 / 确认值不精确匹配 → 拒绝启动
        assert!(ensure_external_login_safety(true, wildcard, None).is_err());
        assert!(ensure_external_login_safety(true, wildcard, Some("")).is_err());
        assert!(
            ensure_external_login_safety(true, wildcard, Some("I-UNDERSTAND-NO-CREDENTIAL-CHECK"))
                .is_err(),
            "确认值必须精确匹配（大小写敏感）"
        );
        assert!(ensure_external_login_safety(true, wildcard, Some(EXTERNAL_LOGIN_ACK)).is_ok());
    }

    #[test]
    fn max_login_count_override_and_zero_passthrough() {
        assert_eq!(assemble_garrison_config(10, true).max_login_count, 10);
        assert_eq!(
            assemble_garrison_config(0, true).max_login_count,
            0,
            "显式 0 透传 = 不限制（保留运维出口）"
        );
        assert_eq!(
            assemble_garrison_config(3, true).max_login_count,
            3,
            "env 覆盖值应生效"
        );
    }

    /// GAR-10：bootstrap 的 amr 播种开关装配进 GarrisonConfig。
    #[test]
    fn seed_primary_amr_assembled_into_config() {
        assert!(
            assemble_garrison_config(10, true).seed_primary_amr,
            "默认（true）应保持框架现状播种"
        );
        assert!(
            !assemble_garrison_config(10, false).seed_primary_amr,
            "GARRISON_SEED_PRIMARY_AMR=false 应关闭播种"
        );
    }
}
