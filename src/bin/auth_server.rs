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
//! - `GARRISON_INTERNAL_API_KEY`：内网 API Key（必须配置，无默认值，fail-closed）。
//!   长度下限由库层 `MIN_INTERNAL_API_KEY_LEN`（32 字节）统一强制，建议
//!   `openssl rand -hex 32` 生成
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
//! - `GARRISON_STRICT_SECURITY`：严格安全档（默认 **true**）。参考部署始终 fail-closed：
//!   密钥不足下限、外网登录暴露未 ACK 均在 `setup_garrison_manager` 之前由库层
//!   `AuthServerConfig::validate()` 拒绝启动。`false` 仅作为密钥尚未轮换时的
//!   一次性逃生阀（同条件降级为库层告警，即棘轮的非严格档）。本路径经 confers
//!   只接受 `true`/`false`（大小写不敏感），非法值拒绝启动——与库层
//!   `AuthServerConfig::default()` 的 `env_flag` 语义不同（后者非法值告警后
//!   回退库层缺省 `false`，以保证不经 bin 的存量部署零行为变化）
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
use std::net::IpAddr;
use std::sync::Arc;

use garrison::backend::embedded::BackendEmbedded;
use garrison::backend::AuthBackend;
use garrison::config::GarrisonConfig;
use garrison::dao::{GarrisonDao, GarrisonDaoOxcache};
use garrison::error::{GarrisonError, GarrisonResult};
use garrison::manager::GarrisonManager;
use garrison::server::is_private_proxy_addr;
use garrison::server::{AuthServerConfig, GarrisonAuthServer};
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
    /// 长度下限由库层 [garrison::server::MIN_INTERNAL_API_KEY_LEN] 统一强制（GAR-33）
    internal_api_key: String,
    /// 可信代理 IP 列表（GAR-34）：逗号分隔，缺省空（不信任任何 XFF）。
    /// 仅当部署在可信反代之后才配置；配置后 XFF 解析才启用。
    /// Option 语义同 `external_bind`，解析见 [`parse_trusted_proxies`]。
    trusted_proxies: Option<String>,
    #[config(default = false)]
    external_login_enabled: bool,
    /// 外网登录开启且外网绑定为非回环地址时的显式风险确认（GAR-03），
    /// 精确匹配 [garrison::server::EXTERNAL_LOGIN_ACK]，否则不得启动。
    external_login_ack: Option<String>,
    /// 严格安全档（棘轮）：参考部署**缺省 `true`**，保持 rc.3 的 fail-closed 基线
    /// （短密钥、未 ACK 的外网登录暴露均拒启动）。库层 `AuthServerConfig` 的同名字段
    /// 缺省为 `false`（默认路径只告警）；`GARRISON_STRICT_SECURITY=false` 仅作
    /// 一次性逃生阀（密钥尚未轮换时）。本路径经 confers 只接受 `true`/`false`，
    /// 非法值拒绝启动（与库层 `env_flag` 的「告警后回退」语义不同）。
    #[config(default = true)]
    strict_security: bool,
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
    if let Some(public) = proxies.iter().find(|ip| !is_private_proxy_addr(ip)) {
        return Err(GarrisonError::Config(format!(
            "auth-server-bootstrap::trusted-proxy-not-private::{public} \
             (trusted proxies must be loopback/RFC1918/link-local/IPv6 ULA; \
             public IPs can be spoofed on the path)"
        )));
    }
    Ok(proxies)
}

/// 启动期安全装配（GAR-30/33/34/03 + 棘轮）：解析绑定地址与可信代理，连同
/// 密钥 / 外网登录 / ACK / 严格档装配成一个完整 `AuthServerConfig`，并在
/// 触碰任何外部依赖（DAO / 迁移）之前调用库层 `validate()` 提前 fail-closed。
///
/// 护栏判定全部在库层（`garrison::server`），bin 不持有阈值常量与判定函数副本；
/// 严格档由 bootstrap 显式带入（缺省 `true`），覆盖 `..AuthServerConfig::default()`
/// 的库层缺省 `false`。
fn resolve_bootstrap_security(
    bootstrap: &AuthServerBootstrapConfig,
) -> GarrisonResult<AuthServerConfig> {
    let external_bind =
        resolve_bind_addr("GARRISON_EXTERNAL_BIND", bootstrap.external_bind.as_deref())?;
    let internal_bind =
        resolve_bind_addr("GARRISON_INTERNAL_BIND", bootstrap.internal_bind.as_deref())?;
    let trusted_proxies =
        parse_trusted_proxies(bootstrap.trusted_proxies.as_deref().unwrap_or(""))?;
    let config = AuthServerConfig {
        external_port: bootstrap.external_port,
        internal_port: bootstrap.internal_port,
        external_bind,
        internal_bind,
        external_rate_limit_per_ip: bootstrap.rate_limit,
        rate_limit_trusted_proxies: trusted_proxies,
        internal_api_key: bootstrap.internal_api_key.clone(),
        external_login_enabled: bootstrap.external_login_enabled,
        external_login_ack: bootstrap.external_login_ack.clone(),
        strict_security: bootstrap.strict_security,
        ..AuthServerConfig::default()
    };
    // 先校验后启动：失败映射为 Config 错误，调用方保持 eprintln + exit(1)
    // （acc_srv_030/031 的快速退出不依赖建库与迁移）。
    config.validate().map_err(GarrisonError::Config)?;
    Ok(config)
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
// 唯一调用方 setup_garrison_manager 在 field-encryption 块内，cfg 全隔离：
// 非 field-encryption 构建不编译本函数，无需 dead_code 豁免。
#[cfg(feature = "field-encryption")]
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
    // 拒绝 0 值——rate_limit=0 会让限速器拒绝所有请求（全部 429）。
    // 负值在解析阶段即失败并启动失败，无需额外校验。
    if bootstrap.rate_limit == 0 {
        eprintln!(
            "FATAL: GARRISON_RATE_LIMIT=0 would reject every request (all 429); \
             set a positive value (e.g. 100), refusing to start"
        );
        std::process::exit(1);
    }
    // GAR-30/33/34/03 + 棘轮：绑定地址 / 可信代理 / 密钥强度 / 外网登录暴露确认
    // 统一交由库层 `validate()` 判定，且保持在 `setup_garrison_manager` 之前——
    // 任何一项不满足即拒绝启动，不触碰 DAO 与迁移。
    let config = match resolve_bootstrap_security(&bootstrap) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("FATAL: {e}");
            std::process::exit(1);
        },
    };
    // C-1: 外网登录端点默认关闭（secure-by-default）；业务方注入凭证校验后显式开启
    if config.external_login_enabled {
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
        bootstrap.max_login_count,
        bootstrap.seed_primary_amr,
    )
    .await
    {
        tracing::error!(error = %e, "failed to initialize GarrisonManager");
        return Err(e);
    }
    let backend: Arc<dyn AuthBackend> = Arc::new(BackendEmbedded::new());

    // GAR-30 / 棘轮：配置对象整体注入——字段清单只在 `resolve_bootstrap_security`
    // 一处装配（端口 / 绑定 / 限速 / 代理 / 密钥 / 严格档），不在装配侧逐项重复；
    // `listen()` 仍会再调 `validate()`（幂等），启动前的提前校验保证
    // 「未触碰外部依赖即已 fail-closed」。
    GarrisonAuthServer::new(backend)
        .with_config(config)
        .listen()
        .await
}

#[cfg(test)]
mod bootstrap_tests {
    use super::*;
    // 库层阈值常量仅在本模块的行为测试中引用（护栏判定全部在库层），因此
    // 由本模块引入；顶层 `use` 保留给非测试代码实际使用的 `is_private_proxy_addr`，
    // 否则非测试构建会产生 unused import 告警。
    use garrison::server::{EXTERNAL_LOGIN_ACK, MIN_INTERNAL_API_KEY_LEN};

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
        assert!(
            resolved.rate_limit_trusted_proxies.is_empty(),
            "缺省不信任任何代理"
        );
        assert!(!resolved.external_login_enabled, "外网登录缺省关闭（C-1）");
        assert_eq!(
            resolved.external_port,
            secure_defaults().external_port,
            "端口经配置对象整体注入不得丢失（R-auth-server-guardrails-004）"
        );
        assert_eq!(
            resolved.external_rate_limit_per_ip,
            secure_defaults().rate_limit,
            "限速经配置对象整体注入不得丢失"
        );
    }

    /// 棘轮：参考部署缺省即严格档（保持 rc.3 的 fail-closed 基线），且严格档
    /// 恒取 bootstrap 值——`..AuthServerConfig::default()` 的库层缺省 `false`
    /// 必须被显式字段覆盖，否则 bin 退化为只告警。
    #[test]
    fn strict_security_defaults_on_in_bin() {
        assert!(
            AuthServerBootstrapConfig::default().strict_security,
            "bin 缺省严格档（GARRISON_STRICT_SECURITY 缺省 true）"
        );
        let resolved =
            resolve_bootstrap_security(&secure_defaults()).expect("默认引导配置应通过安全装配");
        assert!(
            resolved.strict_security,
            "bootstrap 的严格档必须覆盖库层缺省 false（显式字段优先于 ..default()）"
        );
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

    /// 严格档下的密钥长度下限由**库层** `validate()` 强制（bin 不再自带判定副本），
    /// 非严格档（逃生阀）同输入只告警不拒绝——棘轮的非破坏语义。
    #[test]
    fn internal_api_key_min_length_enforced() {
        let mut b = secure_defaults();
        b.internal_api_key = "x".repeat(MIN_INTERNAL_API_KEY_LEN - 8);
        assert_eq!(b.internal_api_key.len(), 24, "构造低于下限的密钥");
        let err = resolve_bootstrap_security(&b).expect_err("严格档下 24 字节密钥应拒启动");
        assert!(
            matches!(err, GarrisonError::Config(ref m) if m.contains("server-internal-api-key-too-short")),
            "错误应为库层下限拒绝，实际: {:?}",
            err
        );
        b.strict_security = false;
        assert!(
            resolve_bootstrap_security(&b).is_ok(),
            "非严格档应保持存量短密钥部署可启动（只告警）"
        );
    }

    /// 外网登录暴露确认：判定在库层 `validate()`，bin 只负责装配与 fail-closed。
    #[test]
    fn external_login_ack_gate() {
        let mut b = secure_defaults();
        b.external_login_enabled = true;
        // 回环绑定：无需确认
        b.external_bind = Some("127.0.0.1".to_string());
        assert!(
            resolve_bootstrap_security(&b).is_ok(),
            "回环绑定开启外网登录无需 ACK（acc_srv_033 同源语义）"
        );
        // 非回环 + 无确认 / 空确认 / 确认值不精确匹配 → 不得启动
        b.external_bind = Some("0.0.0.0".to_string());
        assert!(
            resolve_bootstrap_security(&b).is_err(),
            "非回环 + 无确认应拒启动（acc_srv_032 同源语义）"
        );
        b.external_login_ack = Some(String::new());
        assert!(
            resolve_bootstrap_security(&b).is_err(),
            "空确认串不得视为已确认"
        );
        b.external_login_ack = Some("I-UNDERSTAND-NO-CREDENTIAL-CHECK".to_string());
        assert!(
            resolve_bootstrap_security(&b).is_err(),
            "确认值必须精确匹配（大小写敏感）"
        );
        b.external_login_ack = Some(EXTERNAL_LOGIN_ACK.to_string());
        assert!(
            resolve_bootstrap_security(&b).is_ok(),
            "精确匹配 ACK 应放行"
        );
        // 严格档关闭（逃生阀）时同条件不再拒绝
        b.strict_security = false;
        assert!(
            resolve_bootstrap_security(&b).is_ok(),
            "非严格档不应因未 ACK 拒启动（降级为告警）"
        );
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
