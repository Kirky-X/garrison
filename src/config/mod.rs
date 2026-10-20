// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! 配置模块，提供 GarrisonConfig 全局配置。
//!
//! 配置源由 confers 接管，优先级：环境变量（`GARRISON_` 前缀自动覆盖）> toml 文件（`GarrisonConfig::load`）> 代码默认值（`ConfigBuilder::default()`）。
//! 热更新通过 `tokio::sync::watch` 广播：`watch()` 返回接收端，`update(f)` 闭包式修改并广播。

#[cfg(feature = "credit-metering")]
use crate::credit::CreditConfig;
#[cfg(feature = "rate-limit-redis")]
use crate::strategy::rate_limiter_backend::RateLimitBackend;
#[cfg(feature = "web-cors")]
use crate::web::cors::CorsConfig;
#[cfg(feature = "web-csrf")]
use crate::web::csrf::CsrfConfig;
use confers::types::ConfigValue;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::watch;

pub mod deprecation;
pub mod impls;
/// 配置安全规则集（`config-security-rules` feature 门控，见模块文档）。
#[cfg(feature = "config-security-rules")]
mod security_rules;
/// Token 风格合法值（token_style 校验白名单，4 选一）。
pub const TOKEN_STYLES: &[&str] = &["uuid", "random_64", "simple", "jwt"];

/// Cookie SameSite 合法值。
pub const COOKIE_SAME_SITE_VALUES: &[&str] = &["Lax", "Strict", "None"];

/// 默认 Token 名称（对应 HTTP Header / Cookie 字段名）。
pub const DEFAULT_TOKEN_NAME: &str = "garrison_token";

/// 默认 Token 超时秒数（30 天）。
pub const DEFAULT_TIMEOUT: i64 = 2_592_000;

/// 默认活动超时检测值（-1 = 不启用）。
pub const DEFAULT_ACTIVE_TIMEOUT: i64 = -1;

/// 默认 Cookie Secure 标志。
///
/// 非 `development` profile（未启用 `development` 聚合特性）默认 `true`，
/// 避免嵌入方忘记开启 Secure；`development` profile 默认 `false`，支持本地 HTTP 调试。
/// 两种 profile 均可经 `GarrisonConfig::cookie_secure` 显式覆盖。
#[cfg(feature = "development")]
pub const DEFAULT_COOKIE_SECURE: bool = false;

/// 默认 Cookie Secure 标志（非 `development` profile 强制安全默认）。
#[cfg(not(feature = "development"))]
pub const DEFAULT_COOKIE_SECURE: bool = true;

/// 默认 Cookie SameSite 策略（"Lax" 平衡安全与可用性）。
pub const DEFAULT_COOKIE_SAME_SITE: &str = "Lax";

/// 默认 JWT 签名算法（HS256，兼容 HS512 可选）。
pub const DEFAULT_JWT_ALGORITHM: &str = "HS256";

/// JWT 签名算法白名单；`validate_core` 无论 token_style 是否 jwt 都先校验，防非法值在非 JWT 模式静默通过。
/// 非对称算法（RS256/ES256/EdDSA）需配套对应私钥 PEM 字段。
pub const JWT_ALGORITHMS: &[&str] = &["HS256", "HS384", "HS512", "RS256", "ES256", "EdDSA"];

/// Argon2id 内存成本下限（KiB，19 MiB，OWASP 建议档 m=19MiB/t=2/p=1）。
/// `validate_core` 强制 `argon2_m_cost ≥ 19456`，更低须 `password_hasher.allow_weak_argon2_params = true` 显式风险接受。
pub const ARGON2_MIN_M_COST: u32 = 19_456;

/// bcrypt cost 允许区间 `[10, 15]`（OWASP 建议 ≥10；>15 单次哈希秒级耗时，拒绝误配）。
pub const BCRYPT_MIN_COST: u32 = 10;
/// bcrypt cost 允许区间上界。
pub const BCRYPT_MAX_COST: u32 = 15;

/// Argon2 并发令牌池默认大小（1 = 同时至多一次 Argon2 执行，默认配置即受内存 DoS 防护）。
pub const DEFAULT_ARGON2_POOL_SIZE: u32 = 1;

/// Argon2 并发令牌池下界（0 = 零 permit 永久饥饿，校验 fail-fast 拒绝）。
pub const ARGON2_POOL_SIZE_MIN: u32 = 1;

/// Argon2 并发令牌池上界（256 × 19 MiB ≈ 4.8 GiB，拒绝更大的误配值）。
pub const ARGON2_POOL_SIZE_MAX: u32 = 256;

/// 密码哈希算法白名单（`password_hasher.algorithm`）。
pub const PASSWORD_HASH_ALGORITHMS: &[&str] = &["argon2id", "bcrypt"];

/// 默认签名校验时间窗口秒数（5 分钟）。
pub const DEFAULT_SIGN_WINDOW_SECONDS: i64 = 300;

/// 默认 SSO ticket TTL 秒数（60 秒）。
pub const DEFAULT_SSO_TICKET_TTL_SECONDS: u64 = 60;

/// 默认 JWKS 退役保留时长秒数（7200 = 2× access token TTL，保证存量 token 过期前旧钥不退役）。
pub const DEFAULT_JWKS_RETENTION_SECS: u64 = 7200;

/// 默认 remember-me 超时秒数（90 天，必须 > DEFAULT_TIMEOUT 30 天）。
pub const REMEMBER_ME_DEFAULT_TIMEOUT: i64 = 7_776_000;

/// 默认会话悬停超时秒数（-1 = 不启用）。
pub const DEFAULT_SESSION_HOVER_TIMEOUT: i64 = -1;

/// 默认前后端分离模式（false = Cookie 模式，true = Token Header 模式）。
pub const DEFAULT_FRONTEND_SEPARATION: bool = false;

/// 默认是否从请求体读取 Token（false = 不读取）。
pub const DEFAULT_IS_READ_BODY: bool = false;

/// 默认自动续签阈值（-1 = 不启用，0-100 = 剩余 TTL 百分比低于此值时触发续签）。
pub const DEFAULT_AUTO_RENEWAL_THRESHOLD: i64 = -1;

/// 默认 token map 清理间隔秒数（5 分钟；`<= 0` 禁用后台清理 task，与 `spawn_cleanup_task` 行为一致）。
pub const DEFAULT_TOKEN_MAP_CLEANUP_INTERVAL: i64 = 300;

/// 默认 login_token_map 持久化写入间隔秒数（仅 `login-token-map-persistence` feature 生效）。
/// 0 = 每次变更同步写 DAO（强一致）；>0 = 后台 task 按间隔批量写（最终一致）。
pub const DEFAULT_LOGIN_TOKEN_MAP_PERSIST_INTERVAL_SECS: u64 = 0;

/// 默认 L1 缓存 TTL 秒数（30 秒，仅 `three-tier-cache` feature 生效；oxcache 内存层，TTL 短保证新鲜度）。
pub const DEFAULT_L1_CACHE_TTL_SECS: u64 = 30;

/// 默认 L2 缓存 TTL 秒数（300 秒 = 5 分钟，仅 `three-tier-cache` feature 生效；DAO 持久化层，TTL 长以减少 L3 回调压力）。
pub const DEFAULT_L2_CACHE_TTL_SECS: u64 = 300;

/// 默认 L1 缓存容量（10000 条，仅 `three-tier-cache` feature 生效；超出按 LRU 淘汰）。
pub const DEFAULT_L1_CACHE_CAPACITY: u64 = 10_000;

/// 默认匿名 Session 超时秒数（1800 = 30 分钟，仅 `anonymous-session` feature 生效）。
pub const DEFAULT_ANON_SESSION_TIMEOUT_SECS: u64 = 1800;

/// 默认是否允许并发登录（true = 同一账号可同时在多设备登录）。
pub const DEFAULT_IS_CONCURRENT: bool = true;

/// 默认是否共享 Token（true = 同一账号多登录复用同一 Token，要求 is_concurrent=true）。
pub const DEFAULT_IS_SHARE: bool = false;

/// 默认最大登录数量（0 = 不限制，>0 = 超出时踢出最早登录的会话）。
pub const DEFAULT_MAX_LOGIN_COUNT: u32 = 0;

/// login_id 默认长度上限（字节，255；0 = 框架层不限）。
/// HTTP wire 层 `LoginRequest` 反序列化始终按本常量封顶（防未认证超大 login_id 灌入会话存储的内存增长），运行时配置只能进一步收紧该上限。
pub const DEFAULT_LOGIN_ID_MAX_LEN: u32 = 255;

/// 默认设备绑定模式（"disabled" = 不启用设备绑定）。
pub const DEFAULT_DEVICE_BINDING_MODE: &str = "disabled";

/// 设备绑定模式合法值（"strict" / "loose" / "disabled"）。
pub const DEVICE_BINDING_MODES: &[&str] = &["strict", "loose", "disabled"];

/// 默认顶人下线策略的 serde 表示（"old_device" = 踢出旧设备）。
pub const DEFAULT_REPLACED_LOGIN_EXIT_MODE: &str = "old_device";

/// 默认溢出处理策略的 serde 表示（"logout" = 登出最旧会话）。
pub const DEFAULT_OVERFLOW_LOGOUT_MODE: &str = "logout";

/// 默认 refresh token 重用处置策略的 serde 表示（"theft_detected" = 按盗用处理）。
pub const DEFAULT_RECENT_REUSE_BEHAVIOUR: &str = "theft_detected";

/// 默认 refresh token 宽限窗口时长秒数（0 = 关闭宽限窗口）。
pub const DEFAULT_REFRESH_GRACE_PERIOD_SECS: i64 = 0;

/// 默认 refresh token 宽限窗口内同一旧 token 的最大宽限兑现次数。
pub const DEFAULT_REFRESH_GRACE_MAX_USES: u32 = 1;

/// 默认异常登录分析器扫描间隔秒数（3600 = 1 小时，仅 `anomalous-detector-dual` feature 生效）。
pub const DEFAULT_ANOMALOUS_ANALYZER_INTERVAL_SECS: u64 = 3600;

/// 默认异常登录 burst 检测阈值（5 次/小时，仅 `anomalous-detector-dual` feature 生效）。
pub const DEFAULT_ANOMALOUS_BURST_THRESHOLD: u32 = 5;

/// 环境变量前缀（GARRISON_）。
pub const ENV_PREFIX: &str = "GARRISON_";

// 并发登录控制枚举

/// 顶人下线策略：`is_concurrent=false` 时新设备登录踢出旧设备放行新设备，或拒绝新设备保留旧设备。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplacedLoginExitMode {
    /// 踢出旧设备，允许新设备登录（默认）。
    #[default]
    OldDevice,
    /// 拒绝新设备登录，保留旧设备。
    NewDevice,
}

/// 溢出处理策略：`max_login_count` 超限时登出/踢出/顶替最旧会话（分别触发 Logout / Kickout / Replaced 事件）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OverflowLogoutMode {
    /// 登出最旧会话（默认，触发 Logout 事件）。
    #[default]
    Logout,
    /// 踢出最旧会话（触发 Kickout 事件）。
    Kickout,
    /// 顶替最旧会话（触发 Replaced 事件）。
    Replaced,
}

/// 会话劫持检测模式：`check_login` 路径 IP 对比疑似劫持时仅告警，或告警并踢出会话（均需 `session-hijack-detection` feature）。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionHijackMode {
    /// 仅广播告警事件，不踢出会话（默认，安全降级）。
    #[default]
    AlertOnly,
    /// 广播告警事件并踢出疑似被劫持的会话。
    Kickout,
}

/// Refresh token 重用处置策略（`recent_reuse_behaviour`）。
///
/// 决定「已消费 token 再次呈现且存在存活后代」（RecentPrev / OrphanedBranch 分类）的处置；无存活血缘的 StaleLineage 恒按盗用处理，不受本配置影响。
/// 默认 `TheftDetected` 按盗用吊销整条 chain（OAuth2 线上即 RFC 6819 §5.2.2.1 建议）；`Unauthorised` 仅拒绝本次请求（401）不吊销，供存在良性并发刷新且接受旧 token 泄露窗口的部署做风险取舍。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecentReuseBehaviour {
    /// 按盗用处理（默认）：吊销整条 chain + `TokenRevoked`。
    #[default]
    TheftDetected,
    /// 仅拒绝本次请求（401），不吊销 chain。
    Unauthorised,
}

// 多租户隔离配置

/// 租户解析器类型（配置文件中用小写 `"header"` / `"subdomain"` / `"claim"`）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TenantResolverKind {
    /// 从 `X-Tenant-Id` 请求头解析（`HeaderTenantResolver`）。
    Header,
    /// 从 `Host` header 的 subdomain 解析（`SubdomainTenantResolver`）。
    Subdomain,
    /// 从 JWT `tenant_id` claim 解析（`ClaimTenantResolver`）。
    Claim,
}

/// 审计脱敏模式：`Full` 全量替换为 `"***"`；`Partial` 用 `SensitiveDataMasker` 类型感知脱敏（如手机号 → `138****1234`），无规则字段回退 `"***"`。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditMaskMode {
    /// 所有敏感字段值替换为固定 `"***"`（完全屏蔽）。
    Full,
    /// 使用 `SensitiveDataMasker` 类型感知脱敏（保留部分可见信息）。
    #[default]
    Partial,
}

/// 多租户隔离配置段（默认 `enabled: false`、`resolver: Header` 从 `X-Tenant-Id` header 解析）。
///
/// # 配置示例
///
/// ```toml
/// [tenant_isolation]
/// enabled = true
/// resolver = "header"
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TenantIsolationConfig {
    /// 是否启用多租户隔离。
    pub enabled: bool,
    /// 租户解析器类型。
    pub resolver: TenantResolverKind,
}

/// MFA/step-up 编排配置段（`mfa`）。
///
/// 承载 per-client MFA chain 三态与全局默认链；factor 词汇表校验（fail-closed）见 [`crate::stp::mfa::validate_mfa_chains`]。
/// `per_client_chains` 三态：键缺失 → 回退 `global_chain`；空数组 → 显式禁用；非空数组 → 强制该集合。
///
/// # 配置示例
///
/// ```toml
/// [mfa]
/// global_chain = ["otp"]
///
/// [mfa.per_client_chains]
/// "legacy-client" = []
/// "admin-console" = ["webauthn"]
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct MfaConfig {
    /// 全局默认 chain（factor 列表；空 = 不强制 MFA）。
    pub global_chain: Vec<String>,
    /// per-client chain 覆盖表（键 = client 标识；语义见结构体文档三态）。
    pub per_client_chains: HashMap<String, Vec<String>>,
    /// 恢复码误用豁免额度（默认 0）：连续无效 verify 超过该次数即锁定。
    pub recovery_misuse_tolerance: u32,
}

/// 密码哈希配置段（`password_hasher`）：驱动 `Argon2Hasher` / `BcryptHasher` 构造（`build_hasher()` 工厂），默认值即 OWASP 建议档（Argon2id m=19456/t=2/p=1，选型见 `docs/adr/0001-argon2id-password-hashing.md`）。
///
/// 校验（`validate_core`，fail-closed）：`algorithm ∈ {argon2id, bcrypt}`；Argon2id `m_cost ≥ 19456`（更低需 `allow_weak_argon2_params = true` 显式风险接受并 warn）、`t_cost/p_cost ≥ 1`、`argon2_pool_size ∈ [1, 256]`；bcrypt `10 ≤ cost ≤ 15`。
///
/// # 配置示例
///
/// ```toml
/// [password_hasher]
/// algorithm = "argon2id"
/// argon2_m_cost = 19456
/// argon2_t_cost = 2
/// argon2_p_cost = 1
/// argon2_pool_size = 1
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PasswordHasherConfig {
    /// 哈希算法（"argon2id" 默认 | "bcrypt"，仅影响**新哈希**；verify 按 PHC/ bcrypt
    /// 前缀自动识别，不受本字段影响）。
    pub algorithm: String,
    /// Argon2id 内存成本（KiB），下限 19456（`ARGON2_MIN_M_COST`）。
    pub argon2_m_cost: u32,
    /// Argon2id 时间成本（迭代次数），下限 1。
    pub argon2_t_cost: u32,
    /// Argon2id 并行度，下限 1。
    pub argon2_p_cost: u32,
    /// bcrypt cost（允许区间 [10, 15]）。
    pub bcrypt_cost: u32,
    /// Argon2 并发令牌池大小（默认 1，secure-by-default）：限制同时执行中的 Argon2 hash/verify 数量，进程内存驻留上界 ≈ `argon2_pool_size × argon2_m_cost` KiB，任何取消时序下不超卖、等待调用异步排队（不拒绝）；区间 `[1, 256]`（0 = 零 permit 永久饥饿，fail-fast；256 × 19 MiB ≈ 4.8 GiB 为误配上界）；bcrypt 不入池（KB 级，CPU DoS 由限流与 cost 校验承担）；env `GARRISON_PASSWORD_HASHER__ARGON2_POOL_SIZE`。
    pub argon2_pool_size: u32,
    /// 显式风险接受：允许 Argon2id `m_cost` 低于 19456 下限（内存受限部署）；置 true 时 `validate_core` 放行并输出 warn，不静默降级。
    pub allow_weak_argon2_params: bool,
}

/// JWT secret 类型别名：`protocol-zeroize` 启用时为 `Zeroizing<String>`（Drop 时 zeroize，防内存 dump 泄露），否则退化为 `String`。
/// 赋值用 `.into()`，读取用 `.as_str()` 或 `&*`（两种类型均支持）。
#[cfg(feature = "protocol-zeroize")]
pub type JwtSecret = zeroize::Zeroizing<String>;

/// JWT secret 类型别名（不启用 `protocol-zeroize` 时退化为 `String`）。
///
/// 详见上方 `protocol-zeroize` 启用版本的文档。
#[cfg(not(feature = "protocol-zeroize"))]
pub type JwtSecret = String;

/// 全局配置结构体，定义框架运行参数。
///
/// # 字段说明
///
/// | 字段 | 类型 | 默认值 | 说明 |
/// |------|------|--------|------|
/// | `token_name` | String | "garrison_token" | Token 名称（HTTP Header/Cookie 字段名） |
/// | `timeout` | i64 | 2592000（30 天） | Token 超时秒数（必须 > 0） |
/// | `active_timeout` | i64 | -1 | 活动超时检测（-1 表示不启用） |
/// | `is_read_cookie` | bool | true | 是否从 Cookie 读取 Token |
/// | `is_read_header` | bool | true | 是否从 Header 读取 Token |
/// | `is_read_body` | bool | false | 是否从请求体读取 Token |
/// | `is_write_header` | bool | true | 是否在登录后写入 Header |
/// | `token_style` | String | "uuid" | Token 风格（uuid/random_64/simple/jwt） |
/// | `throw_on_not_login` | bool | true | 未登录时是否抛出异常（false 则返回 false） |
///
/// `token_style` 必须是 `TOKEN_STYLES` 合法值、`timeout` 必须 > 0（其余分组校验见 `validate()`）；热更新经 `watch()` 订阅、`update()` 修改：
///
/// ```ignore
/// let config = GarrisonConfig::default_config();
/// let mut rx = config.watch().unwrap();
/// config.update(|c| c.timeout = 3600).unwrap();
/// let new_config = rx.borrow_and_update();
/// assert_eq!(new_config.timeout, 3600);
/// ```
/// `Debug` 为手动实现（见 `impls.rs`）：`jwt_secret` 在 `{:?}` 输出中脱敏为 `"<redacted>"`，防密钥经日志/调试打印明文泄露。
#[derive(Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GarrisonConfig {
    /// Token 名称（对应 HTTP Header / Cookie 字段名）。
    pub token_name: String,

    /// Token 超时秒数（必须 > 0）。
    pub timeout: i64,

    /// 活动超时检测（-1 = 不启用）。
    pub active_timeout: i64,

    /// 是否从 Cookie 中读取 Token。
    pub is_read_cookie: bool,

    /// 是否从 Header 中读取 Token。
    pub is_read_header: bool,

    /// 是否从请求体中读取 Token（默认 false；启用后 middleware 从请求体（如 JSON 字段）提取 Token，通常与 cookie/header 方式组合）。
    pub is_read_body: bool,

    /// 是否在登录后自动写入 Header。
    pub is_write_header: bool,

    /// 是否在续签后将新 Token 写入 Cookie（默认 false；启用后 middleware 检测到 `CURRENT_RENEWED_TOKEN` 时写入 `HttpOnly; Path=/; SameSite=Lax`）。
    pub is_write_cookie: bool,

    /// Token 风格（uuid / random_64 / simple / jwt）。
    pub token_style: String,

    /// 未登录时是否抛出异常（false 则返回 false）。
    pub throw_on_not_login: bool,

    /// Cookie 是否标记 `Secure`（仅 HTTPS 传输，dev 环境 HTTP 调试时可设为 false）。
    pub cookie_secure: bool,

    /// Cookie 的 `SameSite` 策略（"Lax" / "Strict" / "None"）。
    pub cookie_same_site: String,

    /// JWT 签名算法（"HS256" 默认 / "HS512" 可选）。
    pub jwt_algorithm: String,

    /// JWT 签名密钥（verify/refresh 委托 JwtHandler 需要 secret；默认空，使用 JWT 必须配置非空 secret）。
    ///
    /// `protocol-zeroize` 下为 `Zeroizing<String>`（Drop 自动 zeroize 防内存泄露）；`Debug` 手动实现输出 `"<redacted>"`（derive 会打印明文）。
    pub jwt_secret: JwtSecret,

    /// JWT RSA 私钥 PEM（PKCS#8/PKCS#1，`jwt_algorithm="RS256"` 时必填）；`Debug` 手动实现输出 `"<redacted>"`。
    pub jwt_rsa_private_key_pem: Option<String>,

    /// JWT EC 私钥 PEM（PKCS#8，`jwt_algorithm="ES256"` 时必填，P-256/P-384）；`Debug` 手动实现输出 `"<redacted>"`。
    pub jwt_ec_private_key_pem: Option<String>,

    /// JWT Ed25519 私钥 PEM（PKCS#8，`jwt_algorithm="EdDSA"` 时必填）；`Debug` 手动实现输出 `"<redacted>"`。
    pub jwt_ed_private_key_pem: Option<String>,

    /// 签名校验时间窗口秒数（默认 300 秒）。
    pub sign_window_seconds: i64,

    /// SSO ticket TTL 秒数（默认 60 秒）。
    pub sso_ticket_ttl_seconds: u64,

    /// JWKS 退役保留时长秒数（默认 7200 = 2× access token TTL，必须 > 0；由嵌入方经 `with_jwks_retention_secs` 装配，框架不自动桥接）。
    /// 多 kid 轮换后 Passive 签名钥保留至此超期（对 RP 仍发布于 JWKS），超期转 Disabled 并移出 JWKS；同时决定 JWKS 端点 `Cache-Control: max-age`（取一半）。
    pub jwks_retention_secs: u64,

    /// 是否启用 remember-me 扩展会话超时（默认 false；启用后 `login` params 含 `remember_me=true` 时用 `remember_me_timeout` 作 TTL）。
    pub remember_me_enabled: bool,

    /// remember-me 会话超时秒数（默认 90 天 = 7776000，必须 > `timeout`；仅 `remember_me_enabled = true` 且 login params 含 `remember_me=true` 时生效）。
    pub remember_me_timeout: i64,

    /// 登录时是否向会话播种主认证因子（amr=["pwd"] / aal:1 / auth_time，默认 `true` 保持 login 即主认证的历史契约）。
    /// 安全敏感部署建议显式关闭：凭证委托 / 零凭证 login 路径未发生密码校验，播种 `pwd` 会向 amr_ledger 与 claim 断言一次从未发生的认证，误导下游 step-up 判定；关闭后 `amr_ledger` 空、`auth_time=None`，JWT 不带 `amr`/`auth_time`（MFA 编排仍可 step-up 追加）。
    pub seed_primary_amr: bool,

    /// login_id 长度上限（字节，默认 255；`0` = 框架层不限，但 wire 层 `LoginRequest` 仍按 `DEFAULT_LOGIN_ID_MAX_LEN` 封顶）；stp 登录收口（`login` / `login_with_token` / `login_by_token`）超限返回 `InvalidParam`，封住未认证内存增长源头。
    pub login_id_max_len: u32,

    /// 会话悬停超时秒数（-1 = 不启用，>0 = 不活跃秒数后踢出；启用后 `check_login` 时检查 `last_active_time`）。
    pub session_hover_timeout: i64,

    /// 是否启用前后端分离模式（默认 false = Cookie 模式；启用后 Token 从 Authorization Header 读取，不设置 Cookie）。本批次仅提供配置项与日志提示，Web 框架行为变更留待后续版本。
    pub frontend_separation: bool,

    /// 自动续签阈值（-1 = 不启用，0-100 = 剩余 TTL 百分比低于此值时触发续签；启用后 `check_login` 时检查剩余 TTL）。
    pub auto_renewal_threshold: i64,

    /// token map 清理间隔秒数（默认 300 = 5 分钟；`<= 0` 禁用后台清理 task；由 `GarrisonManager::builder()` 读取后传给 `spawn_cleanup_task`）。
    pub token_map_cleanup_interval_secs: i64,

    /// L1 缓存（oxcache 内存层）TTL 秒数（默认 30，仅 `three-tier-cache` feature 生效；L1 命中不查 L2/L3，TTL 短保新鲜度）。
    #[cfg(feature = "three-tier-cache")]
    pub l1_cache_ttl_secs: u64,

    /// L2 缓存（DAO 持久化层）TTL 秒数（默认 300 = 5 分钟，仅 `three-tier-cache` feature 生效；L1 miss 查 L2，L2 miss 走 L3 回调）。
    #[cfg(feature = "three-tier-cache")]
    pub l2_cache_ttl_secs: u64,

    /// L1 缓存（oxcache 内存层）最大容量（默认 10000 条，仅 `three-tier-cache` feature 生效；超出按 LRU 淘汰）。
    #[cfg(feature = "three-tier-cache")]
    pub l1_cache_capacity: u64,

    /// login_token_map 持久化写入间隔秒数（默认 0 = 同步写 DAO，仅 `login-token-map-persistence` feature 生效；0 = 强一致，>0 = 后台批量写最终一致）。
    #[cfg(feature = "session-extra")]
    pub login_token_map_persist_interval_secs: u64,

    /// 匿名 Session 超时秒数（默认 1800 = 30 分钟，仅 `anonymous-session` feature 生效；匿名 Session 不关联 login_id，超时自动销毁）。
    #[cfg(feature = "session-extra")]
    pub anon_session_timeout: u64,

    /// 是否允许并发登录（对应 `isConcurrent`；默认 true = 同一账号可同时在多设备登录，false 时新登录先踢出该账号所有现有会话）。
    pub is_concurrent: bool,

    /// 是否共享 Token（对应 `isShare`；默认 false，true = 同一账号多登录复用同一 Token，要求 `is_concurrent=true` 否则 `validate()` 报错）。
    pub is_share: bool,

    /// 最大登录数量（对应 `maxLoginCount`；默认 0 = 不限制，>0 = 登录后活跃 Token 超限时按 `last_active_time` 升序踢出最早）。
    pub max_login_count: u32,

    /// 设备绑定模式（默认 "disabled"）：`strict` 新设备登录触发二次认证（`StrictBinding`），`loose` 仅告警不阻断（`LooseBinding`）；字段非 feature-gated，策略注入由 `GarrisonManager::builder()` 按值决定。
    pub device_binding_mode: String,

    /// 顶人下线策略（is_concurrent=false 时新设备登录踢出旧设备或拒绝新设备，默认 `OldDevice`）。
    pub replaced_login_exit_mode: ReplacedLoginExitMode,

    /// 溢出处理策略（max_login_count 超限时登出/踢出/顶替最旧会话，默认 `Logout`）。
    pub overflow_logout_mode: OverflowLogoutMode,

    /// 会话劫持检测模式（默认 `AlertOnly` 仅告警，仅 `session-hijack-detection` feature 生效）。
    #[cfg(feature = "session-hijack-detection")]
    pub session_hijack_mode: SessionHijackMode,

    /// 是否启用 JWT 撤销黑名单（默认 false；启用后 logout/kickout 将 `jti` 写入 DAO 黑名单，`check_login_stateless` 命中返回 `TokenRevoked`；仅 `protocol-jwt` feature 且 `token_style="jwt"` 有实际效果）。
    pub enable_jwt_revocation: bool,

    /// Refresh token 重用处置策略（默认 `TheftDetected`）：仅影响存在存活后代的重用分类（RecentPrev / OrphanedBranch），无存活血缘的 StaleLineage 恒按盗用吊销整条 chain，语义见 [`RecentReuseBehaviour`]。
    pub recent_reuse_behaviour: RecentReuseBehaviour,

    /// Refresh token 宽限窗口时长秒数（默认 0 = 关闭）：窗口内已轮换旧 token 再现时返回轮换时签发的既有新 token（不重新旋转），容忍 in-flight 并发双刷；窗口外按 `recent_reuse_behaviour` 处置。
    /// 兑现凭据由轮换服务进程内暂存不落库，多实例部署下仅签发实例可命中兑现，其余退化为既有重用处置。
    pub refresh_grace_period_secs: i64,

    /// Refresh token 宽限窗口内同一旧 token 的最大宽限兑现次数（默认 1，仅 `refresh_grace_period_secs > 0` 时生效）。
    ///
    /// 预算耗尽后的窗口内重放按 `recent_reuse_behaviour` 处置（默认吊销整条 chain）；仅并发落败方（未抢到消费权且宽限未命中）返回 `InvalidToken` 不吊销。
    pub refresh_grace_max_uses: u32,

    /// 显式风险接受：允许 `token_style=jwt` + `jwt_mode=Stateless` + `enable_jwt_revocation=false` 的不安全组合（不可吊销的永久 JWT 凭证）。默认 `false`，仅运维明确知悉风险时设为 `true`；正常部署应 `enable_jwt_revocation=true` 或 `JwtMode::Mixin`。
    pub allow_stateless_jwt_no_revocation: bool,

    /// 严格收口：Stateless JWT 在租户上下文内必须携带 `tid` 绑定 claim（默认 `false`：无 `tid` 存量 token 放行，兼容随轮替收敛）。
    /// `true` 时 `check_login_stateless` 在租户上下文存在且 claims 无 `tid` 时显性拒绝（`stp-check-login-tenant-unbound`），封住无绑定 token 不受租户约束及 jti 黑名单跨租户 miss 的吊销逃逸面；仅 `token_style="jwt"` + `JwtMode::Stateless` 有效，开启前确认存量 token 已轮替。
    pub require_tenant_bound_jwt: bool,

    /// 严格收口：会话模式在租户上下文内必须持有租户绑定（读 `SESSION_TENANT_ATTR_KEY`，默认 `false`：无绑定存量会话放行，靠 TTL 自然收敛）。
    /// `true` 时 `check_login` 对无绑定会话显性拒绝（`stp-check-login-session-tenant-unbound`）；与 `require_tenant_bound_jwt` 互补（本字段作用于 `jwt_mode = Simple`/`Mixin`，Stateless 由前者读 `tid` claim，开启其一不代表全部收紧）；无租户上下文部署不受影响，开启前确认存量无绑定会话已轮替。
    pub require_session_tenant_binding: bool,

    /// 审计日志脱敏模式（默认 `Partial`：`SensitiveDataMasker` 类型感知脱敏；`Full` 全量替换 `"***"` 完全屏蔽）。
    pub audit_mask_mode: AuditMaskMode,

    /// 多租户隔离配置段（默认不启用；启用需 `tenant-isolation` feature + `tenant_resolution_middleware`）。
    pub tenant_isolation: TenantIsolationConfig,

    /// 密码哈希配置段（默认 Argon2id OWASP 建议档；经 `config.password_hasher.build_hasher()` 构造 hasher 后注入 `with_password_hasher`，verify 按哈希前缀自动识别算法）。
    pub password_hasher: PasswordHasherConfig,

    /// MFA/step-up 编排配置段（per-client chain 三态 + 全局默认链）。
    pub mfa: MfaConfig,

    /// CORS 跨域资源共享配置段（默认 `allowed_origins` 为空；启用需 `web-cors` feature + `garrison_cors_middleware`）。
    #[cfg(feature = "web-cors")]
    pub cors_config: CorsConfig,

    /// CSRF 跨站请求伪造防护配置段（默认 `enabled: true` secure-by-default；启用需 `web-csrf` feature + `garrison_csrf_middleware`）。
    #[cfg(feature = "web-csrf")]
    pub csrf_config: CsrfConfig,

    /// 限流后端配置段（默认 `Memory`，启用 `rate-limit-redis` feature 后可选 `Redis`）。
    #[cfg(feature = "rate-limit-redis")]
    pub rate_limit_backend: RateLimitBackend,

    /// WAF 启用的 Hook 名称列表（firewall-waf feature；空 = WAF 链空全部放行）。
    /// 合法值：white_path / black_path / danger_char / banned_char / dir_traversal / host / http_method / header / parameter。
    #[cfg(feature = "firewall-waf")]
    pub waf_enabled_hooks: Vec<String>,

    /// WAF 白名单路径前缀列表（firewall-waf feature；匹配的路径不被 WAF 拦截，但仍继续执行后续 Hook）。
    #[cfg(feature = "firewall-waf")]
    pub waf_white_paths: Vec<String>,

    /// WAF 黑名单路径前缀列表（firewall-waf feature；匹配的路径被 WAF 拦截返回 403）。
    #[cfg(feature = "firewall-waf")]
    pub waf_black_paths: Vec<String>,

    /// WAF 允许的 Host 列表（firewall-waf feature；空 = 不校验，非空时请求 Host 头必须在列表中）。
    #[cfg(feature = "firewall-waf")]
    pub waf_allowed_hosts: Vec<String>,

    /// WAF 允许的 HTTP 方法列表（firewall-waf feature；空 = 不校验，非空时方法必须为大写且在列表中）。
    #[cfg(feature = "firewall-waf")]
    pub waf_allowed_methods: Vec<String>,

    /// WAF 禁止的 Header 名称列表（firewall-waf feature；请求头含列表中 header 时被拦截）。
    #[cfg(feature = "firewall-waf")]
    pub waf_banned_headers: Vec<String>,

    /// WAF 禁止的参数名称列表（firewall-waf feature；请求参数含列表中参数时被拦截）。
    #[cfg(feature = "firewall-waf")]
    pub waf_banned_params: Vec<String>,

    /// SMS 小时限速阈值（默认 5 次/小时）。
    #[cfg(feature = "sms-rate-limit")]
    pub sms_hourly_limit: u32,

    /// SMS 天限速阈值（默认 10 次/天）。
    #[cfg(feature = "sms-rate-limit")]
    pub sms_daily_limit: u32,

    /// SMS 验证码最大验证尝试次数（默认 3）。
    #[cfg(feature = "sms-rate-limit")]
    pub sms_verify_max_attempts: u32,

    /// SMS 异常发送检测阈值（连续未验证次数，默认 3）。
    #[cfg(feature = "sms-rate-limit")]
    pub sms_unverified_threshold: u32,

    /// 邮箱验证码小时限速阈值（默认 5 次/小时）。
    #[cfg(feature = "email-verification")]
    pub email_hourly_limit: u32,

    /// 邮箱验证码天限速阈值（默认 10 次/天）。
    #[cfg(feature = "email-verification")]
    pub email_daily_limit: u32,

    /// 邮箱验证码最大验证尝试次数（默认 3）。
    #[cfg(feature = "email-verification")]
    pub email_verify_max_attempts: u32,

    /// 邮箱验证码异常发送检测阈值（连续未验证次数，默认 3）。
    #[cfg(feature = "email-verification")]
    pub email_unverified_threshold: u32,

    /// 邮箱验证码有效期（秒，默认 600 = 10 分钟）。
    #[cfg(feature = "email-verification")]
    pub email_code_ttl: u64,

    /// 异常登录分析器扫描间隔秒数（默认 3600，仅 `anomalous-detector-dual` feature 生效）。
    #[cfg(feature = "anomalous-detector-dual")]
    pub anomalous_analyzer_interval_secs: u64,

    /// 异常登录 burst 检测阈值（默认 5，1 小时窗口内登录次数 > 此值则告警；仅 `anomalous-detector-dual` feature 生效）。
    #[cfg(feature = "anomalous-detector-dual")]
    pub anomalous_analyzer_burst_threshold: u32,

    /// Credit 计量配置段（`None` = 不启用 credit 计量，仅 `credit-metering` feature 生效）。
    ///
    /// 配置示例：
    /// ```toml
    /// [credit]
    /// credit_limit = 10000
    /// persist_history = true
    /// ```
    #[cfg(feature = "credit-metering")]
    pub credit: Option<CreditConfig>,

    /// 配置变更广播通道（serde 跳过，反序列化后通过 `with_watcher` 重建）。
    #[serde(skip)]
    watcher: Option<watch::Sender<GarrisonConfig>>,
}

mod helpers;
pub(crate) use helpers::default_jwt_secret;

#[cfg(test)]
mod tests;
