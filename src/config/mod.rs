//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 配置模块，提供 GarrisonConfig 全局配置。
//!
//! 对应 `SaTokenConfig`，
//! 定义 Token 名称、超时、持久化等配置项。
//!
//! ## 配置源
//!
//! 由 [confers](https://docs.rs/confers) 库接管，优先级：环境变量 > toml 文件 > 代码默认值。
//!
//! 1. **代码默认值**：通过 `ConfigBuilder::default()` 设置
//! 2. **toml 文件**：通过 `GarrisonConfig::load(Some(path))` 加载
//! 3. **环境变量**：`GARRISON_` 前缀自动覆盖
//!
//! ## 热更新
//!
//! 通过 `tokio::sync::watch` 通道广播配置变更：
//! - `GarrisonConfig::watch()` 返回 `watch::Receiver<GarrisonConfig>`
//! - `GarrisonConfig::update(f)` 闭包式修改配置并广播

#[cfg(feature = "rate-limit-redis")]
use crate::strategy::rate_limiter_backend::RateLimitBackend;
#[cfg(feature = "web-cors")]
use crate::web::cors::CorsConfig;
#[cfg(feature = "web-csrf")]
use crate::web::csrf::CsrfConfig;
#[cfg(feature = "web-waf")]
use crate::web::waf::WafConfig;
use confers::types::ConfigValue;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::watch;

pub mod impls;
/// Token 风格枚举（对应 token 风格）。
///
/// 配置校验——token_style 必须是以下 4 个合法值之一。
pub const TOKEN_STYLES: &[&str] = &["uuid", "random_64", "simple", "jwt"];

/// Cookie SameSite 合法值。
pub const COOKIE_SAME_SITE_VALUES: &[&str] = &["Lax", "Strict", "None"];

/// 默认 Token 名称（对应 HTTP Header / Cookie 字段名）。
pub const DEFAULT_TOKEN_NAME: &str = "garrison_token";

/// 默认 Token 超时秒数（30 天）。
pub const DEFAULT_TIMEOUT: i64 = 2_592_000;

/// 默认活动超时检测值（-1 表示不启用，保留 既有语义）。
pub const DEFAULT_ACTIVE_TIMEOUT: i64 = -1;

/// 默认 Cookie Secure 标志（生产环境应为 true，dev 环境可设为 false 以支持 HTTP 调试）。
pub const DEFAULT_COOKIE_SECURE: bool = true;

/// 默认 Cookie SameSite 策略（"Lax" 平衡安全与可用性）。
pub const DEFAULT_COOKIE_SAME_SITE: &str = "Lax";

/// 默认 JWT 签名算法（HS256，兼容 HS512 可选）。
pub const DEFAULT_JWT_ALGORITHM: &str = "HS256";

/// 默认签名校验时间窗口秒数（5 分钟）。
pub const DEFAULT_SIGN_WINDOW_SECONDS: i64 = 300;

/// 默认 SSO ticket TTL 秒数（60 秒）。
pub const DEFAULT_SSO_TICKET_TTL_SECONDS: u64 = 60;

/// 默认 remember-me 超时秒数（90 天，必须 > DEFAULT_TIMEOUT 30 天）。
pub const REMEMBER_ME_DEFAULT_TIMEOUT: i64 = 7_776_000;

/// 默认会话悬停超时秒数（-1 = 不启用，保留 既有语义）。
pub const DEFAULT_SESSION_HOVER_TIMEOUT: i64 = -1;

/// 默认前后端分离模式（false = Cookie 模式，true = Token Header 模式）。
pub const DEFAULT_FRONTEND_SEPARATION: bool = false;

/// 默认是否从请求体读取 Token（false = 不读取，向后兼容）。
pub const DEFAULT_IS_READ_BODY: bool = false;

/// 默认自动续签阈值（-1 = 不启用，0-100 = 剩余 TTL 百分比低于此值时触发续签）。
pub const DEFAULT_AUTO_RENEWAL_THRESHOLD: i64 = -1;

/// 默认 token map 清理间隔秒数（5 分钟）。
///
/// `<= 0` 表示禁用后台清理 task（与 T028 `spawn_cleanup_task` 的 `interval_secs <= 0` 行为一致）。
pub const DEFAULT_TOKEN_MAP_CLEANUP_INTERVAL: i64 = 300;

/// 默认 login_token_map 持久化写入间隔秒数（0 = 同步写入）。
///
/// 仅当 `login-token-map-persistence` feature 启用时生效。
/// - `0`：每次变更同步写入 DAO（强一致，性能较低）
/// - `>0`：后台 task 按此间隔批量写入 DAO（最终一致，性能更高）
pub const DEFAULT_LOGIN_TOKEN_MAP_PERSIST_INTERVAL_SECS: u64 = 0;

/// 默认 L1 缓存 TTL 秒数（30 秒）。
///
/// 仅当 `three-tier-cache` feature 启用时生效。
/// L1 为 oxcache 内存层，TTL 较短以保证数据新鲜度。
pub const DEFAULT_L1_CACHE_TTL_SECS: u64 = 30;

/// 默认 L2 缓存 TTL 秒数（300 秒 = 5 分钟）。
///
/// 仅当 `three-tier-cache` feature 启用时生效。
/// L2 为 DAO 持久化缓存，TTL 较长以减少 L3（interface 回调）压力。
pub const DEFAULT_L2_CACHE_TTL_SECS: u64 = 300;

/// 默认 L1 缓存容量（10000 条）。
///
/// 仅当 `three-tier-cache` feature 启用时生效。
/// oxcache L1 缓存的最大条目数，超出后按 LRU 淘汰。
pub const DEFAULT_L1_CACHE_CAPACITY: u64 = 10_000;

/// 默认匿名 Session 超时秒数（1800 = 30 分钟）。
///
/// 仅当 `anonymous-session` feature 启用时生效。
pub const DEFAULT_ANON_SESSION_TIMEOUT_SECS: u64 = 1800;

/// 默认是否允许并发登录（true = 同一账号可同时在多设备登录）。
pub const DEFAULT_IS_CONCURRENT: bool = true;

/// 默认是否共享 Token（true = 同一账号多登录复用同一 Token，要求 is_concurrent=true）。
pub const DEFAULT_IS_SHARE: bool = false;

/// 默认最大登录数量（0 = 不限制，>0 = 超出时踢出最早登录的会话）。
pub const DEFAULT_MAX_LOGIN_COUNT: u32 = 0;

/// 默认设备绑定模式（"disabled" = 不启用设备绑定）。
pub const DEFAULT_DEVICE_BINDING_MODE: &str = "disabled";

/// 设备绑定模式合法值（"strict" / "loose" / "disabled"）。
pub const DEVICE_BINDING_MODES: &[&str] = &["strict", "loose", "disabled"];

/// 默认顶人下线策略的 serde 表示（"old_device" = 踢出旧设备）。
pub const DEFAULT_REPLACED_LOGIN_EXIT_MODE: &str = "old_device";

/// 默认溢出处理策略的 serde 表示（"logout" = 登出最旧会话）。
pub const DEFAULT_OVERFLOW_LOGOUT_MODE: &str = "logout";

/// 默认异常登录分析器扫描间隔秒数（3600 = 1 小时）。
///
/// 仅当 `anomalous-detector-dual` feature 启用时生效。
pub const DEFAULT_ANOMALOUS_ANALYZER_INTERVAL_SECS: u64 = 3600;

/// 默认异常登录 burst 检测阈值（5 次/小时）。
///
/// 仅当 `anomalous-detector-dual` feature 启用时生效。
pub const DEFAULT_ANOMALOUS_BURST_THRESHOLD: u32 = 5;

/// 环境变量前缀（GARRISON_）。
pub const ENV_PREFIX: &str = "GARRISON_";

// ============================================================================
// 并发登录控制枚举
// ============================================================================

/// 顶人下线策略（is_concurrent=false 时生效）。
///
/// 控制 `is_concurrent=false` 场景下新设备登录时的行为：
/// - `OldDevice`：踢出旧设备，允许新设备登录（默认，对应 既有语义）
/// - `NewDevice`：拒绝新设备登录，保留旧设备
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReplacedLoginExitMode {
    /// 踢出旧设备，允许新设备登录（默认）。
    #[default]
    OldDevice,
    /// 拒绝新设备登录，保留旧设备。
    NewDevice,
}

/// 溢出处理策略（max_login_count 超限时生效）。
///
/// 控制 `max_login_count > 0` 场景下登录数量超限时的处理方式：
/// - `Logout`：登出最旧会话（默认，触发 Logout 事件）
/// - `Kickout`：踢出最旧会话（触发 Kickout 事件）
/// - `Replaced`：顶替最旧会话（触发 Replaced 事件）
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

// ============================================================================
// 多租户隔离配置
// ============================================================================

/// 租户解析器类型。
///
/// 配置文件中使用小写形式（`"header"` / `"subdomain"` / `"claim"`）。
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

/// 审计脱敏模式（T012）。
///
/// 控制 `AuditLogListener::mask_metadata` 的脱敏策略：
/// - `Full`：所有 `mask_fields` 中的字段值替换为固定 `"***"`（完全屏蔽）
/// - `Partial`：使用 `SensitiveDataMasker` 进行类型感知脱敏（如手机号 → `138****1234`），
///   无匹配规则的字段回退为 `"***"`
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditMaskMode {
    /// 所有敏感字段值替换为固定 `"***"`（完全屏蔽）。
    Full,
    /// 使用 `SensitiveDataMasker` 类型感知脱敏（保留部分可见信息）。
    #[default]
    Partial,
}

/// 多租户隔离配置段。
///
/// # 默认值
///
/// - `enabled`: `false`（不启用，向后兼容）
/// - `resolver`: `Header`（最常用，从 `X-Tenant-Id` header 解析）
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

/// JWT secret 类型别名（FMEA #8 修复，kueiku RPN=336）。
///
/// - `protocol-zeroize` feature 启用：`Zeroizing<String>`，Drop 时自动 zeroize buffer，
///   防止进程内存 dump / swap-to-disk 泄露 jwt_secret。
/// - 不启用：退化为 `String`，与历史行为一致（向后兼容）。
///
/// 调用方适配规则：
/// - 赋值：`config.jwt_secret = "xxx".to_string().into()`（`String: From<String>` identity，
///   `Zeroizing<String>: From<String>`）
/// - 读取：`config.jwt_secret.as_str()` 或 `&*config.jwt_secret`（两种类型都支持）
#[cfg(feature = "protocol-zeroize")]
pub type JwtSecret = zeroize::Zeroizing<String>;

/// JWT secret 类型别名（不启用 `protocol-zeroize` 时退化为 `String`）。
///
/// 详见上方 `protocol-zeroize` 启用版本的完整文档。
#[cfg(not(feature = "protocol-zeroize"))]
pub type JwtSecret = String;

/// 全局配置结构体，定义框架运行参数。
///
/// 对应 `SaTokenConfig`。
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
/// # 配置校验
///
/// - `token_style` 必须是 `TOKEN_STYLES` 中的合法值
/// - `timeout` 必须 > 0
///
/// # 热更新
///
/// 通过 `watch()` 订阅变更，通过 `update()` 修改配置：
///
/// ```ignore
/// let config = GarrisonConfig::default_config();
/// let mut rx = config.watch().unwrap();
/// config.update(|c| c.timeout = 3600).unwrap();
/// let new_config = rx.borrow_and_update();
/// assert_eq!(new_config.timeout, 3600);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GarrisonConfig {
    /// Token 名称（对应 HTTP Header / Cookie 字段名）。
    pub token_name: String,

    /// Token 超时秒数（必须 > 0）。
    pub timeout: i64,

    /// 活动超时检测（-1 表示不启用，保留 既有语义）。
    pub active_timeout: i64,

    /// 是否从 Cookie 中读取 Token。
    pub is_read_cookie: bool,

    /// 是否从 Header 中读取 Token。
    pub is_read_header: bool,

    /// 是否从请求体中读取 Token（默认 false，向后兼容）。
    ///
    /// 启用后，middleware 会从请求体（如 JSON 字段）中提取 Token。
    /// 通常与 `is_read_cookie` / `is_read_header` 组合使用。
    pub is_read_body: bool,

    /// 是否在登录后自动写入 Header。
    pub is_write_header: bool,

    /// 是否在续签后将新 Token 写入 Cookie（默认 false）。
    ///
    /// 启用后，middleware 检测到 `CURRENT_RENEWED_TOKEN` 时，
    /// 将续签 Token 作为 Set-Cookie 写入响应（`HttpOnly; Path=/; SameSite=Lax`）。
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

    /// JWT 签名密钥（verify_token/refresh_token 委托 JwtHandler 需要 secret）。
    /// 默认空字符串，业务方使用 JWT 时必须配置非空 secret。
    ///
    /// `protocol-zeroize` feature 下类型为 `Zeroizing<String>`，
    /// Drop 时自动 zeroize buffer，防止内存泄露。
    pub jwt_secret: JwtSecret,

    /// 签名校验时间窗口秒数（默认 300 秒）。
    pub sign_window_seconds: i64,

    /// SSO ticket TTL 秒数（默认 60 秒）。
    pub sso_ticket_ttl_seconds: u64,

    /// 是否启用 remember-me 扩展会话超时（默认 false）。
    ///
    /// 启用后，`login` 时 params 含 `remember_me=true` 将使用 `remember_me_timeout` 作为 TTL。
    pub remember_me_enabled: bool,

    /// remember-me 会话超时秒数（默认 90 天 = 7776000，必须 > `timeout`）。
    ///
    /// 仅当 `remember_me_enabled = true` 且 `login` params 含 `remember_me=true` 时生效。
    pub remember_me_timeout: i64,

    /// 会话悬停超时秒数（-1 = 不启用，>0 = 不活跃秒数后踢出）。
    ///
    /// 启用后，`check_login` 时检查 `last_active_time`，
    /// 若 `now - last_active_time > session_hover_timeout` 则踢出会话。
    pub session_hover_timeout: i64,

    /// 是否启用前后端分离模式（默认 false = Cookie 模式）。
    ///
    /// 启用后 Token 从 Authorization Header 读取，不设置 Cookie。
    /// 本批次仅提供配置项与日志提示，Web 框架行为变更留待后续版本。
    pub frontend_separation: bool,

    /// 自动续签阈值（-1 = 不启用，0-100 = 剩余 TTL 百分比低于此值时触发续签）。
    ///
    /// 启用后，`check_login` 时检查 Token 剩余 TTL，
    /// 若 `remaining_pct < auto_renewal_threshold` 则自动续签。
    pub auto_renewal_threshold: i64,

    /// token map 清理间隔秒数（默认 300 = 5 分钟）。
    ///
    /// `<= 0` 表示禁用后台清理 task（与 T028 `spawn_cleanup_task` 的 `interval_secs <= 0` 行为一致）。
    /// 由 `GarrisonManager::init` 读取后传给 `spawn_cleanup_task`。
    pub token_map_cleanup_interval_secs: i64,

    /// L1 缓存（oxcache 内存层）TTL 秒数（默认 30）。
    ///
    /// 仅当 `three-tier-cache` feature 启用时生效。
    /// L1 命中时不查询 L2/L3，TTL 较短以保证数据新鲜度。
    #[cfg(feature = "three-tier-cache")]
    pub l1_cache_ttl_secs: u64,

    /// L2 缓存（DAO 持久化层）TTL 秒数（默认 300 = 5 分钟）。
    ///
    /// 仅当 `three-tier-cache` feature 启用时生效。
    /// L1 未命中时查询 L2，L2 命中时回填 L1；L2 未命中时走 L3（interface 回调）。
    #[cfg(feature = "three-tier-cache")]
    pub l2_cache_ttl_secs: u64,

    /// L1 缓存（oxcache 内存层）最大容量（默认 10000 条）。
    ///
    /// 仅当 `three-tier-cache` feature 启用时生效。
    /// 超出容量后按 LRU 淘汰最久未访问的条目。
    #[cfg(feature = "three-tier-cache")]
    pub l1_cache_capacity: u64,

    /// login_token_map 持久化写入间隔秒数（默认 0 = 同步写入）。
    ///
    /// 仅当 `login-token-map-persistence` feature 启用时生效。
    /// - `0`：每次变更同步写入 DAO（强一致，性能较低）
    /// - `>0`：后台 task 按此间隔批量写入 DAO（最终一致，性能更高）
    #[cfg(feature = "login-token-map-persistence")]
    pub login_token_map_persist_interval_secs: u64,

    /// 匿名 Session 超时秒数（默认 1800 = 30 分钟）。
    ///
    /// 仅当 `anonymous-session` feature 启用时生效。
    /// 匿名 Session 不关联 login_id，超时后自动销毁。
    #[cfg(feature = "anonymous-session")]
    pub anon_session_timeout: u64,

    /// 是否允许并发登录（true = 同一账号可同时在多设备登录）。
    ///
    /// 对应 `isConcurrent` 配置。默认 true。
    /// 设为 false 时，新登录会先踢出该账号的所有现有会话。
    pub is_concurrent: bool,

    /// 是否共享 Token（true = 同一账号多登录复用同一 Token）。
    ///
    /// 对应 `isShare` 配置。默认 false。
    /// 设为 true 时，同一账号再次登录返回已有 Token，不创建新会话。
    /// 要求 `is_concurrent=true`，否则 `validate()` 报错。
    pub is_share: bool,

    /// 最大登录数量（0 = 不限制，>0 = 超出时踢出最早登录的会话）。
    ///
    /// 对应 `maxLoginCount` 配置。默认 0。
    /// 登录后若该账号的活跃 Token 数超过此值，按 `last_active_time` 升序踢出最早的。
    pub max_login_count: u32,

    /// 设备绑定模式（"strict" / "loose" / "disabled"），默认 "disabled"。
    ///
    /// - `strict`：新设备登录触发二次认证（由 `DeviceBindingPolicy::StrictBinding` 处理）
    /// - `loose`：新设备登录仅告警不阻断（由 `LooseBinding` 处理）
    /// - `disabled`：不启用设备绑定（默认，向后兼容）
    ///
    /// 配置字段始终存在（非 feature-gated），策略注入由 `GarrisonManager::init` 根据
    /// 此字段值决定（属于 T020 集成范畴）。
    pub device_binding_mode: String,

    /// 顶人下线策略（is_concurrent=false 时生效）。默认 `OldDevice`。
    ///
    /// `is_concurrent=false` 时新设备登录的行为：
    /// - `OldDevice`：踢出旧设备，允许新设备登录（默认）
    /// - `NewDevice`：拒绝新设备登录，保留旧设备
    pub replaced_login_exit_mode: ReplacedLoginExitMode,

    /// 溢出处理策略（max_login_count 超限时生效）。默认 `Logout`。
    ///
    /// `max_login_count > 0` 且登录数量超限时的处理方式：
    /// - `Logout`：登出最旧会话（默认，触发 Logout 事件）
    /// - `Kickout`：踢出最旧会话（触发 Kickout 事件）
    /// - `Replaced`：顶替最旧会话（触发 Replaced 事件）
    pub overflow_logout_mode: OverflowLogoutMode,

    /// 审计日志脱敏模式（T012）。默认 `Partial`。
    ///
    /// - `Full`：所有 `mask_fields` 字段值替换为 `"***"`（完全屏蔽）
    /// - `Partial`：使用 `SensitiveDataMasker` 类型感知脱敏（如手机号 → `138****1234`）
    pub audit_mask_mode: AuditMaskMode,

    /// 多租户隔离配置段。
    ///
    /// 默认 `enabled: false`（向后兼容）。启用后需配合 `tenant-isolation` Cargo feature
    /// + `tenant_resolution_middleware` 才能生效。
    pub tenant_isolation: TenantIsolationConfig,

    /// WAF 请求内容校验配置段。
    ///
    /// 默认 `enabled: false`（向后兼容）。启用后需配合 `web-waf` Cargo feature
    /// + `garrison_waf_middleware` 才能生效。
    #[cfg(feature = "web-waf")]
    pub waf_config: WafConfig,

    /// CORS 跨域资源共享配置段。
    ///
    /// 默认 `allowed_origins` 为空（向后兼容，不注入 CORS 头）。
    /// 启用后需配合 `web-cors` Cargo feature + `garrison_cors_middleware` 才能生效。
    #[cfg(feature = "web-cors")]
    pub cors_config: CorsConfig,

    /// CSRF 跨站请求伪造防护配置段。
    ///
    /// 默认 `enabled: true`（secure-by-default）。启用后需配合 `web-csrf` Cargo feature
    /// + `garrison_csrf_middleware` 才能生效。
    #[cfg(feature = "web-csrf")]
    pub csrf_config: CsrfConfig,

    /// 限流后端配置段。
    ///
    /// 默认 `Memory`（向后兼容）。启用 `rate-limit-redis` Cargo feature 后可选 `Redis`。
    #[cfg(feature = "rate-limit-redis")]
    pub rate_limit_backend: RateLimitBackend,

    /// WAF 启用的 Hook 名称列表（firewall-waf feature）。
    ///
    /// 空列表表示不启用任何 Hook（WAF 链为空，全部放行）。
    /// 合法值：white_path / black_path / danger_char / banned_char / dir_traversal /
    /// host / http_method / header / parameter。
    #[cfg(feature = "firewall-waf")]
    pub waf_enabled_hooks: Vec<String>,

    /// WAF 白名单路径前缀列表（firewall-waf feature）。
    ///
    /// 匹配白名单的路径不被 WAF 拦截（但仍继续执行后续 Hook）。
    #[cfg(feature = "firewall-waf")]
    pub waf_white_paths: Vec<String>,

    /// WAF 黑名单路径前缀列表（firewall-waf feature）。
    ///
    /// 匹配黑名单的路径被 WAF 拦截（返回 403）。
    #[cfg(feature = "firewall-waf")]
    pub waf_black_paths: Vec<String>,

    /// WAF 允许的 Host 列表（firewall-waf feature）。
    ///
    /// 空列表表示不校验 Host。非空时请求的 Host 头必须在列表中。
    #[cfg(feature = "firewall-waf")]
    pub waf_allowed_hosts: Vec<String>,

    /// WAF 允许的 HTTP 方法列表（firewall-waf feature）。
    ///
    /// 空列表表示不校验方法。非空时方法必须为大写且在列表中。
    #[cfg(feature = "firewall-waf")]
    pub waf_allowed_methods: Vec<String>,

    /// WAF 禁止的 Header 名称列表（firewall-waf feature）。
    ///
    /// 请求头中含此列表中的 header 时被拦截。
    #[cfg(feature = "firewall-waf")]
    pub waf_banned_headers: Vec<String>,

    /// WAF 禁止的参数名称列表（firewall-waf feature）。
    ///
    /// 请求参数中含此列表中的参数时被拦截。
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

    /// 异常登录分析器扫描间隔秒数（默认 3600 = 1 小时）。
    ///
    /// 仅当 `anomalous-detector-dual` feature 启用时生效。
    #[cfg(feature = "anomalous-detector-dual")]
    pub anomalous_analyzer_interval_secs: u64,

    /// 异常登录 burst 检测阈值（默认 5，1 小时窗口内登录次数 > 此值则告警）。
    ///
    /// 仅当 `anomalous-detector-dual` feature 启用时生效。
    #[cfg(feature = "anomalous-detector-dual")]
    pub anomalous_analyzer_burst_threshold: u32,

    /// 配置变更广播通道（serde 跳过，反序列化后通过 `with_watcher` 重建）。
    #[serde(skip)]
    watcher: Option<watch::Sender<GarrisonConfig>>,
}

mod helpers;
pub(crate) use helpers::{collect_env_vars, default_jwt_secret};

#[cfg(test)]
mod tests;
