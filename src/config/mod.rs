//! Copyright (c) 2024-2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 配置模块，提供 BulwarkConfig 全局配置。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `SaTokenConfig`，
//! 定义 Token 名称、超时、持久化等配置项。
//!
//! ## 配置源
//!
//! 由 [confers](https://docs.rs/confers) 库接管，优先级：环境变量 > toml 文件 > 代码默认值。
//!
//! 1. **代码默认值**：通过 `ConfigBuilder::default()` 设置
//! 2. **toml 文件**：通过 `BulwarkConfig::load(Some(path))` 加载
//! 3. **环境变量**：`BULWARK_` 前缀自动覆盖
//!
//! ## 热更新
//!
//! 通过 `tokio::sync::watch` 通道广播配置变更：
//! - `BulwarkConfig::watch()` 返回 `watch::Receiver<BulwarkConfig>`
//! - `BulwarkConfig::update(f)` 闭包式修改配置并广播

use crate::error::{BulwarkError, BulwarkResult};
#[cfg(feature = "rate-limit-redis")]
use crate::strategy::rate_limiter_backend::RateLimitBackend;
#[cfg(feature = "web-cors")]
use crate::web::cors::CorsConfig;
#[cfg(feature = "web-csrf")]
use crate::web::csrf::CsrfConfig;
#[cfg(feature = "web-waf")]
use crate::web::waf::WafConfig;
use confers::config::{ConfigBuilder, FileSource};
use confers::types::ConfigValue;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::watch;

/// Token 风格枚举（对应 Sa-Token 的 token 风格）。
///
/// 配置校验——token_style 必须是以下 4 个合法值之一。
pub const TOKEN_STYLES: &[&str] = &["uuid", "random_64", "simple", "jwt"];

/// Cookie SameSite 合法值。
pub const COOKIE_SAME_SITE_VALUES: &[&str] = &["Lax", "Strict", "None"];

/// 默认 Token 名称（对应 HTTP Header / Cookie 字段名）。
pub const DEFAULT_TOKEN_NAME: &str = "bulwark_token";

/// 默认 Token 超时秒数（30 天）。
pub const DEFAULT_TIMEOUT: i64 = 2_592_000;

/// 默认活动超时检测值（-1 表示不启用，保留 Sa-Token 语义）。
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

/// 默认会话悬停超时秒数（-1 = 不启用，保留 Sa-Token 语义）。
pub const DEFAULT_SESSION_HOVER_TIMEOUT: i64 = -1;

/// 默认前后端分离模式（false = Cookie 模式，true = Token Header 模式）。
pub const DEFAULT_FRONTEND_SEPARATION: bool = false;

/// 默认自动续签阈值（-1 = 不启用，0-100 = 剩余 TTL 百分比低于此值时触发续签）。
pub const DEFAULT_AUTO_RENEWAL_THRESHOLD: i64 = -1;

/// 默认是否允许并发登录（true = 同一账号可同时在多设备登录）。
pub const DEFAULT_IS_CONCURRENT: bool = true;

/// 默认是否共享 Token（true = 同一账号多登录复用同一 Token，要求 is_concurrent=true）。
pub const DEFAULT_IS_SHARE: bool = false;

/// 默认最大登录数量（0 = 不限制，>0 = 超出时踢出最早登录的会话）。
pub const DEFAULT_MAX_LOGIN_COUNT: u32 = 0;

/// 环境变量前缀（BULWARK_）。
pub const ENV_PREFIX: &str = "BULWARK_";

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

impl Default for TenantIsolationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            resolver: TenantResolverKind::Header,
        }
    }
}

/// 全局配置结构体，定义框架运行参数。
///
/// [借鉴 Sa-Token] 对应 `SaTokenConfig`。
///
/// # 字段说明
///
/// | 字段 | 类型 | 默认值 | 说明 |
/// |------|------|--------|------|
/// | `token_name` | String | "bulwark_token" | Token 名称（HTTP Header/Cookie 字段名） |
/// | `timeout` | i64 | 2592000（30 天） | Token 超时秒数（必须 > 0） |
/// | `active_timeout` | i64 | -1 | 活动超时检测（-1 表示不启用） |
/// | `is_read_cookie` | bool | true | 是否从 Cookie 读取 Token |
/// | `is_read_header` | bool | true | 是否从 Header 读取 Token |
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
/// let config = BulwarkConfig::default_config();
/// let mut rx = config.watch().unwrap();
/// config.update(|c| c.timeout = 3600).unwrap();
/// let new_config = rx.borrow_and_update();
/// assert_eq!(new_config.timeout, 3600);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BulwarkConfig {
    /// Token 名称（对应 HTTP Header / Cookie 字段名）。
    pub token_name: String,

    /// Token 超时秒数（必须 > 0）。
    pub timeout: i64,

    /// 活动超时检测（-1 表示不启用，保留 Sa-Token 语义）。
    pub active_timeout: i64,

    /// 是否从 Cookie 中读取 Token。
    pub is_read_cookie: bool,

    /// 是否从 Header 中读取 Token。
    pub is_read_header: bool,

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
    pub jwt_secret: String,

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

    /// 是否允许并发登录（true = 同一账号可同时在多设备登录）。
    ///
    /// [借鉴 Sa-Token] 对应 `isConcurrent` 配置。默认 true。
    /// 设为 false 时，新登录会先踢出该账号的所有现有会话。
    pub is_concurrent: bool,

    /// 是否共享 Token（true = 同一账号多登录复用同一 Token）。
    ///
    /// [借鉴 Sa-Token] 对应 `isShare` 配置。默认 false。
    /// 设为 true 时，同一账号再次登录返回已有 Token，不创建新会话。
    /// 要求 `is_concurrent=true`，否则 `validate()` 报错。
    pub is_share: bool,

    /// 最大登录数量（0 = 不限制，>0 = 超出时踢出最早登录的会话）。
    ///
    /// [借鉴 Sa-Token] 对应 `maxLoginCount` 配置。默认 0。
    /// 登录后若该账号的活跃 Token 数超过此值，按 `last_active_time` 升序踢出最早的。
    pub max_login_count: u32,

    /// 多租户隔离配置段。
    ///
    /// 默认 `enabled: false`（向后兼容）。启用后需配合 `tenant-isolation` Cargo feature
    /// + `tenant_resolution_middleware` 才能生效。
    pub tenant_isolation: TenantIsolationConfig,

    /// WAF 请求内容校验配置段。
    ///
    /// 默认 `enabled: false`（向后兼容）。启用后需配合 `web-waf` Cargo feature
    /// + `bulwark_waf_middleware` 才能生效。
    #[cfg(feature = "web-waf")]
    pub waf_config: WafConfig,

    /// CORS 跨域资源共享配置段。
    ///
    /// 默认 `allowed_origins` 为空（向后兼容，不注入 CORS 头）。
    /// 启用后需配合 `web-cors` Cargo feature + `bulwark_cors_middleware` 才能生效。
    #[cfg(feature = "web-cors")]
    pub cors_config: CorsConfig,

    /// CSRF 跨站请求伪造防护配置段。
    ///
    /// 默认 `enabled: false`（向后兼容）。启用后需配合 `web-csrf` Cargo feature
    /// + `bulwark_csrf_middleware` 才能生效。
    #[cfg(feature = "web-csrf")]
    pub csrf_config: CsrfConfig,

    /// 限流后端配置段。
    ///
    /// 默认 `Memory`（向后兼容）。启用 `rate-limit-redis` Cargo feature 后可选 `Redis`。
    #[cfg(feature = "rate-limit-redis")]
    pub rate_limit_backend: RateLimitBackend,

    /// 配置变更广播通道（serde 跳过，反序列化后通过 `with_watcher` 重建）。
    #[serde(skip)]
    watcher: Option<watch::Sender<BulwarkConfig>>,
}

impl BulwarkConfig {
    /// 创建符合 spec 的默认配置实例。
    ///
    /// Scenario: 代码默认值生效：
    /// - token_style = "uuid"
    /// - timeout = 2592000（30 天）
    /// - throw_on_not_login = true
    pub fn default_config() -> Self {
        let config = Self {
            token_name: DEFAULT_TOKEN_NAME.to_string(),
            timeout: DEFAULT_TIMEOUT,
            active_timeout: DEFAULT_ACTIVE_TIMEOUT,
            is_read_cookie: true,
            is_read_header: true,
            is_write_header: true,
            is_write_cookie: false,
            token_style: "uuid".to_string(),
            throw_on_not_login: true,
            cookie_secure: DEFAULT_COOKIE_SECURE,
            cookie_same_site: DEFAULT_COOKIE_SAME_SITE.to_string(),
            jwt_algorithm: DEFAULT_JWT_ALGORITHM.to_string(),
            jwt_secret: String::new(),
            sign_window_seconds: DEFAULT_SIGN_WINDOW_SECONDS,
            sso_ticket_ttl_seconds: DEFAULT_SSO_TICKET_TTL_SECONDS,
            remember_me_enabled: false,
            remember_me_timeout: REMEMBER_ME_DEFAULT_TIMEOUT,
            session_hover_timeout: DEFAULT_SESSION_HOVER_TIMEOUT,
            frontend_separation: DEFAULT_FRONTEND_SEPARATION,
            auto_renewal_threshold: DEFAULT_AUTO_RENEWAL_THRESHOLD,
            is_concurrent: DEFAULT_IS_CONCURRENT,
            is_share: DEFAULT_IS_SHARE,
            max_login_count: DEFAULT_MAX_LOGIN_COUNT,
            tenant_isolation: TenantIsolationConfig::default(),
            #[cfg(feature = "web-waf")]
            waf_config: WafConfig::default(),
            #[cfg(feature = "web-cors")]
            cors_config: CorsConfig::default(),
            #[cfg(feature = "web-csrf")]
            csrf_config: CsrfConfig::default(),
            #[cfg(feature = "rate-limit-redis")]
            rate_limit_backend: RateLimitBackend::default(),
            watcher: None,
        };
        config.with_watcher()
    }

    /// 使用 confers 加载配置，优先级：环境变量 > toml 文件 > 代码默认值。
    ///
    /// # 参数
    /// - `toml_path`: toml 配置文件路径。`None` 时仅使用默认值 + 环境变量。
    ///
    /// # 返回
    /// 合并后的 `BulwarkConfig`（已附加 watcher 并通过 `validate()`）。
    ///
    /// # 错误
    /// - `BulwarkError::Config`：文件解析失败、环境变量非法或配置校验未通过。
    pub fn load(toml_path: Option<&str>) -> BulwarkResult<Self> {
        let env_values = collect_env_vars(ENV_PREFIX);

        let mut builder = ConfigBuilder::<Self>::new()
            .default("token_name", ConfigValue::string(DEFAULT_TOKEN_NAME))
            .default("timeout", ConfigValue::integer(DEFAULT_TIMEOUT))
            .default(
                "active_timeout",
                ConfigValue::integer(DEFAULT_ACTIVE_TIMEOUT),
            )
            .default("is_read_cookie", ConfigValue::bool(true))
            .default("is_read_header", ConfigValue::bool(true))
            .default("is_write_header", ConfigValue::bool(true))
            .default("is_write_cookie", ConfigValue::bool(false))
            .default("token_style", ConfigValue::string("uuid"))
            .default("throw_on_not_login", ConfigValue::bool(true))
            .default("cookie_secure", ConfigValue::bool(DEFAULT_COOKIE_SECURE))
            .default(
                "cookie_same_site",
                ConfigValue::string(DEFAULT_COOKIE_SAME_SITE),
            )
            .default("jwt_algorithm", ConfigValue::string(DEFAULT_JWT_ALGORITHM))
            .default("jwt_secret", ConfigValue::string(""))
            .default(
                "sign_window_seconds",
                ConfigValue::integer(DEFAULT_SIGN_WINDOW_SECONDS),
            )
            .default(
                "sso_ticket_ttl_seconds",
                ConfigValue::uint(DEFAULT_SSO_TICKET_TTL_SECONDS),
            )
            .default("remember_me_enabled", ConfigValue::bool(false))
            .default(
                "remember_me_timeout",
                ConfigValue::integer(REMEMBER_ME_DEFAULT_TIMEOUT),
            )
            .default(
                "session_hover_timeout",
                ConfigValue::integer(DEFAULT_SESSION_HOVER_TIMEOUT),
            )
            .default(
                "frontend_separation",
                ConfigValue::bool(DEFAULT_FRONTEND_SEPARATION),
            )
            .default(
                "auto_renewal_threshold",
                ConfigValue::integer(DEFAULT_AUTO_RENEWAL_THRESHOLD),
            )
            .default("is_concurrent", ConfigValue::bool(DEFAULT_IS_CONCURRENT))
            .default("is_share", ConfigValue::bool(DEFAULT_IS_SHARE))
            .default(
                "max_login_count",
                ConfigValue::uint(DEFAULT_MAX_LOGIN_COUNT as u64),
            );

        if let Some(path) = toml_path {
            builder = builder.source(Box::new(
                FileSource::new(path)
                    .allow_absolute_paths()
                    .with_priority(10),
            ));
        }

        if !env_values.is_empty() {
            builder = builder.memory_priority(50).memory(env_values);
        }

        let config = builder
            .build()
            .map_err(|e| BulwarkError::Config(format!("confers build error: {}", e)))?;

        let config = config.with_watcher();
        config.validate()?;
        Ok(config)
    }

    /// 为配置实例附加 watcher（创建 watch channel）。
    ///
    /// 反序列化后的 `BulwarkConfig` 没有 watcher，调用此方法启用 `watch()` 与 `update()`。
    pub fn with_watcher(mut self) -> Self {
        if self.watcher.is_none() {
            let (tx, _rx) = watch::channel(self.clone_for_watcher());
            self.watcher = Some(tx);
        }
        self
    }

    /// 克隆实例但不复制 watcher（用于 watcher 初始化时避免递归）。
    fn clone_for_watcher(&self) -> Self {
        let mut c = self.clone();
        c.watcher = None;
        c
    }

    /// 校验配置字段合法性。
    ///
    /// 配置校验：
    /// - `token_style` 必须是 `TOKEN_STYLES` 中的合法值
    /// - `timeout` 必须 > 0（-1 抛错 "timeout must be positive"）
    ///
    /// # 返回
    /// 校验通过返回 `Ok(())`。
    ///
    /// # 错误
    /// - `BulwarkError::Config`：`token_style` 非法（消息含 "unknown token_style"）。
    /// - `BulwarkError::Config`：`timeout` 非正（消息 "timeout must be positive"）。
    /// - `BulwarkError::Config`：`token_style=jwt` 但 `jwt_secret` 为空。
    pub fn validate(&self) -> BulwarkResult<()> {
        if !TOKEN_STYLES.contains(&self.token_style.as_str()) {
            return Err(BulwarkError::Config(format!(
                "unknown token_style: {}",
                self.token_style
            )));
        }
        if self.timeout <= 0 {
            return Err(BulwarkError::Config("timeout must be positive".to_string()));
        }
        if !COOKIE_SAME_SITE_VALUES.contains(&self.cookie_same_site.as_str()) {
            return Err(BulwarkError::Config(format!(
                "unknown cookie_same_site: {} (expected Lax/Strict/None)",
                self.cookie_same_site
            )));
        }
        if self.token_style == "jwt" && self.jwt_secret.is_empty() {
            return Err(BulwarkError::Config(
                "jwt_secret 不能为空（当 token_style=jwt 时）".to_string(),
            ));
        }
        if self.remember_me_enabled && self.remember_me_timeout <= self.timeout {
            return Err(BulwarkError::Config(format!(
                "remember_me_timeout ({}) must be greater than timeout ({}) when remember_me_enabled is true",
                self.remember_me_timeout, self.timeout
            )));
        }
        if !self.remember_me_enabled && self.remember_me_timeout <= 0 {
            return Err(BulwarkError::Config(format!(
                "remember_me_timeout must be positive, got: {}",
                self.remember_me_timeout
            )));
        }
        if self.frontend_separation {
            tracing::info!(
                "前后端分离模式已启用：Token 从 Authorization Header 读取，不设置 Cookie"
            );
        }
        if self.auto_renewal_threshold != -1 && !(0..=100).contains(&self.auto_renewal_threshold) {
            return Err(BulwarkError::Config(format!(
                "auto_renewal_threshold must be -1 or 0-100, got: {}",
                self.auto_renewal_threshold
            )));
        }
        if self.is_share && !self.is_concurrent {
            return Err(BulwarkError::Config(
                "is_share=true requires is_concurrent=true".to_string(),
            ));
        }
        Ok(())
    }

    /// 订阅配置变更。
    ///
    /// 返回 `watch::Receiver<BulwarkConfig>`，调用 `rx.borrow_and_update()` 获取最新配置。
    /// 若实例未调用 `with_watcher()`，返回 `None`。
    ///
    /// # 返回
    /// - `Some(receiver)`：成功订阅配置变更通道，后续可通过 receiver 接收 `update()` 广播的新配置。
    /// - `None`：实例未通过 `with_watcher()` 启用 watcher。
    pub fn watch(&self) -> Option<watch::Receiver<BulwarkConfig>> {
        self.watcher.as_ref().map(|tx| tx.subscribe())
    }

    /// 闭包式更新配置并广播变更。
    ///
    /// ```ignore
    /// config.update(|c| c.timeout = 3600)?;
    /// ```
    ///
    /// # 参数
    /// - `f`: 接收 `&mut BulwarkConfig` 的闭包，在闭包内修改字段值。
    ///
    /// # 返回
    /// 更新并广播成功返回 `Ok(())`；若实例未启用 watcher，亦返回 `Ok(())`（no-op）。
    ///
    /// # 错误
    /// - `BulwarkError::Config`：闭包修改后的配置未通过 `validate()`（如非法 `token_style` 或非正 `timeout`）。
    /// - `BulwarkError::Config`：watcher 已关闭（消息 "config watcher closed"）。
    ///
    /// # 行为
    /// 1. 从 watcher 读取当前配置
    /// 2. 应用闭包修改
    /// 3. 校验新配置
    /// 4. 广播新配置给所有订阅者
    ///
    /// 若实例未调用 `with_watcher()`，此方法为 no-op。
    pub fn update<F: FnOnce(&mut BulwarkConfig)>(&self, f: F) -> BulwarkResult<()> {
        let Some(sender) = &self.watcher else {
            return Ok(());
        };
        let mut new_config = sender.borrow().clone();
        f(&mut new_config);
        new_config.validate()?;
        sender
            .send(new_config)
            .map_err(|_| BulwarkError::Config("config watcher closed".to_string()))?;
        Ok(())
    }
}

impl Default for BulwarkConfig {
    fn default() -> Self {
        Self::default_config()
    }
}

/// 收集 `BULWARK_` 前缀的环境变量，转换为 confers MemorySource 所需的 `HashMap`。
///
/// Key 映射规则（与 confers `EnvSource::with_prefix(prefix).separator("__")` 一致）：
/// 1. 剥离前缀（如 `BULWARK_`）
/// 2. 转小写
/// 3. `__` → `.`（支持嵌套路径，如 `tenant_isolation.enabled`）
///
/// 使用 `MemorySource` 代替 `EnvSource` 的原因：confers 0.4.1 的 `EnvSource::collect()`
/// 未在顶层 `AnnotatedValue` 上调用 `.with_priority()`，导致优先级默认为 0，被
/// `DefaultSource`（同为 priority 0）覆盖。`MemorySource::collect()` 正确设置了 priority。
fn collect_env_vars(prefix: &str) -> HashMap<String, ConfigValue> {
    let mut values = HashMap::new();
    for (key, value) in std::env::vars() {
        if let Some(stripped) = key.strip_prefix(prefix) {
            let config_key = stripped.to_lowercase().replace("__", ".");
            values.insert(config_key, infer_config_value(&value));
        }
    }
    values
}

/// 从字符串推断 `ConfigValue` 类型（与 confers `EnvSource::infer_config_value` 逻辑一致）。
fn infer_config_value(s: &str) -> ConfigValue {
    if s.eq_ignore_ascii_case("true") {
        return ConfigValue::Bool(true);
    }
    if s.eq_ignore_ascii_case("false") {
        return ConfigValue::Bool(false);
    }
    if let Ok(v) = s.parse::<i64>() {
        return ConfigValue::I64(v);
    }
    if let Ok(v) = s.parse::<u64>() {
        return ConfigValue::U64(v);
    }
    if s.contains('.') || s.contains('e') || s.contains('E') {
        if let Ok(v) = s.parse::<f64>() {
            return ConfigValue::F64(v);
        }
    }
    ConfigValue::String(s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    /// 创建临时 toml 文件并写入内容，返回 NamedTempFile（离开作用域自动删除）。
    fn write_temp_toml(content: &str) -> tempfile::NamedTempFile {
        let file = tempfile::Builder::new()
            .suffix(".toml")
            .tempfile()
            .expect("创建临时文件失败");
        std::fs::write(file.path(), content).expect("写入临时文件失败");
        file
    }

    // ========================================================================
    // 代码默认值测试（spec Scenario: 代码默认值生效）
    // ========================================================================

    /// 验证 default_config() 返回符合 spec 的默认值。
    #[test]
    fn default_config_matches_spec() {
        let config = BulwarkConfig::default_config();
        assert_eq!(config.token_style, "uuid");
        assert_eq!(config.timeout, 2_592_000); // 30 天
        assert!(config.throw_on_not_login);
        assert_eq!(config.token_name, "bulwark_token");
        assert!(config.is_read_cookie);
        assert!(config.is_read_header);
        assert!(config.is_write_header);
        // 字段默认值
        assert_eq!(config.jwt_algorithm, "HS256");
        assert_eq!(config.sign_window_seconds, 300);
        assert_eq!(config.sso_ticket_ttl_seconds, 60);
    }

    // ========================================================================
    // is_write_cookie 配置测试（T016）
    // ========================================================================

    /// T016: `default_config()` 的 `is_write_cookie` 为 false。
    #[test]
    fn default_is_write_cookie_is_false() {
        let config = BulwarkConfig::default_config();
        assert!(!config.is_write_cookie, "默认 is_write_cookie 应为 false");
    }

    /// T016: `default_config()` 的 `is_write_header` 为 true（验证已有字段）。
    #[test]
    fn default_is_write_header_is_true() {
        let config = BulwarkConfig::default_config();
        assert!(config.is_write_header, "默认 is_write_header 应为 true");
    }

    /// T016: 可自定义 `is_write_cookie` 为 true。
    #[test]
    fn custom_is_write_cookie_can_be_set() {
        let mut config = BulwarkConfig::default_config();
        config.is_write_cookie = true;
        assert!(config.is_write_cookie, "自定义 is_write_cookie=true 应生效");
        assert!(config.validate().is_ok(), "is_write_cookie=true 应通过校验");
    }

    /// T016: `is_write_header` 和 `is_write_cookie` 可同时为 true。
    #[test]
    fn both_is_write_header_and_is_write_cookie_can_be_true() {
        let mut config = BulwarkConfig::default_config();
        config.is_write_header = true;
        config.is_write_cookie = true;
        assert!(config.is_write_header, "is_write_header 应为 true");
        assert!(config.is_write_cookie, "is_write_cookie 应为 true");
        assert!(config.validate().is_ok(), "两者同时为 true 应通过校验");
    }

    /// 验证 Default::default() 等价于 default_config()。
    #[test]
    fn default_trait_eq_default_config() {
        let d = BulwarkConfig::default();
        let dc = BulwarkConfig::default_config();
        assert_eq!(d.token_style, dc.token_style);
        assert_eq!(d.timeout, dc.timeout);
        assert_eq!(d.throw_on_not_login, dc.throw_on_not_login);
    }

    // ========================================================================
    // 配置校验测试（spec Requirement: 配置校验）
    // ========================================================================

    /// 验证非法 token_style 抛错（spec Scenario: 非法 token_style）。
    #[test]
    fn validate_rejects_invalid_token_style() {
        let mut config = BulwarkConfig::default_config();
        config.token_style = "invalid".to_string();
        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, BulwarkError::Config(ref msg) if msg.contains("unknown token_style: invalid")),
            "应返回 'unknown token_style: invalid'，实际: {:?}",
            err
        );
    }

    /// 验证 timeout = -1 抛错（spec Scenario: timeout 为负数）。
    #[test]
    fn validate_rejects_negative_timeout() {
        let mut config = BulwarkConfig::default_config();
        config.timeout = -1;
        let result = config.validate();
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(
            matches!(err, BulwarkError::Config(ref msg) if msg.contains("timeout must be positive")),
            "应返回 'timeout must be positive'，实际: {:?}",
            err
        );
    }

    /// 验证 timeout = 0 抛错。
    #[test]
    fn validate_rejects_zero_timeout() {
        let mut config = BulwarkConfig::default_config();
        config.timeout = 0;
        assert!(config.validate().is_err());
    }

    /// 验证所有合法 token_style 通过校验。
    #[test]
    fn validate_accepts_all_legal_token_styles() {
        for style in TOKEN_STYLES {
            let mut config = BulwarkConfig::default_config();
            config.token_style = style.to_string();
            if *style == "jwt" {
                config.jwt_secret = "test-secret".to_string();
            }
            assert!(
                config.validate().is_ok(),
                "token_style '{}' 应通过校验",
                style
            );
        }
    }

    /// 验证默认配置通过校验。
    #[test]
    fn default_config_validates_ok() {
        let config = BulwarkConfig::default_config();
        assert!(config.validate().is_ok());
    }

    /// 验证 token_style=jwt 但 jwt_secret 为空时校验失败（A-001 安全审计修复）。
    ///
    /// 配置校验——jwt_secret 不能为空当 token_style=jwt，
    /// 防止攻击者用公开的空字符串密钥伪造 JWT。
    #[test]
    fn validate_rejects_empty_jwt_secret_when_token_style_is_jwt() {
        let mut config = BulwarkConfig::default_config();
        config.token_style = "jwt".to_string();
        // jwt_secret 保持默认空字符串
        let result = config.validate();
        match result {
            Err(BulwarkError::Config(msg)) => {
                assert!(
                    msg.contains("jwt_secret"),
                    "错误消息应包含 jwt_secret，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 BulwarkError::Config，实际: {:?}", other),
            Ok(_) => panic!("token_style=jwt 且 jwt_secret 为空时应返回 Err"),
        }
    }

    // ========================================================================
    // remember_me 配置测试（spec R-session-lifecycle-004）
    // ========================================================================

    /// 验证 remember_me 默认值：enabled=false, timeout=7776000（90 天）。
    #[test]
    fn remember_me_defaults() {
        let config = BulwarkConfig::default_config();
        assert!(!config.remember_me_enabled);
        assert_eq!(config.remember_me_timeout, REMEMBER_ME_DEFAULT_TIMEOUT);
        assert_eq!(config.remember_me_timeout, 7_776_000);
    }

    /// 验证 remember_me_enabled=true 且 remember_me_timeout > timeout 时校验通过。
    #[test]
    fn validate_remember_me_ok_when_timeout_greater() {
        let mut config = BulwarkConfig::default_config();
        config.remember_me_enabled = true;
        // remember_me_timeout 默认 7776000 > timeout 默认 2592000，应通过
        assert!(config.validate().is_ok());
    }

    /// 验证 remember_me_enabled=true 且 remember_me_timeout <= timeout 时校验失败。
    #[test]
    fn validate_remember_me_fails_when_timeout_not_greater() {
        let mut config = BulwarkConfig::default_config();
        config.remember_me_enabled = true;
        config.remember_me_timeout = config.timeout; // 等于 timeout
        let result = config.validate();
        assert!(result.is_err());
        match result {
            Err(BulwarkError::Config(msg)) => {
                assert!(
                    msg.contains("remember_me_timeout"),
                    "错误消息应包含 remember_me_timeout，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 BulwarkError::Config，实际: {:?}", other),
            Ok(_) => panic!("remember_me_timeout <= timeout 时应返回 Err"),
        }
    }

    /// 验证 remember_me_enabled=false 时 remember_me_timeout 仅需 > 0。
    #[test]
    fn validate_remember_me_disabled_only_checks_positive() {
        let mut config = BulwarkConfig::default_config();
        config.remember_me_enabled = false;
        config.remember_me_timeout = 1; // > 0 即可（不需要 > timeout）
        assert!(config.validate().is_ok());
    }

    /// 验证 remember_me_enabled=false 且 remember_me_timeout <= 0 时校验失败。
    #[test]
    fn validate_remember_me_fails_when_timeout_non_positive() {
        let mut config = BulwarkConfig::default_config();
        config.remember_me_enabled = false;
        config.remember_me_timeout = 0;
        assert!(config.validate().is_err());
    }

    /// 验证 toml 可覆盖 remember_me 字段。
    #[test]
    #[serial]
    fn toml_overrides_remember_me() {
        let temp = write_temp_toml(
            r#"
remember_me_enabled = true
remember_me_timeout = 9999999
"#,
        );
        let config = BulwarkConfig::load(Some(temp.path().to_str().unwrap())).unwrap();
        assert!(config.remember_me_enabled);
        assert_eq!(config.remember_me_timeout, 9999999);
    }

    /// 验证环境变量可覆盖 remember_me 字段。
    #[test]
    #[serial]
    fn env_overrides_remember_me() {
        std::env::set_var("BULWARK_REMEMBER_ME_ENABLED", "true");
        std::env::set_var("BULWARK_REMEMBER_ME_TIMEOUT", "9999999");

        let config = BulwarkConfig::load(None).unwrap();

        assert!(config.remember_me_enabled);
        assert_eq!(config.remember_me_timeout, 9999999);

        std::env::remove_var("BULWARK_REMEMBER_ME_ENABLED");
        std::env::remove_var("BULWARK_REMEMBER_ME_TIMEOUT");
    }

    // ========================================================================
    // session_hover_timeout 配置测试（spec R-hover-001）
    // ========================================================================

    /// R-hover-001: `BulwarkConfig::default()` 的 `session_hover_timeout` 为 -1（不启用）。
    #[test]
    fn config_default_session_hover_is_negative_one() {
        let config = BulwarkConfig::default_config();
        assert_eq!(config.session_hover_timeout, -1);
    }

    // ========================================================================
    // frontend_separation 配置测试（spec R-frontend-001 ~ R-frontend-003）
    // ========================================================================

    /// R-frontend-001: `BulwarkConfig::default()` 的 `frontend_separation` 为 false。
    #[test]
    fn config_default_frontend_separation_is_false() {
        let config = BulwarkConfig::default_config();
        assert!(!config.frontend_separation);
    }

    /// R-frontend-002: `BULWARK_FRONTEND_SEPARATION=true` 环境变量覆盖配置为 true。
    #[test]
    #[serial]
    fn env_overrides_frontend_separation() {
        std::env::set_var("BULWARK_FRONTEND_SEPARATION", "true");
        let config = BulwarkConfig::load(None).expect("load with env");
        assert!(config.frontend_separation);
        std::env::remove_var("BULWARK_FRONTEND_SEPARATION");
    }

    /// R-frontend-003: `frontend_separation=true` 时 `validate()` 不报错。
    #[test]
    fn validate_accepts_frontend_separation_true() {
        let mut config = BulwarkConfig::default_config();
        config.frontend_separation = true;
        assert!(config.validate().is_ok());
    }

    // ========================================================================
    // toml 文件覆盖测试
    // ========================================================================

    /// 验证 toml 覆盖默认值，其他字段保持默认。
    #[test]
    #[serial]
    fn toml_overrides_token_style() {
        let temp = write_temp_toml(r#"token_style = "random_64""#);
        let config = BulwarkConfig::load(Some(temp.path().to_str().unwrap())).unwrap();
        assert_eq!(config.token_style, "random_64");
        assert_eq!(config.timeout, DEFAULT_TIMEOUT);
        assert!(config.throw_on_not_login);
    }

    /// 验证 toml 多字段覆盖。
    #[test]
    #[serial]
    fn toml_overrides_multiple_fields() {
        let temp = write_temp_toml(
            r#"
token_style = "jwt"
timeout = 1800
is_read_cookie = false
throw_on_not_login = false
jwt_secret = "test-secret"
"#,
        );
        let config = BulwarkConfig::load(Some(temp.path().to_str().unwrap())).unwrap();
        assert_eq!(config.token_style, "jwt");
        assert_eq!(config.timeout, 1800);
        assert!(!config.is_read_cookie);
        assert!(!config.throw_on_not_login);
        assert_eq!(config.token_name, DEFAULT_TOKEN_NAME);
        assert!(config.is_read_header);
    }

    /// 验证无 toml 文件时返回默认配置。
    #[test]
    #[serial]
    fn no_file_returns_default() {
        let config = BulwarkConfig::load(None).unwrap();
        assert_eq!(config.token_style, "uuid");
        assert_eq!(config.timeout, DEFAULT_TIMEOUT);
    }

    /// 验证 toml 解析错误返回 Config 错误。
    #[test]
    fn invalid_toml_returns_config_error() {
        let temp = write_temp_toml("this is not = valid = toml =");
        let result = BulwarkConfig::load(Some(temp.path().to_str().unwrap()));
        assert!(result.is_err());
        assert!(matches!(result, Err(BulwarkError::Config(_))));
    }

    /// 验证 toml 中的非法值在 validate 阶段被拒绝。
    #[test]
    fn toml_invalid_token_style_rejected() {
        let temp = write_temp_toml(r#"token_style = "unknown""#);
        let result = BulwarkConfig::load(Some(temp.path().to_str().unwrap()));
        assert!(result.is_err());
        assert!(matches!(result, Err(BulwarkError::Config(_))));
    }

    // ========================================================================
    // 环境变量覆盖测试
    // ========================================================================

    /// 验证环境变量优先级高于 toml 配置。
    #[test]
    #[serial]
    fn env_overrides_toml() {
        std::env::set_var("BULWARK_TIMEOUT", "3600");
        std::env::set_var("BULWARK_TOKEN_STYLE", "jwt");

        let temp = write_temp_toml(
            r#"timeout = 1800
jwt_secret = "test-secret""#,
        );
        let config = BulwarkConfig::load(Some(temp.path().to_str().unwrap())).unwrap();

        assert_eq!(config.timeout, 3600);
        assert_eq!(config.token_style, "jwt");

        std::env::remove_var("BULWARK_TIMEOUT");
        std::env::remove_var("BULWARK_TOKEN_STYLE");
    }

    /// 验证布尔环境变量解析。
    #[test]
    #[serial]
    fn env_boolean_parsing() {
        std::env::set_var("BULWARK_IS_READ_COOKIE", "false");
        std::env::set_var("BULWARK_THROW_ON_NOT_LOGIN", "false");

        let config = BulwarkConfig::load(None).unwrap();

        assert!(!config.is_read_cookie);
        assert!(!config.throw_on_not_login);

        std::env::remove_var("BULWARK_IS_READ_COOKIE");
        std::env::remove_var("BULWARK_THROW_ON_NOT_LOGIN");
    }

    /// 验证环境变量非法值抛错。
    #[test]
    #[serial]
    fn env_invalid_value_errors() {
        std::env::set_var("BULWARK_TIMEOUT", "not-a-number");
        let result = BulwarkConfig::load(None);
        assert!(result.is_err());
        std::env::remove_var("BULWARK_TIMEOUT");
    }

    /// 验证完整加载流程 load()：默认值 + toml + 环境变量。
    #[test]
    #[serial]
    fn load_full_pipeline() {
        std::env::set_var("BULWARK_TOKEN_NAME", "custom_token");
        let temp = write_temp_toml(r#"timeout = 3600"#);
        let config = BulwarkConfig::load(Some(temp.path().to_str().unwrap())).unwrap();
        assert_eq!(config.token_name, "custom_token");
        assert_eq!(config.timeout, 3600);
        assert_eq!(config.token_style, "uuid");
        std::env::remove_var("BULWARK_TOKEN_NAME");
    }

    // ========================================================================
    // 热更新测试
    // ========================================================================

    /// 验证 watch() 返回 receiver，update() 广播新值。
    #[test]
    fn watch_and_update_broadcasts() {
        let config = BulwarkConfig::default_config();
        let mut rx = config.watch().expect("default_config 应有 watcher");

        config.update(|c| c.timeout = 3600).expect("update 应成功");

        let new_config = rx.borrow_and_update();
        assert_eq!(new_config.timeout, 3600);
    }

    /// 验证 update() 闭包可以修改多个字段。
    #[test]
    fn update_modifies_multiple_fields() {
        let config = BulwarkConfig::default_config();
        let mut rx = config.watch().unwrap();

        config
            .update(|c| {
                c.timeout = 7200;
                c.token_style = "jwt".to_string();
                c.jwt_secret = "test-secret".to_string();
                c.throw_on_not_login = false;
            })
            .unwrap();

        let new_config = rx.borrow_and_update();
        assert_eq!(new_config.timeout, 7200);
        assert_eq!(new_config.token_style, "jwt");
        assert!(!new_config.throw_on_not_login);
    }

    /// 验证 update() 中非法值被拒绝（不广播）。
    #[test]
    fn update_rejects_invalid_value() {
        let config = BulwarkConfig::default_config();
        let mut rx = config.watch().unwrap();

        let result = config.update(|c| c.token_style = "invalid".to_string());
        assert!(result.is_err());

        let current = rx.borrow_and_update();
        assert_eq!(current.token_style, "uuid");
    }

    /// 验证 update() 中 timeout = -1 被拒绝。
    #[test]
    fn update_rejects_negative_timeout() {
        let config = BulwarkConfig::default_config();
        let mut rx = config.watch().unwrap();

        let result = config.update(|c| c.timeout = -1);
        assert!(result.is_err());

        let current = rx.borrow_and_update();
        assert_eq!(current.timeout, DEFAULT_TIMEOUT);
    }

    /// 验证无 watcher 的实例 update() 是 no-op。
    #[test]
    fn update_without_watcher_is_noop() {
        let config = BulwarkConfig {
            token_name: "x".to_string(),
            timeout: 100,
            active_timeout: -1,
            is_read_cookie: true,
            is_read_header: true,
            is_write_header: true,
            is_write_cookie: false,
            token_style: "uuid".to_string(),
            throw_on_not_login: true,
            cookie_secure: true,
            cookie_same_site: "Lax".to_string(),
            jwt_algorithm: "HS256".to_string(),
            jwt_secret: String::new(),
            sign_window_seconds: 300,
            sso_ticket_ttl_seconds: 60,
            remember_me_enabled: false,
            remember_me_timeout: REMEMBER_ME_DEFAULT_TIMEOUT,
            session_hover_timeout: DEFAULT_SESSION_HOVER_TIMEOUT,
            frontend_separation: DEFAULT_FRONTEND_SEPARATION,
            auto_renewal_threshold: DEFAULT_AUTO_RENEWAL_THRESHOLD,
            is_concurrent: DEFAULT_IS_CONCURRENT,
            is_share: DEFAULT_IS_SHARE,
            max_login_count: DEFAULT_MAX_LOGIN_COUNT,
            tenant_isolation: TenantIsolationConfig::default(),
            #[cfg(feature = "web-waf")]
            waf_config: crate::web::waf::WafConfig::default(),
            #[cfg(feature = "web-cors")]
            cors_config: crate::web::cors::CorsConfig::default(),
            #[cfg(feature = "web-csrf")]
            csrf_config: crate::web::csrf::CsrfConfig::default(),
            #[cfg(feature = "rate-limit-redis")]
            rate_limit_backend: crate::strategy::rate_limiter_backend::RateLimitBackend::default(),
            watcher: None,
        };
        assert!(config.update(|c| c.timeout = 999).is_ok());
        assert!(config.watch().is_none());
    }

    // ========================================================================
    // 序列化测试
    // ========================================================================

    /// 验证序列化为 toml 往返一致。
    #[test]
    fn serialize_deserialize_toml_roundtrip() {
        let mut config = BulwarkConfig::default_config();
        config.timeout = 7200;
        config.token_style = "jwt".to_string();

        let toml_str = toml::to_string(&config).expect("toml 序列化应成功");
        assert!(toml_str.contains("timeout = 7200"));
        assert!(toml_str.contains("token_style = \"jwt\""));

        let parsed: BulwarkConfig = toml::from_str(&toml_str).expect("toml 反序列化应成功");
        assert_eq!(parsed.timeout, 7200);
        assert_eq!(parsed.token_style, "jwt");
    }

    /// 验证序列化为 json 往返一致。
    #[test]
    fn serialize_deserialize_json_roundtrip() {
        let mut config = BulwarkConfig::default_config();
        config.timeout = 1800;
        config.is_read_cookie = false;

        let json_str = serde_json::to_string(&config).expect("json 序列化应成功");
        assert!(json_str.contains("\"timeout\":1800"));
        assert!(json_str.contains("\"is_read_cookie\":false"));

        let parsed: BulwarkConfig = serde_json::from_str(&json_str).expect("json 反序列化应成功");
        assert_eq!(parsed.timeout, 1800);
        assert!(!parsed.is_read_cookie);
    }

    /// 验证 watcher 字段不被序列化。
    #[test]
    fn watcher_not_serialized() {
        let config = BulwarkConfig::default_config();
        let json_str = serde_json::to_string(&config).unwrap();
        assert!(!json_str.contains("watcher"));
        assert!(!json_str.contains("sender"));
    }

    // ========================================================================
    // 环境变量覆盖错误路径测试（confers 处理，错误类型为 Config）
    // ========================================================================

    /// 验证 BULWARK_IS_READ_COOKIE 非法布尔值时 load 抛错。
    #[test]
    #[serial]
    fn env_invalid_is_read_cookie_errors() {
        std::env::set_var("BULWARK_IS_READ_COOKIE", "maybe");
        let result = BulwarkConfig::load(None);
        assert!(result.is_err(), "非法布尔值应导致 load 失败");
        assert!(matches!(result, Err(BulwarkError::Config(_))));
        std::env::remove_var("BULWARK_IS_READ_COOKIE");
    }

    /// 验证 BULWARK_IS_READ_HEADER 非法布尔值时 load 抛错。
    #[test]
    #[serial]
    fn env_invalid_is_read_header_errors() {
        std::env::set_var("BULWARK_IS_READ_HEADER", "yesno");
        let result = BulwarkConfig::load(None);
        assert!(result.is_err());
        assert!(matches!(result, Err(BulwarkError::Config(_))));
        std::env::remove_var("BULWARK_IS_READ_HEADER");
    }

    /// 验证 BULWARK_IS_WRITE_HEADER 非法布尔值时 load 抛错。
    #[test]
    #[serial]
    fn env_invalid_is_write_header_errors() {
        std::env::set_var("BULWARK_IS_WRITE_HEADER", "unknown");
        let result = BulwarkConfig::load(None);
        assert!(result.is_err());
        assert!(matches!(result, Err(BulwarkError::Config(_))));
        std::env::remove_var("BULWARK_IS_WRITE_HEADER");
    }

    /// 验证 BULWARK_THROW_ON_NOT_LOGIN 非法布尔值时 load 抛错。
    #[test]
    #[serial]
    fn env_invalid_throw_on_not_login_errors() {
        std::env::set_var("BULWARK_THROW_ON_NOT_LOGIN", "yes_no");
        let result = BulwarkConfig::load(None);
        assert!(result.is_err());
        assert!(matches!(result, Err(BulwarkError::Config(_))));
        std::env::remove_var("BULWARK_THROW_ON_NOT_LOGIN");
    }

    /// 验证 BULWARK_ACTIVE_TIMEOUT 非数字时 load 抛错。
    #[test]
    #[serial]
    fn env_invalid_active_timeout_errors() {
        std::env::set_var("BULWARK_ACTIVE_TIMEOUT", "not-a-number");
        let result = BulwarkConfig::load(None);
        assert!(result.is_err());
        std::env::remove_var("BULWARK_ACTIVE_TIMEOUT");
    }

    /// 验证 BULWARK_TOKEN_STYLE 非法值导致 load 校验失败。
    #[test]
    #[serial]
    fn env_invalid_token_style_fails_validation() {
        std::env::set_var("BULWARK_TOKEN_STYLE", "unknown_style");
        let result = BulwarkConfig::load(None);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(BulwarkError::Config(ref msg)) if msg.contains("unknown token_style")),
            "应返回 'unknown token_style' 错误，实际: {:?}",
            result
        );
        std::env::remove_var("BULWARK_TOKEN_STYLE");
    }

    /// 验证 BULWARK_TIMEOUT 负值导致 load 校验失败。
    #[test]
    #[serial]
    fn env_negative_timeout_fails_validation() {
        std::env::set_var("BULWARK_TIMEOUT", "-100");
        let result = BulwarkConfig::load(None);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(BulwarkError::Config(ref msg)) if msg.contains("timeout must be positive")),
            "应返回 'timeout must be positive' 错误，实际: {:?}",
            result
        );
        std::env::remove_var("BULWARK_TIMEOUT");
    }

    // ========================================================================
    // 字段环境变量覆盖测试
    // ========================================================================

    /// 验证 `BULWARK_JWT_ALGORITHM` 环境变量覆盖 jwt_algorithm 字段。
    #[test]
    #[serial]
    fn env_overrides_jwt_algorithm() {
        std::env::set_var(format!("{}JWT_ALGORITHM", ENV_PREFIX), "HS512");
        let config = BulwarkConfig::load(None).unwrap();
        assert_eq!(config.jwt_algorithm, "HS512");
        std::env::remove_var(format!("{}JWT_ALGORITHM", ENV_PREFIX));
    }

    /// 验证 `BULWARK_SIGN_WINDOW_SECONDS` 环境变量覆盖 sign_window_seconds 字段。
    #[test]
    #[serial]
    fn env_overrides_sign_window_seconds() {
        std::env::set_var(format!("{}SIGN_WINDOW_SECONDS", ENV_PREFIX), "600");
        let config = BulwarkConfig::load(None).unwrap();
        assert_eq!(config.sign_window_seconds, 600);
        std::env::remove_var(format!("{}SIGN_WINDOW_SECONDS", ENV_PREFIX));
    }

    /// 验证 `BULWARK_SSO_TICKET_TTL_SECONDS` 环境变量覆盖 sso_ticket_ttl_seconds 字段。
    #[test]
    #[serial]
    fn env_overrides_sso_ticket_ttl_seconds() {
        std::env::set_var(format!("{}SSO_TICKET_TTL_SECONDS", ENV_PREFIX), "120");
        let config = BulwarkConfig::load(None).unwrap();
        assert_eq!(config.sso_ticket_ttl_seconds, 120);
        std::env::remove_var(format!("{}SSO_TICKET_TTL_SECONDS", ENV_PREFIX));
    }

    /// 验证 `BULWARK_SIGN_WINDOW_SECONDS` 非数字时 load 抛错。
    #[test]
    #[serial]
    fn env_overrides_sign_window_seconds_invalid() {
        std::env::set_var(format!("{}SIGN_WINDOW_SECONDS", ENV_PREFIX), "not-a-number");
        let result = BulwarkConfig::load(None);
        assert!(
            result.is_err(),
            "非数字 SIGN_WINDOW_SECONDS 应导致 load 失败"
        );
        std::env::remove_var(format!("{}SIGN_WINDOW_SECONDS", ENV_PREFIX));
    }

    /// 验证 `BULWARK_SSO_TICKET_TTL_SECONDS` 非数字时 load 抛错。
    #[test]
    #[serial]
    fn env_overrides_sso_ticket_ttl_seconds_invalid() {
        std::env::set_var(format!("{}SSO_TICKET_TTL_SECONDS", ENV_PREFIX), "abc");
        let result = BulwarkConfig::load(None);
        assert!(
            result.is_err(),
            "非数字 SSO_TICKET_TTL_SECONDS 应导致 load 失败"
        );
        std::env::remove_var(format!("{}SSO_TICKET_TTL_SECONDS", ENV_PREFIX));
    }

    // ========================================================================
    // tenant_isolation 配置段测试
    // ========================================================================

    /// R-tenant-isolation-006: `BulwarkConfig` 反序列化 JSON 含 `tenant_isolation` 段时，
    /// 字段正确填充。
    ///
    /// 验证：`{"tenant_isolation": {"enabled": true, "resolver": "header"}}` 反序列化后
    /// `config.tenant_isolation.enabled == true`
    /// `config.tenant_isolation.resolver == TenantResolverKind::Header`
    #[cfg(feature = "tenant-isolation")]
    #[test]
    fn bulwark_config_includes_tenant_isolation_section() {
        let json = r#"{
            "tenant_isolation": {
                "enabled": true,
                "resolver": "header"
            }
        }"#;
        let config: BulwarkConfig = serde_json::from_str(json).unwrap();
        assert!(
            config.tenant_isolation.enabled,
            "反序列化后 tenant_isolation.enabled 应为 true"
        );
        assert_eq!(
            config.tenant_isolation.resolver,
            TenantResolverKind::Header,
            "反序列化后 resolver 应为 Header"
        );
    }

    /// R-tenant-isolation-006: `default_config()` 的 `tenant_isolation` 默认禁用，
    /// resolver 默认为 `Header`。
    #[cfg(feature = "tenant-isolation")]
    #[test]
    fn tenant_isolation_config_defaults_to_disabled() {
        let config = BulwarkConfig::default_config();
        assert!(
            !config.tenant_isolation.enabled,
            "默认 tenant_isolation.enabled 应为 false（不启用）"
        );
        assert_eq!(
            config.tenant_isolation.resolver,
            TenantResolverKind::Header,
            "默认 resolver 应为 Header"
        );
    }

    /// R-tenant-isolation-006: `TenantResolverKind` 支持全部三种变体反序列化。
    #[cfg(feature = "tenant-isolation")]
    #[test]
    fn tenant_resolver_kind_supports_all_variants() {
        let cases = [
            (r#""header""#, TenantResolverKind::Header),
            (r#""subdomain""#, TenantResolverKind::Subdomain),
            (r#""claim""#, TenantResolverKind::Claim),
        ];
        for (json, expected) in &cases {
            let kind: TenantResolverKind = serde_json::from_str(json)
                .unwrap_or_else(|e| panic!("反序列化 {} 失败: {}", json, e));
            assert_eq!(kind, *expected, "反序列化 {} 应匹配 {:?}", json, expected);
        }
    }

    // ========================================================================
    // auto_renewal_threshold 配置测试（spec R-token-001 ~ R-token-003）
    // ========================================================================

    /// R-token-001: `BulwarkConfig::default()` 的 `auto_renewal_threshold` 为 -1（不启用）。
    #[test]
    fn config_default_auto_renewal_is_negative_one() {
        let config = BulwarkConfig::default_config();
        assert_eq!(config.auto_renewal_threshold, -1);
    }

    /// R-token-002: `auto_renewal_threshold = 101` 时 `validate()` 返回 Err。
    #[test]
    fn validate_rejects_threshold_above_100() {
        let mut config = BulwarkConfig::default_config();
        config.auto_renewal_threshold = 101;
        let result = config.validate();
        assert!(result.is_err());
        match result {
            Err(BulwarkError::Config(msg)) => {
                assert!(
                    msg.contains("auto_renewal_threshold must be -1 or 0-100"),
                    "错误消息应包含范围提示，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 BulwarkError::Config，实际: {:?}", other),
            Ok(_) => panic!("threshold=101 时应返回 Err"),
        }
    }

    /// R-token-002: `auto_renewal_threshold = -2` 时 `validate()` 返回 Err。
    #[test]
    fn validate_rejects_threshold_below_negative_one() {
        let mut config = BulwarkConfig::default_config();
        config.auto_renewal_threshold = -2;
        assert!(config.validate().is_err());
    }

    /// R-token-002: 边界值 -1、0、100 均通过校验。
    #[test]
    fn validate_accepts_threshold_boundaries() {
        for &threshold in &[-1i64, 0, 100] {
            let mut config = BulwarkConfig::default_config();
            config.auto_renewal_threshold = threshold;
            assert!(
                config.validate().is_ok(),
                "threshold={} 应通过校验",
                threshold
            );
        }
    }

    /// R-token-003: `BULWARK_AUTO_RENEWAL_THRESHOLD=20` 环境变量覆盖配置为 20。
    #[test]
    #[serial]
    fn env_overrides_auto_renewal_threshold() {
        std::env::set_var("BULWARK_AUTO_RENEWAL_THRESHOLD", "20");
        let config = BulwarkConfig::load(None).expect("load with env");
        assert_eq!(config.auto_renewal_threshold, 20);
        std::env::remove_var("BULWARK_AUTO_RENEWAL_THRESHOLD");
    }

    // ========================================================================
    // 并发登录控制配置测试（spec R-concurrent-001 ~ R-concurrent-004）
    // ========================================================================

    /// R-concurrent-001: `BulwarkConfig::default()` 的 `is_concurrent` 为 true。
    #[test]
    fn config_default_is_concurrent_true() {
        let config = BulwarkConfig::default_config();
        assert!(config.is_concurrent, "默认允许并发登录");
    }

    /// R-concurrent-001: `BulwarkConfig::default()` 的 `is_share` 为 false。
    #[test]
    fn config_default_is_share_false() {
        let config = BulwarkConfig::default_config();
        assert!(!config.is_share, "默认不共享 token");
    }

    /// R-concurrent-001: `BulwarkConfig::default()` 的 `max_login_count` 为 0（不限制）。
    #[test]
    fn config_default_max_login_count_zero() {
        let config = BulwarkConfig::default_config();
        assert_eq!(config.max_login_count, 0, "默认不限制登录数量");
    }

    /// R-concurrent-002: `is_share=true` 但 `is_concurrent=false` 时 `validate()` 返回 Err。
    #[test]
    fn validate_rejects_share_without_concurrent() {
        let mut config = BulwarkConfig::default_config();
        config.is_concurrent = false;
        config.is_share = true;
        let result = config.validate();
        assert!(result.is_err());
        match result {
            Err(BulwarkError::Config(msg)) => {
                assert!(
                    msg.contains("is_share=true requires is_concurrent=true"),
                    "错误消息应包含约束提示，实际: {}",
                    msg
                );
            },
            Err(other) => panic!("期望 BulwarkError::Config，实际: {:?}", other),
            Ok(_) => panic!("is_share=true + is_concurrent=false 时应返回 Err"),
        }
    }

    /// R-concurrent-002: `is_share=true` 且 `is_concurrent=true` 时校验通过。
    #[test]
    fn validate_accepts_share_with_concurrent() {
        let mut config = BulwarkConfig::default_config();
        config.is_concurrent = true;
        config.is_share = true;
        assert!(config.validate().is_ok());
    }

    /// R-concurrent-003: `BULWARK_IS_CONCURRENT=false` 环境变量覆盖配置。
    #[test]
    #[serial]
    fn env_overrides_is_concurrent() {
        std::env::set_var("BULWARK_IS_CONCURRENT", "false");
        let config = BulwarkConfig::load(None).expect("load with env");
        assert!(!config.is_concurrent);
        std::env::remove_var("BULWARK_IS_CONCURRENT");
    }

    /// R-concurrent-004: `BULWARK_MAX_LOGIN_COUNT=3` 环境变量覆盖配置。
    #[test]
    #[serial]
    fn env_overrides_max_login_count() {
        std::env::set_var("BULWARK_MAX_LOGIN_COUNT", "3");
        let config = BulwarkConfig::load(None).expect("load with env");
        assert_eq!(config.max_login_count, 3);
        std::env::remove_var("BULWARK_MAX_LOGIN_COUNT");
    }
}
