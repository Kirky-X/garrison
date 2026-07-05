//! 配置模块，提供 BulwarkConfig 全局配置与 ConfigLoader trait。
//!
//! [借鉴 Sa-Token] 对应 Sa-Token 的 `SaTokenConfig`，
//! 定义 Token 名称、超时、持久化等配置项。
//!
//! ## 配置源（依据 spec config-system）
//!
//! 1. **代码默认值**：`BulwarkConfig::default_config()` 返回符合 spec 的默认配置
//! 2. **toml 文件**：通过 `ConfigLoader::load_from_toml_str()` 解析 toml 字符串
//! 3. **环境变量**：通过 `ConfigLoader::apply_env_overrides()` 用 `BULWARK_` 前缀覆盖
//!
//! 优先级：环境变量 > toml 文件 > 代码默认值
//!
//! ## 热更新（依据 spec config-system Requirement: 配置热更新）
//!
//! 通过 `tokio::sync::watch` 通道广播配置变更：
//! - `BulwarkConfig::watch()` 返回 `watch::Receiver<BulwarkConfig>`
//! - `BulwarkConfig::update(f)` 闭包式修改配置并广播

use crate::error::{BulwarkError, BulwarkResult};
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

/// Token 风格枚举（对应 Sa-Token 的 token 风格）。
///
/// 依据 spec config-system Requirement: 配置校验——token_style 必须是以下 4 个合法值之一。
pub const TOKEN_STYLES: &[&str] = &["uuid", "random_64", "simple", "jwt"];

/// Cookie SameSite 合法值（依据 RFC 6265bis）。
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

/// 默认 JWT 签名算法（HS256，兼容 HS512 可选，依据 spec protocol-jwt）。
pub const DEFAULT_JWT_ALGORITHM: &str = "HS256";

/// 默认签名校验时间窗口秒数（5 分钟，依据 spec protocol-sign 防重放）。
pub const DEFAULT_SIGN_WINDOW_SECONDS: i64 = 300;

/// 默认 SSO ticket TTL 秒数（60 秒，依据 spec protocol-sso 短时票据）。
pub const DEFAULT_SSO_TICKET_TTL_SECONDS: u64 = 60;

/// 环境变量前缀（BULWARK_）。
pub const ENV_PREFIX: &str = "BULWARK_";

// ============================================================================
// 多租户隔离配置（v0.5.0 新增，依据 spec tenant-isolation R-006）
// ============================================================================

/// 租户解析器类型（依据 spec tenant-isolation R-006）。
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

/// 多租户隔离配置段（依据 spec tenant-isolation R-006）。
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
/// - `timeout` 必须 > 0（依据 spec config-system Requirement: 配置校验）
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

    /// Token 超时秒数（必须 > 0，依据 spec config-system Requirement: 配置校验）。
    pub timeout: i64,

    /// 活动超时检测（-1 表示不启用，保留 Sa-Token 语义）。
    pub active_timeout: i64,

    /// 是否从 Cookie 中读取 Token。
    pub is_read_cookie: bool,

    /// 是否从 Header 中读取 Token。
    pub is_read_header: bool,

    /// 是否在登录后自动写入 Header。
    pub is_write_header: bool,

    /// Token 风格（uuid / random_64 / simple / jwt）。
    pub token_style: String,

    /// 未登录时是否抛出异常（false 则返回 false，依据 spec config-system）。
    pub throw_on_not_login: bool,

    /// Cookie 是否标记 `Secure`（仅 HTTPS 传输，dev 环境 HTTP 调试时可设为 false）。
    pub cookie_secure: bool,

    /// Cookie 的 `SameSite` 策略（"Lax" / "Strict" / "None"）。
    pub cookie_same_site: String,

    /// JWT 签名算法（"HS256" 默认 / "HS512" 可选，依据 spec protocol-jwt）。
    pub jwt_algorithm: String,

    /// JWT 签名密钥（0.2.0 新增，依据 spec core-auth-api：verify_token/refresh_token 委托 JwtHandler 需要 secret）。
    /// 默认空字符串，业务方使用 JWT 时必须配置非空 secret。
    pub jwt_secret: String,

    /// 签名校验时间窗口秒数（默认 300 秒，依据 spec protocol-sign 防重放）。
    pub sign_window_seconds: i64,

    /// SSO ticket TTL 秒数（默认 60 秒，依据 spec protocol-sso 短时票据）。
    pub sso_ticket_ttl_seconds: u64,

    /// 多租户隔离配置段（v0.5.0 新增，依据 spec tenant-isolation R-006）。
    ///
    /// 默认 `enabled: false`（向后兼容）。启用后需配合 `tenant-isolation` Cargo feature
    /// + `tenant_resolution_middleware` 才能生效。
    pub tenant_isolation: TenantIsolationConfig,

    /// 配置变更广播通道（serde 跳过，反序列化后通过 `with_watcher` 重建）。
    #[serde(skip)]
    watcher: Option<watch::Sender<BulwarkConfig>>,
}

impl BulwarkConfig {
    /// 创建符合 spec 的默认配置实例。
    ///
    /// 依据 spec config-system Scenario: 代码默认值生效：
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
            token_style: "uuid".to_string(),
            throw_on_not_login: true,
            cookie_secure: DEFAULT_COOKIE_SECURE,
            cookie_same_site: DEFAULT_COOKIE_SAME_SITE.to_string(),
            jwt_algorithm: DEFAULT_JWT_ALGORITHM.to_string(),
            jwt_secret: String::new(),
            sign_window_seconds: DEFAULT_SIGN_WINDOW_SECONDS,
            sso_ticket_ttl_seconds: DEFAULT_SSO_TICKET_TTL_SECONDS,
            tenant_isolation: TenantIsolationConfig::default(),
            watcher: None,
        };
        config.with_watcher()
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
    /// 依据 spec config-system Requirement: 配置校验：
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
        Ok(())
    }

    /// 订阅配置变更（依据 spec config-system Requirement: 配置热更新）。
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

    /// 闭包式更新配置并广播变更（依据 spec config-system Requirement: 配置热更新）。
    ///
    /// 对应 spec scenario `BulwarkConfig::update("timeout", 3600)`：
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

/// 配置加载器 trait（依据 spec config-system Requirement: 配置加载）。
///
/// 支持三源合并：代码默认值 → toml 文件 → 环境变量覆盖。
pub trait ConfigLoader {
    /// 完整加载流程：toml 文件 → 环境变量覆盖。
    ///
    /// `toml_str` 为空时使用代码默认值。
    ///
    /// # 参数
    /// - `toml_str`: toml 配置字符串，空字符串使用代码默认值。
    ///
    /// # 返回
    /// 合并后的 `BulwarkConfig`（已附加 watcher 并通过 `validate()`）。
    ///
    /// # 错误
    /// - `BulwarkError::Config`：toml 解析失败、环境变量非法或配置校验未通过。
    fn load(toml_str: &str) -> BulwarkResult<BulwarkConfig> {
        let config = Self::load_from_toml_str(toml_str)?;
        Self::apply_env_overrides(config)
    }

    /// 从 toml 字符串加载配置（空字符串返回默认值）。
    ///
    /// # 参数
    /// - `toml_str`: toml 配置字符串，空字符串使用代码默认值。
    ///
    /// # 返回
    /// 解析得到的 `BulwarkConfig`（已附加 watcher 并通过 `validate()`）。
    ///
    /// # 错误
    /// - `BulwarkError::Config`：toml 解析失败（消息含 "toml parse error"）。
    /// - `BulwarkError::Config`：配置校验未通过（如非法 `token_style`）。
    fn load_from_toml_str(toml_str: &str) -> BulwarkResult<BulwarkConfig>;

    /// 应用环境变量覆盖（`BULWARK_` 前缀）。
    ///
    /// # 参数
    /// - `config`: 待覆盖的配置实例。
    ///
    /// # 返回
    /// 应用环境变量覆盖后的 `BulwarkConfig`（已通过 `validate()`）。
    ///
    /// # 错误
    /// - `BulwarkError::Config`：环境变量值非法（如非数字、非布尔）。
    /// - `BulwarkError::Config`：覆盖后配置校验未通过。
    fn apply_env_overrides(config: BulwarkConfig) -> BulwarkResult<BulwarkConfig>;
}

/// 默认配置加载器实现。
pub struct DefaultConfigLoader;

impl ConfigLoader for DefaultConfigLoader {
    fn load_from_toml_str(toml_str: &str) -> BulwarkResult<BulwarkConfig> {
        if toml_str.trim().is_empty() {
            let config = BulwarkConfig::default_config();
            config.validate()?;
            Ok(config)
        } else {
            let config: BulwarkConfig = toml::from_str(toml_str)
                .map_err(|e| BulwarkError::Config(format!("toml parse error: {}", e)))?;
            config.validate()?;
            Ok(config.with_watcher())
        }
    }

    fn apply_env_overrides(mut config: BulwarkConfig) -> BulwarkResult<BulwarkConfig> {
        if let Ok(v) = std::env::var(format!("{}TOKEN_NAME", ENV_PREFIX)) {
            config.token_name = v;
        }
        if let Ok(v) = std::env::var(format!("{}TIMEOUT", ENV_PREFIX)) {
            config.timeout = v.parse().map_err(|_| {
                BulwarkError::Config(format!("{}TIMEOUT invalid: {}", ENV_PREFIX, v))
            })?;
        }
        if let Ok(v) = std::env::var(format!("{}ACTIVE_TIMEOUT", ENV_PREFIX)) {
            config.active_timeout = v.parse().map_err(|_| {
                BulwarkError::Config(format!("{}ACTIVE_TIMEOUT invalid: {}", ENV_PREFIX, v))
            })?;
        }
        if let Ok(v) = std::env::var(format!("{}IS_READ_COOKIE", ENV_PREFIX)) {
            config.is_read_cookie = parse_bool(&v)?;
        }
        if let Ok(v) = std::env::var(format!("{}IS_READ_HEADER", ENV_PREFIX)) {
            config.is_read_header = parse_bool(&v)?;
        }
        if let Ok(v) = std::env::var(format!("{}IS_WRITE_HEADER", ENV_PREFIX)) {
            config.is_write_header = parse_bool(&v)?;
        }
        if let Ok(v) = std::env::var(format!("{}TOKEN_STYLE", ENV_PREFIX)) {
            config.token_style = v;
        }
        if let Ok(v) = std::env::var(format!("{}THROW_ON_NOT_LOGIN", ENV_PREFIX)) {
            config.throw_on_not_login = parse_bool(&v)?;
        }
        if let Ok(v) = std::env::var(format!("{}COOKIE_SECURE", ENV_PREFIX)) {
            config.cookie_secure = parse_bool(&v)?;
        }
        if let Ok(v) = std::env::var(format!("{}COOKIE_SAME_SITE", ENV_PREFIX)) {
            config.cookie_same_site = v;
        }
        if let Ok(v) = std::env::var(format!("{}JWT_ALGORITHM", ENV_PREFIX)) {
            config.jwt_algorithm = v;
        }
        if let Ok(v) = std::env::var(format!("{}SIGN_WINDOW_SECONDS", ENV_PREFIX)) {
            config.sign_window_seconds = v.parse().map_err(|_| {
                BulwarkError::Config(format!("{}SIGN_WINDOW_SECONDS invalid: {}", ENV_PREFIX, v))
            })?;
        }
        if let Ok(v) = std::env::var(format!("{}SSO_TICKET_TTL_SECONDS", ENV_PREFIX)) {
            config.sso_ticket_ttl_seconds = v.parse().map_err(|_| {
                BulwarkError::Config(format!(
                    "{}SSO_TICKET_TTL_SECONDS invalid: {}",
                    ENV_PREFIX, v
                ))
            })?;
        }
        config.validate()?;
        Ok(config)
    }
}

/// 解析布尔字符串（支持 true/false/1/0/yes/no）。
fn parse_bool(s: &str) -> BulwarkResult<bool> {
    match s.to_lowercase().as_str() {
        "true" | "1" | "yes" | "on" => Ok(true),
        "false" | "0" | "no" | "off" => Ok(false),
        _ => Err(BulwarkError::Config(format!(
            "invalid boolean value: {} (expected true/false/1/0/yes/no)",
            s
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

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
        // 0.2.0 新增字段默认值（依据 spec protocol-jwt / protocol-sign / protocol-sso）
        assert_eq!(config.jwt_algorithm, "HS256");
        assert_eq!(config.sign_window_seconds, 300);
        assert_eq!(config.sso_ticket_ttl_seconds, 60);
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
    /// 依据 spec config-system Requirement: 配置校验——jwt_secret 不能为空当 token_style=jwt，
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
    // toml 文件覆盖测试（spec Scenario: toml 文件覆盖默认值）
    // ========================================================================

    /// 验证 toml 覆盖默认值，其他字段保持默认。
    #[test]
    fn toml_overrides_token_style() {
        let toml_str = r#"token_style = "random_64""#;
        let config = DefaultConfigLoader::load_from_toml_str(toml_str).unwrap();
        assert_eq!(config.token_style, "random_64");
        assert_eq!(config.timeout, DEFAULT_TIMEOUT); // 保持默认
        assert!(config.throw_on_not_login); // 保持默认
    }

    /// 验证 toml 多字段覆盖。
    #[test]
    fn toml_overrides_multiple_fields() {
        let toml_str = r#"
token_style = "jwt"
timeout = 1800
is_read_cookie = false
throw_on_not_login = false
jwt_secret = "test-secret"
"#;
        let config = DefaultConfigLoader::load_from_toml_str(toml_str).unwrap();
        assert_eq!(config.token_style, "jwt");
        assert_eq!(config.timeout, 1800);
        assert!(!config.is_read_cookie);
        assert!(!config.throw_on_not_login);
        // 未覆盖的字段保持默认
        assert_eq!(config.token_name, DEFAULT_TOKEN_NAME);
        assert!(config.is_read_header);
    }

    /// 验证空 toml 字符串返回默认配置。
    #[test]
    fn empty_toml_returns_default() {
        let config = DefaultConfigLoader::load_from_toml_str("").unwrap();
        assert_eq!(config.token_style, "uuid");
        assert_eq!(config.timeout, DEFAULT_TIMEOUT);
    }

    /// 验证 toml 解析错误返回 Config 错误。
    #[test]
    fn invalid_toml_returns_config_error() {
        let invalid_toml = "this is not = valid = toml =";
        let result = DefaultConfigLoader::load_from_toml_str(invalid_toml);
        assert!(result.is_err());
        assert!(matches!(result, Err(BulwarkError::Config(_))));
    }

    /// 验证 toml 中的非法值在 validate 阶段被拒绝。
    #[test]
    fn toml_invalid_token_style_rejected() {
        let toml_str = r#"token_style = "unknown""#;
        let result = DefaultConfigLoader::load_from_toml_str(toml_str);
        assert!(result.is_err());
        assert!(matches!(result, Err(BulwarkError::Config(_))));
    }

    // ========================================================================
    // 环境变量覆盖测试（spec Scenario: 环境变量覆盖文件）
    // ========================================================================

    /// 验证环境变量优先级高于 toml 配置。
    #[test]
    #[serial]
    fn env_overrides_toml() {
        // 设置环境变量
        std::env::set_var("BULWARK_TIMEOUT", "3600");
        std::env::set_var("BULWARK_TOKEN_STYLE", "jwt");

        let toml_str = r#"timeout = 1800
jwt_secret = "test-secret""#;
        let config = DefaultConfigLoader::load_from_toml_str(toml_str).unwrap();
        let config = DefaultConfigLoader::apply_env_overrides(config).unwrap();

        assert_eq!(config.timeout, 3600); // 环境变量覆盖
        assert_eq!(config.token_style, "jwt"); // 环境变量覆盖

        // 清理
        std::env::remove_var("BULWARK_TIMEOUT");
        std::env::remove_var("BULWARK_TOKEN_STYLE");
    }

    /// 验证布尔环境变量解析。
    #[test]
    #[serial]
    fn env_boolean_parsing() {
        std::env::set_var("BULWARK_IS_READ_COOKIE", "false");
        std::env::set_var("BULWARK_THROW_ON_NOT_LOGIN", "0");

        let config = BulwarkConfig::default_config();
        let config = DefaultConfigLoader::apply_env_overrides(config).unwrap();

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
        let config = BulwarkConfig::default_config();
        let result = DefaultConfigLoader::apply_env_overrides(config);
        assert!(result.is_err());
        std::env::remove_var("BULWARK_TIMEOUT");
    }

    /// 验证完整加载流程 load()。
    #[test]
    #[serial]
    fn load_full_pipeline() {
        std::env::set_var("BULWARK_TOKEN_NAME", "custom_token");
        let toml_str = r#"timeout = 3600"#;
        let config = DefaultConfigLoader::load(toml_str).unwrap();
        assert_eq!(config.token_name, "custom_token"); // 环境变量
        assert_eq!(config.timeout, 3600); // toml
        assert_eq!(config.token_style, "uuid"); // 默认
        std::env::remove_var("BULWARK_TOKEN_NAME");
    }

    // ========================================================================
    // 热更新测试（spec Requirement: 配置热更新）
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

        // 验证配置未被修改
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
            token_style: "uuid".to_string(),
            throw_on_not_login: true,
            cookie_secure: true,
            cookie_same_site: "Lax".to_string(),
            jwt_algorithm: "HS256".to_string(),
            jwt_secret: String::new(),
            sign_window_seconds: 300,
            sso_ticket_ttl_seconds: 60,
            tenant_isolation: TenantIsolationConfig::default(),
            watcher: None,
        };
        assert!(config.update(|c| c.timeout = 999).is_ok());
        assert!(config.watch().is_none());
    }

    // ========================================================================
    // 序列化测试（spec Requirement: 配置序列化）
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
    // parse_bool 辅助函数测试
    // ========================================================================

    #[test]
    fn parse_bool_accepts_various_formats() {
        assert!(parse_bool("true").unwrap());
        assert!(parse_bool("TRUE").unwrap());
        assert!(parse_bool("1").unwrap());
        assert!(parse_bool("yes").unwrap());
        assert!(parse_bool("on").unwrap());
        assert!(!parse_bool("false").unwrap());
        assert!(!parse_bool("0").unwrap());
        assert!(!parse_bool("no").unwrap());
        assert!(!parse_bool("off").unwrap());
    }

    #[test]
    fn parse_bool_rejects_invalid() {
        assert!(parse_bool("maybe").is_err());
        assert!(parse_bool("").is_err());
    }

    // ========================================================================
    // 环境变量覆盖错误路径补充测试
    // ========================================================================

    /// 验证 BULWARK_IS_READ_COOKIE 非法布尔值时 apply_env_overrides 抛错。
    ///
    /// 覆盖 `apply_env_overrides` 中 `parse_bool(&v)?` 错误路径（IS_READ_COOKIE 分支）。
    #[test]
    #[serial]
    fn env_invalid_is_read_cookie_errors() {
        std::env::set_var("BULWARK_IS_READ_COOKIE", "maybe");
        let config = BulwarkConfig::default_config();
        let result = DefaultConfigLoader::apply_env_overrides(config);
        assert!(result.is_err(), "非法布尔值应导致 apply_env_overrides 失败");
        assert!(
            matches!(result, Err(BulwarkError::Config(ref msg)) if msg.contains("invalid boolean")),
            "应返回 'invalid boolean' 错误，实际: {:?}",
            result
        );
        std::env::remove_var("BULWARK_IS_READ_COOKIE");
    }

    /// 验证 BULWARK_IS_READ_HEADER 非法布尔值时 apply_env_overrides 抛错。
    ///
    /// 覆盖 `apply_env_overrides` 中 `parse_bool(&v)?` 错误路径（IS_READ_HEADER 分支）。
    #[test]
    #[serial]
    fn env_invalid_is_read_header_errors() {
        std::env::set_var("BULWARK_IS_READ_HEADER", "yesno");
        let config = BulwarkConfig::default_config();
        let result = DefaultConfigLoader::apply_env_overrides(config);
        assert!(result.is_err());
        assert!(matches!(result, Err(BulwarkError::Config(_))));
        std::env::remove_var("BULWARK_IS_READ_HEADER");
    }

    /// 验证 BULWARK_IS_WRITE_HEADER 非法布尔值时 apply_env_overrides 抛错。
    ///
    /// 覆盖 `apply_env_overrides` 中 `parse_bool(&v)?` 错误路径（IS_WRITE_HEADER 分支）。
    #[test]
    #[serial]
    fn env_invalid_is_write_header_errors() {
        std::env::set_var("BULWARK_IS_WRITE_HEADER", "unknown");
        let config = BulwarkConfig::default_config();
        let result = DefaultConfigLoader::apply_env_overrides(config);
        assert!(result.is_err());
        assert!(matches!(result, Err(BulwarkError::Config(_))));
        std::env::remove_var("BULWARK_IS_WRITE_HEADER");
    }

    /// 验证 BULWARK_THROW_ON_NOT_LOGIN 非法布尔值时 apply_env_overrides 抛错。
    ///
    /// 覆盖 `apply_env_overrides` 中 `parse_bool(&v)?` 错误路径（THROW_ON_NOT_LOGIN 分支）。
    #[test]
    #[serial]
    fn env_invalid_throw_on_not_login_errors() {
        std::env::set_var("BULWARK_THROW_ON_NOT_LOGIN", "yes_no");
        let config = BulwarkConfig::default_config();
        let result = DefaultConfigLoader::apply_env_overrides(config);
        assert!(result.is_err());
        assert!(matches!(result, Err(BulwarkError::Config(_))));
        std::env::remove_var("BULWARK_THROW_ON_NOT_LOGIN");
    }

    /// 验证 BULWARK_ACTIVE_TIMEOUT 非数字时 apply_env_overrides 抛错。
    ///
    /// 覆盖 `apply_env_overrides` 中 ACTIVE_TIMEOUT 分支的 parse 错误路径。
    #[test]
    #[serial]
    fn env_invalid_active_timeout_errors() {
        std::env::set_var("BULWARK_ACTIVE_TIMEOUT", "not-a-number");
        let config = BulwarkConfig::default_config();
        let result = DefaultConfigLoader::apply_env_overrides(config);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(BulwarkError::Config(ref msg)) if msg.contains("ACTIVE_TIMEOUT invalid")),
            "应包含 'ACTIVE_TIMEOUT invalid'，实际: {:?}",
            result
        );
        std::env::remove_var("BULWARK_ACTIVE_TIMEOUT");
    }

    /// 验证 BULWARK_TOKEN_STYLE 非法值导致 apply_env_overrides 校验失败。
    ///
    /// 覆盖 `apply_env_overrides` 末尾 `config.validate()?` 错误路径
    /// （环境变量覆盖后配置校验未通过）。
    #[test]
    #[serial]
    fn env_invalid_token_style_fails_validation() {
        std::env::set_var("BULWARK_TOKEN_STYLE", "unknown_style");
        let config = BulwarkConfig::default_config();
        let result = DefaultConfigLoader::apply_env_overrides(config);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(BulwarkError::Config(ref msg)) if msg.contains("unknown token_style")),
            "应返回 'unknown token_style' 错误，实际: {:?}",
            result
        );
        std::env::remove_var("BULWARK_TOKEN_STYLE");
    }

    /// 验证 BULWARK_TIMEOUT 负值导致 apply_env_overrides 校验失败。
    ///
    /// 覆盖 `apply_env_overrides` 末尾 `config.validate()?` 错误路径
    /// （环境变量覆盖后 timeout 非法）。
    #[test]
    #[serial]
    fn env_negative_timeout_fails_validation() {
        std::env::set_var("BULWARK_TIMEOUT", "-100");
        let config = BulwarkConfig::default_config();
        let result = DefaultConfigLoader::apply_env_overrides(config);
        assert!(result.is_err());
        assert!(
            matches!(result, Err(BulwarkError::Config(ref msg)) if msg.contains("timeout must be positive")),
            "应返回 'timeout must be positive' 错误，实际: {:?}",
            result
        );
        std::env::remove_var("BULWARK_TIMEOUT");
    }

    /// 验证通过 `ConfigLoader` trait 调用 `load_from_toml_str` 与具体类型一致。
    ///
    /// 覆盖 trait 方法签名行（确保通过 trait dispatch 也能调用）。
    #[test]
    fn trait_dispatch_load_from_toml_str() {
        let config: BulwarkConfig = <DefaultConfigLoader as ConfigLoader>::load_from_toml_str("")
            .expect("通过 trait 调用应与具体类型行为一致");
        assert_eq!(config.token_style, "uuid");
        assert_eq!(config.timeout, DEFAULT_TIMEOUT);
    }

    /// 验证通过 `ConfigLoader` trait 调用 `apply_env_overrides` 与具体类型一致。
    ///
    /// 覆盖 trait 方法签名行（确保通过 trait dispatch 也能调用）。
    #[test]
    #[serial]
    fn trait_dispatch_apply_env_overrides() {
        let config = BulwarkConfig::default_config();
        let result: BulwarkResult<BulwarkConfig> =
            <DefaultConfigLoader as ConfigLoader>::apply_env_overrides(config);
        assert!(result.is_ok());
    }

    /// 验证通过 `ConfigLoader` trait 调用 `load` 完整流程。
    ///
    /// 覆盖 trait 默认方法 `load` 的实现（调用 load_from_toml_str + apply_env_overrides）。
    #[test]
    #[serial_test::serial]
    fn trait_dispatch_load_full_pipeline() {
        let config: BulwarkConfig =
            <DefaultConfigLoader as ConfigLoader>::load("").expect("通过 trait 调用 load 应成功");
        assert_eq!(config.token_style, "uuid");
    }

    // ========================================================================
    // 0.2.0 新增字段环境变量覆盖测试（依据 spec protocol-jwt / protocol-sign / protocol-sso）
    // ========================================================================

    /// 验证 `BULWARK_JWT_ALGORITHM` 环境变量覆盖 jwt_algorithm 字段。
    #[test]
    #[serial]
    fn env_overrides_jwt_algorithm() {
        std::env::set_var(format!("{}JWT_ALGORITHM", ENV_PREFIX), "HS512");
        let config = BulwarkConfig::default_config();
        let config = DefaultConfigLoader::apply_env_overrides(config).unwrap();
        assert_eq!(config.jwt_algorithm, "HS512");
        std::env::remove_var(format!("{}JWT_ALGORITHM", ENV_PREFIX));
    }

    /// 验证 `BULWARK_SIGN_WINDOW_SECONDS` 环境变量覆盖 sign_window_seconds 字段。
    #[test]
    #[serial]
    fn env_overrides_sign_window_seconds() {
        std::env::set_var(format!("{}SIGN_WINDOW_SECONDS", ENV_PREFIX), "600");
        let config = BulwarkConfig::default_config();
        let config = DefaultConfigLoader::apply_env_overrides(config).unwrap();
        assert_eq!(config.sign_window_seconds, 600);
        std::env::remove_var(format!("{}SIGN_WINDOW_SECONDS", ENV_PREFIX));
    }

    /// 验证 `BULWARK_SSO_TICKET_TTL_SECONDS` 环境变量覆盖 sso_ticket_ttl_seconds 字段。
    #[test]
    #[serial]
    fn env_overrides_sso_ticket_ttl_seconds() {
        std::env::set_var(format!("{}SSO_TICKET_TTL_SECONDS", ENV_PREFIX), "120");
        let config = BulwarkConfig::default_config();
        let config = DefaultConfigLoader::apply_env_overrides(config).unwrap();
        assert_eq!(config.sso_ticket_ttl_seconds, 120);
        std::env::remove_var(format!("{}SSO_TICKET_TTL_SECONDS", ENV_PREFIX));
    }

    /// 验证 `BULWARK_SIGN_WINDOW_SECONDS` 非数字时 apply_env_overrides 抛错。
    #[test]
    #[serial]
    fn env_overrides_sign_window_seconds_invalid() {
        std::env::set_var(format!("{}SIGN_WINDOW_SECONDS", ENV_PREFIX), "not-a-number");
        let config = BulwarkConfig::default_config();
        let result = DefaultConfigLoader::apply_env_overrides(config);
        assert!(
            result.is_err(),
            "非数字 SIGN_WINDOW_SECONDS 应导致 apply_env_overrides 失败"
        );
        std::env::remove_var(format!("{}SIGN_WINDOW_SECONDS", ENV_PREFIX));
    }

    /// 验证 `BULWARK_SSO_TICKET_TTL_SECONDS` 非数字时 apply_env_overrides 抛错。
    #[test]
    #[serial]
    fn env_overrides_sso_ticket_ttl_seconds_invalid() {
        std::env::set_var(format!("{}SSO_TICKET_TTL_SECONDS", ENV_PREFIX), "abc");
        let config = BulwarkConfig::default_config();
        let result = DefaultConfigLoader::apply_env_overrides(config);
        assert!(
            result.is_err(),
            "非数字 SSO_TICKET_TTL_SECONDS 应导致 apply_env_overrides 失败"
        );
        std::env::remove_var(format!("{}SSO_TICKET_TTL_SECONDS", ENV_PREFIX));
    }

    // ========================================================================
    // tenant_isolation 配置段测试（v0.5.0 新增，依据 spec tenant-isolation R-006）
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
}
