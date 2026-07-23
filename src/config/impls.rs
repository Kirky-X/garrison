//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `GarrisonConfig` 与 `TenantIsolationConfig` 的实现块。
//!
//! 本文件从 `mod.rs` 迁移而来，遵循 mod-crate-hardening（规则 25）：
//! `mod.rs` 仅保留 trait 定义、pub struct/enum、pub type alias、pub use、mod 声明。

use super::source::TomlContentSource;
use super::*;
use crate::error::{GarrisonError, GarrisonResult};
use confers::config::ConfigBuilder;
use std::io::Read;
use std::path::Path;

impl Default for TenantIsolationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            resolver: TenantResolverKind::Header,
        }
    }
}

impl GarrisonConfig {
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
            is_read_body: DEFAULT_IS_READ_BODY,
            is_write_header: true,
            is_write_cookie: false,
            token_style: "uuid".to_string(),
            throw_on_not_login: true,
            cookie_secure: DEFAULT_COOKIE_SECURE,
            cookie_same_site: DEFAULT_COOKIE_SAME_SITE.to_string(),
            jwt_algorithm: DEFAULT_JWT_ALGORITHM.to_string(),
            jwt_secret: default_jwt_secret(),
            sign_window_seconds: DEFAULT_SIGN_WINDOW_SECONDS,
            sso_ticket_ttl_seconds: DEFAULT_SSO_TICKET_TTL_SECONDS,
            remember_me_enabled: false,
            remember_me_timeout: REMEMBER_ME_DEFAULT_TIMEOUT,
            session_hover_timeout: DEFAULT_SESSION_HOVER_TIMEOUT,
            frontend_separation: DEFAULT_FRONTEND_SEPARATION,
            auto_renewal_threshold: DEFAULT_AUTO_RENEWAL_THRESHOLD,
            token_map_cleanup_interval_secs: DEFAULT_TOKEN_MAP_CLEANUP_INTERVAL,
            #[cfg(feature = "three-tier-cache")]
            l1_cache_ttl_secs: DEFAULT_L1_CACHE_TTL_SECS,
            #[cfg(feature = "three-tier-cache")]
            l2_cache_ttl_secs: DEFAULT_L2_CACHE_TTL_SECS,
            #[cfg(feature = "three-tier-cache")]
            l1_cache_capacity: DEFAULT_L1_CACHE_CAPACITY,
            #[cfg(feature = "login-token-map-persistence")]
            login_token_map_persist_interval_secs: DEFAULT_LOGIN_TOKEN_MAP_PERSIST_INTERVAL_SECS,
            #[cfg(feature = "anonymous-session")]
            anon_session_timeout: DEFAULT_ANON_SESSION_TIMEOUT_SECS,
            is_concurrent: DEFAULT_IS_CONCURRENT,
            is_share: DEFAULT_IS_SHARE,
            max_login_count: DEFAULT_MAX_LOGIN_COUNT,
            device_binding_mode: DEFAULT_DEVICE_BINDING_MODE.to_string(),
            replaced_login_exit_mode: ReplacedLoginExitMode::default(),
            overflow_logout_mode: OverflowLogoutMode::default(),
            audit_mask_mode: AuditMaskMode::default(),
            tenant_isolation: TenantIsolationConfig::default(),
            #[cfg(feature = "web-waf")]
            waf_config: WafConfig::default(),
            #[cfg(feature = "web-cors")]
            cors_config: CorsConfig::default(),
            #[cfg(feature = "web-csrf")]
            csrf_config: CsrfConfig::default(),
            #[cfg(feature = "rate-limit-redis")]
            rate_limit_backend: RateLimitBackend::default(),
            #[cfg(feature = "firewall-waf")]
            waf_enabled_hooks: Vec::new(),
            #[cfg(feature = "firewall-waf")]
            waf_white_paths: Vec::new(),
            #[cfg(feature = "firewall-waf")]
            waf_black_paths: Vec::new(),
            #[cfg(feature = "firewall-waf")]
            waf_allowed_hosts: Vec::new(),
            #[cfg(feature = "firewall-waf")]
            waf_allowed_methods: Vec::new(),
            #[cfg(feature = "firewall-waf")]
            waf_banned_headers: Vec::new(),
            #[cfg(feature = "firewall-waf")]
            waf_banned_params: Vec::new(),
            #[cfg(feature = "sms-rate-limit")]
            sms_hourly_limit: 5,
            #[cfg(feature = "sms-rate-limit")]
            sms_daily_limit: 10,
            #[cfg(feature = "sms-rate-limit")]
            sms_verify_max_attempts: 3,
            #[cfg(feature = "sms-rate-limit")]
            sms_unverified_threshold: 3,
            #[cfg(feature = "anomalous-detector-dual")]
            anomalous_analyzer_interval_secs: DEFAULT_ANOMALOUS_ANALYZER_INTERVAL_SECS,
            #[cfg(feature = "anomalous-detector-dual")]
            anomalous_analyzer_burst_threshold: DEFAULT_ANOMALOUS_BURST_THRESHOLD,
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
    /// 合并后的 `GarrisonConfig`（已附加 watcher 并通过 `validate()`）。
    ///
    /// # 错误
    /// - `GarrisonError::Config`：文件解析失败、环境变量非法或配置校验未通过。
    ///
    /// # Security
    ///
    /// `toml_path` 必须来自可信源（命令行参数 / 硬编码 / 受控环境变量），
    /// 不可直接传入用户输入。本函数已实现以下 7 项防护：
    /// 1. 空路径拒绝（`is_empty()` 检查）
    /// 2. 路径遍历检测（拒绝 `..` / `Component::ParentDir`）
    /// 3. `File::open + file.metadata()` 复用 fd，消除 TOCTOU 和符号链接攻击窗口
    /// 4. 特殊文件拒绝（字符设备/FIFO/目录，通过 `is_file()`）
    /// 5. 文件大小限制（10MB 上限，防 DoS）
    /// 6. `take(MAX+1)` I/O 层强制限制读取字节数（防 TOCTOU）
    /// 7. 错误消息仅含 `file_name()`，不泄露完整路径
    ///
    /// 但不对绝对路径做白名单限制，调用方需自行确保路径可信。
    pub fn load(toml_path: Option<&str>) -> GarrisonResult<Self> {
        #[cfg_attr(not(feature = "rate-limit-redis"), allow(unused_mut))]
        let mut env_values = collect_env_vars(ENV_PREFIX);

        // `GARRISON_RATE_LIMIT_BACKEND=redis` 会被 confers 通用收集（key "rate_limit_backend"
        // 匹配顶层字段），但 "redis" 无法反序列化为 `Redis { redis_url }`（缺子字段），
        // 会导致 build 失败。故从 confers memory source 中移除，由下方显式逻辑处理。
        #[cfg(feature = "rate-limit-redis")]
        {
            env_values.remove("rate_limit_backend");
        }

        let mut builder = ConfigBuilder::<Self>::new()
            .default("token_name", ConfigValue::string(DEFAULT_TOKEN_NAME))
            .default("timeout", ConfigValue::integer(DEFAULT_TIMEOUT))
            .default(
                "active_timeout",
                ConfigValue::integer(DEFAULT_ACTIVE_TIMEOUT),
            )
            .default("is_read_cookie", ConfigValue::bool(true))
            .default("is_read_header", ConfigValue::bool(true))
            .default("is_read_body", ConfigValue::bool(DEFAULT_IS_READ_BODY))
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
            .default(
                "token_map_cleanup_interval_secs",
                ConfigValue::integer(DEFAULT_TOKEN_MAP_CLEANUP_INTERVAL),
            )
            .default("is_concurrent", ConfigValue::bool(DEFAULT_IS_CONCURRENT))
            .default("is_share", ConfigValue::bool(DEFAULT_IS_SHARE))
            .default(
                "max_login_count",
                ConfigValue::uint(DEFAULT_MAX_LOGIN_COUNT as u64),
            )
            .default(
                "device_binding_mode",
                ConfigValue::string(DEFAULT_DEVICE_BINDING_MODE),
            )
            .default(
                "replaced_login_exit_mode",
                ConfigValue::string(DEFAULT_REPLACED_LOGIN_EXIT_MODE),
            )
            .default(
                "overflow_logout_mode",
                ConfigValue::string(DEFAULT_OVERFLOW_LOGOUT_MODE),
            )
            .default("audit_mask_mode", ConfigValue::string("partial"));

        #[cfg(feature = "login-token-map-persistence")]
        {
            builder = builder.default(
                "login_token_map_persist_interval_secs",
                ConfigValue::uint(DEFAULT_LOGIN_TOKEN_MAP_PERSIST_INTERVAL_SECS),
            );
        }

        #[cfg(feature = "three-tier-cache")]
        {
            builder = builder
                .default(
                    "l1_cache_ttl_secs",
                    ConfigValue::uint(DEFAULT_L1_CACHE_TTL_SECS),
                )
                .default(
                    "l2_cache_ttl_secs",
                    ConfigValue::uint(DEFAULT_L2_CACHE_TTL_SECS),
                )
                .default(
                    "l1_cache_capacity",
                    ConfigValue::uint(DEFAULT_L1_CACHE_CAPACITY),
                );
        }

        #[cfg(feature = "anonymous-session")]
        {
            builder = builder.default(
                "anon_session_timeout",
                ConfigValue::uint(DEFAULT_ANON_SESSION_TIMEOUT_SECS),
            );
        }

        #[cfg(feature = "sms-rate-limit")]
        {
            builder = builder
                .default("sms_hourly_limit", ConfigValue::uint(5))
                .default("sms_daily_limit", ConfigValue::uint(10))
                .default("sms_verify_max_attempts", ConfigValue::uint(3))
                .default("sms_unverified_threshold", ConfigValue::uint(3));
        }

        #[cfg(feature = "anomalous-detector-dual")]
        {
            builder = builder
                .default(
                    "anomalous_analyzer_interval_secs",
                    ConfigValue::uint(DEFAULT_ANOMALOUS_ANALYZER_INTERVAL_SECS),
                )
                .default(
                    "anomalous_analyzer_burst_threshold",
                    ConfigValue::uint(DEFAULT_ANOMALOUS_BURST_THRESHOLD.into()),
                );
        }

        if let Some(path) = toml_path {
            // 修复 Windows CI 失败：confers 0.4.1 的 FileSource 在 check_path_components()
            // 无条件拒绝 Component::Prefix（Windows 驱动器号 C:），allow_absolute_paths()
            // 仅放行 RootDir，无法放行带驱动器号的 Windows 绝对路径。改用 std::fs::read_to_string
            // 读取文件内容，通过自定义 TomlContentSource 注入，绕过路径验证。
            // 使用 confers 公共 API（parse_content + Source trait），跨平台一致行为。
            //
            // 安全防护（安全审查 HIGH-1/MEDIUM-1/MEDIUM-2 + 性能审查 MEDIUM-1）：
            // 1. 空路径拒绝：避免 metadata 返回 ENOENT 时消息不明确
            // 2. 路径遍历检测：拒绝 `..`（Component::ParentDir），防 `../../etc/passwd`。
            //    不检查 `%2e`：fs API 不解码 URL，`%2e%2e` 是字面字符串，不会触发路径遍历。
            // 3. File::open + file.metadata()：复用 fd，消除 TOCTOU 和符号链接攻击窗口
            // 4. is_file() 检查：拒绝字符设备（/dev/zero）、FIFO、目录等特殊文件，防 DoS
            // 5. 文件大小限制：10MB 上限，防 DoS（read_to_string 超大文件耗尽内存）
            // 6. take(MAX+1) 限制：I/O 层强制读取字节数，双重保险
            // 7. 错误消息仅含 file_name()：避免泄露服务器文件系统结构
            if path.is_empty() {
                return Err(GarrisonError::Config("配置文件路径不能为空".to_string()));
            }
            let path_ref = Path::new(path);
            let display_name = || {
                path_ref
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(path)
            };
            if path_ref
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
            {
                return Err(GarrisonError::Config(format!(
                    "配置文件路径包含非法的父目录引用（..）：{}",
                    display_name()
                )));
            }
            let file = std::fs::File::open(path_ref).map_err(|e| {
                GarrisonError::Config(format!("打开配置文件失败 [{}]：{}", display_name(), e))
            })?;
            let metadata = file.metadata().map_err(|e| {
                GarrisonError::Config(format!(
                    "读取配置文件元数据失败 [{}]：{}",
                    display_name(),
                    e
                ))
            })?;
            if !metadata.is_file() {
                return Err(GarrisonError::Config(format!(
                    "配置文件路径不是普通文件 [{}]：{:?}",
                    display_name(),
                    metadata.file_type()
                )));
            }
            const MAX_CONFIG_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10MB
            if metadata.len() > MAX_CONFIG_FILE_SIZE {
                return Err(GarrisonError::Config(format!(
                    "配置文件过大 [{}]：{} bytes，上限 {} bytes",
                    display_name(),
                    metadata.len(),
                    MAX_CONFIG_FILE_SIZE
                )));
            }
            // take(MAX+1) 在 I/O 层强制限制读取字节数，防止 TOCTOU（metadata 后文件被替换为超大文件）
            let mut reader = std::io::BufReader::new(file).take(MAX_CONFIG_FILE_SIZE + 1);
            let mut content = String::with_capacity(metadata.len() as usize);
            reader.read_to_string(&mut content).map_err(|e| {
                GarrisonError::Config(format!("读取配置文件失败 [{}]：{}", display_name(), e))
            })?;
            if content.len() > MAX_CONFIG_FILE_SIZE as usize {
                return Err(GarrisonError::Config(format!(
                    "配置文件实际大小超过上限 [{}]：{} bytes",
                    display_name(),
                    content.len()
                )));
            }
            builder = builder.source(Box::new(
                TomlContentSource::new(content, Some(path_ref.to_path_buf())).with_priority(10),
            ));
        }

        if !env_values.is_empty() {
            builder = builder.memory_priority(50).memory(env_values);
        }

        let config = builder
            .build()
            .map_err(|e| GarrisonError::Config(format!("confers build error: {}", e)))?;

        #[cfg_attr(
            not(any(
                feature = "web-cors",
                feature = "web-csrf",
                feature = "rate-limit-redis"
            )),
            allow(unused_mut)
        )]
        let mut config = config.with_watcher();

        // T039: 环境变量覆盖（spec R-cors-001 / R-csrf-003 / R-redis-ratelimit-004）。
        // confers 通用收集无法处理枚举结构变体，故 CORS/CSRF/RateLimit 的环境变量
        // 由显式逻辑覆盖，优先级最高。
        #[cfg(feature = "web-cors")]
        {
            if let Ok(val) = std::env::var("GARRISON_CORS_ALLOWED_ORIGINS") {
                config.cors_config.allowed_origins = val
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
        }
        #[cfg(feature = "web-csrf")]
        {
            if let Ok(val) = std::env::var("GARRISON_CSRF_ENABLED") {
                config.csrf_config.enabled = val.eq_ignore_ascii_case("true");
            }
        }
        #[cfg(feature = "rate-limit-redis")]
        {
            if let Ok(val) = std::env::var("GARRISON_RATE_LIMIT_BACKEND") {
                match val.to_lowercase().as_str() {
                    "memory" => config.rate_limit_backend = RateLimitBackend::Memory,
                    "redis" => {
                        let redis_url = std::env::var("GARRISON_REDIS_URL").unwrap_or_default();
                        config.rate_limit_backend = RateLimitBackend::Redis { redis_url };
                    },
                    _ => {
                        return Err(GarrisonError::Config(format!(
                            "GARRISON_RATE_LIMIT_BACKEND 不支持的值 '{}'，仅支持 'memory' 或 'redis'",
                            val
                        )));
                    },
                }
            }
            if let Ok(val) = std::env::var("GARRISON_REDIS_URL") {
                if let RateLimitBackend::Redis { redis_url } = &mut config.rate_limit_backend {
                    *redis_url = val;
                }
            }
        }

        config.validate()?;
        Ok(config)
    }

    /// 为配置实例附加 watcher（创建 watch channel）。
    ///
    /// 反序列化后的 `GarrisonConfig` 没有 watcher，调用此方法启用 `watch()` 与 `update()`。
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
    /// - `GarrisonError::Config`：`token_style` 非法（消息含 "unknown token_style"）。
    /// - `GarrisonError::Config`：`timeout` 非正（消息 "timeout must be positive"）。
    /// - `GarrisonError::Config`：`token_style=jwt` 但 `jwt_secret` 为空。
    pub fn validate(&self) -> GarrisonResult<()> {
        if !TOKEN_STYLES.contains(&self.token_style.as_str()) {
            return Err(GarrisonError::Config(format!(
                "unknown token_style: {}",
                self.token_style
            )));
        }
        if self.timeout <= 0 {
            return Err(GarrisonError::Config(
                "timeout must be positive".to_string(),
            ));
        }
        if !COOKIE_SAME_SITE_VALUES.contains(&self.cookie_same_site.as_str()) {
            return Err(GarrisonError::Config(format!(
                "unknown cookie_same_site: {} (expected Lax/Strict/None)",
                self.cookie_same_site
            )));
        }
        // jwt_secret 强度校验（仅当 token_style=jwt，即密钥用于 JWT 签名时）：
        // 防止弱密钥被离线爆破。HS256 需 ≥32 字节、HS384 需 ≥48 字节、HS512 需 ≥64 字节
        // （RFC 7518 §3.2）。jwt_algorithm 必须在白名单内，否则 reject（防拼写错误静默走 32 字节分支）。
        // 注意：jwt_secret 在 simple 风格下被复用为 HMAC 密钥、在 refresh 轮换时也走 jwt 分支，
        // 但仅 token_style=jwt 会用它做可离线爆破的 JWT 签名，故长度校验限定在此分支，
        // 避免误伤 simple 等其他风格。simple 风格下的弱密钥在下面单独 warn。
        if self.token_style == "jwt" {
            let secret_len = self.jwt_secret.as_str().len();
            if secret_len == 0 {
                return Err(GarrisonError::Config(
                    "jwt_secret 不能为空（当 token_style=jwt 时）".to_string(),
                ));
            }
            let min_len = match self.jwt_algorithm.as_str() {
                "HS256" => 32,
                "HS384" => 48,
                "HS512" => 64,
                other => {
                    return Err(GarrisonError::Config(format!(
                        "不支持的 jwt_algorithm: {}（仅支持 HS256/HS384/HS512）",
                        other
                    )))
                },
            };
            if secret_len < min_len {
                return Err(GarrisonError::Config(format!(
                    "jwt_secret 长度不足：{} 算法要求 ≥{} 字节，实际 {} 字节",
                    self.jwt_algorithm, min_len, secret_len
                )));
            }
        } else if self.token_style == "simple" && self.jwt_secret.as_str().len() < 32 {
            // simple 风格下 jwt_secret 被复用为 HMAC 密钥，攻击者拿到一条 HMAC 输出
            // 即可离线爆破短密钥。不强制 reject（避免误伤存量配置），但 warn 提示强化。
            tracing::warn!(
                "jwt_secret 长度 {} < 32 字节，token_style={} 不强制校验，但建议强化以防 HMAC 爆破",
                self.jwt_secret.as_str().len(),
                self.token_style
            );
        }
        if self.remember_me_enabled && self.remember_me_timeout <= self.timeout {
            return Err(GarrisonError::Config(format!(
                "remember_me_timeout ({}) must be greater than timeout ({}) when remember_me_enabled is true",
                self.remember_me_timeout, self.timeout
            )));
        }
        if !self.remember_me_enabled && self.remember_me_timeout <= 0 {
            return Err(GarrisonError::Config(format!(
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
            return Err(GarrisonError::Config(format!(
                "auto_renewal_threshold must be -1 or 0-100, got: {}",
                self.auto_renewal_threshold
            )));
        }
        if self.is_share && !self.is_concurrent {
            return Err(GarrisonError::Config(
                "is_share=true requires is_concurrent=true".to_string(),
            ));
        }
        if !DEVICE_BINDING_MODES.contains(&self.device_binding_mode.as_str()) {
            return Err(GarrisonError::Config(format!(
                "unknown device_binding_mode: {} (expected strict/loose/disabled)",
                self.device_binding_mode
            )));
        }
        #[cfg(feature = "anonymous-session")]
        if self.anon_session_timeout == 0 {
            return Err(GarrisonError::Config(
                "anon_session_timeout 必须 > 0".to_string(),
            ));
        }
        #[cfg(feature = "three-tier-cache")]
        {
            if self.l1_cache_ttl_secs == 0 {
                return Err(GarrisonError::Config(
                    "l1_cache_ttl_secs 必须 > 0".to_string(),
                ));
            }
            if self.l2_cache_ttl_secs == 0 {
                return Err(GarrisonError::Config(
                    "l2_cache_ttl_secs 必须 > 0".to_string(),
                ));
            }
            if self.l1_cache_capacity == 0 {
                return Err(GarrisonError::Config(
                    "l1_cache_capacity 必须 > 0".to_string(),
                ));
            }
        }
        #[cfg(feature = "rate-limit-redis")]
        {
            if let RateLimitBackend::Redis { redis_url } = &self.rate_limit_backend {
                if redis_url.is_empty() {
                    return Err(GarrisonError::Config(
                        "rate_limit_backend=Redis 时 redis_url 不能为空".to_string(),
                    ));
                }
            }
        }
        #[cfg(feature = "firewall-waf")]
        {
            for method in &self.waf_allowed_methods {
                if method != &method.to_uppercase() {
                    return Err(GarrisonError::Config(format!(
                        "waf_allowed_methods 中的方法必须为大写，实际: {}",
                        method
                    )));
                }
            }
        }
        #[cfg(feature = "sms-rate-limit")]
        {
            if self.sms_hourly_limit == 0 {
                return Err(GarrisonError::Config(
                    "sms_hourly_limit 必须大于 0".to_string(),
                ));
            }
            if self.sms_daily_limit < self.sms_hourly_limit {
                return Err(GarrisonError::Config(
                    "sms_daily_limit 必须 >= sms_hourly_limit".to_string(),
                ));
            }
            if self.sms_verify_max_attempts == 0 {
                return Err(GarrisonError::Config(
                    "sms_verify_max_attempts 必须大于 0".to_string(),
                ));
            }
            if self.sms_unverified_threshold == 0 {
                return Err(GarrisonError::Config(
                    "sms_unverified_threshold 必须大于 0".to_string(),
                ));
            }
        }
        #[cfg(feature = "anomalous-detector-dual")]
        {
            if self.anomalous_analyzer_interval_secs < 60 {
                return Err(GarrisonError::Config(
                    "anomalous_analyzer_interval_secs 必须 >= 60".to_string(),
                ));
            }
            if self.anomalous_analyzer_burst_threshold == 0 {
                return Err(GarrisonError::Config(
                    "anomalous_analyzer_burst_threshold 必须大于 0".to_string(),
                ));
            }
        }
        Ok(())
    }

    /// 订阅配置变更。
    ///
    /// 返回 `watch::Receiver<GarrisonConfig>`，调用 `rx.borrow_and_update()` 获取最新配置。
    /// 若实例未调用 `with_watcher()`，返回 `None`。
    ///
    /// # 返回
    /// - `Some(receiver)`：成功订阅配置变更通道，后续可通过 receiver 接收 `update()` 广播的新配置。
    /// - `None`：实例未通过 `with_watcher()` 启用 watcher。
    pub fn watch(&self) -> Option<watch::Receiver<GarrisonConfig>> {
        self.watcher.as_ref().map(|tx| tx.subscribe())
    }

    /// 闭包式更新配置并广播变更。
    ///
    /// ```ignore
    /// config.update(|c| c.timeout = 3600)?;
    /// ```
    ///
    /// # 参数
    /// - `f`: 接收 `&mut GarrisonConfig` 的闭包，在闭包内修改字段值。
    ///
    /// # 返回
    /// 更新并广播成功返回 `Ok(())`；若实例未启用 watcher，亦返回 `Ok(())`（no-op）。
    ///
    /// # 错误
    /// - `GarrisonError::Config`：闭包修改后的配置未通过 `validate()`（如非法 `token_style` 或非正 `timeout`）。
    /// - `GarrisonError::Config`：watcher 已关闭（消息 "config watcher closed"）。
    ///
    /// # 行为
    /// 1. 从 watcher 读取当前配置
    /// 2. 应用闭包修改
    /// 3. 校验新配置
    /// 4. 广播新配置给所有订阅者
    ///
    /// 若实例未调用 `with_watcher()`，此方法为 no-op。
    pub fn update<F: FnOnce(&mut GarrisonConfig)>(&self, f: F) -> GarrisonResult<()> {
        let Some(sender) = &self.watcher else {
            return Ok(());
        };
        let mut new_config = sender.borrow().clone();
        f(&mut new_config);
        new_config.validate()?;
        sender
            .send(new_config)
            .map_err(|_| GarrisonError::Config("config watcher closed".to_string()))?;
        Ok(())
    }
}

impl Default for GarrisonConfig {
    fn default() -> Self {
        Self::default_config()
    }
}
