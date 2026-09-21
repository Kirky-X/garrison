// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `GarrisonConfig` 与 `TenantIsolationConfig` 的实现块。
//!
//! 本文件从 `mod.rs` 迁移而来（mod/crate 接口隔离）：
//! `mod.rs` 仅保留 trait 定义、pub struct/enum、pub type alias、pub use、mod 声明。

use super::*;
use crate::error::{GarrisonError, GarrisonResult};
use crate::loc;
use confers::config::ConfigBuilder;

impl Default for TenantIsolationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            resolver: TenantResolverKind::Header,
        }
    }
}

impl Default for PasswordHasherConfig {
    fn default() -> Self {
        Self {
            algorithm: "argon2id".to_string(),
            argon2_m_cost: ARGON2_MIN_M_COST,
            argon2_t_cost: 2,
            argon2_p_cost: 1,
            bcrypt_cost: 12,
            allow_weak_argon2_params: false,
        }
    }
}

impl PasswordHasherConfig {
    /// 按本配置段构造密码哈希器（`account-credential` feature）。
    ///
    /// 返回 `Arc<dyn PasswordHasher>`，可直接传入 `with_password_hasher`。
    /// 校验规则与 `validate_core` 一致（algorithm 白名单 + 参数区间），非法配置
    /// 返回 `Err(GarrisonError::Config)`（fail-fast，与 `validate()` 同语义）。
    ///
    /// 仅影响**新哈希**参数；verify 路径由 `PasswordVerifier` 按哈希前缀自动识别，
    /// 与本配置无关。
    #[cfg(feature = "account-credential")]
    pub fn build_hasher(
        &self,
    ) -> GarrisonResult<std::sync::Arc<dyn crate::account::credential::PasswordHasher>> {
        match self.algorithm.as_str() {
            "argon2id" => {
                if self.argon2_t_cost == 0 || self.argon2_p_cost == 0 {
                    return Err(GarrisonError::Config(
                        "config-password-hash-argon2-param-invalid::".to_string(),
                    ));
                }
                Ok(std::sync::Arc::new(
                    crate::account::credential::password::Argon2Hasher::with_params(
                        self.argon2_m_cost,
                        self.argon2_t_cost,
                        self.argon2_p_cost,
                    ),
                ))
            },
            "bcrypt" => Ok(std::sync::Arc::new(
                crate::account::credential::password::BcryptHasher::with_cost(self.bcrypt_cost),
            )),
            other => Err(GarrisonError::Config(format!(
                "config-password-hash-algorithm-unsupported::{}",
                other
            ))),
        }
    }
}

// 手动 Debug 实现（非 derive）：
// GarrisonConfig 含 `jwt_secret`（`Zeroizing<String>` 的 Debug 是透明的），
// derive(Debug) 会把密钥明文打印进日志。此处借 derived Serialize 输出完整字段映射
// （新增字段自动纳入，不会漏），并将 `jwt_secret` 覆写为 `"<redacted>"`。
impl std::fmt::Debug for GarrisonConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut value = match serde_json::to_value(self) {
            Ok(v) => v,
            Err(_) => serde_json::json!({
                "token_name": self.token_name,
                "token_style": self.token_style,
                "timeout": self.timeout,
            }),
        };
        if let serde_json::Value::Object(ref mut map) = value {
            map.insert(
                "jwt_secret".to_string(),
                serde_json::Value::String("<redacted>".to_string()),
            );
            // 非对称私钥 PEM 脱敏（与 jwt_secret 同等安全等级）
            for key in [
                "jwt_rsa_private_key_pem",
                "jwt_ec_private_key_pem",
                "jwt_ed_private_key_pem",
            ] {
                map.insert(
                    key.to_string(),
                    serde_json::Value::String("<redacted>".to_string()),
                );
            }
        }
        f.write_str("GarrisonConfig ")?;
        std::fmt::Debug::fmt(&value, f)
    }
}

impl GarrisonConfig {
    /// 创建符合 spec 的默认配置实例。
    ///
    /// Scenario: 代码默认值生效：
    /// - token_style = "uuid"
    /// - timeout = 2592000（30 天）
    /// - throw_on_not_login = true
    ///
    /// # 校验语义（安全默认）
    ///
    /// 本方法**不调用 `validate()`**：返回的是未经校验的原始默认值，
    /// 允许调用方在运行前逐字段改写（如测试把 `timeout` 置为非法值后再断言
    /// `validate()` 失败）。生产入口 `GarrisonConfig::load()` 与
    /// `GarrisonManagerBuilder::build()` 均会调用 `validate()`；
    /// 直接以 `default_config()` 驱动生产时，调用方必须在启动前自行调用
    /// `config.validate()`（fail-fast，避免非法配置延迟到请求路径才暴露）。
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
            jwt_rsa_private_key_pem: None,
            jwt_ec_private_key_pem: None,
            jwt_ed_private_key_pem: None,
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
            #[cfg(feature = "session-extra")]
            login_token_map_persist_interval_secs: DEFAULT_LOGIN_TOKEN_MAP_PERSIST_INTERVAL_SECS,
            #[cfg(feature = "session-extra")]
            anon_session_timeout: DEFAULT_ANON_SESSION_TIMEOUT_SECS,
            is_concurrent: DEFAULT_IS_CONCURRENT,
            is_share: DEFAULT_IS_SHARE,
            max_login_count: DEFAULT_MAX_LOGIN_COUNT,
            device_binding_mode: DEFAULT_DEVICE_BINDING_MODE.to_string(),
            replaced_login_exit_mode: ReplacedLoginExitMode::default(),
            overflow_logout_mode: OverflowLogoutMode::default(),
            #[cfg(feature = "session-hijack-detection")]
            session_hijack_mode: SessionHijackMode::default(),
            enable_jwt_revocation: false,
            allow_stateless_jwt_no_revocation: false,
            audit_mask_mode: AuditMaskMode::default(),
            tenant_isolation: TenantIsolationConfig::default(),
            password_hasher: PasswordHasherConfig::default(),
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
            #[cfg(feature = "email-verification")]
            email_hourly_limit: 5,
            #[cfg(feature = "email-verification")]
            email_daily_limit: 10,
            #[cfg(feature = "email-verification")]
            email_verify_max_attempts: 3,
            #[cfg(feature = "email-verification")]
            email_unverified_threshold: 3,
            #[cfg(feature = "email-verification")]
            email_code_ttl: 600,
            #[cfg(feature = "anomalous-detector-dual")]
            anomalous_analyzer_interval_secs: DEFAULT_ANOMALOUS_ANALYZER_INTERVAL_SECS,
            #[cfg(feature = "anomalous-detector-dual")]
            anomalous_analyzer_burst_threshold: DEFAULT_ANOMALOUS_BURST_THRESHOLD,
            #[cfg(feature = "credit-metering")]
            credit: None,
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
        // 环境变量注入（自研库吸收）：confers EnvSource 替代手写
        // collect_env_vars / infer_config_value。
        // separator("__") 与原手写映射一致——仅双下划线折叠为嵌套路径，
        // 单下划线保留，兼容 ConfigBuilder 的扁平 key 模型。
        //
        // excluded_keys：raw 字符串无法反序列化为目标字段的变量（CORS 逗号
        // 列表 → Vec<String>、Redis 后端 → 枚举变体），由 build() 之后的显式
        // 覆盖逻辑处理（优先级最高）。exclude_keys 为追加语义，可多次调用。
        let env_source = {
            let s = confers::config::EnvSource::with_prefix(ENV_PREFIX).separator("__");
            #[cfg(feature = "rate-limit-redis")]
            let s = s.exclude_keys(["rate_limit_backend"]);
            #[cfg(feature = "web-cors")]
            let s = s.exclude_keys(["cors_allowed_origins"]);
            s
        };

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

        #[cfg(feature = "session-extra")]
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

        #[cfg(feature = "session-extra")]
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

        #[cfg(feature = "email-verification")]
        {
            builder = builder
                .default("email_hourly_limit", ConfigValue::uint(5))
                .default("email_daily_limit", ConfigValue::uint(10))
                .default("email_verify_max_attempts", ConfigValue::uint(3))
                .default("email_unverified_threshold", ConfigValue::uint(3))
                .default("email_code_ttl", ConfigValue::uint(600));
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
            // 文件加载改用 confers FileSource（自研库吸收，删除手写安全加载与
            // Windows 路径 workaround `TomlContentSource`——confers 0.6.0-rc.4 已
            // 放行 Windows 盘符前缀，workaround 的前置条件消失）。安全防护由
            // LoaderConfig 承载：
            // - 路径遍历拒绝（`..`）+ canonicalize/symlink 解析
            // - is_file 特殊文件拒绝（/dev/zero、FIFO → read_to_string DoS）
            // - max_size 10MB + take(max+1) I/O 层双保险（TOCTOU 超大文件）
            // - redact_error_paths：错误只含 file_name，不泄露服务端文件系统结构
            // 空路径仍在此前置拒绝（避免下游 canonicalize 的含糊错误）。
            const MAX_CONFIG_FILE_SIZE: usize = 10 * 1024 * 1024; // 10MB
            if path.is_empty() {
                return Err(GarrisonError::Config(loc!("config-path-empty", "")));
            }
            let file_source = confers::config::FileSource::new(path)
                .with_priority(10)
                .with_loader_config(
                    confers::loader::LoaderConfig::new()
                        .allow_absolute()
                        .max_size(MAX_CONFIG_FILE_SIZE)
                        .redact_error_paths(),
                );
            builder = builder.source(Box::new(file_source));
        }

        builder = builder.source(Box::new(env_source));

        let config = builder.build().map_err(map_confers_build_error)?;

        // 显式环境变量覆盖必须在 `with_watcher()` 之前完成——watch channel
        // 的初值取自 `with_watcher()` 时的配置快照；若先建 watcher 再覆盖字段，
        // `watch()` 订阅者会先收到覆盖前的旧配置，`update()` 亦从旧值起步。
        // 覆盖完成后再统一 `with_watcher()` + `validate()`。
        #[cfg_attr(
            not(any(
                feature = "web-cors",
                feature = "web-csrf",
                feature = "rate-limit-redis"
            )),
            allow(unused_mut)
        )]
        let mut config = config;

        // 环境变量覆盖。
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
                            "config-rate-limit-backend-unsupported::{}",
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

        // watcher 在全部环境变量覆盖完成后附加，保证 watch channel 初值
        // 即最终生效配置（订阅者首次 `borrow_and_update()` 拿到的不是覆盖前的旧值）。
        let config = config.with_watcher();

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
    /// 配置校验分组：
    ///
    /// - `validate_core`：`token_style` / `timeout` / `cookie_same_site` / `password_hasher`
    /// - `validate_jwt_secret`：JWT 密钥强度与算法白名单
    /// - `validate_session_config`：`remember_me` / `auto_renewal` / `is_share`
    /// - `validate_device_binding`：`device_binding_mode`
    /// - feature-gated 校验：`anonymous-session` / `three-tier-cache` / `rate-limit-redis` 等
    ///
    /// # 返回
    /// 校验通过返回 `Ok(())`。
    ///
    /// # 错误
    /// - `GarrisonError::Config`：各字段校验失败时返回对应错误消息。
    pub fn validate(&self) -> GarrisonResult<()> {
        self.validate_core()?;
        self.validate_jwt_secret()?;
        self.validate_session_config()?;
        self.validate_device_binding()?;
        self.validate_feature_gated()
    }

    /// 核心字段校验：`token_style` / `timeout` / `cookie_same_site` / `jwt_algorithm`。
    fn validate_core(&self) -> GarrisonResult<()> {
        if !TOKEN_STYLES.contains(&self.token_style.as_str()) {
            return Err(GarrisonError::Config(format!(
                "config-unknown-token-style::{}",
                self.token_style
            )));
        }
        if self.timeout <= 0 {
            return Err(GarrisonError::Config(
                "config-timeout-must-positive::".to_string(),
            ));
        }
        if !COOKIE_SAME_SITE_VALUES.contains(&self.cookie_same_site.as_str()) {
            return Err(GarrisonError::Config(format!(
                "config-unknown-cookie-same-site::{}",
                self.cookie_same_site
            )));
        }
        // jwt_algorithm 白名单校验移入核心校验，不再仅在 token_style=jwt
        // 时（经 validate_jwt_secret）检查——非 JWT 模式下非法算法（如 "RS256"）此前
        // 会静默通过，待切换 token_style 后才暴露。
        if !JWT_ALGORITHMS.contains(&self.jwt_algorithm.as_str()) {
            // 复用既有 locale 键 `config-jwt-algorithm-unsupported`（en/zh 均有翻译，
            // 且与 validate_jwt_secret 的同场景错误保持一致），不新造未翻译键
            return Err(GarrisonError::Config(format!(
                "config-jwt-algorithm-unsupported::{}",
                self.jwt_algorithm
            )));
        }
        // 非对称算法-密钥类型匹配校验（fail-closed）：
        // - 禁止同时配置两类及以上私钥 PEM（防配置歧义）
        // - 非对称算法必须配套同类型私钥 PEM；HS 系算法禁止配置任何非对称私钥
        let rsa_set = self.jwt_rsa_private_key_pem.is_some();
        let ec_set = self.jwt_ec_private_key_pem.is_some();
        let ed_set = self.jwt_ed_private_key_pem.is_some();
        let configured_keys = rsa_set as u8 + ec_set as u8 + ed_set as u8;
        if configured_keys > 1 {
            return Err(GarrisonError::Config(
                "config-jwt-key-multiple-types::".to_string(),
            ));
        }
        let required_key_set = match self.jwt_algorithm.as_str() {
            "RS256" => Some(rsa_set),
            "ES256" => Some(ec_set),
            "EdDSA" => Some(ed_set),
            _ => None, // HS 系
        };
        if let Some(present) = required_key_set {
            if !present {
                return Err(GarrisonError::Config(format!(
                    "config-jwt-key-missing::{}",
                    self.jwt_algorithm
                )));
            }
        } else if configured_keys > 0 {
            return Err(GarrisonError::Config(format!(
                "config-jwt-key-unexpected-for-hs::{}",
                self.jwt_algorithm
            )));
        }
        // 密码哈希参数校验（fail-closed）：默认即 OWASP 建议档，仅防配置弱化。
        // Argon2id m_cost < 19456 须显式 allow_weak_argon2_params（内存受限部署的
        // 风险接受位，放行时 warn 不静默）；bcrypt cost 限 [10, 15]（OWASP ≥10；
        // >15 单次哈希秒级耗多为误配）。
        self.validate_password_hasher()?;
        Ok(())
    }

    /// `password_hasher` 配置段校验（见 `PasswordHasherConfig` 文档）。
    fn validate_password_hasher(&self) -> GarrisonResult<()> {
        let ph = &self.password_hasher;
        if !PASSWORD_HASH_ALGORITHMS.contains(&ph.algorithm.as_str()) {
            return Err(GarrisonError::Config(format!(
                "config-password-hash-algorithm-unsupported::{}",
                ph.algorithm
            )));
        }
        if ph.algorithm == "argon2id" {
            if ph.argon2_t_cost == 0 || ph.argon2_p_cost == 0 {
                return Err(GarrisonError::Config(
                    "config-password-hash-argon2-param-invalid::".to_string(),
                ));
            }
            if ph.argon2_m_cost < ARGON2_MIN_M_COST {
                if !ph.allow_weak_argon2_params {
                    return Err(GarrisonError::Config(format!(
                        "config-password-hash-argon2-m-below-floor::{} (min {})::{}",
                        ph.argon2_m_cost, ARGON2_MIN_M_COST, ph.algorithm
                    )));
                }
                tracing::warn!(
                    "password_hasher: argon2 m_cost {} < OWASP floor {} KiB — weak params explicitly accepted via allow_weak_argon2_params (memory-constrained deployment?)",
                    ph.argon2_m_cost,
                    ARGON2_MIN_M_COST
                );
            }
        } else if !(BCRYPT_MIN_COST..=BCRYPT_MAX_COST).contains(&ph.bcrypt_cost) {
            return Err(GarrisonError::Config(format!(
                "config-password-hash-bcrypt-cost-out-of-range::{} (allowed {}-{})",
                ph.bcrypt_cost, BCRYPT_MIN_COST, BCRYPT_MAX_COST
            )));
        }
        Ok(())
    }

    /// JWT 密钥强度校验（仅当 `token_style=jwt` 时强制校验，`simple` 时 warn）。
    ///
    /// HS256 需 ≥32 字节、HS384 需 ≥48 字节、HS512 需 ≥64 字节（RFC 7518 §3.2）。
    fn validate_jwt_secret(&self) -> GarrisonResult<()> {
        if self.token_style == "jwt" {
            // 非对称算法：密钥强度由 PEM 决定（JwtHandler 构造期校验），
            // jwt_secret 可留空作占位，跳过对称密钥长度校验
            if matches!(self.jwt_algorithm.as_str(), "RS256" | "ES256" | "EdDSA") {
                return Ok(());
            }
            let secret_len = self.jwt_secret.as_str().len();
            if secret_len == 0 {
                return Err(GarrisonError::Config(
                    "config-jwt-secret-empty::".to_string(),
                ));
            }
            let min_len = match self.jwt_algorithm.as_str() {
                "HS256" => 32,
                "HS384" => 48,
                "HS512" => 64,
                // 非对称算法：密钥强度由 PEM 私钥位长/曲线阶决定（RS256 ≥2048 位
                // 在 JwtHandler 构造期用 pkcs1 精确校验），不做 HMAC 对称长度校验
                "RS256" | "ES256" | "EdDSA" => 0,
                other => {
                    return Err(GarrisonError::Config(format!(
                        "config-jwt-algorithm-unsupported::{}",
                        other
                    )))
                },
            };
            if secret_len < min_len {
                return Err(GarrisonError::Config(format!(
                    "config-jwt-secret-too-short::{} (min {} bytes)::{}",
                    self.jwt_algorithm, min_len, secret_len
                )));
            }
        } else if self.token_style == "simple" && self.jwt_secret.as_str().len() < 32 {
            tracing::warn!(
                "jwt_secret length {} < 32 bytes, token_style={} skips mandatory check, but hardening is recommended against HMAC brute force",
                self.jwt_secret.as_str().len(),
                self.token_style
            );
        }
        Ok(())
    }

    /// 会话配置一致性校验：`remember_me` / `auto_renewal` / `is_share` / `frontend_separation`。
    fn validate_session_config(&self) -> GarrisonResult<()> {
        if self.remember_me_enabled && self.remember_me_timeout <= self.timeout {
            return Err(GarrisonError::Config(format!(
                "config-remember-me-timeout-mismatch::{}::{}",
                self.remember_me_timeout, self.timeout
            )));
        }
        if !self.remember_me_enabled && self.remember_me_timeout <= 0 {
            return Err(GarrisonError::Config(format!(
                "config-remember-me-timeout-positive::{}",
                self.remember_me_timeout
            )));
        }
        if self.frontend_separation {
            tracing::info!(
                "frontend separation mode enabled: token read from Authorization header, no cookie set"
            );
        }
        if self.auto_renewal_threshold != -1 && !(0..=100).contains(&self.auto_renewal_threshold) {
            return Err(GarrisonError::Config(format!(
                "config-auto-renewal-threshold-invalid::{}",
                self.auto_renewal_threshold
            )));
        }
        if self.is_share && !self.is_concurrent {
            return Err(GarrisonError::Config(
                "config-is-share-requires-concurrent::".to_string(),
            ));
        }
        // session_hover_timeout 上界：10 年（315_360_000 秒），防止 saturating_mul 之外的
        // 配置层误用超大值。合法值为 -1（禁用）或 (0, 上界]。
        const MAX_SESSION_HOVER_TIMEOUT_SECS: i64 = 315_360_000;
        if self.session_hover_timeout > MAX_SESSION_HOVER_TIMEOUT_SECS {
            return Err(GarrisonError::Config(format!(
                "config-session-hover-timeout-exceeds::{}::{}",
                self.session_hover_timeout, MAX_SESSION_HOVER_TIMEOUT_SECS
            )));
        }
        Ok(())
    }

    /// 设备绑定模式校验。
    fn validate_device_binding(&self) -> GarrisonResult<()> {
        if !DEVICE_BINDING_MODES.contains(&self.device_binding_mode.as_str()) {
            return Err(GarrisonError::Config(format!(
                "config-unknown-device-binding-mode::{}",
                self.device_binding_mode
            )));
        }
        Ok(())
    }

    /// feature-gated 校验：`anonymous-session` / `three-tier-cache` / `rate-limit-redis` / `firewall-waf` / `sms-rate-limit` / `anomalous-detector-dual`。
    fn validate_feature_gated(&self) -> GarrisonResult<()> {
        #[cfg(feature = "session-extra")]
        if self.anon_session_timeout == 0 {
            return Err(GarrisonError::Config(
                "config-anon-timeout-invalid::".to_string(),
            ));
        }
        #[cfg(feature = "three-tier-cache")]
        {
            if self.l1_cache_ttl_secs == 0 {
                return Err(GarrisonError::Config("config-l1-ttl-invalid".to_string()));
            }
            if self.l2_cache_ttl_secs == 0 {
                return Err(GarrisonError::Config("config-l2-ttl-invalid".to_string()));
            }
            if self.l1_cache_capacity == 0 {
                return Err(GarrisonError::Config(
                    "config-l1-capacity-invalid".to_string(),
                ));
            }
        }
        #[cfg(feature = "rate-limit-redis")]
        {
            if let RateLimitBackend::Redis { redis_url } = &self.rate_limit_backend {
                if redis_url.is_empty() {
                    return Err(GarrisonError::Config(
                        "config-redis-url-empty::".to_string(),
                    ));
                }
            }
        }
        #[cfg(feature = "firewall-waf")]
        {
            for method in &self.waf_allowed_methods {
                if method != &method.to_uppercase() {
                    return Err(GarrisonError::Config(format!(
                        "config-waf-method-case::{}",
                        method
                    )));
                }
            }
        }
        #[cfg(feature = "sms-rate-limit")]
        {
            if self.sms_hourly_limit == 0 {
                return Err(GarrisonError::Config(
                    "config-sms-hourly-invalid::".to_string(),
                ));
            }
            if self.sms_daily_limit < self.sms_hourly_limit {
                return Err(GarrisonError::Config(
                    "config-sms-daily-invalid::".to_string(),
                ));
            }
            if self.sms_verify_max_attempts == 0 {
                return Err(GarrisonError::Config(
                    "config-sms-max-attempts-invalid::".to_string(),
                ));
            }
            if self.sms_unverified_threshold == 0 {
                return Err(GarrisonError::Config(
                    "config-sms-threshold-invalid::".to_string(),
                ));
            }
        }
        #[cfg(feature = "email-verification")]
        {
            if self.email_hourly_limit == 0 {
                return Err(GarrisonError::Config(
                    "config-email-hourly-invalid::".to_string(),
                ));
            }
            if self.email_daily_limit < self.email_hourly_limit {
                return Err(GarrisonError::Config(
                    "config-email-daily-invalid::".to_string(),
                ));
            }
            if self.email_verify_max_attempts == 0 {
                return Err(GarrisonError::Config(
                    "config-email-max-attempts-invalid::".to_string(),
                ));
            }
            if self.email_unverified_threshold == 0 {
                return Err(GarrisonError::Config(
                    "config-email-threshold-invalid::".to_string(),
                ));
            }
            if self.email_code_ttl == 0 {
                return Err(GarrisonError::Config(
                    "config-email-ttl-invalid::".to_string(),
                ));
            }
        }
        #[cfg(feature = "anomalous-detector-dual")]
        {
            if self.anomalous_analyzer_interval_secs < 60 {
                return Err(GarrisonError::Config(
                    "config-anomalous-interval-invalid::".to_string(),
                ));
            }
            if self.anomalous_analyzer_burst_threshold == 0 {
                return Err(GarrisonError::Config(
                    "config-anomalous-burst-invalid::".to_string(),
                ));
            }
        }
        // CORS 配置合法性：credentials 与 wildcard origin 冲突校验
        // （此前 CorsConfig::validate 仅测试调用，生产路径从不校验）
        #[cfg(feature = "web-cors")]
        {
            crate::web::cors::CorsConfig::validate(&self.cors_config)?;
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

/// 将 confers `ConfigError` 映射为 i18n 化的 `GarrisonError::Config`。
///
/// 配置文件加载迁入 confers `FileSource` 后，文件 IO/大小/缺失错误从
/// `ConfigBuilder::build()` 冒出；此映射保持原有 FTL 文案出口：
/// - `FileNotFound` → `config-open-failed`
/// - `SizeLimitExceeded` → `config-too-large`
/// - 其余（解析失败、路径遍历拒绝等）→ 泛化 `config-confers-build-failed`
///   （confers 已启用 `redact_error_paths`，错误不含服务端文件系统结构）
fn map_confers_build_error(e: confers::ConfigError) -> GarrisonError {
    use confers::ConfigError as CE;
    match e {
        CE::FileNotFound { filename, .. } => {
            let name = filename.display().to_string();
            GarrisonError::Config(loc!("config-open-failed", "", ("arg0", name.as_str())))
        },
        CE::SizeLimitExceeded { actual, limit } => {
            let actual_str = actual.to_string();
            let limit_str = limit.to_string();
            GarrisonError::Config(loc!(
                "config-too-large",
                "",
                ("arg0", "config"),
                ("arg1", actual_str.as_str()),
                ("arg2", limit_str.as_str())
            ))
        },
        other => GarrisonError::Config(format!("config-confers-build-failed::{}", other)),
    }
}
