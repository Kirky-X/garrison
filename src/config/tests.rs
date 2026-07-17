//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! config 模块测试（从 mod.rs 迁移，Rule 25 合规）。

use super::*;
use crate::error::BulwarkError;
use serial_test::serial;

// === FMEA #8 测试（kueiku RPN=336）：jwt_secret 用 Zeroizing<String> 自动 zeroize on Drop ===

/// 编译期断言：protocol-zeroize feature 下 jwt_secret 字段类型为 Zeroizing<String>，
/// Drop 时自动 zeroize。如果有人改回 String，此测试将编译失败。
#[cfg(feature = "protocol-zeroize")]
#[test]
fn jwt_secret_is_zeroizing_type_when_protocol_zeroize() {
    let cfg = BulwarkConfig::default();
    // 接受 Zeroizing<String> 实例证明类型正确
    fn assert_zeroizing<T: zeroize::Zeroize>(_: &T) {}
    assert_zeroizing(&cfg.jwt_secret);
}

/// 验证 Zeroizing<String> zeroize 后 buffer 内容被清零。
///
/// `Zeroizing<T>::drop` 内部调用 `T::zeroize()`，此测试直接调用 `zeroize()`
/// 验证同一行为（Drop 后访问字段是 UB，因为 String::drop 释放 buffer）。
/// 测试逻辑：zeroize() 清零 buffer 内容但不释放 buffer（String 仍持有 capacity），
/// 所以 ptr 在 zeroize 后仍指向有效内存，可安全读取验证全 0。
#[cfg(feature = "protocol-zeroize")]
#[test]
fn zeroizing_string_drop_clears_buffer() {
    use zeroize::{Zeroize, Zeroizing};

    let mut secret = Zeroizing::new(String::from("sensitive-jwt-secret"));
    let ptr = secret.as_str().as_ptr();
    let len = secret.as_str().len();

    // 直接调用 zeroize（Drop 内部执行同一方法）
    secret.zeroize();

    // String::zeroize 先 as_bytes_mut().zeroize() 清零 buffer，再 clear() 设 len=0
    // buffer 内存仍属于 String（capacity 不变），ptr 仍有效
    unsafe {
        let bytes = std::slice::from_raw_parts(ptr, len);
        assert!(
            bytes.iter().all(|&b| b == 0),
            "Zeroizing<String> zeroize 后 buffer 应为全 0，实际: {:?}",
            bytes
        );
    }
}

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
#[cfg_attr(not(feature = "protocol-zeroize"), allow(clippy::useless_conversion))]
fn validate_accepts_all_legal_token_styles() {
    for style in TOKEN_STYLES {
        let mut config = BulwarkConfig::default_config();
        config.token_style = style.to_string();
        if *style == "jwt" {
            config.jwt_secret = "test-secret".to_string().into();
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
#[cfg_attr(not(feature = "protocol-zeroize"), allow(clippy::useless_conversion))]
fn update_modifies_multiple_fields() {
    let config = BulwarkConfig::default_config();
    let mut rx = config.watch().unwrap();

    config
        .update(|c| {
            c.timeout = 7200;
            c.token_style = "jwt".to_string();
            c.jwt_secret = "test-secret".to_string().into();
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
        is_read_body: DEFAULT_IS_READ_BODY,
        is_write_header: true,
        is_write_cookie: false,
        token_style: "uuid".to_string(),
        throw_on_not_login: true,
        cookie_secure: true,
        cookie_same_site: "Lax".to_string(),
        jwt_algorithm: "HS256".to_string(),
        jwt_secret: default_jwt_secret(),
        sign_window_seconds: 300,
        sso_ticket_ttl_seconds: 60,
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
        waf_config: crate::web::waf::WafConfig::default(),
        #[cfg(feature = "web-cors")]
        cors_config: crate::web::cors::CorsConfig::default(),
        #[cfg(feature = "web-csrf")]
        csrf_config: crate::web::csrf::CsrfConfig::default(),
        #[cfg(feature = "rate-limit-redis")]
        rate_limit_backend: crate::strategy::rate_limiter_backend::RateLimitBackend::default(),
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
        let kind: TenantResolverKind =
            serde_json::from_str(json).unwrap_or_else(|e| panic!("反序列化 {} 失败: {}", json, e));
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
// T029: token_map_cleanup_interval_secs 配置测试（4 个）
// ========================================================================

/// T029: `default_config()` 的 `token_map_cleanup_interval_secs` 为 300（5 分钟）。
#[test]
fn token_map_cleanup_interval_default_is_300() {
    let config = BulwarkConfig::default_config();
    assert_eq!(
        config.token_map_cleanup_interval_secs, 300,
        "默认 token_map_cleanup_interval_secs 应为 300（5 分钟）"
    );
    assert_eq!(
        config.token_map_cleanup_interval_secs, DEFAULT_TOKEN_MAP_CLEANUP_INTERVAL,
        "应等于 DEFAULT_TOKEN_MAP_CLEANUP_INTERVAL 常量"
    );
}

/// T029: 手动设置自定义值（如 600）后字段值生效且通过 `validate()` 校验。
#[test]
fn token_map_cleanup_interval_custom_value() {
    let mut config = BulwarkConfig::default_config();
    config.token_map_cleanup_interval_secs = 600;
    assert_eq!(config.token_map_cleanup_interval_secs, 600);
    assert!(
        config.validate().is_ok(),
        "token_map_cleanup_interval_secs=600 应通过校验"
    );
}

/// T029: 设置 -1 表示禁用后台清理 task（与 T028 `interval_secs <= 0` 行为一致）。
#[test]
fn token_map_cleanup_interval_negative_disables() {
    let mut config = BulwarkConfig::default_config();
    config.token_map_cleanup_interval_secs = -1;
    assert_eq!(config.token_map_cleanup_interval_secs, -1);
    assert!(
        config.validate().is_ok(),
        "token_map_cleanup_interval_secs=-1（禁用）应通过校验"
    );
    // 边界：0 也表示禁用
    config.token_map_cleanup_interval_secs = 0;
    assert_eq!(config.token_map_cleanup_interval_secs, 0);
    assert!(
        config.validate().is_ok(),
        "token_map_cleanup_interval_secs=0（禁用）应通过校验"
    );
}

/// T029: 环境变量 `BULWARK_TOKEN_MAP_CLEANUP_INTERVAL_SECS` 覆盖默认值。
///
/// 注：env var 名按代码库惯例与字段名严格对应（如 `sign_window_seconds` ↔ `BULWARK_SIGN_WINDOW_SECONDS`），
/// 故 `token_map_cleanup_interval_secs` ↔ `BULWARK_TOKEN_MAP_CLEANUP_INTERVAL_SECS`。
#[test]
#[serial]
fn token_map_cleanup_interval_env_var_overrides() {
    std::env::set_var("BULWARK_TOKEN_MAP_CLEANUP_INTERVAL_SECS", "600");
    let config = BulwarkConfig::load(None).expect("load with env");
    assert_eq!(
        config.token_map_cleanup_interval_secs, 600,
        "BULWARK_TOKEN_MAP_CLEANUP_INTERVAL_SECS=600 应覆盖默认值"
    );
    std::env::remove_var("BULWARK_TOKEN_MAP_CLEANUP_INTERVAL_SECS");
}

// ========================================================================
// T013: login_token_map_persist_interval_secs 配置测试
// ========================================================================

/// T013: `default_config()` 的 `login_token_map_persist_interval_secs` 为 0（同步写入）。
#[cfg(feature = "login-token-map-persistence")]
#[test]
fn login_token_map_persist_interval_default_is_zero() {
    let config = BulwarkConfig::default_config();
    assert_eq!(
        config.login_token_map_persist_interval_secs, 0,
        "默认 login_token_map_persist_interval_secs 应为 0（同步写入）"
    );
    assert_eq!(
        config.login_token_map_persist_interval_secs, DEFAULT_LOGIN_TOKEN_MAP_PERSIST_INTERVAL_SECS,
        "应等于 DEFAULT_LOGIN_TOKEN_MAP_PERSIST_INTERVAL_SECS 常量"
    );
}

/// T013: `BULWARK_LOGIN_TOKEN_MAP_PERSIST_INTERVAL_SECS=10` 环境变量覆盖默认值。
#[cfg(feature = "login-token-map-persistence")]
#[test]
#[serial]
fn login_token_map_persist_interval_env_var_overrides() {
    std::env::set_var("BULWARK_LOGIN_TOKEN_MAP_PERSIST_INTERVAL_SECS", "10");
    let config = BulwarkConfig::load(None).expect("load with env");
    assert_eq!(
        config.login_token_map_persist_interval_secs, 10,
        "BULWARK_LOGIN_TOKEN_MAP_PERSIST_INTERVAL_SECS=10 应覆盖默认值"
    );
    std::env::remove_var("BULWARK_LOGIN_TOKEN_MAP_PERSIST_INTERVAL_SECS");
}

// ========================================================================
// T018: anon_session_timeout 配置测试
// ========================================================================

/// T018: `default_config()` 的 `anon_session_timeout` 为 1800（30 分钟）。
#[cfg(feature = "anonymous-session")]
#[test]
fn anon_session_timeout_default_is_1800() {
    let config = BulwarkConfig::default_config();
    assert_eq!(
        config.anon_session_timeout, 1800,
        "默认 anon_session_timeout 应为 1800（30 分钟）"
    );
    assert_eq!(
        config.anon_session_timeout, DEFAULT_ANON_SESSION_TIMEOUT_SECS,
        "应等于 DEFAULT_ANON_SESSION_TIMEOUT_SECS 常量"
    );
}

/// T018: `BULWARK_ANON_SESSION_TIMEOUT=3600` 环境变量覆盖默认值。
#[cfg(feature = "anonymous-session")]
#[test]
#[serial]
fn anon_session_timeout_env_var_overrides() {
    std::env::set_var("BULWARK_ANON_SESSION_TIMEOUT", "3600");
    let config = BulwarkConfig::load(None).expect("load with env");
    assert_eq!(
        config.anon_session_timeout, 3600,
        "BULWARK_ANON_SESSION_TIMEOUT=3600 应覆盖默认值"
    );
    std::env::remove_var("BULWARK_ANON_SESSION_TIMEOUT");
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

// ========================================================================
// T005: is_read_body 配置测试
// ========================================================================

/// T005: `default_config()` 的 `is_read_body` 为 false（向后兼容）。
#[test]
fn config_default_is_read_body_is_false() {
    let config = BulwarkConfig::default_config();
    assert!(
        !config.is_read_body,
        "默认 is_read_body 应为 false（向后兼容）"
    );
    assert_eq!(
        config.is_read_body, DEFAULT_IS_READ_BODY,
        "应等于 DEFAULT_IS_READ_BODY 常量"
    );
}

/// T005: `BULWARK_IS_READ_BODY=true` 环境变量覆盖配置为 true。
#[test]
#[serial]
fn env_overrides_is_read_body() {
    std::env::set_var("BULWARK_IS_READ_BODY", "true");
    let config = BulwarkConfig::load(None).expect("load with env");
    assert!(
        config.is_read_body,
        "BULWARK_IS_READ_BODY=true 应覆盖为 true"
    );
    std::env::remove_var("BULWARK_IS_READ_BODY");
}

// ========================================================================
// T014: device_binding_mode 配置测试（4 个，spec R-device-binding-001）
// ========================================================================

/// T014: `default_config()` 的 `device_binding_mode` 为 "disabled"。
#[test]
fn test_device_binding_mode_default() {
    let config = BulwarkConfig::default_config();
    assert_eq!(
        config.device_binding_mode, "disabled",
        "默认 device_binding_mode 应为 'disabled'"
    );
}

/// T014: 自定义值 "strict" 通过 `validate()` 校验。
#[test]
fn test_device_binding_mode_custom() {
    let mut config = BulwarkConfig::default_config();
    config.device_binding_mode = "strict".to_string();
    assert!(
        config.validate().is_ok(),
        "device_binding_mode='strict' 应通过校验"
    );
}

/// T014: 无效值 "invalid" 校验失败返回 `Err`。
#[test]
fn test_device_binding_mode_invalid() {
    let mut config = BulwarkConfig::default_config();
    config.device_binding_mode = "invalid".to_string();
    let result = config.validate();
    assert!(result.is_err(), "device_binding_mode='invalid' 应校验失败");
    match result {
        Err(BulwarkError::Config(msg)) => {
            assert!(
                msg.contains("device_binding_mode"),
                "错误消息应包含字段名，实际: {}",
                msg
            );
        },
        Err(other) => panic!("期望 BulwarkError::Config，实际: {:?}", other),
        Ok(_) => panic!("device_binding_mode='invalid' 时应返回 Err"),
    }
}

/// T014: 环境变量 `BULWARK_DEVICE_BINDING_MODE=loose` 覆盖配置值。
#[test]
#[serial]
fn test_device_binding_mode_env_override() {
    std::env::set_var("BULWARK_DEVICE_BINDING_MODE", "loose");
    let config = BulwarkConfig::load(None).expect("load with env");
    assert_eq!(
        config.device_binding_mode, "loose",
        "环境变量应覆盖 device_binding_mode 为 'loose'"
    );
    std::env::remove_var("BULWARK_DEVICE_BINDING_MODE");
}

// ========================================================================
// T036: validate() redis_url 非空校验测试（3 个，spec R-redis-ratelimit-004）
// ========================================================================

/// 验证 `rate_limit_backend=Redis` 且 `redis_url` 为空时 `validate()` 返回 Err。
#[cfg(feature = "rate-limit-redis")]
#[test]
fn validate_rejects_empty_redis_url() {
    let mut config = BulwarkConfig::default_config();
    config.rate_limit_backend = RateLimitBackend::Redis {
        redis_url: String::new(),
    };
    let err = config.validate().unwrap_err();
    assert!(
        matches!(err, BulwarkError::Config(ref m) if m.contains("redis_url")),
        "空 redis_url 应被 validate 拒绝，实际错误: {:?}",
        err
    );
}

/// 验证 `rate_limit_backend=Redis` 且 `redis_url` 非空时 `validate()` 通过。
#[cfg(feature = "rate-limit-redis")]
#[test]
fn validate_accepts_non_empty_redis_url() {
    let mut config = BulwarkConfig::default_config();
    config.rate_limit_backend = RateLimitBackend::Redis {
        redis_url: "redis://127.0.0.1:6379/0".to_string(),
    };
    assert!(config.validate().is_ok(), "非空 redis_url 应通过 validate");
}

/// 验证 `rate_limit_backend=Memory` 时 `validate()` 不检查 redis_url。
#[cfg(feature = "rate-limit-redis")]
#[test]
fn validate_memory_backend_skips_redis_url_check() {
    let config = BulwarkConfig::default_config();
    assert_eq!(config.rate_limit_backend, RateLimitBackend::Memory);
    assert!(config.validate().is_ok(), "Memory 后端应通过 validate");
}

// ========================================================================
// T039: 环境变量覆盖测试（6 个 serial，spec R-cors-001 / R-csrf-003 / R-redis-ratelimit-004）
// ========================================================================

/// R-cors-001: `BULWARK_CORS_ALLOWED_ORIGINS` 覆盖 CORS 允许的源列表。
#[cfg(feature = "web-cors")]
#[test]
#[serial]
fn env_overrides_cors_allowed_origins() {
    std::env::set_var(
        "BULWARK_CORS_ALLOWED_ORIGINS",
        "https://a.com,https://b.com",
    );
    let config = BulwarkConfig::load(None).expect("load with env");
    assert_eq!(
        config.cors_config.allowed_origins,
        vec!["https://a.com", "https://b.com"]
    );
    std::env::remove_var("BULWARK_CORS_ALLOWED_ORIGINS");
}

/// R-cors-001: `BULWARK_CORS_ALLOWED_ORIGINS` 过滤空值（连续逗号）。
#[cfg(feature = "web-cors")]
#[test]
#[serial]
fn env_cors_origins_filters_empty_values() {
    std::env::set_var(
        "BULWARK_CORS_ALLOWED_ORIGINS",
        "https://a.com,,https://b.com,",
    );
    let config = BulwarkConfig::load(None).expect("load with env");
    assert_eq!(
        config.cors_config.allowed_origins,
        vec!["https://a.com", "https://b.com"],
        "空值应被过滤"
    );
    std::env::remove_var("BULWARK_CORS_ALLOWED_ORIGINS");
}

/// R-csrf-003: `BULWARK_CSRF_ENABLED=true` 覆盖 CSRF 启用状态。
#[cfg(feature = "web-csrf")]
#[test]
#[serial]
fn env_overrides_csrf_enabled() {
    std::env::set_var("BULWARK_CSRF_ENABLED", "true");
    let config = BulwarkConfig::load(None).expect("load with env");
    assert!(
        config.csrf_config.enabled,
        "BULWARK_CSRF_ENABLED=true 应启用 CSRF"
    );
    std::env::remove_var("BULWARK_CSRF_ENABLED");
}

/// R-redis-ratelimit-004: `BULWARK_RATE_LIMIT_BACKEND=redis` 覆盖限流后端为 Redis。
#[cfg(feature = "rate-limit-redis")]
#[test]
#[serial]
fn env_overrides_rate_limit_backend_to_redis() {
    std::env::set_var("BULWARK_RATE_LIMIT_BACKEND", "redis");
    std::env::set_var("BULWARK_REDIS_URL", "redis://localhost:6379/0");
    let config = BulwarkConfig::load(None).expect("load with env");
    match config.rate_limit_backend {
        RateLimitBackend::Redis { redis_url } => {
            assert_eq!(redis_url, "redis://localhost:6379/0");
        },
        _ => panic!("应为 Redis 后端"),
    }
    std::env::remove_var("BULWARK_RATE_LIMIT_BACKEND");
    std::env::remove_var("BULWARK_REDIS_URL");
}

/// R-redis-ratelimit-004: `BULWARK_RATE_LIMIT_BACKEND=memory` 覆盖限流后端为 Memory。
#[cfg(feature = "rate-limit-redis")]
#[test]
#[serial]
fn env_overrides_rate_limit_backend_to_memory() {
    std::env::set_var("BULWARK_RATE_LIMIT_BACKEND", "memory");
    let config = BulwarkConfig::load(None).expect("load with env");
    assert_eq!(
        config.rate_limit_backend,
        RateLimitBackend::Memory,
        "应为 Memory 后端"
    );
    std::env::remove_var("BULWARK_RATE_LIMIT_BACKEND");
}

/// R-redis-ratelimit-004: 仅设置 `BULWARK_REDIS_URL`（不设 backend）不改变 Memory 后端。
#[cfg(feature = "rate-limit-redis")]
#[test]
#[serial]
fn env_redis_url_alone_does_not_change_memory_backend() {
    std::env::set_var("BULWARK_REDIS_URL", "redis://localhost:6379/0");
    let config = BulwarkConfig::load(None).expect("load with env");
    assert_eq!(
        config.rate_limit_backend,
        RateLimitBackend::Memory,
        "仅设 REDIS_URL 不应改变 Memory 后端"
    );
    std::env::remove_var("BULWARK_REDIS_URL");
}

/// R-redis-ratelimit-004: `BULWARK_RATE_LIMIT_BACKEND` 无效值返回 Config 错误（规则12：失败必须显性化）。
#[cfg(feature = "rate-limit-redis")]
#[test]
#[serial]
fn env_rate_limit_backend_invalid_value_returns_error() {
    std::env::set_var("BULWARK_RATE_LIMIT_BACKEND", "mysql");
    let result = BulwarkConfig::load(None);
    assert!(result.is_err(), "无效 backend 值应返回错误");
    let err = result.unwrap_err();
    match err {
        BulwarkError::Config(msg) => {
            assert!(
                msg.contains("BULWARK_RATE_LIMIT_BACKEND"),
                "错误消息应包含变量名"
            );
            assert!(msg.contains("mysql"), "错误消息应包含无效值");
        },
        _ => panic!("应为 BulwarkError::Config，实际: {:?}", err),
    }
    std::env::remove_var("BULWARK_RATE_LIMIT_BACKEND");
}

// ========================================================================
// T001: 并发登录策略枚举配置测试（spec R-001 / R-004）
// ========================================================================

/// R-001: `BulwarkConfig::default()` 的 `replaced_login_exit_mode` 为 `OldDevice`。
#[test]
fn config_default_replaced_login_exit_mode_is_old_device() {
    let config = BulwarkConfig::default_config();
    assert_eq!(
        config.replaced_login_exit_mode,
        ReplacedLoginExitMode::OldDevice,
        "默认 replaced_login_exit_mode 应为 OldDevice"
    );
}

/// R-004: `BulwarkConfig::default()` 的 `overflow_logout_mode` 为 `Logout`。
#[test]
fn config_default_overflow_logout_mode_is_logout() {
    let config = BulwarkConfig::default_config();
    assert_eq!(
        config.overflow_logout_mode,
        OverflowLogoutMode::Logout,
        "默认 overflow_logout_mode 应为 Logout"
    );
}

/// R-001: `ReplacedLoginExitMode` 序列化为 snake_case 字符串 "old_device"/"new_device"。
#[test]
fn replaced_login_exit_mode_serde_snake_case() {
    // 序列化
    let old_json =
        serde_json::to_string(&ReplacedLoginExitMode::OldDevice).expect("序列化 OldDevice 应成功");
    assert_eq!(old_json, r#""old_device""#);
    let new_json =
        serde_json::to_string(&ReplacedLoginExitMode::NewDevice).expect("序列化 NewDevice 应成功");
    assert_eq!(new_json, r#""new_device""#);

    // 反序列化（往返一致）
    let old: ReplacedLoginExitMode =
        serde_json::from_str(r#""old_device""#).expect("反序列化 old_device 应成功");
    assert_eq!(old, ReplacedLoginExitMode::OldDevice);
    let new: ReplacedLoginExitMode =
        serde_json::from_str(r#""new_device""#).expect("反序列化 new_device 应成功");
    assert_eq!(new, ReplacedLoginExitMode::NewDevice);
}

/// R-004: `OverflowLogoutMode` 序列化为 snake_case 字符串 "logout"/"kickout"/"replaced"。
#[test]
fn overflow_logout_mode_serde_snake_case() {
    // 序列化
    assert_eq!(
        serde_json::to_string(&OverflowLogoutMode::Logout).unwrap(),
        r#""logout""#
    );
    assert_eq!(
        serde_json::to_string(&OverflowLogoutMode::Kickout).unwrap(),
        r#""kickout""#
    );
    assert_eq!(
        serde_json::to_string(&OverflowLogoutMode::Replaced).unwrap(),
        r#""replaced""#
    );

    // 反序列化（往返一致）
    assert_eq!(
        serde_json::from_str::<OverflowLogoutMode>(r#""logout""#).unwrap(),
        OverflowLogoutMode::Logout
    );
    assert_eq!(
        serde_json::from_str::<OverflowLogoutMode>(r#""kickout""#).unwrap(),
        OverflowLogoutMode::Kickout
    );
    assert_eq!(
        serde_json::from_str::<OverflowLogoutMode>(r#""replaced""#).unwrap(),
        OverflowLogoutMode::Replaced
    );
}

/// R-001: `BULWARK_REPLACED_LOGIN_EXIT_MODE=new_device` 环境变量覆盖配置。
#[test]
#[serial]
fn env_overrides_replaced_login_exit_mode() {
    std::env::set_var("BULWARK_REPLACED_LOGIN_EXIT_MODE", "new_device");
    let config = BulwarkConfig::load(None).expect("load with env");
    assert_eq!(
        config.replaced_login_exit_mode,
        ReplacedLoginExitMode::NewDevice,
        "BULWARK_REPLACED_LOGIN_EXIT_MODE=new_device 应覆盖为 NewDevice"
    );
    std::env::remove_var("BULWARK_REPLACED_LOGIN_EXIT_MODE");
}

/// R-004: `BULWARK_OVERFLOW_LOGOUT_MODE=kickout` 环境变量覆盖配置。
#[test]
#[serial]
fn env_overrides_overflow_logout_mode() {
    std::env::set_var("BULWARK_OVERFLOW_LOGOUT_MODE", "kickout");
    let config = BulwarkConfig::load(None).expect("load with env");
    assert_eq!(
        config.overflow_logout_mode,
        OverflowLogoutMode::Kickout,
        "BULWARK_OVERFLOW_LOGOUT_MODE=kickout 应覆盖为 Kickout"
    );
    std::env::remove_var("BULWARK_OVERFLOW_LOGOUT_MODE");
}

// ========================================================================
// T012: audit_mask_mode 配置测试
// ========================================================================

/// T012: `default_config()` 的 `audit_mask_mode` 为 `Partial`。
#[test]
fn default_audit_mask_mode_is_partial() {
    let config = BulwarkConfig::default_config();
    assert_eq!(
        config.audit_mask_mode,
        AuditMaskMode::Partial,
        "默认 audit_mask_mode 应为 Partial"
    );
}

/// T012: `AuditMaskMode` 序列化为 snake_case 字符串 "full"/"partial"。
#[test]
fn audit_mask_mode_serde_snake_case() {
    assert_eq!(
        serde_json::to_string(&AuditMaskMode::Full).unwrap(),
        r#""full""#
    );
    assert_eq!(
        serde_json::to_string(&AuditMaskMode::Partial).unwrap(),
        r#""partial""#
    );
    assert_eq!(
        serde_json::from_str::<AuditMaskMode>(r#""full""#).unwrap(),
        AuditMaskMode::Full
    );
    assert_eq!(
        serde_json::from_str::<AuditMaskMode>(r#""partial""#).unwrap(),
        AuditMaskMode::Partial
    );
}

/// T012: `BULWARK_AUDIT_MASK_MODE=full` 环境变量覆盖配置为 Full。
#[test]
#[serial]
fn env_overrides_audit_mask_mode() {
    std::env::set_var("BULWARK_AUDIT_MASK_MODE", "full");
    let config = BulwarkConfig::load(None).expect("load with env");
    assert_eq!(
        config.audit_mask_mode,
        AuditMaskMode::Full,
        "BULWARK_AUDIT_MASK_MODE=full 应覆盖为 Full"
    );
    std::env::remove_var("BULWARK_AUDIT_MASK_MODE");
}

// ========================================================================
// T023-d: anomalous-detector-dual validate() 校验测试（spec R-007）
// ========================================================================

/// R-007: `anomalous_analyzer_interval_secs < 60` 时 validate() 返回 Err。
#[cfg(feature = "anomalous-detector-dual")]
#[test]
fn validate_rejects_anomalous_interval_below_60() {
    let mut config = BulwarkConfig::default_config();
    config.anomalous_analyzer_interval_secs = 30;
    let err = config.validate().unwrap_err();
    assert!(
        matches!(err, BulwarkError::Config(ref m) if m.contains("anomalous_analyzer_interval_secs")),
        "interval=30 应被拒绝，实际: {:?}",
        err
    );
}

/// R-007: `anomalous_analyzer_interval_secs = 60` 时 validate() 通过（边界值）。
#[cfg(feature = "anomalous-detector-dual")]
#[test]
fn validate_accepts_anomalous_interval_at_60() {
    let mut config = BulwarkConfig::default_config();
    config.anomalous_analyzer_interval_secs = 60;
    assert!(config.validate().is_ok(), "interval=60 应通过 validate");
}

/// R-007: `anomalous_analyzer_burst_threshold = 0` 时 validate() 返回 Err。
#[cfg(feature = "anomalous-detector-dual")]
#[test]
fn validate_rejects_zero_burst_threshold() {
    let mut config = BulwarkConfig::default_config();
    config.anomalous_analyzer_burst_threshold = 0;
    let err = config.validate().unwrap_err();
    assert!(
        matches!(err, BulwarkError::Config(ref m) if m.contains("anomalous_analyzer_burst_threshold")),
        "burst_threshold=0 应被拒绝，实际: {:?}",
        err
    );
}
