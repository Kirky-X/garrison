// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! config 模块测试。

// jwt_secret 的 `.into()` 是跨 feature 兼容的必要转换：protocol-zeroize 下字段
// 类型为 Zeroizing<String>（String→Zeroizing<String>），feature 关闭时退化为
// String，被 clippy 误报 useless_conversion。
#![allow(clippy::useless_conversion)]

use super::*;
use crate::error::GarrisonError;
use serial_test::serial;

/// panic 安全的环境变量守卫：Drop（含 unwind）时 remove_var，防断言 panic 后变量残留污染共享进程 env 的 serial 测试。
///
/// 互斥规则：设置环境变量的测试与调用 `load()`（经 confers `EnvSource` 读进程 env）的测试一律 `#[serial]`，读侧与写侧同队列才不交错。
struct EnvVarGuard {
    keys: Vec<String>,
}

impl EnvVarGuard {
    /// set_var 并返回守卫；Drop 时 remove_var。
    fn set(key: impl Into<String>, value: &str) -> Self {
        let key = key.into();
        // 安全性：set/remove 均发生在 #[serial] 互斥队列内，无并发 set_var 竞争
        std::env::set_var(&key, value);
        Self { keys: vec![key] }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        for k in &self.keys {
            std::env::remove_var(k);
        }
    }
}

// jwt_secret 用 Zeroizing<String> 自动 zeroize on Drop 测试

/// 编译期断言：protocol-zeroize 下 jwt_secret 为 `Zeroizing<String>`（Drop 自动 zeroize），改回 String 即编译失败。
#[cfg(feature = "protocol-zeroize")]
#[test]
fn jwt_secret_is_zeroizing_type_when_protocol_zeroize() {
    let cfg = GarrisonConfig::default();
    // 接受 Zeroizing<String> 实例证明类型正确
    fn assert_zeroizing<T: zeroize::Zeroize>(_: &T) {}
    assert_zeroizing(&cfg.jwt_secret);
}

/// zeroize 后 buffer 内容被清零（`Zeroizing::drop` 内部调 `T::zeroize()`，测试直接调用同一方法；Drop 后访问字段是 UB）。
/// zeroize 不释放 buffer（String 仍持有 capacity），ptr 仍有效可安全读取验证全 0。
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
    // nosemgrep: rust.lang.security.unsafe-usage.unsafe-usage —— 测试断言只读验证 zeroize 清零，非生产 unsafe
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

// 代码默认值测试

#[test]
fn default_config_matches_spec() {
    let config = GarrisonConfig::default_config();
    assert_eq!(config.token_style, "uuid");
    assert_eq!(config.timeout, 2_592_000); // 30 天
    assert!(config.throw_on_not_login);
    assert_eq!(config.token_name, "garrison_token");
    assert!(config.is_read_cookie);
    assert!(config.is_read_header);
    assert!(config.is_write_header);
    assert_eq!(config.jwt_algorithm, "HS256");
    assert_eq!(config.sign_window_seconds, 300);
    assert_eq!(config.sso_ticket_ttl_seconds, 60);
}

// is_write_cookie 配置测试

#[test]
fn default_is_write_cookie_is_false() {
    let config = GarrisonConfig::default_config();
    assert!(!config.is_write_cookie, "默认 is_write_cookie 应为 false");
}

#[test]
fn default_is_write_header_is_true() {
    let config = GarrisonConfig::default_config();
    assert!(config.is_write_header, "默认 is_write_header 应为 true");
}

#[test]
fn custom_is_write_cookie_can_be_set() {
    let mut config = GarrisonConfig::default_config();
    config.is_write_cookie = true;
    assert!(config.is_write_cookie, "自定义 is_write_cookie=true 应生效");
    assert!(config.validate().is_ok(), "is_write_cookie=true 应通过校验");
}

#[test]
fn both_is_write_header_and_is_write_cookie_can_be_true() {
    let mut config = GarrisonConfig::default_config();
    config.is_write_header = true;
    config.is_write_cookie = true;
    assert!(config.is_write_header, "is_write_header 应为 true");
    assert!(config.is_write_cookie, "is_write_cookie 应为 true");
    assert!(config.validate().is_ok(), "两者同时为 true 应通过校验");
}

#[test]
fn default_trait_eq_default_config() {
    let d = GarrisonConfig::default();
    let dc = GarrisonConfig::default_config();
    assert_eq!(d.token_style, dc.token_style);
    assert_eq!(d.timeout, dc.timeout);
    assert_eq!(d.throw_on_not_login, dc.throw_on_not_login);
}

// 配置校验测试

#[test]
fn validate_rejects_invalid_token_style() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "invalid".to_string();
    let result = config.validate();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, GarrisonError::Config(ref msg) if msg.contains("config-unknown-token-style::invalid")),
        "应返回 'config-unknown-token-style::invalid'，实际: {:?}",
        err
    );
}

#[test]
fn validate_rejects_negative_timeout() {
    let mut config = GarrisonConfig::default_config();
    config.timeout = -1;
    let result = config.validate();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, GarrisonError::Config(ref msg) if msg.contains("config-timeout-must-positive")),
        "应返回 'config-timeout-must-positive'，实际: {:?}",
        err
    );
}

#[test]
fn validate_rejects_zero_timeout() {
    let mut config = GarrisonConfig::default_config();
    config.timeout = 0;
    assert!(config.validate().is_err());
}

/// 循环内为 simple 风格补齐 ≥32B 强密钥（simple 的 jwt_secret 即 HMAC 签名密钥，同 jwt 要求）。
#[test]
#[cfg_attr(not(feature = "protocol-zeroize"), allow(clippy::useless_conversion))]
fn validate_accepts_all_legal_token_styles() {
    for style in TOKEN_STYLES {
        let mut config = GarrisonConfig::default_config();
        config.token_style = style.to_string();
        if matches!(*style, "jwt" | "simple") {
            // ≥32 字节，满足 jwt/HS256 与 simple 的 jwt_secret 最小长度校验
            config.jwt_secret = "test-secret-0123456789abcdefghij".to_string().into();
        }
        assert!(
            config.validate().is_ok(),
            "token_style '{}' 应通过校验",
            style
        );
    }
}

#[test]
fn default_config_validates_ok() {
    let config = GarrisonConfig::default_config();
    assert!(config.validate().is_ok());
}

/// jwt_secret 为空（token_style=jwt）应拒绝，防空字符串密钥伪造 JWT。
#[test]
fn validate_rejects_empty_jwt_secret_when_token_style_is_jwt() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    // jwt_secret 保持默认空字符串
    let result = config.validate();
    match result {
        Err(GarrisonError::Config(msg)) => {
            assert!(
                msg.contains("config-jwt-secret-empty"),
                "错误消息应包含 config-jwt-secret-empty，实际: {}",
                msg
            );
        },
        Err(other) => panic!("期望 GarrisonError::Config，实际: {:?}", other),
        Ok(_) => panic!("token_style=jwt 且 jwt_secret 为空时应返回 Err"),
    }
}

/// jwt_secret 短于 32B（HS256）应拒绝（弱密钥易离线爆破，CWE-326 防御）。
#[test]
fn validate_rejects_short_jwt_secret_hs256() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_algorithm = "HS256".to_string();
    config.jwt_secret = "short-secret".to_string().into(); // 12 字节 < 32
    match config.validate() {
        Err(GarrisonError::Config(msg)) => {
            assert!(
                msg.contains("config-jwt-secret-too-short") && msg.contains("min"),
                "实际: {}",
                msg
            );
        },
        other => panic!("HS256 短密钥应被拒绝，实际: {:?}", other),
    }
}

/// HS512 短于 64B 拒绝（即使已满足 HS256 的 32B）。
#[test]
fn validate_rejects_short_jwt_secret_hs512() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_algorithm = "HS512".to_string();
    // 50 字节：满足 HS256(32) 和 HS384(48) 但不满足 HS512（需 ≥64）
    config.jwt_secret = "x".repeat(50).into();
    match config.validate() {
        Err(GarrisonError::Config(msg)) => {
            assert!(
                msg.contains("HS512") && msg.contains("min 64"),
                "HS512 短密钥错误消息应包含算法与最小长度，实际: {}",
                msg
            );
        },
        other => panic!("HS512 50 字节密钥应被拒绝，实际: {:?}", other),
    }
}

/// HS384 短于 48B 拒绝（即使已满足 HS256 的 32B）。
#[test]
fn validate_rejects_short_jwt_secret_hs384() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_algorithm = "HS384".to_string();
    // 40 字节：满足 HS256(32) 但不满足 HS384（需 ≥48）
    config.jwt_secret = "x".repeat(40).into();
    match config.validate() {
        Err(GarrisonError::Config(msg)) => {
            assert!(
                msg.contains("HS384") && msg.contains("min 48"),
                "HS384 短密钥错误消息应包含算法与最小长度，实际: {}",
                msg
            );
        },
        other => panic!("HS384 40 字节密钥应被拒绝，实际: {:?}", other),
    }
}

/// jwt_algorithm 不在白名单应拒绝（防拼写错误静默走 32B 分支）。
#[test]
fn validate_rejects_unknown_jwt_algorithm() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_algorithm = "HS1024".to_string(); // 拼写错误 / 不支持
    config.jwt_secret = "x".repeat(32).into(); // 32 字节（满足 HS256 但算法白名单校验在前）
    match config.validate() {
        Err(GarrisonError::Config(msg)) => {
            assert!(
                msg.contains("config-jwt-algorithm-unsupported") && msg.contains("HS1024"),
                "未知算法错误消息应包含输入值与 key，实际: {}",
                msg
            );
        },
        other => panic!("未知 jwt_algorithm 应被拒绝，实际: {:?}", other),
    }
}

/// simple 的 jwt_secret 直接作 HMAC-SHA256 签名密钥，弱密钥可离线爆破：配置层硬错误对齐运行时 `core-simple-secret-too-short` 的 fail-closed，错误信息含升级指引。
#[test]
fn validate_rejects_short_secret_for_simple_style() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "simple".to_string();
    config.jwt_secret = "weak".to_string().into(); // 4 字节 < 32
    match config.validate() {
        Err(GarrisonError::Config(msg)) => {
            // 原始 detail 只带结构化 key + 参数；升级指引在 locales/{en,zh}.ftl 模板内
            assert!(
                msg.contains("config-jwt-secret-too-short") && msg.contains("min 32"),
                "simple 短密钥错误应含长度约束，实际: {}",
                msg
            );
            let localized = crate::i18n::translate_error(&GarrisonError::Config(msg));
            assert!(
                localized.contains("openssl rand"),
                "simple 短密钥错误应含升级指引（按 locale 取值），实际: {}",
                localized
            );
        },
        other => panic!("simple 风格短密钥应被拒绝，实际: {:?}", other),
    }
}

#[test]
fn validate_accepts_strong_jwt_secret_hs256() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_algorithm = "HS256".to_string();
    config.jwt_secret = "x".repeat(32).into(); // 恰好 32 字节边界
    assert!(config.validate().is_ok(), "32 字节密钥应通过 HS256 校验");
}

#[test]
fn validate_accepts_strong_jwt_secret_hs384() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_algorithm = "HS384".to_string();
    config.jwt_secret = "x".repeat(48).into(); // 恰好 48 字节边界
    assert!(config.validate().is_ok(), "48 字节密钥应通过 HS384 校验");
}

#[test]
fn validate_accepts_strong_jwt_secret_hs512() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_algorithm = "HS512".to_string();
    config.jwt_secret = "x".repeat(64).into(); // 恰好 64 字节边界
    assert!(config.validate().is_ok(), "64 字节密钥应通过 HS512 校验");
}

// JWT 弱密钥黑名单

/// "changeme" + 24 个 '_'（32B）过长度校验但命中黑名单：可预测密钥剥离填充字符后整串比对（忽略大小写）被拒。
#[test]
fn validate_rejects_weak_padded_jwt_secret_hs256() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_algorithm = "HS256".to_string();
    config.jwt_secret = format!("changeme{}", "_".repeat(24)).into();
    match config.validate() {
        Err(GarrisonError::Config(msg)) => {
            assert!(
                msg.contains("config-jwt-secret-weak") && msg.contains("blacklist"),
                "填充弱密钥应命中黑名单，实际: {}",
                msg
            );
        },
        other => panic!("弱密钥填充变体应被拒绝，实际: {:?}", other),
    }
}

#[test]
fn validate_rejects_weak_jwt_secret_case_insensitive() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_algorithm = "HS512".to_string();
    config.jwt_secret = format!("PASSWORD{}", "-".repeat(56)).into(); // 64 字节
    let err = config.validate().expect_err("大写弱密钥填充变体应被拒绝");
    let display = err.to_string();
    assert!(
        display.contains("jwt_secret") && display.contains("blacklist"),
        "弱密钥 Display 应含密钥字段与命中原因，实际: {}",
        display
    );
}

#[test]
fn validate_rejects_weak_secret_for_simple_style() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "simple".to_string();
    config.jwt_secret = format!("letmein{}", ".".repeat(25)).into(); // 32 字节
    let err = config.validate().expect_err("simple 弱密钥应被拒绝");
    let display = err.to_string();
    assert!(
        display.contains("jwt_secret") && display.contains("blacklist"),
        "弱密钥 Display 应含密钥字段与命中原因，实际: {}",
        display
    );
}

/// 强密钥含弱密钥子串不误伤（黑名单整串匹配，非子串）。
#[test]
fn validate_accepts_strong_secret_containing_weak_substring() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_algorithm = "HS256".to_string();
    // 35 字节高熵短句，尾部含 "123456" 子串——整串不命中黑名单
    config.jwt_secret = "correct horse battery staple 123456".to_string().into();
    assert!(config.validate().is_ok(), "含弱密钥子串的强密钥不应被误伤");
}

/// 校验矩阵：uuid/random_64（CSPRNG 不消费 jwt_secret）空弱均放行；simple 空（<32B）硬错误；jwt+非对称算法强度由 PEM 决定、空 secret 放行。
#[test]
fn validate_jwt_secret_style_matrix() {
    for style in ["uuid", "random_64"] {
        let mut config = GarrisonConfig::default_config();
        config.token_style = style.to_string();
        config.jwt_secret = String::new().into();
        assert!(
            config.validate().is_ok(),
            "{style} 风格空 jwt_secret 应放行（不透明风格不消费密钥）"
        );
        config.jwt_secret = "changeme".to_string().into();
        assert!(
            config.validate().is_ok(),
            "{style} 风格弱 jwt_secret 应放行（不透明风格不消费密钥）"
        );
    }
    let mut config = GarrisonConfig::default_config();
    config.token_style = "simple".to_string();
    config.jwt_secret = String::new().into();
    assert!(
        config.validate().is_err(),
        "simple 风格空 jwt_secret 应拒绝（直接参与 HMAC 签名）"
    );
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_algorithm = "RS256".to_string();
    config.jwt_rsa_private_key_pem = Some(TEST_ASYM_RSA_PEM.to_string());
    config.jwt_secret = String::new().into();
    assert!(
        config.validate().is_ok(),
        "jwt 非对称算法空 jwt_secret 应放行（强度由 PEM 决定）"
    );
}

// remember_me 配置测试

#[test]
fn remember_me_defaults() {
    let config = GarrisonConfig::default_config();
    assert!(!config.remember_me_enabled);
    assert_eq!(config.remember_me_timeout, REMEMBER_ME_DEFAULT_TIMEOUT);
    assert_eq!(config.remember_me_timeout, 7_776_000);
}

#[test]
fn validate_remember_me_ok_when_timeout_greater() {
    let mut config = GarrisonConfig::default_config();
    config.remember_me_enabled = true;
    // remember_me_timeout 默认 7776000 > timeout 默认 2592000，应通过
    assert!(config.validate().is_ok());
}

#[test]
fn validate_remember_me_fails_when_timeout_not_greater() {
    let mut config = GarrisonConfig::default_config();
    config.remember_me_enabled = true;
    config.remember_me_timeout = config.timeout; // 等于 timeout
    let result = config.validate();
    assert!(result.is_err());
    match result {
        Err(GarrisonError::Config(msg)) => {
            assert!(
                msg.contains("config-remember-me-timeout-mismatch"),
                "错误消息应包含 config-remember-me-timeout-mismatch，实际: {}",
                msg
            );
        },
        Err(other) => panic!("期望 GarrisonError::Config，实际: {:?}", other),
        Ok(_) => panic!("remember_me_timeout <= timeout 时应返回 Err"),
    }
}

#[serial]
#[test]
fn validate_remember_me_disabled_only_checks_positive() {
    let mut config = GarrisonConfig::default_config();
    config.remember_me_enabled = false;
    config.remember_me_timeout = 1; // > 0 即可（不需要 > timeout）
    assert!(config.validate().is_ok());
}

#[serial]
#[test]
fn validate_remember_me_fails_when_timeout_non_positive() {
    let mut config = GarrisonConfig::default_config();
    config.remember_me_enabled = false;
    config.remember_me_timeout = 0;
    assert!(config.validate().is_err());
}

#[test]
#[serial]
fn toml_overrides_remember_me() {
    let temp = write_temp_toml(
        r#"
remember_me_enabled = true
remember_me_timeout = 9999999
"#,
    );
    let config = GarrisonConfig::load(Some(temp.path().to_str().unwrap())).unwrap();
    assert!(config.remember_me_enabled);
    assert_eq!(config.remember_me_timeout, 9999999);
}

#[test]
#[serial]
fn env_overrides_remember_me() {
    let _env_guards = [
        EnvVarGuard::set("GARRISON_REMEMBER_ME_ENABLED", "true"),
        EnvVarGuard::set("GARRISON_REMEMBER_ME_TIMEOUT", "9999999"),
    ];

    let config = GarrisonConfig::load(None).unwrap();

    assert!(config.remember_me_enabled);
    assert_eq!(config.remember_me_timeout, 9999999);
}

// session_hover_timeout 配置测试

#[test]
fn config_default_session_hover_is_negative_one() {
    let config = GarrisonConfig::default_config();
    assert_eq!(config.session_hover_timeout, -1);
}

#[test]
fn config_rejects_session_hover_timeout_above_max() {
    let mut config = GarrisonConfig::default_config();
    config.session_hover_timeout = 315_360_001;
    let result = config.validate();
    assert!(
        result.is_err(),
        "超过上界的 session_hover_timeout 应被配置校验拒绝"
    );
}

#[test]
fn config_accepts_session_hover_timeout_at_max() {
    let mut config = GarrisonConfig::default_config();
    config.session_hover_timeout = 315_360_000;
    assert!(
        config.validate().is_ok(),
        "等于上界的 session_hover_timeout 应被接受"
    );
}

// frontend_separation 配置测试

#[serial]
#[test]
fn config_default_frontend_separation_is_false() {
    let config = GarrisonConfig::default_config();
    assert!(!config.frontend_separation);
}

#[test]
#[serial]
fn env_overrides_frontend_separation() {
    let _env_guards = [EnvVarGuard::set("GARRISON_FRONTEND_SEPARATION", "true")];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert!(config.frontend_separation);
}

#[serial]
#[test]
fn validate_accepts_frontend_separation_true() {
    let mut config = GarrisonConfig::default_config();
    config.frontend_separation = true;
    assert!(config.validate().is_ok());
}

// toml 文件覆盖测试

#[test]
#[serial]
fn toml_overrides_token_style() {
    let temp = write_temp_toml(r#"token_style = "random_64""#);
    let config = GarrisonConfig::load(Some(temp.path().to_str().unwrap())).unwrap();
    assert_eq!(config.token_style, "random_64");
    assert_eq!(config.timeout, DEFAULT_TIMEOUT);
    assert!(config.throw_on_not_login);
}

#[test]
#[serial]
fn toml_overrides_multiple_fields() {
    let temp = write_temp_toml(
        r#"
token_style = "jwt"
timeout = 1800
is_read_cookie = false
throw_on_not_login = false
jwt_secret = "test-secret-0123456789abcdefghij"
"#,
    );
    let config = GarrisonConfig::load(Some(temp.path().to_str().unwrap())).unwrap();
    assert_eq!(config.token_style, "jwt");
    assert_eq!(config.timeout, 1800);
    assert!(!config.is_read_cookie);
    assert!(!config.throw_on_not_login);
    assert_eq!(config.token_name, DEFAULT_TOKEN_NAME);
    assert!(config.is_read_header);
}

#[test]
#[serial]
fn no_file_returns_default() {
    let config = GarrisonConfig::load(None).unwrap();
    assert_eq!(config.token_style, "uuid");
    assert_eq!(config.timeout, DEFAULT_TIMEOUT);
}

#[serial]
#[test]
fn invalid_toml_returns_config_error() {
    let temp = write_temp_toml("this is not = valid = toml =");
    let result = GarrisonConfig::load(Some(temp.path().to_str().unwrap()));
    assert!(result.is_err());
    assert!(matches!(result, Err(GarrisonError::Config(_))));
}

#[serial]
#[test]
fn toml_invalid_token_style_rejected() {
    let temp = write_temp_toml(r#"token_style = "unknown""#);
    let result = GarrisonConfig::load(Some(temp.path().to_str().unwrap()));
    assert!(result.is_err());
    assert!(matches!(result, Err(GarrisonError::Config(_))));
}

// 环境变量覆盖测试

#[test]
#[serial]
fn env_overrides_toml() {
    let _env_guards = [
        EnvVarGuard::set("GARRISON_TIMEOUT", "3600"),
        EnvVarGuard::set("GARRISON_TOKEN_STYLE", "jwt"),
    ];

    let temp = write_temp_toml(
        r#"timeout = 1800
jwt_secret = "test-secret-0123456789abcdefghij""#,
    );
    let config = GarrisonConfig::load(Some(temp.path().to_str().unwrap())).unwrap();

    assert_eq!(config.timeout, 3600);
    assert_eq!(config.token_style, "jwt");
}

#[test]
#[serial]
fn env_boolean_parsing() {
    let _env_guards = [
        EnvVarGuard::set("GARRISON_IS_READ_COOKIE", "false"),
        EnvVarGuard::set("GARRISON_THROW_ON_NOT_LOGIN", "false"),
    ];

    let config = GarrisonConfig::load(None).unwrap();

    assert!(!config.is_read_cookie);
    assert!(!config.throw_on_not_login);
}

#[test]
#[serial]
fn env_invalid_value_errors() {
    let _env_guards = [EnvVarGuard::set("GARRISON_TIMEOUT", "not-a-number")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err());
}

#[test]
#[serial]
fn load_full_pipeline() {
    let _env_guards = [EnvVarGuard::set("GARRISON_TOKEN_NAME", "custom_token")];
    let temp = write_temp_toml(r#"timeout = 3600"#);
    let config = GarrisonConfig::load(Some(temp.path().to_str().unwrap())).unwrap();
    assert_eq!(config.token_name, "custom_token");
    assert_eq!(config.timeout, 3600);
    assert_eq!(config.token_style, "uuid");
}

// 热更新测试

#[test]
fn watch_and_update_broadcasts() {
    let config = GarrisonConfig::default_config();
    let mut rx = config.watch().expect("default_config 应有 watcher");

    config.update(|c| c.timeout = 3600).expect("update 应成功");

    let new_config = rx.borrow_and_update();
    assert_eq!(new_config.timeout, 3600);
}

#[test]
#[cfg_attr(not(feature = "protocol-zeroize"), allow(clippy::useless_conversion))]
fn update_modifies_multiple_fields() {
    let config = GarrisonConfig::default_config();
    let mut rx = config.watch().unwrap();

    config
        .update(|c| {
            c.timeout = 7200;
            c.token_style = "jwt".to_string();
            c.jwt_secret = "test-secret-0123456789abcdefghij".to_string().into();
            c.throw_on_not_login = false;
        })
        .unwrap();

    let new_config = rx.borrow_and_update();
    assert_eq!(new_config.timeout, 7200);
    assert_eq!(new_config.token_style, "jwt");
    assert!(!new_config.throw_on_not_login);
}

#[test]
fn update_rejects_invalid_value() {
    let config = GarrisonConfig::default_config();
    let mut rx = config.watch().unwrap();

    let result = config.update(|c| c.token_style = "invalid".to_string());
    assert!(result.is_err());

    let current = rx.borrow_and_update();
    assert_eq!(current.token_style, "uuid");
}

#[test]
fn update_rejects_negative_timeout() {
    let config = GarrisonConfig::default_config();
    let mut rx = config.watch().unwrap();

    let result = config.update(|c| c.timeout = -1);
    assert!(result.is_err());

    let current = rx.borrow_and_update();
    assert_eq!(current.timeout, DEFAULT_TIMEOUT);
}

/// default_config() 后移除 watcher 构造"未启用 watcher"实例（不罗列全部字段，新增字段即编译失败）。
#[test]
fn update_without_watcher_is_noop() {
    let mut config = GarrisonConfig::default_config();
    // 移除 default_config() 附加的 watcher，构造"未启用 watcher"实例
    config.watcher = None;
    assert!(config.update(|c| c.timeout = 999).is_ok());
    assert!(config.watch().is_none());
}

// 序列化测试

#[test]
fn serialize_deserialize_toml_roundtrip() {
    let mut config = GarrisonConfig::default_config();
    config.timeout = 7200;
    config.token_style = "jwt".to_string();

    let toml_str = toml::to_string(&config).expect("toml 序列化应成功");
    assert!(toml_str.contains("timeout = 7200"));
    assert!(toml_str.contains("token_style = \"jwt\""));

    let parsed: GarrisonConfig = toml::from_str(&toml_str).expect("toml 反序列化应成功");
    assert_eq!(parsed.timeout, 7200);
    assert_eq!(parsed.token_style, "jwt");
}

#[test]
fn serialize_deserialize_json_roundtrip() {
    let mut config = GarrisonConfig::default_config();
    config.timeout = 1800;
    config.is_read_cookie = false;

    let json_str = serde_json::to_string(&config).expect("json 序列化应成功");
    assert!(json_str.contains("\"timeout\":1800"));
    assert!(json_str.contains("\"is_read_cookie\":false"));

    let parsed: GarrisonConfig = serde_json::from_str(&json_str).expect("json 反序列化应成功");
    assert_eq!(parsed.timeout, 1800);
    assert!(!parsed.is_read_cookie);
}

#[test]
fn watcher_not_serialized() {
    let config = GarrisonConfig::default_config();
    let json_str = serde_json::to_string(&config).unwrap();
    assert!(!json_str.contains("watcher"));
    assert!(!json_str.contains("sender"));
}

// 环境变量覆盖错误路径测试（confers 处理，错误类型为 Config）

#[test]
#[serial]
fn env_invalid_is_read_cookie_errors() {
    let _env_guards = [EnvVarGuard::set("GARRISON_IS_READ_COOKIE", "maybe")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err(), "非法布尔值应导致 load 失败");
    assert!(matches!(result, Err(GarrisonError::Config(_))));
}

#[test]
#[serial]
fn env_invalid_is_read_header_errors() {
    let _env_guards = [EnvVarGuard::set("GARRISON_IS_READ_HEADER", "yesno")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err());
    assert!(matches!(result, Err(GarrisonError::Config(_))));
}

#[test]
#[serial]
fn env_invalid_is_write_header_errors() {
    let _env_guards = [EnvVarGuard::set("GARRISON_IS_WRITE_HEADER", "unknown")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err());
    assert!(matches!(result, Err(GarrisonError::Config(_))));
}

#[test]
#[serial]
fn env_invalid_throw_on_not_login_errors() {
    let _env_guards = [EnvVarGuard::set("GARRISON_THROW_ON_NOT_LOGIN", "yes_no")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err());
    assert!(matches!(result, Err(GarrisonError::Config(_))));
}

#[test]
#[serial]
fn env_invalid_active_timeout_errors() {
    let _env_guards = [EnvVarGuard::set("GARRISON_ACTIVE_TIMEOUT", "not-a-number")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err());
}

#[test]
#[serial]
fn env_invalid_token_style_fails_validation() {
    let _env_guards = [EnvVarGuard::set("GARRISON_TOKEN_STYLE", "unknown_style")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err());
    assert!(
        matches!(result, Err(GarrisonError::Config(ref msg)) if msg.contains("config-unknown-token-style")),
        "应返回 'config-unknown-token-style' 错误，实际: {:?}",
        result
    );
}

#[test]
#[serial]
fn env_negative_timeout_fails_validation() {
    let _env_guards = [EnvVarGuard::set("GARRISON_TIMEOUT", "-100")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err());
    assert!(
        matches!(result, Err(GarrisonError::Config(ref msg)) if msg.contains("config-timeout-must-positive")),
        "应返回 'config-timeout-must-positive' 错误，实际: {:?}",
        result
    );
}

// 字段环境变量覆盖测试

#[test]
#[serial]
fn env_overrides_jwt_algorithm() {
    let _env_guards = [EnvVarGuard::set(
        format!("{}JWT_ALGORITHM", ENV_PREFIX),
        "HS512",
    )];
    let config = GarrisonConfig::load(None).unwrap();
    assert_eq!(config.jwt_algorithm, "HS512");
}

#[test]
#[serial]
fn env_overrides_sign_window_seconds() {
    let _env_guards = [EnvVarGuard::set(
        format!("{}SIGN_WINDOW_SECONDS", ENV_PREFIX),
        "600",
    )];
    let config = GarrisonConfig::load(None).unwrap();
    assert_eq!(config.sign_window_seconds, 600);
}

#[test]
#[serial]
fn env_overrides_sso_ticket_ttl_seconds() {
    let _env_guards = [EnvVarGuard::set(
        format!("{}SSO_TICKET_TTL_SECONDS", ENV_PREFIX),
        "120",
    )];
    let config = GarrisonConfig::load(None).unwrap();
    assert_eq!(config.sso_ticket_ttl_seconds, 120);
}

#[test]
#[serial]
fn env_overrides_sign_window_seconds_invalid() {
    let _env_guards = [EnvVarGuard::set(
        format!("{}SIGN_WINDOW_SECONDS", ENV_PREFIX),
        "not-a-number",
    )];
    let result = GarrisonConfig::load(None);
    assert!(
        result.is_err(),
        "非数字 SIGN_WINDOW_SECONDS 应导致 load 失败"
    );
}

#[test]
#[serial]
fn env_overrides_sso_ticket_ttl_seconds_invalid() {
    let _env_guards = [EnvVarGuard::set(
        format!("{}SSO_TICKET_TTL_SECONDS", ENV_PREFIX),
        "abc",
    )];
    let result = GarrisonConfig::load(None);
    assert!(
        result.is_err(),
        "非数字 SSO_TICKET_TTL_SECONDS 应导致 load 失败"
    );
}

// tenant_isolation 配置段测试

#[cfg(feature = "tenant-isolation")]
#[test]
fn garrison_config_includes_tenant_isolation_section() {
    let json = r#"{
            "tenant_isolation": {
                "enabled": true,
                "resolver": "header"
            }
        }"#;
    let config: GarrisonConfig = serde_json::from_str(json).unwrap();
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

#[cfg(feature = "tenant-isolation")]
#[test]
fn tenant_isolation_config_defaults_to_disabled() {
    let config = GarrisonConfig::default_config();
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

// auto_renewal_threshold 配置测试

#[test]
fn config_default_auto_renewal_is_negative_one() {
    let config = GarrisonConfig::default_config();
    assert_eq!(config.auto_renewal_threshold, -1);
}

#[test]
fn validate_rejects_threshold_above_100() {
    let mut config = GarrisonConfig::default_config();
    config.auto_renewal_threshold = 101;
    let result = config.validate();
    assert!(result.is_err());
    match result {
        Err(GarrisonError::Config(msg)) => {
            assert!(
                msg.contains("config-auto-renewal-threshold-invalid"),
                "错误消息应包含范围提示，实际: {}",
                msg
            );
        },
        Err(other) => panic!("期望 GarrisonError::Config，实际: {:?}", other),
        Ok(_) => panic!("threshold=101 时应返回 Err"),
    }
}

#[test]
fn validate_rejects_threshold_below_negative_one() {
    let mut config = GarrisonConfig::default_config();
    config.auto_renewal_threshold = -2;
    assert!(config.validate().is_err());
}

#[test]
fn validate_accepts_threshold_boundaries() {
    for &threshold in &[-1i64, 0, 100] {
        let mut config = GarrisonConfig::default_config();
        config.auto_renewal_threshold = threshold;
        assert!(
            config.validate().is_ok(),
            "threshold={} 应通过校验",
            threshold
        );
    }
}

#[test]
#[serial]
fn env_overrides_auto_renewal_threshold() {
    let _env_guards = [EnvVarGuard::set("GARRISON_AUTO_RENEWAL_THRESHOLD", "20")];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert_eq!(config.auto_renewal_threshold, 20);
}

// token_map_cleanup_interval_secs 配置测试

#[test]
fn token_map_cleanup_interval_default_is_300() {
    let config = GarrisonConfig::default_config();
    assert_eq!(
        config.token_map_cleanup_interval_secs, 300,
        "默认 token_map_cleanup_interval_secs 应为 300（5 分钟）"
    );
    assert_eq!(
        config.token_map_cleanup_interval_secs, DEFAULT_TOKEN_MAP_CLEANUP_INTERVAL,
        "应等于 DEFAULT_TOKEN_MAP_CLEANUP_INTERVAL 常量"
    );
}

#[test]
fn token_map_cleanup_interval_custom_value() {
    let mut config = GarrisonConfig::default_config();
    config.token_map_cleanup_interval_secs = 600;
    assert_eq!(config.token_map_cleanup_interval_secs, 600);
    assert!(
        config.validate().is_ok(),
        "token_map_cleanup_interval_secs=600 应通过校验"
    );
}

#[test]
fn token_map_cleanup_interval_negative_disables() {
    let mut config = GarrisonConfig::default_config();
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

/// env 名按仓库惯例与字段名严格对应（`token_map_cleanup_interval_secs` ↔ `GARRISON_TOKEN_MAP_CLEANUP_INTERVAL_SECS`）。
#[test]
#[serial]
fn token_map_cleanup_interval_env_var_overrides() {
    let _env_guards = [EnvVarGuard::set(
        "GARRISON_TOKEN_MAP_CLEANUP_INTERVAL_SECS",
        "600",
    )];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert_eq!(
        config.token_map_cleanup_interval_secs, 600,
        "GARRISON_TOKEN_MAP_CLEANUP_INTERVAL_SECS=600 应覆盖默认值"
    );
}

// login_token_map_persist_interval_secs 配置测试

#[cfg(feature = "session-extra")]
#[test]
fn login_token_map_persist_interval_default_is_zero() {
    let config = GarrisonConfig::default_config();
    assert_eq!(
        config.login_token_map_persist_interval_secs, 0,
        "默认 login_token_map_persist_interval_secs 应为 0（同步写入）"
    );
    assert_eq!(
        config.login_token_map_persist_interval_secs, DEFAULT_LOGIN_TOKEN_MAP_PERSIST_INTERVAL_SECS,
        "应等于 DEFAULT_LOGIN_TOKEN_MAP_PERSIST_INTERVAL_SECS 常量"
    );
}

#[cfg(feature = "session-extra")]
#[test]
#[serial]
fn login_token_map_persist_interval_env_var_overrides() {
    let _env_guards = [EnvVarGuard::set(
        "GARRISON_LOGIN_TOKEN_MAP_PERSIST_INTERVAL_SECS",
        "10",
    )];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert_eq!(
        config.login_token_map_persist_interval_secs, 10,
        "GARRISON_LOGIN_TOKEN_MAP_PERSIST_INTERVAL_SECS=10 应覆盖默认值"
    );
}

// anon_session_timeout 配置测试

#[cfg(feature = "session-extra")]
#[test]
fn anon_session_timeout_default_is_1800() {
    let config = GarrisonConfig::default_config();
    assert_eq!(
        config.anon_session_timeout, 1800,
        "默认 anon_session_timeout 应为 1800（30 分钟）"
    );
    assert_eq!(
        config.anon_session_timeout, DEFAULT_ANON_SESSION_TIMEOUT_SECS,
        "应等于 DEFAULT_ANON_SESSION_TIMEOUT_SECS 常量"
    );
}

#[cfg(feature = "session-extra")]
#[test]
#[serial]
fn anon_session_timeout_env_var_overrides() {
    let _env_guards = [EnvVarGuard::set("GARRISON_ANON_SESSION_TIMEOUT", "3600")];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert_eq!(
        config.anon_session_timeout, 3600,
        "GARRISON_ANON_SESSION_TIMEOUT=3600 应覆盖默认值"
    );
}

// 并发登录控制配置测试

#[test]
fn config_default_is_concurrent_true() {
    let config = GarrisonConfig::default_config();
    assert!(config.is_concurrent, "默认允许并发登录");
}

#[test]
fn config_default_is_share_false() {
    let config = GarrisonConfig::default_config();
    assert!(!config.is_share, "默认不共享 token");
}

#[test]
fn config_default_max_login_count_zero() {
    let config = GarrisonConfig::default_config();
    assert_eq!(config.max_login_count, 0, "默认不限制登录数量");
}

#[test]
fn validate_rejects_share_without_concurrent() {
    let mut config = GarrisonConfig::default_config();
    config.is_concurrent = false;
    config.is_share = true;
    let result = config.validate();
    assert!(result.is_err());
    match result {
        Err(GarrisonError::Config(msg)) => {
            assert!(
                msg.contains("config-is-share-requires-concurrent"),
                "错误消息应包含约束提示，实际: {}",
                msg
            );
        },
        Err(other) => panic!("期望 GarrisonError::Config，实际: {:?}", other),
        Ok(_) => panic!("is_share=true + is_concurrent=false 时应返回 Err"),
    }
}

#[test]
fn validate_accepts_share_with_concurrent() {
    let mut config = GarrisonConfig::default_config();
    config.is_concurrent = true;
    config.is_share = true;
    assert!(config.validate().is_ok());
}

#[test]
#[serial]
fn env_overrides_is_concurrent() {
    let _env_guards = [EnvVarGuard::set("GARRISON_IS_CONCURRENT", "false")];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert!(!config.is_concurrent);
}

#[test]
#[serial]
fn env_overrides_max_login_count() {
    let _env_guards = [EnvVarGuard::set("GARRISON_MAX_LOGIN_COUNT", "3")];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert_eq!(config.max_login_count, 3);
}

// is_read_body 配置测试

#[test]
fn config_default_is_read_body_is_false() {
    let config = GarrisonConfig::default_config();
    assert!(!config.is_read_body, "默认 is_read_body 应为 false");
    assert_eq!(
        config.is_read_body, DEFAULT_IS_READ_BODY,
        "应等于 DEFAULT_IS_READ_BODY 常量"
    );
}

#[test]
#[serial]
fn env_overrides_is_read_body() {
    let _env_guards = [EnvVarGuard::set("GARRISON_IS_READ_BODY", "true")];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert!(
        config.is_read_body,
        "GARRISON_IS_READ_BODY=true 应覆盖为 true"
    );
}

// device_binding_mode 配置测试

#[test]
fn test_device_binding_mode_default() {
    let config = GarrisonConfig::default_config();
    assert_eq!(
        config.device_binding_mode, "disabled",
        "默认 device_binding_mode 应为 'disabled'"
    );
}

#[test]
fn test_device_binding_mode_custom() {
    let mut config = GarrisonConfig::default_config();
    config.device_binding_mode = "strict".to_string();
    assert!(
        config.validate().is_ok(),
        "device_binding_mode='strict' 应通过校验"
    );
}

#[test]
fn test_device_binding_mode_invalid() {
    let mut config = GarrisonConfig::default_config();
    config.device_binding_mode = "invalid".to_string();
    let result = config.validate();
    assert!(result.is_err(), "device_binding_mode='invalid' 应校验失败");
    match result {
        Err(GarrisonError::Config(msg)) => {
            assert!(
                msg.contains("config-unknown-device-binding-mode"),
                "错误消息应包含 config-unknown-device-binding-mode，实际: {}",
                msg
            );
        },
        Err(other) => panic!("期望 GarrisonError::Config，实际: {:?}", other),
        Ok(_) => panic!("device_binding_mode='invalid' 时应返回 Err"),
    }
}

#[test]
#[serial]
fn test_device_binding_mode_env_override() {
    let _env_guards = [EnvVarGuard::set("GARRISON_DEVICE_BINDING_MODE", "loose")];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert_eq!(
        config.device_binding_mode, "loose",
        "环境变量应覆盖 device_binding_mode 为 'loose'"
    );
}

// validate() redis_url 非空校验测试

#[cfg(feature = "rate-limit-redis")]
#[test]
fn validate_rejects_empty_redis_url() {
    let mut config = GarrisonConfig::default_config();
    config.rate_limit_backend = RateLimitBackend::Redis {
        redis_url: String::new(),
    };
    let err = config.validate().unwrap_err();
    assert!(
        matches!(err, GarrisonError::Config(ref m) if m.contains("config-redis-url-empty")),
        "空 redis_url 应被 validate 拒绝，实际错误: {:?}",
        err
    );
}

#[cfg(feature = "rate-limit-redis")]
#[test]
fn validate_accepts_non_empty_redis_url() {
    let mut config = GarrisonConfig::default_config();
    config.rate_limit_backend = RateLimitBackend::Redis {
        redis_url: "redis://127.0.0.1:6379/0".to_string(),
    };
    assert!(config.validate().is_ok(), "非空 redis_url 应通过 validate");
}

#[cfg(feature = "rate-limit-redis")]
#[test]
fn validate_memory_backend_skips_redis_url_check() {
    let config = GarrisonConfig::default_config();
    assert_eq!(config.rate_limit_backend, RateLimitBackend::Memory);
    assert!(config.validate().is_ok(), "Memory 后端应通过 validate");
}

// 环境变量覆盖测试

#[cfg(feature = "web-cors")]
#[test]
#[serial]
fn env_overrides_cors_allowed_origins() {
    let _env_guards = [EnvVarGuard::set(
        "GARRISON_CORS_ALLOWED_ORIGINS",
        "https://a.com,https://b.com",
    )];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert_eq!(
        config.cors_config.allowed_origins,
        vec!["https://a.com", "https://b.com"]
    );
}

#[cfg(feature = "web-cors")]
#[test]
#[serial]
fn env_cors_origins_filters_empty_values() {
    let _env_guards = [EnvVarGuard::set(
        "GARRISON_CORS_ALLOWED_ORIGINS",
        "https://a.com,,https://b.com,",
    )];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert_eq!(
        config.cors_config.allowed_origins,
        vec!["https://a.com", "https://b.com"],
        "空值应被过滤"
    );
}

#[cfg(feature = "web-csrf")]
#[test]
#[serial]
fn env_overrides_csrf_enabled() {
    let _env_guards = [EnvVarGuard::set("GARRISON_CSRF_ENABLED", "true")];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert!(
        config.csrf_config.enabled,
        "GARRISON_CSRF_ENABLED=true 应启用 CSRF"
    );
}

/// `GARRISON_CSRF_ENABLED` 仅接受 true/false（大小写不敏感，fail-closed 对齐 `GARRISON_RATE_LIMIT_BACKEND`）。
#[cfg(feature = "web-csrf")]
#[test]
#[serial]
fn env_csrf_enabled_accepts_true_false_case_insensitive() {
    for (raw, expected) in [("TRUE", true), ("False", false), ("false", false)] {
        let _guard = EnvVarGuard::set("GARRISON_CSRF_ENABLED", raw);
        let config = GarrisonConfig::load(None).expect("合法布尔值 load 应成功");
        assert_eq!(
            config.csrf_config.enabled, expected,
            "GARRISON_CSRF_ENABLED={raw} 应生效为 {expected}"
        );
    }
}

/// 非 true/false 值返回 Config 硬错误（fail-closed）："1"/"yes"/"on" 等 truthy 习惯值不得静默禁用 CSRF 防护。
#[cfg(feature = "web-csrf")]
#[test]
#[serial]
fn env_csrf_enabled_invalid_value_fails_load() {
    for raw in ["1", "yes", "on", "garbage"] {
        let _guard = EnvVarGuard::set("GARRISON_CSRF_ENABLED", raw);
        match GarrisonConfig::load(None) {
            Err(GarrisonError::Config(msg)) => assert!(
                msg.contains("config-csrf-enabled-unsupported") && msg.contains(raw),
                "GARRISON_CSRF_ENABLED={raw} 应报错并回显原值，实际: {msg}"
            ),
            other => panic!("GARRISON_CSRF_ENABLED={raw} 应 load 失败，实际: {other:?}"),
        }
    }
}

// config-security-rules 安全规则集

/// feature 开启时弱密钥配置经 validate() 被拒（规则路径复用 JWT 强度+黑名单）。
#[cfg(feature = "config-security-rules")]
#[test]
fn security_rules_rejects_weak_jwt_secret() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    // 32 字节填充变体：过长度校验、命中黑名单，隔离出规则集自身的拒绝能力
    config.jwt_secret = format!("changeme{}", "_".repeat(24)).into();
    let err = config
        .validate()
        .expect_err("弱密钥应被 config-security-rules 拒绝");
    let display = err.to_string();
    assert!(
        display.contains("jwt_secret") && display.contains("blacklist"),
        "弱密钥 Display 应含密钥字段与命中原因，实际: {}",
        display
    );
}

#[cfg(all(feature = "config-security-rules", feature = "web-cors"))]
#[test]
fn security_rules_accepts_hardened_config() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_secret = "x".repeat(32).into();
    config.cors_config.allowed_origins = vec!["https://a.example".to_string()];
    config.cors_config.allow_credentials = true;
    assert!(config.validate().is_ok(), "加固配置应通过安全规则校验");
}

/// 通配 origin 未开 credentials：不拒绝（公开只读 API 合法）但必须落 warn（显性提示任意源可读响应）。
#[cfg(all(feature = "config-security-rules", feature = "web-cors"))]
#[test]
fn security_rules_warns_wildcard_origins_without_credentials() {
    let mut config = GarrisonConfig::default_config();
    config.cors_config.allowed_origins = vec!["*".to_string()];
    config.cors_config.allow_credentials = false;
    with_captured_deprecation_logs(|logs| {
        config
            .validate()
            .expect("通配 origin 无 credentials 应放行");
        let lines = logs.lock().expect("日志缓冲锁应可用");
        assert!(
            lines
                .iter()
                .any(|l| { l.contains("WARN") && l.contains("allowed_origins=[\"*\"]") }),
            "通配 origin 应落风险警示 warn，实际日志: {:?}",
            *lines
        );
    });
}

/// feature 关闭时安全规则集不生效（零行为变化）：同样配置不产生 warn——与开启侧测试分别锁定两个 feature 形态。
#[cfg(all(not(feature = "config-security-rules"), feature = "web-cors"))]
#[test]
fn security_rules_disabled_no_rule_warnings() {
    let mut config = GarrisonConfig::default_config();
    config.cors_config.allowed_origins = vec!["*".to_string()];
    with_captured_deprecation_logs(|logs| {
        config.validate().expect("关闭规则集不应改变校验结果");
        let lines = logs.lock().expect("日志缓冲锁应可用");
        assert!(
            !lines.iter().any(|l| l.contains("allowed_origins=[\"*\"]")),
            "feature 关闭时不应有安全规则集 warn，实际日志: {:?}",
            *lines
        );
    });
}

#[cfg(feature = "rate-limit-redis")]
#[test]
#[serial]
fn env_overrides_rate_limit_backend_to_redis() {
    let _env_guards = [
        EnvVarGuard::set("GARRISON_RATE_LIMIT_BACKEND", "redis"),
        EnvVarGuard::set("GARRISON_REDIS_URL", "redis://localhost:6379/0"),
    ];
    let config = GarrisonConfig::load(None).expect("load with env");
    match config.rate_limit_backend {
        RateLimitBackend::Redis { redis_url } => {
            assert_eq!(redis_url, "redis://localhost:6379/0");
        },
        _ => panic!("应为 Redis 后端"),
    }
}

#[cfg(feature = "rate-limit-redis")]
#[test]
#[serial]
fn env_overrides_rate_limit_backend_to_memory() {
    let _env_guards = [EnvVarGuard::set("GARRISON_RATE_LIMIT_BACKEND", "memory")];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert_eq!(
        config.rate_limit_backend,
        RateLimitBackend::Memory,
        "应为 Memory 后端"
    );
}

#[cfg(feature = "rate-limit-redis")]
#[test]
#[serial]
fn env_redis_url_alone_does_not_change_memory_backend() {
    let _env_guards = [EnvVarGuard::set(
        "GARRISON_REDIS_URL",
        "redis://localhost:6379/0",
    )];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert_eq!(
        config.rate_limit_backend,
        RateLimitBackend::Memory,
        "仅设 REDIS_URL 不应改变 Memory 后端"
    );
}

#[cfg(feature = "rate-limit-redis")]
#[test]
#[serial]
fn env_rate_limit_backend_invalid_value_returns_error() {
    let _env_guards = [EnvVarGuard::set("GARRISON_RATE_LIMIT_BACKEND", "mysql")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err(), "无效 backend 值应返回错误");
    let err = result.unwrap_err();
    match err {
        GarrisonError::Config(msg) => {
            assert!(
                msg.contains("config-rate-limit-backend-unsupported"),
                "错误消息应包含 config-rate-limit-backend-unsupported"
            );
            assert!(msg.contains("mysql"), "错误消息应包含无效值");
        },
        _ => panic!("应为 GarrisonError::Config，实际: {:?}", err),
    }
}

// 并发登录策略枚举配置测试

#[test]
fn config_default_replaced_login_exit_mode_is_old_device() {
    let config = GarrisonConfig::default_config();
    assert_eq!(
        config.replaced_login_exit_mode,
        ReplacedLoginExitMode::OldDevice,
        "默认 replaced_login_exit_mode 应为 OldDevice"
    );
}

#[test]
fn config_default_overflow_logout_mode_is_logout() {
    let config = GarrisonConfig::default_config();
    assert_eq!(
        config.overflow_logout_mode,
        OverflowLogoutMode::Logout,
        "默认 overflow_logout_mode 应为 Logout"
    );
}

#[test]
fn replaced_login_exit_mode_serde_snake_case() {
    let old_json =
        serde_json::to_string(&ReplacedLoginExitMode::OldDevice).expect("序列化 OldDevice 应成功");
    assert_eq!(old_json, r#""old_device""#);
    let new_json =
        serde_json::to_string(&ReplacedLoginExitMode::NewDevice).expect("序列化 NewDevice 应成功");
    assert_eq!(new_json, r#""new_device""#);

    let old: ReplacedLoginExitMode =
        serde_json::from_str(r#""old_device""#).expect("反序列化 old_device 应成功");
    assert_eq!(old, ReplacedLoginExitMode::OldDevice);
    let new: ReplacedLoginExitMode =
        serde_json::from_str(r#""new_device""#).expect("反序列化 new_device 应成功");
    assert_eq!(new, ReplacedLoginExitMode::NewDevice);
}

#[test]
fn overflow_logout_mode_serde_snake_case() {
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

#[test]
#[serial]
fn env_overrides_replaced_login_exit_mode() {
    let _env_guards = [EnvVarGuard::set(
        "GARRISON_REPLACED_LOGIN_EXIT_MODE",
        "new_device",
    )];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert_eq!(
        config.replaced_login_exit_mode,
        ReplacedLoginExitMode::NewDevice,
        "GARRISON_REPLACED_LOGIN_EXIT_MODE=new_device 应覆盖为 NewDevice"
    );
}

#[test]
#[serial]
fn env_overrides_overflow_logout_mode() {
    let _env_guards = [EnvVarGuard::set("GARRISON_OVERFLOW_LOGOUT_MODE", "kickout")];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert_eq!(
        config.overflow_logout_mode,
        OverflowLogoutMode::Kickout,
        "GARRISON_OVERFLOW_LOGOUT_MODE=kickout 应覆盖为 Kickout"
    );
}

// recent_reuse_behaviour / refresh_grace 配置测试

#[test]
fn default_recent_reuse_behaviour_is_theft_detected() {
    let config = GarrisonConfig::default_config();
    assert_eq!(
        config.recent_reuse_behaviour,
        RecentReuseBehaviour::TheftDetected,
        "默认 recent_reuse_behaviour 应为 TheftDetected"
    );
}

#[test]
fn recent_reuse_behaviour_serde_snake_case() {
    assert_eq!(
        serde_json::to_string(&RecentReuseBehaviour::TheftDetected).unwrap(),
        r#""theft_detected""#
    );
    assert_eq!(
        serde_json::to_string(&RecentReuseBehaviour::Unauthorised).unwrap(),
        r#""unauthorised""#
    );
    assert_eq!(
        serde_json::from_str::<RecentReuseBehaviour>(r#""theft_detected""#).unwrap(),
        RecentReuseBehaviour::TheftDetected
    );
    assert_eq!(
        serde_json::from_str::<RecentReuseBehaviour>(r#""unauthorised""#).unwrap(),
        RecentReuseBehaviour::Unauthorised
    );
    // 白名单外的值反序列化失败（fail-closed）
    assert!(serde_json::from_str::<RecentReuseBehaviour>(r#""permissive""#).is_err());
}

#[test]
#[serial]
fn env_overrides_recent_reuse_behaviour() {
    let _env_guards = [EnvVarGuard::set(
        "GARRISON_RECENT_REUSE_BEHAVIOUR",
        "unauthorised",
    )];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert_eq!(
        config.recent_reuse_behaviour,
        RecentReuseBehaviour::Unauthorised,
        "GARRISON_RECENT_REUSE_BEHAVIOUR=unauthorised 应覆盖为 Unauthorised"
    );
}

#[test]
#[serial]
fn env_invalid_recent_reuse_behaviour_errors() {
    let _env_guards = [EnvVarGuard::set(
        "GARRISON_RECENT_REUSE_BEHAVIOUR",
        "permissive",
    )];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err(), "非法重用处置策略应导致启动失败");
    assert!(matches!(result, Err(GarrisonError::Config(_))));
}

#[test]
fn default_refresh_grace_window_is_disabled() {
    let config = GarrisonConfig::default_config();
    assert_eq!(
        config.refresh_grace_period_secs, 0,
        "默认 refresh_grace_period_secs 应为 0（关闭）"
    );
    assert_eq!(
        config.refresh_grace_max_uses, 1,
        "默认 refresh_grace_max_uses 应为 1"
    );
}

#[test]
fn negative_refresh_grace_period_fails_validation() {
    let mut config = GarrisonConfig::default_config();
    config.refresh_grace_period_secs = -1;
    let result = config.validate();
    assert!(
        matches!(result, Err(GarrisonError::Config(ref msg)) if msg.contains("grace-period-negative")),
        "负宽限窗口应校验失败，实际: {:?}",
        result
    );
}

#[test]
fn zero_refresh_grace_max_uses_fails_validation() {
    let mut config = GarrisonConfig::default_config();
    config.refresh_grace_max_uses = 0;
    let result = config.validate();
    assert!(
        matches!(result, Err(GarrisonError::Config(ref msg)) if msg.contains("grace-max-uses-zero")),
        "零兑现次数应校验失败，实际: {:?}",
        result
    );
}

#[test]
#[serial]
fn env_overrides_refresh_grace_period_secs() {
    let _env_guards = [EnvVarGuard::set("GARRISON_REFRESH_GRACE_PERIOD_SECS", "30")];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert_eq!(
        config.refresh_grace_period_secs, 30,
        "GARRISON_REFRESH_GRACE_PERIOD_SECS=30 应覆盖宽限窗口"
    );
}

// audit_mask_mode 配置测试

#[test]
fn default_audit_mask_mode_is_partial() {
    let config = GarrisonConfig::default_config();
    assert_eq!(
        config.audit_mask_mode,
        AuditMaskMode::Partial,
        "默认 audit_mask_mode 应为 Partial"
    );
}

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

#[test]
#[serial]
fn env_overrides_audit_mask_mode() {
    let _env_guards = [EnvVarGuard::set("GARRISON_AUDIT_MASK_MODE", "full")];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert_eq!(
        config.audit_mask_mode,
        AuditMaskMode::Full,
        "GARRISON_AUDIT_MASK_MODE=full 应覆盖为 Full"
    );
}

// anomalous-detector-dual validate() 校验测试

#[cfg(feature = "anomalous-detector-dual")]
#[test]
fn validate_rejects_anomalous_interval_below_60() {
    let mut config = GarrisonConfig::default_config();
    config.anomalous_analyzer_interval_secs = 30;
    let err = config.validate().unwrap_err();
    assert!(
        matches!(err, GarrisonError::Config(ref m) if m.contains("config-anomalous-interval-invalid")),
        "interval=30 应被拒绝，实际: {:?}",
        err
    );
}

#[cfg(feature = "anomalous-detector-dual")]
#[test]
fn validate_accepts_anomalous_interval_at_60() {
    let mut config = GarrisonConfig::default_config();
    config.anomalous_analyzer_interval_secs = 60;
    assert!(config.validate().is_ok(), "interval=60 应通过 validate");
}

#[cfg(feature = "anomalous-detector-dual")]
#[test]
fn validate_rejects_zero_burst_threshold() {
    let mut config = GarrisonConfig::default_config();
    config.anomalous_analyzer_burst_threshold = 0;
    let err = config.validate().unwrap_err();
    assert!(
        matches!(err, GarrisonError::Config(ref m) if m.contains("config-anomalous-burst-invalid")),
        "burst_threshold=0 应被拒绝，实际: {:?}",
        err
    );
}

// 安全审查 load() 安全防护集成测试

#[test]
fn load_rejects_empty_path() {
    let err = GarrisonConfig::load(Some("")).unwrap_err();
    assert!(
        matches!(err, GarrisonError::Config(ref m) if m.contains("must not be empty")),
        "空路径应被拒绝，实际: {:?}",
        err
    );
}

/// `..` 路径遍历由 confers `check_path_components` 拒绝 ParentDir（错误文案为 confers 泛化格式）。
#[test]
fn load_rejects_path_traversal() {
    let err = GarrisonConfig::load(Some("../etc/passwd")).unwrap_err();
    assert!(
        matches!(err, GarrisonError::Config(ref m) if m.contains("config-open-failed")),
        "路径遍历 `..` 应被拒绝（红acted FileNotFound），实际: {:?}",
        err
    );
}

/// URL 编码遍历 `%2e%2e` 被上游路径验证前置扫描拒绝（防御纵深：fs 虽不解码，下游代理/网关可能解码）。
#[test]
fn load_url_encoded_traversal_returns_enoent() {
    let err = GarrisonConfig::load(Some("%2e%2e/etc/passwd")).unwrap_err();
    assert!(
        matches!(err, GarrisonError::Config(ref m) if m.contains("config-open-failed")),
        "%2e%2e 应被拒绝，实际: {:?}",
        err
    );
}

#[test]
fn load_rejects_oversized_config() {
    let dir = tempfile::tempdir().expect("创建临时目录失败");
    let path = dir.path().join("big.toml");
    // 写入 11MB 数据（>10MB 上限），用注释避免 TOML 解析失败
    let big_content = "# ".to_string() + &"x".repeat(11 * 1024 * 1024);
    std::fs::write(&path, big_content.as_bytes()).expect("写入大文件失败");
    let path_str = path.to_str().expect("路径转 str 失败");
    let err = GarrisonConfig::load(Some(path_str)).unwrap_err();
    assert!(
        matches!(err, GarrisonError::Config(ref m) if m.contains("too large")),
        "超大文件应被拒绝，实际: {:?}",
        err
    );
}

#[cfg(unix)]
#[test]
fn load_rejects_special_file() {
    // /dev/null 是字符设备，metadata.is_file() 返回 false
    let err = GarrisonConfig::load(Some("/dev/null")).unwrap_err();
    assert!(
        matches!(err, GarrisonError::Config(ref m) if m.contains("not a regular file")),
        "字符设备应被拒绝，实际: {:?}",
        err
    );
}

/// load 拒绝目录：Linux/macOS 由 `metadata.is_file()` 返回 false 触发，Windows `File::open` 直接 ERROR_ACCESS_DENIED——两条路径都达到拒绝目标，测试同时接受。
#[serial]
#[test]
fn load_rejects_directory() {
    let dir = tempfile::tempdir().expect("创建临时目录失败");
    let path_str = dir.path().to_str().expect("路径转 str 失败");
    let err = GarrisonConfig::load(Some(path_str)).unwrap_err();
    assert!(
        matches!(err, GarrisonError::Config(ref m) if m.contains("not a regular file") || m.contains("config-open-failed")),
        "目录应被拒绝（Linux 走 is_file 检查 / Windows 走 File::open EACCES 经 config-open-failed），实际: {:?}",
        err
    );
}

// JWT 非对称配置扩展（RS256/ES256/EdDSA）

/// 测试专用 RSA 2048 私钥（PKCS#8，非真实凭证）。
// nosemgrep: generic.secrets.security.detected-private-key.detected-private-key —— CI 已验证的测试夹具 PEM（假钥，非真实凭证）
const TEST_ASYM_RSA_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDMQoXOvmvs4kpj
nYshns5CYyNziLt/xBQBZtlkzY3KUuHtJMz9zK0TTz0DbhCnDCWF8tpWqxHBTtON
pMnnC6bTN4Wg/PWDn67hub23b4xAKq5qH45RmWn4a0TGTUyQktebjlCiWBlMCo43
j7FLyvGrOx3SmyUUaI5vh02Pf5Swg2CCQ69ht3L58jM6lp+jILJ4gEjNC2hmaWgH
bbYhTX5qCaPgZTndfgPXX9wkDG8jhpgRpfwmSuJ4aRiRrjvgycWuPccryX7aXiBU
c5H8rdKVgnjPTzSL8h3P/2tpZkNj5OFBZKTgmdPuwF87Mjlbr7Oi2xpCIpNpnyF1
L8G/mIIRAgMBAAECggEAY2vnzIOEbceRtN4cuC8fr1GpElXWCfELWclRfI7O+tGP
9YlpnAmxnsn9ZTuAMIcphoL4QqI+4Kw5LeMtgV/7AikuyncGG9ywV1+819ocVqlP
vwkAEXjOi2PPFITQhThsaOODHRorqgcjRSkUf9NXAWUjdX0dtcrUtbWSi4vqeGWC
O0Ni/9iWJYFjAgHu+XJgYXZtn7sJGe30PuIFmiKHfHuuM9alo6SubQ3UU80B+hQm
N4VVuYN+dYmGsekp+Ofj65mq2+WAyvHE2V9OB92L+yVY0uKZ428eXdN9ydp8kVqh
yOW2yLTq6sBNBOi/F/DMim6QrIzn6zpp0hXyc97d1wKBgQD+2qQOQ+urTE1ymdXT
C/os5kMrjsYd/rfcMaBbl4XmDE/PjlJg1Z6yVBGMmvM/shjTslcV8kgKyKf+aHm1
b3ckgu9PLtoYGX0yjeHbYCidwkjJPz8sy5pIFHslY/bGhV5RqsSPJo1aX2En0c4R
3cJHGGGn2YguQuWSOU94VTKgowKBgQDNLaS9Q08j/tiozEY23oH9i5p5iSwxc3It
hS/UwLYNFad6byRiDgVlvx+sVHZfLBsmNMlHEY+oMGocctqGAC8+a0pvtaLnU12/
GI61axWfAlCJrYs3CBOKwOH3hBM04mqPUb2ySHdlzPawpIr55jMkohuXXyw/22je
pK7iIPHZuwKBgQC+/Gi/TAUbjQXpIQHNtAcaiMDDrq4nolB00jfjC81LVeSlnXl8
mfngmAHCxggOrs/OLbL3fmagtji2/eJfppW5penjBDBqqQda0Fr2xLwLZaKYNi6I
ylfnNnoGzkAMC7xgJUJCKNj7ZcjwR1lPqElEcDAW0n0sdfOGvi4g9nAHUwKBgGIB
E1dz9zFyYXr/V+qNjfnV3QuAgiN8yWUE4Tv2cP7/AOhyfiZ4HAvlpvNhxMjhAHbX
b+0KblwgBA9irQ6kt+xQw1VopU9perX0vPXbGJDDQkUBKCY5LVxxlX3tEF+KZuve
V4X5J07xAESP0/JaCsPMyvEa/L/jxcvTTdWlduBRAoGBAPx2MMqUGXa+UZ+a0cyF
tW0xGglEWCX+e2vSNf31v4FyoGxNi6h2ap2OWEddpGttS+UbOzO9BlzcCtYJvPwW
lRVGEQXEoVyslCUwTlV8LmtrJS6Xl9YwRHmmajJMH6GJTk/CToOLIvj2bOMxHW5A
dzWfBsm+KAfTJuqbV7VnJL3G
-----END PRIVATE KEY-----
";

#[test]
fn validate_accepts_rs256_with_rsa_pem() {
    let config = GarrisonConfig {
        token_style: "jwt".to_string(),
        jwt_algorithm: "RS256".to_string(),
        jwt_rsa_private_key_pem: Some(TEST_ASYM_RSA_PEM.to_string()),
        ..GarrisonConfig::default()
    };
    assert!(config.validate().is_ok(), "RS256 + rsa pem 应通过校验");
}

#[test]
fn validate_rejects_rs256_without_rsa_pem() {
    let config = GarrisonConfig {
        token_style: "jwt".to_string(),
        jwt_algorithm: "RS256".to_string(),
        jwt_secret: "0123456789abcdef0123456789abcdef".to_string().into(),
        ..GarrisonConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("config-jwt-key-missing"));
}

#[test]
fn validate_rejects_multiple_key_types() {
    let config = GarrisonConfig {
        jwt_algorithm: "RS256".to_string(),
        jwt_rsa_private_key_pem: Some(TEST_ASYM_RSA_PEM.to_string()),
        jwt_ec_private_key_pem: Some("dummy".to_string()),
        ..GarrisonConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("config-jwt-key-multiple-types"));
}

#[test]
fn validate_rejects_asymmetric_key_for_hs() {
    let config = GarrisonConfig {
        jwt_algorithm: "HS256".to_string(),
        jwt_secret: "0123456789abcdef0123456789abcdef".to_string().into(),
        jwt_rsa_private_key_pem: Some(TEST_ASYM_RSA_PEM.to_string()),
        ..GarrisonConfig::default()
    };
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("config-jwt-key-unexpected-for-hs"));
}

#[test]
fn debug_redacts_asymmetric_pem_fields() {
    let config = GarrisonConfig {
        jwt_rsa_private_key_pem: Some(TEST_ASYM_RSA_PEM.to_string()),
        ..GarrisonConfig::default()
    };
    let debug = format!("{:?}", config);
    assert!(!debug.contains("MIIEvg"), "Debug 输出不得包含 PEM 内容");
    assert!(debug.contains("<redacted>"));
}

// password_hasher 配置段

/// 默认值即 OWASP 建议档（argon2id 19456/2/1、bcrypt 12、风险接受位关闭）且整体校验通过。
#[test]
fn password_hasher_defaults_are_owasp_recommended() {
    let config = GarrisonConfig::default();
    let ph = &config.password_hasher;
    assert_eq!(ph.algorithm, "argon2id");
    assert_eq!(ph.argon2_m_cost, 19_456);
    assert_eq!(ph.argon2_t_cost, 2);
    assert_eq!(ph.argon2_p_cost, 1);
    assert_eq!(ph.bcrypt_cost, 12);
    assert!(!ph.allow_weak_argon2_params);
    assert!(
        config.validate().is_ok(),
        "默认 password_hasher 配置必须通过 validate: {:?}",
        config.validate().err()
    );
}

#[test]
fn password_hasher_toml_section_roundtrip() {
    let toml = r#"
[password_hasher]
algorithm = "bcrypt"
bcrypt_cost = 14
"#;
    let config: GarrisonConfig = toml::from_str(toml).unwrap();
    assert_eq!(config.password_hasher.algorithm, "bcrypt");
    assert_eq!(config.password_hasher.bcrypt_cost, 14);
    // 未写出的字段取默认值
    assert_eq!(config.password_hasher.argon2_m_cost, 19_456);
    assert!(!config.password_hasher.allow_weak_argon2_params);
}

#[test]
fn validate_rejects_unknown_password_hash_algorithm() {
    let mut config = GarrisonConfig::default();
    config.password_hasher.algorithm = "md5".to_string();
    let err = config.validate().unwrap_err();
    assert!(
        err.to_string()
            .contains("config-password-hash-algorithm-unsupported"),
        "实际: {}",
        err
    );
}

#[test]
fn validate_rejects_argon2_m_below_floor_without_risk_acceptance() {
    let mut config = GarrisonConfig::default();
    config.password_hasher.argon2_m_cost = 8192;
    let err = config.validate().unwrap_err();
    assert!(
        err.to_string()
            .contains("config-password-hash-argon2-m-below-floor"),
        "实际: {}",
        err
    );
}

/// argon2id m_cost 低于下限但显式风险接受：放行（内存受限部署逃生口）。
#[test]
fn validate_accepts_argon2_m_below_floor_with_risk_acceptance() {
    let mut config = GarrisonConfig::default();
    config.password_hasher.argon2_m_cost = 8192;
    config.password_hasher.allow_weak_argon2_params = true;
    assert!(
        config.validate().is_ok(),
        "显式风险接受后应放行: {:?}",
        config.validate().err()
    );
}

/// argon2id t_cost/p_cost 为 0：拒绝（argon2 Params 构造期会失败，配置层提前拦截）。
#[test]
fn validate_rejects_argon2_zero_cost_params() {
    let mut config = GarrisonConfig::default();
    config.password_hasher.argon2_t_cost = 0;
    assert!(config
        .validate()
        .unwrap_err()
        .to_string()
        .contains("config-password-hash-argon2-param-invalid"));

    let mut config = GarrisonConfig::default();
    config.password_hasher.argon2_p_cost = 0;
    assert!(config
        .validate()
        .unwrap_err()
        .to_string()
        .contains("config-password-hash-argon2-param-invalid"));
}

/// bcrypt cost 越界：9（低于下限）与 16（高于上界）均拒绝，10/15 边界放行。
#[test]
fn validate_rejects_bcrypt_cost_out_of_range() {
    for cost in [9u32, 16] {
        let mut config = GarrisonConfig::default();
        config.password_hasher.algorithm = "bcrypt".to_string();
        config.password_hasher.bcrypt_cost = cost;
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("config-password-hash-bcrypt-cost-out-of-range"),
            "cost={} 实际: {}",
            cost,
            err
        );
    }
    let mut config = GarrisonConfig {
        password_hasher: PasswordHasherConfig {
            algorithm: "bcrypt".to_string(),
            bcrypt_cost: 10,
            ..PasswordHasherConfig::default()
        },
        ..GarrisonConfig::default()
    };
    assert!(config.validate().is_ok());
    config.password_hasher.bcrypt_cost = 15;
    assert!(config.validate().is_ok());
}

#[cfg(feature = "account-credential")]
#[test]
fn build_hasher_argon2id_uses_configured_params() {
    let hasher = PasswordHasherConfig {
        argon2_m_cost: 32768,
        argon2_t_cost: 3,
        argon2_p_cost: 2,
        ..PasswordHasherConfig::default()
    }
    .build_hasher()
    .unwrap();
    let hash = hasher.hash("password").unwrap();
    assert!(
        hash.starts_with("$argon2id$v=19$m=32768,t=3,p=2"),
        "PHC 前缀应反映配置参数，实际: {}",
        &hash[..hash.len().min(40)]
    );
}

#[cfg(feature = "account-credential")]
#[test]
fn build_hasher_bcrypt_uses_configured_cost() {
    let hasher = PasswordHasherConfig {
        algorithm: "bcrypt".to_string(),
        bcrypt_cost: 10,
        ..PasswordHasherConfig::default()
    }
    .build_hasher()
    .unwrap();
    let hash = hasher.hash("password").unwrap();
    assert!(
        hash.starts_with("$2b$10$"),
        "bcrypt 哈希应使用配置 cost=10，实际: {}",
        &hash[..hash.len().min(10)]
    );
}

#[cfg(feature = "account-credential")]
#[test]
fn build_hasher_rejects_unknown_algorithm() {
    let ph = PasswordHasherConfig {
        algorithm: "scrypt".to_string(),
        ..PasswordHasherConfig::default()
    };
    let err = match ph.build_hasher() {
        Err(e) => e,
        Ok(_) => panic!("非法算法名应返回 Err"),
    };
    assert!(
        err.to_string()
            .contains("config-password-hash-algorithm-unsupported"),
        "实际: {}",
        err
    );
}

// argon2 并发令牌池（内存 DoS 防护）

/// 默认 1（secure-by-default：默认配置即受并发内存上界防护）且整体校验通过。
#[test]
fn argon2_pool_size_default_is_one() {
    let config = GarrisonConfig::default();
    assert_eq!(config.password_hasher.argon2_pool_size, 1);
    assert_eq!(
        config.password_hasher.argon2_pool_size,
        DEFAULT_ARGON2_POOL_SIZE
    );
    assert!(
        config.validate().is_ok(),
        "默认 argon2_pool_size 必须通过 validate: {:?}",
        config.validate().err()
    );
}

/// 区间 [1, 256]：0（零 permit 永久饥饿）与 257（误配上界之外）拒绝，1/256 边界放行。
#[test]
fn argon2_pool_size_validation_bounds() {
    for size in [0u32, 257] {
        let mut config = GarrisonConfig::default();
        config.password_hasher.argon2_pool_size = size;
        let err = config.validate().unwrap_err();
        assert!(
            err.to_string()
                .contains("config-password-hash-argon2-pool-size-out-of-range"),
            "size={} 实际: {}",
            size,
            err
        );
    }
    for size in [1u32, 256] {
        let mut config = GarrisonConfig::default();
        config.password_hasher.argon2_pool_size = size;
        assert!(
            config.validate().is_ok(),
            "size={} 应放行: {:?}",
            size,
            config.validate().err()
        );
    }
}

/// 环境变量嵌套映射生效（双下划线折叠为嵌套路径，与既有嵌套段同机制）。
#[test]
#[serial]
fn argon2_pool_size_env_mapping() {
    let _env_guards = [EnvVarGuard::set(
        "GARRISON_PASSWORD_HASHER__ARGON2_POOL_SIZE",
        "8",
    )];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert_eq!(
        config.password_hasher.argon2_pool_size, 8,
        "env 嵌套映射应覆盖默认值 1"
    );
}

#[cfg(feature = "account-credential")]
#[test]
fn build_hasher_argon2_wires_pool_size() {
    let ph = PasswordHasherConfig {
        argon2_pool_size: 3,
        ..PasswordHasherConfig::default()
    };
    let hasher = ph.build_hasher().unwrap();
    let gate = hasher.concurrency_gate().expect("argon2id 分支应装配池");
    assert_eq!(gate.available_permits(), 3, "permit 数应等于配置池大小");
}

/// bcrypt 分支不装配并发令牌池（gate 为 None）：工作区 KB 级池化无内存防护收益，CPU DoS 由限流与 cost 校验承担；以测试固化防后续无意接入。
#[cfg(feature = "account-credential")]
#[test]
fn build_hasher_bcrypt_has_no_pool() {
    let ph = PasswordHasherConfig {
        algorithm: "bcrypt".to_string(),
        bcrypt_cost: 12,
        ..PasswordHasherConfig::default()
    };
    let hasher = ph.build_hasher().unwrap();
    assert!(
        hasher.concurrency_gate().is_none(),
        "bcrypt 不入池：gate 必须为 None"
    );
}

// 弃用配置键注册表：加载期自动迁移 + 1.0 版本门

/// 进程内日志捕获 writer（fmt Layer 的 MakeWriter，收集格式化行）。
#[derive(Clone)]
struct DeprecationLogCapture(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for DeprecationLogCapture {
    type Writer = DeprecationLogCaptureWriter;
    fn make_writer(&'a self) -> Self::Writer {
        DeprecationLogCaptureWriter(self.0.clone())
    }
}

struct DeprecationLogCaptureWriter(std::sync::Arc<std::sync::Mutex<Vec<String>>>);

impl std::io::Write for DeprecationLogCaptureWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .expect("日志缓冲锁应可用")
            .push(String::from_utf8_lossy(buf).to_string());
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// 在捕获 tracing 事件的上下文中执行 `f`（守卫覆盖全程，返回后恢复）；日志行经回调由断言读取（`DefaultGuard` 在 default-features=false 下无公开类型路径，故以闭包作用域持有）。
fn with_captured_deprecation_logs(f: impl FnOnce(&std::sync::Mutex<Vec<String>>)) {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let logs = DeprecationLogCapture(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_ansi(false)
            .with_writer(logs.clone()),
    );
    let _guard = subscriber.set_default();
    f(&logs.0);
}

/// fixture：`timeout_seconds`（分钟）→ `timeout`（秒）×60 自动映射。
fn fixture_timeout_migration() -> deprecation::Deprecation {
    deprecation::Deprecation {
        key: "timeout_seconds",
        since_version: "0.9.0",
        new_key: "timeout",
        auto_map: true,
        map_fn: Some(|v| match v.as_i64() {
            Some(mins) if mins > 0 => Ok(serde_json::json!(mins * 60)),
            _ => Err(format!(
                "timeout_seconds must be a positive integer, got {v}"
            )),
        }),
    }
}

/// fixture：同类型改名（值原样搬迁，无 map_fn）。
fn fixture_verbatim_rename() -> deprecation::Deprecation {
    deprecation::Deprecation {
        key: "token_name_legacy",
        since_version: "0.8.0",
        new_key: "token_name",
        auto_map: true,
        map_fn: None,
    }
}

#[test]
fn auto_mapped_key_moves_value_through_map_fn_to_new_key() {
    let mut tree = serde_json::json!({ "timeout_seconds": 120 });
    deprecation::apply_deprecations(
        &mut tree,
        &[fixture_timeout_migration()],
        "0.9.0",
        &serde_json::Value::Null,
    )
    .expect("命中可映射键不应报错");
    assert_eq!(
        tree["timeout"],
        serde_json::json!(7200),
        "新键应携带 map_fn 转换后的值"
    );
    assert!(
        tree.get("timeout_seconds").is_none(),
        "旧键迁移后应从树中移除"
    );
}

#[test]
fn auto_mapped_key_without_map_fn_moves_value_verbatim() {
    let mut tree = serde_json::json!({ "token_name_legacy": "legacy_token" });
    deprecation::apply_deprecations(
        &mut tree,
        &[fixture_verbatim_rename()],
        "0.9.0",
        &serde_json::Value::Null,
    )
    .expect("命中可映射键不应报错");
    assert_eq!(tree["token_name"], serde_json::json!("legacy_token"));
    assert!(tree.get("token_name_legacy").is_none());
}

#[test]
fn auto_map_does_not_overwrite_new_key_already_present() {
    let mut tree = serde_json::json!({ "token_name_legacy": "legacy", "token_name": "current" });
    deprecation::apply_deprecations(
        &mut tree,
        &[fixture_verbatim_rename()],
        "0.9.0",
        &serde_json::Value::Null,
    )
    .expect("命中可映射键不应报错");
    assert_eq!(
        tree["token_name"],
        serde_json::json!("current"),
        "新键已配置时保持用户值"
    );
    assert!(tree.get("token_name_legacy").is_none(), "旧键仍应移除");
}

#[test]
fn nested_section_keys_auto_map_through_map_fn() {
    let dep = deprecation::Deprecation {
        key: "password_hasher.bcrypt_cost_legacy",
        since_version: "0.9.0",
        new_key: "password_hasher.bcrypt_cost",
        auto_map: true,
        map_fn: Some(|v| match v.as_i64() {
            Some(n) => Ok(serde_json::json!(n)),
            _ => Err("must be an integer".to_string()),
        }),
    };
    let mut tree = serde_json::json!({ "password_hasher": { "bcrypt_cost_legacy": 12 } });
    deprecation::apply_deprecations(&mut tree, &[dep], "0.9.0", &serde_json::Value::Null)
        .expect("嵌套键迁移不应报错");
    assert_eq!(
        tree["password_hasher"]["bcrypt_cost"],
        serde_json::json!(12)
    );
    assert!(tree["password_hasher"].get("bcrypt_cost_legacy").is_none());
}

/// 迁移 warn 必须含 since 版本与新键名。
#[test]
fn warn_log_contains_since_version_and_new_key_name() {
    with_captured_deprecation_logs(|logs| {
        let mut tree = serde_json::json!({ "timeout_seconds": 120 });
        deprecation::apply_deprecations(
            &mut tree,
            &[fixture_timeout_migration()],
            "0.9.0",
            &serde_json::Value::Null,
        )
        .expect("命中可映射键不应报错");
        let lines = logs.lock().expect("日志缓冲锁应可用").join("\n");
        assert!(
            lines.contains("0.9.0"),
            "warn 日志应含 since 版本，实际日志:\n{lines}"
        );
        assert!(
            lines.contains("timeout"),
            "warn 日志应含新键名，实际日志:\n{lines}"
        );
        assert!(
            lines.contains("timeout_seconds"),
            "warn 日志应含弃用键名，实际日志:\n{lines}"
        );
    });
}

#[test]
fn no_deprecated_key_hit_leaves_tree_untouched() {
    with_captured_deprecation_logs(|logs| {
        let mut tree = serde_json::json!({ "timeout": 7200 });
        deprecation::apply_deprecations(
            &mut tree,
            &[fixture_timeout_migration()],
            "0.9.0",
            &serde_json::Value::Null,
        )
        .expect("无命中不应报错");
        assert_eq!(
            tree,
            serde_json::json!({ "timeout": 7200 }),
            "无命中时树不得被修改"
        );
        let lines = logs.lock().expect("日志缓冲锁应可用").join("\n");
        assert!(lines.is_empty(), "无命中时不得产生告警，实际日志:\n{lines}");
    });
}

#[test]
#[serial]
fn load_auto_migrates_deprecated_toml_key() {
    let temp = write_temp_toml("timeout_seconds = 120\n");
    let config = GarrisonConfig::load_with_deprecations(
        Some(temp.path().to_str().unwrap()),
        &[fixture_timeout_migration()],
        "0.9.0",
    )
    .expect("弃用键自动迁移后加载应成功");
    assert_eq!(
        config.timeout, 7200,
        "新键字段应携带 map_fn 转换后的值（120 分钟 → 7200 秒）"
    );
}

#[test]
#[serial]
fn load_auto_migrates_deprecated_env_key() {
    let _guard = EnvVarGuard::set("GARRISON_TIMEOUT_SECONDS", "120");
    let config =
        GarrisonConfig::load_with_deprecations(None, &[fixture_timeout_migration()], "0.9.0")
            .expect("弃用键自动迁移后加载应成功");
    assert_eq!(config.timeout, 7200);
}

#[test]
#[serial]
fn load_without_deprecated_keys_leaves_config_intact() {
    let temp = write_temp_toml("timeout = 3600\n");
    let config = GarrisonConfig::load_with_deprecations(
        Some(temp.path().to_str().unwrap()),
        &[fixture_timeout_migration()],
        "0.9.0",
    )
    .expect("无弃用键命中时加载应成功");
    assert_eq!(config.timeout, 3600);
}

#[test]
fn deprecation_registry_keys_are_unique() {
    let registry = deprecation::deprecations();
    let mut keys: Vec<&str> = registry.iter().map(|d| d.key).collect();
    let total = keys.len();
    keys.sort_unstable();
    keys.dedup();
    assert_eq!(keys.len(), total, "注册表键必须唯一，发现重复: {keys:?}");
}

/// fixture：不可自动映射的键（键被彻底移除，无新键）。
fn fixture_removed_key() -> deprecation::Deprecation {
    deprecation::Deprecation {
        key: "legacy_feature_flag",
        since_version: "0.7.0",
        new_key: "",
        auto_map: false,
        map_fn: None,
    }
}

#[test]
fn unmappable_key_before_1_0_warns_and_passes() {
    with_captured_deprecation_logs(|logs| {
        let mut tree = serde_json::json!({ "legacy_feature_flag": true });
        deprecation::apply_deprecations(
            &mut tree,
            &[fixture_removed_key()],
            "0.9.0",
            &serde_json::Value::Null,
        )
        .expect("1.0 前不可映射键应放行");
        assert_eq!(
            tree,
            serde_json::json!({ "legacy_feature_flag": true }),
            "不可映射键放行时树不得被修改"
        );
        let lines = logs.lock().expect("日志缓冲锁应可用").join("\n");
        assert!(
            lines.contains("legacy_feature_flag") && lines.contains("0.7.0"),
            "warn 日志应含弃用键名与 since 版本，实际日志:\n{lines}"
        );
    });
}

#[test]
fn unmappable_key_at_1_0_is_hard_error_with_key_name_and_guidance() {
    let mut tree = serde_json::json!({ "legacy_feature_flag": true });
    let err = deprecation::apply_deprecations(
        &mut tree,
        &[fixture_removed_key()],
        "1.0.0",
        &serde_json::Value::Null,
    )
    .expect_err("1.0 起不可映射键必须报错");
    let joined = err.join("; ");
    assert!(
        joined.contains("legacy_feature_flag"),
        "错误应含弃用键名，实际: {joined}"
    );
    assert!(
        joined.contains("0.7.0") && joined.contains("removed"),
        "错误应含 since 版本与移除指引，实际: {joined}"
    );
}

#[test]
fn mappable_key_at_1_0_is_hard_error() {
    let mut tree = serde_json::json!({ "timeout_seconds": 120 });
    let err = deprecation::apply_deprecations(
        &mut tree,
        &[fixture_timeout_migration()],
        "1.0.0",
        &serde_json::Value::Null,
    )
    .expect_err("1.0 起可映射键不再代迁，必须报错");
    let joined = err.join("; ");
    assert!(
        joined.contains("timeout_seconds") && joined.contains("timeout"),
        "错误应含弃用键名与新键指引，实际: {joined}"
    );
}

#[test]
fn version_1_0_0_prerelease_is_still_within_grace_window() {
    let mut tree = serde_json::json!({ "timeout_seconds": 120 });
    deprecation::apply_deprecations(
        &mut tree,
        &[fixture_timeout_migration()],
        "1.0.0-rc.1",
        &serde_json::Value::Null,
    )
    .expect("1.0.0 pre-release 仍在宽限窗口内");
    assert_eq!(tree["timeout"], serde_json::json!(7200));
}

#[test]
fn unparsable_current_version_fails_closed() {
    let mut tree = serde_json::json!({ "timeout_seconds": 120 });
    let err = deprecation::apply_deprecations(
        &mut tree,
        &[fixture_timeout_migration()],
        "not-a-version",
        &serde_json::Value::Null,
    )
    .expect_err("版本不可解析必须 fail-closed");
    assert!(
        err.join("; ").contains("timeout_seconds"),
        "错误应含弃用键名，实际: {:?}",
        err
    );
}

#[test]
fn map_fn_rejection_is_hard_error() {
    let mut tree = serde_json::json!({ "timeout_seconds": "not-a-number" });
    let err = deprecation::apply_deprecations(
        &mut tree,
        &[fixture_timeout_migration()],
        "0.9.0",
        &serde_json::Value::Null,
    )
    .expect_err("map_fn 拒绝的值必须报错");
    let joined = err.join("; ");
    assert!(
        joined.contains("timeout_seconds") && joined.contains("cannot be auto-migrated"),
        "错误应含键名与迁移失败原因，实际: {joined}"
    );
}

/// ≥1.0.0 时弃用键使 load 返回 Config（错误含键名与迁移指引，发生在 validate 之前）。
#[test]
#[serial]
fn load_rejects_deprecated_key_at_1_0() {
    let temp = write_temp_toml("timeout_seconds = 120\n");
    let err = GarrisonConfig::load_with_deprecations(
        Some(temp.path().to_str().unwrap()),
        &[fixture_timeout_migration()],
        "1.0.0",
    )
    .expect_err("1.0 起弃用键必须使加载失败");
    match &err {
        GarrisonError::Config(msg) => {
            assert!(
                msg.contains("timeout_seconds") && msg.contains("timeout"),
                "错误消息应含键名与迁移指引，实际: {msg}"
            );
        },
        other => panic!("应为 GarrisonError::Config，实际: {other:?}"),
    }
}

#[test]
#[serial]
fn load_rejects_unmigratable_value() {
    let temp = write_temp_toml("timeout_seconds = \"not-a-number\"\n");
    let err = GarrisonConfig::load_with_deprecations(
        Some(temp.path().to_str().unwrap()),
        &[fixture_timeout_migration()],
        "0.9.0",
    )
    .expect_err("map_fn 拒绝的值必须使加载失败");
    match &err {
        GarrisonError::Config(msg) => {
            assert!(
                msg.contains("timeout_seconds"),
                "错误消息应含弃用键名，实际: {msg}"
            );
        },
        other => panic!("应为 GarrisonError::Config，实际: {other:?}"),
    }
}

/// 生产注册表 `waf_config`（<1.0）：warn 含键名与 since 版本，放行且树不变（不再静默）。
#[test]
fn registered_waf_config_passes_with_warn_before_1_0() {
    with_captured_deprecation_logs(|logs| {
        let mut tree = serde_json::json!({ "waf_config": { "enabled": true } });
        deprecation::apply_deprecations(
            &mut tree,
            deprecation::deprecations(),
            "0.9.0",
            &serde_json::Value::Null,
        )
        .expect("1.0 前命中已注册的不可映射键应放行");
        assert_eq!(
            tree,
            serde_json::json!({ "waf_config": { "enabled": true } }),
            "不可映射键放行时树不得被修改"
        );
        let lines = logs.lock().expect("日志缓冲锁应可用").join("\n");
        assert!(
            lines.contains("waf_config") && lines.contains("0.9.0"),
            "warn 日志应含 waf_config 与 since 版本，实际日志:\n{lines}"
        );
    });
}

#[test]
fn registered_waf_config_is_hard_error_at_1_0() {
    let mut tree = serde_json::json!({ "waf_config": { "enabled": true } });
    let err = deprecation::apply_deprecations(
        &mut tree,
        deprecation::deprecations(),
        "1.0.0",
        &serde_json::Value::Null,
    )
    .expect_err("1.0 起命中 waf_config 必须报错");
    let joined = err.join("; ");
    assert!(
        joined.contains("waf_config") && joined.contains("0.9.0") && joined.contains("removed"),
        "错误应含键名、since 版本与移除指引，实际: {joined}"
    );
}

/// 端到端：toml `[waf_config]` 经生产注册表 + 生产版本（<1.0）加载——warn 显性化且成功。
#[test]
#[serial]
fn load_production_registry_warns_on_waf_config_section() {
    with_captured_deprecation_logs(|logs| {
        let temp = write_temp_toml("[waf_config]\nenabled = true\n");
        let config = GarrisonConfig::load(Some(temp.path().to_str().unwrap()))
            .expect("waf_config 命中在宽限窗口内应放行");
        assert_eq!(config.timeout, DEFAULT_TIMEOUT, "waf_config 不影响其余配置");
        let lines = logs.lock().expect("日志缓冲锁应可用").join("\n");
        assert!(
            lines.contains("waf_config") && lines.contains("0.9.0"),
            "生产加载应输出 waf_config 弃用告警，实际日志:\n{lines}"
        );
    });
}

#[test]
#[serial]
fn load_production_registry_rejects_waf_config_at_1_0() {
    let temp = write_temp_toml("[waf_config]\nenabled = true\n");
    let err = GarrisonConfig::load_with_deprecations(
        Some(temp.path().to_str().unwrap()),
        deprecation::deprecations(),
        "1.0.0",
    )
    .expect_err("1.0 起含 waf_config 的配置必须加载失败");
    match &err {
        GarrisonError::Config(msg) => {
            assert!(
                msg.contains("waf_config"),
                "错误消息应含 waf_config，实际: {msg}"
            );
        },
        other => panic!("应为 GarrisonError::Config，实际: {other:?}"),
    }
}

// jwks_retention_secs 配置测试

#[test]
fn jwks_retention_default_is_two_access_token_ttls() {
    let config = GarrisonConfig::default_config();
    assert_eq!(config.jwks_retention_secs, 7200);
}

/// retention=0 为误配必须显性拒绝（0 等价轮换瞬间退役旧钥，存量 token 验证立即中断）。
#[test]
fn jwks_retention_zero_fails_validation() {
    let mut config = GarrisonConfig::default_config();
    config.jwks_retention_secs = 0;
    let err = config.validate().expect_err("retention=0 必须显性拒绝");
    assert!(
        err.to_string()
            .contains("config-jwks-retention-must-positive"),
        "错误必须显性指明 retention 非法，实际: {err}"
    );
}

#[test]
fn jwks_retention_positive_passes_validation() {
    let mut config = GarrisonConfig::default_config();
    config.jwks_retention_secs = 600;
    config.validate().expect("正值 retention 必须通过校验");
}

// MFA 编排基座：per-client chain 三态与 fail-closed 校验

#[test]
fn mfa_config_defaults_empty() {
    let config = GarrisonConfig::default_config();
    assert!(config.mfa.global_chain.is_empty(), "全局链默认空");
    assert!(
        config.mfa.per_client_chains.is_empty(),
        "per-client 覆盖默认空"
    );
    assert_eq!(
        config.mfa.recovery_misuse_tolerance, 0,
        "恢复码误用豁免默认 0（首次误用即锁定）"
    );
    assert!(config.validate().is_ok(), "默认 mfa 配置应通过校验");
}

#[test]
fn mfa_global_chain_unknown_factor_fails_validation() {
    let mut config = GarrisonConfig::default_config();
    config.mfa.global_chain = vec!["otp".to_string(), "sms".to_string()];
    let result = config.validate();
    assert!(
        matches!(result, Err(GarrisonError::Config(ref m)) if m.contains("mfa-chain-factor-unknown") && m.contains("sms")),
        "全局链引用未知 factor 应 fail-closed，实际: {:?}",
        result
    );
}

#[test]
fn mfa_per_client_chain_unknown_factor_fails_validation() {
    let mut config = GarrisonConfig::default_config();
    config
        .mfa
        .per_client_chains
        .insert("client-a".to_string(), vec!["push".to_string()]);
    let result = config.validate();
    assert!(
        matches!(result, Err(GarrisonError::Config(ref m)) if m.contains("mfa-chain-factor-unknown") && m.contains("push")),
        "per-client 链引用未知 factor 应 fail-closed，实际: {:?}",
        result
    );
}

#[test]
fn mfa_known_factors_pass_validation() {
    let mut config = GarrisonConfig::default_config();
    config.mfa.global_chain = vec!["otp".to_string()];
    config
        .mfa
        .per_client_chains
        .insert("client-a".to_string(), vec!["webauthn".to_string()]);
    config
        .mfa
        .per_client_chains
        .insert("client-b".to_string(), vec![]);
    assert!(config.validate().is_ok(), "已知 factor 应通过校验");
}

// seed_primary_amr / login_id_max_len 配置测试

#[test]
fn config_default_seed_primary_amr_is_true() {
    let config = GarrisonConfig::default_config();
    assert!(
        config.seed_primary_amr,
        "seed_primary_amr 默认应为 true（开关默认保持现状，安全敏感部署显式关闭）"
    );
}

#[test]
fn config_default_login_id_max_len_is_255() {
    let config = GarrisonConfig::default_config();
    assert_eq!(config.login_id_max_len, 255);
    assert_eq!(config.login_id_max_len, DEFAULT_LOGIN_ID_MAX_LEN);
}

#[serial]
#[test]
fn config_env_override_seed_primary_amr_false() {
    let _env_guards = [EnvVarGuard::set("GARRISON_SEED_PRIMARY_AMR", "false")];
    let config = GarrisonConfig::load(None).expect("合法 env 覆盖应加载成功");
    assert!(!config.seed_primary_amr, "env 覆盖 false 应生效");
}

#[serial]
#[test]
fn config_env_seed_primary_amr_invalid_type_rejected() {
    let _env_guards = [EnvVarGuard::set("GARRISON_SEED_PRIMARY_AMR", "not-a-bool")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err(), "非布尔 seed_primary_amr 应在加载期拒绝");
}

// require_tenant_bound_jwt 配置测试

#[test]
fn config_default_require_tenant_bound_jwt_is_false() {
    let config = GarrisonConfig::default_config();
    assert!(
        !config.require_tenant_bound_jwt,
        "require_tenant_bound_jwt 默认应为 false（开关默认放行存量无 tid token，安全敏感部署显式开启）"
    );
}

#[serial]
#[test]
fn config_env_override_require_tenant_bound_jwt_true() {
    let _env_guards = [EnvVarGuard::set(
        "GARRISON_REQUIRE_TENANT_BOUND_JWT",
        "true",
    )];
    let config = GarrisonConfig::load(None).expect("合法 env 覆盖应加载成功");
    assert!(config.require_tenant_bound_jwt, "env 覆盖 true 应生效");
}

#[serial]
#[test]
fn config_env_require_tenant_bound_jwt_invalid_type_rejected() {
    let _env_guards = [EnvVarGuard::set(
        "GARRISON_REQUIRE_TENANT_BOUND_JWT",
        "not-a-bool",
    )];
    let result = GarrisonConfig::load(None);
    assert!(
        result.is_err(),
        "非布尔 require_tenant_bound_jwt 应在加载期拒绝"
    );
}

// require_session_tenant_binding 配置测试（与 require_tenant_bound_jwt 互补：覆盖 Simple/Mixin 与 Stateless 两半）

#[test]
fn config_default_require_session_tenant_binding_is_false() {
    let config = GarrisonConfig::default_config();
    assert!(
        !config.require_session_tenant_binding,
        "require_session_tenant_binding 默认应为 false（存量无绑定会话放行，安全敏感部署显式开启）"
    );
}

#[serial]
#[test]
fn config_env_override_require_session_tenant_binding_true() {
    let _env_guards = [EnvVarGuard::set(
        "GARRISON_REQUIRE_SESSION_TENANT_BINDING",
        "true",
    )];
    let config = GarrisonConfig::load(None).expect("合法 env 覆盖应加载成功");
    assert!(
        config.require_session_tenant_binding,
        "env 覆盖 true 应生效"
    );
}

#[serial]
#[test]
fn config_env_require_session_tenant_binding_invalid_type_rejected() {
    let _env_guards = [EnvVarGuard::set(
        "GARRISON_REQUIRE_SESSION_TENANT_BINDING",
        "not-a-bool",
    )];
    let result = GarrisonConfig::load(None);
    assert!(
        result.is_err(),
        "非布尔 require_session_tenant_binding 应在加载期拒绝"
    );
}

#[serial]
#[test]
fn config_env_override_login_id_max_len() {
    let _env_guards = [EnvVarGuard::set("GARRISON_LOGIN_ID_MAX_LEN", "128")];
    let config = GarrisonConfig::load(None).expect("合法 env 覆盖应加载成功");
    assert_eq!(config.login_id_max_len, 128);
}

#[serial]
#[test]
fn config_env_login_id_max_len_zero_means_unlimited() {
    let _env_guards = [EnvVarGuard::set("GARRISON_LOGIN_ID_MAX_LEN", "0")];
    let config = GarrisonConfig::load(None).expect("0=不限制应加载成功");
    assert_eq!(config.login_id_max_len, 0);
}

#[serial]
#[test]
fn config_env_login_id_max_len_invalid_type_rejected() {
    let _env_guards = [EnvVarGuard::set("GARRISON_LOGIN_ID_MAX_LEN", "abc")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err(), "非整数 login_id_max_len 应在加载期拒绝");
}
