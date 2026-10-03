// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! config 模块测试（从 mod.rs 迁移）。

// jwt_secret 的 `.into()` 是跨 feature 兼容的必要转换：protocol-zeroize 下字段
// 类型为 Zeroizing<String>（String→Zeroizing<String>），feature 关闭时退化为
// String，被 clippy 误报 useless_conversion。
#![allow(clippy::useless_conversion)]

use super::*;
use crate::error::GarrisonError;
use serial_test::serial;

/// panic 安全的环境变量守卫。
///
/// 原环境变量测试在测试末尾手动 `remove_var`：一旦断言 panic，清理被跳过，
/// 变量残留会污染后续（共享进程 env 的）serial 测试。守卫在 Drop（含 unwind）
/// 时移除变量，保证 panic 路径同样清理。
///
/// 互斥规则：`#[serial]` 只让 serial 测试彼此互斥，挡不住并行的非 serial
/// 测试；而 confers `EnvSource` 读进程级 `std::env`。因此凡设置环境变量的
/// 测试与凡调用 `load()`（经 EnvSource 读 env）的测试一律 `#[serial]`，
/// 两组同处一个互斥队列，读侧与写侧才不会交错。
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

/// 编译期断言：protocol-zeroize feature 下 jwt_secret 字段类型为 Zeroizing<String>，
/// Drop 时自动 zeroize。如果有人改回 String，此测试将编译失败。
#[cfg(feature = "protocol-zeroize")]
#[test]
fn jwt_secret_is_zeroizing_type_when_protocol_zeroize() {
    let cfg = GarrisonConfig::default();
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

// ========================================================================
// 代码默认值测试（spec Scenario: 代码默认值生效）
// ========================================================================

/// 验证 default_config() 返回符合 spec 的默认值。
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
    // 字段默认值
    assert_eq!(config.jwt_algorithm, "HS256");
    assert_eq!(config.sign_window_seconds, 300);
    assert_eq!(config.sso_ticket_ttl_seconds, 60);
}

// ========================================================================
// is_write_cookie 配置测试
// ========================================================================

/// `default_config()` 的 `is_write_cookie` 为 false。
#[test]
fn default_is_write_cookie_is_false() {
    let config = GarrisonConfig::default_config();
    assert!(!config.is_write_cookie, "默认 is_write_cookie 应为 false");
}

/// `default_config()` 的 `is_write_header` 为 true（验证已有字段）。
#[test]
fn default_is_write_header_is_true() {
    let config = GarrisonConfig::default_config();
    assert!(config.is_write_header, "默认 is_write_header 应为 true");
}

/// 可自定义 `is_write_cookie` 为 true。
#[test]
fn custom_is_write_cookie_can_be_set() {
    let mut config = GarrisonConfig::default_config();
    config.is_write_cookie = true;
    assert!(config.is_write_cookie, "自定义 is_write_cookie=true 应生效");
    assert!(config.validate().is_ok(), "is_write_cookie=true 应通过校验");
}

/// `is_write_header` 和 `is_write_cookie` 可同时为 true。
#[test]
fn both_is_write_header_and_is_write_cookie_can_be_true() {
    let mut config = GarrisonConfig::default_config();
    config.is_write_header = true;
    config.is_write_cookie = true;
    assert!(config.is_write_header, "is_write_header 应为 true");
    assert!(config.is_write_cookie, "is_write_cookie 应为 true");
    assert!(config.validate().is_ok(), "两者同时为 true 应通过校验");
}

/// 验证 Default::default() 等价于 default_config()。
#[test]
fn default_trait_eq_default_config() {
    let d = GarrisonConfig::default();
    let dc = GarrisonConfig::default_config();
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

/// 验证 timeout = -1 抛错（spec Scenario: timeout 为负数）。
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

/// 验证 timeout = 0 抛错。
#[test]
fn validate_rejects_zero_timeout() {
    let mut config = GarrisonConfig::default_config();
    config.timeout = 0;
    assert!(config.validate().is_err());
}

/// 验证所有合法 token_style 通过校验。
///
/// simple 风格自 静态-配置与部署-6 起 jwt_secret 即 HMAC 签名密钥，同 jwt 一样
/// 要求 ≥32B 强密钥（空/短密钥硬错误），循环内一并补齐。
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

/// 验证默认配置通过校验。
#[test]
fn default_config_validates_ok() {
    let config = GarrisonConfig::default_config();
    assert!(config.validate().is_ok());
}

/// 验证 token_style=jwt 但 jwt_secret 为空时校验失败。
///
/// 配置校验——jwt_secret 不能为空当 token_style=jwt，
/// 防止攻击者用公开的空字符串密钥伪造 JWT。
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

/// 验证 token_style=jwt 且 jwt_secret 短于 32 字节（HS256）时校验失败。
///
/// 弱密钥易被离线爆破，validate() 应拒绝（CWE-326 防御）。
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

/// 验证 HS512 算法下 jwt_secret 短于 64 字节时校验失败（即使已满足 HS256 的 32 字节）。
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

/// 验证 HS384 算法下 jwt_secret 短于 48 字节时校验失败（即使已满足 HS256 的 32 字节）。
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

/// 验证 jwt_algorithm 不在白名单内时校验失败（防拼写错误静默走 32 字节分支）。
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

/// 验证 token_style=simple 且 jwt_secret 短于 32 字节时校验失败。
///
/// simple 风格的 jwt_secret 直接作为 HMAC-SHA256 签名密钥（`SimpleTokenStyle`），
/// 弱密钥可离线爆破，安全关键。rc 阶段接受 breaking：原 warn 不阻断与
/// `SimpleTokenStyle::generate` 的运行时 fail-closed（`core-simple-secret-too-short`）
/// 不一致，现配置层对齐硬错误，错误信息注明升级指引。
#[test]
fn validate_rejects_short_secret_for_simple_style() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "simple".to_string();
    config.jwt_secret = "weak".to_string().into(); // 4 字节 < 32
    match config.validate() {
        Err(GarrisonError::Config(msg)) => {
            assert!(
                msg.contains("config-jwt-secret-too-short")
                    && msg.contains("min 32")
                    && msg.contains("openssl rand"),
                "simple 短密钥错误应含长度约束与升级指引，实际: {}",
                msg
            );
        },
        other => panic!("simple 风格短密钥应被拒绝，实际: {:?}", other),
    }
}

/// 验证 ≥32 字节的 jwt_secret 在 HS256 下通过校验。
#[test]
fn validate_accepts_strong_jwt_secret_hs256() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_algorithm = "HS256".to_string();
    config.jwt_secret = "x".repeat(32).into(); // 恰好 32 字节边界
    assert!(config.validate().is_ok(), "32 字节密钥应通过 HS256 校验");
}

/// 验证 HS384 算法下 ≥48 字节 jwt_secret 通过校验。
#[test]
fn validate_accepts_strong_jwt_secret_hs384() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_algorithm = "HS384".to_string();
    config.jwt_secret = "x".repeat(48).into(); // 恰好 48 字节边界
    assert!(config.validate().is_ok(), "48 字节密钥应通过 HS384 校验");
}

/// 验证 HS512 算法下 ≥64 字节 jwt_secret 通过校验。
#[test]
fn validate_accepts_strong_jwt_secret_hs512() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_algorithm = "HS512".to_string();
    config.jwt_secret = "x".repeat(64).into(); // 恰好 64 字节边界
    assert!(config.validate().is_ok(), "64 字节密钥应通过 HS512 校验");
}

// ========================================================================
// JWT 弱密钥黑名单（静态-配置与部署-6）
// ========================================================================

/// 验证 jwt 风格下 32 字节填充变体弱密钥被拒（过长度校验、命中黑名单）。
///
/// "changeme" + 24 个 '_' = 32 字节：仅靠长度校验拦不住可预测密钥，
/// 黑名单剥离填充字符后整串比对（忽略大小写）。
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

/// 验证弱密钥黑名单忽略大小写（jwt/HS512，满足长度仍拒）。
#[test]
fn validate_rejects_weak_jwt_secret_case_insensitive() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_algorithm = "HS512".to_string();
    config.jwt_secret = format!("PASSWORD{}", "-".repeat(56)).into(); // 64 字节
    let err = config.validate().expect_err("大写弱密钥填充变体应被拒绝");
    assert!(
        err.to_string().contains("config-jwt-secret-weak"),
        "实际: {}",
        err
    );
}

/// 验证 simple 风格弱密钥（满足 32 字节长度）同样命中黑名单。
#[test]
fn validate_rejects_weak_secret_for_simple_style() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "simple".to_string();
    config.jwt_secret = format!("letmein{}", ".".repeat(25)).into(); // 32 字节
    let err = config.validate().expect_err("simple 弱密钥应被拒绝");
    assert!(
        err.to_string().contains("config-jwt-secret-weak"),
        "实际: {}",
        err
    );
}

/// 验证强密钥包含弱密钥子串不误伤（黑名单为整串匹配，非子串匹配）。
#[test]
fn validate_accepts_strong_secret_containing_weak_substring() {
    let mut config = GarrisonConfig::default_config();
    config.token_style = "jwt".to_string();
    config.jwt_algorithm = "HS256".to_string();
    // 35 字节高熵短句，尾部含 "123456" 子串——整串不命中黑名单
    config.jwt_secret = "correct horse battery staple 123456".to_string().into();
    assert!(config.validate().is_ok(), "含弱密钥子串的强密钥不应被误伤");
}

/// 验证各 token_style × 空/弱/强 jwt_secret 的校验矩阵。
///
/// - `uuid` / `random_64`：CSPRNG 不透明 token，签名不消费 jwt_secret，
///   空/弱均放行（维持宽松默认，不迫使非 JWT 部署配置无意义密钥）
/// - `simple`：空（<32B）硬错误
/// - `jwt` + 非对称算法：强度由 PEM 决定，jwt_secret 空放行（既有语义）
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

// ========================================================================
// remember_me 配置测试（spec R-session-lifecycle-004）
// ========================================================================

/// 验证 remember_me 默认值：enabled=false, timeout=7776000（90 天）。
#[test]
fn remember_me_defaults() {
    let config = GarrisonConfig::default_config();
    assert!(!config.remember_me_enabled);
    assert_eq!(config.remember_me_timeout, REMEMBER_ME_DEFAULT_TIMEOUT);
    assert_eq!(config.remember_me_timeout, 7_776_000);
}

/// 验证 remember_me_enabled=true 且 remember_me_timeout > timeout 时校验通过。
#[test]
fn validate_remember_me_ok_when_timeout_greater() {
    let mut config = GarrisonConfig::default_config();
    config.remember_me_enabled = true;
    // remember_me_timeout 默认 7776000 > timeout 默认 2592000，应通过
    assert!(config.validate().is_ok());
}

/// 验证 remember_me_enabled=true 且 remember_me_timeout <= timeout 时校验失败。
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
/// 验证 remember_me_enabled=false 时 remember_me_timeout 仅需 > 0。
#[test]
fn validate_remember_me_disabled_only_checks_positive() {
    let mut config = GarrisonConfig::default_config();
    config.remember_me_enabled = false;
    config.remember_me_timeout = 1; // > 0 即可（不需要 > timeout）
    assert!(config.validate().is_ok());
}

#[serial]
/// 验证 remember_me_enabled=false 且 remember_me_timeout <= 0 时校验失败。
#[test]
fn validate_remember_me_fails_when_timeout_non_positive() {
    let mut config = GarrisonConfig::default_config();
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
    let config = GarrisonConfig::load(Some(temp.path().to_str().unwrap())).unwrap();
    assert!(config.remember_me_enabled);
    assert_eq!(config.remember_me_timeout, 9999999);
}

/// 验证环境变量可覆盖 remember_me 字段。
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

// ========================================================================
// session_hover_timeout 配置测试
// ========================================================================

/// `GarrisonConfig::default()` 的 `session_hover_timeout` 为 -1（不启用）。
#[test]
fn config_default_session_hover_is_negative_one() {
    let config = GarrisonConfig::default_config();
    assert_eq!(config.session_hover_timeout, -1);
}

/// `session_hover_timeout` 超过 10 年（315_360_000 秒）上界时校验应拒绝。
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

/// `session_hover_timeout` 等于上界（10 年）时校验应通过。
#[test]
fn config_accepts_session_hover_timeout_at_max() {
    let mut config = GarrisonConfig::default_config();
    config.session_hover_timeout = 315_360_000;
    assert!(
        config.validate().is_ok(),
        "等于上界的 session_hover_timeout 应被接受"
    );
}

// ========================================================================
// frontend_separation 配置测试
// ========================================================================

/// `GarrisonConfig::default()` 的 `frontend_separation` 为 false。
#[serial]
#[test]
fn config_default_frontend_separation_is_false() {
    let config = GarrisonConfig::default_config();
    assert!(!config.frontend_separation);
}

/// `GARRISON_FRONTEND_SEPARATION=true` 环境变量覆盖配置为 true。
#[test]
#[serial]
fn env_overrides_frontend_separation() {
    let _env_guards = [EnvVarGuard::set("GARRISON_FRONTEND_SEPARATION", "true")];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert!(config.frontend_separation);
}

/// `frontend_separation=true` 时 `validate()` 不报错。
#[serial]
#[test]
fn validate_accepts_frontend_separation_true() {
    let mut config = GarrisonConfig::default_config();
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
    let config = GarrisonConfig::load(Some(temp.path().to_str().unwrap())).unwrap();
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

/// 验证无 toml 文件时返回默认配置。
#[test]
#[serial]
fn no_file_returns_default() {
    let config = GarrisonConfig::load(None).unwrap();
    assert_eq!(config.token_style, "uuid");
    assert_eq!(config.timeout, DEFAULT_TIMEOUT);
}

#[serial]
/// 验证 toml 解析错误返回 Config 错误。
#[test]
fn invalid_toml_returns_config_error() {
    let temp = write_temp_toml("this is not = valid = toml =");
    let result = GarrisonConfig::load(Some(temp.path().to_str().unwrap()));
    assert!(result.is_err());
    assert!(matches!(result, Err(GarrisonError::Config(_))));
}

#[serial]
/// 验证 toml 中的非法值在 validate 阶段被拒绝。
#[test]
fn toml_invalid_token_style_rejected() {
    let temp = write_temp_toml(r#"token_style = "unknown""#);
    let result = GarrisonConfig::load(Some(temp.path().to_str().unwrap()));
    assert!(result.is_err());
    assert!(matches!(result, Err(GarrisonError::Config(_))));
}

// ========================================================================
// 环境变量覆盖测试
// ========================================================================

/// 验证环境变量优先级高于 toml 配置。
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

/// 验证布尔环境变量解析。
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

/// 验证环境变量非法值抛错。
#[test]
#[serial]
fn env_invalid_value_errors() {
    let _env_guards = [EnvVarGuard::set("GARRISON_TIMEOUT", "not-a-number")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err());
}

/// 验证完整加载流程 load()：默认值 + toml + 环境变量。
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

// ========================================================================
// 热更新测试
// ========================================================================

/// 验证 watch() 返回 receiver，update() 广播新值。
#[test]
fn watch_and_update_broadcasts() {
    let config = GarrisonConfig::default_config();
    let mut rx = config.watch().expect("default_config 应有 watcher");

    config.update(|c| c.timeout = 3600).expect("update 应成功");

    let new_config = rx.borrow_and_update();
    assert_eq!(new_config.timeout, 3600);
}

/// 验证 update() 闭包可以修改多个字段。
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

/// 验证 update() 中非法值被拒绝（不广播）。
#[test]
fn update_rejects_invalid_value() {
    let config = GarrisonConfig::default_config();
    let mut rx = config.watch().unwrap();

    let result = config.update(|c| c.token_style = "invalid".to_string());
    assert!(result.is_err());

    let current = rx.borrow_and_update();
    assert_eq!(current.token_style, "uuid");
}

/// 验证 update() 中 timeout = -1 被拒绝。
#[test]
fn update_rejects_negative_timeout() {
    let config = GarrisonConfig::default_config();
    let mut rx = config.watch().unwrap();

    let result = config.update(|c| c.timeout = -1);
    assert!(result.is_err());

    let current = rx.borrow_and_update();
    assert_eq!(current.timeout, DEFAULT_TIMEOUT);
}

/// 验证无 watcher 的实例 update() 是 no-op。
///
/// 不再手动罗列全部字段构造 `GarrisonConfig`（新增字段即编译失败），
/// 改为 `default_config()` 后移除 watcher（字段对本 crate 子模块可见）。
#[test]
fn update_without_watcher_is_noop() {
    let mut config = GarrisonConfig::default_config();
    // 移除 default_config() 附加的 watcher，构造"未启用 watcher"实例
    config.watcher = None;
    assert!(config.update(|c| c.timeout = 999).is_ok());
    assert!(config.watch().is_none());
}

// ========================================================================
// 序列化测试
// ========================================================================

/// 验证序列化为 toml 往返一致。
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

/// 验证序列化为 json 往返一致。
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

/// 验证 watcher 字段不被序列化。
#[test]
fn watcher_not_serialized() {
    let config = GarrisonConfig::default_config();
    let json_str = serde_json::to_string(&config).unwrap();
    assert!(!json_str.contains("watcher"));
    assert!(!json_str.contains("sender"));
}

// ========================================================================
// 环境变量覆盖错误路径测试（confers 处理，错误类型为 Config）
// ========================================================================

/// 验证 GARRISON_IS_READ_COOKIE 非法布尔值时 load 抛错。
#[test]
#[serial]
fn env_invalid_is_read_cookie_errors() {
    let _env_guards = [EnvVarGuard::set("GARRISON_IS_READ_COOKIE", "maybe")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err(), "非法布尔值应导致 load 失败");
    assert!(matches!(result, Err(GarrisonError::Config(_))));
}

/// 验证 GARRISON_IS_READ_HEADER 非法布尔值时 load 抛错。
#[test]
#[serial]
fn env_invalid_is_read_header_errors() {
    let _env_guards = [EnvVarGuard::set("GARRISON_IS_READ_HEADER", "yesno")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err());
    assert!(matches!(result, Err(GarrisonError::Config(_))));
}

/// 验证 GARRISON_IS_WRITE_HEADER 非法布尔值时 load 抛错。
#[test]
#[serial]
fn env_invalid_is_write_header_errors() {
    let _env_guards = [EnvVarGuard::set("GARRISON_IS_WRITE_HEADER", "unknown")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err());
    assert!(matches!(result, Err(GarrisonError::Config(_))));
}

/// 验证 GARRISON_THROW_ON_NOT_LOGIN 非法布尔值时 load 抛错。
#[test]
#[serial]
fn env_invalid_throw_on_not_login_errors() {
    let _env_guards = [EnvVarGuard::set("GARRISON_THROW_ON_NOT_LOGIN", "yes_no")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err());
    assert!(matches!(result, Err(GarrisonError::Config(_))));
}

/// 验证 GARRISON_ACTIVE_TIMEOUT 非数字时 load 抛错。
#[test]
#[serial]
fn env_invalid_active_timeout_errors() {
    let _env_guards = [EnvVarGuard::set("GARRISON_ACTIVE_TIMEOUT", "not-a-number")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err());
}

/// 验证 GARRISON_TOKEN_STYLE 非法值导致 load 校验失败。
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

/// 验证 GARRISON_TIMEOUT 负值导致 load 校验失败。
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

// ========================================================================
// 字段环境变量覆盖测试
// ========================================================================

/// 验证 `GARRISON_JWT_ALGORITHM` 环境变量覆盖 jwt_algorithm 字段。
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

/// 验证 `GARRISON_SIGN_WINDOW_SECONDS` 环境变量覆盖 sign_window_seconds 字段。
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

/// 验证 `GARRISON_SSO_TICKET_TTL_SECONDS` 环境变量覆盖 sso_ticket_ttl_seconds 字段。
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

/// 验证 `GARRISON_SIGN_WINDOW_SECONDS` 非数字时 load 抛错。
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

/// 验证 `GARRISON_SSO_TICKET_TTL_SECONDS` 非数字时 load 抛错。
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

// ========================================================================
// tenant_isolation 配置段测试
// ========================================================================

/// `GarrisonConfig` 反序列化 JSON 含 `tenant_isolation` 段时，
/// 字段正确填充。
///
/// 验证：`{"tenant_isolation": {"enabled": true, "resolver": "header"}}` 反序列化后
/// `config.tenant_isolation.enabled == true`
/// `config.tenant_isolation.resolver == TenantResolverKind::Header`
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

/// `default_config()` 的 `tenant_isolation` 默认禁用，
/// resolver 默认为 `Header`。
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

/// `TenantResolverKind` 支持全部三种变体反序列化。
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
// auto_renewal_threshold 配置测试
// ========================================================================

/// `GarrisonConfig::default()` 的 `auto_renewal_threshold` 为 -1（不启用）。
#[test]
fn config_default_auto_renewal_is_negative_one() {
    let config = GarrisonConfig::default_config();
    assert_eq!(config.auto_renewal_threshold, -1);
}

/// `auto_renewal_threshold = 101` 时 `validate()` 返回 Err。
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

/// `auto_renewal_threshold = -2` 时 `validate()` 返回 Err。
#[test]
fn validate_rejects_threshold_below_negative_one() {
    let mut config = GarrisonConfig::default_config();
    config.auto_renewal_threshold = -2;
    assert!(config.validate().is_err());
}

/// 边界值 -1、0、100 均通过校验。
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

/// `GARRISON_AUTO_RENEWAL_THRESHOLD=20` 环境变量覆盖配置为 20。
#[test]
#[serial]
fn env_overrides_auto_renewal_threshold() {
    let _env_guards = [EnvVarGuard::set("GARRISON_AUTO_RENEWAL_THRESHOLD", "20")];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert_eq!(config.auto_renewal_threshold, 20);
}

// ========================================================================
// token_map_cleanup_interval_secs 配置测试（4 个）
// ========================================================================

/// `default_config()` 的 `token_map_cleanup_interval_secs` 为 300（5 分钟）。
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

/// 手动设置自定义值（如 600）后字段值生效且通过 `validate()` 校验。
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

/// 设置 -1 表示禁用后台清理 task（与 `interval_secs <= 0` 行为一致）。
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

/// 环境变量 `GARRISON_TOKEN_MAP_CLEANUP_INTERVAL_SECS` 覆盖默认值。
///
/// 注：env var 名按代码库惯例与字段名严格对应（如 `sign_window_seconds` ↔ `GARRISON_SIGN_WINDOW_SECONDS`），
/// 故 `token_map_cleanup_interval_secs` ↔ `GARRISON_TOKEN_MAP_CLEANUP_INTERVAL_SECS`。
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

// ========================================================================
// login_token_map_persist_interval_secs 配置测试
// ========================================================================

/// `default_config()` 的 `login_token_map_persist_interval_secs` 为 0（同步写入）。
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

/// `GARRISON_LOGIN_TOKEN_MAP_PERSIST_INTERVAL_SECS=10` 环境变量覆盖默认值。
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

// ========================================================================
// anon_session_timeout 配置测试
// ========================================================================

/// `default_config()` 的 `anon_session_timeout` 为 1800（30 分钟）。
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

/// `GARRISON_ANON_SESSION_TIMEOUT=3600` 环境变量覆盖默认值。
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

// ========================================================================
// 并发登录控制配置测试
// ========================================================================

/// `GarrisonConfig::default()` 的 `is_concurrent` 为 true。
#[test]
fn config_default_is_concurrent_true() {
    let config = GarrisonConfig::default_config();
    assert!(config.is_concurrent, "默认允许并发登录");
}

/// `GarrisonConfig::default()` 的 `is_share` 为 false。
#[test]
fn config_default_is_share_false() {
    let config = GarrisonConfig::default_config();
    assert!(!config.is_share, "默认不共享 token");
}

/// `GarrisonConfig::default()` 的 `max_login_count` 为 0（不限制）。
#[test]
fn config_default_max_login_count_zero() {
    let config = GarrisonConfig::default_config();
    assert_eq!(config.max_login_count, 0, "默认不限制登录数量");
}

/// `is_share=true` 但 `is_concurrent=false` 时 `validate()` 返回 Err。
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

/// `is_share=true` 且 `is_concurrent=true` 时校验通过。
#[test]
fn validate_accepts_share_with_concurrent() {
    let mut config = GarrisonConfig::default_config();
    config.is_concurrent = true;
    config.is_share = true;
    assert!(config.validate().is_ok());
}

/// `GARRISON_IS_CONCURRENT=false` 环境变量覆盖配置。
#[test]
#[serial]
fn env_overrides_is_concurrent() {
    let _env_guards = [EnvVarGuard::set("GARRISON_IS_CONCURRENT", "false")];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert!(!config.is_concurrent);
}

/// `GARRISON_MAX_LOGIN_COUNT=3` 环境变量覆盖配置。
#[test]
#[serial]
fn env_overrides_max_login_count() {
    let _env_guards = [EnvVarGuard::set("GARRISON_MAX_LOGIN_COUNT", "3")];
    let config = GarrisonConfig::load(None).expect("load with env");
    assert_eq!(config.max_login_count, 3);
}

// ========================================================================
// is_read_body 配置测试
// ========================================================================

/// `default_config()` 的 `is_read_body` 为 false。
#[test]
fn config_default_is_read_body_is_false() {
    let config = GarrisonConfig::default_config();
    assert!(!config.is_read_body, "默认 is_read_body 应为 false");
    assert_eq!(
        config.is_read_body, DEFAULT_IS_READ_BODY,
        "应等于 DEFAULT_IS_READ_BODY 常量"
    );
}

/// `GARRISON_IS_READ_BODY=true` 环境变量覆盖配置为 true。
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

// ========================================================================
// device_binding_mode 配置测试（4 个，spec R-device-binding-001）
// ========================================================================

/// `default_config()` 的 `device_binding_mode` 为 "disabled"。
#[test]
fn test_device_binding_mode_default() {
    let config = GarrisonConfig::default_config();
    assert_eq!(
        config.device_binding_mode, "disabled",
        "默认 device_binding_mode 应为 'disabled'"
    );
}

/// 自定义值 "strict" 通过 `validate()` 校验。
#[test]
fn test_device_binding_mode_custom() {
    let mut config = GarrisonConfig::default_config();
    config.device_binding_mode = "strict".to_string();
    assert!(
        config.validate().is_ok(),
        "device_binding_mode='strict' 应通过校验"
    );
}

/// 无效值 "invalid" 校验失败返回 `Err`。
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

/// 环境变量 `GARRISON_DEVICE_BINDING_MODE=loose` 覆盖配置值。
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

// ========================================================================
// validate() redis_url 非空校验测试（3 个）
// ========================================================================

/// 验证 `rate_limit_backend=Redis` 且 `redis_url` 为空时 `validate()` 返回 Err。
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

/// 验证 `rate_limit_backend=Redis` 且 `redis_url` 非空时 `validate()` 通过。
#[cfg(feature = "rate-limit-redis")]
#[test]
fn validate_accepts_non_empty_redis_url() {
    let mut config = GarrisonConfig::default_config();
    config.rate_limit_backend = RateLimitBackend::Redis {
        redis_url: "redis://127.0.0.1:6379/0".to_string(),
    };
    assert!(config.validate().is_ok(), "非空 redis_url 应通过 validate");
}

/// 验证 `rate_limit_backend=Memory` 时 `validate()` 不检查 redis_url。
#[cfg(feature = "rate-limit-redis")]
#[test]
fn validate_memory_backend_skips_redis_url_check() {
    let config = GarrisonConfig::default_config();
    assert_eq!(config.rate_limit_backend, RateLimitBackend::Memory);
    assert!(config.validate().is_ok(), "Memory 后端应通过 validate");
}

// ========================================================================
// 环境变量覆盖测试（6 个 serial）
// ========================================================================

/// `GARRISON_CORS_ALLOWED_ORIGINS` 覆盖 CORS 允许的源列表。
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

/// `GARRISON_CORS_ALLOWED_ORIGINS` 过滤空值（连续逗号）。
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

/// `GARRISON_CSRF_ENABLED=true` 覆盖 CSRF 启用状态。
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

/// `GARRISON_CSRF_ENABLED` 仅接受 true/false（大小写不敏感）。
///
/// "TRUE"/"False" 合法生效；fail-closed 对齐 `GARRISON_RATE_LIMIT_BACKEND`。
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

/// `GARRISON_CSRF_ENABLED` 非 true/false 值返回 Config 硬错误（fail-closed）。
///
/// "1"/"yes"/"on" 等 truthy 习惯值此前会静默禁用 CSRF 防护（安全控制
/// 不允许歧义取值），现对齐限流后端覆盖的硬错误语义。
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

// ========================================================================
// config-security-rules 安全规则集（静态-配置与部署-1）
// ========================================================================

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
    assert!(
        err.to_string().contains("config-jwt-secret-weak"),
        "实际: {}",
        err
    );
}

/// feature 开启时加固配置通过 validate()（强密钥 + 显式 origin 白名单）。
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

/// feature 开启时通配 origin 且未开 credentials：不拒绝（公开只读 API 是
/// 合法场景）但必须落 warn（显性提示任意源可读响应）。
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

/// feature 关闭时安全规则集不生效（零行为变化）：同样的通配 origin 配置
/// 不产生规则集 warn——两条 cfg 侧测试分别锁定两个 feature 形态的行为。
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

/// `GARRISON_RATE_LIMIT_BACKEND=redis` 覆盖限流后端为 Redis。
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

/// `GARRISON_RATE_LIMIT_BACKEND=memory` 覆盖限流后端为 Memory。
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

/// 仅设置 `GARRISON_REDIS_URL`（不设 backend）不改变 Memory 后端。
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

/// `GARRISON_RATE_LIMIT_BACKEND` 无效值返回 Config 错误（失败必须显性化）。
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

// ========================================================================
// 并发登录策略枚举配置测试
// ========================================================================

/// `GarrisonConfig::default()` 的 `replaced_login_exit_mode` 为 `OldDevice`。
#[test]
fn config_default_replaced_login_exit_mode_is_old_device() {
    let config = GarrisonConfig::default_config();
    assert_eq!(
        config.replaced_login_exit_mode,
        ReplacedLoginExitMode::OldDevice,
        "默认 replaced_login_exit_mode 应为 OldDevice"
    );
}

/// `GarrisonConfig::default()` 的 `overflow_logout_mode` 为 `Logout`。
#[test]
fn config_default_overflow_logout_mode_is_logout() {
    let config = GarrisonConfig::default_config();
    assert_eq!(
        config.overflow_logout_mode,
        OverflowLogoutMode::Logout,
        "默认 overflow_logout_mode 应为 Logout"
    );
}

/// `ReplacedLoginExitMode` 序列化为 snake_case 字符串 "old_device"/"new_device"。
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

/// `OverflowLogoutMode` 序列化为 snake_case 字符串 "logout"/"kickout"/"replaced"。
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

/// `GARRISON_REPLACED_LOGIN_EXIT_MODE=new_device` 环境变量覆盖配置。
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

/// `GARRISON_OVERFLOW_LOGOUT_MODE=kickout` 环境变量覆盖配置。
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

// ========================================================================
// recent_reuse_behaviour / refresh_grace 配置测试
// ========================================================================

/// `default_config()` 的 `recent_reuse_behaviour` 为 `TheftDetected`。
#[test]
fn default_recent_reuse_behaviour_is_theft_detected() {
    let config = GarrisonConfig::default_config();
    assert_eq!(
        config.recent_reuse_behaviour,
        RecentReuseBehaviour::TheftDetected,
        "默认 recent_reuse_behaviour 应为 TheftDetected"
    );
}

/// `RecentReuseBehaviour` 序列化为 snake_case 字符串。
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

/// `GARRISON_RECENT_REUSE_BEHAVIOUR=unauthorised` 环境变量覆盖配置。
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

/// `GARRISON_RECENT_REUSE_BEHAVIOUR` 非法值启动期 fail-fast。
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

/// `default_config()` 的宽限窗口默认关闭（0 秒 / 1 次）。
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

/// `refresh_grace_period_secs` 为负数时校验失败。
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

/// `refresh_grace_max_uses = 0` 时校验失败（关闭窗口应置 period_secs = 0）。
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

/// `GARRISON_REFRESH_GRACE_PERIOD_SECS` 环境变量覆盖配置。
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

// ========================================================================
// audit_mask_mode 配置测试
// ========================================================================

/// `default_config()` 的 `audit_mask_mode` 为 `Partial`。
#[test]
fn default_audit_mask_mode_is_partial() {
    let config = GarrisonConfig::default_config();
    assert_eq!(
        config.audit_mask_mode,
        AuditMaskMode::Partial,
        "默认 audit_mask_mode 应为 Partial"
    );
}

/// `AuditMaskMode` 序列化为 snake_case 字符串 "full"/"partial"。
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

/// `GARRISON_AUDIT_MASK_MODE=full` 环境变量覆盖配置为 Full。
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

// ========================================================================
// anomalous-detector-dual validate() 校验测试
// ========================================================================

/// `anomalous_analyzer_interval_secs < 60` 时 validate() 返回 Err。
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

/// `anomalous_analyzer_interval_secs = 60` 时 validate() 通过（边界值）。
#[cfg(feature = "anomalous-detector-dual")]
#[test]
fn validate_accepts_anomalous_interval_at_60() {
    let mut config = GarrisonConfig::default_config();
    config.anomalous_analyzer_interval_secs = 60;
    assert!(config.validate().is_ok(), "interval=60 应通过 validate");
}

/// `anomalous_analyzer_burst_threshold = 0` 时 validate() 返回 Err。
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

// === 安全审查 load() 安全防护集成测试 ===

/// 验证 `load` 拒绝空路径。
#[test]
fn load_rejects_empty_path() {
    let err = GarrisonConfig::load(Some("")).unwrap_err();
    assert!(
        matches!(err, GarrisonError::Config(ref m) if m.contains("must not be empty")),
        "空路径应被拒绝，实际: {:?}",
        err
    );
}

/// 验证 `load` 拒绝包含 `..` 的路径遍历路径。
///
/// 文件加载迁入 confers `FileSource` 后由上游 `check_path_components`
/// 拒绝 ParentDir（行为不变，错误文案为 confers 泛化格式）。
#[test]
fn load_rejects_path_traversal() {
    let err = GarrisonConfig::load(Some("../etc/passwd")).unwrap_err();
    assert!(
        matches!(err, GarrisonError::Config(ref m) if m.contains("config-open-failed")),
        "路径遍历 `..` 应被拒绝（红acted FileNotFound），实际: {:?}",
        err
    );
}

/// 验证 `load` 拒绝 URL 编码的路径遍历 `%2e%2e`。
///
/// 文件加载迁入 confers `FileSource` 后，上游在路径验证前置扫描 URL 编码
/// 遍历模式（防御纵深：fs API 虽不解码 `%2e`，但下游代理/网关可能解码），
/// `%2e%2e` 被主动拒绝而非按字面路径处理。
#[test]
fn load_url_encoded_traversal_returns_enoent() {
    let err = GarrisonConfig::load(Some("%2e%2e/etc/passwd")).unwrap_err();
    assert!(
        matches!(err, GarrisonError::Config(ref m) if m.contains("config-open-failed")),
        "%2e%2e 应被拒绝，实际: {:?}",
        err
    );
}

/// 验证 `load` 拒绝超大配置文件（10MB 上限）。
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

/// 验证 `load` 拒绝字符设备（is_file 检查）。
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

/// 验证 `load` 拒绝目录（is_file 检查）。
///
/// 跨平台行为差异：
/// - Linux/macOS：`File::open(dir)` 成功，由 `metadata.is_file()` 返回 false 触发 "不是普通文件"
/// - Windows：`File::open(dir)` 直接返回 `ERROR_ACCESS_DENIED`，触发 "打开配置文件失败"
///
#[serial]
/// 两种路径都达到了"目录被拒绝"的安全目标，测试应同时接受。
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

// ========================================================================
// JWT 非对称配置扩展（RS256/ES256/EdDSA）
// ========================================================================

/// 测试专用 RSA 2048 私钥（PKCS#8，非真实凭证）。
#[allow(dead_code)]
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

/// RS256 + RSA 私钥 PEM：合法配置通过校验。
#[test]
fn validate_accepts_rs256_with_rsa_pem() {
    let mut config = GarrisonConfig::default();
    config.token_style = "jwt".to_string();
    config.jwt_algorithm = "RS256".to_string();
    config.jwt_rsa_private_key_pem = Some(TEST_ASYM_RSA_PEM.to_string());
    assert!(config.validate().is_ok(), "RS256 + rsa pem 应通过校验");
}

/// RS256 缺 RSA 私钥 PEM：拒绝。
#[test]
fn validate_rejects_rs256_without_rsa_pem() {
    let mut config = GarrisonConfig::default();
    config.token_style = "jwt".to_string();
    config.jwt_algorithm = "RS256".to_string();
    config.jwt_secret = "0123456789abcdef0123456789abcdef".to_string().into();
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("config-jwt-key-missing"));
}

/// 同时配置两类私钥 PEM：拒绝（防配置歧义）。
#[test]
fn validate_rejects_multiple_key_types() {
    let mut config = GarrisonConfig::default();
    config.jwt_algorithm = "RS256".to_string();
    config.jwt_rsa_private_key_pem = Some(TEST_ASYM_RSA_PEM.to_string());
    config.jwt_ec_private_key_pem = Some("dummy".to_string());
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("config-jwt-key-multiple-types"));
}

/// HS 系算法配置任何非对称私钥：拒绝。
#[test]
fn validate_rejects_asymmetric_key_for_hs() {
    let mut config = GarrisonConfig::default();
    config.jwt_algorithm = "HS256".to_string();
    config.jwt_secret = "0123456789abcdef0123456789abcdef".to_string().into();
    config.jwt_rsa_private_key_pem = Some(TEST_ASYM_RSA_PEM.to_string());
    let err = config.validate().unwrap_err();
    assert!(err.to_string().contains("config-jwt-key-unexpected-for-hs"));
}

/// 非对称私钥字段 Debug 输出脱敏。
#[test]
fn debug_redacts_asymmetric_pem_fields() {
    let mut config = GarrisonConfig::default();
    config.jwt_rsa_private_key_pem = Some(TEST_ASYM_RSA_PEM.to_string());
    let debug = format!("{:?}", config);
    assert!(!debug.contains("MIIEvg"), "Debug 输出不得包含 PEM 内容");
    assert!(debug.contains("<redacted>"));
}

// ============================================================================
// password_hasher 配置段（T030）
// ============================================================================

/// 默认值锁定：argon2id + OWASP 建议档（19456/2/1）+ bcrypt 12 + 风险接受位关闭，
/// 且默认配置整体校验通过。
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

/// TOML 配置节反序列化（serde(default) 补全缺省字段）。
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

/// 非法算法名：拒绝。
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

/// argon2id m_cost 低于 19456 下限且未显式风险接受：拒绝。
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
    let mut config = GarrisonConfig::default();
    config.password_hasher.algorithm = "bcrypt".to_string();
    config.password_hasher.bcrypt_cost = 10;
    assert!(config.validate().is_ok());
    config.password_hasher.bcrypt_cost = 15;
    assert!(config.validate().is_ok());
}

/// `build_hasher` 工厂：argon2id 按配置参数产出（PHC 前缀断言 m/t/p）。
#[cfg(feature = "account-credential")]
#[test]
fn build_hasher_argon2id_uses_configured_params() {
    let mut ph = PasswordHasherConfig::default();
    ph.argon2_m_cost = 32768;
    ph.argon2_t_cost = 3;
    ph.argon2_p_cost = 2;
    let hasher = ph.build_hasher().unwrap();
    let hash = hasher.hash("password").unwrap();
    assert!(
        hash.starts_with("$argon2id$v=19$m=32768,t=3,p=2"),
        "PHC 前缀应反映配置参数，实际: {}",
        &hash[..hash.len().min(40)]
    );
}

/// `build_hasher` 工厂：bcrypt 按配置 cost 产出（$2b$ 前缀携带 cost）。
#[cfg(feature = "account-credential")]
#[test]
fn build_hasher_bcrypt_uses_configured_cost() {
    let mut ph = PasswordHasherConfig::default();
    ph.algorithm = "bcrypt".to_string();
    ph.bcrypt_cost = 10;
    let hasher = ph.build_hasher().unwrap();
    let hash = hasher.hash("password").unwrap();
    assert!(
        hash.starts_with("$2b$10$"),
        "bcrypt 哈希应使用配置 cost=10，实际: {}",
        &hash[..hash.len().min(10)]
    );
}

/// `build_hasher` 工厂：非法算法名 fail-fast（与 validate 同语义）。
#[cfg(feature = "account-credential")]
#[test]
fn build_hasher_rejects_unknown_algorithm() {
    let mut ph = PasswordHasherConfig::default();
    ph.algorithm = "scrypt".to_string();
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

// ============================================================================
// argon2 并发令牌池（R02 内存 DoS 防护）
// ============================================================================

/// argon2_pool_size 默认 1（secure-by-default：默认配置即受并发内存上界防护），
/// 且默认配置整体校验通过。
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

/// argon2_pool_size 区间校验 [1, 256]：0（零 permit 永久饥饿）与 257
/// （256 × 19 MiB ≈ 4.8 GiB 误配上界之外）拒绝，1/256 边界放行。
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

/// 环境变量嵌套映射：`GARRISON_PASSWORD_HASHER__ARGON2_POOL_SIZE=8` 经 load() 生效
/// （双下划线折叠为嵌套路径，与既有嵌套段同机制）。
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

/// `build_hasher` 池装配：argon2id 分支按 `argon2_pool_size` 配置装配并发令牌池。
#[cfg(feature = "account-credential")]
#[test]
fn build_hasher_argon2_wires_pool_size() {
    let mut ph = PasswordHasherConfig::default();
    ph.argon2_pool_size = 3;
    let hasher = ph.build_hasher().unwrap();
    let gate = hasher.concurrency_gate().expect("argon2id 分支应装配池");
    assert_eq!(gate.available_permits(), 3, "permit 数应等于配置池大小");
}

/// bcrypt 决策锁定：bcrypt 分支不装配并发令牌池（gate 为 None）。
///
/// 依据：bcrypt 单次执行工作区 KB 级，池化无内存防护收益；CPU DoS 由限流与
/// cost 区间校验承担。该决策以测试固化，防止后续无意接入池语义。
#[cfg(feature = "account-credential")]
#[test]
fn build_hasher_bcrypt_has_no_pool() {
    let mut ph = PasswordHasherConfig::default();
    ph.algorithm = "bcrypt".to_string();
    ph.bcrypt_cost = 12;
    let hasher = ph.build_hasher().unwrap();
    assert!(
        hasher.concurrency_gate().is_none(),
        "bcrypt 不入池：gate 必须为 None"
    );
}

// ========================================================================
// 弃用配置键注册表：加载期自动迁移 + 1.0 版本门
// ========================================================================

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

/// 在捕获 tracing 事件的上下文中执行 `f`（守卫覆盖 `f` 全程，返回后恢复）。
/// 日志行通过回调参数交由断言读取；`DefaultGuard` 在 default-features=false
/// 构建下无公开类型路径，故以闭包作用域持有。
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

/// 命中可自动映射键：旧值经 map_fn 转换后写入新键，旧键从树中移除。
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

/// 命中 auto_map 且无 map_fn：旧值原样搬迁到新键（同类型改名）。
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

/// 新键已被显式配置时不覆盖（新键优先），旧键仍移除。
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

/// 嵌套段键（点号路径）同样支持自动映射。
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

/// 迁移 warn 日志必须含 since 版本与新键名（R-cfg-dep-001 日志捕获断言）。
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

/// 无命中时树不变、零告警（热路径零开销的行为面）。
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

/// 加载路径接线：toml 中的弃用键在加载后迁移到新配置字段（值经 map_fn 转换）。
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

/// 加载路径接线：环境变量中的弃用键同样迁移。
#[test]
#[serial]
fn load_auto_migrates_deprecated_env_key() {
    let _guard = EnvVarGuard::set("GARRISON_TIMEOUT_SECONDS", "120");
    let config =
        GarrisonConfig::load_with_deprecations(None, &[fixture_timeout_migration()], "0.9.0")
            .expect("弃用键自动迁移后加载应成功");
    assert_eq!(config.timeout, 7200);
}

/// 注册表非空但配置无弃用键：加载行为与无注册表完全一致。
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

/// 注册表不变式：键唯一且按注册顺序可线性扫描（未来补录条目时防止重复注册）。
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

/// 不可映射键在 <1.0.0 命中：warn 后放行（Ok，树不变——旧键保留随 serde 忽略）。
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

/// 不可映射键在 ≥1.0.0 命中：GarrisonError 显性报错，消息含键名与迁移指引。
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

/// 可自动映射键在 ≥1.0.0 命中：同样报错（1.0 起不再代迁）。
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

/// 1.0.0 的 pre-release（如 1.0.0-rc.1）仍在宽限窗口内（< 1.0.0 本体）。
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

/// 当前版本不可解析且存在命中：fail-closed 报错。
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

/// map_fn 拒绝迁移该值：计入错误（静默丢弃即静默失效）。
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

/// 加载路径：≥1.0.0 时弃用键使 load 整体返回 GarrisonError::Config（错误
/// 含键名与迁移指引，且发生在 validate 之前）。
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

/// 加载路径：map_fn 拒绝迁移的值使 load 整体失败（错误显性，值不静默丢弃）。
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

/// 生产注册表真实条目 `waf_config`（<1.0 命中）：warn 含键名与 since 版本，
/// 放行且树不变（旧键随 serde 忽略——但不再静默）。
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

/// 生产注册表真实条目 `waf_config`（≥1.0 命中）：硬错误，消息含键名与移除指引。
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

/// 端到端：toml `[waf_config]` 段经生产注册表 + 生产版本（0.9.0-rc.2，<1.0）
/// 加载——warn 显性化且加载成功（旧行为是无任何提示的静默忽略）。
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

/// 端到端：同一 toml 在注入 1.0.0 版本时加载整体失败（宽限窗口关闭）。
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

// ========================================================================
// jwks_retention_secs 配置测试
// ========================================================================

/// `default_config()` 的 `jwks_retention_secs` 为 7200（2× access token TTL）。
#[test]
fn jwks_retention_default_is_two_access_token_ttls() {
    let config = GarrisonConfig::default_config();
    assert_eq!(config.jwks_retention_secs, 7200);
}

/// `jwks_retention_secs = 0` 为误配：validate 显性拒绝（0 等价于轮换瞬间
/// 退役旧钥，存量 token 验证立即中断）。
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

/// 正值 retention 通过校验。
#[test]
fn jwks_retention_positive_passes_validation() {
    let mut config = GarrisonConfig::default_config();
    config.jwks_retention_secs = 600;
    config.validate().expect("正值 retention 必须通过校验");
}

// ============================================================================
// MFA 编排基座：per-client chain 三态与 fail-closed 校验
// ============================================================================

/// default_config() 的 mfa 段：全局链为空、无 per-client 覆盖（不强制 MFA）。
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

/// 全局链引用未知 factor → validate 返回 Config 错误（fail-closed）。
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

/// per-client 链引用未知 factor → validate 返回 Config 错误（fail-closed）。
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

/// 已知 factor（otp / webauthn）的全局与 per-client 链均通过校验。
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

// ========================================================================
// seed_primary_amr / login_id_max_len 配置测试（渗透-认证绕过-3 /
// 注入-login_id 无长度上限-2）
// ========================================================================

/// `default_config()`：seed_primary_amr 默认 true（保持既有播种契约）。
#[test]
fn config_default_seed_primary_amr_is_true() {
    let config = GarrisonConfig::default_config();
    assert!(
        config.seed_primary_amr,
        "seed_primary_amr 默认应为 true（开关默认保持现状，安全敏感部署显式关闭）"
    );
}

/// `default_config()`：login_id_max_len 默认 255。
#[test]
fn config_default_login_id_max_len_is_255() {
    let config = GarrisonConfig::default_config();
    assert_eq!(config.login_id_max_len, 255);
    assert_eq!(config.login_id_max_len, DEFAULT_LOGIN_ID_MAX_LEN);
}

/// `GARRISON_SEED_PRIMARY_AMR=false` 环境变量覆盖生效。
#[serial]
#[test]
fn config_env_override_seed_primary_amr_false() {
    let _env_guards = [EnvVarGuard::set("GARRISON_SEED_PRIMARY_AMR", "false")];
    let config = GarrisonConfig::load(None).expect("合法 env 覆盖应加载成功");
    assert!(!config.seed_primary_amr, "env 覆盖 false 应生效");
}

/// `GARRISON_SEED_PRIMARY_AMR` 非布尔值 → 加载期类型校验拒绝（fail-closed）。
#[serial]
#[test]
fn config_env_seed_primary_amr_invalid_type_rejected() {
    let _env_guards = [EnvVarGuard::set("GARRISON_SEED_PRIMARY_AMR", "not-a-bool")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err(), "非布尔 seed_primary_amr 应在加载期拒绝");
}

// ========================================================================
// require_tenant_bound_jwt 配置测试（渗透-租户隔离严格收口：存量无 tid
// Stateless token 在租户上下文内显性拒绝的开关）
// ========================================================================

/// `default_config()`：require_tenant_bound_jwt 默认 false（保持存量 token 兼容）。
#[test]
fn config_default_require_tenant_bound_jwt_is_false() {
    let config = GarrisonConfig::default_config();
    assert!(
        !config.require_tenant_bound_jwt,
        "require_tenant_bound_jwt 默认应为 false（开关默认放行存量无 tid token，安全敏感部署显式开启）"
    );
}

/// `GARRISON_REQUIRE_TENANT_BOUND_JWT=true` 环境变量覆盖生效。
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

/// `GARRISON_REQUIRE_TENANT_BOUND_JWT` 非布尔值 → 加载期类型校验拒绝（fail-closed）。
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

/// `GARRISON_LOGIN_ID_MAX_LEN=128` 环境变量覆盖生效。
#[serial]
#[test]
fn config_env_override_login_id_max_len() {
    let _env_guards = [EnvVarGuard::set("GARRISON_LOGIN_ID_MAX_LEN", "128")];
    let config = GarrisonConfig::load(None).expect("合法 env 覆盖应加载成功");
    assert_eq!(config.login_id_max_len, 128);
}

/// `GARRISON_LOGIN_ID_MAX_LEN=0` 合法（0 = 框架层不限制）。
#[serial]
#[test]
fn config_env_login_id_max_len_zero_means_unlimited() {
    let _env_guards = [EnvVarGuard::set("GARRISON_LOGIN_ID_MAX_LEN", "0")];
    let config = GarrisonConfig::load(None).expect("0=不限制应加载成功");
    assert_eq!(config.login_id_max_len, 0);
}

/// `GARRISON_LOGIN_ID_MAX_LEN` 非整数值 → 加载期类型校验拒绝。
#[serial]
#[test]
fn config_env_login_id_max_len_invalid_type_rejected() {
    let _env_guards = [EnvVarGuard::set("GARRISON_LOGIN_ID_MAX_LEN", "abc")];
    let result = GarrisonConfig::load(None);
    assert!(result.is_err(), "非整数 login_id_max_len 应在加载期拒绝");
}
