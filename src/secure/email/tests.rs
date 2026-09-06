//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! 邮箱验证码模块单元测试。

use super::rate_limiter::{normalize_email, validate_email};
use super::service::{constant_time_eq, generate_code};

// ============================================================
// normalize_email 测试
// ============================================================

#[test]
fn normalize_email_trims_and_lowercases() {
    assert_eq!(normalize_email(" Foo@Example.COM "), "foo@example.com");
    assert_eq!(normalize_email("USER@DOMAIN.ORG"), "user@domain.org");
    assert_eq!(normalize_email("  a@b.c  "), "a@b.c");
}

#[test]
fn normalize_email_empty_string() {
    assert_eq!(normalize_email(""), "");
    assert_eq!(normalize_email("   "), "");
}

// ============================================================
// validate_email 测试
// ============================================================

#[test]
fn validate_email_valid() {
    assert!(validate_email("user@example.com").is_ok());
    assert!(validate_email("a@b.c").is_ok());
    assert!(validate_email("test+tag@domain.org").is_ok());
}

#[test]
fn validate_email_empty_rejected() {
    let err = validate_email("").unwrap_err();
    assert!(
        matches!(err, crate::error::GarrisonError::InvalidParam(msg) if msg.starts_with("secure-email-empty"))
    );
}

#[test]
fn validate_email_colon_rejected() {
    let err = validate_email("a:b@c.com").unwrap_err();
    assert!(
        matches!(err, crate::error::GarrisonError::InvalidParam(msg) if msg == "secure-email-no-colon")
    );
}

#[test]
fn validate_email_control_char_rejected() {
    let err = validate_email("user\x00@example.com").unwrap_err();
    assert!(
        matches!(err, crate::error::GarrisonError::InvalidParam(msg) if msg == "secure-email-no-control-char")
    );
}

#[test]
fn validate_email_too_long_rejected() {
    let long = format!("{}@b.com", "a".repeat(250));
    let err = validate_email(&long).unwrap_err();
    assert!(
        matches!(err, crate::error::GarrisonError::InvalidParam(msg) if msg.starts_with("secure-email-invalid-format"))
    );
}

#[test]
fn validate_email_no_at_rejected() {
    let err = validate_email("userexample.com").unwrap_err();
    assert!(
        matches!(err, crate::error::GarrisonError::InvalidParam(msg) if msg.starts_with("secure-email-invalid-format"))
    );
}

// ============================================================
// generate_code 测试
// ============================================================

#[test]
fn generate_code_returns_six_digits() {
    for _ in 0..100 {
        let code = generate_code().unwrap();
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert_ne!(code, "000000");
        // 范围 100000..1000000
        let num: u32 = code.parse().unwrap();
        assert!(num >= 100000 && num < 1000000);
    }
}

// ============================================================
// constant_time_eq 测试
// ============================================================

#[test]
fn constant_time_eq_equal_strings() {
    assert!(constant_time_eq("123456", "123456"));
}

#[test]
fn constant_time_eq_different_strings() {
    assert!(!constant_time_eq("123456", "654321"));
    assert!(!constant_time_eq("123456", "123457"));
}

#[test]
fn constant_time_eq_different_lengths() {
    assert!(!constant_time_eq("123456", "12345"));
    assert!(!constant_time_eq("12", "123456"));
}

// ============================================================
// SmtpConfig 测试（仅 email-verification-smtp feature）
// ============================================================

#[cfg(feature = "email-verification-smtp")]
#[test]
fn smtp_config_defaults() {
    let config = super::smtp::SmtpConfig::default();
    assert_eq!(config.port, 587);
    assert_eq!(config.from_name, "Garrison");
    assert!(config.use_tls);
    assert!(config.host.is_empty());
    assert!(config.username.is_empty());
}
