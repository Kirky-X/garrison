//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! `httpbasic` 模块单元测试。

use super::*;
use base64::{engine::general_purpose::STANDARD, Engine};

// ========================================================================
// encode 测试
// ========================================================================

/// 编码用户名密码为 Base64，解码后等于 "user:pass"。
#[test]
fn encode_produces_valid_base64() {
    let encoded = HttpBasicAuth::encode("alice", "secret");
    let decoded = STANDARD.decode(&encoded).unwrap();
    let decoded_str = String::from_utf8(decoded).unwrap();
    assert_eq!(decoded_str, "alice:secret");
}

/// encode/decode 往返一致。
#[test]
fn encode_decode_roundtrip() {
    let encoded = HttpBasicAuth::encode("bob", "p@ss");
    let cred = HttpBasicAuth::decode(&encoded).unwrap();
    assert_eq!(cred.user, "bob");
    assert_eq!(cred.pass, "p@ss");
}

/// 空用户名编码解码。
#[test]
fn encode_decode_empty_user() {
    let encoded = HttpBasicAuth::encode("", "pass");
    let cred = HttpBasicAuth::decode(&encoded).unwrap();
    assert_eq!(cred.user, "");
    assert_eq!(cred.pass, "pass");
}

/// 含特殊字符的凭证。
#[test]
fn encode_decode_special_characters() {
    let encoded = HttpBasicAuth::encode("用户", "密码!@#");
    let cred = HttpBasicAuth::decode(&encoded).unwrap();
    assert_eq!(cred.user, "用户");
    assert_eq!(cred.pass, "密码!@#");
}

// ========================================================================
// decode 测试
// ========================================================================

/// 解码合法 Base64 凭证（spec Scenario）。
#[test]
fn decode_valid_base64_credential() {
    // "alice:secret" 的 Base64
    let cred = HttpBasicAuth::decode("YWxpY2U6c2VjcmV0").unwrap();
    assert_eq!(cred.user, "alice");
    assert_eq!(cred.pass, "secret");
}

/// 解码非法 Base64 字符串失败（spec Scenario）。
#[test]
fn decode_invalid_base64_errors() {
    let result = HttpBasicAuth::decode("!!!not-base64!!!");
    assert!(result.is_err());
}

/// 解码后缺失冒号分隔符失败（spec Scenario）。
#[test]
fn decode_missing_colon_errors() {
    // "usernocolon" 的 Base64
    let result = HttpBasicAuth::decode("dXNlcm5hbWVub2NvbG9u");
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("冒号分隔符"));
}

// ========================================================================
// parse_authorization_header 测试
// ========================================================================

/// 解析完整 Authorization Header（spec Scenario）。
#[test]
fn parse_full_authorization_header() {
    let cred = HttpBasicAuth::parse_authorization_header("Basic YWxpY2U6c2VjcmV0").unwrap();
    assert_eq!(cred.user, "alice");
    assert_eq!(cred.pass, "secret");
}

/// Header 前缀非 Basic 失败（spec Scenario）。
#[test]
fn parse_non_basic_scheme_errors() {
    let result = HttpBasicAuth::parse_authorization_header("Bearer some.token.value");
    assert!(result.is_err());
}

/// Header 缺少凭证部分失败（spec Scenario）。
#[test]
fn parse_missing_credentials_errors() {
    let result = HttpBasicAuth::parse_authorization_header("Basic");
    assert!(result.is_err());
}

/// Basic 方案大小写不敏感（RFC 7235）。
#[test]
fn parse_basic_scheme_case_insensitive() {
    let cred = HttpBasicAuth::parse_authorization_header("BASIC YWxpY2U6c2VjcmV0").unwrap();
    assert_eq!(cred.user, "alice");
}
