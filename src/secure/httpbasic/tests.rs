// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! `httpbasic` 模块单元测试。

use super::*;
use crate::error::GarrisonError;
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

/// 解码合法 Base64 凭证。
#[test]
fn decode_valid_base64_credential() {
    // "alice:secret" 的 Base64
    let cred = HttpBasicAuth::decode("YWxpY2U6c2VjcmV0").unwrap();
    assert_eq!(cred.user, "alice");
    assert_eq!(cred.pass, "secret");
}

/// 解码非法 Base64 字符串失败。
#[test]
fn decode_invalid_base64_errors() {
    let result = HttpBasicAuth::decode("!!!not-base64!!!");
    // 客户端输入错误应返回 InvalidParam（HTTP 400 语义），而非 Internal（500）
    assert!(
        matches!(result, Err(GarrisonError::InvalidParam(_))),
        "非法 Base64 应返回 InvalidParam，实际: {:?}",
        result
    );
}

/// 解码后缺失冒号分隔符失败。
#[test]
fn decode_missing_colon_errors() {
    // 钉住 locale：断言依赖中文模板文案（42b7675 起默认语言为英文，guard 随测试作用域恢复）
    let _locale_guard = crate::i18n::set_locale(crate::i18n::GarrisonLocale::Zh);
    // "usernocolon" 的 Base64
    let result = HttpBasicAuth::decode("dXNlcm5hbWVub2NvbG9u");
    assert!(result.is_err());
    assert!(
        matches!(result, Err(GarrisonError::InvalidParam(_))),
        "缺失冒号分隔符应返回 InvalidParam，实际: {:?}",
        result
    );
    assert!(result.unwrap_err().to_string().contains("冒号分隔符"));
}

/// 密码中包含冒号：split_once 在第一个冒号处分割，密码含 `:` 应正确往返。
#[test]
fn decode_password_containing_colon_roundtrips() {
    // "alice:p@ss:word" → user="alice", pass="p@ss:word"
    let encoded = HttpBasicAuth::encode("alice", "p@ss:word");
    let cred = HttpBasicAuth::decode(&encoded).unwrap();
    assert_eq!(cred.user, "alice");
    assert_eq!(cred.pass, "p@ss:word");
}

/// 解码结果为非法 UTF-8 字节时返回 InvalidParam（而非 from_utf8_lossy 静默替换）。
#[test]
fn decode_invalid_utf8_errors() {
    // bytes [0xFF, 0xFE] 为非法 UTF-8；Base64 编码为 "//4="
    use base64::{engine::general_purpose::STANDARD, Engine};
    let encoded = STANDARD.encode([0xFFu8, 0xFE]);
    let result = HttpBasicAuth::decode(&encoded);
    assert!(
        matches!(result, Err(GarrisonError::InvalidParam(ref msg)) if msg.contains("secure-utf8-decode")),
        "非法 UTF-8 解码应返回 InvalidParam（secure-utf8-decode），实际: {:?}",
        result
    );
}

/// 超过 4KB 上限的 Base64 凭证被拒绝（DoS 防护）。
#[test]
fn decode_over_max_length_rejected() {
    // 5KB 合法 Base64 字符（'A' 重复），超过 4KB 上限
    let oversized = "A".repeat(5 * 1024);
    let result = HttpBasicAuth::decode(&oversized);
    assert!(
        matches!(result, Err(GarrisonError::InvalidParam(ref msg)) if msg.contains("secure-cred-too-long")),
        "超过 4KB 输入应返回 InvalidParam（secure-cred-too-long），实际: {:?}",
        result
    );
}

/// 恰好在 4KB 上限内的输入不触发长度拒绝（边界：错误为 Base64 内容，非超长）。
#[test]
fn decode_within_max_length_not_length_rejected() {
    // 4KB 'A' 重复是合法 Base64（解码为 3072 字节 0x00），不含冒号 → 报"缺冒号"而非"超长"
    let within = "A".repeat(4 * 1024);
    let result = HttpBasicAuth::decode(&within);
    match result {
        Err(GarrisonError::InvalidParam(msg)) => {
            assert!(
                msg.contains("secure-cred-missing-colon"),
                "4KB 内输入不应被长度上限拒绝，实际: {}",
                msg
            );
        },
        other => panic!("应返回缺冒号的 InvalidParam，实际: {:?}", other.err()),
    }
}

/// Credential 的 Debug 实现脱敏密码：{:?} 不输出明文 pass。
#[test]
fn credential_debug_redacts_pass() {
    let encoded = HttpBasicAuth::encode("alice", "top-secret");
    let cred = HttpBasicAuth::decode(&encoded).unwrap();
    let debug = format!("{:?}", cred);
    assert!(
        !debug.contains("top-secret"),
        "Debug 输出不应包含明文密码，实际: {}",
        debug
    );
    assert!(
        debug.contains("<redacted>"),
        "Debug 输出应含 <redacted> 占位符"
    );
    // PartialEq 不受手动 Debug 影响
    let cred2 = HttpBasicAuth::decode(&encoded).unwrap();
    assert_eq!(cred, cred2);
}

// ========================================================================
// parse_authorization_header 测试
// ========================================================================

/// 解析完整 Authorization Header。
#[test]
fn parse_full_authorization_header() {
    let cred = HttpBasicAuth::parse_authorization_header("Basic YWxpY2U6c2VjcmV0").unwrap();
    assert_eq!(cred.user, "alice");
    assert_eq!(cred.pass, "secret");
}

/// Header 前缀非 Basic 失败。
#[test]
fn parse_non_basic_scheme_errors() {
    let result = HttpBasicAuth::parse_authorization_header("Bearer some.token.value");
    assert!(result.is_err());
}

/// Header 缺少凭证部分失败。
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
