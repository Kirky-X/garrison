//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! Token 模块单元测试（从 mod.rs 迁移，遵守 mod.rs 接口隔离规则 25）。
//!
//! 覆盖 `TokenClaims` 序列化、四种 Token 风格（uuid / random_64 / simple / jwt）
//! 的 generate / verify / parse 行为，以及 `TokenStyleFactory` 的风格路由。

use super::*;

// ========================================================================
// TokenClaims 测试
// ========================================================================

/// TokenClaims 可序列化/反序列化。
#[test]
fn token_claims_serializes() {
    let claims = TokenClaims {
        login_id: "1001".to_string(),
        expire_at: 1700003600,
        device: Some("web".to_string()),
    };
    let json = serde_json::to_string(&claims).unwrap();
    let parsed: TokenClaims = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.login_id, "1001");
    assert_eq!(parsed.expire_at, 1700003600);
    assert_eq!(parsed.device, Some("web".to_string()));
}

/// TokenClaims device 字段可选。
#[test]
fn token_claims_device_optional() {
    let claims = TokenClaims {
        login_id: "1".to_string(),
        expire_at: 0,
        device: None,
    };
    assert!(claims.device.is_none());
}

// ========================================================================
// UuidTokenStyle 测试
// ========================================================================

/// UuidTokenStyle 生成 UUID v4 格式 token。
#[test]
fn uuid_style_generates_uuid_format() {
    let style = UuidTokenStyle;
    let token = style.generate("1001", 3600).unwrap();
    // UUID v4 格式：8-4-4-4-12 十六进制
    assert_eq!(token.len(), 36);
    let parts: Vec<&str> = token.split('-').collect();
    assert_eq!(parts.len(), 5);
    assert_eq!(parts[0].len(), 8);
    assert_eq!(parts[1].len(), 4);
    assert_eq!(parts[2].len(), 4);
    assert_eq!(parts[3].len(), 4);
    assert_eq!(parts[4].len(), 12);
}

/// UuidTokenStyle verify 始终返回 None。
#[test]
fn uuid_style_verify_returns_none() {
    let style = UuidTokenStyle;
    let token = style.generate("1001", 3600).unwrap();
    assert_eq!(style.verify(&token).unwrap(), None);
}

/// UuidTokenStyle parse 返回错误。
#[test]
fn uuid_style_parse_errors() {
    let style = UuidTokenStyle;
    assert!(style.parse("some-token").is_err());
}

// ========================================================================
// Random64TokenStyle 测试
// ========================================================================

/// Random64TokenStyle 生成 64 字符随机 hex。
#[test]
fn random64_style_generates_64_hex() {
    let style = Random64TokenStyle;
    let token = style.generate("1001", 3600).unwrap();
    assert_eq!(token.len(), 64);
    assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
}

/// Random64TokenStyle 多次调用返回不同 token。
#[test]
fn random64_style_generates_unique() {
    let style = Random64TokenStyle;
    let t1 = style.generate("1001", 3600).unwrap();
    let t2 = style.generate("1001", 3600).unwrap();
    assert_ne!(t1, t2);
}

/// Random64TokenStyle verify 始终返回 None。
#[test]
fn random64_style_verify_returns_none() {
    let style = Random64TokenStyle;
    assert_eq!(style.verify("abc123").unwrap(), None);
}

// ========================================================================
// SimpleTokenStyle 测试
// ========================================================================

/// SimpleTokenStyle 生成 `<login_id>-<uuid>` 格式。
#[test]
fn simple_style_generates_login_id_prefix() {
    let style = SimpleTokenStyle;
    let token = style.generate("1001", 3600).unwrap();
    assert!(token.starts_with("1001-"));
    // 后缀为 UUID v4 格式（36 字符）
    let uuid_part = &token[5..]; // 跳过 "1001-"
    assert_eq!(uuid_part.len(), 36);
}

/// SimpleTokenStyle verify 解析 login_id。
#[test]
fn simple_style_verify_extracts_login_id() {
    let style = SimpleTokenStyle;
    let token = style.generate("2002", 3600).unwrap();
    let login_id = style.verify(&token).unwrap();
    assert_eq!(login_id, Some("2002".to_string()));
}

/// SimpleTokenStyle parse 返回 TokenClaims。
#[test]
fn simple_style_parse_returns_claims() {
    let style = SimpleTokenStyle;
    let token = style.generate("3003", 3600).unwrap();
    let claims = style.parse(&token).unwrap();
    assert_eq!(claims.login_id, "3003");
}

/// SimpleTokenStyle parse 非数字 login_id 返回 Ok（String 类型不再要求数字）。
#[test]
fn simple_style_parse_non_numeric_login_id_returns_ok() {
    let style = SimpleTokenStyle;
    // 使用合法 UUID v4 格式确保通过 UUID 校验
    let result = style.parse("admin-550e8400-e29b-41d4-a716-446655440000");
    assert!(result.is_ok());
    let claims = result.unwrap();
    assert_eq!(claims.login_id, "admin");
}

/// SimpleTokenStyle parse 无分隔符返回 Err。
#[test]
fn simple_style_parse_no_separator_errors() {
    let style = SimpleTokenStyle;
    assert!(style.parse("noseparator").is_err());
}

/// verify 拒绝 UUID 部分无效的伪造 token。
#[test]
fn simple_style_verify_rejects_invalid_uuid_suffix() {
    let style = SimpleTokenStyle;
    // 伪造 token：UUID 部分不是合法 UUID 格式
    let forged = "admin-not-a-valid-uuid";
    let result = style.verify(forged).unwrap();
    assert_eq!(result, None, "UUID 部分无效的伪造 token 应返回 None");
}

/// verify 拒绝任意字符串后缀的伪造 token。
#[test]
fn simple_style_verify_rejects_arbitrary_string_suffix() {
    let style = SimpleTokenStyle;
    let forged = "admin-anything";
    let result = style.verify(forged).unwrap();
    assert_eq!(result, None, "非 UUID 后缀的伪造 token 应返回 None");
}

/// parse 拒绝 UUID 部分无效的伪造 token。
#[test]
fn simple_style_parse_rejects_invalid_uuid_suffix() {
    let style = SimpleTokenStyle;
    let forged = "admin-fake-uuid-string";
    let result = style.parse(forged);
    assert!(result.is_err(), "UUID 部分无效的 token parse 应返回 Err");
}

/// verify 接受合法 UUID 后缀的 token。
#[test]
fn simple_style_verify_accepts_valid_uuid_suffix() {
    let style = SimpleTokenStyle;
    let token = "root-550e8400-e29b-41d4-a716-446655440000";
    let result = style.verify(token).unwrap();
    assert_eq!(result, Some("root".to_string()));
}

// ========================================================================
// TokenStyleFactory 测试
// ========================================================================

/// Factory 返回 UuidTokenStyle。
#[test]
fn factory_creates_uuid_style() {
    let token = TokenStyleFactory::new("uuid", "secret").unwrap();
    let t = token.generate("1", 60).unwrap();
    assert_eq!(t.len(), 36);
}

/// Factory 返回 Random64TokenStyle。
#[test]
fn factory_creates_random64_style() {
    let token = TokenStyleFactory::new("random_64", "secret").unwrap();
    let t = token.generate("1", 60).unwrap();
    assert_eq!(t.len(), 64);
}

/// Factory 返回 SimpleTokenStyle。
#[test]
fn factory_creates_simple_style() {
    let token = TokenStyleFactory::new("simple", "secret").unwrap();
    let t = token.generate("42", 60).unwrap();
    assert!(t.starts_with("42-"));
}

/// Factory 未知风格返回 Config 错误（spec Scenario）。
#[test]
fn factory_rejects_unknown_style() {
    let result = TokenStyleFactory::new("unknown", "secret");
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::Config(msg)) => assert!(msg.contains("unknown token_style")),
        other => panic!("期望 Config 错误，实际: {:?}", other),
    }
}

/// Factory jwt 风格在无 protocol-jwt feature 时返回错误。
#[cfg(not(feature = "protocol-jwt"))]
#[test]
fn factory_jwt_without_feature_errors() {
    let result = TokenStyleFactory::new("jwt", "secret");
    assert!(result.is_err());
}

/// Factory jwt 风格在有 protocol-jwt feature 时成功创建。
#[cfg(feature = "protocol-jwt")]
#[test]
fn factory_creates_jwt_style() {
    let token = TokenStyleFactory::new("jwt", "secret");
    assert!(token.is_ok());
}

// ========================================================================
// 覆盖率补充测试（Random64TokenStyle::parse / SimpleTokenStyle::verify 边界）
// ========================================================================

/// Random64TokenStyle::parse 返回 Err（无 payload）。
#[test]
fn random64_style_parse_errors() {
    let style = Random64TokenStyle;
    let result = style.parse("any-token");
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::Internal(msg)) => {
            assert!(msg.contains("random_64"), "应提示 random_64 不支持 parse")
        },
        other => panic!("期望 Internal 错误，实际: {:?}", other),
    }
}

/// SimpleTokenStyle::verify 无分隔符时返回 Ok(None)（spec: token 不含 login_id）。
#[test]
fn simple_style_verify_no_separator_returns_none() {
    let style = SimpleTokenStyle;
    let result = style.verify("noseparator").unwrap();
    assert_eq!(result, None, "无 '-' 分隔符的 token verify 应返回 None");
}

/// SimpleTokenStyle::verify 非数字 login_id 返回 Ok（String 类型不再要求数字）。
#[test]
fn simple_style_verify_non_numeric_returns_ok() {
    let style = SimpleTokenStyle;
    // 使用合法 UUID v4 后缀确保通过 UUID 校验
    let result = style.verify("abc-550e8400-e29b-41d4-a716-446655440000");
    assert!(result.is_ok(), "verify 应返回 Ok，实际: {:?}", result);
    assert_eq!(result.unwrap(), Some("abc".to_string()));
}

// ========================================================================
// JwtTokenStyle 覆盖率补充测试（feature-gated）
// ========================================================================

/// JwtTokenStyle generate + verify 往返测试。
#[cfg(feature = "protocol-jwt")]
#[test]
fn jwt_style_generate_and_verify_roundtrip() {
    let style = JwtTokenStyle::new("test-secret-key");
    let token = style.generate("1001", 3600).unwrap();
    let login_id = style.verify(&token).unwrap();
    assert_eq!(
        login_id,
        Some("1001".to_string()),
        "JWT verify 应返回 generate 时的 login_id"
    );
}

/// JwtTokenStyle::verify 无效 token 返回 Ok(None)。
#[cfg(feature = "protocol-jwt")]
#[test]
fn jwt_style_verify_invalid_returns_none() {
    let style = JwtTokenStyle::new("test-secret-key");
    // 篡改的 token（无法通过签名校验）
    let result = style.verify("invalid.jwt.token").unwrap();
    assert_eq!(result, None, "无效 JWT verify 应返回 Ok(None)");
}

/// JwtTokenStyle::parse 有效 token 返回 TokenClaims。
#[cfg(feature = "protocol-jwt")]
#[test]
fn jwt_style_parse_valid_returns_claims() {
    let style = JwtTokenStyle::new("test-secret-key");
    let token = style.generate("2002", 3600).unwrap();
    let claims = style.parse(&token).unwrap();
    assert_eq!(claims.login_id, "2002");
    assert!(claims.expire_at > 0, "JWT parse 应返回非零过期时间");
}

/// JwtTokenStyle::parse 无效 token 返回 Err。
#[cfg(feature = "protocol-jwt")]
#[test]
fn jwt_style_parse_invalid_returns_error() {
    let style = JwtTokenStyle::new("test-secret-key");
    let result = style.parse("invalid.jwt.token");
    assert!(result.is_err(), "无效 JWT parse 应返回 Err");
}
