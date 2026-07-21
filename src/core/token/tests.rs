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
// SimpleTokenStyle 测试（A11: HMAC-SHA256 签名版）
// ========================================================================
//
// 测试需 `secure-simple-token` feature（已包含在 `auth-server` 中）。
// 未启用 feature 时，SimpleTokenStyle::generate 返回 Err（fail-closed）。

/// 测试用 HMAC 密钥（生产环境应从配置注入）。
#[cfg(feature = "secure-simple-token")]
const TEST_SECRET: &str = "test-hmac-secret-key-for-unit-tests";

/// 创建带 TEST_SECRET 的 SimpleTokenStyle 实例。
#[cfg(feature = "secure-simple-token")]
fn make_simple_style() -> SimpleTokenStyle {
    SimpleTokenStyle::new(TEST_SECRET.to_string())
}

/// SimpleTokenStyle 生成 `<login_id>\x1f<uuid>.<hmac>` 格式。
#[cfg(feature = "secure-simple-token")]
#[test]
fn simple_style_generates_login_id_prefix() {
    let style = make_simple_style();
    let token = style.generate("1001", 3600).unwrap();
    assert!(
        token.starts_with("1001\x1f"),
        "token 应以 login_id + \\x1f 开头，实际: {}",
        token
    );
    // A11: token 应含 '.' 分隔 HMAC 部分
    assert!(
        token.contains('.'),
        "token 应含 '.' 分隔 HMAC，实际: {}",
        token
    );
    // 验证 UUID 部分（\x1f 之后、'.' 之前）为合法 UUID
    let after_login = &token["1001\x1f".len()..];
    let uuid_part = after_login.split('.').next().expect("应有 '.' 分隔");
    assert!(
        uuid::Uuid::parse_str(uuid_part).is_ok(),
        "UUID 部分应合法，实际: {}",
        uuid_part
    );
}

/// SimpleTokenStyle verify 解析 login_id（HMAC 校验通过）。
#[cfg(feature = "secure-simple-token")]
#[test]
fn simple_style_verify_extracts_login_id() {
    let style = make_simple_style();
    let token = style.generate("2002", 3600).unwrap();
    let login_id = style.verify(&token).unwrap();
    assert_eq!(login_id, Some("2002".to_string()));
}

/// SimpleTokenStyle parse 返回 TokenClaims（HMAC 校验通过）。
#[cfg(feature = "secure-simple-token")]
#[test]
fn simple_style_parse_returns_claims() {
    let style = make_simple_style();
    let token = style.generate("3003", 3600).unwrap();
    let claims = style.parse(&token).unwrap();
    assert_eq!(claims.login_id, "3003");
}

/// SimpleTokenStyle parse 非数字 login_id 返回 Ok（String 类型不再要求数字）。
#[cfg(feature = "secure-simple-token")]
#[test]
fn simple_style_parse_non_numeric_login_id_returns_ok() {
    let style = make_simple_style();
    let token = style.generate("admin", 3600).unwrap();
    let result = style.parse(&token);
    assert!(result.is_ok());
    let claims = result.unwrap();
    assert_eq!(claims.login_id, "admin");
}

/// SimpleTokenStyle parse 无分隔符返回 Err。
#[cfg(feature = "secure-simple-token")]
#[test]
fn simple_style_parse_no_separator_errors() {
    let style = make_simple_style();
    assert!(style.parse("noseparator").is_err());
}

/// verify 拒绝 UUID 部分无效的伪造 token。
#[cfg(feature = "secure-simple-token")]
#[test]
fn simple_style_verify_rejects_invalid_uuid_suffix() {
    let style = make_simple_style();
    // 伪造 token：UUID 部分不是合法 UUID 格式 + 伪造 HMAC
    let forged = "admin\x1fnot-a-valid-uuid.fakeHmac";
    let result = style.verify(forged).unwrap();
    assert_eq!(result, None, "UUID 部分无效的伪造 token 应返回 None");
}

/// verify 拒绝任意字符串后缀的伪造 token。
#[cfg(feature = "secure-simple-token")]
#[test]
fn simple_style_verify_rejects_arbitrary_string_suffix() {
    let style = make_simple_style();
    let forged = "admin-anything";
    let result = style.verify(forged).unwrap();
    assert_eq!(result, None, "无 HMAC 的伪造 token 应返回 None");
}

/// parse 拒绝 UUID 部分无效的伪造 token。
#[cfg(feature = "secure-simple-token")]
#[test]
fn simple_style_parse_rejects_invalid_uuid_suffix() {
    let style = make_simple_style();
    let forged = "admin\x1ffake-uuid-string.fakeHmac";
    let result = style.parse(forged);
    assert!(result.is_err(), "UUID 部分无效的 token parse 应返回 Err");
}

/// A11 核心测试：verify 拒绝无 HMAC 的旧格式 token（防降级攻击）。
///
/// 攻击场景：攻击者构造旧格式 `<login_id>-<uuid>`（无 HMAC）的 token，
/// 试图绕过 HMAC 校验。应返回 None。
#[cfg(feature = "secure-simple-token")]
#[test]
fn a11_simple_style_verify_rejects_legacy_token_without_hmac() {
    let style = make_simple_style();
    // 旧格式 token（无 HMAC 后缀）
    let legacy_token = "root-550e8400-e29b-41d4-a716-446655440000";
    let result = style.verify(legacy_token).unwrap();
    assert_eq!(
        result, None,
        "A11: 旧格式 token（无 HMAC）应被拒绝，防止降级攻击"
    );
}

/// A11 核心测试：verify 拒绝 HMAC 不匹配的伪造 token。
///
/// 攻击场景：攻击者知道 token 格式但不知道 secret，
/// 构造 `<login_id>\x1f<valid_uuid>.<fake_hmac>` 试图冒充。
/// HMAC 校验失败应返回 None。
#[cfg(feature = "secure-simple-token")]
#[test]
fn a11_simple_style_verify_rejects_forged_hmac() {
    let style = make_simple_style();
    // 用合法 UUID + 伪造 HMAC
    let forged = "admin\x1f550e8400-e29b-41d4-a716-446655440000.fake-hmac-value";
    let result = style.verify(forged).unwrap();
    assert_eq!(result, None, "A11: HMAC 不匹配的伪造 token 应被拒绝");
}

/// A11 核心测试：不同 secret 生成的 token 互不兼容。
///
/// 攻击场景：攻击者用自己的 secret 生成合法格式 token，
/// 试图在受害者的服务端通过验证。应返回 None。
#[cfg(feature = "secure-simple-token")]
#[test]
fn a11_simple_style_verify_rejects_token_from_different_secret() {
    let style_a = SimpleTokenStyle::new("secret-A".to_string());
    let style_b = SimpleTokenStyle::new("secret-B".to_string());
    // 用 secret-A 生成 token
    let token = style_a.generate("victim", 3600).unwrap();
    // 用 secret-B 验证 → 应失败
    let result = style_b.verify(&token).unwrap();
    assert_eq!(result, None, "A11: 不同 secret 生成的 token 不应通过验证");
}

/// A11 核心测试：空 secret 时 generate 返回 Err（fail-closed）。
#[cfg(feature = "secure-simple-token")]
#[test]
fn a11_simple_style_empty_secret_generate_errors() {
    let style = SimpleTokenStyle::default(); // secret = ""
    let result = style.generate("user", 3600);
    assert!(
        matches!(result, Err(GarrisonError::Config(_))),
        "A11: 空 secret 应返回 Config 错误（fail-closed），实际: {:?}",
        result
    );
}

/// A11 核心测试：空 secret 时 verify 返回 None（fail-closed）。
#[cfg(feature = "secure-simple-token")]
#[test]
fn a11_simple_style_empty_secret_verify_returns_none() {
    let style = SimpleTokenStyle::default(); // secret = ""
    let result = style.verify("any-token").unwrap();
    assert_eq!(
        result, None,
        "A11: 空 secret 时所有 token 应视为无效（fail-closed）"
    );
}

/// A11 核心测试：generate + verify + parse 往返一致性。
///
/// H2 修复后 token 格式为 `<login_id>\x1f<uuid>.<hmac>`，login_id 可含任意字符
/// （除 `\x1f` 和 `.`，但二者在正常 login_id 中不会出现）。
#[cfg(feature = "secure-simple-token")]
#[test]
fn a11_simple_style_roundtrip() {
    let style = make_simple_style();
    let token = style.generate("roundtrip_user", 3600).unwrap();
    // verify 返回正确 login_id
    assert_eq!(
        style.verify(&token).unwrap(),
        Some("roundtrip_user".to_string())
    );
    // parse 返回正确 TokenClaims
    let claims = style.parse(&token).unwrap();
    assert_eq!(claims.login_id, "roundtrip_user");
    assert_eq!(claims.expire_at, 0); // Simple token 不含过期时间
    assert_eq!(claims.device, None);
}

/// A11 核心测试：parse 拒绝 HMAC 不匹配的 token。
#[cfg(feature = "secure-simple-token")]
#[test]
fn a11_simple_style_parse_rejects_forged_hmac() {
    let style = make_simple_style();
    let forged = "admin\x1f550e8400-e29b-41d4-a716-446655440000.fake-hmac";
    let result = style.parse(forged);
    assert!(
        matches!(result, Err(GarrisonError::InvalidToken(_))),
        "A11: HMAC 不匹配的 token parse 应返回 InvalidToken，实际: {:?}",
        result
    );
}

// ========================================================================
// H2 修复测试：SimpleTokenStyle 支持含 `-` 的 login_id
//（原格式用 `-` 分割 login_id 与 uuid，login_id 含 `-` 时 verify 返回 None）
// ========================================================================

/// H2: login_id 含 `-`（email 形式）时 generate + verify + parse 往返一致。
///
/// 复现：login_id = "user-1@example.com"，原实现 verify 用 `split_once('-')`
/// 会得到 login_id="user"、uuid_part="1@example.com-<uuid>"，UUID 解析失败 → 返回 None。
/// 修复后用 `\x1f` Unit Separator 分割，login_id 可含任意 `-`。
#[cfg(feature = "secure-simple-token")]
#[test]
fn h2_simple_style_supports_dashed_login_id_email() {
    let style = make_simple_style();
    let login_id = "user-1@example.com";
    let token = style.generate(login_id, 3600).unwrap();
    // token 应以 "user-1@example.com\x1f" 开头（login_id 完整保留）
    assert!(
        token.starts_with(&format!("{}\x1f", login_id)),
        "token 应以 login_id + \\x1f 开头，实际: {}",
        token
    );
    // verify 返回完整 login_id
    assert_eq!(
        style.verify(&token).unwrap(),
        Some(login_id.to_string()),
        "verify 应返回完整 login_id（含 `-`），实际 token: {}",
        token
    );
    // parse 返回完整 login_id
    let claims = style.parse(&token).unwrap();
    assert_eq!(
        claims.login_id, login_id,
        "parse 应返回完整 login_id（含 `-`）"
    );
}

/// H2: login_id 为 UUID 格式（含 4 个 `-`）时 generate + verify + parse 往返一致。
///
/// 复现：login_id = "550e8400-e29b-41d4-a716-446655440000"（UUID 形式），
/// 原实现 verify 用 `split_once('-')` 会得到 login_id="550e8400"、
/// uuid_part="e29b-41d4-a716-446655440000-<uuid>"，UUID 解析失败 → 返回 None。
#[cfg(feature = "secure-simple-token")]
#[test]
fn h2_simple_style_supports_uuid_login_id() {
    let style = make_simple_style();
    let login_id = "550e8400-e29b-41d4-a716-446655440000";
    let token = style.generate(login_id, 3600).unwrap();
    assert_eq!(
        style.verify(&token).unwrap(),
        Some(login_id.to_string()),
        "verify 应返回完整 UUID 形式 login_id，实际 token: {}",
        token
    );
    let claims = style.parse(&token).unwrap();
    assert_eq!(
        claims.login_id, login_id,
        "parse 应返回完整 UUID 形式 login_id"
    );
}

/// H2: login_id 含多个连续 `-`（kebab-case）时往返一致。
#[cfg(feature = "secure-simple-token")]
#[test]
fn h2_simple_style_supports_kebab_case_login_id() {
    let style = make_simple_style();
    let login_id = "service-account-admin";
    let token = style.generate(login_id, 3600).unwrap();
    assert_eq!(
        style.verify(&token).unwrap(),
        Some(login_id.to_string()),
        "verify 应返回完整 kebab-case login_id，实际 token: {}",
        token
    );
    let claims = style.parse(&token).unwrap();
    assert_eq!(claims.login_id, login_id);
}

/// A11 核心测试：未启用 secure-simple-token feature 时 generate 返回 Err。
#[cfg(not(feature = "secure-simple-token"))]
#[test]
fn a11_simple_style_without_feature_generate_errors() {
    let style = SimpleTokenStyle::new("secret".to_string());
    let result = style.generate("user", 3600);
    assert!(
        matches!(result, Err(GarrisonError::Config(_))),
        "A11: 未启用 secure-simple-token feature 时 generate 应返回 Config 错误"
    );
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

/// Factory 返回 SimpleTokenStyle（传入 secret 用于 HMAC）。
#[cfg(feature = "secure-simple-token")]
#[test]
fn factory_creates_simple_style() {
    let token = TokenStyleFactory::new("simple", "factory-secret").unwrap();
    let t = token.generate("42", 60).unwrap();
    assert!(t.starts_with("42\x1f"), "token 应以 login_id + \\x1f 开头");
    assert!(t.contains('.'), "token 应含 '.' 分隔 HMAC");
}

/// Factory 返回 SimpleTokenStyle（未启用 feature 时 generate 返回 Err）。
#[cfg(not(feature = "secure-simple-token"))]
#[test]
fn factory_creates_simple_style() {
    let token = TokenStyleFactory::new("simple", "factory-secret").unwrap();
    let result = token.generate("42", 60);
    assert!(
        matches!(result, Err(GarrisonError::Config(_))),
        "A11: 未启用 feature 时 generate 应返回 Config 错误"
    );
}

/// Factory 未知风格返回 Config 错误（spec Scenario）。
#[test]
fn factory_rejects_unknown_style() {
    let result = TokenStyleFactory::new("unknown", "secret");
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::Config(msg)) => assert!(msg.contains("unknown token_style")),
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
        Some(GarrisonError::Internal(msg)) => {
            assert!(msg.contains("random_64"), "应提示 random_64 不支持 parse")
        },
        other => panic!("期望 Internal 错误，实际: {:?}", other),
    }
}

/// SimpleTokenStyle::verify 无分隔符时返回 Ok(None)（A11: 无 '.' 视为无效）。
#[cfg(feature = "secure-simple-token")]
#[test]
fn simple_style_verify_no_separator_returns_none() {
    let style = make_simple_style();
    let result = style.verify("noseparator").unwrap();
    assert_eq!(result, None, "无 '.' 分隔符的 token verify 应返回 None");
}

/// SimpleTokenStyle::verify 非数字 login_id 返回 Ok（A11: 需合法 HMAC）。
#[cfg(feature = "secure-simple-token")]
#[test]
fn simple_style_verify_non_numeric_returns_ok() {
    let style = make_simple_style();
    // A11: 用 generate 生成合法 token（含非数字 login_id + HMAC）
    let token = style.generate("abc", 3600).unwrap();
    let result = style.verify(&token);
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
