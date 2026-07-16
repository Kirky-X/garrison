//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! JwtHandler 与 BulwarkJwtClaims 单元测试。

use super::*;
use crate::error::BulwarkError;

// ============================================================================
// BulwarkJwtClaims 测试
// ============================================================================

/// BulwarkJwtClaims 完整字段序列化（spec Scenario）。
#[test]
fn claims_serializes_full_fields() {
    let claims = BulwarkJwtClaims {
        sub: "1001".to_string(),
        iat: 1700000000,
        exp: 1700003600,
        login_id: "1001".to_string(),
        device: Some("web".to_string()),
        jti: Some("test-jti".to_string()),
        nbf: Some(1700000000),
    };
    let json = serde_json::to_string(&claims).unwrap();
    assert!(json.contains("\"sub\":\"1001\""));
    assert!(json.contains("\"iat\":1700000000"));
    assert!(json.contains("\"exp\":1700003600"));
    assert!(json.contains("\"login_id\":\"1001\""));
    assert!(json.contains("\"device\":\"web\""));
    assert!(json.contains("\"jti\":\"test-jti\""));
    assert!(json.contains("\"nbf\":1700000000"));
}

/// BulwarkJwtClaims device 字段为 None 时序列化为 null（spec Scenario）。
#[test]
fn claims_device_none_serializes_as_null() {
    let claims = BulwarkJwtClaims {
        sub: "1001".to_string(),
        iat: 1700000000,
        exp: 1700003600,
        login_id: "1001".to_string(),
        device: None,
        jti: None,
        nbf: None,
    };
    let json = serde_json::to_string(&claims).unwrap();
    assert!(json.contains("\"device\":null"));
    // jti=None 时应跳过序列化（skip_serializing_if）
    assert!(!json.contains("jti"), "jti=None 时不应序列化 jti 字段");
    // nbf=None 时应跳过序列化（skip_serializing_if）
    assert!(!json.contains("nbf"), "nbf=None 时不应序列化 nbf 字段");
}

/// jti=None 时序列化结果不含 jti 字段（向后兼容旧 token）。
#[test]
fn claims_jti_none_skipped_in_json() {
    let claims = BulwarkJwtClaims {
        sub: "1001".to_string(),
        iat: 1700000000,
        exp: 1700003600,
        login_id: "1001".to_string(),
        device: None,
        jti: None,
        nbf: None,
    };
    let json = serde_json::to_string(&claims).unwrap();
    assert!(!json.contains("jti"));
    assert!(!json.contains("nbf"));
}

/// sign 生成的新 token 包含唯一的 jti（UUID v4）。
#[test]
fn sign_generates_unique_jti() {
    let handler = JwtHandler::new("secret");
    let t1 = handler.sign("1001", 3600).unwrap();
    let t2 = handler.sign("1001", 3600).unwrap();
    // 同一秒内同一用户的 token 应不同（jti 保证唯一性）
    assert_ne!(t1, t2, "jti 应保证同一秒内签发的 token 唯一");
    let c1 = handler.verify(&t1).unwrap();
    let c2 = handler.verify(&t2).unwrap();
    assert!(c1.jti.is_some(), "sign 生成的 token 应包含 jti");
    assert!(c2.jti.is_some());
    assert_ne!(c1.jti, c2.jti, "两个 token 的 jti 应不同");
}

/// 旧 token（无 jti 字段）仍可反序列化（向后兼容）。
#[test]
fn claims_without_jti_deserializes() {
    let json =
        r#"{"sub":"1001","iat":1700000000,"exp":1700003600,"login_id":"1001","device":"web"}"#;
    let claims: BulwarkJwtClaims = serde_json::from_str(json).unwrap();
    assert_eq!(claims.sub, "1001");
    assert_eq!(claims.jti, None, "旧 token 无 jti 字段时应反序列化为 None");
}

/// BulwarkJwtClaims 可反序列化。
#[test]
fn claims_deserializes() {
    let json =
        r#"{"sub":"1001","iat":1700000000,"exp":1700003600,"login_id":"1001","device":"web"}"#;
    let claims: BulwarkJwtClaims = serde_json::from_str(json).unwrap();
    assert_eq!(claims.sub, "1001");
    assert_eq!(claims.iat, 1700000000);
    assert_eq!(claims.exp, 1700003600);
    assert_eq!(claims.login_id, "1001");
    assert_eq!(claims.device, Some("web".to_string()));
}

// ============================================================================
// JwtHandler 构造测试
// ============================================================================

/// new 默认采用 HS256 算法（spec Scenario）。
#[test]
fn new_defaults_to_hs256() {
    let handler = JwtHandler::new("my-secret-key");
    assert_eq!(handler.algorithm, Algorithm::HS256);
    assert_eq!(handler.secret, "my-secret-key");
    assert!(handler.device.is_none());
}

/// with_algorithm 切换为 HS512（spec Scenario）。
#[test]
fn with_algorithm_switches_to_hs512() {
    let handler = JwtHandler::new("my-secret-key").with_algorithm(Algorithm::HS512);
    assert_eq!(handler.algorithm, Algorithm::HS512);
}

/// with_device 设置设备标识。
#[test]
fn with_device_sets_device() {
    let handler = JwtHandler::new("secret").with_device("ios-app");
    assert_eq!(handler.device, Some("ios-app".to_string()));
}

// ============================================================================
// sign 测试
// ============================================================================

/// sign 返回三段 Base64URL（spec Scenario）。
#[test]
fn sign_returns_three_segment_jwt() {
    let handler = JwtHandler::new("secret");
    let token = handler.sign("1001", 3600).unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT 应由三段组成");
    assert!(!parts[0].is_empty());
    assert!(!parts[1].is_empty());
    assert!(!parts[2].is_empty());
}

/// sign 空密钥返回 Config 错误（spec Scenario）。
#[test]
fn sign_rejects_empty_secret() {
    let handler = JwtHandler::new("");
    let result = handler.sign("1001", 3600);
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::Config(msg)) => assert!(msg.contains("secret")),
        other => panic!("期望 Config 错误，实际: {:?}", other),
    }
}

/// sign 负数 timeout 返回 Config 错误（spec Scenario）。
#[test]
fn sign_rejects_negative_timeout() {
    let handler = JwtHandler::new("secret");
    let result = handler.sign("1001", -1);
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::Config(msg)) => assert!(msg.contains("timeout")),
        other => panic!("期望 Config 错误，实际: {:?}", other),
    }
}

/// sign 带 device 写入 payload（spec Scenario）。
#[test]
fn sign_with_device_includes_device_in_claims() {
    let handler = JwtHandler::new("secret").with_device("ios-app");
    let token = handler.sign("1001", 3600).unwrap();
    // verify 后检查 device
    let claims = handler.verify(&token).unwrap();
    assert_eq!(claims.device, Some("ios-app".to_string()));
}

// ============================================================================
// verify 测试
// ============================================================================

/// verify 有效 token 返回 claims（spec Scenario）。
#[test]
fn verify_valid_token_returns_claims() {
    let handler = JwtHandler::new("secret");
    let token = handler.sign("1001", 3600).unwrap();
    let claims = handler.verify(&token).unwrap();
    assert_eq!(claims.sub, "1001");
    assert_eq!(claims.login_id, "1001");
    assert!(claims.exp > claims.iat);
}

/// verify 篡改 payload 返回错误（spec Scenario）。
#[test]
fn verify_tampered_payload_fails() {
    let handler = JwtHandler::new("secret");
    let token = handler.sign("1001", 3600).unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    // 篡改 payload 段（替换为另一个 base64url 串）
    let tampered = format!("{}.{}.{}", parts[0], "ZmFrZS1wYXlsb2Fk", parts[2]);
    let result = handler.verify(&tampered);
    assert!(result.is_err());
}

/// verify 错误密钥返回错误（spec Scenario）。
#[test]
fn verify_wrong_secret_fails() {
    let signer = JwtHandler::new("secret-a");
    let token = signer.sign("1001", 3600).unwrap();
    let verifier = JwtHandler::new("secret-b");
    let result = verifier.verify(&token);
    assert!(result.is_err());
}

/// verify 已过期 token 返回 ExpiredToken（spec Scenario）。
#[test]
fn verify_expired_token_returns_expired_error() {
    let handler = JwtHandler::new("secret");
    // sign timeout=1 秒，sleep 3 秒后 verify 应触发 ExpiredSignature
    // （leeway=0，不容忍时钟偏差；3 秒容差避免高负载下时序敏感失败）
    let token = handler.sign("1001", 1).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(3));
    let result = handler.verify(&token);
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::ExpiredToken(_)) => {},
        other => panic!("期望 ExpiredToken，实际: {:?}", other),
    }
}

/// verify 算法不匹配返回错误（spec Scenario）。
#[test]
fn verify_algorithm_mismatch_fails() {
    let signer = JwtHandler::new("secret").with_algorithm(Algorithm::HS512);
    let token = signer.sign("1001", 3600).unwrap();
    let verifier = JwtHandler::new("secret"); // 默认 HS256
    let result = verifier.verify(&token);
    assert!(result.is_err());
}

// ============================================================================
// nbf 校验测试（vuln-0019 修复）
// ============================================================================

/// verify 拒绝 nbf 为未来时间的 token（vuln-0019 修复）。
#[test]
fn verify_future_nbf_returns_invalid_token() {
    let handler = JwtHandler::new("secret");
    // 手动构造 nbf = now + 10 的 token
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = BulwarkJwtClaims {
        sub: "1001".to_string(),
        iat: now,
        exp: now + 3600,
        login_id: "1001".to_string(),
        device: None,
        jti: Some(uuid::Uuid::new_v4().to_string()),
        nbf: Some(now + 10), // 未来 10 秒生效
    };
    let header = jsonwebtoken::Header::new(Algorithm::HS256);
    let key = jsonwebtoken::EncodingKey::from_secret(b"secret");
    let token = jsonwebtoken::encode(&header, &claims, &key).unwrap();
    // 立即 verify 应返回 Err(InvalidToken)
    let result = handler.verify(&token);
    assert!(result.is_err(), "未来 nbf 应被拒绝: {:?}", result.ok());
    match result.err() {
        Some(BulwarkError::InvalidToken(msg)) => {
            assert!(
                msg.contains("nbf") || msg.contains("ImmatureSignature") || msg.contains("未生效"),
                "错误消息应包含 nbf/ImmatureSignature/未生效，实际: {}",
                msg
            );
        },
        other => panic!("期望 InvalidToken，实际: {:?}", other),
    }
}

/// verify 接受 nbf = now 的 token（边界场景，vuln-0019 修复）。
#[test]
fn verify_present_nbf_returns_ok() {
    let handler = JwtHandler::new("secret");
    // sign 自动设置 nbf = now，verify 应通过
    let token = handler.sign("1001", 3600).unwrap();
    let result = handler.verify(&token);
    assert!(result.is_ok(), "nbf = now 应通过校验: {:?}", result.err());
    let claims = result.unwrap();
    assert!(claims.nbf.is_some(), "sign 应设置 nbf");
}

/// verify 接受 nbf = now - 10 的 token（过去时间，vuln-0019 修复）。
#[test]
fn verify_past_nbf_returns_ok() {
    let handler = JwtHandler::new("secret");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = BulwarkJwtClaims {
        sub: "1001".to_string(),
        iat: now - 10,
        exp: now + 3600,
        login_id: "1001".to_string(),
        device: None,
        jti: Some(uuid::Uuid::new_v4().to_string()),
        nbf: Some(now - 10), // 过去 10 秒已生效
    };
    let header = jsonwebtoken::Header::new(Algorithm::HS256);
    let key = jsonwebtoken::EncodingKey::from_secret(b"secret");
    let token = jsonwebtoken::encode(&header, &claims, &key).unwrap();
    let result = handler.verify(&token);
    assert!(result.is_ok(), "nbf = 过去应通过校验: {:?}", result.err());
}

/// verify 接受无 nbf 字段的旧 token（向后兼容，vuln-0019 修复）。
#[test]
fn verify_token_without_nbf_field_returns_ok() {
    let handler = JwtHandler::new("secret");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // 手动构造无 nbf 字段的 JSON（模拟旧 token）
    let claims_json = serde_json::json!({
        "sub": "1001",
        "iat": now,
        "exp": now + 3600,
        "login_id": "1001",
        "device": null,
        "jti": uuid::Uuid::new_v4().to_string()
    });
    let header = jsonwebtoken::Header::new(Algorithm::HS256);
    let key = jsonwebtoken::EncodingKey::from_secret(b"secret");
    let token = jsonwebtoken::encode(&header, &claims_json, &key).unwrap();
    let result = handler.verify(&token);
    assert!(
        result.is_ok(),
        "无 nbf 字段应通过校验（向后兼容）: {:?}",
        result.err()
    );
    let claims = result.unwrap();
    assert!(claims.nbf.is_none(), "旧 token nbf 应为 None");
}

// ============================================================================
// refresh 测试
// ============================================================================

/// refresh 返回新 token 且可 verify。
#[test]
fn refresh_issues_new_valid_token() {
    let handler = JwtHandler::new("secret");
    let token = handler.sign("1001", 3600).unwrap();
    let new_token = handler.refresh(&token, 7200).unwrap();
    assert_ne!(token, new_token);
    let claims = handler.verify(&new_token).unwrap();
    assert_eq!(claims.login_id, "1001");
}

/// refresh 旧 token 无效时返回错误。
#[test]
fn refresh_invalid_token_fails() {
    let handler = JwtHandler::new("secret");
    let result = handler.refresh("invalid.token.here", 3600);
    assert!(result.is_err());
}

/// JwtClaims 类型别名兼容 0.1.0 代码。
#[test]
fn jwt_claims_alias_works() {
    let claims: JwtClaims = BulwarkJwtClaims {
        sub: "1".to_string(),
        iat: 0,
        exp: 0,
        login_id: "1".to_string(),
        device: None,
        jti: None,
        nbf: None, // vuln-0019 修复：补充 nbf 字段
    };
    assert_eq!(claims.login_id, "1");
}

// ============================================================================
// LoginId newtype 接入（impl Into<LoginId>）
// ============================================================================

/// 验证 `JwtHandler::sign` 接受 String 形式 login_id。
#[test]
fn sign_accepts_login_id_numeric() {
    let handler = JwtHandler::new("secret");
    let token = handler.sign("1001".to_string(), 3600).unwrap();
    let claims = handler.verify(&token).unwrap();
    assert_eq!(claims.login_id, "1001");
}
