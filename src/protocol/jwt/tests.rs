// Copyright (c) 2026 Kirky.X🌠
// SPDX-License-Identifier: Apache-2.0

//! JwtHandler 与 GarrisonJwtClaims 单元测试。

use super::*;
use crate::error::GarrisonError;

// ============================================================================
// GarrisonJwtClaims 测试
// ============================================================================

/// GarrisonJwtClaims 完整字段序列化）。
#[test]
fn claims_serializes_full_fields() {
    let claims = GarrisonJwtClaims {
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

/// GarrisonJwtClaims device 字段为 None 时序列化为 null）。
#[test]
fn claims_device_none_serializes_as_null() {
    let claims = GarrisonJwtClaims {
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

/// jti=None 时序列化结果不含 jti 字段（`skip_serializing_if`）。
#[test]
fn claims_jti_none_skipped_in_json() {
    let claims = GarrisonJwtClaims {
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
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
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

/// 无 jti 字段的 claims 仍可反序列化（RFC 7519 中 jti 为可选 claim）。
#[test]
fn claims_without_jti_deserializes() {
    let json =
        r#"{"sub":"1001","iat":1700000000,"exp":1700003600,"login_id":"1001","device":"web"}"#;
    let claims: GarrisonJwtClaims = serde_json::from_str(json).unwrap();
    assert_eq!(claims.sub, "1001");
    assert_eq!(claims.jti, None, "无 jti 字段时应反序列化为 None");
}

/// GarrisonJwtClaims 可反序列化。
#[test]
fn claims_deserializes() {
    let json =
        r#"{"sub":"1001","iat":1700000000,"exp":1700003600,"login_id":"1001","device":"web"}"#;
    let claims: GarrisonJwtClaims = serde_json::from_str(json).unwrap();
    assert_eq!(claims.sub, "1001");
    assert_eq!(claims.iat, 1700000000);
    assert_eq!(claims.exp, 1700003600);
    assert_eq!(claims.login_id, "1001");
    assert_eq!(claims.device, Some("web".to_string()));
}

// ============================================================================
// JwtHandler 构造测试
// ============================================================================

/// new 默认采用 HS256 算法）。
#[test]
fn new_defaults_to_hs256() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
    assert_eq!(handler.algorithm, Algorithm::HS256);
    assert_eq!(handler.secret, "0123456789abcdef0123456789abcdef");
    assert!(handler.device.is_none());
}

/// with_algorithm 切换为 HS512）。
#[test]
fn with_algorithm_switches_to_hs512() {
    let handler =
        JwtHandler::new("0123456789abcdef0123456789abcdef").with_algorithm(Algorithm::HS512);
    assert_eq!(handler.algorithm, Algorithm::HS512);
}

/// with_device 设置设备标识。
#[test]
fn with_device_sets_device() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef").with_device("ios-app");
    assert_eq!(handler.device, Some("ios-app".to_string()));
}

// ============================================================================
// sign 测试
// ============================================================================

/// sign 返回三段 Base64URL）。
#[test]
fn sign_returns_three_segment_jwt() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
    let token = handler.sign("1001", 3600).unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT 应由三段组成");
    assert!(!parts[0].is_empty());
    assert!(!parts[1].is_empty());
    assert!(!parts[2].is_empty());
}

/// sign 空密钥返回 Config 错误）。
#[test]
fn sign_rejects_empty_secret() {
    let handler = JwtHandler::new("");
    let result = handler.sign("1001", 3600);
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::Config(msg)) => assert!(msg.contains("secret")),
        other => panic!("期望 Config 错误，实际: {:?}", other),
    }
}

/// sign 负数 timeout 返回 Config 错误）。
#[test]
fn sign_rejects_negative_timeout() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
    let result = handler.sign("1001", -1);
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::Config(msg)) => assert!(msg.contains("timeout")),
        other => panic!("期望 Config 错误，实际: {:?}", other),
    }
}

/// sign 带 device 写入 payload）。
#[test]
fn sign_with_device_includes_device_in_claims() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef").with_device("ios-app");
    let token = handler.sign("1001", 3600).unwrap();
    // verify 后检查 device
    let claims = handler.verify(&token).unwrap();
    assert_eq!(claims.device, Some("ios-app".to_string()));
}

// ============================================================================
// verify 测试
// ============================================================================

/// verify 有效 token 返回 claims）。
#[test]
fn verify_valid_token_returns_claims() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
    let token = handler.sign("1001", 3600).unwrap();
    let claims = handler.verify(&token).unwrap();
    assert_eq!(claims.sub, "1001");
    assert_eq!(claims.login_id, "1001");
    assert!(claims.exp > claims.iat);
}

/// verify 篡改 payload 返回错误）。
#[test]
fn verify_tampered_payload_fails() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
    let token = handler.sign("1001", 3600).unwrap();
    let parts: Vec<&str> = token.split('.').collect();
    // 篡改 payload 段（替换为另一个 base64url 串）
    let tampered = format!("{}.{}.{}", parts[0], "ZmFrZS1wYXlsb2Fk", parts[2]);
    let result = handler.verify(&tampered);
    assert!(result.is_err());
}

/// verify 错误密钥返回错误）。
#[test]
fn verify_wrong_secret_fails() {
    let signer = JwtHandler::new("0123456789abcdef0123456789abcdef");
    let token = signer.sign("1001", 3600).unwrap();
    let verifier = JwtHandler::new("fedcba9876543210fedcba9876543210");
    let result = verifier.verify(&token);
    assert!(result.is_err());
}

/// verify 已过期 token 返回 ExpiredToken）。
#[test]
fn verify_expired_token_returns_expired_error() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
    // sign timeout=1 秒，sleep 3 秒后 verify 应触发 ExpiredSignature
    // （leeway=0，不容忍时钟偏差；3 秒容差避免高负载下时序敏感失败）
    let token = handler.sign("1001", 1).unwrap();
    std::thread::sleep(std::time::Duration::from_secs(3));
    let result = handler.verify(&token);
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::ExpiredToken(_)) => {},
        other => panic!("期望 ExpiredToken，实际: {:?}", other),
    }
}

/// verify 算法不匹配返回错误）。
#[test]
fn verify_algorithm_mismatch_fails() {
    let signer =
        JwtHandler::new("0123456789abcdef0123456789abcdef").with_algorithm(Algorithm::HS512);
    let token = signer.sign("1001", 3600).unwrap();
    let verifier = JwtHandler::new("0123456789abcdef0123456789abcdef"); // 默认 HS256
    let result = verifier.verify(&token);
    assert!(result.is_err());
}

// ============================================================================
// nbf 校验测试
// ============================================================================

/// verify 拒绝 nbf 为未来时间的 token。
#[test]
fn verify_future_nbf_returns_invalid_token() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
    // 手动构造 nbf = now + 10 的 token
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = GarrisonJwtClaims {
        sub: "1001".to_string(),
        iat: now,
        exp: now + 3600,
        login_id: "1001".to_string(),
        device: None,
        jti: Some(uuid::Uuid::new_v4().to_string()),
        nbf: Some(now + 10), // 未来 10 秒生效
    };
    let header = jsonwebtoken::Header::new(Algorithm::HS256);
    let key = jsonwebtoken::EncodingKey::from_secret(b"0123456789abcdef0123456789abcdef");
    let token = jsonwebtoken::encode(&header, &claims, &key).unwrap();
    // 立即 Verify 应返回 Err(InvalidToken)
    let result = handler.verify(&token);
    assert!(result.is_err(), "未来 nbf 应被拒绝: {:?}", result.ok());
    match result.err() {
        Some(GarrisonError::InvalidToken(msg)) => {
            assert!(
                msg.contains("nbf") || msg.contains("ImmatureSignature") || msg.contains("未生效"),
                "错误消息应包含 nbf/ImmatureSignature/未生效，实际: {}",
                msg
            );
        },
        other => panic!("期望 InvalidToken，实际: {:?}", other),
    }
}

/// verify 接受 nbf = now 的 token（边界场景）。
#[test]
fn verify_present_nbf_returns_ok() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
    // sign 自动设置 nbf = now，verify 应通过
    let token = handler.sign("1001", 3600).unwrap();
    let result = handler.verify(&token);
    assert!(result.is_ok(), "nbf = now 应通过校验: {:?}", result.err());
    let claims = result.unwrap();
    assert!(claims.nbf.is_some(), "sign 应设置 nbf");
}

/// verify 接受 nbf = now - 10 的 token（过去时间）。
#[test]
fn verify_past_nbf_returns_ok() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let claims = GarrisonJwtClaims {
        sub: "1001".to_string(),
        iat: now - 10,
        exp: now + 3600,
        login_id: "1001".to_string(),
        device: None,
        jti: Some(uuid::Uuid::new_v4().to_string()),
        nbf: Some(now - 10), // 过去 10 秒已生效
    };
    let header = jsonwebtoken::Header::new(Algorithm::HS256);
    let key = jsonwebtoken::EncodingKey::from_secret(b"0123456789abcdef0123456789abcdef");
    let token = jsonwebtoken::encode(&header, &claims, &key).unwrap();
    let result = handler.verify(&token);
    assert!(result.is_ok(), "nbf = 过去应通过校验: {:?}", result.err());
}

/// verify 接受无 nbf 字段的 token（RFC 7519 中 nbf 为可选 claim）。
#[test]
fn verify_token_without_nbf_field_returns_ok() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
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
    let key = jsonwebtoken::EncodingKey::from_secret(b"0123456789abcdef0123456789abcdef");
    let token = jsonwebtoken::encode(&header, &claims_json, &key).unwrap();
    let result = handler.verify(&token);
    assert!(result.is_ok(), "无 nbf 字段应通过校验: {:?}", result.err());
    let claims = result.unwrap();
    assert!(claims.nbf.is_none(), "无 nbf 字段时 claims.nbf 应为 None");
}

// ============================================================================
// refresh 测试
// ============================================================================

/// refresh 返回新 token 且可 verify。
#[test]
fn refresh_issues_new_valid_token() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
    let token = handler.sign("1001", 3600).unwrap();
    let new_token = handler.refresh(&token, 7200).unwrap();
    assert_ne!(token, new_token);
    let claims = handler.verify(&new_token).unwrap();
    assert_eq!(claims.login_id, "1001");
}

/// refresh 旧 token 无效时返回错误。
#[test]
fn refresh_invalid_token_fails() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
    let result = handler.refresh("invalid.token.here", 3600);
    assert!(result.is_err());
}

// ============================================================================
// LoginId newtype 接入（impl Into<LoginId>）
// ============================================================================

/// 验证 `JwtHandler::sign` 接受 String 形式 login_id。
#[test]
fn sign_accepts_login_id_numeric() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
    let token = handler.sign("1001".to_string(), 3600).unwrap();
    let claims = handler.verify(&token).unwrap();
    assert_eq!(claims.login_id, "1001");
}

// ============================================================================
// JWT 密钥最小长度校验
// ============================================================================

/// `sign` 拒绝 < 32 字节密钥，返回 Config 错误。
#[test]
fn sign_rejects_short_secret() {
    let handler = JwtHandler::new("short-key"); // 9 bytes < 32
    let result = handler.sign("1001", 3600);
    assert!(result.is_err(), "短密钥 sign 应返回错误");
    match result.err() {
        Some(GarrisonError::Config(msg)) => {
            assert!(
                msg.contains("jwt-secret-too-short"),
                "错误应包含 jwt-secret-too-short，实际: {}",
                msg
            );
        },
        other => panic!("期望 Config 错误，实际: {:?}", other),
    }
}

/// `verify` 拒绝 < 32 字节密钥，返回 Config 错误。
#[test]
fn verify_rejects_short_secret() {
    let handler = JwtHandler::new("short-key"); // 9 bytes < 32
    let result = handler.verify("eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMDAxIn0.fake");
    assert!(result.is_err(), "短密钥 verify 应返回错误");
    match result.err() {
        Some(GarrisonError::Config(msg)) => {
            assert!(
                msg.contains("jwt-secret-too-short"),
                "错误应包含 jwt-secret-too-short，实际: {}",
                msg
            );
        },
        other => panic!("期望 Config 错误，实际: {:?}", other),
    }
}

/// 恰好 32 字节密钥应正常工作（边界值）。
#[test]
fn sign_accepts_exactly_32_byte_secret() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef"); // exactly 32 bytes
    let token = handler.sign("1001", 3600).unwrap();
    let claims = handler.verify(&token).unwrap();
    assert_eq!(claims.login_id, "1001");
}

// ========================================================================
// alg confusion 对抗测试（行为锁定：攻击输入必须全部拒绝）
// ========================================================================

/// `alg=none`（无签名）token 必须被拒绝——防 JWT none 算法攻击。
#[test]
fn verify_rejects_none_algorithm_token() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
    // header {"alg":"none","typ":"JWT"}，无签名段
    let none_token = "eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIn0.eyJzdWIiOiAidXNlcjEyMyIsICJsb2dpbl9pZCI6ICJ1c2VyMTIzIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDB9.";
    let result = handler.verify(none_token);
    assert!(result.is_err(), "alg=none token 必须被拒绝");
}

/// header alg=RS256 与 handler 配置 HS256 不符的 token 必须被拒绝——防算法替换攻击。
#[test]
fn verify_rejects_algorithm_swap_token() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
    // header {"alg":"RS256","typ":"JWT"}，payload 合法但签名无效（"fakesign"）
    let swapped = "eyJhbGciOiAiUlMyNTYiLCAidHlwIjogIkpXVCJ9.eyJzdWIiOiAidXNlcjEyMyIsICJsb2dpbl9pZCI6ICJ1c2VyMTIzIiwiZXhwIjo5OTk5OTk5OTk5LCJpYXQiOjE3MDAwMDAwMDB9.ZmFrZXNpZ24";
    let result = handler.verify(swapped);
    assert!(
        result.is_err(),
        "header alg 与配置算法不符的 token 必须被拒绝"
    );
}

/// HS256 签发的 token 送 HS512 配置的 handler 必须被拒绝——防跨算法重放。
#[test]
fn verify_rejects_cross_algorithm_replay() {
    let secret = "0123456789abcdef0123456789abcdef";
    let hs256_handler = JwtHandler::new(secret);
    let hs512_handler = JwtHandler::new(secret).with_algorithm(Algorithm::HS512);

    let token = hs256_handler.sign("user123", 3600).unwrap();
    let result = hs512_handler.verify(&token);
    assert!(
        result.is_err(),
        "HS256 签发的 token 送 HS512 handler 必须被拒绝"
    );
}

/// 篡改 payload 后签名校验必须失败。
#[test]
fn verify_rejects_tampered_payload() {
    let handler = JwtHandler::new("0123456789abcdef0123456789abcdef");
    let token = handler.sign("user123", 3600).unwrap();

    // 拆三段，篡改 payload（翻转 login_id），重组
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let mut payload = base64_decode_urlsafe(parts[1]);
    // 翻转 payload 中一个字节（不影响 base64 结构）
    payload[4] ^= 0x01;
    let tampered = format!(
        "{}.{}.{}",
        parts[0],
        base64_encode_urlsafe(&payload),
        parts[2]
    );

    let result = handler.verify(&tampered);
    assert!(result.is_err(), "篡改 payload 后的 token 必须被拒绝");
    // 原始 token 仍须可验证（排除测试自身构造错误）
    assert!(handler.verify(&token).is_ok());
}

/// URL-safe Base64 解码（无 padding）。
fn base64_decode_urlsafe(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .expect("测试辅助 base64 解码")
}

/// URL-safe Base64 编码（无 padding）。
fn base64_encode_urlsafe(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

// ========================================================================
// 非对称签名：RSA（RS256/RS384/RS512）
// ========================================================================

/// 测试专用 RSA 2048 私钥（PKCS#8 PEM，仅用于单元测试，非真实凭证）。
// nosemgrep: generic.secrets.security.detected-private-key.detected-private-key —— CI 已验证的测试夹具 PEM（假钥，非真实凭证）
const TEST_RSA_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
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

/// RSA 构造器 + RS256 sign/verify 全链路。
#[test]
fn rsa_pem_rs256_sign_verify_roundtrip() {
    let handler = JwtHandler::new("placeholder-secret-not-used")
        .with_rsa_private_pem(TEST_RSA_PRIVATE_PEM)
        .unwrap()
        .try_with_algorithm(Algorithm::RS256)
        .unwrap();

    let token = handler.sign("user123", 3600).unwrap();
    let claims = handler.verify(&token).unwrap();
    assert_eq!(claims.login_id, "user123");
}

/// RS384 / RS512 算法族同样可用。
#[test]
fn rsa_pem_rs384_rs512_sign_verify_roundtrip() {
    for alg in [Algorithm::RS384, Algorithm::RS512] {
        let handler = JwtHandler::new("placeholder-secret-not-used")
            .with_rsa_private_pem(TEST_RSA_PRIVATE_PEM)
            .unwrap()
            .try_with_algorithm(alg)
            .unwrap();
        let token = handler.sign("user123", 3600).unwrap();
        let claims = handler.verify(&token).unwrap();
        assert_eq!(claims.login_id, "user123");
    }
}

/// 非法 PEM 在构造期 fail-fast（不延迟到 sign）。
#[test]
fn rsa_pem_invalid_pem_fails_fast() {
    let result = JwtHandler::new("placeholder").with_rsa_private_pem("not-a-pem");
    assert!(result.is_err(), "非法 PEM 必须在构造期报错");
}

/// RSA 密钥 + HS 系算法的组合被 validate_algorithm_match 拒绝（fail-closed）。
#[test]
fn rsa_pem_rejects_hs_algorithm() {
    let handler = JwtHandler::new("placeholder")
        .with_rsa_private_pem(TEST_RSA_PRIVATE_PEM)
        .unwrap();
    let err = match handler.try_with_algorithm(Algorithm::HS256) {
        Err(e) => e,
        Ok(_) => panic!("RSA 密钥配 HS256 应被拒绝"),
    };
    assert!(
        matches!(err, GarrisonError::Config(ref m) if m.contains("jwt-key-algorithm-mismatch")),
        "RSA 密钥配 HS256 应报 jwt-key-algorithm-mismatch，实际: {:?}",
        err
    );
}

/// KeyMaterial 的 Debug 输出脱敏：PEM 私钥内容不得出现。
#[test]
fn rsa_key_material_debug_redacts_pem() {
    let handler = JwtHandler::new("placeholder")
        .with_rsa_private_pem(TEST_RSA_PRIVATE_PEM)
        .unwrap();
    let debug = format!("{:?}", handler.key_material);
    assert!(
        !debug.contains("PRIVATE KEY") && !debug.contains("MIIEvg"),
        "KeyMaterial Debug 输出不得包含 PEM 内容，实际: {}",
        debug
    );
}

// ========================================================================
// 非对称签名：EC（ES256/ES384）
// ========================================================================

/// 测试专用 P-256 EC 私钥（PKCS#8 PEM，仅用于单元测试，非真实凭证）。
// nosemgrep: generic.secrets.security.detected-private-key.detected-private-key —— CI 已验证的测试夹具 PEM（假钥，非真实凭证）
const TEST_EC_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgHu89Emnr1D+OpkZF
T2f/jZRjQNl9Q6AyVEnsI2rH+tihRANCAARSS8Qlg3TwbmWk6ICPdeHxy/X0LARI
FTcfYH6rUSsxJH2JD7Adnx1iw7UhnOZXVf8YOnDrqaXJkQcXNWPSUBqA
-----END PRIVATE KEY-----
";

/// EC 构造器 + ES256 sign/verify 全链路。
#[test]
fn ec_pem_es256_sign_verify_roundtrip() {
    let handler = JwtHandler::new("placeholder-secret-not-used")
        .with_ec_pem(TEST_EC_PRIVATE_PEM)
        .unwrap()
        .try_with_algorithm(Algorithm::ES256)
        .unwrap();

    let token = handler.sign("user123", 3600).unwrap();
    let claims = handler.verify(&token).unwrap();
    assert_eq!(claims.login_id, "user123");
}

/// 非法 EC PEM 在构造期 fail-fast。
#[test]
fn ec_pem_invalid_pem_fails_fast() {
    let result = JwtHandler::new("placeholder").with_ec_pem("not-a-pem");
    assert!(result.is_err(), "非法 EC PEM 必须在构造期报错");
}

/// EC 密钥 + HS 系算法的组合被 validate_algorithm_match 拒绝。
#[test]
fn ec_pem_rejects_hs_algorithm() {
    let handler = JwtHandler::new("placeholder")
        .with_ec_pem(TEST_EC_PRIVATE_PEM)
        .unwrap();
    let result = handler.try_with_algorithm(Algorithm::HS256);
    assert!(result.is_err(), "EC 密钥配 HS256 应被拒绝");
}

/// 测试专用 P-384 EC 私钥（PKCS#8 PEM，仅用于单元测试，非真实凭证）。
// nosemgrep: generic.secrets.security.detected-private-key.detected-private-key —— CI 已验证的测试夹具 PEM（假钥，非真实凭证）
const TEST_EC_P384_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIG2AgEAMBAGByqGSM49AgEGBSuBBAAiBIGeMIGbAgEBBDA7FBewvmXSGqCaqiUM
8WJE3UDFs8aHiXNcnz4TzkYW5FHiZKVufY2cGbuu68R71VGhZANiAAQN57zuQF41
RG768ifH35dHUGaCy0FFgEq/LpAQHQGafVI/DVkmz21C4uezJg4dId/PhuhhXgiR
kNTRzfBIl0uPVyBJA2hncDTiVcKiOHfdyZ678wwtTNpxsnL3oEm1h+8=
-----END PRIVATE KEY-----
";

/// ES384（P-384 曲线）sign/verify 全链路。
#[test]
fn ec_pem_es384_sign_verify_roundtrip() {
    let handler = JwtHandler::new("placeholder-secret-not-used")
        .with_ec_pem(TEST_EC_P384_PRIVATE_PEM)
        .unwrap()
        .try_with_algorithm(Algorithm::ES384)
        .unwrap();

    let token = handler.sign("user123", 3600).unwrap();
    let claims = handler.verify(&token).unwrap();
    assert_eq!(claims.login_id, "user123");
}

// ========================================================================
// 非对称签名：Ed25519（EdDSA）
// ========================================================================

/// 测试专用 Ed25519 私钥（PKCS#8 PEM，RFC 8410，仅用于单元测试，非真实凭证）。
// nosemgrep: generic.secrets.security.detected-private-key.detected-private-key —— CI 已验证的测试夹具 PEM（假钥，非真实凭证）
const TEST_ED_PRIVATE_PEM: &str = "-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIOChr1YQD9KWBWWGBLFFjHQiHx9+OznRi69Gh25Uhv8H
-----END PRIVATE KEY-----
";

/// Ed 构造器 + EdDSA sign/verify 全链路。
#[test]
fn ed_pem_eddsa_sign_verify_roundtrip() {
    let handler = JwtHandler::new("placeholder-secret-not-used")
        .with_ed_pem(TEST_ED_PRIVATE_PEM)
        .unwrap()
        .try_with_algorithm(Algorithm::EdDSA)
        .unwrap();

    let token = handler.sign("user123", 3600).unwrap();
    let claims = handler.verify(&token).unwrap();
    assert_eq!(claims.login_id, "user123");
}

/// 非法 Ed PEM 在构造期 fail-fast。
#[test]
fn ed_pem_invalid_pem_fails_fast() {
    let result = JwtHandler::new("placeholder").with_ed_pem("not-a-pem");
    assert!(result.is_err(), "非法 Ed PEM 必须在构造期报错");
}

/// 非对称算法 + 空 jwt_secret 占位：sign 与 verify 语义必须对称（都不误拒）。
///
/// config 层明确允许非对称算法下 jwt_secret 留空（密钥强度由 PEM 决定，
/// `validate_jwt_secret` 对 RS/ES/EdDSA 跳过对称长度校验）；verify 曾因无条件的
/// `secret.is_empty()` 检查误拒该合法配置（sign 有 KeyMaterial 门控而 verify 没有），
/// 本测试锁定修复后的对称语义。
#[test]
fn asymmetric_empty_secret_placeholder_sign_verify_symmetric() {
    let handler = JwtHandler::new("")
        .with_ed_pem(TEST_ED_PRIVATE_PEM)
        .unwrap()
        .try_with_algorithm(Algorithm::EdDSA)
        .unwrap();
    let token = handler
        .sign("user123", 3600)
        .expect("空 secret 占位 + EdDSA 的 sign 不应误拒");
    let claims = handler
        .verify(&token)
        .expect("空 secret 占位 + EdDSA 的 verify 不应误拒（修复前 Err(jwt-secret-empty)）");
    assert_eq!(claims.login_id, "user123");
}

// ========================================================================
// 跨密钥类型 alg confusion（T020-T023 KeyMaterial 齐备后的交叉验证）
// ========================================================================

/// 跨密钥类型令牌交叉使用全部必须被拒绝：
/// RS 签发 → HS 验证、HS 签发 → RS 验证、HS 签发 → EC 验证、HS 签发 → Ed 验证。
#[test]
fn cross_key_type_tokens_always_rejected() {
    let hs = JwtHandler::new("0123456789abcdef0123456789abcdef");
    let hs_token = hs.sign("user123", 3600).unwrap();

    let rsa = JwtHandler::new("placeholder")
        .with_rsa_private_pem(TEST_RSA_PRIVATE_PEM)
        .unwrap()
        .try_with_algorithm(Algorithm::RS256)
        .unwrap();
    let rsa_token = rsa.sign("user123", 3600).unwrap();

    let ec = JwtHandler::new("placeholder")
        .with_ec_pem(TEST_EC_PRIVATE_PEM)
        .unwrap()
        .try_with_algorithm(Algorithm::ES256)
        .unwrap();
    let ec_token = ec.sign("user123", 3600).unwrap();

    let ed = JwtHandler::new("placeholder")
        .with_ed_pem(TEST_ED_PRIVATE_PEM)
        .unwrap()
        .try_with_algorithm(Algorithm::EdDSA)
        .unwrap();

    // HS token → RS / EC / Ed handler（签名族不匹配）
    assert!(
        rsa.verify(&hs_token).is_err(),
        "HS token 送 RS handler 必须被拒绝"
    );
    assert!(
        ec.verify(&hs_token).is_err(),
        "HS token 送 EC handler 必须被拒绝"
    );
    assert!(
        ed.verify(&hs_token).is_err(),
        "HS token 送 Ed handler 必须被拒绝"
    );

    // RS token → HS / EC / Ed handler
    assert!(
        hs.verify(&rsa_token).is_err(),
        "RS token 送 HS handler 必须被拒绝"
    );
    assert!(
        ec.verify(&rsa_token).is_err(),
        "RS token 送 EC handler 必须被拒绝"
    );
    assert!(
        ed.verify(&rsa_token).is_err(),
        "RS token 送 Ed handler 必须被拒绝"
    );

    // EC / Ed token → HS handler
    assert!(
        hs.verify(&ec_token).is_err(),
        "EC token 送 HS handler 必须被拒绝"
    );
    assert!(
        hs.verify(ed.sign("user123", 3600).unwrap().as_str())
            .is_err(),
        "Ed token 送 HS handler 必须被拒绝"
    );

    // 正向路径 sanity：同 handler 验证自身签发的 token 必须通过
    assert!(rsa.verify(&rsa_token).is_ok());
    assert!(ec.verify(&ec_token).is_ok());
    assert!(hs.verify(&hs_token).is_ok());
}
