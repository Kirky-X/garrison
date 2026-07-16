//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! JWT 协议边界场景测试（TG8，0.2.1 patch release）。
//!
//! 验证 `JwtHandler` 在边界条件下的行为：
//! - 8.2 "alg":"none" 注入攻击被拒绝（安全）
//! - 8.3 iat 略微未来的时间容忍时钟偏差
//! - 8.4 已过期的 JWT 调用 refresh 返回错误
//! - 8.5 空 claims 的 JWT 被拒绝
//!
//! 依据 spec protocol-jwt。直接测试 `JwtHandler`（无状态，不需要 MockDao）。

#![cfg(feature = "protocol-jwt")]

use bulwark::error::BulwarkError;
use bulwark::protocol::jwt::{BulwarkJwtClaims, JwtHandler};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// 辅助函数
// ============================================================================

/// 获取当前 Unix 时间戳（秒）。
fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

/// Base64URL 编码（无 padding），用于手工构造 JWT 字符串。
fn base64url_encode(input: &[u8]) -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut result = String::with_capacity((input.len() * 4).div_ceil(3));
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = if chunk.len() > 1 { chunk[1] as u32 } else { 0 };
        let b2 = if chunk.len() > 2 { chunk[2] as u32 } else { 0 };
        let n = (b0 << 16) | (b1 << 8) | b2;
        result.push(CHARSET[((n >> 18) & 0x3F) as usize] as char);
        result.push(CHARSET[((n >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            result.push(CHARSET[((n >> 6) & 0x3F) as usize] as char);
        }
        if chunk.len() > 2 {
            result.push(CHARSET[(n & 0x3F) as usize] as char);
        }
    }
    result
}

// ============================================================================
// 边界场景测试
// ============================================================================

/// 8.2 none_algorithm_injection_rejected
///
/// 验证 JWT 头部使用 `"alg":"none"` 的注入攻击被拒绝（安全边界）。
///
/// 攻击场景：攻击者构造一个 `alg:none` 的 JWT，签名段为空，期望绕过签名校验。
/// `JwtHandler::verify` 使用 `jsonwebtoken::decode` 并要求 HS256 算法，
/// `decode` 会校验头部 `alg` 与 `Validation::algorithms` 是否匹配，
/// `alg:none` 不在允许列表中 → 返回 `InvalidToken` 错误。
#[tokio::test]
async fn none_algorithm_injection_rejected() {
    let handler = JwtHandler::new("secret-key");

    // 手工构造 alg:none JWT（header.payload.，签名段为空）
    let header_json = r#"{"alg":"none","typ":"JWT"}"#;
    let claims_json =
        r#"{"sub":"1001","iat":1700000000,"exp":9999999999,"login_id":1001,"device":null}"#;
    let header_b64 = base64url_encode(header_json.as_bytes());
    let claims_b64 = base64url_encode(claims_json.as_bytes());
    let forged_token = format!("{}.{}.", header_b64, claims_b64);

    let result = handler.verify(&forged_token);
    assert!(
        result.is_err(),
        "alg:none 注入应被拒绝（安全边界），token: {}",
        forged_token
    );
    match result.err() {
        Some(BulwarkError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
    }
}

/// 8.3 iat_future_time_tolerates_clock_skew
///
/// 验证 JWT 的 `iat`（签发时间）略微在未来时被容忍（不拒绝）。
///
/// `JwtHandler::verify` 使用 `jsonwebtoken::decode`，`Validation` 仅启用
/// `validate_exp`（校验过期时间），不启用 `validate_iat`。因此即使 `iat`
/// 在未来，只要 `exp` 未过期，token 仍可校验通过。
///
/// 这模拟了时钟偏差场景：签发方时钟比校验方快几秒，`iat` 略在未来，
/// 但 token 仍应有效。
#[tokio::test]
async fn iat_future_time_tolerates_clock_skew() {
    let secret = "clock-skew-secret";
    let handler = JwtHandler::new(secret);

    let now = now_ts();
    // 构造 iat 在未来 60 秒的 claims（模拟时钟偏差）
    let claims = BulwarkJwtClaims {
        sub: "1001".to_string(),
        iat: now + 60, // iat 在未来 60 秒
        exp: now + 3600,
        login_id: "1001".to_string(),
        device: None,
        jti: None,
        nbf: None, // 补充 nbf 字段
    };

    // 使用 jsonwebtoken::encode 直接编码（绕过 JwtHandler::sign 的 iat=now 逻辑）
    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret(secret.as_bytes());
    let token = encode(&header, &claims, &key).expect("编码应成功");

    // JwtHandler::verify 应容忍 iat 在未来（不校验 iat）
    let result = handler.verify(&token);
    assert!(
        result.is_ok(),
        "iat 在未来应被容忍（时钟偏差），实际错误: {:?}",
        result.err()
    );

    let verified_claims = result.unwrap();
    assert_eq!(verified_claims.login_id, "1001".to_string());
    assert_eq!(verified_claims.iat, now + 60, "iat 应保留未来时间值");
}

/// 8.4 refresh_expired_token_returns_error
///
/// 验证对已过期的 JWT 调用 `refresh` 返回 `ExpiredToken` 错误。
///
/// `JwtHandler::refresh` 内部先调用 `verify`（会校验 `exp`），
/// 已过期的 token 在 `verify` 阶段即被拒绝，返回 `ExpiredToken`。
#[tokio::test]
async fn refresh_expired_token_returns_error() {
    let handler = JwtHandler::new("refresh-secret");

    // 签发一个 1 秒过期的 token
    let token = handler.sign("1001", 1).unwrap();

    // 等待 2 秒让 token 过期
    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

    // refresh 已过期的 token 应返回 ExpiredToken
    let result = handler.refresh(&token, 3600);
    assert!(result.is_err(), "已过期 token 的 refresh 应失败");
    match result.err() {
        Some(BulwarkError::ExpiredToken(_)) => {},
        other => panic!("期望 ExpiredToken 错误，实际: {:?}", other),
    }
}

/// 8.5 empty_claims_jwt_rejected
///
/// 验证空 claims（`{}`）的 JWT 被拒绝。
///
/// `JwtHandler::verify` 将 payload 反序列化为 `BulwarkJwtClaims`，
/// 该结构体的 `sub`、`iat`、`exp`、`login_id` 字段均为必填。
/// 空 claims `{}` 缺少这些字段 → 反序列化失败 → 返回 `InvalidToken`。
#[tokio::test]
async fn empty_claims_jwt_rejected() {
    let secret = "empty-claims-secret";
    let handler = JwtHandler::new(secret);

    // 使用 jsonwebtoken::encode 编码空 claims（{}）
    let header = Header::new(Algorithm::HS256);
    let key = EncodingKey::from_secret(secret.as_bytes());
    let empty_claims = serde_json::json!({});
    let token = encode(&header, &empty_claims, &key).expect("编码应成功");

    // verify 应拒绝（反序列化失败，缺少必填字段）
    let result = handler.verify(&token);
    assert!(result.is_err(), "空 claims 的 JWT 应被拒绝");
    match result.err() {
        Some(BulwarkError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
    }
}
