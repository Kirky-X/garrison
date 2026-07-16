//! Copyright (c) 2026 Kirky.X. All rights reserved.
//! See LICENSE for full license text.

//! SignHandler 单元测试。

use super::mock::MockDao;
use super::*;
use crate::error::BulwarkError;
use std::time::{SystemTime, UNIX_EPOCH};

/// 测试用 app_secret（32 字节，满足最小长度要求）。
const TEST_APP_SECRET: &str = "test-secret-key-with-32-bytes!!!";

/// 创建 SignHandler（使用 MockDao）。
fn make_handler() -> SignHandler {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    SignHandler::new("app-001", TEST_APP_SECRET, dao).unwrap()
}

/// 获取当前时间戳。
fn now_ts() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}

// ========================================================================
// SignHandler 构造测试
// ========================================================================

/// 构造 SignHandler，字段正确填充（spec Scenario）。
#[test]
fn new_populates_fields() {
    let handler = make_handler();
    assert_eq!(handler.app_key(), "app-001");
    assert_eq!(handler.timestamp_window(), 300);
}

/// app_key 为空返回 Config 错误（spec Scenario）。
#[test]
fn new_empty_app_key_returns_config_error() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let result = SignHandler::new("", TEST_APP_SECRET, dao);
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::Config(_)) => {},
        other => panic!("期望 Config 错误，实际: {:?}", other),
    }
}

/// app_secret 短于 32 字节返回 Config 错误。
#[test]
fn new_short_app_secret_returns_config_error() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let result = SignHandler::new("app-001", "short-secret", dao);
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::Config(msg)) => {
            assert!(
                msg.contains("32") && msg.contains("字节"),
                "错误消息应包含最小长度提示: {}",
                msg
            );
        },
        other => panic!("期望 Config 错误，实际: {:?}", other),
    }
}

/// app_secret 正好 32 字节通过校验。
#[test]
fn new_app_secret_exactly_32_bytes_passes() {
    let dao: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    // 正好 32 字节
    let secret_32 = "0123456789abcdef0123456789abcdef";
    assert_eq!(secret_32.len(), 32);
    let result = SignHandler::new("app-001", secret_32, dao);
    assert!(result.is_ok());
}

/// 自定义时间窗口（spec Scenario）。
#[test]
fn with_timestamp_window_sets_window() {
    let handler = make_handler().with_timestamp_window(120);
    assert_eq!(handler.timestamp_window(), 120);
}

// ========================================================================
// sign 测试
// ========================================================================

/// 标准签名生成，返回 Base64 字符串（spec Scenario）。
#[test]
fn sign_returns_base64_string() {
    let handler = make_handler();
    let sig = handler.sign(
        "POST",
        "/api/v1/users",
        1700000000,
        "nonce-abc",
        "e3b0c44298fc1c149afbf4c8996fb924",
    );
    // Base64 编码的 HMAC-SHA256 应为 44 字符（32 字节 → 44 字符含 padding）
    assert_eq!(sig.len(), 44);
    assert!(sig
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '='));
}

/// 不同 body_sha256 产生不同签名（spec Scenario）。
#[test]
fn sign_different_body_sha256_produces_different_signatures() {
    let handler = make_handler();
    let s1 = handler.sign("POST", "/api", 1700000000, "n", "aaa");
    let s2 = handler.sign("POST", "/api", 1700000000, "n", "bbb");
    assert_ne!(s1, s2);
}

/// 不同 method 产生不同签名（spec Scenario）。
#[test]
fn sign_different_method_produces_different_signatures() {
    let handler = make_handler();
    let s1 = handler.sign("GET", "/api", 1700000000, "n", "body");
    let s2 = handler.sign("POST", "/api", 1700000000, "n", "body");
    assert_ne!(s1, s2);
}

/// HKDF 派生确保不同 app_key 产生不同签名（域分隔）。
#[test]
fn sign_different_app_key_produces_different_signatures() {
    let dao1: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let dao2: Arc<dyn BulwarkDao> = Arc::new(MockDao::new());
    let h1 = SignHandler::new("app-key-1", TEST_APP_SECRET, dao1).unwrap();
    let h2 = SignHandler::new("app-key-2", TEST_APP_SECRET, dao2).unwrap();
    let s1 = h1.sign("POST", "/api", 1700000000, "n", "body");
    let s2 = h2.sign("POST", "/api", 1700000000, "n", "body");
    // 相同 app_secret 但不同 app_key → HKDF salt 不同 → 派生密钥不同 → 签名不同
    assert_ne!(s1, s2, "不同 app_key 应通过 HKDF salt 产生不同签名");
}

// ========================================================================
// validate 测试
// ========================================================================

/// 成功校验（spec Scenario）。
#[tokio::test]
async fn validate_success() {
    let handler = make_handler();
    let ts = now_ts();
    let sig = handler.sign("POST", "/api/v1/users", ts, "nonce-1", "body-sha256");
    let result = handler
        .validate("POST", "/api/v1/users", ts, "nonce-1", "body-sha256", &sig)
        .await;
    assert!(result.is_ok());
}

/// 校验成功后 nonce 存入 dao（spec Scenario）。
#[tokio::test]
async fn validate_success_stores_nonce() {
    let dao = Arc::new(MockDao::new());
    let handler = SignHandler::new("app-001", TEST_APP_SECRET, dao.clone()).unwrap();
    let ts = now_ts();
    let sig = handler.sign("GET", "/api", ts, "nonce-store", "body");
    handler
        .validate("GET", "/api", ts, "nonce-store", "body", &sig)
        .await
        .unwrap();
    let key = "bulwark:sign:nonce:nonce-store";
    let stored = dao.get(key).await.unwrap();
    assert!(stored.is_some());
}

/// 签名不匹配返回错误（spec Scenario）。
#[tokio::test]
async fn validate_signature_mismatch_returns_error() {
    let handler = make_handler();
    let ts = now_ts();
    let result = handler
        .validate(
            "POST",
            "/api",
            ts,
            "nonce-mismatch",
            "body",
            "forged-signature",
        )
        .await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
    }
}

/// 时间戳过期返回错误（spec Scenario）。
#[tokio::test]
async fn validate_expired_timestamp_returns_error() {
    let handler = make_handler();
    let old_ts = now_ts() - 600; // 超过 300 秒窗口
    let sig = handler.sign("POST", "/api", old_ts, "nonce-exp", "body");
    let result = handler
        .validate("POST", "/api", old_ts, "nonce-exp", "body", &sig)
        .await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::ExpiredToken(_)) => {},
        other => panic!("期望 ExpiredToken 错误，实际: {:?}", other),
    }
}

/// 未来时间戳返回错误（spec Scenario）。
#[tokio::test]
async fn validate_future_timestamp_returns_error() {
    let handler = make_handler();
    let future_ts = now_ts() + 600;
    let sig = handler.sign("POST", "/api", future_ts, "nonce-fut", "body");
    let result = handler
        .validate("POST", "/api", future_ts, "nonce-fut", "body", &sig)
        .await;
    assert!(result.is_err());
    match result.err() {
        Some(BulwarkError::ExpiredToken(_)) => {},
        other => panic!("期望 ExpiredToken 错误，实际: {:?}", other),
    }
}

/// nonce 重放被拒绝（spec Scenario）。
#[tokio::test]
async fn validate_nonce_replay_rejected() {
    let handler = make_handler();
    let ts = now_ts();
    let sig = handler.sign("POST", "/api", ts, "nonce-replay", "body");
    // 第一次校验成功
    let first = handler
        .validate("POST", "/api", ts, "nonce-replay", "body", &sig)
        .await;
    assert!(first.is_ok());
    // 第二次校验失败（nonce 重放）
    let second = handler
        .validate("POST", "/api", ts, "nonce-replay", "body", &sig)
        .await;
    assert!(second.is_err());
    match second.err() {
        Some(BulwarkError::InvalidToken(_)) => {},
        other => panic!("期望 InvalidToken 错误，实际: {:?}", other),
    }
}

/// method 大小写差异导致签名不匹配（spec Scenario）。
#[tokio::test]
async fn validate_method_case_difference_returns_error() {
    let handler = make_handler();
    let ts = now_ts();
    let sig = handler.sign("POST", "/api", ts, "nonce-case", "body");
    let result = handler
        .validate("post", "/api", ts, "nonce-case", "body", &sig)
        .await;
    assert!(result.is_err());
}
