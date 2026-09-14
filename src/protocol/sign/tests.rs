//! Copyright (c) 2026 Kirky-X <Kirky-X@outlook.com>. All rights reserved.
//! See LICENSE for full license text.

//! SignHandler 单元测试。

use super::mock::MockDao;
use super::*;
use crate::error::GarrisonError;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// 测试用 app_secret（32 字节，满足最小长度要求）。
const TEST_APP_SECRET: &str = "test-secret-key-with-32-bytes!!!";

/// 创建 SignHandler（使用 MockDao）。
fn make_handler() -> SignHandler {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
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
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let result = SignHandler::new("", TEST_APP_SECRET, dao);
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::Config(_)) => {},
        other => panic!("期望 Config 错误，实际: {:?}", other),
    }
}

/// app_secret 短于 32 字节返回 Config 错误。
#[test]
fn new_short_app_secret_returns_config_error() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let result = SignHandler::new("app-001", "short-secret", dao);
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::Config(msg)) => {
            assert!(
                msg.starts_with("sign-app-secret-too-short::"),
                "错误消息应使用 i18n key 形式: {}",
                msg
            );
        },
        other => panic!("期望 Config 错误，实际: {:?}", other),
    }
}

/// app_secret 正好 32 字节通过校验。
#[test]
fn new_app_secret_exactly_32_bytes_passes() {
    let dao: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    // 正好 32 字节
    let secret_32 = "0123456789abcdef0123456789abcdef";
    assert_eq!(secret_32.len(), 32);
    let result = SignHandler::new("app-001", secret_32, dao);
    let _handler = result.expect("32 字节 secret 应通过校验");
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
    let dao1: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
    let dao2: Arc<dyn GarrisonDao> = Arc::new(MockDao::new());
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
    assert_eq!(result.unwrap(), (), "签名校验应返回 Ok(())");
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
    let key = "garrison:sign:nonce:app-001:nonce-store";
    let stored = dao.get(key).await.unwrap();
    assert!(stored.is_some());
}

/// 签名不匹配返回错误（spec Scenario）。
///
/// 伪造签名必须是**合法 Base64**（用不同 body 真实算出一个"算法正确但内容
/// 不匹配"的签名）：若传入含 `-` 等非法 Base64 字符的串，会先在 Base64 解码处
/// 失败（`sign-base64-decode`），根本走不到 HMAC 常量时间比较——那验证的是
/// 解码失败路径而非签名不匹配路径。此处精确断言 `sign-mismatch`，确保覆盖
/// 的确是签名比较失败。
#[tokio::test]
async fn validate_signature_mismatch_returns_error() {
    let handler = make_handler();
    let ts = now_ts();
    // 用篡改的 body 计算真实签名（合法 Base64，44 字符），再对原始 body 校验
    let forged = handler.sign("POST", "/api", ts, "nonce-mismatch", "tampered-body");
    assert_eq!(forged.len(), 44);
    let result = handler
        .validate("POST", "/api", ts, "nonce-mismatch", "body", &forged)
        .await;
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::InvalidToken(msg)) => {
            assert_eq!(msg, "sign-mismatch", "应命中 HMAC 签名不匹配路径");
        },
        other => panic!("期望 InvalidToken(sign-mismatch)，实际: {:?}", other),
    }
}

/// 非法 Base64 签名在解码阶段即被拒（`sign-base64-decode` 路径）。
#[tokio::test]
async fn validate_malformed_base64_signature_returns_error() {
    let handler = make_handler();
    let ts = now_ts();
    // '-' 不是合法 Base64 字符，STANDARD.decode 必然失败
    let result = handler
        .validate("POST", "/api", ts, "nonce-b64", "body", "forged-signature")
        .await;
    assert!(result.is_err());
    match result.err() {
        Some(GarrisonError::InvalidToken(msg)) => {
            assert!(
                msg.starts_with("sign-base64-decode::"),
                "应命中 Base64 解码失败路径，实际: {}",
                msg
            );
        },
        other => panic!("期望 InvalidToken(sign-base64-decode)，实际: {:?}", other),
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
        Some(GarrisonError::ExpiredToken(_)) => {},
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
        Some(GarrisonError::ExpiredToken(_)) => {},
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
        Some(GarrisonError::InvalidToken(_)) => {},
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

/// 并发重放 — 16 个 tokio 任务同时用同一 nonce 校验，
/// 仅一个成功（incr 返回 1），其余全部被拒（incr 返回 >1），原子防重放。
#[tokio::test]
async fn validate_nonce_concurrent_replay_only_one_wins() {
    let dao = Arc::new(MockDao::new());
    let handler = SignHandler::new("app-001", TEST_APP_SECRET, dao.clone()).unwrap();
    let ts = now_ts();
    let sig = handler.sign("POST", "/api", ts, "nonce-conc", "body");

    let handler = Arc::new(handler);
    let mut handles = Vec::new();
    for _ in 0..16 {
        let h = handler.clone();
        let s = sig.clone();
        handles.push(tokio::spawn(async move {
            h.validate("POST", "/api", ts, "nonce-conc", "body", &s)
                .await
                .is_ok()
        }));
    }
    let mut wins = 0usize;
    for h in handles {
        if h.await.unwrap() {
            wins += 1;
        }
    }
    assert_eq!(wins, 1, "并发重放：仅一个 nonce 校验应成功，实际 {}", wins);
}

/// 不同 app_key 的相同 nonce 互不污染（key 含 app_key 前缀）。
#[tokio::test]
async fn validate_nonce_isolated_by_app_key() {
    let dao = Arc::new(MockDao::new());
    let h1 = SignHandler::new("app-a", TEST_APP_SECRET, dao.clone()).unwrap();
    let h2 = SignHandler::new("app-b", TEST_APP_SECRET, dao.clone()).unwrap();
    let ts = now_ts();
    let sig1 = h1.sign("POST", "/api", ts, "shared-nonce", "body");
    let sig2 = h2.sign("POST", "/api", ts, "shared-nonce", "body");
    // app-a 使用 shared-nonce 成功
    h1.validate("POST", "/api", ts, "shared-nonce", "body", &sig1)
        .await
        .unwrap();
    // app-b 使用相同 nonce（不同 app_key）仍应成功，互不污染
    h2.validate("POST", "/api", ts, "shared-nonce", "body", &sig2)
        .await
        .unwrap();
    // app-a 再次使用 shared-nonce 应被拒（自身重放）
    assert!(h1
        .validate("POST", "/api", ts, "shared-nonce", "body", &sig1)
        .await
        .is_err());
}

/// TTL 过期语义：nonce 跨窗口过期后可重新使用（经 MockDao 真实 TTL 验证）。
///
/// MockDao 的 `expire`/TTL 此前为 no-op，nonce 永不过期，任何依赖 TTL 过期
/// 的测试都会"假通过"。现 mock 实现真实过期时刻：`timestamp_window = 1s`
/// 时 nonce 以 1s TTL 写入，等待过期后同一 nonce 在新窗口内应可再次校验
/// 成功（若 mock 无 TTL，此处会得到 nonce 重放错误）。
#[tokio::test]
async fn validate_nonce_reusable_after_ttl_expiry() {
    let handler = make_handler().with_timestamp_window(1);
    let ts1 = now_ts();
    let sig1 = handler.sign("POST", "/api", ts1, "nonce-cross", "body");
    handler
        .validate("POST", "/api", ts1, "nonce-cross", "body", &sig1)
        .await
        .unwrap();
    // 等待 nonce TTL（= timestamp_window = 1s）过期（sleep 下限保证 >= 1.2s）
    tokio::time::sleep(Duration::from_millis(1200)).await;
    // 同一 nonce 在新窗口内重新签名后应再次成功（旧 nonce 记录已过期清除）
    let ts2 = now_ts();
    let sig2 = handler.sign("POST", "/api", ts2, "nonce-cross", "body");
    let result = handler
        .validate("POST", "/api", ts2, "nonce-cross", "body", &sig2)
        .await;
    assert_eq!(result.unwrap(), (), "nonce TTL 过期后应可在新窗口重新使用");
}
